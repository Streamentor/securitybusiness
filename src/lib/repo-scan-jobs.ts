import { prisma } from "@/lib/db";
import { ensureRepoTables } from "@/lib/repo-store";
import { getGitHubAppConfig, getInstallationToken, GitHubAppError } from "@/lib/github-app";
import { GitHubScannerError, parseGitHubRepository, riskScore, scanGitHubRepository, type RepoScanResult } from "@/lib/github-scanner";
import { canReviewWithAI, resultForEntitlement, reviewRepositoryWithAI, scoreReviewedFindings, type ReviewFile } from "@/lib/ai-review";
import { getAIReviewPreference, reserveAIReviewTokens, settleAIReviewTokens } from "@/lib/ai-review-store";
import type { Prisma } from "@/generated/prisma/client";

export const PRIVATE_REPO_PLANS = new Set(["starter", "pro"]);
const MAX_SCANS_PER_HOUR = 15;
const MAX_ACTIVE_SCANS = 2;
/** A job still queued/running after this long is reported as failed (the function was stopped). */
export const STALE_JOB_MS = 6 * 60 * 1000;

export class RepoJobError extends Error {
  constructor(public status: number, message: string, public code: string) {
    super(message);
  }
}

export function canScanPrivateRepositories(user: { plan: string; role?: string | null }) {
  return PRIVATE_REPO_PLANS.has(user.plan) || user.role === "admin";
}

/** Pure staleness rule, exported for fixture tests. */
export function isStale(job: { status: string; createdAt: Date; startedAt: Date | null }, now = Date.now()) {
  if (job.status !== "queued" && job.status !== "running") return false;
  return now - (job.startedAt ?? job.createdAt).getTime() > STALE_JOB_MS;
}

const GITHUB_API = "https://api.github.com";

async function repositoryVisibleWith(owner: string, repo: string, token?: string): Promise<{ private: boolean } | null> {
  const response = await fetch(`${GITHUB_API}/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`, {
    cache: "no-store",
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": "2022-11-28",
      "User-Agent": "ScanMySaaS-Repo-Scanner/1.0",
      ...(token ? { Authorization: `Bearer ${token}` } : process.env.GITHUB_SCANNER_TOKEN ? { Authorization: `Bearer ${process.env.GITHUB_SCANNER_TOKEN}` } : {}),
    },
  }).catch(() => null);
  if (!response?.ok) return null;
  const data = await response.json().catch(() => null) as { private?: boolean } | null;
  return data ? { private: Boolean(data.private) } : null;
}

/**
 * Validate access and entitlement, then create a queued job. The caller schedules
 * runRepoScanJob with after() so the browser can leave while the scan runs.
 */
export async function createRepoScanJob(userId: string, input: string): Promise<{ id: string }> {
  await ensureRepoTables();
  const { owner, repo, refCandidates } = parseGitHubRepository(input);
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { plan: true, role: true } });
  if (!user) throw new RepoJobError(401, "Sign in to scan repositories.", "unauthorized");

  const since = new Date(Date.now() - 60 * 60 * 1000);
  const [recent, active] = await Promise.all([
    prisma.repoScan.count({ where: { userId, createdAt: { gte: since } } }),
    prisma.repoScan.findMany({ where: { userId, status: { in: ["queued", "running"] } }, select: { status: true, createdAt: true, startedAt: true } }),
  ]);
  if (recent >= MAX_SCANS_PER_HOUR) throw new RepoJobError(429, "You have started many repository scans in the last hour. Try again a little later.", "rate_limited");
  if (active.filter((job) => !isStale(job)).length >= MAX_ACTIVE_SCANS) throw new RepoJobError(429, "Two repository scans are already running. Wait for one to finish.", "too_many_active");

  // Prefer a connected installation that can see the repository (works for public and private).
  let installationId: number | null = null;
  let visibility: "public" | "private" | null = null;
  if (getGitHubAppConfig()) {
    const installations = await prisma.gitHubInstallation.findMany({ where: { userId }, select: { installationId: true } });
    for (const { installationId: candidate } of installations) {
      try {
        const token = await getInstallationToken(candidate);
        const seen = await repositoryVisibleWith(owner, repo, token);
        if (seen) { installationId = candidate; visibility = seen.private ? "private" : "public"; break; }
      } catch (error) {
        if (!(error instanceof GitHubAppError)) throw error;
      }
    }
  }
  if (!visibility) {
    const seen = await repositoryVisibleWith(owner, repo);
    if (!seen) {
      throw new RepoJobError(404, getGitHubAppConfig()
        ? "We could not access this repository. If it is private, connect GitHub and grant the ScanMySaaS app access to it."
        : "The repository could not be found. Check the URL; private repositories are not available yet.", "not_found");
    }
    visibility = seen.private ? "private" : "public";
  }
  if (visibility === "private" && !installationId) throw new RepoJobError(403, "Connect GitHub and grant access to this private repository first.", "needs_connection");
  if (visibility === "private" && !canScanPrivateRepositories(user)) {
    throw new RepoJobError(402, "Private repository scans are included in Starter and Pro. Public repositories stay free.", "upgrade_required");
  }

  const job = await prisma.repoScan.create({
    data: {
      userId,
      repository: `${owner}/${repo}`,
      requestedRef: refCandidates[0] ?? null,
      visibility,
      installationId,
      status: "queued",
      stage: "queued",
    },
    select: { id: true },
  });
  return job;
}

export async function runRepoScanJob(id: string): Promise<void> {
  const started = Date.now();
  await ensureRepoTables();
  const job = await prisma.repoScan.findUnique({ where: { id } });
  if (!job || job.status !== "queued") return;
  const claim = await prisma.repoScan.updateMany({where: {id, status: "queued"}, data: {status: "running", startedAt: new Date(), stage: "resolving"}});
  if (claim.count !== 1) return;
  try {
    const accessToken = job.installationId ? await getInstallationToken(job.installationId) : undefined;
    const input = job.requestedRef ? `${job.repository}@${job.requestedRef}` : job.repository;
    let files: ReviewFile[] = [];
    const result: RepoScanResult = await scanGitHubRepository(input, {
      onFilesLoaded: (loaded) => { files = [...loaded].sort((a, b) => riskScore(b.path) - riskScore(a.path)); },
      accessToken,
      onStage: (stage) => stage === "scoring" ? Promise.resolve() : prisma.repoScan.update({ where: { id }, data: { stage } }).then(() => undefined),
    });
    const month = new Date().toISOString().slice(0, 7);
    let ai;
    try {
      const user = await prisma.user.findUnique({where: {id: job.userId}, select: {plan: true, role: true}});
      const enabled = user && canReviewWithAI(user) && process.env.OPENAI_API_KEY ? await getAIReviewPreference(job.userId) : true;
      if (user && canReviewWithAI(user) && enabled && process.env.OPENAI_API_KEY) await prisma.repoScan.update({where: {id}, data: {stage: "ai-review"}});
      ai = await reviewRepositoryWithAI({user: {...(user || {plan: "free"}), enabled}, files, findings: result.findings, timeoutMs: 110_000 - (Date.now() - started)}, {
        reserve: (tokens, cap) => reserveAIReviewTokens(job.userId, month, tokens, cap),
        settle: (reserved, charged) => settleAIReviewTokens(job.userId, month, reserved, charged),
      });
    } catch {
      ai = {status: "failed", note: "AI review was unavailable. Rule-based checks completed.", findings: [], model: null, inputTokens: 0, outputTokens: 0, filesReviewed: 0};
    } finally { files = []; }
    result.findings.push(...ai.findings);
    Object.assign(result, scoreReviewedFindings(result.findings));
    result.aiReview = {status: ai.status, note: ai.note, findingsCount: ai.findings.length, filesReviewed: ai.filesReviewed};
    await prisma.repoScan.update({where: {id}, data: {stage: "scoring"}});
    await prisma.repoScan.update({
      where: { id },
      data: {
        aiModel: ai.model, aiInputTokens: ai.model ? ai.inputTokens : null, aiOutputTokens: ai.model ? ai.outputTokens : null, aiFindingsCount: ai.findings.length,
        status: "completed",
        stage: "done",
        completedAt: new Date(),
        commitSha: result.repository.commitSha,
        score: result.score,
        risk: result.risk,
        findingsCount: result.findings.length,
        result: result as unknown as Prisma.InputJsonValue,
      },
    });
  } catch (error) {
    const message = error instanceof GitHubScannerError || error instanceof GitHubAppError ? error.message : "The repository scan failed. Try again in a moment.";
    if (!(error instanceof GitHubScannerError)) console.error("Repository job failed:", error instanceof Error ? error.message : "unknown");
    await prisma.repoScan.update({ where: { id }, data: { status: "failed", stage: "failed", error: message, completedAt: new Date() } }).catch(() => undefined);
  }
}

export async function getRepoScanForUser(id: string, userId: string) {
  await ensureRepoTables();
  let job = await prisma.repoScan.findFirst({ where: { id, userId } });
  if (!job) return null;
  if (isStale(job)) {
    const message = "The scan took too long and was stopped. Try again; very large repositories may need a branch with fewer files.";
    await prisma.repoScan.update({ where: { id }, data: { status: "failed", stage: "failed", error: message, completedAt: new Date() } });
    job = { ...job, status: "failed", stage: "failed", error: message };
  }
  const user = await prisma.user.findUnique({where: {id: userId}, select: {plan: true, role: true}});
  if (!user || !canReviewWithAI(user)) {
    const result = job.result ? resultForEntitlement(job.result as unknown as RepoScanResult, false) : null;
    return {...job, result, score: result?.score ?? job.score, risk: result?.risk ?? job.risk, findingsCount: result?.findings.length ?? job.findingsCount,
      aiModel: null, aiInputTokens: null, aiOutputTokens: null, aiFindingsCount: result?.aiReview?.findingsCount ?? 0};
  }
  return job;
}

export async function listRepoScansForUser(userId: string, take = 20) {
  await ensureRepoTables();
  const rows = await prisma.repoScan.findMany({
    where: { userId },
    orderBy: { createdAt: "desc" },
    take,
    select: { id: true, repository: true, requestedRef: true, commitSha: true, visibility: true, status: true, stage: true, score: true, risk: true, findingsCount: true, result: true, error: true, createdAt: true, completedAt: true },
  });
  const user = await prisma.user.findUnique({where: {id: userId}, select: {plan: true, role: true}});
  return rows.map(({result: stored, ...row}) => {
    const result = stored && (!user || !canReviewWithAI(user)) ? resultForEntitlement(stored as unknown as RepoScanResult, false) : null;
    return result ? {...row, score: result.score, risk: result.risk, findingsCount: result.findings.length} : row;
  });
}
