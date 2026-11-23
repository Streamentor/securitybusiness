import { prioritizeRepoReview } from "@/lib/repo-route-inventory";
import { prisma } from "@/lib/db";
import { ensureRepoTables } from "@/lib/repo-store";
import { getGitHubAppConfig, getInstallationToken, GitHubAppError } from "@/lib/github-app";
import { GitHubScannerError, parseGitHubRepository, riskScore, scanGitHubRepository, type RepoScanResult } from "@/lib/github-scanner";
import { eligibleReviewFile, canReviewWithAI, resultForEntitlement, reviewRepositoryWithAI, scoreReviewedFindings, type ReviewFile } from "@/lib/ai-review";
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
export async function createRepoScanJob(userId: string, input: string, reviewParentId?: string): Promise<{ id: string }> {
  await ensureRepoTables();
  if (reviewParentId) {
    const parent = await prisma.repoScan.findFirst({ where: { id: reviewParentId, userId, status: "completed" }, select: { repository: true, commitSha: true, result: true } });
    const report = parent?.result as unknown as RepoScanResult | null;
    if (!parent || !parent.commitSha || !/^[0-9a-f]{40}$/.test(parent.commitSha) || !report?.aiReview?.hasNextBatch) {
      throw new RepoJobError(404, "No further AI batch is available for this report.", "no_next_batch");
    }
    input = parent.repository + "@" + parent.commitSha;
  }
  const { owner, repo, refCandidates } = parseGitHubRepository(input);
  const user = await prisma.user.findUnique({ where: { id: userId }, select: { plan: true, role: true } });
  if (!user) throw new RepoJobError(401, "Sign in to scan repositories.", "unauthorized");
  if (reviewParentId && (!canReviewWithAI(user) || !process.env.OPENAI_API_KEY || !await getAIReviewPreference(userId))) {
    throw new RepoJobError(403, "An enabled Starter or Pro AI review is required for another batch.", "ai_review_unavailable");
  }

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

  const data = {
    userId, repository: owner + "/" + repo, requestedRef: refCandidates[0] ?? null,
    visibility, installationId, status: "queued", stage: "queued", reviewParentId,
  };
  if (!reviewParentId) return prisma.repoScan.create({ data, select: { id: true } });
  return prisma.$transaction(async (db) => {
    // Serialize review requests for this account, then debit and enqueue together.
    await db.$queryRaw`SELECT "id" FROM "User" WHERE "id" = ${userId} FOR UPDATE`;
    const existing = await db.repoScan.findFirst({
      where: { userId, reviewParentId, status: { in: ["queued", "running", "completed"] } },
      select: { id: true },
    });
    if (existing) return existing;
    const reserved = await db.user.updateMany({
      where: { id: userId, credits: { gt: 0 }, OR: [{ plan: { in: ["starter", "pro"] } }, { role: "admin" }] },
      data: { credits: { decrement: 1 } },
    });
    if (!reserved.count) throw new RepoJobError(402, "One available scan credit is required for a new AI batch.", "no_credit");
    return db.repoScan.create({ data, select: { id: true } });
  });
}

async function failRepoScanJob(job: { id: string; userId: string; reviewParentId: string | null }, message: string) {
  await prisma.$transaction(async (db) => {
    const changed = await db.repoScan.updateMany({
      where: { id: job.id, status: { in: ["queued", "running"] } },
      data: { status: "failed", stage: "failed", error: message, completedAt: new Date() },
    });
    if (changed.count && job.reviewParentId) {
      await db.user.updateMany({ where: { id: job.userId }, data: { credits: { increment: 1 } } });
    }
  });
}

export async function runRepoScanJob(id: string): Promise<void> {
  const started = Date.now();
  await ensureRepoTables();
  const job = await prisma.repoScan.findUnique({ where: { id } });
  if (!job || job.status !== "queued") return;
  const claim = await prisma.repoScan.updateMany({where: {id, status: "queued"}, data: {status: "running", startedAt: new Date(), stage: "resolving"}});
  if (claim.count !== 1) return;
  try {
    const parent = job.reviewParentId ? await prisma.repoScan.findFirst({
      where: { id: job.reviewParentId, userId: job.userId, commitSha: job.requestedRef, status: "completed" },
      select: { result: true },
    }) : null;
    const previous = parent?.result as unknown as RepoScanResult | null;
    if (job.reviewParentId && !previous?.aiReview?.reviewedPaths?.length) {
      throw new RepoJobError(404, "The original review can no longer be used.", "no_next_batch");
    }
    if (job.installationId && !await prisma.gitHubInstallation.findFirst({
      where: { userId: job.userId, installationId: job.installationId }, select: { id: true },
    })) throw new RepoJobError(403, "Reconnect GitHub before starting another repository scan.", "needs_connection");
    const accessToken = job.installationId ? await getInstallationToken(job.installationId) : undefined;
    const input = job.requestedRef ? `${job.repository}@${job.requestedRef}` : job.repository;
    let files: ReviewFile[] = [];
    const result: RepoScanResult = await scanGitHubRepository(input, {
      onFilesLoaded: (loaded) => { files = [...loaded]; },
      accessToken,
      onStage: (stage) => stage === "scoring" ? Promise.resolve() : prisma.repoScan.update({ where: { id }, data: { stage } }).then(() => undefined),
    });
    const highRiskPaths = [...new Set([
      ...(result.routes ?? []).filter((route) => route.priority >= 2).map((route) => route.file),
      ...files.filter((file) => riskScore(file.path) >= 6 && eligibleReviewFile(file.path)).map((file) => file.path),
    ])];
    const alreadyReviewed = new Set(previous?.aiReview?.reviewedPaths ?? []);
    const reviewCandidates = job.reviewParentId ? files.filter((file) => highRiskPaths.includes(file.path) && !alreadyReviewed.has(file.path)) : files;
    const available = new Set(reviewCandidates.map((file) => file.path));
    files = prioritizeRepoReview(files, result.routes ?? [], riskScore, eligibleReviewFile, alreadyReviewed)
      .filter((file) => available.has(file.path));
    if (previous) result.findings.push(...previous.findings.filter((finding) => finding.source === "ai"));
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
      ai = {status: "failed", note: "AI review was unavailable. Rule-based checks completed.", findings: [], model: null, inputTokens: 0, outputTokens: 0, filesReviewed: 0, reviewedPaths: [] as string[]};
    } finally { files = []; }
    if (job.reviewParentId && !ai.filesReviewed) {
      await failRepoScanJob(job, "No additional files were reviewed. Your scan credit was returned.");
      return;
    }
    result.findings.push(...ai.findings);
    // Evidence excerpts are used to validate model output in memory. Persist
    // only the description and file/line reference for each verified excerpt.
    for (const finding of result.findings) if (finding.source === "ai") delete finding.evidence;
    Object.assign(result, scoreReviewedFindings(result.findings));
    const reviewed = new Set([...alreadyReviewed, ...ai.reviewedPaths]);
    const remaining = highRiskPaths.filter((path) => !reviewed.has(path));
    result.aiReview = {
      status: ai.status, note: ai.note, findingsCount: ai.findings.length, filesReviewed: reviewed.size, reviewedPaths: [...reviewed], hasNextBatch: reviewed.size > 0 && remaining.length > 0,
      highRiskTotal: highRiskPaths.length, highRiskReviewed: highRiskPaths.length - remaining.length, highRiskNotReviewed: remaining,
    };
    await prisma.repoScan.updateMany({
      where: { id, status: "running" },
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
    const message = error instanceof GitHubScannerError || error instanceof GitHubAppError || error instanceof RepoJobError ? error.message : "The repository scan failed. Try again in a moment.";
    if (!(error instanceof GitHubScannerError)) console.error("Repository job failed:", error instanceof Error ? error.message : "unknown");
    await failRepoScanJob(job, message).catch(() => console.error("Repository job failure could not be saved."));
  }
}

export async function getRepoScanForUser(id: string, userId: string) {
  await ensureRepoTables();
  let job = await prisma.repoScan.findFirst({ where: { id, userId } });
  if (!job) return null;
  if (isStale(job)) {
    const message = "The scan took too long and was stopped. Try again; very large repositories may need a branch with fewer files.";
    await failRepoScanJob(job, message);
    job = await prisma.repoScan.findFirst({ where: { id, userId } });
    if (!job) return null;
  }
  const user = await prisma.user.findUnique({where: {id: userId}, select: {plan: true, role: true}});
  if (!user || !canReviewWithAI(user)) {
    const result = job.result ? resultForEntitlement(job.result as unknown as RepoScanResult, false) : null;
    return {...job, result, score: result?.score ?? job.score, risk: result?.risk ?? job.risk, findingsCount: result?.findings.length ?? job.findingsCount,
      aiModel: null, aiInputTokens: null, aiOutputTokens: null, aiFindingsCount: result?.aiReview?.findingsCount ?? 0};
  }
  if (!job.result) return job;
  const result = resultForEntitlement(job.result as unknown as RepoScanResult, true);
  return {...job, result, score: result.score, risk: result.risk};
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
    const result = stored ? resultForEntitlement(stored as unknown as RepoScanResult, Boolean(user && canReviewWithAI(user))) : null;
    return result ? {...row, score: result.score, risk: result.risk, findingsCount: result.findings.length} : row;
  });
}
