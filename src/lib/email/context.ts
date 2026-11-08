import "server-only";
import { prisma } from "@/lib/db";
import { ensureRepoTables } from "@/lib/repo-store";
import { ensureEmailTables } from "@/lib/email/store";
import { applyWebsiteRemediationAccess, isVisibleWebsiteFinding } from "@/lib/scan-remediation";
import { decideScanAccess, hostnameKey, isSameHost, VERIFICATION_WINDOW_MS } from "@/lib/scan-access";
import { compareScanFindings } from "@/lib/scan-comparison";
import { findingImpact, safeText } from "@/lib/email/finding-impact";
import type { EmailContext, EmailFinding } from "@/lib/email/types";
const ranks: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
function path(value: string) { try { return safeText(new URL(value).pathname, 55); } catch { return "/"; } }
export async function loadEmailContext(userId: string, now = new Date()): Promise<EmailContext | null> {
  await ensureEmailTables(); await ensureRepoTables();
  const u = await prisma.user.findUnique({ where: { id: userId }, select: { id: true, email: true, name: true, plan: true, credits: true, createdAt: true, referrerSource: true, emailPreference: true } });
  if (!u) return null;
  const c: EmailContext = { userId: u.id, email: u.email, name: u.name, plan: u.plan, createdAt: u.createdAt, signupSource: u.referrerSource, optedOut: u.emailPreference?.marketingOptOut ?? false, suppressed: u.emailPreference?.suppressed ?? false, consentAt: u.emailPreference?.consentAt ?? null };
  const [latest, first, repo] = await Promise.all([
    prisma.scan.findFirst({ where: { userId, status: "completed", overallScore: { not: null } }, orderBy: [{ createdAt: "desc" }, { id: "desc" }], include: { vulnerabilities: true } }),
    prisma.scan.findFirst({ where: { userId, status: "completed", completedAt: { not: null } }, orderBy: [{ completedAt: "asc" }, { id: "asc" }], select: { completedAt: true } }),
    prisma.repoScan.findFirst({ where: { userId, status: "completed" }, orderBy: { createdAt: "desc" }, select: { id: true, result: true, visibility: true } }),
  ]);
  if (latest?.completedAt && first?.completedAt) {
    let domain: string; try { domain = hostnameKey(latest.url); } catch { return c; }
    const hostScans = (await prisma.scan.findMany({ where: { userId, status: "completed", url: { contains: domain, mode: "insensitive" } }, orderBy: [{ createdAt: "asc" }, { id: "asc" }], select: { id: true, url: true, userId: true, createdAt: true } })).filter(s => isSameHost(s.url, domain));
    const previousId = hostScans.filter(s => s.id !== latest.id && +s.createdAt <= +latest.createdAt).at(-1)?.id;
    const previous = previousId ? await prisma.scan.findUnique({ where: { id: previousId }, select: { vulnerabilities: true } }) : null;
    const actionable = latest.vulnerabilities.filter(f => isVisibleWebsiteFinding(f) && Object.hasOwn(ranks, f.severity) && f.type !== "seo");
    const access = applyWebsiteRemediationAccess(latest.vulnerabilities, "free");
    const selected = access.find(f => f.remediationAccess === "free" && isVisibleWebsiteFinding(f));
    const sorted = [...actionable].sort((a, b) => ranks[a.severity] - ranks[b.severity] || a.title.localeCompare(b.title));
    const toFinding = (f: typeof actionable[number]): EmailFinding => ({ title: safeText(f.title, 75), path: path(f.url), severity: f.severity, impact: findingImpact(f) });
    const decision = decideScanAccess({ userId, plan: u.plan, credits: u.credits, targetUrl: latest.url, priorFreeScans: hostScans, now });
    const comp = previous ? compareScanFindings(previous.vulnerabilities.filter(isVisibleWebsiteFinding), latest.vulnerabilities.filter(isVisibleWebsiteFinding)) : null;
    c.scan = { id: latest.id, domain, score: latest.overallScore!, createdAt: latest.createdAt, completedAt: latest.completedAt, anchor: new Date(Math.max(+first.completedAt, +u.createdAt)), openCount: actionable.length, lockedCount: access.filter(f => f.remediationAccess === "locked" && actionable.some(a => a.id === f.id)).length, critical: actionable.filter(f => f.severity === "critical").length, high: actionable.filter(f => f.severity === "high").length, medium: actionable.filter(f => f.severity === "medium").length, top: selected ? toFinding(selected) : sorted[0] ? toFinding(sorted[0]) : undefined, top3: sorted.slice(0, 3).map(toFinding), rescanAvailable: decision.allowed && decision.kind === "verification", deadline: new Date(+(hostScans[0]?.createdAt || latest.createdAt) + VERIFICATION_WINDOW_MS), rescanned: !!previous, resolved: comp?.resolved.length || 0, added: comp?.added.length || 0, stillOpen: comp?.stillOpen || 0 };
  }
  if (repo) {
    const result = repo.result as { findings?: Array<{ title?: string; file?: string; line?: number; severity?: string; description?: string; source?: string }> } | null;
    const findings = Array.isArray(result?.findings) ? result.findings.filter(f => typeof f.title === "string" && Object.hasOwn(ranks, f.severity || "")) : [];
    findings.sort((a, b) => ranks[a.severity!] - ranks[b.severity!]); const f = findings[0];
    c.repo = { id: repo.id, visibility: repo.visibility, count: findings.length, top: f ? { title: safeText(f.title, 75), path: safeText(`${f.file || "see report"}:${Number.isInteger(f.line) ? f.line : ""}`, 75), severity: f.severity!, impact: f.source === "ai" ? "This AI finding needs verification against the code before you treat it as a confirmed issue." : findingImpact(f) } : undefined };
  }
  return c;
}
