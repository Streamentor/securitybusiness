export type RemediationAccess = "free" | "paid" | "locked" | "none";

interface RemediationFinding {
  id: string;
  type: string;
  severity: string;
  title: string;
  url: string;
  remedy: string;
}

const suppressedLegacyTitles = new Set([
  "Missing X-XSS-Protection Header",
  "Missing Cache-Control for Sensitive Content",
  "Dangerous HTTP Methods Allowed",
  "API Docs Publicly Accessible",
  "External Iframes Without Sandbox",
  "Password Fields Allow Autocomplete",
  'target="_blank" Missing rel="noopener"',
  "Potential Open Redirect Parameters",
  "No WAF Detected",
]);

export function isVisibleWebsiteFinding(finding: Pick<RemediationFinding, "type" | "title">) {
  return !["scan-meta", "fingerprint", "waf"].includes(finding.type) && !suppressedLegacyTitles.has(finding.title);
}

const severityRank: Record<string, number> = { critical: 0, high: 1, medium: 2, low: 3 };
const categoryRank: Record<string, number> = { "sensitive-file": 0, xss: 1, cors: 2, "api-exposure": 3, ssl: 4, cookies: 5, csrf: 6, headers: 7, csp: 8, privacy: 10, "cookies-consent": 10, accessibility: 11 };

/** Server-side entitlement boundary: one stable actionable fix per free report. */
export function applyWebsiteRemediationAccess<T extends RemediationFinding>(findings: readonly T[], plan: unknown): Array<T & { remediationAccess: RemediationAccess }> {
  const paid = plan === "starter" || plan === "pro";
  const freeFinding = paid ? undefined : findings
    .filter((finding) => isVisibleWebsiteFinding(finding) && Object.hasOwn(severityRank, finding.severity) && finding.remedy.trim())
    .sort((left, right) => severityRank[left.severity] - severityRank[right.severity]
      || (categoryRank[left.type] ?? 9) - (categoryRank[right.type] ?? 9)
      || left.title.localeCompare(right.title)
      || left.url.localeCompare(right.url)
      || left.id.localeCompare(right.id))[0];
  const freeIndex = freeFinding ? findings.indexOf(freeFinding) : -1;

  return findings.map((finding, index) => {
    const remediationAccess: RemediationAccess = !finding.remedy.trim() ? "none" : paid ? "paid" : index === freeIndex ? "free" : "locked";
    return {
      ...finding,
      remediationAccess,
      remedy: remediationAccess === "free" || remediationAccess === "paid" ? finding.remedy : "",
    };
  });
}

/** A distinct boundary from paid fixes: anonymous previews disclose one real finding.
 * Locked rows use an allowlist so future evidence fields cannot accidentally leak.
 * Sharing links bypass this gate, but retain the existing plan-based fix boundary.
 */
export function serializeWebsiteFindings<T extends RemediationFinding>(findings: readonly T[], plan: unknown, requiresAccount: boolean) {
  const entitled = applyWebsiteRemediationAccess(findings, requiresAccount ? "free" : plan);
  if (!requiresAccount) return entitled;
  const visible = entitled.filter(isVisibleWebsiteFinding);
  const sample = visible.find(finding => finding.remediationAccess === "free")
    ?? [...visible].sort((a, b) => (severityRank[a.severity] ?? 4) - (severityRank[b.severity] ?? 4) || a.id.localeCompare(b.id))[0];
  return visible.map(finding => finding === sample ? {...finding, detailsLocked: false} : {
    id: finding.id, title: finding.title, severity: finding.severity,
    type: "account-locked", detailsLocked: true, remediationAccess: "locked" as const,
  });
}
