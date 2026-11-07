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
const categoryRank: Record<string, number> = { "sensitive-file": 0, xss: 1, cors: 2, "api-exposure": 3, ssl: 4, cookies: 5, csrf: 6, headers: 7, csp: 8 };

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
