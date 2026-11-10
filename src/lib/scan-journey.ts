import { validPendingScanId } from "@/lib/scan-auth-return";

export interface ScanLimit {
  message: string;
  rateLimited: boolean;
  retryMinutes?: number;
}

/** Admission denials are recoverable next steps, not failed scanner execution. */
export function scanLimit(status: number, message: string, retryAfter?: string | null): ScanLimit | null {
  if (status !== 403 && status !== 429) return null;
  const seconds = Number(retryAfter);
  return {
    message,
    rateLimited: status === 429,
    ...(status === 429 && Number.isFinite(seconds) && seconds > 0 ? {retryMinutes: Math.ceil(seconds / 60)} : {}),
  };
}

export function reportReturnHref(scanId: string, finding: string | null = null) {
  const id = validPendingScanId(scanId);
  const selected = validPendingScanId(finding);
  return id ? `/scan/${id}${selected ? `#finding-${selected}` : ""}` : "/dashboard";
}

/** Legacy callers now open the report rather than forcing a repo/paywall redirect. */
export function deeperScanAuthHref(scanId: string, mode: "register" | "login" = "register") {
  return authPageHref(mode, {scanId});
}

export function validPendingPlan(value: string | null) {
  return value === "starter" || value === "pro" ? value : null;
}

export function authReturnHref(scanId: string | null, finding: string | null, plan: string | null, fallback: string) {
  if (validPendingScanId(scanId)) return reportReturnHref(scanId!, finding);
  const paidPlan = validPendingPlan(plan);
  return paidPlan ? `/pricing?checkout=${paidPlan}#paid-plans` : fallback;
}

/** Checkout intent belongs to the current URL, never an old browser-wide value. */
export function authPageHref(mode: "register" | "login", input: {scanId?: string | null; finding?: string | null; plan?: string | null; redirect?: string | null}) {
  const query = new URLSearchParams();
  const scan = validPendingScanId(input.scanId);
  if (scan) {
    query.set("scan", scan);
    const finding = validPendingScanId(input.finding);
    if (finding) query.set("finding", finding);
  } else if (validPendingPlan(input.plan ?? null)) query.set("plan", input.plan!);
  else if (input.redirect?.startsWith("/") && !input.redirect.startsWith("//")) query.set("redirect", input.redirect);
  return `/${mode}${query.size ? `?${query}` : ""}`;
}

export function websiteScanReturnHref(target: string) {
  try {
    const url = new URL(/^https?:\/\//i.test(target) ? target : `https://${target}`);
    if (!['http:', 'https:'].includes(url.protocol) || url.username || url.password) return "/free-website-vulnerability-scanner#scan";
    return `/free-website-vulnerability-scanner?url=${encodeURIComponent(url.href)}#scan`;
  } catch { return "/free-website-vulnerability-scanner#scan"; }
}

/** Public preview uses only already-public titles/severity, never locked details. */
export function previewFindingTitles(findings: Array<{title: string; severity: string}>) {
  const order = ['critical', 'high', 'medium', 'low', 'info'];
  const seen = new Set<string>();
  return [...findings].sort((a,b) => order.indexOf(a.severity) - order.indexOf(b.severity)).filter(f => {
    if (seen.has(f.title)) return false;
    seen.add(f.title); return true;
  }).slice(0,3).map(({title,severity}) => ({title,severity}));
}
