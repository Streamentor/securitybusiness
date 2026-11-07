/**
 * Pure access rules for website scans. Database reads happen in the route;
 * everything here is deterministic so it can be verified with fixtures.
 */

export const VERIFICATION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
/** Distinct free accounts that may each spend their own free credit on one hostname. */
export const MAX_FREE_ACCOUNTS_PER_HOST = 3;

export interface PriorScan {
  userId: string | null;
  url: string;
  createdAt: Date;
}

export type ScanAccessDecision =
  | { allowed: true; kind: "first" | "verification" | "paid"; consumesCredit: boolean }
  | { allowed: false; status: 403; error: string };

/** Exact hostname key: lowercase, without a leading "www.". */
export function hostnameKey(url: string): string {
  return new URL(url).hostname.toLowerCase().replace(/^www\./, "");
}

export function isSameHost(url: string, key: string): boolean {
  try { return hostnameKey(url) === key; } catch { return false; }
}

const NO_CREDITS = "No scan credits remaining. Please upgrade your plan.";

export function decideScanAccess(input: {
  userId: string | null;
  plan: string;
  credits: number;
  targetUrl: string;
  /** Completed scans by anonymous or free users whose URL may contain the hostname. */
  priorFreeScans: PriorScan[];
  now: Date;
}): ScanAccessDecision {
  const { userId, plan, credits, targetUrl, now } = input;
  if (plan === "starter" || plan === "pro") {
    return credits > 0 ? { allowed: true, kind: "paid", consumesCredit: true } : { allowed: false, status: 403, error: NO_CREDITS };
  }

  const key = hostnameKey(targetUrl);
  // The database filter is a substring match; only exact hostnames count.
  const prior = input.priorFreeScans.filter((scan) => isSameHost(scan.url, key));

  if (!userId) {
    if (prior.length) {
      return { allowed: false, status: 403, error: "This domain was already scanned on a free plan. Sign in to use your own free scan, or upgrade to Starter or Pro for monthly scan credits." };
    }
    return { allowed: true, kind: "first", consumesCredit: false };
  }

  const own = prior.filter((scan) => scan.userId === userId);
  if (own.length) {
    const first = own.reduce((oldest, scan) => scan.createdAt < oldest.createdAt ? scan : oldest);
    const withinWindow = now.getTime() - first.createdAt.getTime() <= VERIFICATION_WINDOW_MS;
    if (own.length === 1 && withinWindow) return { allowed: true, kind: "verification", consumesCredit: false };
    return {
      allowed: false,
      status: 403,
      error: withinWindow
        ? "You already used the free verification rescan for this domain. Upgrade to Starter or Pro to keep scanning it."
        : "The free verification rescan is available for 7 days after your first scan. Upgrade to Starter or Pro to scan this domain again.",
    };
  }

  if (credits <= 0) return { allowed: false, status: 403, error: NO_CREDITS };
  const otherAccounts = new Set(prior.filter((scan) => scan.userId).map((scan) => scan.userId));
  if (otherAccounts.size >= MAX_FREE_ACCOUNTS_PER_HOST) {
    return { allowed: false, status: 403, error: "This domain has reached its free scan limit. Upgrade to Starter or Pro for monthly scan credits you can use on any domain." };
  }
  return { allowed: true, kind: "first", consumesCredit: true };
}

// ── Rate limiting (per server instance; complements, not replaces, edge limits) ──

const WINDOW_MS = 60 * 60 * 1000;
const LIMITS = { anonymous: 3, user: 20 } as const;
const attempts = new Map<string, number[]>();

export function allowScanRequest(identity: string, kind: keyof typeof LIMITS, now = Date.now()): boolean {
  const key = `${kind}:${identity}`;
  const recent = (attempts.get(key) || []).filter((time) => now - time < WINDOW_MS);
  if (recent.length >= LIMITS[kind]) {
    attempts.set(key, recent);
    return false;
  }
  recent.push(now);
  attempts.set(key, recent);
  if (attempts.size > 5_000) {
    for (const [entry, times] of attempts) if (!times.some((time) => now - time < WINDOW_MS)) attempts.delete(entry);
  }
  return true;
}
