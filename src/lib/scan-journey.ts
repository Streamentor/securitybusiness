import { validPendingScanId } from "./scan-auth-return";

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

export function reportReturnHref(scanId: string, intent: string | null) {
  const id = validPendingScanId(scanId);
  return id ? `/scan/${id}${intent === "deeper" ? "?next=repo" : ""}` : "/dashboard";
}

export function deeperScanAuthHref(scanId: string, mode: "register" | "login" = "register") {
  const id = validPendingScanId(scanId);
  return id ? `/${mode}?scan=${id}&intent=deeper` : `/${mode}`;
}

export function validPendingPlan(value: string | null) {
  return value === "starter" || value === "pro" ? value : null;
}

export function authReturnHref(scanId: string | null, intent: string | null, plan: string | null, fallback: string) {
  const paidPlan = validPendingPlan(plan);
  if (paidPlan) return `/pricing?checkout=${paidPlan}#plans`;
  return scanId ? reportReturnHref(scanId, intent) : fallback;
}
