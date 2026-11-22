export type NotCheckedReason = "time_budget" | "blocked" | "timeout" | "redirect_offsite" | "error" | "plan" | "off" | "not_applicable";

export const checkReasonLabel: Record<NotCheckedReason, string> = {
  time_budget: "The scan reached its time limit.",
  blocked: "The website blocked the request.",
  timeout: "The request timed out.",
  redirect_offsite: "The request redirected to a different site.",
  error: "The check could not complete.",
  plan: "This check is outside the scan's plan.",
  off: "This check was turned off.",
  not_applicable: "The signal needed to run this check was not observed.",
};

export type CheckState =
  | { status: "pass" | "issue"; detail: string }
  | { status: "not_checked"; reason: NotCheckedReason; detail: string };

export function notChecked(reason: NotCheckedReason): CheckState & { status: "not_checked" } {
  return { status: "not_checked", reason, detail: checkReasonLabel[reason] };
}

export type CheckItem = CheckState & { key: string; label: string; url?: string };
