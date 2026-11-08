import { DAY, dueEmail, eligibilityReason, humanTime, MIN_GAP } from "@/lib/email/policy";
import { EMAIL_KEYS, type EmailContext, type EmailKey, type SendHistory } from "@/lib/email/types";
import type { SequenceMode } from "@/lib/email/config";
export const EMAIL_NAMES: Record<EmailKey, string> = {
  welcome_report: "Report saved", still_open: "Priority website findings", clean_outside: "Check the code behind a clean website",
  repo_gap: "Repository invitation", repo_findings: "Repository findings", rescan_expiring: "Verification rescan reminder",
  what_paid_unlocks: "Paid plan features", last_note: "Final report follow-up", first_scan_nudge: "First website scan reminder", first_scan_last: "Final first-scan reminder",
};
/** A forecast, not a queued promise: calls the sender's actual policy at cron ticks. */
export function nextEmail(c: EmailContext, history: SendHistory[], now: Date) {
  if (history.filter(s => s.status !== "cancelled").length >= 6 || (!c.scan && c.repo)) return null;
  const due = dueEmail(c, history, now);
  if (due) return { key: due, at: now.toISOString(), due: true };
  const tick = 10 * 60_000;
  for (let time = Math.ceil((+now + 1) / tick) * tick; time <= +now + 20 * DAY; time += tick) {
    const at = new Date(time); if (at.getUTCMinutes() > 40) continue;
    const key = dueEmail(c, history, at);
    if (key) return { key, at: at.toISOString(), due: false };
  }
  return null;
}
export function emailJourney(c: EmailContext, history: SendHistory[], now: Date, start: Date | null, mode: SequenceMode) {
  const blocked = eligibilityReason(c, start);
  const consumed = history.filter(s => s.status !== "cancelled");
  const next = blocked ? null : nextEmail(c, history, now);
  const last = consumed.reduce((n, s) => Math.max(n, +s.createdAt), 0);
  const s = c.scan;
  const websiteDays: Partial<Record<EmailKey, [number, number]>> = { still_open: [1, 3], clean_outside: [1, 3], repo_gap: [3, 5], repo_findings: [3, 5], rescan_expiring: [5, 7], what_paid_unlocks: [8, 12], last_note: [14, 18] };
  const steps = EMAIL_KEYS.map(key => {
    const entry = history.find(h => h.emailKey === key);
    if (entry) return { key, name: EMAIL_NAMES[key], state: entry.status, at: entry.createdAt.toISOString(), reason: entry.status === "unknown" ? "Provider outcome is unknown. This message is not retried automatically." : "Recorded send history" };
    let reason = "", end: number | null = null, begins: number | null = null;
    if (!s) {
      if (c.repo) reason = "Repository already scanned; first-scan reminders are unnecessary";
      else if (key === "first_scan_nudge" || key === "first_scan_last") {
        const day = key === "first_scan_nudge" ? 1 : 4;
        begins = +humanTime(c, new Date(+c.createdAt + day * DAY)); end = +c.createdAt + (day === 1 ? 4 : 7) * DAY;
      } else reason = "Requires a completed website scan";
    } else if (key.startsWith("first_scan_")) reason = "Website already scanned";
    else if (+s.anchor > +c.createdAt + 14 * DAY) reason = "First scan was outside the 14-day enrollment window";
    else if (key === "welcome_report") { begins = +s.anchor; end = +s.anchor + 10 * 60_000; }
    else {
      const range = websiteDays[key]!; begins = +s.anchor + range[0] * DAY; end = +s.anchor + range[1] * DAY;
      if (key === "still_open" && (s.critical + s.high === 0 || s.openCount < 2)) reason = "Needs at least two open issues and a critical or high finding";
      if (key === "clean_outside" && (s.critical + s.high > 0 || c.repo)) reason = c.repo ? "Repository already scanned; no repeat invitation" : "Website has critical or high findings";
      if (key === "repo_gap" && (c.repo || consumed.some(h => h.emailKey === "clean_outside"))) reason = c.repo ? "Repository already scanned" : "Repository invitation was already included in the clean-outside email";
      if (key === "repo_findings" && !c.repo?.count) reason = "No completed repository scan with findings";
      if (["repo_gap", "repo_findings"].includes(key) && consumed.some(h => ["repo_gap", "repo_findings"].includes(h.emailKey))) reason = "This sequence slot was already used by its alternative";
      if (["still_open", "clean_outside"].includes(key) && consumed.some(h => ["still_open", "clean_outside"].includes(h.emailKey))) reason = "This sequence slot was already used by its alternative";
      if (key === "rescan_expiring" && (!s.rescanAvailable || s.openCount < 1)) reason = "No unused verification rescan with open findings";
      if (key === "rescan_expiring" && +s.deadline - +now < DAY) reason = "Less than one day remains in the verification window";
      if (key === "what_paid_unlocks" && s.openCount < 1 && !c.repo) reason = "No website findings or completed repository scan";
      if (key === "last_note" && s.openCount < 1) reason = "No actionable website findings";
    }
    if (reason) return { key, name: EMAIL_NAMES[key], state: "skipped", at: null, reason };
    if (blocked) return { key, name: EMAIL_NAMES[key], state: "blocked", at: null, reason: blocked };
    if (consumed.length >= 6) return { key, name: EMAIL_NAMES[key], state: "skipped", at: null, reason: "Six-message lifetime limit reached" };
    if (end !== null && +now >= end) return { key, name: EMAIL_NAMES[key], state: "expired", at: null, reason: "Send window passed; messages do not pile up" };
    if (next?.key === key) return { key, name: EMAIL_NAMES[key], state: mode === "live" ? next.due ? "due" : "scheduled" : "paused", at: next.at, reason: mode === "live" ? "Next eligible check, subject to fresh data and rate limits" : `Mode is ${mode}; no customer delivery` };
    return { key, name: EMAIL_NAMES[key], state: "conditional", at: begins ? new Date(begins).toISOString() : null, reason: "Re-evaluated from current scan data when its window opens; not queued" };
  });
  return {
    state: blocked ? "excluded" : consumed.length >= 6 ? "complete" : mode !== "live" ? "paused" : next ? next.due ? "due" : "waiting" : "complete",
    reason: blocked || (consumed.length >= 6 ? "Six-message limit reached" : mode !== "live" ? `Mode is ${mode}` : next ? "Next step uses current scan data" : "No remaining eligible messages with current scan data"),
    used: consumed.length, maximum: 6, next, cooldownUntil: last ? new Date(last + MIN_GAP).toISOString() : null, steps,
  };
}
