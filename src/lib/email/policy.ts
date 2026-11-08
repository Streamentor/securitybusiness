import { createHash } from "node:crypto";
import type { EmailContext, EmailKey, SendHistory } from "@/lib/email/types";
import { validEmail } from "@/lib/email/config";
export const DAY = 86_400_000;
export const MIN_GAP = 44 * 3_600_000;
export function eligible(c: EmailContext, start: Date | null): boolean {
  return !!start && +c.createdAt >= +start && c.plan === "free" && validEmail(c.email) && !c.optedOut && !c.suppressed && !!c.consentAt;
}
export function jitter(userId: string): number { return createHash("sha256").update(userId).digest().readUInt32BE(0) % 41; }
export function humanTime(c: Pick<EmailContext, "userId" | "createdAt">, earliest: Date): Date {
  const hour = c.createdAt.getUTCHours();
  const result = new Date(earliest); result.setUTCHours(hour < 6 ? 8 : hour, jitter(c.userId), 0, 0);
  if (+result < +earliest) result.setUTCDate(result.getUTCDate() + 1);
  return result;
}
/** The 44-hour cap wins over nominal day numbers. Slots expire rather than being shifted indefinitely. */
export function dueEmail(c: EmailContext, history: SendHistory[], now: Date): EmailKey | null {
  const consumed = history.filter(s => s.status !== "cancelled");
  if (consumed.length >= 6) return null;
  const latest = consumed.reduce((n, s) => Math.max(n, +s.createdAt), 0);
  if (latest && +now - latest < MIN_GAP) return null;
  const sent = (key: string) => consumed.some(s => s.emailKey === key);
  const signupHour = c.createdAt.getUTCHours();
  const isHumanHour = now.getUTCHours() === (signupHour < 6 ? 8 : signupHour) && now.getUTCMinutes() <= 40;
  if (!c.scan) {
    if (!isHumanHour) return null;
    for (const [key, day, end] of [["first_scan_nudge", 1, 4], ["first_scan_last", 4, 7]] as const) {
      const due = humanTime(c, new Date(+c.createdAt + day * DAY));
      if (!sent(key) && +now >= +due && +now < +c.createdAt + end * DAY) return key;
    }
    return null;
  }
  const s = c.scan;
  if (+s.anchor > +c.createdAt + 14 * DAY) return null;
  if (!sent("welcome_report") && +now >= +s.anchor && +now <= +s.anchor + 10 * 60_000) return "welcome_report";
  if (!isHumanHour) return null;
  const slots: Array<{ keys: EmailKey[]; day: number; end: number; pick: EmailKey | null }> = [
    { keys: ["still_open", "clean_outside"], day: 1, end: 3, pick: s.critical + s.high === 0 ? "clean_outside" : s.openCount >= 2 ? "still_open" : null },
    { keys: ["repo_gap", "repo_findings"], day: 3, end: 5, pick: c.repo ? c.repo.count > 0 ? "repo_findings" : null : sent("clean_outside") ? null : "repo_gap" },
    { keys: ["rescan_expiring"], day: 5, end: 7, pick: s.rescanAvailable && +s.deadline - +now >= DAY && +s.deadline - +now <= 3 * DAY && s.openCount > 0 ? "rescan_expiring" : null },
    { keys: ["what_paid_unlocks"], day: 8, end: 12, pick: s.openCount > 0 || c.repo ? "what_paid_unlocks" : null },
    { keys: ["last_note"], day: 14, end: 18, pick: s.openCount > 0 ? "last_note" : null },
  ];
  for (const slot of slots) {
    if (!slot.pick || slot.keys.some(sent)) continue;
    const earliest = Math.max(+s.anchor + slot.day * DAY, latest ? latest + MIN_GAP : 0);
    if (+now >= +humanTime(c, new Date(earliest)) && +now < +s.anchor + slot.end * DAY) return slot.pick;
  }
  return null;
}
