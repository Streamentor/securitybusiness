export const EMAIL_KEYS = ["welcome_report", "still_open", "clean_outside", "repo_gap", "repo_findings", "rescan_expiring", "what_paid_unlocks", "last_note", "first_scan_nudge", "first_scan_last"] as const;
export type EmailKey = typeof EMAIL_KEYS[number];
export interface EmailFinding { title: string; path: string; severity: string; impact: string }
export interface EmailContext {
  userId: string; email: string; name: string; plan: string; createdAt: Date; signupSource: string | null;
  optedOut: boolean; suppressed: boolean; consentAt: Date | null;
  scan?: { partial?: boolean; comparisonUnavailable?: boolean; id: string; domain: string; score: number; createdAt: Date; completedAt: Date; anchor: Date; openCount: number; lockedCount: number; critical: number; high: number; medium: number; top?: EmailFinding; top3: EmailFinding[]; rescanAvailable: boolean; deadline: Date; rescanned: boolean; resolved: number; stillOpen: number; added: number };
  repo?: { id: string; count: number; visibility: string; top?: EmailFinding };
}
export interface SendHistory { emailKey: string; createdAt: Date; status: string }
export interface RenderedEmail { subject: string; body: string; text: string; html: string; unsubscribeUrl: string }
