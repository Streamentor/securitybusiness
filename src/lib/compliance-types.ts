import { notChecked, type CheckItem, type NotCheckedReason } from "./website-check-state.ts";

/** Finding types for privacy, consent and accessibility checks. Safe to import in client code. */
export const COMPLIANCE_TYPES = ["privacy", "cookies-consent", "accessibility"] as const;
export type ComplianceType = (typeof COMPLIANCE_TYPES)[number];

export function isComplianceFinding(finding: { type: string }) {
  return (COMPLIANCE_TYPES as readonly string[]).includes(finding.type);
}

export const COMPLIANCE_DISCLAIMER = "Automated checks of the public site. Not legal advice: obligations depend on your country, company size and the data you process.";

/** Stored as a scan-meta row so the report can say which compliance checks ran. */
export const COMPLIANCE_COVERAGE_TITLE = "Compliance coverage";

export interface ComplianceCoverage {
  browser: "ran" | "plan" | "unavailable";
  ai: "ran" | "plan" | "off" | "unavailable" | "no-policy";
  policyUrl?: string;
  trackers: string[];
  checks?: CheckItem[];
  state?: "running" | "complete";
  deadline?: number;
}

export function pendingCompliance(deadline: number): ComplianceCoverage {
  return { state: "running", deadline, browser: "unavailable", ai: "unavailable", trackers: [] };
}

export function unavailableCompliance(reason: NotCheckedReason): ComplianceCoverage {
  return {
    state: "complete", browser: "unavailable", ai: "unavailable", trackers: [],
    checks: [
      ["policy", "Privacy policy"], ["terms", "Terms link"], ["accessibility", "HTML accessibility"],
      ["consent", "Browser consent"], ["ai", "AI privacy policy review"],
    ].map(([key, label]) => ({ key, label, ...notChecked(reason) })),
  };
}

export function parseComplianceCoverage(description: string | null | undefined): ComplianceCoverage | null {
  try {
    const parsed = JSON.parse(description || "") as Partial<ComplianceCoverage>;
    if (!parsed || typeof parsed !== "object" || typeof parsed.browser !== "string" || typeof parsed.ai !== "string") return null;
    if (parsed.state === "running" && (!parsed.deadline || parsed.deadline <= Date.now())) return unavailableCompliance("time_budget");
    return { ...parsed, policyUrl: typeof parsed.policyUrl === "string" ? parsed.policyUrl : undefined, trackers: Array.isArray(parsed.trackers) ? parsed.trackers.filter((item): item is string => typeof item === "string").slice(0, 30) : [] } as ComplianceCoverage;
  } catch { return null; }
}
