import type { VulnerabilityResult } from "./scanner";
import type { ReviewMeter } from "@/lib/ai-review";
import { checkCompliance, checkPolicyAgainstTrackers, findLegalPages, type CompliancePage, type TrackerSignature } from "@/lib/compliance";
import { runBrowserConsentCheck, type BrowserConsentResult, type BrowserOptions } from "@/lib/compliance-browser";
import { reviewPolicyWithAI } from "@/lib/compliance-ai";
import { COMPLIANCE_COVERAGE_TITLE, unavailableCompliance, type ComplianceCoverage } from "@/lib/compliance-types";
import { notChecked, type NotCheckedReason } from "@/lib/website-check-state";

export interface ComplianceRunnerOptions {
  /** The scanning user's plan. Starter and Pro get the browser consent test; Pro gets the AI policy review. */
  plan: string;
  /** Token meter for the AI policy review. Without it the review does not run. */
  aiMeter?: ReviewMeter | null;
  /** The user's AI review preference. */
  aiEnabled?: boolean;
}

export interface ComplianceRunner {
  findPrivacyLink(pages: CompliancePage[]): string | undefined;
  /** Starts the browser test early so it runs beside the HTTP checks. */
  start(homeUrl: string, browser: BrowserOptions): void;
  /** Runs the HTML checks, merges the browser result and returns findings plus one coverage row. */
  finish(input: { url: string; pages: CompliancePage[]; fetchHtml: (url: string) => Promise<CompliancePage | null>; failureFor: (url: string) => NotCheckedReason | undefined; remainingMs: () => number }): Promise<VulnerabilityResult[]>;
}

export function createComplianceRunner(options: ComplianceRunnerOptions): ComplianceRunner {
  const paid = options.plan === "starter" || options.plan === "pro";
  let browserCheck: Promise<BrowserConsentResult> | null = null;
  return {
    findPrivacyLink: (pages) => findLegalPages(pages).privacyUrl,
    start(homeUrl, browser) {
      if (!paid || process.env.COMPLIANCE_BROWSER === "false" || browserCheck) return;
      browserCheck = runBrowserConsentCheck(homeUrl, browser);
    },
    async finish({ url, pages, fetchHtml, failureFor, remainingMs }) {
      if (!pages.length) return [];
      let coverage: ComplianceCoverage = { state: "complete", browser: browserCheck || paid ? "unavailable" : "plan", ai: options.plan === "pro" ? "unavailable" : "plan", trackers: [] };
      const findings: VulnerabilityResult[] = [];
      try {
        const staticResult = await checkCompliance(url, pages, { fetchHtml, failureFor });
        const checks = staticResult.checks;
        coverage.checks = checks;
        findings.push(...staticResult.findings);
        const trackers: TrackerSignature[] = [...staticResult.trackers];
        const browser = browserCheck ? await browserCheck.catch(() => null) : null;
        if (browser?.status === "ran") {
          coverage.browser = "ran";
          findings.push(...browser.findings);
          checks.push(...(browser.checks ?? []));
          for (const tracker of browser.trackers) if (!trackers.includes(tracker)) trackers.push(tracker);
        }
        checks.push({ key: "consent", label: "Browser consent", ...(browser?.status === "ran"
          ? { status: browser.findings.some((finding) => finding.type === "cookies-consent") ? "issue" : "pass", detail: "A clean browser checked tracking cookies before any interaction." }
          : notChecked(!paid ? "plan" : process.env.COMPLIANCE_BROWSER === "false" ? "off" : browser?.reason ?? "error")) });
        coverage.trackers = trackers.map((tracker) => tracker.name);
        if (staticResult.policy) {
          coverage.policyUrl = staticResult.policy.url;
          findings.push(...checkPolicyAgainstTrackers(staticResult.policy, trackers));
          if (options.plan === "pro") {
            if (options.aiEnabled === false) coverage.ai = "off";
            else if (options.aiMeter && remainingMs() > 3_000) {
              const review = await reviewPolicyWithAI({ url: staticResult.policy.url, text: staticResult.policy.text, plan: options.plan, timeoutMs: Math.min(20_000, remainingMs() - 2_000) }, options.aiMeter);
              coverage.ai = review.status;
              if (review.finding) findings.push(review.finding);
            }
          }
        } else if (options.plan === "pro") {
          coverage.ai = "no-policy";
        }
        const policyCheck = checks.find((item) => item.key === "policy");
        checks.push({ key: "ai", label: "AI privacy policy review", ...(coverage.ai === "ran"
          ? { status: findings.some((finding) => finding.title.startsWith("AI policy review")) ? "issue" : "pass", detail: "The AI policy review completed." }
          : notChecked(coverage.ai === "plan" || coverage.ai === "off" ? coverage.ai : remainingMs() <= 3_000 ? "time_budget" : policyCheck?.status === "not_checked" ? policyCheck.reason : "error")) });
      } catch {
        coverage = unavailableCompliance(remainingMs() <= 0 ? "time_budget" : "error");
        findings.length = 0;
      }
      findings.push({ type: "scan-meta", severity: "info", title: COMPLIANCE_COVERAGE_TITLE, description: JSON.stringify(coverage), url, remedy: "" });
      return findings;
    },
  };
}
