import type { VulnerabilityResult } from "./scanner";
import type { ReviewMeter } from "@/lib/ai-review";
import { checkCompliance, checkPolicyAgainstTrackers, type CompliancePage, type TrackerSignature } from "@/lib/compliance";
import { runBrowserConsentCheck, type BrowserConsentResult } from "@/lib/compliance-browser";
import { reviewPolicyWithAI } from "@/lib/compliance-ai";
import { COMPLIANCE_COVERAGE_TITLE, type ComplianceCoverage } from "@/lib/compliance-types";

export interface ComplianceRunnerOptions {
  /** The scanning user's plan. Starter and Pro get the browser consent test; Pro gets the AI policy review. */
  plan: string;
  /** Token meter for the AI policy review. Without it the review does not run. */
  aiMeter?: ReviewMeter | null;
  /** The user's AI review preference. */
  aiEnabled?: boolean;
}

export interface ComplianceRunner {
  /** Starts the browser test early so it runs beside the HTTP checks. */
  start(homeUrl: string, browser: { timeoutMs: number; assertPublicHost: (hostname: string) => Promise<void> }): void;
  /** Runs the HTML checks, merges the browser result and returns findings plus one coverage row. */
  finish(input: { url: string; pages: CompliancePage[]; fetchHtml: (url: string) => Promise<CompliancePage | null>; remainingMs: () => number }): Promise<VulnerabilityResult[]>;
}

export function createComplianceRunner(options: ComplianceRunnerOptions): ComplianceRunner {
  const paid = options.plan === "starter" || options.plan === "pro";
  let browserCheck: Promise<BrowserConsentResult> | null = null;
  return {
    start(homeUrl, browser) {
      if (!paid || process.env.COMPLIANCE_BROWSER === "false" || browserCheck) return;
      browserCheck = runBrowserConsentCheck(homeUrl, browser);
    },
    async finish({ url, pages, fetchHtml, remainingMs }) {
      if (!pages.length) return [];
      const coverage: ComplianceCoverage = { browser: browserCheck ? "unavailable" : "plan", ai: options.plan === "pro" ? "unavailable" : "plan", trackers: [] };
      const findings: VulnerabilityResult[] = [];
      try {
        const staticResult = await checkCompliance(url, pages, { fetchHtml });
        findings.push(...staticResult.findings);
        const trackers: TrackerSignature[] = [...staticResult.trackers];
        const browser = browserCheck ? await browserCheck.catch(() => null) : null;
        if (browser?.status === "ran") {
          coverage.browser = "ran";
          // A real browser sees JavaScript-rendered banners, so it replaces the HTML-only guess.
          if (staticResult.noConsentToolFinding) findings.splice(findings.indexOf(staticResult.noConsentToolFinding), 1);
          findings.push(...browser.findings);
          for (const tracker of browser.trackers) if (!trackers.includes(tracker)) trackers.push(tracker);
        }
        coverage.trackers = trackers.map((tracker) => tracker.name);
        if (staticResult.policy) {
          coverage.policyUrl = staticResult.policy.url;
          findings.push(...checkPolicyAgainstTrackers(staticResult.policy, trackers));
          if (options.plan === "pro") {
            if (options.aiEnabled === false) coverage.ai = "off";
            else if (options.aiMeter) {
              const review = await reviewPolicyWithAI({ url: staticResult.policy.url, text: staticResult.policy.text, plan: options.plan, timeoutMs: Math.min(20_000, remainingMs() - 2_000) }, options.aiMeter);
              coverage.ai = review.status;
              if (review.finding) findings.push(review.finding);
            }
          }
        } else if (options.plan === "pro") {
          coverage.ai = "no-policy";
        }
      } catch {
        // Compliance checks never fail the security scan.
      }
      findings.push({ type: "scan-meta", severity: "info", title: COMPLIANCE_COVERAGE_TITLE, description: JSON.stringify(coverage), url, remedy: "" });
      return findings;
    },
  };
}
