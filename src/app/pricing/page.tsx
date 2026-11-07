"use client";

import { useState } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import { ArrowRight, Check, ChevronDown, Loader2, Minus, ShieldCheck, Sparkles, Zap } from "lucide-react";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";
import { ToastContainer, toast } from "@/components/Toast";

const plans = [
  {
    name: "Free",
    key: null,
    price: "$0",
    cadence: "once",
    summary: "Find an issue and try one practical fix.",
    credits: "1 scan credit",
    rollover: "—",
    accent: false,
    features: ["Up to 25 pages", "60+ automated checks", "Security score", "Prioritized findings", "One actionable fix, when found", "One free rescan to verify your fix", "Public GitHub repository scans"],
    cta: "Run the free scan",
  },
  {
    name: "Starter",
    key: "starter",
    price: "$29",
    cadence: "per month",
    summary: "For a founder shipping one or two products.",
    credits: "10 credits / month",
    rollover: "Up to 20",
    accent: true,
    features: ["Everything in Free", "Private GitHub repository scans (read-only)", "AI logic review (monthly token limits)", "Step-by-step remediation", "Resolved / new findings after each rescan", "Scan history and score trends", "Credits roll over"],
    cta: "Choose Starter",
  },
  {
    name: "Pro",
    key: "pro",
    price: "$79",
    cadence: "per month",
    summary: "For teams checking multiple apps and environments.",
    credits: "30 credits / month",
    rollover: "Up to 60",
    accent: false,
    features: ["Everything in Starter", "30 monthly credits", "Private GitHub repository scans (read-only)", "Background scans saved to your dashboard", "Step-by-step remediation", "Score trends"],
    cta: "Choose Pro",
  },
];

const faqs = [
  ["What counts as a scan credit?", "One credit runs a new crawl and security report for one website. A scan can cover up to 25 reachable pages on that site."],
  ["Do unused credits roll over?", "Yes. Starter can hold up to 20 credits and Pro can hold up to 60. New monthly credits are added up to that cap."],
  ["Why pay if the first report is free?", "The free report shows the score, affected URLs, severity, and descriptions, plus one prioritized fix when an actionable finding is available. Paid plans unlock remediation for the remaining findings and give you credits to verify fixes over time."],
  ["How does private repository access work?", "You install the ScanMySaaS GitHub App on the repositories you choose. It can only read repository contents and metadata. Files are read in memory for the scan and discarded; only the report is saved, and it is visible only to your account. You can revoke access on GitHub at any time."],
  ["How does AI logic review handle my code?", "On Starter and Pro, selected source files are sent to OpenAI for analysis using store: false. AI findings need verification. You can opt out in your dashboard; rule-based scans still run. Input and monthly token budgets apply, with a higher monthly budget on Pro. If AI is unavailable or the budget is exhausted, your rule-based report still completes."],
  ["Can I change or cancel my plan?", "Yes. Subscribers can open the Stripe billing portal from the dashboard to manage or cancel billing."],
  ["Is the result a security certification?", "No. It is an automated outside-in assessment, not a certification or penetration test. Use it as a fast feedback layer in a broader security process."],
];

export default function PricingPage() {
  const { data: session } = useSession();
  const router = useRouter();
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);

  async function handleSubscribe(planKey: string | null) {
    if (!planKey) {
      router.push("/#scan");
      return;
    }
    if (!session?.user) {
      localStorage.setItem("pendingPlan", planKey);
      router.push("/register");
      return;
    }
    setLoadingPlan(planKey);
    try {
      const response = await fetch("/api/stripe/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan: planKey }),
      });
      const data = await response.json();
      if (data.url) window.location.href = data.url;
      else toast(data.error || "Checkout could not be started.", "error");
    } catch {
      toast("Checkout could not be started. Please try again.", "error");
    } finally {
      setLoadingPlan(null);
    }
  }

  return (
    <main>
      <SiteHeader />
      <ToastContainer />
      <section className="relative overflow-hidden pb-16 pt-20 text-center sm:pb-20 sm:pt-28">
        <div className="pointer-events-none absolute inset-0 -z-10 hairline-grid [mask-image:radial-gradient(circle_at_top,black,transparent_70%)]" />
        <div className="app-shell">
          <p className="eyebrow">Simple monthly plans</p>
          <h1 className="section-title mx-auto mt-5 max-w-4xl text-balance sm:!text-[4.8rem]">Pay for scans, not security theater.</h1>
          <p className="mx-auto mt-6 max-w-2xl text-pretty text-lg leading-8 text-[#98a2b3]">Start with a free scan and one actionable fix when an issue is found. Upgrade for guidance across the report and credits to check each release.</p>
          <div className="mx-auto mt-7 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5 text-xs text-[#aab3bf]"><ShieldCheck className="h-3.5 w-3.5 text-[var(--signal)]" /> Existing subscriber prices stay unchanged</div>
        </div>
      </section>

      <section className="app-shell pb-24">
        <div className="grid gap-4 lg:grid-cols-3">
          {plans.map((plan) => (
            <article key={plan.name} className={`relative flex min-h-[34rem] flex-col overflow-hidden rounded-2xl p-6 sm:p-7 ${plan.accent ? "border border-[var(--signal)]/40 bg-[var(--signal)]/[0.055] shadow-[0_22px_80px_rgba(185,255,102,.08)]" : "surface-muted"}`}>
              {plan.accent && <div className="absolute right-5 top-5 rounded-full bg-[var(--signal)] px-2.5 py-1 text-[0.65rem] font-bold uppercase tracking-[.1em] text-[#0a0d0b]">Most popular</div>}
              <div className="flex h-10 w-10 items-center justify-center rounded-xl border border-white/10 bg-white/[0.04]">{plan.name === "Free" ? <ShieldCheck className="h-5 w-5 text-[#aab3bf]" /> : plan.name === "Starter" ? <Zap className="h-5 w-5 text-[var(--signal)]" /> : <Sparkles className="h-5 w-5 text-[var(--cobalt)]" />}</div>
              <h2 className="mt-6 text-xl font-semibold">{plan.name}</h2>
              <p className="mt-2 min-h-12 text-sm leading-6 text-[#8f99a7]">{plan.summary}</p>
              <div className="mt-7 flex items-end gap-2"><span className="text-5xl font-semibold tracking-[-0.06em]">{plan.price}</span><span className="pb-1 text-xs text-[#7c8796]">{plan.cadence}</span></div>
              <div className="mt-7 border-y border-white/[0.08] py-4"><p className="text-sm font-semibold text-white">{plan.credits}</p><p className="mt-1 text-xs text-[#707b8a]">Rollover: {plan.rollover}</p></div>
              <ul className="mt-6 space-y-3 text-sm text-[#aeb7c4]">
                {plan.features.map((feature) => <li key={feature} className="flex gap-2.5"><Check className="mt-0.5 h-4 w-4 shrink-0 text-[var(--signal)]" />{feature}</li>)}
              </ul>
              <button onClick={() => handleSubscribe(plan.key)} disabled={loadingPlan !== null && loadingPlan === plan.key} className={`${plan.accent ? "button-primary" : "button-secondary"} mt-auto w-full`}>
                {loadingPlan !== null && loadingPlan === plan.key ? <Loader2 className="h-4 w-4 animate-spin" /> : <>{plan.cta}<ArrowRight className="h-4 w-4" /></>}
              </button>
            </article>
          ))}
        </div>

        <div className="mt-16 overflow-hidden rounded-2xl border border-white/[0.08]">
          <div className="border-b border-white/[0.08] bg-white/[0.025] px-6 py-5"><h2 className="text-lg font-semibold">What changes when you upgrade</h2><p className="mt-1 text-sm text-[#7f8998]">Paid plans add AI logic review of selected repository files, alongside remediation and repeat checks.</p></div>
          <div className="overflow-x-auto">
            <table className="w-full min-w-[42rem] text-left text-sm">
              <thead className="text-xs text-[#778191]"><tr><th className="px-6 py-4 font-medium">Capability</th><th className="px-5 py-4 font-medium">Free</th><th className="px-5 py-4 font-medium">Starter</th><th className="px-5 py-4 font-medium">Pro</th></tr></thead>
              <tbody className="divide-y divide-white/[0.07] text-[#aeb7c4]">
                {[
                  ["Monthly credits", "1 once", "10", "30"],
                  ["Pages per scan", "25", "25", "25"],
                  ["Finding descriptions", true, true, true],
                  ["Step-by-step remediation", "One finding", "All findings", "All findings"],
                  ["Saved scan history", true, true, true],
                  ["Free verification rescan", "Within 7 days", "Uses credits", "Uses credits"],
                  ["Public GitHub repository scans", true, true, true],
                  ["Private GitHub repository scans", false, true, true],
                  ["AI logic review", false, "Monthly token limit", "Higher monthly token limit"],
                  ["Credit rollover", false, "20 max", "60 max"],
                ].map((row) => <tr key={String(row[0])}>{row.map((value, index) => <td key={index} className={index === 0 ? "px-6 py-4 font-medium text-white" : "px-5 py-4"}>{typeof value === "boolean" ? value ? <Check className="h-4 w-4 text-[var(--signal)]" /> : <Minus className="h-4 w-4 text-[#4c5664]" /> : value}</td>)}</tr>)}
              </tbody>
            </table>
          </div>
        </div>
      </section>

      <section className="border-t border-white/[0.07] bg-[#0a0e14] py-24">
        <div className="app-shell grid gap-12 lg:grid-cols-[0.7fr_1.3fr] lg:gap-20">
          <div><p className="eyebrow">Pricing FAQ</p><h2 className="section-title mt-4">No fine print.</h2></div>
          <div className="divide-y divide-white/[0.08] border-y border-white/[0.08]">
            {faqs.map(([question, answer]) => <details key={question} className="group py-5"><summary className="flex cursor-pointer list-none items-center justify-between gap-4 font-medium"><span>{question}</span><ChevronDown className="h-4 w-4 text-[#727d8c] transition group-open:rotate-180" /></summary><p className="max-w-2xl pt-4 text-sm leading-7 text-[#8f99a7]">{answer}</p></details>)}
          </div>
        </div>
      </section>
      <SiteFooter />
    </main>
  );
}
