"use client";

import Link from "next/link";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import { motion } from "framer-motion";
import {
  Shield,
  CheckCircle2,
  ArrowRight,
  Star,
  Sparkles,
  Zap,
  ArrowLeft,
  HelpCircle,
  Loader2,
  LayoutDashboard,
} from "lucide-react";
import { useState } from "react";

const plans = [
  {
    name: "Free",
    planKey: null,
    price: "$0",
    period: "forever",
    description: "Try SecureSaaS and scan your first site",
    credits: "1 free scan",
    features: [
      "1 scan credit (one-time)",
      "Up to 25 pages per scan",
      "60+ vulnerability checks",
      "Security score & severity breakdown",
      "Vulnerability descriptions",
    ],
    limitations: [
      "Fix suggestions locked",
      "No PDF export",
      "No scheduled scans",
    ],
    cta: "Start Free",
    popular: false,
    icon: Shield,
  },
  {
    name: "Starter",
    planKey: "starter",
    price: "$29",
    period: "/month",
    description: "For indie hackers & small SaaS teams",
    credits: "10 scan credits / month",
    features: [
      "10 scan credits per month",
      "Up to 25 pages per scan",
      "60+ vulnerability checks",
      "Security score & severity breakdown",
      "Vulnerability descriptions",
      "✨ Fix suggestions & remedies",
      "✨ PDF report export",
      "Email notifications",
      "Credits roll over (max 20)",
    ],
    limitations: [],
    cta: "Get Starter",
    popular: true,
    icon: Zap,
  },
  {
    name: "Pro",
    planKey: "pro",
    price: "$79",
    period: "/month",
    description: "For growing SaaS businesses",
    credits: "30 scan credits / month",
    features: [
      "30 scan credits per month",
      "Up to 50 pages per scan",
      "60+ vulnerability checks",
      "Security score & severity breakdown",
      "Vulnerability descriptions",
      "✨ Fix suggestions & remedies",
      "✨ PDF report export",
      "✨ API access",
      "✨ Scheduled weekly scans",
      "✨ Slack & webhook alerts",
      "✨ Team access (up to 5 seats)",
      "Priority scanning queue",
      "Credits roll over (max 60)",
    ],
    limitations: [],
    cta: "Go Pro",
    popular: false,
    icon: Sparkles,
  },
];

const faqs = [
  {
    q: "What is a scan credit?",
    a: "One scan credit lets you run a full security scan on one website URL. Each scan crawls up to 25 pages (or 50 on Pro) and runs 60+ security checks.",
  },
  {
    q: "Do credits roll over?",
    a: "Yes! Unused credits roll over to the next month, up to 2x your monthly allowance. Starter can bank up to 20 credits, Pro up to 60.",
  },
  {
    q: "I only have one SaaS — do I need many credits?",
    a: "Most SaaS founders scan after each major deploy. With Starter's 10 credits/month, you can scan weekly with room to spare. Credits also work for scanning staging environments.",
  },
  {
    q: "Can I buy extra credits?",
    a: "Coming soon! We'll offer credit top-ups at $3/scan for Starter and $2.50/scan for Pro users.",
  },
  {
    q: "What's the difference between Free and paid plans?",
    a: "Free gives you the full scan with vulnerability descriptions and severity ratings. Paid plans unlock fix suggestions (how to actually resolve each issue), PDF exports, and advanced features.",
  },
  {
    q: "Can I cancel anytime?",
    a: "Absolutely. No contracts, no commitments. Cancel anytime and keep access until the end of your billing period.",
  },
];

export default function PricingPage() {
  const [openFaq, setOpenFaq] = useState<number | null>(null);
  const [loadingPlan, setLoadingPlan] = useState<string | null>(null);
  const { data: session } = useSession();
  const router = useRouter();

  async function handleSubscribe(planKey: string | null) {
    if (!planKey) {
      router.push("/register");
      return;
    }

    if (!session?.user) {
      // Save intended plan and redirect to register
      localStorage.setItem("pendingPlan", planKey);
      router.push("/register");
      return;
    }

    setLoadingPlan(planKey);
    try {
      const res = await fetch("/api/stripe/checkout", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ plan: planKey }),
      });

      const data = await res.json();
      if (data.url) {
        window.location.href = data.url;
      } else {
        alert(data.error || "Something went wrong.");
      }
    } catch {
      alert("Failed to start checkout. Please try again.");
    } finally {
      setLoadingPlan(null);
    }
  }

  return (
    <div className="min-h-screen pb-20">
      {/* Nav */}
      <nav className="border-b border-gray-800/50 bg-gray-950/80 backdrop-blur-xl">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-16 items-center justify-between">
            <Link href="/" className="flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <span className="text-xl font-bold">
                Secure<span className="bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">SaaS</span>
              </span>
            </Link>
            <div className="flex items-center gap-3">
              <Link href="/" className="flex items-center gap-2 text-sm text-gray-400 hover:text-white">
                <ArrowLeft className="h-4 w-4" />
                Home
              </Link>
              {session?.user ? (
                <Link
                  href="/dashboard"
                  className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 px-4 py-2 text-sm font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
                >
                  <LayoutDashboard className="h-4 w-4" />
                  Dashboard
                </Link>
              ) : (
                <>
                  <Link
                    href="/login"
                    className="rounded-lg px-4 py-2 text-sm text-gray-300 transition hover:text-white"
                  >
                    Log in
                  </Link>
                  <Link
                    href="/register"
                    className="rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 px-4 py-2 text-sm font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
                  >
                    Get Started
                  </Link>
                </>
              )}
            </div>
          </div>
        </div>
      </nav>

      <div className="mx-auto max-w-7xl px-4 py-16 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mx-auto max-w-2xl text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
          >
            <div className="mb-4 inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-1.5 text-sm text-emerald-400">
              <Sparkles className="h-4 w-4" />
              Simple credit-based pricing
            </div>
          </motion.div>
          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.1 }}
            className="text-4xl font-bold sm:text-5xl"
          >
            Scan now, pay for{" "}
            <span className="bg-gradient-to-r from-emerald-400 to-cyan-400 bg-clip-text text-transparent">
              what you use
            </span>
          </motion.h1>
          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ delay: 0.2 }}
            className="mt-4 text-lg text-gray-400"
          >
            Every plan includes the full scanner. Paid plans unlock fix suggestions,
            PDF exports, and team features. Credits roll over — nothing wasted.
          </motion.p>
        </div>

        {/* Pricing cards */}
        <div className="mt-16 grid gap-8 lg:grid-cols-3">
          {plans.map((plan, index) => (
            <motion.div
              key={plan.name}
              initial={{ opacity: 0, y: 20 }}
              animate={{ opacity: 1, y: 0 }}
              transition={{ duration: 0.5, delay: 0.1 + index * 0.1 }}
              className={`relative rounded-2xl border p-8 ${
                plan.popular
                  ? "border-emerald-500/50 bg-gray-900/80 shadow-lg shadow-emerald-500/5"
                  : "border-gray-800 bg-gray-900/50"
              }`}
            >
              {plan.popular && (
                <div className="absolute -top-3 left-1/2 -translate-x-1/2">
                  <div className="flex items-center gap-1 rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 px-4 py-1 text-xs font-medium text-white">
                    <Star className="h-3 w-3" />
                    Most Popular
                  </div>
                </div>
              )}

              <div>
                <div className="flex items-center gap-3">
                  <div className={`flex h-10 w-10 items-center justify-center rounded-xl ${
                    plan.popular
                      ? "bg-gradient-to-br from-emerald-500 to-cyan-500"
                      : "bg-gray-800"
                  }`}>
                    <plan.icon className="h-5 w-5 text-white" />
                  </div>
                  <h3 className="text-xl font-semibold">{plan.name}</h3>
                </div>
                <p className="mt-2 text-sm text-gray-400">{plan.description}</p>
                <div className="mt-4 flex items-baseline">
                  <span className="text-4xl font-bold">{plan.price}</span>
                  <span className="ml-1 text-gray-400">{plan.period}</span>
                </div>
                <div className="mt-2 inline-flex items-center gap-1.5 rounded-full bg-gray-800 px-3 py-1 text-xs font-medium text-gray-300">
                  {plan.credits}
                </div>
              </div>

              <ul className="mt-8 space-y-3">
                {plan.features.map((feature) => (
                  <li key={feature} className="flex items-start gap-3 text-sm text-gray-300">
                    <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0 text-emerald-500" />
                    <span>{feature}</span>
                  </li>
                ))}
                {plan.limitations.map((lim) => (
                  <li key={lim} className="flex items-start gap-3 text-sm text-gray-500">
                    <span className="mt-0.5 h-4 w-4 shrink-0 text-center text-gray-600">✕</span>
                    <span>{lim}</span>
                  </li>
                ))}
              </ul>

              <button
                onClick={() => handleSubscribe(plan.planKey)}
                disabled={loadingPlan === plan.planKey}
                className={`mt-8 flex w-full items-center justify-center gap-2 rounded-xl px-6 py-3 font-medium transition disabled:opacity-50 ${
                  plan.popular
                    ? "bg-gradient-to-r from-emerald-500 to-cyan-500 text-white hover:from-emerald-600 hover:to-cyan-600"
                    : "border border-gray-700 text-white hover:bg-gray-800"
                }`}
              >
                {loadingPlan === plan.planKey ? (
                  <Loader2 className="h-4 w-4 animate-spin" />
                ) : (
                  <>
                    {plan.cta}
                    <ArrowRight className="h-4 w-4" />
                  </>
                )}
              </button>
            </motion.div>
          ))}
        </div>

        {/* Credit explainer */}
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          whileInView={{ opacity: 1, y: 0 }}
          viewport={{ once: true }}
          className="mx-auto mt-20 max-w-3xl"
        >
          <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-8">
            <h2 className="text-center text-2xl font-bold">
              How credits work
            </h2>
            <div className="mt-8 grid gap-6 sm:grid-cols-3">
              <div className="text-center">
                <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-emerald-500/10 text-emerald-400">
                  <span className="text-xl font-bold">1</span>
                </div>
                <h3 className="font-medium text-white">1 credit = 1 scan</h3>
                <p className="mt-1 text-sm text-gray-400">
                  Each credit runs a full scan on one URL with 60+ checks
                </p>
              </div>
              <div className="text-center">
                <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-cyan-500/10 text-cyan-400">
                  <span className="text-xl font-bold">↻</span>
                </div>
                <h3 className="font-medium text-white">Credits roll over</h3>
                <p className="mt-1 text-sm text-gray-400">
                  Unused credits carry forward up to 2x your monthly limit
                </p>
              </div>
              <div className="text-center">
                <div className="mx-auto mb-3 flex h-12 w-12 items-center justify-center rounded-xl bg-blue-500/10 text-blue-400">
                  <span className="text-xl font-bold">∞</span>
                </div>
                <h3 className="font-medium text-white">Reports forever</h3>
                <p className="mt-1 text-sm text-gray-400">
                  Past scan reports stay accessible even on the free plan
                </p>
              </div>
            </div>
          </div>
        </motion.div>

        {/* FAQs */}
        <div className="mx-auto mt-20 max-w-2xl">
          <h2 className="text-center text-2xl font-bold">
            Frequently asked questions
          </h2>
          <div className="mt-8 space-y-3">
            {faqs.map((faq, i) => (
              <motion.div
                key={i}
                initial={{ opacity: 0, y: 10 }}
                whileInView={{ opacity: 1, y: 0 }}
                viewport={{ once: true }}
                transition={{ delay: i * 0.05 }}
                className="rounded-xl border border-gray-800 bg-gray-900/50"
              >
                <button
                  onClick={() => setOpenFaq(openFaq === i ? null : i)}
                  className="flex w-full items-center justify-between p-4 text-left"
                >
                  <div className="flex items-center gap-3">
                    <HelpCircle className="h-4 w-4 shrink-0 text-gray-500" />
                    <span className="font-medium text-white">{faq.q}</span>
                  </div>
                  <motion.div
                    animate={{ rotate: openFaq === i ? 180 : 0 }}
                    transition={{ duration: 0.2 }}
                  >
                    <ArrowRight className="h-4 w-4 rotate-90 text-gray-500" />
                  </motion.div>
                </button>
                {openFaq === i && (
                  <motion.div
                    initial={{ height: 0, opacity: 0 }}
                    animate={{ height: "auto", opacity: 1 }}
                    className="border-t border-gray-800 px-4 pb-4 pt-3"
                  >
                    <p className="text-sm text-gray-400 leading-relaxed">{faq.a}</p>
                  </motion.div>
                )}
              </motion.div>
            ))}
          </div>
        </div>

        {/* CTA */}
        <div className="mt-20 text-center">
          <h2 className="text-2xl font-bold">Ready to secure your SaaS?</h2>
          <p className="mt-2 text-gray-400">Start with a free scan — no credit card required.</p>
          <Link
            href="/register"
            className="mt-6 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-8 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
          >
            Get Started Free
            <ArrowRight className="h-4 w-4" />
          </Link>
        </div>
      </div>
    </div>
  );
}
