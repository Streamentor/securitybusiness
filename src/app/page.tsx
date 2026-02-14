"use client";

import { useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { motion } from "framer-motion";
import ScanningOverlay from "@/components/ScanningOverlay";
import {
  Shield,
  Search,
  Zap,
  Lock,
  Globe,
  ArrowRight,
  CheckCircle2,
  AlertTriangle,
  ShieldCheck,
  Code2,
  Loader2,
  ChevronRight,
  Star,
  Sparkles,
  FileWarning,
  Mail,
  Eye,
  Cookie,
  Fingerprint,
  FolderOpen,
  Bug,
  Network,
  LayoutDashboard,
} from "lucide-react";

function Navbar() {
  const { data: session, status } = useSession();
  const isLoggedIn = status === "authenticated" && !!session?.user;

  return (
    <nav className="fixed top-0 left-0 right-0 z-50 border-b border-gray-800/50 bg-gray-950/80 backdrop-blur-xl">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex h-16 items-center justify-between">
          <Link href="/" className="flex items-center gap-2">
            <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="text-xl font-bold">
              Secure<span className="gradient-text">SaaS</span>
            </span>
          </Link>

          <div className="hidden items-center gap-8 md:flex">
            <a href="#features" className="text-sm text-gray-400 transition hover:text-white">
              Features
            </a>
            <a href="#how-it-works" className="text-sm text-gray-400 transition hover:text-white">
              How it Works
            </a>
            <a href="#pricing" className="text-sm text-gray-400 transition hover:text-white">
              Pricing
            </a>
            <Link href="/pricing" className="text-sm text-gray-400 transition hover:text-white">
              Plans & Credits
            </Link>
          </div>

          <div className="flex items-center gap-3">
            {isLoggedIn ? (
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
  );
}

function HeroSection() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanUrl, setScanUrl] = useState("");

  function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;

    let normalizedUrl = url.trim();
    if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
      normalizedUrl = "https://" + normalizedUrl;
    }

    setScanUrl(normalizedUrl);
    setScanning(true);
  }

  return (
    <section className="relative overflow-hidden pt-32 pb-20 sm:pt-40 sm:pb-32">
      {/* Scanning overlay */}
      <ScanningOverlay
        url={scanUrl}
        isOpen={scanning}
        onClose={() => {
          setScanning(false);
          setScanUrl("");
        }}
      />
      {/* Background effects */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute top-0 left-1/2 h-[600px] w-[600px] -translate-x-1/2 rounded-full bg-emerald-500/5 blur-3xl" />
        <div className="absolute top-20 right-1/4 h-[400px] w-[400px] rounded-full bg-cyan-500/5 blur-3xl" />
        <div className="absolute top-40 left-1/4 h-[300px] w-[300px] rounded-full bg-blue-500/5 blur-3xl" />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-4xl text-center">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5 }}
          >
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-1.5 text-sm text-emerald-400">
              <Sparkles className="h-4 w-4" />
              3 free scans for SaaS builders — no credit card needed
            </div>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-5xl leading-tight font-bold tracking-tight sm:text-7xl"
          >
            Secure your SaaS
            <br />
            <span className="gradient-text">before hackers do</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="mx-auto mt-6 max-w-2xl text-lg text-gray-400 sm:text-xl"
          >
            We crawl your entire website and analyze it for security vulnerabilities.
            Get a detailed report with severity scores — upgrade for actionable fixes.
          </motion.p>

          <motion.form
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.3 }}
            onSubmit={handleScan}
            className="mx-auto mt-10 max-w-2xl"
          >
            <div className="glow flex items-center gap-2 rounded-2xl border border-gray-700/50 bg-gray-900/80 p-2 backdrop-blur-sm">
              <div className="flex flex-1 items-center gap-3 px-4">
                <Globe className="h-5 w-5 shrink-0 text-gray-500" />
                <input
                  type="text"
                  value={url}
                  onChange={(e) => setUrl(e.target.value)}
                  placeholder="Enter your website URL (e.g., myapp.com)"
                  className="w-full bg-transparent py-3 text-white placeholder:text-gray-500 focus:outline-none"
                />
              </div>
              <button
                type="submit"
                disabled={scanning || !url.trim()}
                className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600 disabled:opacity-50 disabled:cursor-not-allowed sm:px-8"
              >
                <Search className="h-4 w-4" />
                Scan Now
              </button>
            </div>
            <p className="mt-3 text-sm text-gray-500">
              ✓ 3 free scans &nbsp; ✓ Full site crawl &nbsp; ✓ Detailed report
            </p>
          </motion.form>

          {/* Trust indicators */}
          <motion.div
            initial={{ opacity: 0 }}
            animate={{ opacity: 1 }}
            transition={{ duration: 0.5, delay: 0.5 }}
            className="mt-16 flex flex-wrap items-center justify-center gap-8 text-sm text-gray-500"
          >
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              SSL/TLS Analysis
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              Security Headers
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              XSS Detection
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              CSRF Checks
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              Cookie Security
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

function FeaturesSection() {
  const features = [
    {
      icon: Search,
      title: "Full Site Crawl",
      description:
        "We don't just check your homepage. Our crawler discovers and scans up to 10 pages on your site for comprehensive coverage.",
    },
    {
      icon: Lock,
      title: "SSL/TLS Analysis",
      description:
        "Verify your SSL certificate, check for mixed content, HTTPS redirects, and HSTS configuration — the foundation of secure data transit.",
    },
    {
      icon: Shield,
      title: "30+ Security Headers",
      description:
        "Check for CSP, HSTS, X-Frame-Options, Permissions-Policy, Referrer-Policy, and more. Get exact configuration recommendations.",
    },
    {
      icon: Code2,
      title: "XSS & Injection Detection",
      description:
        "Detect unsafe JavaScript patterns, inline eval(), document.write(), innerHTML usage, and potential cross-site scripting vulnerabilities.",
    },
    {
      icon: AlertTriangle,
      title: "CSRF Protection Audit",
      description:
        "Verify forms have CSRF tokens and cookies have proper SameSite, HttpOnly, and Secure attributes to prevent cross-site request forgery.",
    },
    {
      icon: FileWarning,
      title: "Sensitive File Exposure",
      description:
        "Detect exposed .env files, .git repositories, database backups, debug logs, and 14+ other commonly leaked sensitive files.",
    },
    {
      icon: Mail,
      title: "Email Security (SPF/DMARC)",
      description:
        "Check DNS records for SPF and DMARC configuration. Prevent email spoofing and phishing attacks using your domain.",
    },
    {
      icon: Eye,
      title: "CSP Deep Analysis",
      description:
        "Parse and grade your Content-Security-Policy. Detect unsafe-inline, unsafe-eval, wildcards, and missing directives.",
    },
    {
      icon: Cookie,
      title: "Cookie Security Audit",
      description:
        "Analyze cookies for HttpOnly, Secure, SameSite attributes, and overly broad domain scoping that could leak session data.",
    },
    {
      icon: Bug,
      title: "Vulnerable Library Detection",
      description:
        "Identify outdated jQuery, AngularJS 1.x, old Bootstrap, and deprecated libraries with known security vulnerabilities.",
    },
    {
      icon: Fingerprint,
      title: "Technology Fingerprinting",
      description:
        "Detect WordPress, Next.js, Shopify, Drupal, and 10+ frameworks. Know what your site reveals to potential attackers.",
    },
    {
      icon: FolderOpen,
      title: "Directory & robots.txt Audit",
      description:
        "Check for exposed directory listings, sensitive paths in robots.txt, and error pages that leak stack traces or framework details.",
    },
    {
      icon: Network,
      title: "CORS Misconfiguration",
      description:
        "Detect overly permissive CORS policies (Access-Control-Allow-Origin: *) and dangerous credential/wildcard combinations.",
    },
    {
      icon: Globe,
      title: "Open Redirect Detection",
      description:
        "Find redirect parameters (url=, next=, goto=) in links and forms that could be exploited to redirect users to malicious sites.",
    },
    {
      icon: ShieldCheck,
      title: "SRI Verification",
      description:
        "Ensure external CDN scripts and stylesheets use Subresource Integrity (SRI) hashes to prevent supply-chain attacks.",
    },
    {
      icon: Zap,
      title: "Actionable Remedies",
      description:
        "Every vulnerability comes with a clear, developer-friendly explanation and exact code snippets to fix it. No security jargon.",
    },
  ];

  return (
    <section id="features" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">
            Everything you need to
            <br />
            <span className="gradient-text">secure your SaaS</span>
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            50+ security checks across 15 categories — designed specifically for modern web
            applications and SaaS platforms.
          </p>
        </div>

        <div className="mt-16 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {features.map((feature, index) => (
            <motion.div
              key={feature.title}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className="group rounded-2xl border border-gray-800 bg-gray-900/50 p-6 transition hover:border-gray-700 hover:bg-gray-900/80"
            >
              <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 text-emerald-400 transition group-hover:from-emerald-500/30 group-hover:to-cyan-500/30">
                <feature.icon className="h-6 w-6" />
              </div>
              <h3 className="text-lg font-semibold text-white">{feature.title}</h3>
              <p className="mt-2 text-gray-400 leading-relaxed">{feature.description}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}

function HowItWorksSection() {
  const steps = [
    {
      step: "01",
      title: "Enter your URL",
      description:
        "Just paste your website URL into the scanner. Start with 3 free scans — no credit card required.",
    },
    {
      step: "02",
      title: "We crawl & analyze",
      description:
        "Our engine crawls your site and runs 50+ checks across 15 categories — SSL, headers, XSS, CSRF, email security, exposed files, and more.",
    },
    {
      step: "03",
      title: "Get your report",
      description:
        "Receive a detailed security report with severity ratings and explanations. Upgrade to unlock step-by-step remediation guides.",
    },
  ];

  return (
    <section id="how-it-works" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">
            How it <span className="gradient-text">works</span>
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Get your security report in three simple steps
          </p>
        </div>

        <div className="mt-16 grid gap-8 md:grid-cols-3">
          {steps.map((item, index) => (
            <motion.div
              key={item.step}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.15 }}
              className="relative text-center"
            >
              <div className="mx-auto mb-6 flex h-16 w-16 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-500 to-cyan-500 text-2xl font-bold text-white">
                {item.step}
              </div>
              {index < steps.length - 1 && (
                <div className="absolute top-8 left-[calc(50%+40px)] hidden w-[calc(100%-80px)] md:block">
                  <ChevronRight className="mx-auto h-6 w-6 text-gray-700" />
                </div>
              )}
              <h3 className="text-xl font-semibold">{item.title}</h3>
              <p className="mt-2 text-gray-400">{item.description}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}

function PricingSection() {
  const plans = [
    {
      name: "Free",
      price: "$0",
      period: "forever",
      description: "Try SecureSaaS and scan your first site",
      features: [
        "3 scan credits (one-time)",
        "Up to 25 pages per scan",
        "60+ vulnerability checks",
        "Security score & severity breakdown",
        "Vulnerability descriptions",
      ],
      cta: "Start Free",
      popular: false,
    },
    {
      name: "Starter",
      price: "$29",
      period: "/month",
      description: "For indie hackers & small SaaS teams",
      features: [
        "10 scan credits / month",
        "60+ vulnerability checks",
        "✨ Fix suggestions & remedies",
        "✨ PDF report export",
        "Email notifications",
        "Credits roll over (max 20)",
      ],
      cta: "Get Starter",
      popular: true,
    },
    {
      name: "Pro",
      price: "$79",
      period: "/month",
      description: "For growing SaaS businesses",
      features: [
        "30 scan credits / month",
        "Up to 50 pages per scan",
        "✨ Fix suggestions & remedies",
        "✨ API access & scheduled scans",
        "✨ Slack & webhook alerts",
        "✨ Team access (5 seats)",
        "Priority scanning queue",
        "Credits roll over (max 60)",
      ],
      cta: "Go Pro",
      popular: false,
    },
  ];

  return (
    <section id="pricing" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">
            Simple, transparent <span className="gradient-text">pricing</span>
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Start free and upgrade as you grow. No hidden fees.
          </p>
        </div>

        <div className="mt-16 grid gap-8 lg:grid-cols-3">
          {plans.map((plan, index) => (
            <motion.div
              key={plan.name}
              initial={{ opacity: 0, y: 20 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ duration: 0.5, delay: index * 0.1 }}
              className={`relative rounded-2xl border p-8 ${
                plan.popular
                  ? "border-emerald-500/50 bg-gray-900/80 glow"
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
                <h3 className="text-xl font-semibold">{plan.name}</h3>
                <p className="mt-1 text-sm text-gray-400">{plan.description}</p>
                <div className="mt-4 flex items-baseline">
                  <span className="text-4xl font-bold">{plan.price}</span>
                  <span className="ml-1 text-gray-400">{plan.period}</span>
                </div>
              </div>

              <ul className="mt-8 space-y-3">
                {plan.features.map((feature) => (
                  <li key={feature} className="flex items-center gap-3 text-sm text-gray-300">
                    <CheckCircle2 className="h-4 w-4 shrink-0 text-emerald-500" />
                    {feature}
                  </li>
                ))}
              </ul>

              <Link
                href="/register"
                className={`mt-8 flex w-full items-center justify-center gap-2 rounded-xl px-6 py-3 font-medium transition ${
                  plan.popular
                    ? "bg-gradient-to-r from-emerald-500 to-cyan-500 text-white hover:from-emerald-600 hover:to-cyan-600"
                    : "border border-gray-700 text-white hover:bg-gray-800"
                }`}
              >
                {plan.cta}
                <ArrowRight className="h-4 w-4" />
              </Link>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}

function CTASection() {
  return (
    <section className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="glow relative overflow-hidden rounded-3xl border border-gray-800 bg-gray-900/80 px-8 py-16 text-center sm:px-16">
          <div className="pointer-events-none absolute inset-0">
            <div className="absolute top-0 left-1/2 h-[300px] w-[600px] -translate-x-1/2 rounded-full bg-emerald-500/10 blur-3xl" />
          </div>

          <div className="relative">
            <ShieldCheck className="mx-auto h-12 w-12 text-emerald-400" />
            <h2 className="mt-6 text-3xl font-bold sm:text-4xl">
              Ready to secure your SaaS?
            </h2>
            <p className="mx-auto mt-4 max-w-xl text-lg text-gray-400">
              Don&apos;t wait for a security breach. Scan your website now and fix vulnerabilities
              before they become problems.
            </p>
            <div className="mt-8 flex flex-col items-center justify-center gap-4 sm:flex-row">
              <Link
                href="/register"
                className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-8 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
              >
                Get Started Free
                <ArrowRight className="h-4 w-4" />
              </Link>
              <a
                href="#features"
                className="flex items-center gap-2 rounded-xl border border-gray-700 px-8 py-3 font-medium text-white transition hover:bg-gray-800"
              >
                Learn More
              </a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

function Footer() {
  return (
    <footer className="border-t border-gray-800/50 py-12">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-lg font-bold">
              Secure<span className="gradient-text">SaaS</span>
            </span>
          </div>
          <p className="text-sm text-gray-500">
            © {new Date().getFullYear()} SecureSaaS. All rights reserved.
          </p>
          <div className="flex gap-6">
            <a href="#" className="text-sm text-gray-400 hover:text-white">
              Privacy
            </a>
            <a href="#" className="text-sm text-gray-400 hover:text-white">
              Terms
            </a>
            <a href="#" className="text-sm text-gray-400 hover:text-white">
              Contact
            </a>
          </div>
        </div>
      </div>
    </footer>
  );
}

export default function HomePage() {
  return (
    <div className="min-h-screen">
      <Navbar />
      <HeroSection />
      <FeaturesSection />
      <HowItWorksSection />
      <PricingSection />
      <CTASection />
      <Footer />
    </div>
  );
}
