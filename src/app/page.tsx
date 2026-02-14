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
              Free website vulnerability scanner — no credit card needed
            </div>
          </motion.div>

          <motion.h1
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.1 }}
            className="text-5xl leading-tight font-bold tracking-tight sm:text-7xl"
          >
            Website Vulnerability
            <br />
            <span className="gradient-text">Scanner for Web Apps</span>
          </motion.h1>

          <motion.p
            initial={{ opacity: 0, y: 20 }}
            animate={{ opacity: 1, y: 0 }}
            transition={{ duration: 0.5, delay: 0.2 }}
            className="mx-auto mt-6 max-w-2xl text-lg text-gray-400 sm:text-xl"
          >
            Run a free website vulnerability scan on your web app in seconds. Our automated scanner
            crawls your site, checks for security issues, and delivers a detailed report with severity
            scores — upgrade for actionable fixes.
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
              ✓ 3 free scans &nbsp; ✓ Full site crawl &nbsp; ✓ 60+ vulnerability checks &nbsp; ✓ Automated scanning
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
              XSS & Injection Detection
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              OWASP Top 10 Risks
            </div>
            <div className="flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 text-emerald-500" />
              Access Controls
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
      title: "Full Site Crawl & Vulnerability Detection",
      description:
        "Unlike basic scanning tools, our web vulnerability scanner crawls up to 10 pages on your site to detect vulnerabilities across your entire web application — not just the homepage.",
    },
    {
      icon: Lock,
      title: "SSL/TLS & Web Server Scanner",
      description:
        "Verify your SSL certificate, check for mixed content, HTTPS redirects, and HSTS on your web server — the foundation of secure data transit and strong security posture.",
    },
    {
      icon: Shield,
      title: "30+ Security Header Checks",
      description:
        "Run vulnerability checks on CSP, HSTS, X-Frame-Options, Permissions-Policy, Referrer-Policy, and more. Get exact configuration recommendations to fix security issues.",
    },
    {
      icon: Code2,
      title: "XSS & Injection Vulnerability Scan",
      description:
        "Detect unsafe JavaScript patterns, inline eval(), document.write(), innerHTML usage, and potential cross-site scripting — common web application vulnerabilities in source code.",
    },
    {
      icon: AlertTriangle,
      title: "CSRF & Access Controls Audit",
      description:
        "Verify forms have CSRF tokens and cookies have proper SameSite, HttpOnly, and Secure attributes. Check access controls to prevent cross-site request forgery attacks.",
    },
    {
      icon: FileWarning,
      title: "Sensitive File & Open Ports Exposure",
      description:
        "Detect exposed .env files, .git repositories, database backups, debug logs, open ports, and 14+ other commonly leaked paths that penetration testers look for first.",
    },
    {
      icon: Mail,
      title: "Email Security (SPF/DMARC)",
      description:
        "Check DNS records for SPF and DMARC configuration. Prevent email spoofing and phishing attacks — a critical security check often missed by other security tools.",
    },
    {
      icon: Eye,
      title: "CSP Deep Analysis",
      description:
        "Parse and grade your Content-Security-Policy. Detect unsafe-inline, unsafe-eval, wildcards, and missing directives — identify vulnerabilities that DAST tools flag in production.",
    },
    {
      icon: Cookie,
      title: "Cookie Security Audit",
      description:
        "Analyze cookies for HttpOnly, Secure, SameSite attributes, and overly broad domain scoping that could leak session data to attackers performing penetration testing.",
    },
    {
      icon: Bug,
      title: "Known Vulnerabilities in Libraries",
      description:
        "Identify outdated jQuery, AngularJS 1.x, old Bootstrap, and unpatched software with known vulnerabilities — the kind of vulnerability discovery that prevents real breaches.",
    },
    {
      icon: Fingerprint,
      title: "Technology Fingerprinting",
      description:
        "Detect WordPress, Next.js, Shopify, Drupal, and 10+ frameworks. Understand what your site reveals to potential attackers — essential for vulnerability management.",
    },
    {
      icon: FolderOpen,
      title: "Directory & robots.txt Audit",
      description:
        "Check for exposed directory listings, sensitive paths in robots.txt, and error pages that leak stack traces — the same checks penetration testers run with tools like Nikto web scanner.",
    },
    {
      icon: Network,
      title: "CORS Misconfiguration",
      description:
        "Detect overly permissive CORS policies (Access-Control-Allow-Origin: *) and dangerous credential/wildcard combinations — a critical web app security vulnerability.",
    },
    {
      icon: Globe,
      title: "Open Redirect Detection",
      description:
        "Find redirect parameters (url=, next=, goto=) in links and forms that could be exploited — a common finding in dynamic application security testing.",
    },
    {
      icon: ShieldCheck,
      title: "SRI & Supply Chain Security",
      description:
        "Ensure external CDN scripts use Subresource Integrity (SRI) hashes. Guard against supply-chain attacks — a growing concern for application security testing.",
    },
    {
      icon: Zap,
      title: "Actionable Fix Suggestions",
      description:
        "Every vulnerability comes with a clear, developer-friendly explanation and exact code snippets. No manual testing or security jargon — just step-by-step remedies.",
    },
  ];

  return (
    <section id="features" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">
            What Our Vulnerability Scanner
            <br />
            <span className="gradient-text">Checks For</span>
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            60+ automated vulnerability checks across 15 categories — covering the types of vulnerability
            that security teams care about most in modern web apps.
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
        "Paste your website URL into our vulnerability scanning tool. Start with 3 free scans — no credit card or GitHub account required.",
    },
    {
      step: "02",
      title: "Automated scanning begins",
      description:
        "Our automated scanner crawls your web app and runs 60+ security checks — SSL, headers, XSS, CSRF, cookie security, exposed files, and OWASP top 10 risks.",
    },
    {
      step: "03",
      title: "Get your security report",
      description:
        "Receive a detailed vulnerability scan report with severity ratings. Upgrade to unlock step-by-step fix suggestions to eliminate critical vulnerabilities.",
    },
  ];

  return (
    <section id="how-it-works" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">
            How Does a Web Vulnerability <span className="gradient-text">Scanner Work?</span>
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Run your first free website security scan in three simple steps
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
      description: "Free website security scan — try our scanner",
      features: [
        "3 scan credits (one-time)",
        "Up to 25 pages per scan",
        "60+ vulnerability checks",
        "Security score & severity breakdown",
        "Vulnerability descriptions",
      ],
      cta: "Start Free Scan",
      popular: false,
    },
    {
      name: "Starter",
      price: "$29",
      period: "/month",
      description: "For indie hackers & small security teams",
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
      description: "Full vulnerability management platform",
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
            Website Vulnerability Scanning <span className="gradient-text">Plans</span>
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Start with a free website scanner and upgrade as your security needs grow. No hidden fees.
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

function ComparisonSection() {
  return (
    <section className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">
            How SecureSaaS Compares to Other
            <br />
            <span className="gradient-text">Scanning Tools</span>
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            There are many commercial and open source vulnerability scanners on the market — from
            enterprise-grade DAST tools to open source tools like Nikto web server scanner and
            OpenVAS. Here&apos;s how we fit in.
          </p>
        </div>

        <div className="mt-16 grid gap-8 md:grid-cols-2">
          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            className="rounded-2xl border border-gray-800 bg-gray-900/50 p-8"
          >
            <h3 className="text-xl font-semibold text-white">
              Commercial and Open Source Alternatives
            </h3>
            <p className="mt-3 text-gray-400 leading-relaxed">
              Tools like Burp Suite are powerful but complex — built for penetration testers and
              security teams with deep expertise. OpenVAS is a powerful open source vulnerability
              scanner designed for network-level vulnerability scanning across infrastructure. SAST
              tools analyze source code for flaws (static application security testing), while DAST
              tools like our scanner test running applications from the outside (dynamic application
              security testing). Commercial tools from major vendors or scanning tools by listing
              can cost thousands per year.
            </p>
          </motion.div>

          <motion.div
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ delay: 0.1 }}
            className="rounded-2xl border border-emerald-500/20 bg-gray-900/50 p-8"
          >
            <h3 className="text-xl font-semibold text-white">
              Why Choose SecureSaaS as Your Website Scanner
            </h3>
            <p className="mt-3 text-gray-400 leading-relaxed">
              SecureSaaS is built specifically for web app security. Vulnerability scanners are
              automated tools that scan web applications for common flaws — and ours does exactly
              that, without the steep learning curve. No CLI setup, no false positives to wade
              through, no manual testing required. Just paste your URL and get actionable results.
              Unlike a web application security scanner aimed at enterprise, we&apos;re designed for
              SaaS builders, indie hackers, and small security teams who need fast, reliable
              application security testing.
            </p>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

function FAQSection() {
  const faqs = [
    {
      question: "How does a website vulnerability scanner work?",
      answer:
        "A website vulnerability scanner is an automated tool that scans web applications for security flaws. It crawls your site, analyzes pages for known vulnerabilities like XSS, CSRF, missing security headers, SSL misconfigurations, and exposed files. SecureSaaS runs 60+ automated vulnerability checks and generates a report with severity ratings and fix suggestions.",
    },
    {
      question: "What types of vulnerability does the scanner detect?",
      answer:
        "Our scanner covers a wide range of web application vulnerability categories: SSL/TLS issues, missing or misconfigured security headers, cross-site scripting (XSS), cross-site request forgery (CSRF), cookie security flaws, sensitive file exposure, outdated libraries with known vulnerabilities, CORS misconfigurations, open redirects, SPF/DMARC email security, and more — covering the OWASP top 10 risks.",
    },
    {
      question: "Is SecureSaaS a free website vulnerability scanner?",
      answer:
        "Yes — every account starts with 3 free scan credits. Run a complete website vulnerability scanning session with full results, severity scores, and vulnerability descriptions at no cost. Upgrade to Starter ($29/mo) or Pro ($79/mo) to unlock fix suggestions, PDF exports, and more credits.",
    },
    {
      question: "How is this different from Burp Suite or Nikto?",
      answer:
        "Burp Suite is a comprehensive web application scanner and testing tools platform built for penetration testers and security professionals. Nikto is an open source web server scanner focused on server-level checks. SecureSaaS provides automated scanning focused on web app security — no installation, no CLI, no steep learning curve. Think of it as application security testing made simple for developers.",
    },
    {
      question: "Do I need penetration testing experience to use this?",
      answer:
        "Not at all. Unlike commercial tools that require expertise in penetration testing or security check configurations, SecureSaaS is designed for developers and SaaS builders. Just enter your URL and our security scanner handles the rest — vulnerability discovery, severity scoring, and actionable remedies you can implement immediately.",
    },
    {
      question: "Does it reduce false positives?",
      answer:
        "Yes. Our scanner is tuned specifically for modern web apps and SaaS platforms, which significantly reduces false positives compared to generic scanning tools. Every finding includes context about why it matters and how to verify it, so your security teams can focus on real issues — not noise.",
    },
  ];

  return (
    <section className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8">
        <div className="text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">
            Vulnerability Scanner <span className="gradient-text">FAQ</span>
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Common questions about our web vulnerability scanning tool
          </p>
        </div>

        <div className="mt-12 space-y-6">
          {faqs.map((faq, index) => (
            <motion.div
              key={faq.question}
              initial={{ opacity: 0, y: 10 }}
              whileInView={{ opacity: 1, y: 0 }}
              viewport={{ once: true }}
              transition={{ delay: index * 0.08 }}
              className="rounded-2xl border border-gray-800 bg-gray-900/50 p-6"
            >
              <h3 className="text-lg font-semibold text-white">{faq.question}</h3>
              <p className="mt-3 text-gray-400 leading-relaxed">{faq.answer}</p>
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
              Automate Your Web App Security Scan
            </h2>
            <p className="mx-auto mt-4 max-w-xl text-lg text-gray-400">
              Don&apos;t wait for a security breach. Use our website vulnerability scanner to look
              for security vulnerabilities and fix them before attackers find them.
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
      <ComparisonSection />
      <PricingSection />
      <FAQSection />
      <CTASection />
      <Footer />
    </div>
  );
}
