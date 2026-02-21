"use client";

import { useState, useEffect } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { motion, useMotionValue, useTransform, animate } from "framer-motion";
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
  ShieldX,
  ShieldAlert,
  AlertCircle,
  Info,
  TrendingUp,
  Users,
  BarChart3,
  Clock,
  ChevronDown,
  Play,
} from "lucide-react";

/* ---- Navbar ---- */

function Navbar() {
  const { data: session, status } = useSession();
  const isLoggedIn = status === "authenticated" && !!session?.user;
  const [credits, setCredits] = useState<number | null>(null);

  useEffect(() => {
    if (isLoggedIn) {
      fetch("/api/user/plan")
        .then((r) => r.json())
        .then((d) => setCredits(d.credits ?? null))
        .catch(() => {});
    }
  }, [isLoggedIn]);

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
            <a href="#features" className="text-sm text-gray-400 transition hover:text-white">Features</a>
            <a href="#how-it-works" className="text-sm text-gray-400 transition hover:text-white">How it Works</a>
            <a href="#report-preview" className="text-sm text-gray-400 transition hover:text-white">Sample Report</a>
            <a href="#pricing" className="text-sm text-gray-400 transition hover:text-white">Pricing</a>
          </div>

          <div className="flex items-center gap-3">
            {isLoggedIn ? (
              <>
                {credits !== null && (
                  <div className={`flex items-center gap-1.5 rounded-lg border px-3 py-2 text-sm font-medium ${credits > 0 ? "border-amber-500/20 bg-amber-500/10 text-amber-400" : "border-red-500/20 bg-red-500/10 text-red-400"}`}>
                    <Zap className="h-3.5 w-3.5" />
                    {credits} scan{credits !== 1 ? "s" : ""} left
                  </div>
                )}
                <Link
                  href="/dashboard"
                  className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 px-4 py-2 text-sm font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
                >
                  <LayoutDashboard className="h-4 w-4" />
                  Dashboard
                </Link>
              </>
            ) : (
              <>
                <Link href="/login" className="rounded-lg px-4 py-2 text-sm text-gray-300 transition hover:text-white">Log in</Link>
                <Link href="/register" className="rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 px-4 py-2 text-sm font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600">Get Started</Link>
              </>
            )}
          </div>
        </div>
      </div>
    </nav>
  );
}

/* ---- AnimatedCounter ---- */

function AnimatedCounter({ target, suffix = "" }: { target: number; suffix?: string }) {
  const count = useMotionValue(0);
  const rounded = useTransform(count, (v) => Math.floor(v).toLocaleString());
  const [displayValue, setDisplayValue] = useState("0");

  useEffect(() => {
    const controls = animate(count, target, { duration: 2, ease: "easeOut" });
    const unsubscribe = rounded.on("change", (v) => setDisplayValue(v));
    return () => { controls.stop(); unsubscribe(); };
  }, [count, rounded, target]);

  return <span>{displayValue}{suffix}</span>;
}

/* ---- Hero ---- */

function HeroSection() {
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanUrl, setScanUrl] = useState("");
  const [heroPlaying, setHeroPlaying] = useState(false);

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
      <ScanningOverlay url={scanUrl} isOpen={scanning} onClose={() => { setScanning(false); setScanUrl(""); }} />

      {/* Background effects */}
      <div className="pointer-events-none absolute inset-0">
        <div className="absolute top-0 left-1/2 h-[600px] w-[600px] -translate-x-1/2 rounded-full bg-emerald-500/5 blur-3xl" />
        <div className="absolute top-20 right-1/4 h-[400px] w-[400px] rounded-full bg-cyan-500/5 blur-3xl" />
        <div className="absolute top-40 left-1/4 h-[300px] w-[300px] rounded-full bg-blue-500/5 blur-3xl" />
        <div className="absolute inset-0 opacity-[0.03]" style={{ backgroundImage: "linear-gradient(rgba(255,255,255,0.1) 1px, transparent 1px), linear-gradient(90deg, rgba(255,255,255,0.1) 1px, transparent 1px)", backgroundSize: "60px 60px" }} />
      </div>

      <div className="relative mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-4xl text-center">
          <motion.div initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5 }}>
            <div className="mb-6 inline-flex items-center gap-2 rounded-full border border-emerald-500/20 bg-emerald-500/10 px-4 py-1.5 text-sm text-emerald-400">
              <Sparkles className="h-4 w-4" />
              Free website vulnerability scanner — no credit card needed
            </div>
          </motion.div>

          <motion.h1 initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.1 }} className="text-5xl leading-tight font-bold tracking-tight sm:text-7xl">
            Website Vulnerability<br /><span className="gradient-text">Scanner for Web Apps</span>
          </motion.h1>

          <motion.p initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.2 }} className="mx-auto mt-6 max-w-2xl text-lg text-gray-400 sm:text-xl">
            Run a free website vulnerability scan on your web app in seconds. Our automated scanner crawls your site, checks for security issues, and delivers a detailed report with severity scores — upgrade for actionable fixes.
          </motion.p>

          <motion.form initial={{ opacity: 0, y: 20 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.5, delay: 0.3 }} onSubmit={handleScan} className="mx-auto mt-10 max-w-2xl">
            <div className="glow flex items-center gap-2 rounded-2xl border border-gray-700/50 bg-gray-900/80 p-2 backdrop-blur-sm">
              <div className="flex flex-1 items-center gap-3 px-4">
                <Globe className="h-5 w-5 shrink-0 text-gray-500" />
                <input type="text" value={url} onChange={(e) => setUrl(e.target.value)} placeholder="Enter your website URL (e.g., myapp.com)" className="w-full bg-transparent py-3 text-white placeholder:text-gray-500 focus:outline-none" />
              </div>
              <button type="submit" disabled={scanning || !url.trim()} className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600 disabled:cursor-not-allowed disabled:opacity-50 sm:px-8">
                <Search className="h-4 w-4" />
                Scan Now
              </button>
            </div>
            <p className="mt-3 text-sm text-gray-500">&#10003; 1 free scan &nbsp; &#10003; Full site crawl &nbsp; &#10003; 60+ vulnerability checks &nbsp; &#10003; Automated scanning</p>
          </motion.form>

          {/* Demo Video */}
          <motion.div initial={{ opacity: 0, y: 40 }} animate={{ opacity: 1, y: 0 }} transition={{ duration: 0.7, delay: 0.5 }} className="mx-auto mt-14 max-w-4xl">
            <div className="mb-5 flex items-center justify-center gap-2 text-sm text-gray-400">
              <Play className="h-4 w-4 text-cyan-400" />
              <span>See a full scan in under 60 seconds</span>
            </div>
            <div className="glow overflow-hidden rounded-2xl border border-gray-700/50 shadow-2xl shadow-emerald-500/5">
              <div className="relative aspect-video w-full bg-gray-900">
                {!heroPlaying ? (
                  <div className="group relative h-full w-full cursor-pointer" onClick={() => setHeroPlaying(true)}>
                    <img
                      src="https://img.youtube.com/vi/8wF8yVI161c/maxresdefault.jpg"
                      alt="SecureSaaS Demo — Website Vulnerability Scanner"
                      className="h-full w-full object-cover transition-transform duration-500 group-hover:scale-105"
                    />
                    <div className="absolute inset-0 bg-black/40 transition-colors duration-300 group-hover:bg-black/30" />
                    <div className="absolute inset-0 flex items-center justify-center">
                      <div className="flex h-20 w-20 items-center justify-center rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500 shadow-lg shadow-emerald-500/30 transition-transform duration-300 group-hover:scale-110">
                        <Play className="ml-1 h-8 w-8 text-white" fill="white" />
                      </div>
                    </div>
                    <div className="absolute bottom-4 right-4 rounded-lg bg-black/70 px-3 py-1 text-sm font-medium text-white backdrop-blur-sm">
                      ▶ Watch Demo
                    </div>
                  </div>
                ) : (
                  <iframe
                    src="https://www.youtube.com/embed/8wF8yVI161c?autoplay=1&rel=0&modestbranding=1"
                    title="SecureSaaS Demo — Website Vulnerability Scanner"
                    allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture"
                    allowFullScreen
                    className="h-full w-full"
                  />
                )}
              </div>
            </div>
          </motion.div>

          <motion.div initial={{ opacity: 0 }} animate={{ opacity: 1 }} transition={{ duration: 0.5, delay: 0.7 }} className="mt-16 flex flex-wrap items-center justify-center gap-8 text-sm text-gray-500">
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-emerald-500" />SSL/TLS Analysis</div>
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-emerald-500" />Security Headers</div>
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-emerald-500" />XSS &amp; Injection Detection</div>
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-emerald-500" />OWASP Top 10 Risks</div>
            <div className="flex items-center gap-2"><CheckCircle2 className="h-4 w-4 text-emerald-500" />Access Controls</div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

/* ---- Stats ---- */

function StatsSection() {
  return (
    <section className="relative -mt-8 pb-16">
      <div className="mx-auto max-w-5xl px-4 sm:px-6 lg:px-8">
        <motion.div initial={{ opacity: 0, y: 30 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="glow-sm grid grid-cols-2 gap-px overflow-hidden rounded-2xl border border-gray-800 bg-gray-800 md:grid-cols-4">
          {[
            { value: 2847, suffix: "+", label: "Scans completed", icon: BarChart3 },
            { value: 18400, suffix: "+", label: "Vulnerabilities found", icon: ShieldAlert },
            { value: 60, suffix: "+", label: "Security checks", icon: ShieldCheck },
            { value: 15, suffix: "", label: "Check categories", icon: FolderOpen },
          ].map((stat) => (
            <div key={stat.label} className="flex flex-col items-center bg-gray-950 px-6 py-8">
              <stat.icon className="mb-3 h-5 w-5 text-emerald-500" />
              <span className="text-3xl font-bold text-white">
                <AnimatedCounter target={stat.value} suffix={stat.suffix} />
              </span>
              <span className="mt-1 text-sm text-gray-500">{stat.label}</span>
            </div>
          ))}
        </motion.div>
      </div>
    </section>
  );
}

/* ---- Report Preview ---- */

function ReportPreviewSection() {
  const mockVulns = [
    { severity: "critical", title: "Missing Content-Security-Policy Header", type: "headers", url: "/dashboard" },
    { severity: "high", title: "jQuery 2.1.4 — Known XSS Vulnerability", type: "outdated-lib", url: "/" },
    { severity: "medium", title: "Cookies without SameSite attribute", type: "cookies", url: "/login" },
    { severity: "low", title: "X-Powered-By header exposes server info", type: "headers", url: "/" },
    { severity: "info", title: "robots.txt lists /admin path", type: "info-disclosure", url: "/robots.txt" },
  ];

  const severityConfig: Record<string, { color: string; bg: string; border: string; icon: React.ElementType }> = {
    critical: { color: "text-red-400", bg: "bg-red-500/10", border: "border-red-500/20", icon: ShieldX },
    high: { color: "text-orange-400", bg: "bg-orange-500/10", border: "border-orange-500/20", icon: ShieldAlert },
    medium: { color: "text-yellow-400", bg: "bg-yellow-500/10", border: "border-yellow-500/20", icon: AlertTriangle },
    low: { color: "text-blue-400", bg: "bg-blue-500/10", border: "border-blue-500/20", icon: AlertCircle },
    info: { color: "text-gray-400", bg: "bg-gray-500/10", border: "border-gray-500/20", icon: Info },
  };

  return (
    <section id="report-preview" className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">
            See What Your <span className="gradient-text">Security Report</span> Looks Like
          </h2>
          <p className="mt-4 text-lg text-gray-400">
            Every scan produces a detailed vulnerability report with severity scores, descriptions, and fix suggestions. Here&apos;s a sample report preview.
          </p>
        </div>

        <motion.div initial={{ opacity: 0, y: 40 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.7 }} className="mx-auto mt-16 max-w-4xl">
          {/* Browser chrome */}
          <div className="overflow-hidden rounded-2xl border border-gray-700/50 shadow-2xl shadow-black/40">
            <div className="flex items-center gap-3 border-b border-gray-800 bg-gray-900 px-4 py-3">
              <div className="flex gap-1.5">
                <div className="h-3 w-3 rounded-full bg-red-500/70" />
                <div className="h-3 w-3 rounded-full bg-yellow-500/70" />
                <div className="h-3 w-3 rounded-full bg-green-500/70" />
              </div>
              <div className="flex-1 rounded-lg bg-gray-800 px-4 py-1.5 text-center text-xs text-gray-500">scanmysaas.com/scan/report-preview</div>
            </div>

            <div className="bg-gray-950 p-6 sm:p-8">
              {/* Header row */}
              <div className="flex flex-col items-center gap-6 sm:flex-row sm:items-start sm:gap-8">
                {/* Score gauge */}
                <div className="relative flex h-36 w-36 shrink-0 items-center justify-center">
                  <svg className="-rotate-90 h-full w-full" viewBox="0 0 140 140">
                    <circle cx="70" cy="70" r="60" fill="none" stroke="currentColor" strokeWidth="8" className="text-gray-800" />
                    <motion.circle cx="70" cy="70" r="60" fill="none" strokeWidth="8" strokeLinecap="round" stroke="currentColor" className="text-yellow-500" strokeDasharray={2 * Math.PI * 60} initial={{ strokeDashoffset: 2 * Math.PI * 60 }} whileInView={{ strokeDashoffset: 2 * Math.PI * 60 * (1 - 0.62) }} viewport={{ once: true }} transition={{ duration: 1.5, ease: "easeInOut" }} />
                  </svg>
                  <div className="absolute flex flex-col items-center">
                    <span className="text-3xl font-bold text-yellow-500">62</span>
                    <span className="text-xs text-gray-500">Moderate</span>
                  </div>
                </div>

                {/* Summary */}
                <div className="flex-1 text-center sm:text-left">
                  <div className="flex items-center justify-center gap-2 sm:justify-start">
                    <Globe className="h-5 w-5 text-gray-500" />
                    <h3 className="text-xl font-bold text-white">example-saas.com</h3>
                  </div>
                  <p className="mt-1 text-sm text-gray-500">Scanned Feb 14, 2026 &middot; 8 pages crawled &middot; 5 vulnerabilities</p>
                  <div className="mt-4 flex flex-wrap items-center justify-center gap-2 sm:justify-start">
                    <span className="rounded-full bg-red-500/15 px-3 py-1 text-xs font-semibold text-red-400 ring-1 ring-red-500/20">1 Critical</span>
                    <span className="rounded-full bg-orange-500/15 px-3 py-1 text-xs font-semibold text-orange-400 ring-1 ring-orange-500/20">1 High</span>
                    <span className="rounded-full bg-yellow-500/15 px-3 py-1 text-xs font-semibold text-yellow-400 ring-1 ring-yellow-500/20">1 Medium</span>
                    <span className="rounded-full bg-blue-500/15 px-3 py-1 text-xs font-semibold text-blue-400 ring-1 ring-blue-500/20">1 Low</span>
                    <span className="rounded-full bg-gray-500/15 px-3 py-1 text-xs font-semibold text-gray-400 ring-1 ring-gray-500/20">1 Info</span>
                  </div>
                </div>
              </div>

              {/* Vulnerability list */}
              <div className="mt-8 space-y-3">
                {mockVulns.map((vuln, i) => {
                  const cfg = severityConfig[vuln.severity];
                  const Icon = cfg.icon;
                  return (
                    <motion.div key={vuln.title} initial={{ opacity: 0, x: -20 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ delay: 0.3 + i * 0.1 }} className={`flex items-center gap-4 rounded-xl border ${cfg.border} ${cfg.bg} p-4`}>
                      <div className={cfg.color}><Icon className="h-5 w-5" /></div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm font-medium text-white">{vuln.title}</p>
                        <p className="mt-0.5 text-xs text-gray-500">{vuln.type} &middot; {vuln.url}</p>
                      </div>
                      <span className={`hidden rounded-full px-2.5 py-0.5 text-xs font-semibold uppercase sm:inline ${cfg.color} ${cfg.bg}`}>{vuln.severity}</span>
                    </motion.div>
                  );
                })}
              </div>

              {/* Blurred remedy */}
              <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} transition={{ delay: 0.8 }} className="relative mt-6 overflow-hidden rounded-xl border border-emerald-500/20 bg-gray-900/80 p-5">
                <div className="mb-3 flex items-center gap-2">
                  <Sparkles className="h-4 w-4 text-emerald-400" />
                  <span className="text-sm font-semibold text-emerald-400">How to Fix — Content-Security-Policy</span>
                </div>
                <div className="pointer-events-none select-none text-sm leading-relaxed text-gray-400 blur-[4px]">
                  Add a Content-Security-Policy header to your web server or application. Start with a restrictive policy: Content-Security-Policy: default-src self; script-src self; style-src self unsafe-inline; img-src self data:; font-src self; connect-src self; For Next.js, add this to your next.config.js headers...
                </div>
                <div className="absolute inset-0 flex items-center justify-center bg-gray-950/30 backdrop-blur-[1px]">
                  <Link href="/register" className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 text-sm font-semibold text-white shadow-lg shadow-emerald-500/20 transition hover:from-emerald-600 hover:to-cyan-600 hover:shadow-emerald-500/30">
                    <Lock className="h-4 w-4" />
                    Upgrade to Unlock Fix Suggestions
                  </Link>
                </div>
              </motion.div>
            </div>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

/* ---- Dashboard Preview ---- */

function DashboardPreviewSection() {
  return (
    <section className="relative overflow-hidden py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="grid items-center gap-16 lg:grid-cols-2">
          <motion.div initial={{ opacity: 0, x: -30 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }}>
            <h2 className="text-3xl font-bold sm:text-4xl">Your Security <span className="gradient-text">Dashboard</span></h2>
            <p className="mt-4 text-lg text-gray-400">Track all your scans, manage credits, view trends, and re-scan at any time. Everything you need for ongoing vulnerability management in one place.</p>
            <div className="mt-8 space-y-4">
              {[
                { icon: BarChart3, title: "Scan History", desc: "View all past scans with scores, dates, and vulnerability counts" },
                { icon: TrendingUp, title: "Security Trends", desc: "Track how your security posture improves over time" },
                { icon: Zap, title: "One-Click Re-scan", desc: "Re-scan any URL instantly to verify your fixes worked" },
                { icon: Users, title: "Team Access", desc: "Invite your team (Pro plan) to collaborate on security" },
              ].map((item) => (
                <div key={item.title} className="flex gap-4">
                  <div className="flex h-10 w-10 shrink-0 items-center justify-center rounded-lg bg-emerald-500/10">
                    <item.icon className="h-5 w-5 text-emerald-400" />
                  </div>
                  <div>
                    <h4 className="font-medium text-white">{item.title}</h4>
                    <p className="text-sm text-gray-500">{item.desc}</p>
                  </div>
                </div>
              ))}
            </div>
          </motion.div>

          <motion.div initial={{ opacity: 0, x: 30 }} whileInView={{ opacity: 1, x: 0 }} viewport={{ once: true }} transition={{ duration: 0.7 }} className="relative">
            <div className="absolute -inset-4 rounded-3xl bg-gradient-to-br from-emerald-500/10 to-cyan-500/10 blur-2xl" />
            <div className="relative overflow-hidden rounded-2xl border border-gray-700/50 shadow-2xl shadow-black/40">
              <div className="flex items-center gap-3 border-b border-gray-800 bg-gray-900 px-4 py-3">
                <div className="flex gap-1.5">
                  <div className="h-3 w-3 rounded-full bg-red-500/70" />
                  <div className="h-3 w-3 rounded-full bg-yellow-500/70" />
                  <div className="h-3 w-3 rounded-full bg-green-500/70" />
                </div>
                <div className="flex-1 rounded-lg bg-gray-800 px-4 py-1.5 text-center text-xs text-gray-500">scanmysaas.com/dashboard</div>
              </div>

              <div className="bg-gray-950 p-6">
                <div className="grid grid-cols-3 gap-3">
                  {[
                    { label: "Total Scans", value: "12", color: "text-white" },
                    { label: "Credits Left", value: "8", color: "text-emerald-400" },
                    { label: "Avg Score", value: "74", color: "text-yellow-400" },
                  ].map((stat) => (
                    <div key={stat.label} className="rounded-xl border border-gray-800 bg-gray-900/50 p-4 text-center">
                      <p className={`text-2xl font-bold ${stat.color}`}>{stat.value}</p>
                      <p className="mt-1 text-xs text-gray-500">{stat.label}</p>
                    </div>
                  ))}
                </div>

                <div className="mt-4 rounded-xl border border-emerald-500/20 bg-gradient-to-r from-emerald-500/5 to-cyan-500/5 p-4">
                  <div className="flex items-center justify-between">
                    <div>
                      <div className="flex items-center gap-2">
                        <span className="text-sm font-semibold text-white">Starter Plan</span>
                        <span className="rounded-full bg-emerald-500/20 px-2 py-0.5 text-xs font-medium text-emerald-400">Active</span>
                      </div>
                      <p className="mt-0.5 text-xs text-gray-500">Renews Mar 14, 2026</p>
                    </div>
                    <span className="text-lg font-bold text-white">$29<span className="text-sm text-gray-500">/mo</span></span>
                  </div>
                </div>

                <div className="mt-4 space-y-2">
                  <p className="text-xs font-medium uppercase tracking-wider text-gray-500">Recent Scans</p>
                  {[
                    { url: "myapp.io", score: 87, vulns: 3, date: "2 hours ago", scoreColor: "text-emerald-400" },
                    { url: "staging.myapp.io", score: 62, vulns: 7, date: "Yesterday", scoreColor: "text-yellow-400" },
                    { url: "api.myapp.io", score: 91, vulns: 1, date: "3 days ago", scoreColor: "text-emerald-400" },
                  ].map((scan) => (
                    <div key={scan.url} className="flex items-center gap-3 rounded-lg border border-gray-800 bg-gray-900/30 p-3">
                      <div className={`w-10 text-center text-lg font-bold ${scan.scoreColor}`}>{scan.score}</div>
                      <div className="min-w-0 flex-1">
                        <p className="truncate text-sm text-white">{scan.url}</p>
                        <p className="text-xs text-gray-600">{scan.date}</p>
                      </div>
                      <span className="text-xs text-gray-500">{scan.vulns} issues</span>
                    </div>
                  ))}
                </div>
              </div>
            </div>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

/* ---- Features ---- */

function FeaturesSection() {
  const features = [
    { icon: Search, title: "Full Site Crawl & Vulnerability Detection", description: "Unlike basic scanning tools, our web vulnerability scanner crawls up to 10 pages on your site to detect vulnerabilities across your entire web application — not just the homepage." },
    { icon: Lock, title: "SSL/TLS & Web Server Scanner", description: "Verify your SSL certificate, check for mixed content, HTTPS redirects, and HSTS on your web server — the foundation of secure data transit and strong security posture." },
    { icon: Shield, title: "30+ Security Header Checks", description: "Run vulnerability checks on CSP, HSTS, X-Frame-Options, Permissions-Policy, Referrer-Policy, and more. Get exact configuration recommendations to fix security issues." },
    { icon: Code2, title: "XSS & Injection Vulnerability Scan", description: "Detect unsafe JavaScript patterns, inline eval(), document.write(), innerHTML usage, and potential cross-site scripting — common web application vulnerabilities in source code." },
    { icon: AlertTriangle, title: "CSRF & Access Controls Audit", description: "Verify forms have CSRF tokens and cookies have proper SameSite, HttpOnly, and Secure attributes. Check access controls to prevent cross-site request forgery attacks." },
    { icon: FileWarning, title: "Sensitive File & Open Ports Exposure", description: "Detect exposed .env files, .git repositories, database backups, debug logs, open ports, and 14+ other commonly leaked paths that penetration testers look for first." },
    { icon: Bug, title: "Known Vulnerabilities in Libraries", description: "Identify outdated jQuery, AngularJS 1.x, old Bootstrap, and unpatched software with known vulnerabilities — the kind of vulnerability discovery that prevents real breaches." },
    { icon: Zap, title: "Actionable Fix Suggestions", description: "Every vulnerability comes with a clear, developer-friendly explanation and exact code snippets. No manual testing or security jargon — just step-by-step remedies." },
  ];

  const moreChecks = [
    { icon: Mail, label: "Email Security (SPF/DMARC)" },
    { icon: Eye, label: "CSP Deep Analysis" },
    { icon: Cookie, label: "Cookie Security Audit" },
    { icon: Fingerprint, label: "Technology Fingerprinting" },
    { icon: FolderOpen, label: "Directory & robots.txt Audit" },
    { icon: Network, label: "CORS Misconfiguration" },
    { icon: Globe, label: "Open Redirect Detection" },
    { icon: ShieldCheck, label: "SRI & Supply Chain" },
  ];

  return (
    <section id="features" className="relative py-24 sm:py-32">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-gray-800 to-transparent" />
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">What Our Vulnerability Scanner<br /><span className="gradient-text">Checks For</span></h2>
          <p className="mt-4 text-lg text-gray-400">60+ automated vulnerability checks across 15 categories — covering the types of vulnerability that security teams care about most in modern web apps.</p>
        </div>

        <div className="mt-16 grid gap-6 sm:grid-cols-2 lg:grid-cols-4">
          {features.map((feature, index) => (
            <motion.div key={feature.title} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.4, delay: index * 0.05 }} className="group relative rounded-2xl border border-gray-800 bg-gray-900/50 p-6 transition hover:border-emerald-500/30 hover:bg-gray-900/80">
              <div className="pointer-events-none absolute -inset-px rounded-2xl bg-gradient-to-br from-emerald-500/0 to-cyan-500/0 opacity-0 transition-opacity group-hover:from-emerald-500/5 group-hover:to-cyan-500/5 group-hover:opacity-100" />
              <div className="relative">
                <div className="mb-4 flex h-12 w-12 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500/20 to-cyan-500/20 text-emerald-400 transition group-hover:from-emerald-500/30 group-hover:to-cyan-500/30">
                  <feature.icon className="h-6 w-6" />
                </div>
                <h3 className="text-lg font-semibold text-white">{feature.title}</h3>
                <p className="mt-2 text-sm leading-relaxed text-gray-400">{feature.description}</p>
              </div>
            </motion.div>
          ))}
        </div>

        <motion.div initial={{ opacity: 0 }} whileInView={{ opacity: 1 }} viewport={{ once: true }} className="mt-10 flex flex-wrap items-center justify-center gap-3">
          <span className="mr-2 text-sm text-gray-600">Also includes:</span>
          {moreChecks.map((check) => (
            <span key={check.label} className="inline-flex items-center gap-1.5 rounded-full border border-gray-800 bg-gray-900/50 px-3 py-1.5 text-xs text-gray-400">
              <check.icon className="h-3.5 w-3.5 text-emerald-500/60" />
              {check.label}
            </span>
          ))}
        </motion.div>
      </div>
    </section>
  );
}

/* ---- How It Works ---- */

function HowItWorksSection() {
  const steps = [
    { step: "01", title: "Enter your URL", description: "Paste your website URL into our vulnerability scanning tool. Start with a free scan — no credit card or GitHub account required.", icon: Globe },
    { step: "02", title: "Automated scanning begins", description: "Our automated scanner crawls your web app and runs 60+ security checks — SSL, headers, XSS, CSRF, cookie security, exposed files, and OWASP top 10 risks.", icon: Search },
    { step: "03", title: "Get your security report", description: "Receive a detailed vulnerability scan report with severity ratings. Upgrade to unlock step-by-step fix suggestions to eliminate critical vulnerabilities.", icon: ShieldCheck },
  ];

  return (
    <section id="how-it-works" className="relative py-24 sm:py-32">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-gray-800 to-transparent" />
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">How Does a Web Vulnerability <span className="gradient-text">Scanner Work?</span></h2>
          <p className="mt-4 text-lg text-gray-400">Run your first free website security scan in three simple steps</p>
        </div>

        <div className="mt-16 grid gap-8 md:grid-cols-3">
          {steps.map((item, index) => (
            <motion.div key={item.step} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.5, delay: index * 0.15 }} className="relative text-center">
              <div className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-2xl bg-gradient-to-br from-emerald-500 to-cyan-500 shadow-lg shadow-emerald-500/20">
                <item.icon className="h-9 w-9 text-white" />
              </div>
              {index < steps.length - 1 && (
                <div className="absolute top-10 left-[calc(50%+50px)] hidden w-[calc(100%-100px)] md:block">
                  <div className="border-t border-dashed border-gray-700" />
                  <ChevronRight className="absolute -right-3 -top-3 h-6 w-6 text-gray-700" />
                </div>
              )}
              <span className="text-xs font-bold uppercase tracking-widest text-emerald-500">Step {item.step}</span>
              <h3 className="mt-2 text-xl font-semibold">{item.title}</h3>
              <p className="mt-2 text-gray-400">{item.description}</p>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---- Urgency ---- */

function UrgencySection() {
  return (
    <section className="relative py-16">
      <div className="mx-auto max-w-4xl px-4 sm:px-6 lg:px-8">
        <motion.div initial={{ opacity: 0, scale: 0.95 }} whileInView={{ opacity: 1, scale: 1 }} viewport={{ once: true }} className="relative overflow-hidden rounded-2xl border border-amber-500/20 bg-gradient-to-br from-amber-500/5 via-gray-950 to-red-500/5 p-8 text-center sm:p-12">
          <div className="pointer-events-none absolute -top-20 left-1/2 h-40 w-80 -translate-x-1/2 animate-pulse rounded-full bg-amber-500/10 blur-3xl" />
          <div className="relative">
            <div className="mx-auto flex h-16 w-16 items-center justify-center rounded-full bg-amber-500/10 ring-1 ring-amber-500/20">
              <Clock className="h-8 w-8 text-amber-400" />
            </div>
            <h2 className="mt-6 text-2xl font-bold sm:text-3xl">Your Website Is Being Scanned by Attackers <span className="text-amber-400">Right Now</span></h2>
            <p className="mx-auto mt-4 max-w-2xl text-gray-400">Automated bots scan the internet 24/7 looking for unpatched software, exposed .env files, missing security headers, and known vulnerabilities. The average web application is probed within <span className="font-semibold text-white">39 hours</span> of going live.</p>
            <div className="mt-8 grid grid-cols-3 gap-4 sm:gap-6">
              {[
                { stat: "2,200+", label: "Attacks per day on avg web app" },
                { stat: "39 hrs", label: "Until first automated probe" },
                { stat: "73%", label: "Of breaches target web apps" },
              ].map((item) => (
                <div key={item.label} className="rounded-xl border border-gray-800 bg-gray-900/50 p-4">
                  <p className="text-xl font-bold text-amber-400 sm:text-2xl">{item.stat}</p>
                  <p className="mt-1 text-xs text-gray-500">{item.label}</p>
                </div>
              ))}
            </div>
            <button onClick={() => { window.scrollTo({ top: 0, behavior: "smooth" }); }} className="mt-8 inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-amber-500 to-orange-500 px-8 py-3 font-medium text-white transition hover:from-amber-600 hover:to-orange-600">
              Scan My Website Now — It&apos;s Free
              <ArrowRight className="h-4 w-4" />
            </button>
          </div>
        </motion.div>
      </div>
    </section>
  );
}

/* ---- Pricing ---- */

function PricingSection() {
  const plans = [
    { name: "Free", price: "$0", period: "forever", description: "Free website security scan — try our scanner", features: ["1 free scan credit", "Up to 25 pages per scan", "60+ vulnerability checks", "Security score & severity breakdown", "Vulnerability descriptions"], cta: "Start Free Scan", popular: false },
    { name: "Starter", price: "$29", period: "/month", description: "For indie hackers & small security teams", features: ["10 scan credits / month", "60+ vulnerability checks", "Fix suggestions & remedies", "PDF report export", "Email notifications", "Credits roll over (max 20)"], cta: "Get Starter", popular: true },
    { name: "Pro", price: "$79", period: "/month", description: "Full vulnerability management platform", features: ["30 scan credits / month", "Up to 50 pages per scan", "Fix suggestions & remedies", "API access & scheduled scans", "Slack & webhook alerts", "Team access (5 seats)", "Priority scanning queue", "Credits roll over (max 60)"], cta: "Go Pro", popular: false },
  ];

  return (
    <section id="pricing" className="relative py-24 sm:py-32">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-gray-800 to-transparent" />
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-2xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">Website Vulnerability Scanning <span className="gradient-text">Plans</span></h2>
          <p className="mt-4 text-lg text-gray-400">Start with a free website scanner and upgrade as your security needs grow. No hidden fees.</p>
        </div>

        <div className="mt-16 grid gap-8 lg:grid-cols-3">
          {plans.map((plan, index) => (
            <motion.div key={plan.name} initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ duration: 0.5, delay: index * 0.1 }} className={`relative rounded-2xl border p-8 transition ${plan.popular ? "glow scale-[1.02] border-emerald-500/50 bg-gray-900/80" : "border-gray-800 bg-gray-900/50 hover:border-gray-700"}`}>
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
              <Link href="/register" className={`mt-8 flex w-full items-center justify-center gap-2 rounded-xl px-6 py-3 font-medium transition ${plan.popular ? "bg-gradient-to-r from-emerald-500 to-cyan-500 text-white hover:from-emerald-600 hover:to-cyan-600" : "border border-gray-700 text-white hover:bg-gray-800"}`}>
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

/* ---- Comparison ---- */

function ComparisonSection() {
  return (
    <section className="relative py-24 sm:py-32">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="mx-auto max-w-3xl text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">How SecureSaaS Compares to Other<br /><span className="gradient-text">Scanning Tools</span></h2>
          <p className="mt-4 text-lg text-gray-400">There are many commercial and open source vulnerability scanners on the market — from enterprise-grade DAST tools to open source tools like Nikto web server scanner and OpenVAS. Here&apos;s how we fit in.</p>
        </div>

        <div className="mt-16 grid gap-8 md:grid-cols-2">
          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} className="rounded-2xl border border-gray-800 bg-gray-900/50 p-8">
            <h3 className="text-xl font-semibold text-white">Commercial and Open Source Alternatives</h3>
            <p className="mt-3 leading-relaxed text-gray-400">Tools like Burp Suite are powerful but complex — built for penetration testers and security teams with deep expertise. OpenVAS is a powerful open source vulnerability scanner designed for network-level vulnerability scanning across infrastructure. SAST tools analyze source code for flaws (static application security testing), while DAST tools like our scanner test running applications from the outside (dynamic application security testing). Commercial tools from major vendors or scanning tools by listing can cost thousands per year.</p>
          </motion.div>

          <motion.div initial={{ opacity: 0, y: 20 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: 0.1 }} className="rounded-2xl border border-emerald-500/20 bg-gray-900/50 p-8">
            <h3 className="text-xl font-semibold text-white">Why Choose SecureSaaS as Your Website Scanner</h3>
            <p className="mt-3 leading-relaxed text-gray-400">SecureSaaS is built specifically for web app security. Vulnerability scanners are automated tools that scan web applications for common flaws — and ours does exactly that, without the steep learning curve. No CLI setup, no false positives to wade through, no manual testing required. Just paste your URL and get actionable results. Unlike a web application security scanner aimed at enterprise, we&apos;re designed for SaaS builders, indie hackers, and small security teams who need fast, reliable application security testing.</p>
          </motion.div>
        </div>
      </div>
    </section>
  );
}

/* ---- FAQ ---- */

function FAQSection() {
  const [openIndex, setOpenIndex] = useState<number | null>(null);

  const faqs = [
    { question: "How does a website vulnerability scanner work?", answer: "A website vulnerability scanner is an automated tool that scans web applications for security flaws. It crawls your site, analyzes pages for known vulnerabilities like XSS, CSRF, missing security headers, SSL misconfigurations, and exposed files. SecureSaaS runs 60+ automated vulnerability checks and generates a report with severity ratings and fix suggestions." },
    { question: "What types of vulnerability does the scanner detect?", answer: "Our scanner covers a wide range of web application vulnerability categories: SSL/TLS issues, missing or misconfigured security headers, cross-site scripting (XSS), cross-site request forgery (CSRF), cookie security flaws, sensitive file exposure, outdated libraries with known vulnerabilities, CORS misconfigurations, open redirects, SPF/DMARC email security, and more — covering the OWASP top 10 risks." },
    { question: "Is SecureSaaS a free website vulnerability scanner?", answer: "Yes — every account starts with 1 free scan credit. Run a complete website vulnerability scanning session with full results, severity scores, and vulnerability descriptions at no cost. Upgrade to Starter ($29/mo) or Pro ($79/mo) to unlock fix suggestions, PDF exports, and more credits." },
    { question: "How is this different from Burp Suite or Nikto?", answer: "Burp Suite is a comprehensive web application scanner and testing tools platform built for penetration testers and security professionals. Nikto is an open source web server scanner focused on server-level checks. SecureSaaS provides automated scanning focused on web app security — no installation, no CLI, no steep learning curve. Think of it as application security testing made simple for developers." },
    { question: "Do I need penetration testing experience to use this?", answer: "Not at all. Unlike commercial tools that require expertise in penetration testing or security check configurations, SecureSaaS is designed for developers and SaaS builders. Just enter your URL and our security scanner handles the rest — vulnerability discovery, severity scoring, and actionable remedies you can implement immediately." },
    { question: "Does it reduce false positives?", answer: "Yes. Our scanner is tuned specifically for modern web apps and SaaS platforms, which significantly reduces false positives compared to generic scanning tools. Every finding includes context about why it matters and how to verify it, so your security teams can focus on real issues — not noise." },
  ];

  return (
    <section className="relative py-24 sm:py-32">
      <div className="absolute inset-x-0 top-0 h-px bg-gradient-to-r from-transparent via-gray-800 to-transparent" />
      <div className="mx-auto max-w-3xl px-4 sm:px-6 lg:px-8">
        <div className="text-center">
          <h2 className="text-3xl font-bold sm:text-4xl">Vulnerability Scanner <span className="gradient-text">FAQ</span></h2>
          <p className="mt-4 text-lg text-gray-400">Common questions about our web vulnerability scanning tool</p>
        </div>
        <div className="mt-12 space-y-3">
          {faqs.map((faq, index) => (
            <motion.div key={faq.question} initial={{ opacity: 0, y: 10 }} whileInView={{ opacity: 1, y: 0 }} viewport={{ once: true }} transition={{ delay: index * 0.05 }} className="overflow-hidden rounded-2xl border border-gray-800 bg-gray-900/50">
              <button onClick={() => setOpenIndex(openIndex === index ? null : index)} className="flex w-full items-center justify-between p-6 text-left">
                <h3 className="pr-4 text-lg font-semibold text-white">{faq.question}</h3>
                <ChevronDown className={`h-5 w-5 shrink-0 text-gray-500 transition-transform ${openIndex === index ? "rotate-180" : ""}`} />
              </button>
              <div className={`overflow-hidden transition-all duration-300 ${openIndex === index ? "max-h-96 pb-6" : "max-h-0"}`}>
                <p className="px-6 leading-relaxed text-gray-400">{faq.answer}</p>
              </div>
            </motion.div>
          ))}
        </div>
      </div>
    </section>
  );
}

/* ---- CTA ---- */

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
            <h2 className="mt-6 text-3xl font-bold sm:text-4xl">Automate Your Web App Security Scan</h2>
            <p className="mx-auto mt-4 max-w-xl text-lg text-gray-400">Don&apos;t wait for a security breach. Use our website vulnerability scanner to look for security vulnerabilities and fix them before attackers find them.</p>
            <div className="mt-8 flex flex-col items-center justify-center gap-4 sm:flex-row">
              <Link href="/register" className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-8 py-3 font-medium text-white shadow-lg shadow-emerald-500/20 transition hover:from-emerald-600 hover:to-cyan-600">
                Get Started Free
                <ArrowRight className="h-4 w-4" />
              </Link>
              <a href="#features" className="flex items-center gap-2 rounded-xl border border-gray-700 px-8 py-3 font-medium text-white transition hover:bg-gray-800">Learn More</a>
            </div>
          </div>
        </div>
      </div>
    </section>
  );
}

/* ---- Footer ---- */

function Footer() {
  return (
    <footer className="border-t border-gray-800/50 py-12">
      <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
        <div className="flex flex-col items-center justify-between gap-4 md:flex-row">
          <div className="flex items-center gap-2">
            <div className="flex h-8 w-8 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500">
              <Shield className="h-4 w-4 text-white" />
            </div>
            <span className="text-lg font-bold">Secure<span className="gradient-text">SaaS</span></span>
          </div>
          <a href="https://theresanaiforthat.com/ai/website-vulnerability-scanner-securesaas/?ref=featured&v=1092536" target="_blank" rel="nofollow">
            <img width={300} src="https://media.theresanaiforthat.com/featured-on-taaft.png?width=600" alt="Featured on TAAFT" />
          </a>
          <p className="text-sm text-gray-500">&copy; {new Date().getFullYear()} SecureSaaS. All rights reserved.</p>
          <div className="flex gap-6">
            <a href="/privacy" className="text-sm text-gray-400 hover:text-white">Privacy</a>
            <a href="/terms" className="text-sm text-gray-400 hover:text-white">Terms</a>
            <a href="/contact" className="text-sm text-gray-400 hover:text-white">Contact</a>
          </div>
        </div>
      </div>
    </footer>
  );
}

/* ---- Page ---- */

export default function HomePage() {
  return (
    <div className="min-h-screen" id="top-scanner">
      <Navbar />
      <HeroSection />
      <StatsSection />
      <ReportPreviewSection />
      <DashboardPreviewSection />
      <FeaturesSection />
      <HowItWorksSection />
      <UrgencySection />
      <PricingSection />
      <ComparisonSection />
      <FAQSection />
      <CTASection />
      <Footer />
    </div>
  );
}
