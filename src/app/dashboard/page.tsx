"use client";

import { useCallback, useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { signOut, useSession } from "next-auth/react";
import {
  AlertTriangle,
  BarChart3,
  CheckCircle2,
  Clock3,
  CreditCard,
  ExternalLink,
  FileSearch,
  Gauge,
  Github,
  Globe2,
  History,
  Loader2,
  LogOut,
  Minus,
  Plus,
  Search,
  ShieldCheck,
  Sparkles,
  TrendingDown,
  TrendingUp,
  XCircle,
  Zap,
} from "lucide-react";
import { Brand } from "@/components/Brand";
import ScanningOverlay from "@/components/ScanningOverlay";
import { ToastContainer, toast } from "@/components/Toast";
import { formatDate } from "@/lib/utils";
import { RepoScansSection } from "@/components/RepoScansSection";

interface Vulnerability { id: string; severity: string; type: string }
interface Scan { id: string; url: string; status: string; overallScore: number | null; pagesScanned: number; createdAt: string; vulnerabilities: Vulnerability[] }
interface UserPlan { plan: string; credits: number; scansUsed: number; hasSubscription: boolean; currentPeriodEnd: string | null }

function domainOf(url: string) {
  try { return new URL(url).hostname.replace(/^www\./, ""); } catch { return url; }
}

function scoreTone(score: number | null) {
  if (score === null) return "text-[#768190]";
  if (score >= 85) return "text-[var(--signal)]";
  if (score >= 65) return "text-[#ffcf78]";
  return "text-[#ff8585]";
}

function findingCount(scan: Scan) {
  return scan.vulnerabilities.filter((item) => item.type !== "scan-meta").length;
}

export default function DashboardPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState("");
  const [scanUrl, setScanUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [billingLoading, setBillingLoading] = useState(false);
  const [userPlan, setUserPlan] = useState<UserPlan>({ plan: "free", credits: 1, scansUsed: 0, hasSubscription: false, currentPeriodEnd: null });

  const loadData = useCallback(async () => {
    try {
      const [scanResponse, planResponse] = await Promise.all([fetch("/api/scan"), fetch("/api/user/plan")]);
      if (scanResponse.ok) setScans(await scanResponse.json());
      if (planResponse.ok) setUserPlan(await planResponse.json());
    } catch { /* handled with resilient empty states */ }
    finally { setLoading(false); }
  }, []);

  useEffect(() => { if (status === "unauthenticated") router.push("/login?redirect=/dashboard"); }, [status, router]);
  useEffect(() => { if (status === "authenticated") loadData(); }, [status, loadData]);

  const summary = useMemo(() => {
    const completed = scans.filter((scan) => scan.status === "completed" && scan.overallScore !== null);
    const average = completed.length ? Math.round(completed.reduce((total, scan) => total + (scan.overallScore || 0), 0) / completed.length) : null;
    const priority = scans.reduce((total, scan) => total + scan.vulnerabilities.filter((item) => item.severity === "critical" || item.severity === "high").length, 0);
    return { average, priority };
  }, [scans]);

  async function manageBilling() {
    setBillingLoading(true);
    try {
      const response = await fetch("/api/stripe/portal", { method: "POST" });
      const data = await response.json();
      if (data.url) window.location.href = data.url;
      else toast(data.error || "Billing portal could not be opened.", "error");
    } catch { toast("Billing portal could not be opened.", "error"); }
    finally { setBillingLoading(false); }
  }

  function startScan(event: React.FormEvent) {
    event.preventDefault();
    if (!url.trim()) return;
    if (userPlan.credits <= 0) { toast("You have no scan credits left. Choose a plan to continue.", "warning"); return; }
    setScanUrl(/^https?:\/\//i.test(url.trim()) ? url.trim() : `https://${url.trim()}`);
    setScanning(true);
  }

  if (status === "loading" || loading) return <div className="flex min-h-screen items-center justify-center"><Loader2 className="h-7 w-7 animate-spin text-[var(--signal)]" /></div>;
  if (status === "unauthenticated") return null;

  return (
    <main className="min-h-screen lg:grid lg:grid-cols-[15rem_1fr]">
      <aside className="hidden border-r border-white/[0.08] bg-[#090c11] lg:flex lg:flex-col lg:p-5">
        <Brand href="/dashboard" />
        <nav className="mt-10 space-y-1 text-sm">
          <Link href="/dashboard" className="flex items-center gap-3 rounded-xl bg-white/[0.06] px-3 py-2.5 font-medium text-white"><BarChart3 className="h-4 w-4 text-[var(--signal)]" /> Overview</Link>
          <a href="#new-scan" className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-[#8f99a7] hover:bg-white/[0.04] hover:text-white"><Plus className="h-4 w-4" /> New scan</a>
          <a href="#history" className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-[#8f99a7] hover:bg-white/[0.04] hover:text-white"><History className="h-4 w-4" /> Scan history</a>
          <a href="#repo-scans" className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-[#8f99a7] hover:bg-white/[0.04] hover:text-white"><Github className="h-4 w-4" /> Repositories</a>
          <Link href="/pricing" className="flex items-center gap-3 rounded-xl px-3 py-2.5 text-[#8f99a7] hover:bg-white/[0.04] hover:text-white"><Zap className="h-4 w-4" /> Plans</Link>
        </nav>
        <div className="mt-auto rounded-xl border border-white/[0.08] bg-white/[0.025] p-3">
          <p className="truncate text-xs font-medium text-[#cbd2da]">{session?.user?.name || session?.user?.email}</p>
          <p className="mt-1 truncate text-[0.68rem] text-[#687382]">{session?.user?.email}</p>
          <button onClick={() => signOut({ callbackUrl: "/" })} className="mt-3 flex w-full items-center gap-2 rounded-lg px-2 py-2 text-xs text-[#7f8998] hover:bg-white/[0.05] hover:text-white"><LogOut className="h-3.5 w-3.5" /> Sign out</button>
        </div>
      </aside>

      <div className="min-w-0">
        <header className="border-b border-white/[0.08] bg-[#07090d]/85 backdrop-blur-xl lg:hidden"><div className="flex h-16 items-center justify-between px-4"><Brand href="/dashboard" /><button onClick={() => signOut({ callbackUrl: "/" })} className="rounded-lg border border-white/10 p-2 text-[#9aa4b1]" aria-label="Sign out"><LogOut className="h-4 w-4" /></button></div></header>
        <div className="mx-auto max-w-[92rem] px-4 py-7 sm:px-7 sm:py-10 lg:px-10">
          <div className="flex flex-col gap-5 sm:flex-row sm:items-end sm:justify-between">
            <div><p className="eyebrow">Security workspace</p><h1 className="mt-3 text-3xl font-semibold tracking-[-0.045em] sm:text-4xl">Good to see you{session?.user?.name ? `, ${session.user.name.split(" ")[0]}` : ""}.</h1><p className="mt-2 text-sm text-[#7f8998]">Run a check, review the priority issues, and verify the next fix.</p></div>
            <a href="#new-scan" className="button-primary"><Plus className="h-4 w-4" /> New scan</a>
          </div>

          <section className="mt-8 grid grid-cols-2 gap-3 xl:grid-cols-4">
            {[
              { label: "Credits left", value: userPlan.credits, icon: Zap, tone: "text-[var(--amber)]" },
              { label: "Scans run", value: userPlan.scansUsed, icon: FileSearch, tone: "text-[var(--cobalt)]" },
              { label: "Average score", value: summary.average ?? "—", icon: Gauge, tone: summary.average === null ? "text-[#6e7988]" : scoreTone(summary.average) },
              { label: "Priority findings", value: summary.priority, icon: AlertTriangle, tone: summary.priority ? "text-[#ff8585]" : "text-[var(--signal)]" },
            ].map((stat) => <article key={stat.label} className="surface-muted rounded-xl p-4 sm:p-5"><div className="flex items-center justify-between"><p className="text-xs text-[#778191]">{stat.label}</p><stat.icon className={`h-4 w-4 ${stat.tone}`} /></div><p className="mt-5 text-3xl font-semibold tracking-[-0.05em]">{stat.value}</p></article>)}
          </section>

          <section className="mt-5 grid gap-5 xl:grid-cols-[1fr_20rem]">
            <div id="new-scan" className="surface rounded-2xl p-5 sm:p-7">
              <div className="flex items-start justify-between"><div><p className="text-sm font-semibold">Scan a website</p><p className="mt-1 text-xs text-[#788392]">Use a public URL you own or have permission to test.</p></div><Globe2 className="h-5 w-5 text-[var(--signal)]" /></div>
              <form onSubmit={startScan} className="mt-6 flex flex-col gap-2 sm:flex-row">
                <label className="input-shell flex min-w-0 flex-1 items-center gap-3 rounded-xl px-3.5"><Globe2 className="h-4 w-4 shrink-0 text-[#697483]" /><input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="app.yourcompany.com" inputMode="url" className="min-w-0 flex-1 bg-transparent py-3.5 text-sm text-white placeholder:text-[#596473] focus:outline-none" /></label>
                <button type="submit" disabled={!url.trim() || scanning} className="button-primary sm:min-w-32"><Search className="h-4 w-4" /> Scan now</button>
              </form>
              <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-[0.7rem] text-[#687382]"><span>60+ checks</span><span>Up to 25 pages</span><span>Uses 1 credit</span></div>
            </div>

            <aside className={`rounded-2xl border p-5 ${userPlan.plan === "free" ? "border-[var(--signal)]/20 bg-[var(--signal)]/[0.04]" : "border-white/[0.08] bg-white/[0.025]"}`}>
              <div className="flex items-center justify-between"><p className="text-xs font-semibold uppercase tracking-[.12em] text-[#7f8998]">Current plan</p><span className="rounded-full bg-white/[0.06] px-2 py-1 text-[0.62rem] font-semibold uppercase text-[#aeb7c4]">{userPlan.plan}</span></div>
              <p className="mt-6 text-2xl font-semibold tracking-[-0.04em]">{userPlan.plan === "free" ? "One scan to start." : `${userPlan.credits} credits ready.`}</p>
              <p className="mt-2 text-sm leading-6 text-[#7f8998]">{userPlan.plan === "free" ? "Upgrade to unlock every remediation guide and continue checking releases." : userPlan.currentPeriodEnd ? `Current period ends ${new Date(userPlan.currentPeriodEnd).toLocaleDateString("en-US", { month: "short", day: "numeric", year: "numeric" })}.` : "Your subscription is active."}</p>
              {userPlan.hasSubscription ? <button onClick={manageBilling} disabled={billingLoading} className="button-secondary mt-6 w-full"><CreditCard className="h-4 w-4" />{billingLoading ? "Opening…" : "Manage billing"}</button> : <Link href="/pricing" className="button-primary mt-6 w-full"><Sparkles className="h-4 w-4" /> View plans</Link>}
            </aside>
          </section>

          <section id="history" className="mt-10">
            <div className="mb-4 flex items-end justify-between"><div><h2 className="text-xl font-semibold tracking-[-0.025em]">Scan history</h2><p className="mt-1 text-xs text-[#717c8b]">Newest reports first</p></div>{scans.length > 0 && <span className="text-xs text-[#687382]">{scans.length} total</span>}</div>
            {scans.length === 0 ? (
              <div className="surface-muted rounded-2xl px-6 py-16 text-center"><div className="mx-auto flex h-12 w-12 items-center justify-center rounded-2xl bg-white/[0.04]"><ShieldCheck className="h-6 w-6 text-[#667180]" /></div><h3 className="mt-5 font-semibold">Your first report will live here.</h3><p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-[#778191]">Enter your website above to get a score, prioritized findings, and a report you can return to.</p></div>
            ) : (
              <div className="overflow-hidden rounded-2xl border border-white/[0.08]">
                <div className="hidden grid-cols-[1.3fr_.55fr_.55fr_.55fr_1.5rem] gap-4 border-b border-white/[0.08] bg-white/[0.025] px-5 py-3 text-[0.68rem] font-medium uppercase tracking-[.1em] text-[#687382] sm:grid"><span>Website</span><span>Score</span><span>Priority</span><span>Date</span><span /></div>
                <div className="divide-y divide-white/[0.07]">
                  {scans.map((scan, index) => {
                    const priority = scan.vulnerabilities.filter((item) => item.severity === "critical" || item.severity === "high").length;
                    const older = scans.find((candidate, candidateIndex) => candidateIndex > index && candidate.status === "completed" && candidate.overallScore !== null && domainOf(candidate.url) === domainOf(scan.url));
                    const delta = scan.overallScore !== null && older?.overallScore !== null && older?.overallScore !== undefined ? scan.overallScore - older.overallScore : null;
                    return <Link key={scan.id} href={`/scan/${scan.id}`} className="grid gap-4 bg-[#0a0e14] px-5 py-4 transition hover:bg-white/[0.035] sm:grid-cols-[1.3fr_.55fr_.55fr_.55fr_1.5rem] sm:items-center">
                      <div className="min-w-0"><div className="flex items-center gap-2"><span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${scan.status === "completed" ? "bg-[var(--signal)]/[0.07] text-[var(--signal)]" : scan.status === "failed" ? "bg-[#ff6b6b]/10 text-[#ff8585]" : "bg-white/[0.05] text-[#7f8998]"}`}>{scan.status === "completed" ? <CheckCircle2 className="h-4 w-4" /> : scan.status === "failed" ? <XCircle className="h-4 w-4" /> : <Loader2 className="h-4 w-4 animate-spin" />}</span><div className="min-w-0"><p className="truncate text-sm font-medium text-white">{domainOf(scan.url)}</p><p className="mt-0.5 text-[0.68rem] text-[#667180]">{scan.pagesScanned} pages · {findingCount(scan)} findings</p></div></div></div>
                      <div className="flex items-center gap-2"><span className={`text-xl font-semibold ${scoreTone(scan.overallScore)}`}>{scan.overallScore ?? "—"}</span>{delta !== null && <span className={`flex items-center text-[0.65rem] ${delta > 0 ? "text-[var(--signal)]" : delta < 0 ? "text-[#ff8585]" : "text-[#687382]"}`}>{delta > 0 ? <TrendingUp className="h-3 w-3" /> : delta < 0 ? <TrendingDown className="h-3 w-3" /> : <Minus className="h-3 w-3" />}{delta > 0 ? `+${delta}` : delta || ""}</span>}</div>
                      <div className={`text-sm ${priority ? "text-[#ff9696]" : "text-[#7f8998]"}`}>{priority || "None"}</div>
                      <div className="flex items-center gap-1.5 text-xs text-[#717c8b]"><Clock3 className="h-3.5 w-3.5" />{formatDate(scan.createdAt)}</div>
                      <ExternalLink className="hidden h-4 w-4 text-[#596473] sm:block" />
                    </Link>;
                  })}
                </div>
              </div>
            )}
          </section>

          <RepoScansSection />
        </div>
      </div>

      <ScanningOverlay url={scanUrl} isOpen={scanning} onClose={() => { setScanning(false); setScanUrl(""); setUrl(""); loadData(); }} />
      <ToastContainer />
    </main>
  );
}
