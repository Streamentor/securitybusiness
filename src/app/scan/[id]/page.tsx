"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useSession } from "next-auth/react";
import {
  AlertCircle,
  AlertTriangle,
  ArrowLeft,
  ArrowUpRight,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Clock3,
  FileSearch,
  Globe2,
  Info,
  Loader2,
  Lock,
  RotateCw,
  Share2,
  ShieldX,
  Sparkles,
  Trophy,
  Zap,
} from "lucide-react";
import { Brand } from "@/components/Brand";
import { CopyPromptButton } from "@/components/CopyPromptButton";
import ScanningOverlay from "@/components/ScanningOverlay";
import { ToastContainer, toast } from "@/components/Toast";
import { formatDate } from "@/lib/utils";
import { buildFixPrompt } from "@/lib/fix-prompt";
import { isVisibleWebsiteFinding } from "@/lib/scan-remediation";
import type { RemediationAccess } from "@/lib/scan-remediation";

interface Vulnerability { id: string; type: string; severity: string; title: string; description: string; url: string; remedy: string; remediationAccess: RemediationAccess }
interface Scan { id: string; url: string; status: string; overallScore: number | null; totalPages: number; pagesScanned: number; createdAt: string; completedAt: string | null; userId: string | null; vulnerabilities: Vulnerability[]; comparison?: ScanComparison | null }
interface ScanComparison { previousScanId: string; previousScore: number | null; previousCreatedAt: string; resolved: string[]; added: string[]; stillOpen: number }

const VERIFICATION_WINDOW_MS = 7 * 24 * 60 * 60 * 1000;
interface ReadinessItem { key: string; label: string; status: "pass" | "warning" | "unknown"; detail: string; url: string }

const severityOrder = ["critical", "high", "medium", "low", "info"];
const severityConfig: Record<string, { label: string; text: string; bg: string; border: string; icon: React.ElementType }> = {
  critical: { label: "Critical", text: "text-[#ff8585]", bg: "bg-[#ff6b6b]/[0.08]", border: "border-[#ff6b6b]/20", icon: ShieldX },
  high: { label: "High", text: "text-[#ffae76]", bg: "bg-[#ff9f43]/[0.08]", border: "border-[#ff9f43]/20", icon: AlertTriangle },
  medium: { label: "Medium", text: "text-[#ffd66b]", bg: "bg-[#ffd43b]/[0.07]", border: "border-[#ffd43b]/20", icon: AlertCircle },
  low: { label: "Low", text: "text-[#91a3ff]", bg: "bg-[#7b91ff]/[0.08]", border: "border-[#7b91ff]/20", icon: Info },
  info: { label: "Info", text: "text-[#a8b1bd]", bg: "bg-white/[0.035]", border: "border-white/[0.08]", icon: Info },
};

function scoreStatus(score: number) {
  if (score >= 85) return { label: "Strong", color: "#b9ff66" };
  if (score >= 65) return { label: "Needs work", color: "#ffbf69" };
  return { label: "At risk", color: "#ff6b6b" };
}

function guideForFinding(finding: Vulnerability) {
  if (finding.type === "ssl" || finding.title.toLowerCase().includes("strict-transport")) return "/guides/ssl-tls-checklist-for-saas";
  if (finding.type === "headers" || finding.type === "csp" || finding.type === "iframe") return "/guides/security-headers-for-saas";
  if (finding.type === "source-maps" || finding.type === "sensitive-file" || finding.type === "info-disclosure") return "/guides/exposed-files-and-source-maps";
  if (finding.type === "seo") return "/guides/robots-txt-and-sitemap-for-saas";
  return null;
}

function FindingCard({ finding, defaultOpen, expanded, onExpandedChange }: { finding: Vulnerability; defaultOpen: boolean; expanded?: boolean; onExpandedChange?: (value: boolean) => void }) {
  const [open, setOpen] = useState(defaultOpen);
  const isOpen = expanded ?? open;
  const freeFix = finding.remediationAccess === "free";
  const canViewRemedy = freeFix || finding.remediationAccess === "paid";
  const config = severityConfig[finding.severity] || severityConfig.info;
  const Icon = config.icon;
  const guideHref = guideForFinding(finding);
  const fixPrompt = buildFixPrompt({ surface: "deployed website", title: finding.title, severity: finding.severity, category: finding.type, target: finding.url, evidence: finding.description, remediation: finding.remedy });
  return (
    <article id={`finding-${finding.id}`} className={`scroll-mt-6 overflow-hidden rounded-xl border ${config.border} bg-[#0b1016]`}>
      <button onClick={() => onExpandedChange ? onExpandedChange(!isOpen) : setOpen(!isOpen)} className="grid w-full grid-cols-[auto_1fr_auto] items-start gap-3 p-4 text-left sm:gap-4 sm:p-5" aria-expanded={isOpen}>
        <span className={`flex h-9 w-9 items-center justify-center rounded-lg ${config.bg} ${config.text}`}><Icon className="h-4 w-4" /></span>
        <span className="min-w-0"><span className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold text-white sm:text-base">{finding.title}</span><span className={`rounded px-1.5 py-0.5 text-[0.61rem] font-bold uppercase tracking-[.08em] ${config.bg} ${config.text}`}>{config.label}</span>{freeFix && <span className="rounded bg-[var(--signal)]/10 px-1.5 py-0.5 text-[0.61rem] font-bold uppercase tracking-[.08em] text-[var(--signal)]">Free fix</span>}</span><span className="mt-1.5 block break-all text-xs leading-5 text-[#667180]">{finding.type} · {finding.url}</span></span>
        {isOpen ? <ChevronUp className="mt-2 h-4 w-4 text-[#687382]" /> : <ChevronDown className="mt-2 h-4 w-4 text-[#687382]" />}
      </button>
      {isOpen && (
        <div className="border-t border-white/[0.07] px-4 py-5 sm:px-5 sm:py-6 lg:px-6">
          <div className="grid min-w-0 gap-5 lg:grid-cols-[minmax(0,.82fr)_minmax(0,1.18fr)]">
            <div className="min-w-0"><p className="text-[0.68rem] font-bold uppercase tracking-[.12em] text-[#687382]">What we observed</p><p className="mt-3 break-words text-sm leading-7 text-[#a5aeba]">{finding.description}</p><div className="mt-5 rounded-lg border border-white/[0.07] bg-black/20 px-3 py-2.5"><p className="text-[0.65rem] font-medium uppercase tracking-[.1em] text-[#606b79]">Affected URL</p><p className="mt-1 break-all font-mono text-xs leading-5 text-[#909aa8]">{finding.url}</p></div>{guideHref && <Link href={guideHref} className="mt-4 inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--signal)] hover:underline">Understand this check <ArrowUpRight className="h-3.5 w-3.5" /></Link>}</div>
            <div className="min-w-0 rounded-xl border border-white/[0.08] bg-white/[0.025] p-4 sm:p-5">
              <div className="flex flex-wrap items-center justify-between gap-3"><div className="flex items-center gap-2 text-sm font-semibold text-white"><Sparkles className="h-4 w-4 text-[var(--signal)]" /> {freeFix ? "Your free fix" : "How to fix it"}</div>{canViewRemedy && <CopyPromptButton prompt={fixPrompt} />}</div>
              {canViewRemedy ? <pre className="mt-4 max-w-full overflow-x-auto whitespace-pre-wrap break-words font-sans text-sm leading-7 text-[#b6bec9]">{finding.remedy}</pre> : finding.remediationAccess === "none" ? <p className="mt-4 text-sm leading-6 text-[#8f99a7]">No implementation steps were provided for this observation. Review its evidence and any linked guide.</p> : <div className="mt-5 rounded-xl border border-[var(--signal)]/15 bg-[#0b1016] p-5 text-center"><span className="mx-auto flex h-10 w-10 items-center justify-center rounded-xl bg-[var(--signal)]/10 text-[var(--signal)]"><Lock className="h-4 w-4" /></span><p className="mt-3 text-sm font-semibold text-white">The remediation is ready.</p><p className="mx-auto mt-2 max-w-xs text-xs leading-5 text-[#8f99a7]">Unlock the implementation steps and configuration examples for this finding.</p><Link href="/pricing" className="button-primary mt-4 w-full sm:w-auto">Unlock the fix</Link></div>}
            </div>
          </div>
        </div>
      )}
    </article>
  );
}

export default function ScanResultPage() {
  const params = useParams();
  const { data: session } = useSession();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [userPlan, setUserPlan] = useState("free");
  const [userCredits, setUserCredits] = useState<number | null>(null);
  const [percentile, setPercentile] = useState<number | null>(null);
  const [filter, setFilter] = useState("all");
  const [freeFixExpanded, setFreeFixExpanded] = useState(true);
  const [rescanning, setRescanning] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const [scanResponse, planResponse] = await Promise.all([fetch(`/api/scan/${params.id}`), fetch("/api/user/plan")]);
        if (!scanResponse.ok) { setError("This scan could not be found."); return; }
        const scanData: Scan = await scanResponse.json();
        setScan(scanData);
        if (session?.user?.id && !scanData.userId) {
          fetch("/api/scan/claim", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scanId: scanData.id }) }).catch(() => undefined);
        }
        if (planResponse.ok) { const plan = await planResponse.json(); setUserPlan(plan.plan || "free"); setUserCredits(plan.credits ?? null); }
        if (scanData.overallScore !== null) {
          const response = await fetch(`/api/scan/percentile?score=${scanData.overallScore}`).catch(() => null);
          if (response?.ok) setPercentile((await response.json()).percentile);
        }
      } catch { setError("The report could not be loaded. Please try again."); }
      finally { setLoading(false); }
    }
    load();
  }, [params.id, session?.user?.id]);

  const canViewRemedies = userPlan === "starter" || userPlan === "pro";
  const findings = useMemo(() => [...(scan?.vulnerabilities || [])].filter(isVisibleWebsiteFinding).sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)), [scan]);
  const readiness = useMemo<ReadinessItem[]>(() => {
    const snapshot = scan?.vulnerabilities.find((finding) => finding.type === "scan-meta" && finding.title === "SaaS readiness snapshot");
    if (!snapshot) return [];
    try {
      const parsed = JSON.parse(snapshot.description) as { items?: ReadinessItem[] };
      return Array.isArray(parsed.items) ? parsed.items : [];
    } catch { return []; }
  }, [scan]);
  const counts = useMemo(() => Object.fromEntries(severityOrder.map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length])) as Record<string, number>, [findings]);
  const visibleFindings = filter === "all" ? findings : findings.filter((finding) => finding.severity === filter);
  const freeFix = findings.find((finding) => finding.remediationAccess === "free");
  const lockedFixCount = findings.filter((finding) => finding.remediationAccess === "locked").length;

  function openFreeFix() {
    if (!freeFix) return;
    setFilter("all");
    setFreeFixExpanded(true);
    requestAnimationFrame(() => document.getElementById(`finding-${freeFix.id}`)?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  async function shareReport() {
    try {
      if (navigator.share) await navigator.share({ title: "ScanMySaaS security report", url: window.location.href });
      else { await navigator.clipboard.writeText(window.location.href); toast("Report link copied.", "success"); }
    } catch { /* sharing dismissed */ }
  }

  // Free users get one verification rescan of their own site within 7 days; the server enforces it.
  const ownsScan = Boolean(session?.user?.id && scan?.userId === session.user.id);
  const verificationRescan = !canViewRemedies && ownsScan && !scan?.comparison && scan !== null && Date.now() - new Date(scan.createdAt).getTime() <= VERIFICATION_WINDOW_MS;
  const canRescan = Boolean(session?.user) && (verificationRescan || userCredits === null || userCredits > 0);

  function rescan() {
    if (!scan) return;
    if (!canRescan) { toast("You have no scan credits left.", "warning"); return; }
    setRescanning(true);
  }

  if (loading) return <div className="flex min-h-screen items-center justify-center"><Loader2 className="h-7 w-7 animate-spin text-[var(--signal)]" /></div>;
  if (error || !scan) return <div className="flex min-h-screen items-center justify-center px-5"><div className="max-w-sm text-center"><ShieldX className="mx-auto h-10 w-10 text-[#ff8585]" /><h1 className="mt-5 text-xl font-semibold">{error || "Scan not found"}</h1><Link href="/" className="button-secondary mt-6"><ArrowLeft className="h-4 w-4" /> Back home</Link></div></div>;

  const status = scoreStatus(scan.overallScore ?? 0);
  const priorityCount = counts.critical + counts.high;

  return (
    <main className="min-h-screen pb-20">
      <header className="border-b border-white/[0.08] bg-[#07090d]/88 backdrop-blur-xl"><div className="app-shell flex min-h-16 flex-wrap items-center justify-between gap-3 py-3"><Brand /><div className="flex items-center gap-2">{userCredits !== null && <span className="hidden items-center gap-1.5 rounded-lg border border-white/10 px-3 py-2 text-xs text-[#aab3bf] sm:flex"><Zap className="h-3.5 w-3.5 text-[var(--amber)]" />{userCredits} left</span>}<button onClick={shareReport} className="button-secondary !min-h-9 !px-3 !py-2"><Share2 className="h-3.5 w-3.5" /><span className="hidden sm:inline">Share</span></button>{session?.user && <button onClick={rescan} disabled={userCredits !== null && userCredits <= 0} className="button-primary !min-h-9 !px-3 !py-2"><RotateCw className="h-3.5 w-3.5" /><span className="hidden sm:inline">Rescan</span></button>}<Link href={session?.user ? "/dashboard" : "/"} className="ml-1 text-xs text-[#8a94a2] hover:text-white"><span className="hidden sm:inline">{session?.user ? "Dashboard" : "New scan"}</span><ArrowLeft className="h-4 w-4 sm:hidden" /></Link></div></div></header>

      <div className="app-shell py-8 sm:py-12">
        <section className="surface overflow-hidden rounded-2xl">
          <div className="grid gap-8 p-6 sm:p-8 lg:grid-cols-[1fr_auto] lg:items-center">
            <div><div className="flex items-center gap-2 text-xs text-[#798493]"><Globe2 className="h-3.5 w-3.5" /><span className="break-all">{scan.url}</span></div><h1 className="mt-4 text-3xl font-semibold tracking-[-0.05em] sm:text-4xl">Website security report</h1><div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-xs text-[#7b8695]"><span className="flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{formatDate(scan.createdAt)}</span><span className="flex items-center gap-1.5"><FileSearch className="h-3.5 w-3.5" />{scan.pagesScanned} pages</span><span className="flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5" />{findings.length} findings</span></div>{percentile !== null && <div className="mt-5 inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.035] px-3 py-1.5 text-xs text-[#aab3bf]"><Trophy className="h-3.5 w-3.5 text-[var(--amber)]" /> Scores above {percentile}% of scanned sites</div>}</div>
            <div className="flex items-center gap-5 lg:pl-12"><div className="relative flex h-32 w-32 items-center justify-center rounded-full" style={{ background: `conic-gradient(${status.color} ${(scan.overallScore ?? 0) * 3.6}deg, rgba(255,255,255,.07) 0deg)` }}><div className="absolute inset-[9px] rounded-full bg-[#10161e]" /><div className="relative text-center"><p className="text-4xl font-semibold tracking-[-0.06em]">{scan.overallScore ?? "—"}</p><p className="mt-0.5 text-[0.65rem] font-semibold uppercase tracking-[.1em]" style={{ color: status.color }}>{status.label}</p></div></div></div>
          </div>
          <div className="grid grid-cols-2 border-t border-white/[0.08] sm:grid-cols-5">{severityOrder.map((severity) => { const config = severityConfig[severity]; return <button key={severity} onClick={() => setFilter(filter === severity ? "all" : severity)} className={`border-r border-white/[0.07] px-4 py-4 text-left transition last:border-r-0 hover:bg-white/[0.025] ${filter === severity ? config.bg : ""}`}><p className={`text-2xl font-semibold ${config.text}`}>{counts[severity]}</p><p className="mt-1 text-[0.66rem] font-medium uppercase tracking-[.09em] text-[#697483]">{config.label}</p></button>; })}</div>
        </section>

        {freeFix && <section className="mt-6 rounded-2xl border border-[var(--signal)]/25 bg-[var(--signal)]/[0.05] p-5 sm:p-6"><div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between"><div className="min-w-0"><p className="flex items-center gap-2 text-sm font-semibold text-[var(--signal)]"><Sparkles className="h-4 w-4" /> One free fix included</p><h2 className="mt-2 text-lg font-semibold">{freeFix.title}</h2><p className="mt-2 max-w-2xl text-sm leading-6 text-[#9aa5b3]">Start with the highest-priority actionable finding in this report. Review the steps or copy its fix prompt into your coding agent, then verify the finding before changing code.</p></div><button onClick={openFreeFix} className="button-primary shrink-0">Open your free fix <ArrowUpRight className="h-4 w-4" /></button></div></section>}

        {readiness.length > 0 && <section className="mt-8">
          <div className="mb-4"><p className="eyebrow">SaaS readiness</p><h2 className="mt-2 text-xl font-semibold tracking-[-0.025em]">Discovery, trust, and crawl essentials</h2><p className="mt-1 text-xs leading-5 text-[#717c8b]">Operational signals that sit beside the security score and do not change it.</p></div>
          <div className="grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
            {readiness.map((item) => {
              const passing = item.status === "pass";
              const unknown = item.status === "unknown";
              return <a key={item.key} href={item.url} target="_blank" rel="noreferrer" className="surface-muted group min-w-0 rounded-xl p-4 transition hover:border-white/20">
                <div className="flex items-center justify-between gap-3"><p className="truncate text-sm font-semibold text-white">{item.label}</p><span className={`inline-flex shrink-0 items-center gap-1 rounded-full px-2 py-1 text-[0.62rem] font-bold uppercase tracking-[.08em] ${passing ? "bg-[var(--signal)]/10 text-[var(--signal)]" : unknown ? "bg-white/[0.06] text-[#98a2b3]" : "bg-[#ffbf69]/10 text-[#ffca7d]"}`}>{passing ? <CheckCircle2 className="h-3 w-3" /> : <AlertCircle className="h-3 w-3" />}{passing ? "Ready" : unknown ? "Check" : "Review"}</span></div>
                <p className="mt-3 text-xs leading-5 text-[#7f8998]">{item.detail}</p><span className="mt-4 inline-flex items-center gap-1 text-[0.68rem] text-[#626d7c] transition group-hover:text-white">Open resource <ArrowUpRight className="h-3 w-3" /></span>
              </a>;
            })}
          </div>
        </section>}

        <div className="mt-8 grid min-w-0 gap-8 xl:grid-cols-[minmax(0,1fr)_19rem]">
          <section className="min-w-0">
            {scan.comparison && <div className="surface-muted mb-6 rounded-2xl p-5">
              <div className="flex flex-wrap items-baseline justify-between gap-2"><h2 className="text-base font-semibold tracking-[-0.02em]">Since your previous scan</h2><Link href={`/scan/${scan.comparison.previousScanId}`} className="text-xs text-[#8f99a7] hover:text-white">{new Date(scan.comparison.previousCreatedAt).toLocaleDateString()} · score {scan.comparison.previousScore ?? "—"} → {scan.overallScore ?? "—"}</Link></div>
              <div className="mt-4 grid grid-cols-3 gap-3 text-center">
                <div className="rounded-xl bg-[#b9ff66]/[0.06] px-3 py-3"><p className="text-2xl font-semibold text-[#b9ff66]">{scan.comparison.resolved.length}</p><p className="mt-1 text-[0.66rem] uppercase tracking-[.09em] text-[#8f99a7]">Resolved</p></div>
                <div className="rounded-xl bg-[#ff6b6b]/[0.06] px-3 py-3"><p className="text-2xl font-semibold text-[#ff8585]">{scan.comparison.added.length}</p><p className="mt-1 text-[0.66rem] uppercase tracking-[.09em] text-[#8f99a7]">New</p></div>
                <div className="rounded-xl bg-white/[0.035] px-3 py-3"><p className="text-2xl font-semibold text-white">{scan.comparison.stillOpen}</p><p className="mt-1 text-[0.66rem] uppercase tracking-[.09em] text-[#8f99a7]">Still open</p></div>
              </div>
              {(scan.comparison.resolved.length > 0 || scan.comparison.added.length > 0) && <ul className="mt-4 space-y-1 text-xs leading-5 text-[#a5afbd]">{scan.comparison.resolved.map((title) => <li key={`r-${title}`}><span className="mr-2 text-[#b9ff66]">✓</span>{title}</li>)}{scan.comparison.added.map((title) => <li key={`a-${title}`}><span className="mr-2 text-[#ff8585]">+</span>{title}</li>)}</ul>}
            </div>}
            <div className="mb-4 flex items-center justify-between"><div><h2 className="text-xl font-semibold tracking-[-0.025em]">{filter === "all" ? "All findings" : `${severityConfig[filter].label} findings`}</h2><p className="mt-1 text-xs text-[#717c8b]">Ordered from highest to lowest priority</p></div>{filter !== "all" && <button onClick={() => setFilter("all")} className="text-xs text-[var(--signal)] hover:underline">Clear filter</button>}</div>
            {visibleFindings.length ? <div className="space-y-3">{visibleFindings.map((finding, index) => <FindingCard key={finding.id} finding={finding} defaultOpen={index === 0} expanded={finding.remediationAccess === "free" ? freeFixExpanded : undefined} onExpandedChange={finding.remediationAccess === "free" ? setFreeFixExpanded : undefined} />)}</div> : <div className="surface-muted rounded-2xl px-6 py-14 text-center"><CheckCircle2 className="mx-auto h-8 w-8 text-[var(--signal)]" /><p className="mt-4 font-medium">No {filter} findings.</p></div>}
          </section>

          <aside className="space-y-4 xl:sticky xl:top-6 xl:self-start">
            <div className="surface-muted rounded-2xl p-5"><p className="text-xs font-semibold uppercase tracking-[.12em] text-[#6e7988]">Next move</p><p className="mt-4 text-lg font-semibold tracking-[-0.025em]">{priorityCount ? `Start with ${priorityCount} priority finding${priorityCount === 1 ? "" : "s"}.` : findings.length ? "Work through the medium-risk findings." : "Keep monitoring after releases."}</p><p className="mt-3 text-sm leading-6 text-[#7f8998]">{priorityCount ? "Critical and high findings can have the largest impact. Verify each one before making a production change." : "A clean automated result is useful, but it does not prove the app is vulnerability-free."}</p></div>
            {!canViewRemedies && lockedFixCount > 0 && <div className="rounded-2xl border border-[var(--signal)]/20 bg-[var(--signal)]/[0.05] p-5"><span className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--signal)]/10 text-[var(--signal)]"><Lock className="h-4 w-4" /></span><h3 className="mt-5 font-semibold">Unlock the remaining fixes.</h3><p className="mt-2 text-sm leading-6 text-[#8f99a7]">{freeFix ? "Your first actionable fix is included. Paid plans add the remaining implementation steps and scan credits for follow-up checks." : "Paid plans add implementation steps and scan credits for follow-up checks."}</p><Link href="/pricing" className="button-primary mt-5 w-full">View plans</Link></div>}
            <button onClick={rescan} disabled={!canRescan} className="button-secondary w-full"><RotateCw className="h-4 w-4" /> {verificationRescan && !(userCredits && userCredits > 0) ? "Verify your fixes (free rescan)" : "Scan this site again"}</button>
            <Link href="/" className="flex items-center justify-center gap-2 py-2 text-xs text-[#737e8d] hover:text-white"><ArrowLeft className="h-3.5 w-3.5" /> Scan another website</Link>
          </aside>
        </div>
      </div>

      <ScanningOverlay url={scan.url} isOpen={rescanning} onClose={() => setRescanning(false)} />
      <ToastContainer />
    </main>
  );
}
