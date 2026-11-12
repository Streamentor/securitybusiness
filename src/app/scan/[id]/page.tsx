"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { useParams } from "next/navigation";
import { useSession } from "next-auth/react";
import {
  Github,
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
import { ReportUpgradeBanner } from "@/components/ReportUpgradeBanner";
import { ScanLimitDialog } from "@/components/ScanLimitDialog";
import { authPageHref, reportReturnHref, previewFindingTitles, type ScanLimit } from "@/lib/scan-journey";
import { ToastContainer, toast } from "@/components/Toast";
import { formatDate } from "@/lib/utils";
import { buildFixPrompt } from "@/lib/fix-prompt";
import { isVisibleWebsiteFinding } from "@/lib/scan-remediation";
import { COMPLIANCE_COVERAGE_TITLE, COMPLIANCE_DISCLAIMER, isComplianceFinding, parseComplianceCoverage } from "@/lib/compliance-types";
import type { RemediationAccess } from "@/lib/scan-remediation";

interface Vulnerability { id: string; type: string; severity: string; title: string; description?: string; url?: string; remedy?: string; detailsLocked?: boolean; remediationAccess: RemediationAccess }
interface Scan { id: string; url: string; status: string; overallScore: number | null; totalPages: number; pagesScanned: number; createdAt: string; completedAt: string | null; userId: string | null; vulnerabilities: Vulnerability[]; diagnostic?: {failureMessage?: string | null; failureCode?: string | null; partial?: boolean; coverageNote?: string | null} | null; access?: {owner: boolean; canClaim: boolean; shared: boolean; sharingEnabled: boolean; requiresAccount?: boolean}; comparison?: ScanComparison | null }
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

function scoreStatus(score: number, critical: number, high: number, partial: boolean, findingCount: number) {
  if (critical > 0) return {label: "Critical findings", color: "#ff6b6b"};
  if (high > 0) return {label: "High findings", color: "#ffbf69"};
  if (partial) return {label: "Partial scan", color: "#ffbf69"};
  if (findingCount > 0) return {label: "Findings to review", color: "#ffbf69"};
  if (score >= 85) return { label: "Strong", color: "#b9ff66" };
  if (score >= 65) return { label: "Needs work", color: "#ffbf69" };
  return { label: "At risk", color: "#ff6b6b" };
}

function guideForFinding(finding: Vulnerability) {
  if (finding.type === "ssl" || finding.title.toLowerCase().includes("strict-transport")) return "/guides/ssl-tls-checklist-for-saas";
  if (finding.type === "headers" || finding.type === "csp" || finding.type === "iframe") return "/guides/security-headers-for-saas";
  if (finding.type === "source-maps" || finding.type === "sensitive-file" || finding.type === "info-disclosure") return "/guides/exposed-files-and-source-maps";
  if (finding.type === "seo") return "/guides/robots-txt-and-sitemap-for-saas";
  if (finding.type === "cookies-consent") return "/guides/cookie-consent-for-saas";
  if (finding.type === "privacy") return "/guides/privacy-policy-checklist-for-saas";
  return null;
}

function FindingCard({ finding, defaultOpen, expanded, onExpandedChange, onRegister, registerHref }: { finding: Vulnerability; defaultOpen: boolean; expanded?: boolean; onExpandedChange?: (value: boolean) => void; onRegister: () => void; registerHref: string }) {
  const [open, setOpen] = useState(defaultOpen);
  const isOpen = expanded ?? open;
  const freeFix = finding.remediationAccess === "free";
  const canViewRemedy = freeFix || finding.remediationAccess === "paid";
  const config = severityConfig[finding.severity] || severityConfig.info;
  const Icon = config.icon;
  const guideHref = guideForFinding(finding);
  if (finding.detailsLocked) return <article id={`finding-${finding.id}`} className={`scroll-mt-24 rounded-xl border ${config.border} ${finding.severity !== "info" ? "border-l-[3px] border-l-[#ff6b6b] bg-[#ff6b6b]/[0.035]" : "bg-[#0b1016]"} p-4 sm:p-5`}><div className="flex items-start justify-between gap-3"><h3 className="min-w-0 break-words text-sm font-semibold text-white">{finding.title}</h3><span className={`shrink-0 text-xs font-semibold ${config.text}`}>{config.label}</span></div><Link href={`${registerHref}&finding=${encodeURIComponent(finding.id)}`} onClick={onRegister} className="mt-3 inline-flex items-center gap-2 text-xs text-[#ffc1c1] hover:underline"><Lock className="h-3.5 w-3.5" />Open this finding with a free account</Link></article>;
  const fixPrompt = buildFixPrompt({ surface: "deployed website", title: finding.title, severity: finding.severity, category: finding.type, target: finding.url || "", evidence: finding.description || "", remediation: finding.remedy || "" });
  return (
    <article id={`finding-${finding.id}`} className={`scroll-mt-24 overflow-hidden rounded-xl border ${config.border} bg-[#0b1016]`}>
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
  const [limit, setLimit] = useState<ScanLimit | null>(null);
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
  const [shareUrl, setShareUrl] = useState("");
  const [sharingBusy, setSharingBusy] = useState(false);

  useEffect(() => {
    async function load() {
      try {
        const token = new URLSearchParams(window.location.hash.slice(1)).get("share");
        const [scanResponse, planResponse] = await Promise.all([fetch(`/api/scan/${params.id}`, {cache: "no-store", headers: token ? {"x-report-share-token": token} : {}}), fetch("/api/user/plan")]);
        if (!scanResponse.ok) { setError("Report unavailable. Sign in as its owner or open an active sharing link."); return; }
        const scanData: Scan = await scanResponse.json();
        setScan(scanData);
        if (session?.user?.id && scanData.access?.canClaim) {
          const claimed = await fetch("/api/scan/claim", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scanId: scanData.id }) });
          if (claimed.ok) {
            if (sessionStorage.getItem("pendingScanId") === scanData.id) sessionStorage.removeItem("pendingScanId");
            setScan({...scanData, userId: session.user.id, access: {...scanData.access, owner: true, canClaim: false}});
          }
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

  useEffect(() => {
    if (loading) return;
    const match = window.location.hash.match(/^#finding-([A-Za-z0-9_-]{1,100})$/);
    if (match) requestAnimationFrame(() => document.getElementById(`finding-${match[1]}`)?.scrollIntoView({block: "start"}));
  }, [loading, scan?.id]);

  const canViewRemedies = userPlan === "starter" || userPlan === "pro";
  const allFindings = useMemo(() => [...(scan?.vulnerabilities || [])].filter(isVisibleWebsiteFinding).sort((a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)), [scan]);
  // Privacy, consent and accessibility findings have their own section and do not count toward the security summary.
  const findings = useMemo(() => allFindings.filter((finding) => !isComplianceFinding(finding)), [allFindings]);
  const complianceFindings = useMemo(() => allFindings.filter(isComplianceFinding), [allFindings]);
  const complianceCoverage = useMemo(() => parseComplianceCoverage(scan?.vulnerabilities.find((finding) => finding.type === "scan-meta" && finding.title === COMPLIANCE_COVERAGE_TITLE)?.description), [scan]);
  const readiness = useMemo<ReadinessItem[]>(() => {
    const snapshot = scan?.vulnerabilities.find((finding) => finding.type === "scan-meta" && finding.title === "SaaS readiness snapshot");
    if (!snapshot) return [];
    try {
      const parsed = JSON.parse(snapshot.description || "{}") as { items?: ReadinessItem[] };
      return Array.isArray(parsed.items) ? parsed.items : [];
    } catch { return []; }
  }, [scan]);
  const counts = useMemo(() => Object.fromEntries(severityOrder.map((severity) => [severity, findings.filter((finding) => finding.severity === severity).length])) as Record<string, number>, [findings]);
  const visibleFindings = filter === "all" ? findings : findings.filter((finding) => finding.severity === filter);
  const freeFix = allFindings.find((finding) => finding.remediationAccess === "free");
  const displayedFindings = scan?.access?.requiresAccount && filter === "all" && freeFix && !isComplianceFinding(freeFix) ? [freeFix, ...visibleFindings.filter(finding => finding.id !== freeFix.id)] : visibleFindings;
  const lockedFixCount = allFindings.filter((finding) => finding.remediationAccess === "locked").length;

  const registerHref = authPageHref("register", {scanId: String(params.id)});
  function startRegistration() {
    if (!scan) return;
    sessionStorage.setItem("pendingScanId", scan.id);
    void fetch(`/api/scan/${scan.id}/signup`, {method: "POST", keepalive: true}).catch(() => undefined);
  }

  function openFreeFix() {
    if (!freeFix) return;
    setFilter("all");
    setFreeFixExpanded(true);
    requestAnimationFrame(() => document.getElementById(`finding-${freeFix.id}`)?.scrollIntoView({ behavior: "smooth", block: "start" }));
  }

  async function shareReport() {
    if (!scan) return;
    setSharingBusy(true);
    try {
      const response = await fetch(`/api/scan/${scan.id}/share`, {method: "POST"});
      if (!response.ok) throw new Error();
      const data = await response.json();
      setShareUrl(data.url);
      setScan({...scan, access: {...scan.access!, sharingEnabled: true}});
      toast("Sharing link created. Anyone with this link can view the report.", "success");
    } catch { toast("Could not create sharing link. Please try again.", "warning"); }
    finally { setSharingBusy(false); }
  }
  async function revokeShare() {
    if (!scan) return;
    setSharingBusy(true);
    try {
      const response = await fetch(`/api/scan/${scan.id}/share`, {method: "DELETE"});
      if (!response.ok) throw new Error();
      setShareUrl("");
      setScan({...scan, access: {...scan.access!, sharingEnabled: false}});
      toast("Sharing link revoked. Existing links no longer work.", "success");
    } catch { toast("Could not revoke sharing link. Please try again.", "warning"); }
    finally { setSharingBusy(false); }
  }

  // Free users get one verification rescan of their own site within 7 days; the server enforces it.
  const ownsScan = Boolean(session?.user?.id && scan?.userId === session.user.id);
  const verificationRescan = !canViewRemedies && ownsScan && !scan?.comparison && scan !== null && Date.now() - new Date(scan.createdAt).getTime() <= VERIFICATION_WINDOW_MS;


  function rescan() {
    if (!scan) return;
    if (!session?.user) {
      setLimit({message: "Sign in to check your free verification rescan, or choose a paid plan for monthly scan credits.", rateLimited: false});
      return;
    }
    // The server decides verification eligibility and reserves credits atomically.
    // Zero credits must not disable an eligible free verification rescan.
    setRescanning(true);
  }

  if (loading) return <div className="flex min-h-screen items-center justify-center"><Loader2 className="h-7 w-7 animate-spin text-[var(--signal)]" /></div>;
  if (error || !scan) return <div className="flex min-h-screen items-center justify-center px-5"><div className="max-w-sm text-center"><ShieldX className="mx-auto h-10 w-10 text-[#ff8585]" /><h1 className="mt-5 text-xl font-semibold">{error || "Scan not found"}</h1><Link href="/login" className="button-secondary mt-6">Sign in</Link><Link href="/" className="ml-4 text-sm">Back home</Link></div></div>;

  if (scan.status === "failed") return <main className="app-shell py-16"><Brand /><section className="surface mt-8 max-w-2xl rounded-2xl p-6"><h1 className="text-2xl font-semibold">The scan could not finish</h1><p className="mt-4 text-sm leading-7 text-[#a5aeba]">{scan.diagnostic?.failureMessage || "This scan did not record a detailed failure reason. No security score was calculated. Try again when the public website is reachable."}</p><Link href="/free-website-vulnerability-scanner" className="button-primary mt-6">Try your website again</Link><Link href="/repo-scan" className="button-secondary ml-3 mt-6">Scan your repository</Link></section></main>;

  const status = scoreStatus(scan.overallScore ?? 0, counts.critical, counts.high, Boolean(scan.diagnostic?.partial), findings.length);
  const siteHost = (() => { try { return new URL(scan.url).hostname.replace(/^www\./, ""); } catch { return "your site"; } })();
  const priorityCount = counts.critical + counts.high;

  return (
    <main className="min-h-screen pb-20">
      <header className="border-b border-white/[0.08] bg-[#07090d]/88 backdrop-blur-xl"><div className="app-shell flex min-h-16 flex-wrap items-center justify-between gap-3 py-3"><Brand /><div className="flex items-center gap-2">{session?.user && userCredits !== null && <span className="hidden items-center gap-1.5 rounded-lg border border-white/10 px-3 py-2 text-xs text-[#aab3bf] sm:flex"><Zap className="h-3.5 w-3.5 text-[var(--amber)]" />{userCredits} left</span>}{ownsScan && <button onClick={shareReport} disabled={sharingBusy} className="button-secondary !min-h-9 !px-3 !py-2"><Share2 className="h-3.5 w-3.5" /><span>{scan.access?.sharingEnabled ? "Replace share link" : "Create share link"}</span></button>}{session?.user && <button onClick={rescan} aria-label="Rescan this website" className="button-primary !min-h-9 !px-3 !py-2"><RotateCw className="h-3.5 w-3.5" /><span className="hidden sm:inline">Rescan</span></button>}<Link href={session?.user ? "/dashboard" : "/"} className="ml-1 text-xs text-[#8a94a2] hover:text-white"><span className="hidden sm:inline">{session?.user ? "Dashboard" : "New scan"}</span><ArrowLeft className="h-4 w-4 sm:hidden" /></Link></div></div></header>

      {!canViewRemedies && <ReportUpgradeBanner />}

      <div className="app-shell py-8 sm:py-12">
        {ownsScan && (shareUrl || scan.access?.sharingEnabled) && <section className="surface-muted mb-6 rounded-xl p-4" aria-label="Report sharing">
          <p className="text-sm text-[#a5aeba]">{scan.access?.sharingEnabled ? "Link sharing is enabled. Anyone with the current link can view this report." : "This report is private. Create a sharing link to let someone else view it."}</p>
          {shareUrl && <div className="mt-3 flex flex-wrap gap-2"><input aria-label="Sharing link" readOnly value={shareUrl} className="min-w-0 flex-1 rounded border border-white/10 bg-black/20 p-2 text-xs" /><button className="button-secondary" onClick={async () => {try {await navigator.clipboard.writeText(shareUrl); toast("Sharing link copied.", "success");} catch {toast("Select and copy the sharing link above.", "warning");}}}>Copy link</button></div>}
          {scan.access?.sharingEnabled && <button className="button-secondary mt-3" disabled={sharingBusy} onClick={revokeShare}>Revoke sharing link</button>}
        </section>}
        {scan.access?.shared && !ownsScan && <p className="mb-6 text-sm text-[#a5aeba]">Shared report · access can be revoked by its owner.</p>}

        <section className={`surface overflow-hidden rounded-2xl ${findings.length > 0 ? "!border-[#ff6b6b]/30" : ""}`}>
          <div className="grid grid-cols-[minmax(0,1fr)_auto] items-center gap-4 p-4 sm:gap-8 sm:p-8">
            <div><div className="flex items-center gap-2 text-xs text-[#798493]"><Globe2 className="h-3.5 w-3.5" /><span className="break-all">{scan.url}</span></div><h1 className="mt-3 text-xl font-semibold tracking-[-0.05em] sm:text-4xl">Website security report</h1><p className={`mt-3 flex items-start gap-2 text-sm font-semibold sm:text-lg ${findings.length > 0 ? "text-[#ff9292]" : "text-[#cbd3df]"}`}><AlertTriangle className="mt-1 h-5 w-5 shrink-0" />{findings.length > 0 ? `${findings.length} finding${findings.length === 1 ? "" : "s"} to review, even with a ${scan.overallScore ?? "—"}/100 score.` : "No findings observed. Your repository has not been assessed."}</p><div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-xs text-[#7b8695]"><span className="flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{formatDate(scan.createdAt)}</span><span className="flex items-center gap-1.5"><FileSearch className="h-3.5 w-3.5" />{scan.pagesScanned} pages</span><span className="flex items-center gap-1.5"><AlertTriangle className="h-3.5 w-3.5" />{findings.length} findings</span></div>{percentile !== null && findings.length === 0 && !scan.diagnostic?.partial && <div className="mt-5 inline-flex items-center gap-1.5 rounded-full border border-white/[0.08] bg-white/[0.035] px-3 py-1.5 text-xs text-[#aab3bf]"><Trophy className="h-3.5 w-3.5 text-[var(--amber)]" /> Scores above {percentile}% of scanned sites</div>}</div>
            <div className="flex items-center gap-5 lg:pl-12"><div className="relative flex h-28 w-28 items-center sm:h-32 sm:w-32 justify-center rounded-full" style={{ background: `conic-gradient(${status.color} ${(scan.overallScore ?? 0) * 3.6}deg, rgba(255,255,255,.07) 0deg)` }}><div className="absolute inset-[9px] rounded-full bg-[#10161e]" /><div className="relative max-w-[90px] text-center"><p className="mb-1 text-[0.56rem] font-semibold uppercase tracking-wide text-[#98a2b3]">Public surface</p><p className="text-3xl font-semibold tracking-[-0.06em] sm:text-4xl">{scan.overallScore ?? "—"}</p><p className="mx-auto mt-0.5 max-w-[88px] text-[0.56rem] font-semibold uppercase leading-3 tracking-[.04em]" style={{ color: status.color }}>{status.label}</p></div></div></div>
          </div>
          <div className="grid grid-cols-5 border-t border-white/[0.08]">{severityOrder.map((severity) => { const config = severityConfig[severity]; return <button key={severity} onClick={() => setFilter(filter === severity ? "all" : severity)} className={`border-r border-white/[0.07] px-2 py-4 text-left sm:px-4 transition last:border-r-0 hover:bg-white/[0.025] ${filter === severity ? config.bg : ""}`}><p className={`text-2xl font-semibold ${counts[severity] > 0 && severity !== "info" ? "text-[#ff9292]" : "text-[#697483]"}`}>{counts[severity]}</p><p className="mt-1 text-[0.66rem] font-medium uppercase tracking-[.09em] text-[#697483]">{config.label}</p></button>; })}</div>
          {findings.length > 1 && <nav aria-label="Priority finding titles" className="border-t border-white/[0.08] px-4 py-2 sm:px-8">{previewFindingTitles(findings).map(preview => {
            const finding = findings.find(item => item.title === preview.title);
            if (!finding) return null;
            return <a key={finding.title} href={`#finding-${finding.id}`} className="flex items-center justify-between gap-3 py-2 text-xs hover:underline"><span className="min-w-0 truncate text-[#e2e8f0]">{finding.title}</span><span className={`shrink-0 capitalize ${(severityConfig[finding.severity] || severityConfig.info).text}`}>{finding.severity}</span></a>;
          })}</nav>}

        </section>

        <div className="mt-5 grid min-w-0 gap-8 xl:grid-cols-[minmax(0,1fr)_19rem]">
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
            <div className="mb-4 flex items-center justify-between"><div><h2 className="text-xl font-semibold tracking-[-0.025em]">{filter === "all" ? "All findings" : `${severityConfig[filter].label} findings`}</h2><p className="mt-1 text-xs text-[#717c8b]">{scan.access?.requiresAccount && freeFix ? "One complete finding first. Remaining findings follow in priority order." : "Ordered from highest to lowest priority"}</p></div>{freeFix && <button onClick={openFreeFix} className="ml-3 shrink-0 text-xs font-semibold text-[var(--signal)]">Open your free fix</button>}{filter !== "all" && <button onClick={() => setFilter("all")} className="text-xs text-[var(--signal)] hover:underline">Clear filter</button>}</div>
            {visibleFindings.length ? <div className="space-y-3">{displayedFindings.map((finding, index) => <FindingCard key={finding.id} onRegister={startRegistration} registerHref={registerHref} finding={finding} defaultOpen={index === 0} expanded={finding.remediationAccess === "free" ? freeFixExpanded : undefined} onExpandedChange={finding.remediationAccess === "free" ? setFreeFixExpanded : undefined} />)}</div> : <div className="surface-muted rounded-2xl px-6 py-14 text-center"><CheckCircle2 className="mx-auto h-8 w-8 text-[var(--signal)]" /><p className="mt-4 font-medium">No {filter} findings.</p></div>}
          </section>

          <aside className="space-y-4 xl:sticky xl:top-6 xl:self-start">
            <div className="surface-muted rounded-2xl p-5"><p className="text-xs font-semibold uppercase tracking-[.12em] text-[#6e7988]">Next move</p><p className="mt-4 text-lg font-semibold tracking-[-0.025em]">{priorityCount ? `Start with ${priorityCount} priority finding${priorityCount === 1 ? "" : "s"}.` : findings.length ? "Work through the medium-risk findings." : "Keep monitoring after releases."}</p><p className="mt-3 text-sm leading-6 text-[#7f8998]">{priorityCount ? "Critical and high findings can have the largest impact. Verify each one before making a production change." : "A clean automated result is useful, but it does not prove the app is vulnerability-free."}</p></div>
            {!scan.access?.requiresAccount && !canViewRemedies && lockedFixCount > 0 && <div className="rounded-2xl border border-[var(--signal)]/20 bg-[var(--signal)]/[0.05] p-5"><span className="flex h-9 w-9 items-center justify-center rounded-xl bg-[var(--signal)]/10 text-[var(--signal)]"><Lock className="h-4 w-4" /></span><h3 className="mt-5 font-semibold">Unlock the remaining fixes.</h3><p className="mt-2 text-sm leading-6 text-[#8f99a7]">{freeFix ? "Your first actionable fix is included. Paid plans add the remaining implementation steps and scan credits for follow-up checks." : "Paid plans add implementation steps and scan credits for follow-up checks."}</p><Link href="/pricing" className="button-primary mt-5 w-full">View plans</Link></div>}
            <button onClick={rescan} className="button-secondary w-full"><RotateCw className="h-4 w-4" /> {verificationRescan && !(userCredits && userCredits > 0) ? "Verify your fixes (free rescan)" : "Scan this site again"}</button>
            <Link href="/" className="flex items-center justify-center gap-2 py-2 text-xs text-[#737e8d] hover:text-white"><ArrowLeft className="h-3.5 w-3.5" /> Scan another website</Link>
          </aside>
        </div>

        {scan.access?.requiresAccount && <section className="mt-6 rounded-2xl border border-[#ff6b6b]/30 bg-[#ff6b6b]/[0.05] p-5 sm:p-6" aria-label="Open your report">
          <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#ff9292]"><Lock className="h-4 w-4" /> Your report is ready</p>
          <h2 className="mt-3 text-2xl font-semibold">{findings.filter(f => f.detailsLocked).length > 0 ? `Open all findings for ${siteHost}.` : "Save your report."}</h2>
          <p className="mt-3 max-w-3xl text-sm leading-6 text-[#b7c0cd]">Create a free account to see every affected page and finding description. You will return to this report. One available fix is included; remaining fixes are on paid plans.</p>
          <div className="mt-5 flex flex-wrap gap-3"><Link href={registerHref} onClick={startRegistration} className="button-primary">Create free account to open findings <ArrowUpRight className="h-4 w-4" /></Link><Link href={authPageHref("login", {scanId: scan.id})} onClick={() => sessionStorage.setItem("pendingScanId", scan.id)} className="button-secondary">Already have an account? Sign in</Link></div>
          <p className="mt-3 text-xs text-[#98a2b3]">No card needed. One fix included when available; remaining fix steps require a paid plan.</p>
        </section>}

        {(complianceCoverage || complianceFindings.length > 0) && <section id="compliance" className="mt-8" aria-label="Privacy and compliance">
          <div className="mb-4"><p className="eyebrow">Privacy & compliance</p><h2 className="mt-2 text-xl font-semibold tracking-[-0.025em]">{complianceFindings.filter((finding) => finding.severity !== "info").length ? `${complianceFindings.filter((finding) => finding.severity !== "info").length} privacy, consent or accessibility finding${complianceFindings.filter((finding) => finding.severity !== "info").length === 1 ? "" : "s"}` : "No privacy or accessibility findings in the checks that ran"}</h2><p className="mt-1 max-w-3xl text-xs leading-5 text-[#8f99a7]">{COMPLIANCE_DISCLAIMER} These findings do not change the security score.</p>
            {complianceCoverage && <ul className="mt-3 flex flex-wrap gap-x-5 gap-y-1 text-xs text-[#717c8b]">
              <li>{complianceCoverage.browser === "ran" ? "Browser consent test ran (first visit, Reject, Global Privacy Control)" : complianceCoverage.browser === "plan" ? "Browser consent test: Starter and Pro" : "Browser consent test could not run this time"}</li>
              <li>{complianceCoverage.ai === "ran" ? "AI privacy policy review ran" : complianceCoverage.ai === "plan" ? "AI privacy policy review: Pro" : complianceCoverage.ai === "off" ? "AI review is off in your account" : complianceCoverage.ai === "no-policy" ? "No readable privacy policy to review" : "AI privacy policy review was unavailable"}</li>
              {complianceCoverage.policyUrl && <li><a href={complianceCoverage.policyUrl} target="_blank" rel="noreferrer" className="hover:text-white hover:underline">Privacy policy read</a></li>}
            </ul>}
          </div>
          {complianceFindings.length ? <div className="space-y-3">{complianceFindings.map((finding) => <FindingCard key={finding.id} onRegister={startRegistration} registerHref={registerHref} finding={finding} defaultOpen={false} expanded={finding.remediationAccess === "free" ? freeFixExpanded : undefined} onExpandedChange={finding.remediationAccess === "free" ? setFreeFixExpanded : undefined} />)}</div> : <div className="surface-muted rounded-2xl px-6 py-8 text-center text-sm text-[#a5aeba]"><CheckCircle2 className="mx-auto h-6 w-6 text-[var(--signal)]" /><p className="mt-3">No missing privacy pages, consent problems or accessibility issues were detected on the scanned pages.</p></div>}
        </section>}

        <section className="mt-6 grid gap-4 lg:grid-cols-2" aria-label="Scan the code and unlock fixes">
          <div className="rounded-2xl border border-[#ff6b6b]/25 bg-[#ff6b6b]/[0.04] p-5 sm:p-6">
            <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#ff9292]"><Github className="h-4 w-4" /> Repository not assessed</p>
            <h2 className="mt-3 text-xl font-semibold">Now scan the code behind {siteHost}.</h2>
            <p className="mt-3 text-sm leading-6 text-[#aeb8c5]">This report only sees what is public. Scan the repository for committed secrets, risky GitHub Actions, missing database-rule signals and vulnerable dependencies, with findings pointing to the file and line.</p>
            <Link href={`/repo-scan?report=${scan.id}`} className="button-secondary mt-5 w-full sm:w-auto">Scan your repository <ArrowUpRight className="h-4 w-4" /></Link>
            <p className="mt-3 text-xs text-[#98a2b3]">Public repos are free. Private repos use a read-only GitHub App on paid plans.</p>
          </div>
          <div className="rounded-2xl border border-[var(--cobalt)]/30 bg-[var(--cobalt)]/[0.06] p-5 sm:p-6">
            <p className="flex items-center gap-2 text-xs font-semibold uppercase tracking-wider text-[#a8b6ff]"><Sparkles className="h-4 w-4" /> {canViewRemedies ? "Your paid scan tools" : "Go beyond the free report"}</p>
            <h2 className="mt-3 text-xl font-semibold">{canViewRemedies ? "Put your plan to work." : "Unlock maximum scan"}</h2>
            <p className="mt-3 text-sm leading-6 text-[#aeb8c5]">Get available fix steps and coding-agent prompts across the report, private repository scans, AI review of high-risk server code and monthly credits to rescan after changes.</p>
            <Link href={canViewRemedies ? "/repo-scan?tab=private" : "/pricing#paid-plans"} className="button-primary mt-5 w-full sm:w-auto">{canViewRemedies ? "Start a private repo scan" : "Unlock maximum scan"} <ArrowUpRight className="h-4 w-4" /></Link>
            <p className="mt-3 text-xs text-[#98a2b3]">{canViewRemedies ? "AI review has token limits. Verify findings before changing code." : "Choose Starter or Pro, then continue to checkout. AI review has token limits."}</p>
          </div>
        </section>

        <section className="mt-6 rounded-2xl border border-amber-400/20 bg-amber-400/[0.04] p-5 sm:p-6" aria-label="Scan coverage"><h2 className="text-lg font-semibold text-amber-200">{findings.length} finding{findings.length === 1 ? "" : "s"} on the public surface</h2><p className="mt-2 text-sm leading-6 text-[#a5aeba]">{priorityCount > 0 ? `${priorityCount} critical or high finding${priorityCount === 1 ? "" : "s"} to verify first. ` : "Review the evidence before changing code. "}The public surface score is not an overall app security score. Ownership checks, roles and database permissions need code review and authenticated testing.</p>{scan.diagnostic?.partial && <p className="mt-3 text-sm leading-6 text-amber-200"><strong>Partial scan.</strong> {scan.diagnostic.coverageNote}</p>}</section>

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


      </div>

      <ScanningOverlay reportId={scan.id} url={scan.url} isOpen={rescanning} onClose={() => setRescanning(false)} />
      {limit && <ScanLimitDialog limit={limit} signedIn={Boolean(session?.user)} returnTo={reportReturnHref(scan.id)} onClose={() => setLimit(null)} />}
      <ToastContainer />
    </main>
  );
}
