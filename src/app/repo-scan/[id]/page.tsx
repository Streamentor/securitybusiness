"use client";

import { useCallback, useEffect, useRef, useState, useSyncExternalStore } from "react";
import Link from "next/link";
import { useParams, useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import { AlertCircle, ArrowLeft, Bell, BellRing, Check, GitBranch, Github, LayoutDashboard, Loader2, Lock, RotateCw } from "lucide-react";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";
import { RepoReport, type RepoReportResult } from "@/components/RepoReport";

interface Job {
  id: string;
  repository: string;
  requestedRef: string | null;
  commitSha: string | null;
  visibility: "public" | "private";
  status: "queued" | "running" | "completed" | "failed";
  stage: string | null;
  error: string | null;
  result: RepoReportResult | null;
  createdAt: string;
  completedAt: string | null;
}

const STAGES = [
  { key: "resolving", label: "Resolving the branch to an exact commit", hint: "Every file is read from this one commit." },
  { key: "reading-tree", label: "Mapping the repository tree", hint: "Finding security-relevant files." },
  { key: "reading-files", label: "Reading the highest-risk files first", hint: "Auth, API routes, payments, configs and workflows." },
  { key: "analyzing", label: "Checking secrets, workflows and code patterns", hint: "Secret values never enter the report." },
  { key: "dependencies", label: "Matching exact dependency versions against OSV", hint: "Known vulnerabilities in your lockfiles." },
  { key: "ai-review", label: "Reviewing application logic with AI", hint: "Selected files only. Findings still need verification." },
  { key: "scoring", label: "Scoring and prioritising findings", hint: "Building fix prompts for your coding agent." },
];

function stageIndex(job: Job | null) {
  if (!job) return -1;
  if (job.status === "completed") return STAGES.length;
  const index = STAGES.findIndex((stage) => stage.key === job.stage);
  return index === -1 ? 0 : index;
}

export default function RepoScanJobPage() {
  const params = useParams<{ id: string }>();
  const router = useRouter();
  const { status: sessionStatus } = useSession();
  const [job, setJob] = useState<Job | null>(null);
  const [error, setError] = useState("");
  const [elapsed, setElapsed] = useState(0);
  const [notify, setNotify] = useState(false);
  const [retrying, setRetrying] = useState(false);
  const canNotify = useSyncExternalStore(() => () => undefined, () => typeof Notification !== "undefined", () => false);
  const finishedRef = useRef(false);

  const load = useCallback(async () => {
    const response = await fetch(`/api/repo-scans/${params.id}`, { cache: "no-store" });
    if (response.status === 401) { setError("signin"); return null; }
    if (!response.ok) { setError("This scan could not be found."); return null; }
    const data: Job = await response.json();
    setJob(data);
    return data;
  }, [params.id]);

  useEffect(() => {
    if (sessionStatus !== "authenticated") return;
    let timer: ReturnType<typeof setTimeout>;
    let cancelled = false;
    const tick = async () => {
      const data = await load().catch(() => null);
      if (cancelled) return;
      if (data && (data.status === "queued" || data.status === "running")) timer = setTimeout(tick, 2000);
    };
    tick();
    return () => { cancelled = true; clearTimeout(timer); };
  }, [load, sessionStatus]);

  // Elapsed timer while the scan runs.
  useEffect(() => {
    if (!job || job.status === "completed" || job.status === "failed") return;
    const started = new Date(job.createdAt).getTime();
    const interval = setInterval(() => setElapsed(Math.max(0, Math.floor((Date.now() - started) / 1000))), 1000);
    return () => clearInterval(interval);
  }, [job]);

  // Finish signals: tab title and an optional browser notification.
  useEffect(() => {
    if (!job || finishedRef.current) return;
    if (job.status === "completed" || job.status === "failed") {
      finishedRef.current = true;
      const name = job.repository.split("/")[1];
      document.title = job.status === "completed" ? `✓ ${name} report ready | ScanMySaaS` : `Scan failed | ScanMySaaS`;
      if (notify && typeof Notification !== "undefined" && Notification.permission === "granted" && document.visibilityState !== "visible") {
        new Notification(job.status === "completed" ? "Repository report ready" : "Repository scan failed", { body: job.status === "completed" ? `${job.repository}: ${job.result?.findings.length ?? 0} findings, score ${job.result?.score ?? "—"}` : job.error || "Open ScanMySaaS for details." });
      }
    }
  }, [job, notify]);

  async function enableNotifications() {
    if (typeof Notification === "undefined") return;
    const permission = Notification.permission === "default" ? await Notification.requestPermission() : Notification.permission;
    setNotify(permission === "granted");
  }

  async function retry() {
    if (!job) return;
    setRetrying(true);
    const repository = job.requestedRef ? `${job.repository}@${job.requestedRef}` : job.repository;
    const response = await fetch("/api/repo-scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository, authorized: true }) }).catch(() => null);
    const data = response ? await response.json().catch(() => ({})) : {};
    if (response?.ok && data.id) router.push(`/repo-scan/${data.id}`);
    else { setRetrying(false); setError(data.error || "The scan could not be restarted."); }
  }

  const running = job && (job.status === "queued" || job.status === "running");
  const current = stageIndex(job);
  const progress = job?.status === "completed" ? 100 : Math.min(95, Math.round(((current + 0.5) / STAGES.length) * 100));
  const minutes = Math.floor(elapsed / 60);

  return <main className="min-h-screen">
    <SiteHeader />

    {error === "signin" || sessionStatus === "unauthenticated" ? <Centered><Lock className="mx-auto h-9 w-9 text-[var(--signal)]" /><h1 className="mt-5 text-xl font-semibold">Sign in to view this report</h1><p className="mt-2 text-sm text-[#8f99a7]">Repository reports are private to the account that ran them.</p><Link href={`/login?callbackUrl=${encodeURIComponent(`/repo-scan/${params.id}`)}`} className="button-primary mt-6">Sign in</Link></Centered>
    : error && !job ? <Centered><AlertCircle className="mx-auto h-9 w-9 text-[#ff8585]" /><h1 className="mt-5 text-xl font-semibold">{error}</h1><Link href="/repo-scan" className="button-secondary mt-6"><ArrowLeft className="h-4 w-4" /> Back to repository scanner</Link></Centered>
    : !job ? <Centered><Loader2 className="mx-auto h-7 w-7 animate-spin text-[var(--signal)]" /></Centered>
    : running ? <section className="app-shell py-12 sm:py-20">
      <div className="mx-auto max-w-2xl">
        <div className="surface relative overflow-hidden rounded-[1.5rem] p-6 sm:p-9">
          <div className="pointer-events-none absolute -right-24 -top-24 h-64 w-64 rounded-full bg-[var(--signal)]/[0.07] blur-3xl" />
          <div className="flex items-start gap-4">
            <div className="relative flex h-14 w-14 shrink-0 items-center justify-center">
              <svg viewBox="0 0 56 56" className="absolute inset-0 h-14 w-14 -rotate-90"><circle cx="28" cy="28" r="24" fill="none" stroke="rgba(255,255,255,.08)" strokeWidth="4" /><circle cx="28" cy="28" r="24" fill="none" stroke="var(--signal)" strokeWidth="4" strokeLinecap="round" strokeDasharray={`${(progress / 100) * 150.8} 150.8`} className="transition-all duration-700" /></svg>
              <span className="text-xs font-semibold text-white">{progress}%</span>
            </div>
            <div className="min-w-0">
              <p className="text-[0.67rem] font-bold uppercase tracking-[.14em] text-[var(--signal)]">{job.status === "queued" ? "Starting" : "Scanning"} · {minutes ? `${minutes}m ` : ""}{elapsed % 60}s</p>
              <h1 className="mt-1.5 flex flex-wrap items-center gap-2 text-xl font-semibold tracking-[-0.03em] sm:text-2xl"><span className="break-all">{job.repository}</span>{job.visibility === "private" && <span className="inline-flex items-center gap-1 rounded-md bg-[#ffd43b]/10 px-1.5 py-0.5 text-[0.62rem] font-bold uppercase tracking-[.08em] text-[#ffd66b]"><Lock className="h-3 w-3" /> Private</span>}</h1>
              {job.requestedRef && <p className="mt-1 flex items-center gap-1.5 text-xs text-[#7f8998]"><GitBranch className="h-3.5 w-3.5" />{job.requestedRef}</p>}
            </div>
          </div>

          <ol className="mt-8 space-y-1">{STAGES.map((stage, index) => {
            const done = index < current;
            const active = index === current;
            return <li key={stage.key} className={`flex gap-3 rounded-xl px-3 py-2.5 transition ${active ? "bg-white/[0.04]" : ""}`}>
              <span className={`mt-0.5 flex h-5 w-5 shrink-0 items-center justify-center rounded-full ${done ? "bg-[var(--signal)] text-[#071006]" : active ? "border border-[var(--signal)]/60" : "border border-white/15"}`}>{done ? <Check className="h-3 w-3" strokeWidth={3} /> : active ? <span className="h-2 w-2 animate-pulse rounded-full bg-[var(--signal)]" /> : null}</span>
              <span className="min-w-0"><span className={`block text-sm ${done ? "text-[#8f99a7]" : active ? "font-medium text-white" : "text-[#5f6977]"}`}>{stage.label}</span>{active && <span className="mt-0.5 block text-xs text-[#7f8998]">{stage.hint}</span>}</span>
            </li>;
          })}</ol>

          <div className="mt-8 rounded-xl border border-white/[0.07] bg-[#0b1016] p-4">
            <p className="text-sm font-medium text-white">You can leave this page.</p>
            <p className="mt-1 text-xs leading-5 text-[#8c96a4]">The scan keeps running on our servers and the report is saved to your dashboard. Most repositories finish in under a minute.</p>
            <div className="mt-4 flex flex-wrap gap-2">
              <Link href="/dashboard#repo-scans" className="button-secondary"><LayoutDashboard className="h-4 w-4" /> Go to dashboard</Link>
              {canNotify && <button type="button" onClick={enableNotifications} disabled={notify} className="button-secondary">{notify ? <><BellRing className="h-4 w-4 text-[var(--signal)]" /> We&apos;ll notify this tab</> : <><Bell className="h-4 w-4" /> Notify me when done</>}</button>}
            </div>
          </div>
        </div>
      </div>
    </section>
    : job.status === "failed" ? <Centered>
      <AlertCircle className="mx-auto h-9 w-9 text-[#ff8585]" />
      <h1 className="mt-5 text-xl font-semibold">The scan of {job.repository} did not finish</h1>
      <p className="mx-auto mt-2 max-w-md text-sm leading-6 text-[#8f99a7]">{job.error || "Something went wrong while reading the repository."}</p>
      {error && <p className="mt-3 text-xs text-[#ff9d9d]">{error}</p>}
      <div className="mt-6 flex flex-wrap justify-center gap-2"><button type="button" onClick={retry} disabled={retrying} className="button-primary">{retrying ? <Loader2 className="h-4 w-4 animate-spin" /> : <RotateCw className="h-4 w-4" />} Try again</button><Link href="/repo-scan" className="button-secondary">Choose another repository</Link></div>
    </Centered>
    : job.result ? <>
      <div className="app-shell pt-8"><div className="flex flex-wrap items-center justify-between gap-3 rounded-xl border border-white/[0.07] bg-white/[0.02] px-4 py-3 text-xs text-[#8c96a4]"><span className="flex items-center gap-2">{job.visibility === "private" ? <Lock className="h-3.5 w-3.5 text-[#ffd66b]" /> : <Github className="h-3.5 w-3.5" />}Saved to your dashboard · visible only to you · {new Date(job.completedAt || job.createdAt).toLocaleString()}</span><span className="flex gap-3"><button type="button" onClick={retry} disabled={retrying} className="inline-flex items-center gap-1.5 hover:text-white"><RotateCw className="h-3.5 w-3.5" /> Rescan after fixing</button><Link href="/dashboard#repo-scans" className="hover:text-white">All repository scans</Link></span></div></div>
      <RepoReport result={job.result} />
    </> : null}

    <SiteFooter />
  </main>;
}

function Centered({ children }: { children: React.ReactNode }) {
  return <section className="app-shell flex min-h-[60vh] items-center justify-center py-16"><div className="max-w-lg text-center">{children}</div></section>;
}
