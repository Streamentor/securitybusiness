"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { AlertCircle, CheckCircle2, Clock3, ExternalLink, GitBranch, Github, Loader2, Lock, Plus } from "lucide-react";

interface RepoScanRow {
  id: string;
  repository: string;
  requestedRef: string | null;
  commitSha: string | null;
  visibility: "public" | "private";
  status: "queued" | "running" | "completed" | "failed";
  score: number | null;
  findingsCount: number | null;
  createdAt: string;
}

function tone(score: number | null) {
  if (score === null) return "text-[#768190]";
  if (score >= 85) return "text-[var(--signal)]";
  if (score >= 65) return "text-[#ffcf78]";
  return "text-[#ff8585]";
}

export function RepoScansSection() {
  const [rows, setRows] = useState<RepoScanRow[] | null>(null);

  useEffect(() => {
    let timer: ReturnType<typeof setTimeout>;
    let cancelled = false;
    const load = async () => {
      const data: RepoScanRow[] = await fetch("/api/repo-scans", { cache: "no-store" }).then((response) => response.ok ? response.json() : []).catch(() => []);
      if (cancelled) return;
      setRows(data);
      // Keep the list live while a background scan is still running.
      if (data.some((row) => row.status === "queued" || row.status === "running")) timer = setTimeout(load, 3000);
    };
    load();
    return () => { cancelled = true; clearTimeout(timer); };
  }, []);

  return <section id="repo-scans" className="mt-10 scroll-mt-6">
    <div className="mb-4 flex items-end justify-between gap-3"><div><h2 className="text-xl font-semibold tracking-[-0.025em]">Repository scans</h2><p className="mt-1 text-xs text-[#717c8b]">Public and private repositories, saved only to your account</p></div><Link href="/repo-scan" className="button-secondary"><Plus className="h-4 w-4" /> Scan a repository</Link></div>
    {rows === null ? <div className="surface-muted flex h-28 items-center justify-center rounded-2xl"><Loader2 className="h-5 w-5 animate-spin text-[var(--signal)]" /></div>
      : rows.length === 0 ? <div className="surface-muted rounded-2xl px-6 py-12 text-center"><div className="mx-auto flex h-11 w-11 items-center justify-center rounded-2xl bg-white/[0.04]"><Github className="h-5 w-5 text-[#667180]" /></div><h3 className="mt-4 font-semibold">Scan the code behind your app.</h3><p className="mx-auto mt-2 max-w-sm text-sm leading-6 text-[#778191]">Connect GitHub with read-only access, pick a repository, and find committed secrets, risky workflows and missing auth checks.</p><Link href="/repo-scan?tab=private" className="button-primary mt-5">Connect a repository</Link></div>
      : <div className="overflow-hidden rounded-2xl border border-white/[0.08]"><div className="divide-y divide-white/[0.07]">{rows.map((row) => {
        const running = row.status === "queued" || row.status === "running";
        return <Link key={row.id} href={`/repo-scan/${row.id}`} className="grid gap-3 bg-[#0a0e14] px-5 py-4 transition hover:bg-white/[0.035] sm:grid-cols-[1.4fr_.5fr_.5fr_.6fr_1.5rem] sm:items-center">
          <div className="min-w-0"><div className="flex items-center gap-2"><span className={`flex h-8 w-8 shrink-0 items-center justify-center rounded-lg ${row.status === "completed" ? "bg-[var(--signal)]/[0.07] text-[var(--signal)]" : row.status === "failed" ? "bg-[#ff6b6b]/10 text-[#ff8585]" : "bg-white/[0.05] text-[#7f8998]"}`}>{row.status === "completed" ? <CheckCircle2 className="h-4 w-4" /> : row.status === "failed" ? <AlertCircle className="h-4 w-4" /> : <Loader2 className="h-4 w-4 animate-spin" />}</span><div className="min-w-0"><p className="flex items-center gap-1.5 truncate text-sm font-medium text-white">{row.visibility === "private" && <Lock className="h-3.5 w-3.5 shrink-0 text-[#ffd66b]" />}<span className="truncate">{row.repository}</span></p><p className="mt-0.5 flex items-center gap-1.5 text-[0.68rem] text-[#6e7988]"><GitBranch className="h-3 w-3" />{row.requestedRef || "default branch"}{row.commitSha && /^[0-9a-f]{40}$/.test(row.commitSha) ? ` @ ${row.commitSha.slice(0, 7)}` : ""}</p></div></div></div>
          <div className={`text-xl font-semibold ${tone(row.score)}`}>{running ? <span className="text-xs font-medium text-[#8f99a7]">Scanning…</span> : row.status === "failed" ? <span className="text-xs font-medium text-[#ff8585]">Failed</span> : row.score ?? "—"}</div>
          <div className="text-sm text-[#a5aeba]">{row.findingsCount ?? (running ? "" : "—")}{row.findingsCount !== null && <span className="ml-1 text-xs text-[#6e7988]">findings</span>}</div>
          <div className="flex items-center gap-1.5 text-xs text-[#717c8b]"><Clock3 className="h-3.5 w-3.5" />{new Date(row.createdAt).toLocaleDateString()}</div>
          <ExternalLink className="hidden h-4 w-4 text-[#596473] sm:block" />
        </Link>;
      })}</div></div>}
  </section>;
}
