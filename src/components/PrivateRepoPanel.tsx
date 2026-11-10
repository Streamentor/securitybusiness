"use client";

import { useEffect, useMemo, useState } from "react";
import Link from "next/link";
import { AIReviewPreference } from "@/components/AIReviewPreference";
import { useRouter } from "next/navigation";
import { AlertCircle, ArrowRight, CheckCircle2, Eye, GitBranch, Github, Loader2, Lock, LogIn, Search, ShieldCheck, Sparkles, Unplug } from "lucide-react";

interface Status { configured: boolean; signedIn: boolean; connected: boolean; installations: Array<{ accountLogin: string; accountType: string }>; plan?: string; canScanPrivate: boolean }
interface Repo { fullName: string; private: boolean; defaultBranch: string; pushedAt: string | null; account: string }

function relative(date: string | null) {
  if (!date) return "";
  const days = Math.floor((Date.now() - new Date(date).getTime()) / 86_400_000);
  if (days <= 0) return "today";
  if (days === 1) return "yesterday";
  if (days < 30) return `${days} days ago`;
  const months = Math.floor(days / 30);
  return months < 12 ? `${months} mo ago` : `${Math.floor(months / 12)} yr ago`;
}

const CONNECT_MESSAGES: Record<string, { tone: "ok" | "warn"; text: string }> = {
  connected: { tone: "ok", text: "GitHub connected. Choose a repository to scan." },
  cancelled: { tone: "warn", text: "GitHub connection was cancelled." },
  expired: { tone: "warn", text: "That connection link expired or came from another session. Please connect again." },
  "no-installation": { tone: "warn", text: "GitHub did not report an installation for your account. Install the app on the account that owns the repositories." },
  requested: { tone: "warn", text: "An organization owner must approve the ScanMySaaS app before you can scan its repositories." },
  error: { tone: "warn", text: "GitHub connection failed. Please try again." },
};

export function PrivateRepoPanel({ connectResult }: { connectResult?: string | null }) {
  const router = useRouter();
  const [status, setStatus] = useState<Status | null>(null);
  const [repos, setRepos] = useState<Repo[] | null>(null);
  const [query, setQuery] = useState("");
  const [selected, setSelected] = useState<Repo | null>(null);
  const [branch, setBranch] = useState("");
  const [authorized, setAuthorized] = useState(true);
  const [starting, setStarting] = useState(false);
  const [error, setError] = useState("");
  const [disconnecting, setDisconnecting] = useState(false);

  useEffect(() => {
    fetch("/api/github/status").then((response) => response.json()).then(setStatus).catch(() => setStatus({ configured: false, signedIn: false, connected: false, installations: [], canScanPrivate: false }));
  }, []);

  useEffect(() => {
    if (!status?.connected) return;
    fetch("/api/github/repos").then(async (response) => {
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "Repositories could not be loaded.");
      setRepos(data.repositories);
      if (data.revoked?.length && !data.repositories.length) setStatus((current) => current ? { ...current, connected: false, installations: [] } : current);
    }).catch((loadError) => { setRepos([]); setError(loadError instanceof Error ? loadError.message : "Repositories could not be loaded."); });
  }, [status?.connected]);

  const filtered = useMemo(() => {
    const term = query.trim().toLowerCase();
    return (repos || []).filter((repo) => !term || repo.fullName.toLowerCase().includes(term)).slice(0, 50);
  }, [repos, query]);

  async function startScan() {
    if (!selected) return;
    setStarting(true);
    setError("");
    try {
      const repository = branch.trim() ? `${selected.fullName}@${branch.trim()}` : selected.fullName;
      const response = await fetch("/api/repo-scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository, authorized }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The scan could not be started.");
      router.push(`/repo-scan/${data.id}`);
    } catch (startError) {
      setError(startError instanceof Error ? startError.message : "The scan could not be started.");
      setStarting(false);
    }
  }

  async function disconnect() {
    setDisconnecting(true);
    await fetch("/api/github/connect", { method: "DELETE" }).catch(() => undefined);
    setStatus((current) => current ? { ...current, connected: false, installations: [] } : current);
    setRepos(null);
    setSelected(null);
    setDisconnecting(false);
  }

  const notice = connectResult ? CONNECT_MESSAGES[connectResult] : undefined;

  if (!status) return <div className="flex h-64 items-center justify-center"><Loader2 className="h-5 w-5 animate-spin text-[var(--signal)]" /></div>;

  if (!status.configured) return <div className="mt-6 rounded-xl border border-white/[0.08] bg-white/[0.025] p-5 text-sm leading-6 text-[#9aa4b1]"><p className="flex items-center gap-2 font-semibold text-white"><Lock className="h-4 w-4 text-[var(--signal)]" /> Private repositories are almost here</p><p className="mt-2">A read-only GitHub App connection is being enabled. Public repositories can be scanned right now.</p></div>;

  const promises = [
    { icon: Eye, text: "Read-only: repository contents and metadata, nothing else" },
    { icon: ShieldCheck, text: "You pick the repositories; revoke any time on GitHub" },
    { icon: Lock, text: "Code is read in memory and discarded; only the report is saved, visible only to you" },
  ];

  if (!status.signedIn) return <div className="mt-6">
    <ul className="space-y-3">{promises.map((item) => <li key={item.text} className="flex gap-3 text-sm leading-6 text-[#a5aeba]"><item.icon className="mt-1 h-4 w-4 shrink-0 text-[var(--signal)]" />{item.text}</li>)}</ul>
    <Link href={`/login?redirect=${encodeURIComponent("/repo-scan?tab=private")}`} className="button-primary mt-6 w-full"><LogIn className="h-4 w-4" /> Sign in to connect GitHub</Link>
  </div>;

  if (!status.connected) return <div className="mt-6">
    {notice && <Notice {...notice} />}
    <ul className="space-y-3">{promises.map((item) => <li key={item.text} className="flex gap-3 text-sm leading-6 text-[#a5aeba]"><item.icon className="mt-1 h-4 w-4 shrink-0 text-[var(--signal)]" />{item.text}</li>)}</ul>
    {!status.canScanPrivate && <div className="mt-5 rounded-xl border border-[var(--cobalt)]/25 bg-[var(--cobalt)]/[0.06] p-4"><h3 className="font-semibold text-white">Unlock private repo scanning and AI review</h3><p className="mt-2 text-sm leading-6 text-[#98a2b3]">Starter and Pro review selected high-risk server code for potential ownership and role-check flaws. Findings need verification.</p><Link href="/pricing#plans" className="button-primary mt-4 w-full">Upgrade for a deeper review</Link></div>}
    <a href="/api/github/connect" className="button-secondary mt-6 w-full"><Github className="h-4 w-4" /> Connect GitHub</a>
    <p className="mt-3 text-center text-[0.7rem] text-[#5f6977]">Already installed the app? <a href="/api/github/connect?mode=authorize" className="text-[#9aa4b1] underline-offset-2 hover:text-white hover:underline">Authorize this account instead</a></p>
    {!status.canScanPrivate && <p className="mt-4 flex items-start gap-2 rounded-lg bg-white/[0.03] p-3 text-xs leading-5 text-[#8c96a4]"><Sparkles className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--amber)]" />Connecting is free. Scanning private repositories is included in Starter and Pro; connected public repositories stay free.</p>}
  </div>;

  const needsUpgrade = selected?.private && !status.canScanPrivate;
  return <div className="mt-5">
    <AIReviewPreference />
    {notice && <Notice {...notice} />}
    <label className="input-shell flex items-center gap-3 rounded-xl px-3.5"><Search className="h-4 w-4 shrink-0 text-[#697483]" /><input value={query} onChange={(event) => setQuery(event.target.value)} placeholder="Search your repositories" className="min-w-0 flex-1 bg-transparent py-3 text-sm text-white placeholder:text-[#596473] focus:outline-none" /></label>
    <div className="mt-3 max-h-64 overflow-y-auto rounded-xl border border-white/[0.07] bg-[#0b1016]" role="listbox" aria-label="Repositories">
      {repos === null ? <div className="flex h-32 items-center justify-center gap-2 text-xs text-[#7f8998]"><Loader2 className="h-4 w-4 animate-spin text-[var(--signal)]" /> Loading repositories…</div>
        : filtered.length === 0 ? <div className="px-4 py-8 text-center text-xs leading-5 text-[#7f8998]">{repos.length ? "No repository matches your search." : <>No repositories are shared with the app yet. <a href="/api/github/connect" className="text-[var(--signal)] hover:underline">Choose repositories on GitHub</a>.</>}</div>
        : filtered.map((repo) => {
          const active = selected?.fullName === repo.fullName;
          return <button key={repo.fullName} type="button" role="option" aria-selected={active} onClick={() => { setSelected(repo); setBranch(""); setError(""); }} className={`flex w-full items-center gap-3 border-b border-white/[0.05] px-3.5 py-3 text-left transition last:border-b-0 ${active ? "bg-[var(--signal)]/[0.08]" : "hover:bg-white/[0.03]"}`}>
            <span className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-lg ${repo.private ? "bg-[#ffd43b]/10 text-[#ffd66b]" : "bg-white/[0.05] text-[#8f99a7]"}`}>{repo.private ? <Lock className="h-3.5 w-3.5" /> : <Github className="h-3.5 w-3.5" />}</span>
            <span className="min-w-0 flex-1"><span className="block truncate text-sm font-medium text-white">{repo.fullName}</span><span className="mt-0.5 flex items-center gap-2 text-[0.68rem] text-[#6e7988]"><GitBranch className="h-3 w-3" />{repo.defaultBranch}{repo.pushedAt && <span>· pushed {relative(repo.pushedAt)}</span>}</span></span>
            {active && <CheckCircle2 className="h-4 w-4 shrink-0 text-[var(--signal)]" />}
          </button>;
        })}
    </div>

    {selected && <div className="mt-4 space-y-3">
      <label className="input-shell flex items-center gap-3 rounded-xl px-3.5"><GitBranch className="h-4 w-4 shrink-0 text-[#697483]" /><input value={branch} onChange={(event) => setBranch(event.target.value)} placeholder={`Branch, tag or commit (default: ${selected.defaultBranch})`} className="min-w-0 flex-1 bg-transparent py-3 text-sm text-white placeholder:text-[#596473] focus:outline-none" /></label>
      <label className="flex cursor-pointer items-start gap-3 text-xs leading-5 text-[#8c96a4]"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} className="mt-1 h-4 w-4 accent-[#b9ff66]" /><span>I own this repository or have permission to scan it.</span></label>
    </div>}

    {error && <div className="mt-4 flex gap-2 rounded-xl border border-[#ff6b6b]/20 bg-[#ff6b6b]/[0.06] p-3 text-xs leading-5 text-[#ff9d9d]"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{error}</div>}

    {needsUpgrade ? <div className="mt-5 rounded-xl border border-[var(--signal)]/20 bg-[var(--signal)]/[0.05] p-4"><p className="flex items-center gap-2 text-sm font-semibold text-white"><Sparkles className="h-4 w-4 text-[var(--signal)]" /> Private repositories are a Starter and Pro feature</p><p className="mt-1.5 text-xs leading-5 text-[#9aa4b1]">Scan private code with read-only access, keep every report, and verify fixes before you ship. Public repositories stay free.</p><Link href="/pricing" className="button-primary mt-4 w-full">See plans <ArrowRight className="h-4 w-4" /></Link></div>
      : <button type="button" onClick={startScan} disabled={!selected || !authorized || starting} className="button-primary mt-5 w-full">{starting ? <><Loader2 className="h-4 w-4 animate-spin" /> Starting scan…</> : <><Search className="h-4 w-4" /> {selected ? `Scan ${selected.fullName.split("/")[1]}` : "Choose a repository"}</>}</button>}

    <div className="mt-4 flex flex-wrap items-center justify-between gap-2 text-[0.68rem] text-[#5f6977]">
      <span className="flex items-center gap-1.5"><span className="h-1.5 w-1.5 rounded-full bg-[var(--signal)]" /> Connected: {status.installations.map((installation) => `@${installation.accountLogin}`).join(", ")}</span>
      <span className="flex items-center gap-3"><a href="/api/github/connect" className="hover:text-white">Manage repositories</a><button type="button" onClick={disconnect} disabled={disconnecting} className="inline-flex items-center gap-1 hover:text-white"><Unplug className="h-3 w-3" /> Disconnect</button></span>
    </div>
  </div>;
}

function Notice({ tone, text }: { tone: "ok" | "warn"; text: string }) {
  return <div className={`mb-4 flex gap-2 rounded-xl border p-3 text-xs leading-5 ${tone === "ok" ? "border-[var(--signal)]/25 bg-[var(--signal)]/[0.06] text-[#d9ffb0]" : "border-[#ffd43b]/20 bg-[#ffd43b]/[0.05] text-[#ffe08a]"}`}>{tone === "ok" ? <CheckCircle2 className="mt-0.5 h-4 w-4 shrink-0" /> : <AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />}{text}</div>;
}
