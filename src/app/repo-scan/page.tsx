"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import {
  AlertCircle,
  ArrowRight,
  Bot,
  Boxes,
  CheckCircle2,
  Code2,
  Github,
  GitPullRequestArrow,
  KeyRound,
  Loader2,
  Lock,
  LockKeyhole,
  Search,
} from "lucide-react";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";
import { RepoReport, type RepoReportResult } from "@/components/RepoReport";
import { PrivateRepoPanel } from "@/components/PrivateRepoPanel";
import { repoFaqs, repoScanSteps } from "@/lib/site-content";

const checks = [
  { icon: KeyRound, title: "Secrets and credentials", copy: "Committed .env files, private keys, provider tokens, database URLs, and secret-like literals." },
  { icon: GitPullRequestArrow, title: "GitHub Actions", copy: "Broad token permissions, mutable action tags, secret output, and dangerous pull_request_target flows." },
  { icon: Code2, title: "Client exposure", copy: "Public environment secrets, raw HTML sinks, dynamic code execution, wildcard CORS, and source maps." },
  { icon: LockKeyhole, title: "Database boundaries", copy: "Supabase service-role exposure and SQL migrations that create tables without visible RLS enablement." },
  { icon: Boxes, title: "Known vulnerable dependencies", copy: "Exact versions from npm, Python, Go, and Rust lock data checked against the OSV advisory database." },
  { icon: Bot, title: "Codex, Claude, Cursor, and MCP", copy: "Agent permissions, remote MCP transport, unpinned tool packages, destructive commands, and secret-transfer paths." },
];

export default function RepositoryScannerPage() {
  const [repository, setRepository] = useState("");
  const [authorized, setAuthorized] = useState(false);
  const [loading, setLoading] = useState(false);
  const [error, setError] = useState("");
  const [result, setResult] = useState<RepoReportResult | null>(null);
  const [tab, setTab] = useState<"public" | "private">("public");
  const [connectResult, setConnectResult] = useState<string | null>(null);
  const { status: sessionStatus } = useSession();
  const router = useRouter();

  useEffect(() => {
    const params = new URLSearchParams(window.location.search);
    if (params.get("tab") === "private" || params.get("github")) setTab("private");
    setConnectResult(params.get("github"));
  }, []);


  async function startScan(event: React.FormEvent) {
    event.preventDefault();
    if (!repository.trim() || !authorized) return;
    setLoading(true);
    setError("");
    setResult(null);
    try {
      // Signed-in users get a saved report that keeps running in the background.
      if (sessionStatus === "authenticated") {
        const response = await fetch("/api/repo-scans", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository: repository.trim(), authorized }) });
        const data = await response.json();
        if (!response.ok) throw new Error(data.error || "The repository scan failed.");
        router.push(`/repo-scan/${data.id}`);
        return;
      }
      const response = await fetch("/api/repo-scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ repository: repository.trim(), authorized }) });
      const data = await response.json();
      if (!response.ok) throw new Error(data.error || "The repository scan failed.");
      setResult(data);
      requestAnimationFrame(() => document.getElementById("repo-results")?.scrollIntoView({ behavior: "smooth", block: "start" }));
    } catch (scanError) { setError(scanError instanceof Error ? scanError.message : "The repository scan failed."); }
    finally { setLoading(false); }
  }

  return <main className="min-h-screen">
    <SiteHeader />
    <section className="relative overflow-hidden border-b border-white/[0.07] py-14 sm:py-20">
      <div className="pointer-events-none absolute inset-0 -z-10 hairline-grid [mask-image:linear-gradient(to_bottom,black,transparent)]" />
      <div className="app-shell grid gap-12 lg:grid-cols-[0.85fr_1.15fr] lg:items-center lg:gap-16">
        <div>
          <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5 text-xs text-[#b4bdc9]"><Github className="h-3.5 w-3.5 text-[var(--signal)]" /> Read-only public and private repository scan</div>
          <h1 className="display-title mt-7 text-balance">GitHub repo scanner <span className="text-[var(--signal)]">for vibe-coded apps.</span></h1>
          <p className="mt-6 max-w-xl text-lg leading-8 text-[#9aa4b1]">Check a public or private repository for the mistakes AI coding agents cannot see after deployment: committed secrets, unsafe workflows, exposed client keys, missing database boundaries, and risky code patterns.</p>
          <div className="mt-6 flex flex-wrap gap-x-5 gap-y-2 text-xs text-[#778191]"><span className="inline-flex items-center gap-1.5"><CheckCircle2 className="h-3.5 w-3.5 text-[var(--signal)]" /> We never execute repository code</span><span className="inline-flex items-center gap-1.5"><CheckCircle2 className="h-3.5 w-3.5 text-[var(--signal)]" /> Secret values stay out of the report</span></div>
        </div>

        <div className="surface rounded-[1.5rem] p-5 sm:p-7">
          <div className="grid grid-cols-2 gap-1 rounded-xl border border-white/[0.07] bg-[#0b1016] p-1" role="tablist" aria-label="Repository type">
            <button type="button" role="tab" aria-selected={tab === "public"} onClick={() => setTab("public")} className={`flex items-center justify-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium transition ${tab === "public" ? "bg-white/[0.08] text-white" : "text-[#7f8998] hover:text-white"}`}><Github className="h-4 w-4" /> Public repo</button>
            <button type="button" role="tab" aria-selected={tab === "private"} onClick={() => setTab("private")} className={`flex items-center justify-center gap-2 rounded-lg px-3 py-2.5 text-sm font-medium transition ${tab === "private" ? "bg-white/[0.08] text-white" : "text-[#7f8998] hover:text-white"}`}><Lock className="h-4 w-4" /> Private repo <span className="rounded bg-[var(--signal)]/15 px-1.5 py-0.5 text-[0.58rem] font-bold uppercase tracking-[.08em] text-[var(--signal)]">New</span></button>
          </div>
          {tab === "private" ? <>
            <div className="mt-6 flex items-center justify-between"><div><p className="text-sm font-semibold">Scan a private repository</p><p className="mt-1 text-xs text-[#778191]">Connect the read-only ScanMySaaS GitHub App and pick a repository.</p></div><LockKeyhole className="h-5 w-5 text-[var(--signal)]" /></div>
            <PrivateRepoPanel connectResult={connectResult} />
          </> : <form onSubmit={startScan}>
          <div className="mt-6 flex items-center justify-between"><div><p className="text-sm font-semibold">Scan a public GitHub repository</p><p className="mt-1 text-xs text-[#778191]">{sessionStatus === "authenticated" ? "Runs in the background and is saved to your dashboard." : "Free, no account needed. Sign in to save reports."}</p></div><Github className="h-5 w-5 text-[var(--signal)]" /></div>
          <label className="input-shell mt-6 flex items-center gap-3 rounded-xl px-3.5"><Github className="h-4 w-4 shrink-0 text-[#697483]" /><input value={repository} onChange={(event) => setRepository(event.target.value)} placeholder="https://github.com/owner/repository or …/tree/branch" className="min-w-0 flex-1 bg-transparent py-4 text-sm text-white placeholder:text-[#596473] focus:outline-none" inputMode="url" autoCapitalize="none" autoCorrect="off" /></label>
          <label className="mt-4 flex cursor-pointer items-start gap-3 text-xs leading-5 text-[#8c96a4]"><input type="checkbox" checked={authorized} onChange={(event) => setAuthorized(event.target.checked)} className="mt-1 h-4 w-4 accent-[#b9ff66]" /><span>I own this repository or have permission to scan it.</span></label>
          {error && <div className="mt-4 flex gap-2 rounded-xl border border-[#ff6b6b]/20 bg-[#ff6b6b]/[0.06] p-3 text-xs leading-5 text-[#ff9d9d]"><AlertCircle className="mt-0.5 h-4 w-4 shrink-0" />{error}</div>}
          <button type="submit" disabled={loading || !repository.trim() || !authorized} className="button-primary mt-5 w-full">{loading ? <><Loader2 className="h-4 w-4 animate-spin" />Reading repository security files...</> : <><Search className="h-4 w-4" />Scan repository</>}</button>
          <p className="mt-3 text-center text-[0.67rem] leading-5 text-[#5f6977]">Reads up to 60 security-relevant files from one pinned commit, highest-risk first. It does not search full Git history.</p>
          </form>}
        </div>
      </div>
    </section>

    {!result && <>
      <section className="app-shell py-20 sm:py-28"><div className="max-w-2xl"><p className="eyebrow">What the repo scan checks</p><h2 className="section-title mt-4 text-balance">The mistakes hidden behind a working demo.</h2></div><div className="mt-12 grid gap-4 md:grid-cols-2">{checks.map((check) => <article key={check.title} className="surface-muted rounded-2xl p-6 sm:p-7"><check.icon className="h-5 w-5 text-[var(--signal)]" /><h3 className="mt-8 text-xl font-semibold tracking-[-0.025em]">{check.title}</h3><p className="mt-3 text-sm leading-6 text-[#87919f]">{check.copy}</p></article>)}</div></section>
      <section className="border-y border-white/[0.07] bg-[#0a0e14] py-20"><div className="app-shell grid gap-8 lg:grid-cols-[1fr_auto] lg:items-end"><div><p className="eyebrow">Two scans, two surfaces</p><h2 className="mt-4 max-w-3xl text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">Scan the repository before launch. Scan the public app after launch.</h2><p className="mt-5 max-w-2xl text-sm leading-7 text-[#8f99a7]">Repository checks catch secrets and configuration mistakes. The website scanner checks the deployed headers, TLS, cookies, files, routes, and browser-facing behavior.</p></div><Link href="/#scan" className="button-secondary shrink-0">Open website scanner <ArrowRight className="h-4 w-4" /></Link></div></section>
      <section className="app-shell py-20 sm:py-24">
        <div className="max-w-2xl"><p className="eyebrow">How to scan a GitHub repository</p><h2 className="section-title mt-4 text-balance">Scan a repo in three steps.</h2></div>
        <ol className="mt-10 grid gap-4 md:grid-cols-3">{repoScanSteps.map((step, index) => <li key={step.title} className="surface-muted rounded-2xl p-6"><span className="font-mono text-sm text-[var(--signal)]">0{index + 1}</span><h3 className="mt-3 text-lg font-semibold">{step.title}</h3><p className="mt-2 text-sm leading-7 text-[#8f99a7]">{step.copy}</p></li>)}</ol>
      </section>
      <section className="app-shell pb-20 sm:pb-28">
        <div className="max-w-2xl"><p className="eyebrow">Repo scanner FAQ</p><h2 className="section-title mt-4 text-balance">Questions about scanning your repository.</h2></div>
        <div className="mt-10 divide-y divide-white/[0.08] border-y border-white/[0.08]">{repoFaqs.map((faq) => <details key={faq.question} className="group py-5"><summary className="flex cursor-pointer list-none items-center justify-between gap-4 text-base font-medium text-white">{faq.question}<span className="text-[#6e7988] transition group-open:rotate-45">+</span></summary><p className="mt-3 max-w-3xl text-sm leading-7 text-[#9aa4b1]">{faq.answer}</p></details>)}</div>
        <p className="mt-8 text-sm text-[#8f99a7]">Shipping with AI tools? Read the <Link href="/vibe-coding-security" className="text-[var(--signal)] hover:underline">vibe coding security guide</Link>, or run the <Link href="/free-website-vulnerability-scanner" className="text-[var(--signal)] hover:underline">free website vulnerability scanner</Link> on your live app.</p>
      </section>
    </>}

    {result && <RepoReport result={result} onReset={() => { setResult(null); setRepository(""); setAuthorized(false); window.scrollTo({ top: 0, behavior: "smooth" }); }} />}

    <SiteFooter />
  </main>;
}
