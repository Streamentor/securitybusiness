"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { AlertCircle, AlertTriangle, ArrowRight, ArrowUpRight, ChevronDown, ChevronUp, Github, ShieldCheck, ShieldX } from "lucide-react";
import { CopyPromptButton } from "@/components/CopyPromptButton";
import { repoResponseOrder } from "@/lib/repo-response-order";
import type { RepoRoute } from "@/lib/repo-route-inventory";
import { buildFixPrompt, buildRepoAuditPrompt } from "@/lib/fix-prompt";

export type Severity = "critical" | "high" | "medium" | "low";

export interface RepoFinding {
  id: string;
  severity: Severity;
  category: string;
  title: string;
  description: string;
  file: string;
  line: number | null;
  remedy: string;
  referenceUrl?: string;
  source?: "ai" | "rule";
  confidence?: "high" | "medium" | "low";
  evidence?: string;
  why?: string;
}

export interface RepoReportResult {
  repository: { fullName: string; url: string; defaultBranch: string; ref?: string; visibility?: "public" | "private"; commitSha?: string; latestPush: string | null };
  score: number;
  risk: "low" | "moderate" | "high" | "critical";
  filesInRepository: number;
  filesScanned: number;
  bytesScanned: number;
  truncated: boolean;
  findings: RepoFinding[];
  coverage: {
    candidateFiles: number;
    filesSkipped: number;
    treeComplete?: boolean;
    skippedByReason?: NonNullable<import("@/lib/github-scanner").RepoScanResult["coverage"]["skippedByReason"]>;
    skippedHighRiskFiles?: string[];
    agentFilesScanned: number;
    dependencyManifests: number;
    dependenciesChecked: number;
    knownVulnerabilities: number;
    dependencyStatus: "checked" | "partial" | "unavailable" | "not-detected";
  };
  routes?: RepoRoute[];
  aiReview?: {hasNextBatch?: boolean; highRiskTotal?: number; highRiskReviewed?: number; highRiskNotReviewed?: string[]; status: string; note: string; findingsCount?: number; filesReviewed?: number};
  scannedAt: string;
}

const severityStyle: Record<Severity, { label: string; text: string; bg: string; border: string; icon: React.ElementType }> = {
  critical: { label: "Critical", text: "text-[#ff8585]", bg: "bg-[#ff6b6b]/10", border: "border-[#ff6b6b]/25", icon: ShieldX },
  high: { label: "High", text: "text-[#ffae76]", bg: "bg-[#ff9f43]/10", border: "border-[#ff9f43]/25", icon: AlertTriangle },
  medium: { label: "Medium", text: "text-[#ffd66b]", bg: "bg-[#ffd43b]/10", border: "border-[#ffd43b]/20", icon: AlertCircle },
  low: { label: "Low", text: "text-[#91a3ff]", bg: "bg-[#7b91ff]/10", border: "border-[#7b91ff]/20", icon: AlertCircle },
};

function formatBytes(bytes: number) {
  if (bytes < 1024) return `${bytes} B`;
  if (bytes < 1024 * 1024) return `${Math.round(bytes / 1024)} KB`;
  return `${(bytes / 1024 / 1024).toFixed(1)} MB`;
}

function FindingCard({ finding, repository, defaultBranch, defaultOpen }: { finding: RepoFinding; repository: string; defaultBranch: string; defaultOpen: boolean }) {
  const [open, setOpen] = useState(defaultOpen);
  const style = severityStyle[finding.severity];
  const Icon = style.icon;
  const fileUrl = `https://github.com/${repository}/blob/${encodeURIComponent(defaultBranch)}/${finding.file.split("/").map(encodeURIComponent).join("/")}${finding.line ? `#L${finding.line}` : ""}`;
  const fixPrompt = buildFixPrompt({ surface: "source repository", title: finding.title, severity: finding.severity, category: finding.category, target: `${finding.file}${finding.line ? `:${finding.line}` : ""}`, repository, evidence: `${finding.source === "ai" ? "AI hypothesis — Needs verification. " : ""}${finding.evidence || ""}\n${finding.description}`, remediation: finding.remedy });
  return <article className={`overflow-hidden rounded-xl border ${finding.source === "ai" ? "border-violet-400/40 border-dashed" : style.border} bg-[#0b1016]`}>
    <button onClick={() => setOpen((value) => !value)} className="grid w-full grid-cols-[auto_1fr_auto] items-start gap-3 p-4 text-left sm:p-5" aria-expanded={open}>
      <span className={`flex h-9 w-9 items-center justify-center rounded-lg ${style.bg} ${style.text}`}><Icon className="h-4 w-4" /></span>
      <span className="min-w-0"><span className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold text-white sm:text-base">{finding.title}</span><span className={`rounded px-1.5 py-0.5 text-[0.61rem] font-bold uppercase tracking-[.08em] ${style.bg} ${style.text}`}>{style.label}</span>{finding.source === "ai" && <span className="rounded bg-violet-400/10 px-2 py-1 text-xs text-violet-200">AI · Needs verification · {finding.confidence} confidence</span>}</span><span className="mt-1.5 block break-all font-mono text-xs leading-5 text-[#667180]">{finding.file}{finding.line ? `:${finding.line}` : ""}</span></span>
      {open ? <ChevronUp className="mt-2 h-4 w-4 text-[#687382]" /> : <ChevronDown className="mt-2 h-4 w-4 text-[#687382]" />}
    </button>
    {open && <div className="border-t border-white/[0.07] p-4 sm:p-5">
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="min-w-0"><p className="text-[0.67rem] font-bold uppercase tracking-[.12em] text-[#687382]">Why it was flagged</p><p className="mt-3 text-sm leading-7 text-[#a5aeba]">{finding.description}</p>{finding.source === "ai" && finding.evidence && <pre className="mt-3 overflow-x-auto whitespace-pre-wrap break-words rounded bg-white/5 p-3 text-xs text-[#a5aeba]">{finding.evidence}</pre>}<div className="mt-4 flex flex-wrap gap-x-4 gap-y-2"><a href={fileUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--signal)] hover:underline">Open file on GitHub <ArrowUpRight className="h-3.5 w-3.5" /></a>{finding.referenceUrl && <a href={finding.referenceUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#aeb8c5] hover:text-white hover:underline">Open advisory <ArrowUpRight className="h-3.5 w-3.5" /></a>}</div></div>
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.025] p-4 sm:p-5"><div className="flex flex-wrap items-center justify-between gap-3"><p className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-[var(--signal)]" />What to do next</p><CopyPromptButton prompt={fixPrompt} /></div><p className="mt-3 text-sm leading-7 text-[#a5aeba]">{finding.remedy}</p></div>
      </div>
    </div>}
  </article>;
}

export function RepoReport({ result, onReset, onNextBatch, nextBatchBusy }: { result: RepoReportResult; onReset?: () => void; onNextBatch?: () => void; nextBatchBusy?: boolean }) {
  const denominator = result.coverage.candidateFiles;
  const partialScore = result.coverage.treeComplete === false || denominator > 0 && result.filesScanned / denominator < 0.9;
  const routes = result.routes ?? [];
  const routeStatus = (status: RepoRoute["status"]) => routes.filter((route) => route.status === status).length;
  const skipped = result.coverage.skippedByReason;
  const skipLabels = skipped ? [
    [skipped.perFile, "per-file size limit"],
    [skipped.sourceBudget, "total source size limit"],
    [skipped.archiveUnread, "unread or unsupported archive entries"],
    [skipped.ruleTime, "rule time limit"],
  ].filter(([count]) => Number(count) > 0).map(([count, label]) => count + " " + label) : [];
  const responseOrder = repoResponseOrder(result.findings);
  const counts = useMemo(() => Object.fromEntries((["critical", "high", "medium", "low"] as Severity[]).map((severity) => [severity, result?.findings.filter((finding) => finding.severity === severity).length || 0])) as Record<Severity, number>, [result]);
  const fullAuditPrompt = useMemo(() => result ? buildRepoAuditPrompt({ repository: result.repository.fullName, score: result.score, coverageSummary: `${result.filesScanned} of ${result.coverage.candidateFiles} supported files read; ${result.coverage.filesSkipped} skipped. ${result.truncated ? "The scan is incomplete." : "The supported file selection was read."} Dependency advisory coverage: ${result.coverage.dependencyStatus}; ${result.coverage.dependenciesChecked} exact versions checked. Git history and runtime authorization were not tested.`, findings: result.findings.map((finding) => ({ title: finding.title, severity: finding.severity, category: finding.category, target: `${finding.file}${finding.line ? `:${finding.line}` : ""}`, evidence: `${finding.source === "ai" ? "AI hypothesis — Needs verification. " : ""}${finding.evidence || ""}\n${finding.description}`, remediation: finding.remedy })) }) : "", [result]);

  return <section id="repo-results" className="app-shell scroll-mt-24 py-12 sm:py-16">
      <div className="surface overflow-hidden rounded-2xl">
        <div className="grid gap-8 p-6 sm:p-8 lg:grid-cols-[1fr_auto] lg:items-center">
          <div><a href={result.repository.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 break-all text-xs text-[#798493] hover:text-white"><Github className="h-3.5 w-3.5" />{result.repository.fullName}<ArrowUpRight className="h-3.5 w-3.5" /></a><h2 className="mt-4 text-3xl font-semibold tracking-[-0.045em]">Repository security report</h2><div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-xs text-[#778191]"><span>{result.filesScanned} of {result.coverage.candidateFiles} supported files checked</span><span>{formatBytes(result.bytesScanned)} read</span><span>Ref {result.repository.ref || result.repository.defaultBranch}{result.repository.commitSha && /^[0-9a-f]{40}$/.test(result.repository.commitSha) ? ` @ ${result.repository.commitSha.slice(0, 7)}` : ""}</span>{result.truncated && <span className="text-[#ffcf78]">Incomplete scan{result.coverage.filesSkipped > 0 ? `, ${result.coverage.filesSkipped} supported files skipped` : ", repository tree was truncated"}</span>}</div><CopyPromptButton prompt={fullAuditPrompt} label="Copy full audit prompt" copiedLabel="Full prompt copied" ariaLabel="Copy one technical prompt for the full repository audit" className="mt-5 border-[var(--signal)]/25 bg-[var(--signal)]/[0.07] text-white" /></div>
          <div className="relative flex h-28 w-28 items-center justify-center rounded-full" style={{ background: `conic-gradient(${partialScore ? "#7f8998" : result.score >= 85 ? "#b9ff66" : result.score >= 65 ? "#ffbf69" : "#ff6b6b"} ${result.score * 3.6}deg, rgba(255,255,255,.07) 0deg)` }}><div className="absolute inset-[8px] rounded-full bg-[#10161e]" /><div className="relative text-center"><p className={"text-3xl font-semibold tracking-[-0.05em]" + (partialScore ? " text-[#8f99a7]" : "")}>{result.score}</p><p className="mt-0.5 text-[0.58rem] font-semibold uppercase tracking-[.1em] text-[#8f99a7]">repo score</p></div></div>
        </div>
        <div className="grid grid-cols-2 border-t border-white/[0.08] sm:grid-cols-4">{(["critical", "high", "medium", "low"] as Severity[]).map((severity) => <div key={severity} className="border-r border-white/[0.07] px-4 py-4 last:border-r-0"><p className={`text-2xl font-semibold ${severityStyle[severity].text}`}>{counts[severity]}</p><p className="mt-1 text-[0.66rem] font-medium uppercase tracking-[.09em] text-[#697483]">{severityStyle[severity].label}</p></div>)}</div>
      </div>

      <div className="surface-muted mt-5 rounded-xl p-4">
        <p className="text-base font-semibold text-white">Rules: {result.filesScanned.toLocaleString()}/{denominator.toLocaleString()} files{result.aiReview?.highRiskTotal !== undefined ? ` · AI: ${result.aiReview.highRiskReviewed ?? 0}/${result.aiReview.highRiskTotal} high-risk files` : ""}</p>
        {skipLabels.length > 0 && <p className="mt-1 text-sm text-[#a5aeba]">Skipped files · {skipLabels.join(" · ")}</p>}
        {partialScore && <p className="mt-1 text-sm text-[#a5aeba]">Partial: score covers only the files read</p>}
        {result.coverage.treeComplete === false && <p className="mt-1 text-sm text-[#a5aeba]">GitHub returned an incomplete tree. Coverage is for the listed files.</p>}
        {result.aiReview && <p className="mt-2 text-sm text-[#a5aeba]">AI logic review · {result.aiReview.status}. {result.aiReview.note}</p>}
        {result.aiReview && ["completed", "partial"].includes(result.aiReview.status) && <button className="mt-2 text-xs text-[#a5aeba] underline" title="High-confidence AI findings carry half the normal penalty and medium-confidence findings one quarter. Low-confidence findings carry none. Total AI penalty is capped at 20 points.">How AI affects the score</button>}
      </div>
      {!!result.aiReview?.highRiskNotReviewed?.length && <details className="surface-muted mt-4 rounded-xl p-4">
        <summary className="cursor-pointer text-sm font-semibold">High-risk files not reviewed by AI ({result.aiReview.highRiskNotReviewed.length})</summary>
        {result.aiReview.hasNextBatch && onNextBatch && <button type="button" className="button-secondary mt-3" onClick={onNextBatch} disabled={nextBatchBusy}>{nextBatchBusy ? "Starting review…" : "Review next batch · 1 credit"}</button>}
        <ul className="mt-3 max-h-64 space-y-1 overflow-auto font-mono text-xs text-[#a5aeba]">{result.aiReview.highRiskNotReviewed.map((file) => <li key={file} className="break-all">{file}</li>)}</ul>
      </details>}
      {!!routes.length && <details className="surface-muted mt-4 rounded-xl p-4">
        <summary className="cursor-pointer text-sm font-semibold">{routes.length} route and server {routes.length === 1 ? "entry point" : "entry points"} · {routeStatus("auth-checked")} auth checked · {routeStatus("public-by-design")} public by design · {routeStatus("no-auth-seen")} with no auth seen</summary>
        <p className="mt-3 text-xs text-[#a5aeba]">Classification is based on code signals. Review roles, tenant checks, resource ownership and middleware behavior in the application.</p>
        <ul className="mt-3 max-h-96 divide-y divide-white/10 overflow-auto">{routes.map((route) => <li key={`${route.file}:${route.line}:${route.method}:${route.path}`} className="py-2 text-sm">
          <span className="font-mono break-all text-white">{route.method} {route.path}</span><span className="ml-2 text-[#a5aeba]">{route.status.replaceAll("-", " ")} · {route.evidence}</span>
          <a href={`https://github.com/${result.repository.fullName}/blob/${encodeURIComponent(result.repository.commitSha || result.repository.defaultBranch)}/${route.file.split("/").map(encodeURIComponent).join("/")}#L${route.line}`} target="_blank" rel="noreferrer" className="mt-1 block break-all text-xs text-[#a5aeba] underline">{route.file}:{route.line}</a>
        </li>)}</ul>
      </details>}
      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="surface-muted rounded-xl p-4"><p className="text-2xl font-semibold text-white">{result.coverage.dependenciesChecked}</p><p className="mt-1 text-xs text-[#788392]">Exact dependency versions checked</p></div>
        <div className="surface-muted rounded-xl p-4"><p className={`text-2xl font-semibold ${result.coverage.knownVulnerabilities ? "text-[#ffd66b]" : "text-white"}`}>{["unavailable", "not-detected"].includes(result.coverage.dependencyStatus) ? "—" : result.coverage.knownVulnerabilities}</p><p className="mt-1 text-xs text-[#788392]">OSV advisory matches</p></div>
        <div className="surface-muted rounded-xl p-4"><p className="text-2xl font-semibold text-white">{result.coverage.agentFilesScanned}</p><p className="mt-1 text-xs text-[#788392]">Agent and MCP files checked</p></div>
        <div className="surface-muted rounded-xl p-4"><p className="text-sm font-semibold capitalize text-white">{result.coverage.dependencyStatus.replace("-", " ")}</p><p className="mt-2 text-xs leading-5 text-[#788392]">Dependency advisory coverage{result.coverage.dependencyStatus === "unavailable" ? " was unavailable; local checks still ran" : " via OSV"}</p></div>
      </div>

      {!!result.coverage.skippedHighRiskFiles?.length && <div className="surface-muted mt-5 rounded-xl p-4"><p className="text-sm font-semibold text-[#ffcf78]">Security-relevant files not read in this scan</p><p className="mt-1 text-xs leading-5 text-[#788392]">Review these files manually or with your coding agent.</p><ul className="mt-3 grid gap-1 font-mono text-xs text-[#a5afbd] sm:grid-cols-2">{result.coverage.skippedHighRiskFiles.map((file) => <li key={file} className="break-all">{file}</li>)}</ul></div>}

      <div className="mt-8 grid min-w-0 gap-8 xl:grid-cols-[minmax(0,1fr)_19rem]">
        <div className="min-w-0"><div className="mb-4"><h2 className="text-xl font-semibold tracking-[-0.025em]">Repository findings</h2><p className="mt-1 text-xs text-[#717c8b]">Review the file and verify every result before changing code.</p></div>{result.findings.length ? <div className="space-y-3">{result.findings.map((finding, index) => <FindingCard key={finding.id} finding={finding} repository={result.repository.fullName} defaultBranch={result.repository.commitSha || result.repository.defaultBranch} defaultOpen={index === 0} />)}</div> : <div className="surface-muted rounded-2xl px-6 py-14 text-center"><ShieldCheck className="mx-auto h-8 w-8 text-[var(--signal)]" /><p className="mt-4 font-medium">No matching risks were found in the files inspected.</p><p className="mx-auto mt-2 max-w-md text-xs leading-5 text-[#778191]">This bounded scan checks the current repository tree and cannot prove the repository is secure. Keep GitHub secret scanning, push protection, and dependency alerts enabled.</p></div>}</div>
        <aside className="space-y-4 xl:sticky xl:top-24 xl:self-start"><div className="surface-muted rounded-2xl p-5"><p className="text-xs font-semibold uppercase tracking-[.12em] text-[#6e7988]">Safe response order</p><ol className="mt-4 space-y-3 text-sm leading-6 text-[#8f99a7]">{responseOrder.map((step, index) => <li key={step}><span className="mr-2 font-mono text-[var(--signal)]">{String(index + 1).padStart(2, "0")}</span>{step}</li>)}</ol></div>{onReset ? <button onClick={onReset} className="button-secondary w-full">Scan another repository</button> : <Link href="/repo-scan" className="button-secondary w-full">Scan another repository</Link>}<Link href="/#scan" className="button-primary w-full">Scan the deployed app <ArrowRight className="h-4 w-4" /></Link></aside>
      </div>
  </section>;
}
