"use client";

import { useMemo, useState } from "react";
import Link from "next/link";
import { AlertCircle, AlertTriangle, ArrowRight, ArrowUpRight, ChevronDown, ChevronUp, Github, ShieldCheck, ShieldX } from "lucide-react";
import { CopyPromptButton } from "@/components/CopyPromptButton";
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
    skippedHighRiskFiles?: string[];
    agentFilesScanned: number;
    dependencyManifests: number;
    dependenciesChecked: number;
    knownVulnerabilities: number;
    dependencyStatus: "checked" | "partial" | "unavailable" | "not-detected";
  };
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
  const fixPrompt = buildFixPrompt({ surface: "source repository", title: finding.title, severity: finding.severity, category: finding.category, target: `${finding.file}${finding.line ? `:${finding.line}` : ""}`, repository, evidence: finding.description, remediation: finding.remedy });
  return <article className={`overflow-hidden rounded-xl border ${style.border} bg-[#0b1016]`}>
    <button onClick={() => setOpen((value) => !value)} className="grid w-full grid-cols-[auto_1fr_auto] items-start gap-3 p-4 text-left sm:p-5" aria-expanded={open}>
      <span className={`flex h-9 w-9 items-center justify-center rounded-lg ${style.bg} ${style.text}`}><Icon className="h-4 w-4" /></span>
      <span className="min-w-0"><span className="flex flex-wrap items-center gap-2"><span className="text-sm font-semibold text-white sm:text-base">{finding.title}</span><span className={`rounded px-1.5 py-0.5 text-[0.61rem] font-bold uppercase tracking-[.08em] ${style.bg} ${style.text}`}>{style.label}</span></span><span className="mt-1.5 block break-all font-mono text-xs leading-5 text-[#667180]">{finding.file}{finding.line ? `:${finding.line}` : ""}</span></span>
      {open ? <ChevronUp className="mt-2 h-4 w-4 text-[#687382]" /> : <ChevronDown className="mt-2 h-4 w-4 text-[#687382]" />}
    </button>
    {open && <div className="border-t border-white/[0.07] p-4 sm:p-5">
      <div className="grid gap-5 lg:grid-cols-2">
        <div className="min-w-0"><p className="text-[0.67rem] font-bold uppercase tracking-[.12em] text-[#687382]">Why it was flagged</p><p className="mt-3 text-sm leading-7 text-[#a5aeba]">{finding.description}</p><div className="mt-4 flex flex-wrap gap-x-4 gap-y-2"><a href={fileUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--signal)] hover:underline">Open file on GitHub <ArrowUpRight className="h-3.5 w-3.5" /></a>{finding.referenceUrl && <a href={finding.referenceUrl} target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-xs font-semibold text-[#aeb8c5] hover:text-white hover:underline">Open advisory <ArrowUpRight className="h-3.5 w-3.5" /></a>}</div></div>
        <div className="rounded-xl border border-white/[0.08] bg-white/[0.025] p-4 sm:p-5"><div className="flex flex-wrap items-center justify-between gap-3"><p className="flex items-center gap-2 text-sm font-semibold"><ShieldCheck className="h-4 w-4 text-[var(--signal)]" />What to do next</p><CopyPromptButton prompt={fixPrompt} /></div><p className="mt-3 text-sm leading-7 text-[#a5aeba]">{finding.remedy}</p></div>
      </div>
    </div>}
  </article>;
}

export function RepoReport({ result, onReset }: { result: RepoReportResult; onReset?: () => void }) {
  const counts = useMemo(() => Object.fromEntries((["critical", "high", "medium", "low"] as Severity[]).map((severity) => [severity, result?.findings.filter((finding) => finding.severity === severity).length || 0])) as Record<Severity, number>, [result]);
  const fullAuditPrompt = useMemo(() => result ? buildRepoAuditPrompt({ repository: result.repository.fullName, score: result.score, coverageSummary: `${result.filesScanned} of ${result.coverage.candidateFiles} supported files read; ${result.coverage.filesSkipped} skipped. ${result.truncated ? "The scan is incomplete." : "The supported file selection was read."} Dependency advisory coverage: ${result.coverage.dependencyStatus}; ${result.coverage.dependenciesChecked} exact versions checked. Git history and runtime authorization were not tested.`, findings: result.findings.map((finding) => ({ title: finding.title, severity: finding.severity, category: finding.category, target: `${finding.file}${finding.line ? `:${finding.line}` : ""}`, evidence: finding.description, remediation: finding.remedy })) }) : "", [result]);

  return <section id="repo-results" className="app-shell scroll-mt-24 py-12 sm:py-16">
      <div className="surface overflow-hidden rounded-2xl">
        <div className="grid gap-8 p-6 sm:p-8 lg:grid-cols-[1fr_auto] lg:items-center">
          <div><a href={result.repository.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 break-all text-xs text-[#798493] hover:text-white"><Github className="h-3.5 w-3.5" />{result.repository.fullName}<ArrowUpRight className="h-3.5 w-3.5" /></a><h2 className="mt-4 text-3xl font-semibold tracking-[-0.045em]">Repository security report</h2><div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-xs text-[#778191]"><span>{result.filesScanned} of {result.coverage.candidateFiles} supported files scanned</span><span>{formatBytes(result.bytesScanned)} read</span><span>Ref {result.repository.ref || result.repository.defaultBranch}{result.repository.commitSha && /^[0-9a-f]{40}$/.test(result.repository.commitSha) ? ` @ ${result.repository.commitSha.slice(0, 7)}` : ""}</span>{result.truncated && <span className="text-[#ffcf78]">Incomplete scan{result.coverage.filesSkipped > 0 ? `, ${result.coverage.filesSkipped} supported files skipped` : ", repository tree was truncated"}</span>}</div><CopyPromptButton prompt={fullAuditPrompt} label="Copy full audit prompt" copiedLabel="Full prompt copied" ariaLabel="Copy one technical prompt for the full repository audit" className="mt-5 border-[var(--signal)]/25 bg-[var(--signal)]/[0.07] text-white" /></div>
          <div className="relative flex h-28 w-28 items-center justify-center rounded-full" style={{ background: `conic-gradient(${result.score >= 85 ? "#b9ff66" : result.score >= 65 ? "#ffbf69" : "#ff6b6b"} ${result.score * 3.6}deg, rgba(255,255,255,.07) 0deg)` }}><div className="absolute inset-[8px] rounded-full bg-[#10161e]" /><div className="relative text-center"><p className="text-3xl font-semibold tracking-[-0.05em]">{result.score}</p><p className="mt-0.5 text-[0.58rem] font-semibold uppercase tracking-[.1em] text-[#8f99a7]">repo score</p></div></div>
        </div>
        <div className="grid grid-cols-2 border-t border-white/[0.08] sm:grid-cols-4">{(["critical", "high", "medium", "low"] as Severity[]).map((severity) => <div key={severity} className="border-r border-white/[0.07] px-4 py-4 last:border-r-0"><p className={`text-2xl font-semibold ${severityStyle[severity].text}`}>{counts[severity]}</p><p className="mt-1 text-[0.66rem] font-medium uppercase tracking-[.09em] text-[#697483]">{severityStyle[severity].label}</p></div>)}</div>
      </div>

      <div className="mt-5 grid gap-3 sm:grid-cols-2 xl:grid-cols-4">
        <div className="surface-muted rounded-xl p-4"><p className="text-2xl font-semibold text-white">{result.coverage.dependenciesChecked}</p><p className="mt-1 text-xs text-[#788392]">Exact dependency versions checked</p></div>
        <div className="surface-muted rounded-xl p-4"><p className={`text-2xl font-semibold ${result.coverage.knownVulnerabilities ? "text-[#ffd66b]" : "text-white"}`}>{["unavailable", "not-detected"].includes(result.coverage.dependencyStatus) ? "—" : result.coverage.knownVulnerabilities}</p><p className="mt-1 text-xs text-[#788392]">OSV advisory matches</p></div>
        <div className="surface-muted rounded-xl p-4"><p className="text-2xl font-semibold text-white">{result.coverage.agentFilesScanned}</p><p className="mt-1 text-xs text-[#788392]">Agent and MCP files checked</p></div>
        <div className="surface-muted rounded-xl p-4"><p className="text-sm font-semibold capitalize text-white">{result.coverage.dependencyStatus.replace("-", " ")}</p><p className="mt-2 text-xs leading-5 text-[#788392]">Dependency advisory coverage{result.coverage.dependencyStatus === "unavailable" ? " was unavailable; local checks still ran" : " via OSV"}</p></div>
      </div>

      {!!result.coverage.skippedHighRiskFiles?.length && <div className="surface-muted mt-5 rounded-xl p-4"><p className="text-sm font-semibold text-[#ffcf78]">Security-relevant files not read in this scan</p><p className="mt-1 text-xs leading-5 text-[#788392]">These files did not fit the per-scan file budget. Review them manually or ask your coding agent to audit them.</p><ul className="mt-3 grid gap-1 font-mono text-xs text-[#a5afbd] sm:grid-cols-2">{result.coverage.skippedHighRiskFiles.map((file) => <li key={file} className="break-all">{file}</li>)}</ul></div>}

      <div className="mt-8 grid min-w-0 gap-8 xl:grid-cols-[minmax(0,1fr)_19rem]">
        <div className="min-w-0"><div className="mb-4"><h2 className="text-xl font-semibold tracking-[-0.025em]">Repository findings</h2><p className="mt-1 text-xs text-[#717c8b]">Review the file and verify every result before changing code.</p></div>{result.findings.length ? <div className="space-y-3">{result.findings.map((finding, index) => <FindingCard key={finding.id} finding={finding} repository={result.repository.fullName} defaultBranch={result.repository.commitSha || result.repository.defaultBranch} defaultOpen={index === 0} />)}</div> : <div className="surface-muted rounded-2xl px-6 py-14 text-center"><ShieldCheck className="mx-auto h-8 w-8 text-[var(--signal)]" /><p className="mt-4 font-medium">No matching risks were found in the files inspected.</p><p className="mx-auto mt-2 max-w-md text-xs leading-5 text-[#778191]">This bounded scan checks the current repository tree and cannot prove the repository is secure. Keep GitHub secret scanning, push protection, and dependency alerts enabled.</p></div>}</div>
        <aside className="space-y-4 xl:sticky xl:top-24 xl:self-start"><div className="surface-muted rounded-2xl p-5"><p className="text-xs font-semibold uppercase tracking-[.12em] text-[#6e7988]">Safe response order</p><ol className="mt-4 space-y-3 text-sm leading-6 text-[#8f99a7]"><li><span className="mr-2 font-mono text-[var(--signal)]">01</span>Revoke exposed credentials.</li><li><span className="mr-2 font-mono text-[var(--signal)]">02</span>Remove them from Git history.</li><li><span className="mr-2 font-mono text-[var(--signal)]">03</span>Fix permissions and code paths.</li><li><span className="mr-2 font-mono text-[var(--signal)]">04</span>Run both scanners again.</li></ol></div>{onReset ? <button onClick={onReset} className="button-secondary w-full">Scan another repository</button> : <Link href="/repo-scan" className="button-secondary w-full">Scan another repository</Link>}<Link href="/#scan" className="button-primary w-full">Scan the deployed app <ArrowRight className="h-4 w-4" /></Link></aside>
      </div>
  </section>;
}
