"use client";

import { useEffect, useState } from "react";
import { useParams } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  Shield,
  ArrowLeft,
  Globe,
  Clock,
  FileSearch,
  AlertTriangle,
  AlertCircle,
  Info,
  CheckCircle2,
  ChevronDown,
  ChevronUp,
  Loader2,
  ShieldAlert,
  ShieldCheck,
  ShieldX,
  Lock,
  Sparkles,
} from "lucide-react";
import { formatDate, getSeverityColor, getScoreColor, getScoreLabel } from "@/lib/utils";

interface Vulnerability {
  id: string;
  type: string;
  severity: string;
  title: string;
  description: string;
  url: string;
  remedy: string;
}

interface Scan {
  id: string;
  url: string;
  status: string;
  overallScore: number | null;
  pagesScanned: number;
  totalPages: number;
  createdAt: string;
  completedAt: string | null;
  vulnerabilities: Vulnerability[];
}

function SeverityIcon({ severity }: { severity: string }) {
  switch (severity) {
    case "critical":
      return <ShieldX className="h-5 w-5" />;
    case "high":
      return <ShieldAlert className="h-5 w-5" />;
    case "medium":
      return <AlertTriangle className="h-5 w-5" />;
    case "low":
      return <AlertCircle className="h-5 w-5" />;
    case "info":
      return <Info className="h-5 w-5" />;
    default:
      return <Info className="h-5 w-5" />;
  }
}

function ScoreGauge({ score }: { score: number }) {
  const circumference = 2 * Math.PI * 60;
  const offset = circumference - (score / 100) * circumference;

  return (
    <div className="relative flex h-40 w-40 items-center justify-center">
      <svg className="h-full w-full -rotate-90" viewBox="0 0 140 140">
        <circle
          cx="70"
          cy="70"
          r="60"
          fill="none"
          stroke="currentColor"
          strokeWidth="8"
          className="text-gray-800"
        />
        <motion.circle
          cx="70"
          cy="70"
          r="60"
          fill="none"
          strokeWidth="8"
          strokeLinecap="round"
          strokeDasharray={circumference}
          initial={{ strokeDashoffset: circumference }}
          animate={{ strokeDashoffset: offset }}
          transition={{ duration: 1.5, ease: "easeInOut" }}
          className={getScoreColor(score)}
          stroke="currentColor"
        />
      </svg>
      <div className="absolute flex flex-col items-center">
        <span className={`text-4xl font-bold ${getScoreColor(score)}`}>{score}</span>
        <span className="text-sm text-gray-400">{getScoreLabel(score)}</span>
      </div>
    </div>
  );
}

function VulnerabilityCard({ vulnerability, canViewRemedies }: { vulnerability: Vulnerability; canViewRemedies: boolean }) {
  const [expanded, setExpanded] = useState(false);

  return (
    <motion.div
      initial={{ opacity: 0, y: 10 }}
      animate={{ opacity: 1, y: 0 }}
      className={`rounded-xl border ${getSeverityColor(vulnerability.severity)} bg-gray-900/50 overflow-hidden`}
    >
      <button
        onClick={() => setExpanded(!expanded)}
        className="flex w-full items-center justify-between p-4 text-left"
      >
        <div className="flex items-center gap-3">
          <div className={getSeverityColor(vulnerability.severity)}>
            <SeverityIcon severity={vulnerability.severity} />
          </div>
          <div>
            <h3 className="font-medium text-white">{vulnerability.title}</h3>
            <div className="mt-1 flex items-center gap-3 text-xs">
              <span
                className={`rounded-full px-2 py-0.5 font-medium uppercase ${getSeverityColor(
                  vulnerability.severity
                )}`}
              >
                {vulnerability.severity}
              </span>
              <span className="text-gray-500">{vulnerability.type}</span>
            </div>
          </div>
        </div>
        {expanded ? (
          <ChevronUp className="h-5 w-5 shrink-0 text-gray-500" />
        ) : (
          <ChevronDown className="h-5 w-5 shrink-0 text-gray-500" />
        )}
      </button>

      {expanded && (
        <div className="border-t border-gray-800 px-4 pb-4 pt-3 space-y-4">
          <div>
            <h4 className="mb-1 text-sm font-medium text-gray-300">Description</h4>
            <p className="text-sm text-gray-400 leading-relaxed">{vulnerability.description}</p>
          </div>

          <div>
            <h4 className="mb-1 text-sm font-medium text-gray-300">Found on</h4>
            <p className="text-sm text-gray-400 break-all">{vulnerability.url}</p>
          </div>

          <div>
            <h4 className="mb-1 text-sm font-medium text-emerald-400">How to Fix</h4>
            {canViewRemedies ? (
              <p className="text-sm text-gray-300 leading-relaxed rounded-lg bg-gray-800/50 p-3">
                {vulnerability.remedy}
              </p>
            ) : (
              <div className="relative rounded-lg bg-gray-800/50 p-3 overflow-hidden">
                <p className="text-sm text-gray-300 leading-relaxed select-none blur-sm" aria-hidden>
                  {vulnerability.remedy}
                </p>
                <div className="absolute inset-0 flex flex-col items-center justify-center bg-gray-900/60 backdrop-blur-[2px]">
                  <Lock className="h-5 w-5 text-amber-400 mb-2" />
                  <p className="text-sm font-medium text-white">Upgrade to unlock fix suggestions</p>
                  <Link
                    href="/pricing"
                    className="mt-2 inline-flex items-center gap-1.5 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 px-4 py-1.5 text-xs font-medium text-white hover:from-emerald-600 hover:to-cyan-600 transition"
                  >
                    <Sparkles className="h-3 w-3" />
                    View Plans
                  </Link>
                </div>
              </div>
            )}
          </div>
        </div>
      )}
    </motion.div>
  );
}

export default function ScanResultPage() {
  const params = useParams();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [userPlan, setUserPlan] = useState<string>("free");

  useEffect(() => {
    async function fetchData() {
      try {
        const [scanRes, planRes] = await Promise.all([
          fetch(`/api/scan/${params.id}`),
          fetch("/api/user/plan"),
        ]);

        if (!scanRes.ok) {
          setError("Scan not found");
          setLoading(false);
          return;
        }

        const scanData = await scanRes.json();
        setScan(scanData);

        if (planRes.ok) {
          const planData = await planRes.json();
          setUserPlan(planData.plan || "free");
        }
      } catch {
        setError("Failed to load scan results");
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, [params.id]);

  const canViewRemedies = userPlan === "starter" || userPlan === "pro";

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Loader2 className="mx-auto h-8 w-8 animate-spin text-emerald-500" />
          <p className="mt-4 text-gray-400">Loading scan results...</p>
        </div>
      </div>
    );
  }

  if (error || !scan) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <ShieldX className="mx-auto h-12 w-12 text-red-500" />
          <h1 className="mt-4 text-xl font-bold">{error || "Scan not found"}</h1>
          <Link href="/" className="mt-4 inline-flex items-center gap-2 text-emerald-400 hover:text-emerald-300">
            <ArrowLeft className="h-4 w-4" />
            Back to home
          </Link>
        </div>
      </div>
    );
  }

  const severityCounts = {
    critical: scan.vulnerabilities.filter((v) => v.severity === "critical").length,
    high: scan.vulnerabilities.filter((v) => v.severity === "high").length,
    medium: scan.vulnerabilities.filter((v) => v.severity === "medium").length,
    low: scan.vulnerabilities.filter((v) => v.severity === "low").length,
    info: scan.vulnerabilities.filter((v) => v.severity === "info").length,
  };

  // Sort vulnerabilities by severity
  const severityOrder = ["critical", "high", "medium", "low", "info"];
  const sortedVulns = [...scan.vulnerabilities].sort(
    (a, b) => severityOrder.indexOf(a.severity) - severityOrder.indexOf(b.severity)
  );

  return (
    <div className="min-h-screen pb-20">
      {/* Header */}
      <div className="border-b border-gray-800/50 bg-gray-950/80 backdrop-blur-xl">
        <div className="mx-auto max-w-7xl px-4 py-4 sm:px-6 lg:px-8">
          <div className="flex items-center justify-between">
            <Link href="/" className="flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <span className="text-xl font-bold">
                Secure<span className="gradient-text">SaaS</span>
              </span>
            </Link>
            <Link href="/" className="flex items-center gap-2 text-sm text-gray-400 hover:text-white">
              <ArrowLeft className="h-4 w-4" />
              New Scan
            </Link>
          </div>
        </div>
      </div>

      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Scan Overview */}
        <div className="mb-8 rounded-2xl border border-gray-800 bg-gray-900/50 p-6 sm:p-8">
          <div className="flex flex-col gap-8 md:flex-row md:items-center md:justify-between">
            <div className="flex-1">
              <div className="flex items-center gap-2 text-sm text-gray-400">
                <Globe className="h-4 w-4" />
                <span className="break-all">{scan.url}</span>
              </div>
              <h1 className="mt-3 text-2xl font-bold sm:text-3xl">Security Report</h1>
              <div className="mt-4 flex flex-wrap gap-4 text-sm text-gray-400">
                <div className="flex items-center gap-1.5">
                  <Clock className="h-4 w-4" />
                  {formatDate(scan.createdAt)}
                </div>
                <div className="flex items-center gap-1.5">
                  <FileSearch className="h-4 w-4" />
                  {scan.pagesScanned} page{scan.pagesScanned !== 1 ? "s" : ""} scanned
                </div>
                <div className="flex items-center gap-1.5">
                  <AlertTriangle className="h-4 w-4" />
                  {scan.vulnerabilities.length} issue{scan.vulnerabilities.length !== 1 ? "s" : ""} found
                </div>
              </div>
            </div>

            <div className="flex justify-center">
              {scan.overallScore !== null && <ScoreGauge score={scan.overallScore} />}
            </div>
          </div>
        </div>

        {/* Severity Summary */}
        <div className="mb-8 grid grid-cols-2 gap-4 sm:grid-cols-5">
          {[
            { label: "Critical", count: severityCounts.critical, color: "text-red-500 bg-red-500/10 border-red-500/20" },
            { label: "High", count: severityCounts.high, color: "text-orange-500 bg-orange-500/10 border-orange-500/20" },
            { label: "Medium", count: severityCounts.medium, color: "text-yellow-500 bg-yellow-500/10 border-yellow-500/20" },
            { label: "Low", count: severityCounts.low, color: "text-blue-500 bg-blue-500/10 border-blue-500/20" },
            { label: "Info", count: severityCounts.info, color: "text-gray-400 bg-gray-400/10 border-gray-400/20" },
          ].map((item) => (
            <div
              key={item.label}
              className={`rounded-xl border p-4 text-center ${item.color}`}
            >
              <div className="text-2xl font-bold">{item.count}</div>
              <div className="mt-1 text-xs font-medium uppercase">{item.label}</div>
            </div>
          ))}
        </div>

        {/* Vulnerabilities List */}
        {sortedVulns.length > 0 ? (
          <div>
            <div className="mb-4 flex items-center justify-between">
              <h2 className="text-xl font-semibold">Vulnerabilities Found</h2>
              {!canViewRemedies && (
                <Link
                  href="/pricing"
                  className="flex items-center gap-2 rounded-lg bg-gradient-to-r from-emerald-500/10 to-cyan-500/10 border border-emerald-500/20 px-4 py-2 text-sm font-medium text-emerald-400 transition hover:from-emerald-500/20 hover:to-cyan-500/20"
                >
                  <Sparkles className="h-4 w-4" />
                  Upgrade to unlock all fix suggestions
                </Link>
              )}
            </div>
            <div className="space-y-3">
              {sortedVulns.map((vuln) => (
                <VulnerabilityCard key={vuln.id} vulnerability={vuln} canViewRemedies={canViewRemedies} />
              ))}
            </div>
          </div>
        ) : (
          <div className="rounded-2xl border border-emerald-500/20 bg-emerald-500/5 p-12 text-center">
            <ShieldCheck className="mx-auto h-16 w-16 text-emerald-500" />
            <h2 className="mt-4 text-2xl font-bold">All Clear!</h2>
            <p className="mt-2 text-gray-400">
              No vulnerabilities were found on your website. Great job keeping your SaaS secure!
            </p>
          </div>
        )}

        {/* Back to Scan */}
        <div className="mt-12 text-center">
          <Link
            href="/"
            className="inline-flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-8 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
          >
            Scan Another Website
          </Link>
        </div>
      </div>
    </div>
  );
}
