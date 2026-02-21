"use client";

import { useEffect, useState } from "react";
import { useParams, useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import Link from "next/link";
import { motion } from "framer-motion";
import ScanningOverlay from "@/components/ScanningOverlay";
import { ToastContainer, toast } from "@/components/Toast";
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
  Zap,
  RotateCw,
  Share2,
  Copy,
  TrendingUp,
  Trophy,
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
  userId: string | null;
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

function VulnerabilityCard({ vulnerability, canViewRemedies, index }: { vulnerability: Vulnerability; canViewRemedies: boolean; index: number }) {
  // Auto-expand the first vulnerability for free users so they see the locked remedy CTA
  const [expanded, setExpanded] = useState(!canViewRemedies && index === 0);

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
            <h4 className="mb-1 text-sm font-medium text-emerald-400 flex items-center gap-1.5">
              <Sparkles className="h-3.5 w-3.5" />
              How to Fix
            </h4>
            {canViewRemedies ? (
              <p className="text-sm text-gray-300 leading-relaxed rounded-lg bg-gray-800/50 p-3">
                {vulnerability.remedy}
              </p>
            ) : (
              <div className="relative rounded-xl border border-amber-500/20 bg-gradient-to-br from-amber-500/5 to-orange-500/5 p-4 overflow-hidden">
                {/* Blurred preview */}
                <p className="text-sm text-gray-400 leading-relaxed select-none blur-[6px] pointer-events-none" aria-hidden>
                  {vulnerability.remedy}
                </p>
                {/* Overlay CTA */}
                <div className="absolute inset-0 flex flex-col items-center justify-center bg-gray-950/40 backdrop-blur-[1px]">
                  <div className="flex flex-col items-center gap-3 p-4">
                    <div className="flex h-10 w-10 items-center justify-center rounded-full bg-amber-500/10 ring-1 ring-amber-500/30">
                      <Lock className="h-5 w-5 text-amber-400" />
                    </div>
                    <div className="text-center">
                      <p className="text-sm font-semibold text-white">
                        Fix available — upgrade to view
                      </p>
                      <p className="mt-0.5 text-xs text-gray-400">
                        {vulnerability.severity === "critical" || vulnerability.severity === "high"
                          ? "This is a high-priority issue. Get the fix now."
                          : "Step-by-step instructions to resolve this issue."}
                      </p>
                    </div>
                    <Link
                      href="/pricing"
                      className="inline-flex items-center gap-2 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 px-5 py-2 text-sm font-semibold text-white shadow-lg shadow-emerald-500/20 transition hover:from-emerald-600 hover:to-cyan-600 hover:shadow-emerald-500/30"
                    >
                      <Sparkles className="h-3.5 w-3.5" />
                      Unlock Fixes — From $29/mo
                    </Link>
                  </div>
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
  const router = useRouter();
  const { data: session } = useSession();
  const [scan, setScan] = useState<Scan | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState("");
  const [userPlan, setUserPlan] = useState<string>("free");
  const [userCredits, setUserCredits] = useState<number | null>(null);
  const [percentile, setPercentile] = useState<number | null>(null);
  const [rescanning, setRescanning] = useState(false);
  const [rescanUrl, setRescanUrl] = useState("");

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

        // Auto-claim: if user is logged in and scan has no owner, claim it
        if (session?.user?.id && !scanData.userId) {
          try {
            await fetch("/api/scan/claim", {
              method: "POST",
              headers: { "Content-Type": "application/json" },
              body: JSON.stringify({ scanId: scanData.id }),
            });
          } catch {
            // Non-fatal — scan will still display, just won't appear in history
          }
        }

        if (planRes.ok) {
          const planData = await planRes.json();
          setUserPlan(planData.plan || "free");
          setUserCredits(planData.credits ?? null);
        }

        // Fetch score percentile
        if (scanData.overallScore !== null) {
          try {
            const pctRes = await fetch(`/api/scan/percentile?score=${scanData.overallScore}`);
            if (pctRes.ok) {
              const pctData = await pctRes.json();
              setPercentile(pctData.percentile);
            }
          } catch {
            // Non-fatal
          }
        }
      } catch {
        setError("Failed to load scan results");
      } finally {
        setLoading(false);
      }
    }

    fetchData();
  }, [params.id, session?.user?.id]);

  const canViewRemedies = userPlan === "starter" || userPlan === "pro";

  function handleRescan() {
    if (!scan) return;
    if (userCredits !== null && userCredits <= 0) {
      toast("No scan credits remaining. Upgrade your plan.", "warning");
      return;
    }
    setRescanUrl(scan.url);
    setRescanning(true);
  }

  function handleCopyLink() {
    const url = window.location.href;
    navigator.clipboard.writeText(url).then(
      () => toast("Report link copied to clipboard!", "success"),
      () => toast("Failed to copy link", "error")
    );
  }

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
    <div className={`min-h-screen ${!canViewRemedies && sortedVulns.length > 0 ? "pb-32" : "pb-20"}`}>
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
            <div className="flex items-center gap-3">
              {userCredits !== null && (
                <div className={`flex items-center gap-1.5 rounded-lg border px-3 py-1.5 text-sm font-medium ${userCredits > 0 ? "border-amber-500/20 bg-amber-500/10 text-amber-400" : "border-red-500/20 bg-red-500/10 text-red-400"}`}>
                  <Zap className="h-3.5 w-3.5" />
                  {userCredits} scan{userCredits !== 1 ? "s" : ""} left
                </div>
              )}
              <button
                onClick={handleCopyLink}
                className="flex items-center gap-1.5 rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-400 transition hover:bg-gray-800 hover:text-white"
                title="Copy report link"
              >
                <Copy className="h-3.5 w-3.5" />
                <span className="hidden sm:inline">Share</span>
              </button>
              {session?.user && (
                <button
                  onClick={handleRescan}
                  disabled={userCredits !== null && userCredits <= 0}
                  className="flex items-center gap-1.5 rounded-lg border border-emerald-500/30 bg-emerald-500/10 px-3 py-1.5 text-sm font-medium text-emerald-400 transition hover:bg-emerald-500/20 disabled:opacity-40 disabled:cursor-not-allowed"
                  title="Rescan this website"
                >
                  <RotateCw className="h-3.5 w-3.5" />
                  <span className="hidden sm:inline">Rescan</span>
                </button>
              )}
              <Link href="/" className="flex items-center gap-2 text-sm text-gray-400 hover:text-white">
                <ArrowLeft className="h-4 w-4" />
                New Scan
              </Link>
            </div>
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

            <div className="flex flex-col items-center gap-3 justify-center">
              {scan.overallScore !== null && <ScoreGauge score={scan.overallScore} />}
              {percentile !== null && (
                <motion.div
                  initial={{ opacity: 0, scale: 0.9 }}
                  animate={{ opacity: 1, scale: 1 }}
                  transition={{ delay: 1.8 }}
                  className={`flex items-center gap-1.5 rounded-full px-3 py-1 text-xs font-semibold ${
                    percentile >= 70
                      ? "bg-emerald-500/10 text-emerald-400 border border-emerald-500/20"
                      : percentile >= 40
                        ? "bg-yellow-500/10 text-yellow-400 border border-yellow-500/20"
                        : "bg-red-500/10 text-red-400 border border-red-500/20"
                  }`}
                >
                  <Trophy className="h-3 w-3" />
                  Better than {percentile}% of sites
                </motion.div>
              )}
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
            <div className="mb-4">
              <h2 className="text-xl font-semibold">Vulnerabilities Found</h2>
            </div>

            {/* Upgrade Banner — shown to free users */}
            {!canViewRemedies && (
              <motion.div
                initial={{ opacity: 0, y: 10 }}
                animate={{ opacity: 1, y: 0 }}
                className="mb-6 rounded-2xl border border-emerald-500/20 bg-gradient-to-r from-emerald-500/5 via-cyan-500/5 to-emerald-500/5 p-6 sm:p-8"
              >
                <div className="flex flex-col gap-6 sm:flex-row sm:items-center sm:justify-between">
                  <div className="flex items-start gap-4">
                    <div className="flex h-12 w-12 shrink-0 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-500 shadow-lg shadow-emerald-500/20">
                      <Sparkles className="h-6 w-6 text-white" />
                    </div>
                    <div>
                      <h3 className="text-lg font-bold text-white">
                        We found {sortedVulns.length} issue{sortedVulns.length !== 1 ? "s" : ""} — unlock the fixes
                      </h3>
                      <p className="mt-1 text-sm text-gray-400">
                        {severityCounts.critical + severityCounts.high > 0
                          ? `Including ${severityCounts.critical + severityCounts.high} high-priority issue${severityCounts.critical + severityCounts.high !== 1 ? "s" : ""} that need immediate attention. `
                          : ""}
                        Upgrade to get step-by-step remediation guides for every vulnerability.
                      </p>
                    </div>
                  </div>
                  <Link
                    href="/pricing"
                    className="inline-flex shrink-0 items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 font-semibold text-white shadow-lg shadow-emerald-500/25 transition hover:from-emerald-600 hover:to-cyan-600 hover:shadow-emerald-500/40"
                  >
                    <Lock className="h-4 w-4" />
                    Unlock All Fixes
                  </Link>
                </div>
              </motion.div>
            )}

            <div className="space-y-3">
              {sortedVulns.map((vuln, i) => (
                <VulnerabilityCard key={vuln.id} vulnerability={vuln} canViewRemedies={canViewRemedies} index={i} />
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

      {/* Sticky bottom upgrade bar — free users only */}
      {!canViewRemedies && sortedVulns.length > 0 && (
        <div className="fixed bottom-0 inset-x-0 z-50 border-t border-gray-800 bg-gray-950/95 backdrop-blur-xl">
          <div className="mx-auto flex max-w-7xl items-center justify-between gap-4 px-4 py-3 sm:px-6 lg:px-8">
            <div className="flex items-center gap-3 min-w-0">
              <div className="hidden sm:flex h-8 w-8 shrink-0 items-center justify-center rounded-lg bg-amber-500/10 ring-1 ring-amber-500/30">
                <Lock className="h-4 w-4 text-amber-400" />
              </div>
              <p className="text-sm text-gray-300 truncate">
                <span className="font-semibold text-white">{sortedVulns.length} fix{sortedVulns.length !== 1 ? "es" : ""}</span>{" "}
                available — unlock step-by-step remediation
              </p>
            </div>
            <Link
              href="/pricing"
              className="inline-flex shrink-0 items-center gap-2 rounded-lg bg-gradient-to-r from-emerald-500 to-cyan-500 px-5 py-2.5 text-sm font-semibold text-white shadow-lg shadow-emerald-500/20 transition hover:from-emerald-600 hover:to-cyan-600"
            >
              <Sparkles className="h-4 w-4" />
              <span className="hidden sm:inline">Upgrade Now</span>
              <span className="sm:hidden">Upgrade</span>
            </Link>
          </div>
        </div>
      )}

      {/* Rescan overlay */}
      <ScanningOverlay
        url={rescanUrl}
        isOpen={rescanning}
        onClose={() => {
          setRescanning(false);
          setRescanUrl("");
        }}
      />

      {/* Toast notifications */}
      <ToastContainer />
    </div>
  );
}
