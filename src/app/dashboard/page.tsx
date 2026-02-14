"use client";

import { useEffect, useState } from "react";
import { useRouter } from "next/navigation";
import { useSession, signOut } from "next-auth/react";
import Link from "next/link";
import { motion } from "framer-motion";
import ScanningOverlay from "@/components/ScanningOverlay";
import {
  Shield,
  Globe,
  Search,
  Clock,
  AlertTriangle,
  CheckCircle2,
  Loader2,
  LogOut,
  Plus,
  ExternalLink,
  ShieldCheck,
  XCircle,
} from "lucide-react";
import { formatDate, getScoreColor, getScoreLabel } from "@/lib/utils";

interface Vulnerability {
  id: string;
  severity: string;
}

interface Scan {
  id: string;
  url: string;
  status: string;
  overallScore: number | null;
  pagesScanned: number;
  createdAt: string;
  vulnerabilities: Vulnerability[];
}

export default function DashboardPage() {
  const { data: session, status } = useSession();
  const router = useRouter();
  const [scans, setScans] = useState<Scan[]>([]);
  const [loading, setLoading] = useState(true);
  const [url, setUrl] = useState("");
  const [scanning, setScanning] = useState(false);
  const [scanUrl, setScanUrl] = useState("");

  useEffect(() => {
    if (status === "unauthenticated") {
      router.push("/login");
    }
  }, [status, router]);

  useEffect(() => {
    async function fetchScans() {
      try {
        const res = await fetch("/api/scan");
        if (res.ok) {
          const data = await res.json();
          setScans(data);
        }
      } catch {
        // Silently handle errors
      } finally {
        setLoading(false);
      }
    }

    if (status === "authenticated") {
      fetchScans();
    }
  }, [status]);

  function handleScan(e: React.FormEvent) {
    e.preventDefault();
    if (!url.trim()) return;

    let normalizedUrl = url.trim();
    if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
      normalizedUrl = "https://" + normalizedUrl;
    }

    setScanUrl(normalizedUrl);
    setScanning(true);
  }

  if (status === "loading" || loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-emerald-500" />
      </div>
    );
  }

  if (status === "unauthenticated") return null;

  return (
    <div className="min-h-screen">
      {/* Nav */}
      <nav className="border-b border-gray-800/50 bg-gray-950/80 backdrop-blur-xl">
        <div className="mx-auto max-w-7xl px-4 sm:px-6 lg:px-8">
          <div className="flex h-16 items-center justify-between">
            <Link href="/dashboard" className="flex items-center gap-2">
              <div className="flex h-9 w-9 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500">
                <Shield className="h-5 w-5 text-white" />
              </div>
              <span className="text-xl font-bold">
                Secure<span className="gradient-text">SaaS</span>
              </span>
            </Link>

            <div className="flex items-center gap-4">
              <span className="text-sm text-gray-400">
                {session?.user?.name || session?.user?.email}
              </span>
              <button
                onClick={() => signOut({ callbackUrl: "/" })}
                className="flex items-center gap-2 rounded-lg border border-gray-700 px-3 py-1.5 text-sm text-gray-400 transition hover:bg-gray-800 hover:text-white"
              >
                <LogOut className="h-4 w-4" />
                Sign Out
              </button>
            </div>
          </div>
        </div>
      </nav>

      <div className="mx-auto max-w-7xl px-4 py-8 sm:px-6 lg:px-8">
        {/* Header */}
        <div className="mb-8">
          <h1 className="text-3xl font-bold">Dashboard</h1>
          <p className="mt-1 text-gray-400">
            Scan your websites and monitor security vulnerabilities
          </p>
        </div>

        {/* New Scan */}
        <div className="mb-8 rounded-2xl border border-gray-800 bg-gray-900/50 p-6">
          <h2 className="mb-4 flex items-center gap-2 text-lg font-semibold">
            <Plus className="h-5 w-5 text-emerald-500" />
            New Scan
          </h2>
          <form onSubmit={handleScan} className="flex gap-3">
            <div className="flex flex-1 items-center gap-3 rounded-xl border border-gray-700 bg-gray-900 px-4">
              <Globe className="h-5 w-5 text-gray-500" />
              <input
                type="text"
                value={url}
                onChange={(e) => setUrl(e.target.value)}
                placeholder="Enter website URL (e.g., myapp.com)"
                className="w-full bg-transparent py-3 text-white placeholder:text-gray-500 focus:outline-none"
              />
            </div>
            <button
              type="submit"
              disabled={scanning || !url.trim()}
              className="flex items-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600 disabled:opacity-50"
            >
              {scanning ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Scanning...
                </>
              ) : (
                <>
                  <Search className="h-4 w-4" />
                  Scan
                </>
              )}
            </button>
          </form>
        </div>

        {/* Scan History */}
        <div>
          <h2 className="mb-4 text-xl font-semibold">Scan History</h2>

          {scans.length === 0 ? (
            <div className="rounded-2xl border border-gray-800 bg-gray-900/50 p-12 text-center">
              <ShieldCheck className="mx-auto h-12 w-12 text-gray-600" />
              <h3 className="mt-4 text-lg font-medium text-gray-400">No scans yet</h3>
              <p className="mt-2 text-sm text-gray-500">
                Enter a URL above to start your first security scan
              </p>
            </div>
          ) : (
            <div className="space-y-3">
              {scans.map((scan, index) => {
                const criticalCount = scan.vulnerabilities.filter(
                  (v) => v.severity === "critical" || v.severity === "high"
                ).length;

                return (
                  <motion.div
                    key={scan.id}
                    initial={{ opacity: 0, y: 10 }}
                    animate={{ opacity: 1, y: 0 }}
                    transition={{ delay: index * 0.05 }}
                  >
                    <Link
                      href={`/scan/${scan.id}`}
                      className="flex items-center justify-between rounded-xl border border-gray-800 bg-gray-900/50 p-5 transition hover:border-gray-700 hover:bg-gray-900/80"
                    >
                      <div className="flex items-center gap-4">
                        <div
                          className={`flex h-10 w-10 items-center justify-center rounded-lg ${
                            scan.status === "completed"
                              ? scan.overallScore !== null && scan.overallScore >= 70
                                ? "bg-emerald-500/10 text-emerald-500"
                                : "bg-orange-500/10 text-orange-500"
                              : scan.status === "failed"
                              ? "bg-red-500/10 text-red-500"
                              : "bg-gray-500/10 text-gray-500"
                          }`}
                        >
                          {scan.status === "completed" ? (
                            scan.overallScore !== null && scan.overallScore >= 70 ? (
                              <CheckCircle2 className="h-5 w-5" />
                            ) : (
                              <AlertTriangle className="h-5 w-5" />
                            )
                          ) : scan.status === "failed" ? (
                            <XCircle className="h-5 w-5" />
                          ) : (
                            <Loader2 className="h-5 w-5 animate-spin" />
                          )}
                        </div>

                        <div>
                          <div className="flex items-center gap-2">
                            <span className="font-medium text-white">{scan.url}</span>
                            <ExternalLink className="h-3.5 w-3.5 text-gray-500" />
                          </div>
                          <div className="mt-1 flex items-center gap-3 text-xs text-gray-500">
                            <span className="flex items-center gap-1">
                              <Clock className="h-3 w-3" />
                              {formatDate(scan.createdAt)}
                            </span>
                            {scan.status === "completed" && (
                              <>
                                <span>{scan.pagesScanned} pages</span>
                                <span>{scan.vulnerabilities.length} issues</span>
                              </>
                            )}
                          </div>
                        </div>
                      </div>

                      <div className="flex items-center gap-4">
                        {scan.status === "completed" && scan.overallScore !== null && (
                          <div className="text-right">
                            <div className={`text-2xl font-bold ${getScoreColor(scan.overallScore)}`}>
                              {scan.overallScore}
                            </div>
                            <div className="text-xs text-gray-500">
                              {getScoreLabel(scan.overallScore)}
                            </div>
                          </div>
                        )}
                        {criticalCount > 0 && (
                          <div className="rounded-full bg-red-500/10 px-3 py-1 text-xs font-medium text-red-400">
                            {criticalCount} critical/high
                          </div>
                        )}
                      </div>
                    </Link>
                  </motion.div>
                );
              })}
            </div>
          )}
        </div>
      </div>

      <ScanningOverlay
        url={scanUrl}
        isOpen={scanning}
        onClose={() => {
          setScanning(false);
          setScanUrl("");
          setUrl("");
          // Refresh scan history
          fetch("/api/scan")
            .then((res) => res.json())
            .then((data) => setScans(data))
            .catch(() => {});
        }}
      />
    </div>
  );
}
