"use client";

import { useState, useEffect, useRef, useCallback } from "react";
import { useRouter } from "next/navigation";
import { useSession } from "next-auth/react";
import { motion, AnimatePresence } from "framer-motion";
import {
  Shield,
  Lock,
  FileWarning,
  Mail,
  Bot,
  AlertTriangle,
  FolderOpen,
  ShieldCheck,
  Cookie,
  Code2,
  Fingerprint,
  CheckCircle2,
  XCircle,
  Loader2,
  ArrowRight,
  Radar,
  Globe,
  Network,
  Map,
  ShieldAlert,
  ArrowRightLeft,
  FileCode,
  UserPlus,
} from "lucide-react";

interface ScanProgress {
  step: string;
  label: string;
  status: "running" | "done" | "error";
  found?: number;
  totalSteps: number;
  currentStep: number;
  pagesDiscovered?: number;
}

interface ScanComplete {
  scanId: string;
  score: number;
  totalVulnerabilities: number;
  pagesScanned: number;
  critical: number;
  high: number;
  medium: number;
  low: number;
  info: number;
}

const stepIcons: Record<string, React.ElementType> = {
  crawl: Radar,
  ssl: Lock,
  "sensitive-files": FileWarning,
  email: Mail,
  robots: Bot,
  "error-pages": AlertTriangle,
  directories: FolderOpen,
  "api-probe": Globe,
  "http-methods": Network,
  sitemap: Map,
  waf: ShieldAlert,
  redirects: ArrowRightLeft,
  headers: ShieldCheck,
  cookies: Cookie,
  csp: Shield,
  html: Code2,
  "source-maps": FileCode,
  fingerprint: Fingerprint,
  saving: CheckCircle2,
};

const stepColors: Record<string, string> = {
  crawl: "text-blue-400",
  ssl: "text-emerald-400",
  "sensitive-files": "text-red-400",
  email: "text-yellow-400",
  robots: "text-purple-400",
  "error-pages": "text-orange-400",
  directories: "text-pink-400",
  "api-probe": "text-sky-400",
  "http-methods": "text-rose-400",
  sitemap: "text-lime-400",
  waf: "text-fuchsia-400",
  redirects: "text-slate-400",
  headers: "text-cyan-400",
  cookies: "text-amber-400",
  csp: "text-teal-400",
  html: "text-indigo-400",
  "source-maps": "text-orange-300",
  fingerprint: "text-violet-400",
  saving: "text-emerald-400",
};

interface ScanningOverlayProps {
  url: string;
  isOpen: boolean;
  onClose: () => void;
}

export default function ScanningOverlay({ url, isOpen, onClose }: ScanningOverlayProps) {
  const router = useRouter();
  const { data: session, status: authStatus } = useSession();
  const [progress, setProgress] = useState<ScanProgress[]>([]);
  const [currentStep, setCurrentStep] = useState<ScanProgress | null>(null);
  const [complete, setComplete] = useState<ScanComplete | null>(null);
  const [error, setError] = useState<string | null>(null);
  const [totalFound, setTotalFound] = useState(0);
  const [terminalLines, setTerminalLines] = useState<string[]>([]);
  const terminalRef = useRef<HTMLDivElement>(null);
  const hasStarted = useRef(false);
  const [verifiedLoggedIn, setVerifiedLoggedIn] = useState(false);

  // Verify the user actually exists in DB (handles stale JWT after DB reset)
  useEffect(() => {
    if (authStatus !== "authenticated") {
      setVerifiedLoggedIn(false);
      return;
    }
    fetch("/api/user/plan")
      .then((res) => res.json())
      .then((data) => {
        // If the API returns "anonymous" despite having a session, the user doesn't exist in DB
        setVerifiedLoggedIn(data.plan !== "anonymous");
      })
      .catch(() => setVerifiedLoggedIn(false));
  }, [authStatus]);

  const addTerminalLine = useCallback((line: string) => {
    setTerminalLines((prev) => [...prev.slice(-50), line]); // Keep last 50 lines
  }, []);

  useEffect(() => {
    if (!isOpen || hasStarted.current) return;
    hasStarted.current = true;

    const startScan = async () => {
      addTerminalLine(`$ securesaas scan --target ${url}`);
      addTerminalLine(`[init] SecureSaaS Scanner v2.0 — starting deep scan…`);
      addTerminalLine(`[init] Target: ${url}`);
      addTerminalLine("─".repeat(50));

      try {
        const res = await fetch("/api/scan/stream", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ url }),
        });

        if (!res.ok || !res.body) {
          try {
            const errData = await res.json();
            setError(errData.error || "Failed to start scan. Please try again.");
          } catch {
            setError("Failed to start scan. Please try again.");
          }
          addTerminalLine("[error] Connection failed");
          return;
        }

        const reader = res.body.getReader();
        const decoder = new TextDecoder();
        let buffer = "";

        while (true) {
          const { done, value } = await reader.read();
          if (done) break;

          buffer += decoder.decode(value, { stream: true });
          const lines = buffer.split("\n\n");
          buffer = lines.pop() || "";

          for (const chunk of lines) {
            const eventMatch = chunk.match(/^event: (.+)$/m);
            const dataMatch = chunk.match(/^data: (.+)$/m);
            if (!eventMatch || !dataMatch) continue;

            const event = eventMatch[1];
            const data = JSON.parse(dataMatch[1]);

            if (event === "scan-created") {
              addTerminalLine(`[scan] Scan ID: ${data.scanId}`);
            } else if (event === "progress") {
              const p = data as ScanProgress;
              setCurrentStep(p);

              if (p.status === "running") {
                addTerminalLine(`[${p.step}] ${p.label}`);
              } else if (p.status === "done") {
                if (p.found && p.found > 0) {
                  addTerminalLine(`[${p.step}] ⚠ ${p.found} issue(s) found`);
                  setTotalFound((prev) => prev + p.found!);
                } else {
                  addTerminalLine(`[${p.step}] ✓ ${p.label}`);
                }

                setProgress((prev) => {
                  const existing = prev.findIndex((x) => x.step === p.step);
                  if (existing >= 0) {
                    const updated = [...prev];
                    updated[existing] = p;
                    return updated;
                  }
                  return [...prev, p];
                });
              }
            } else if (event === "complete") {
              const c = data as ScanComplete;
              setComplete(c);
              addTerminalLine("─".repeat(50));
              addTerminalLine(`[done] Scan complete — Score: ${c.score}/100`);
              addTerminalLine(`[done] ${c.totalVulnerabilities} vulnerabilities found across ${c.pagesScanned} page(s)`);
              if (c.critical > 0) addTerminalLine(`[!!]   ${c.critical} CRITICAL`);
              if (c.high > 0) addTerminalLine(`[!]    ${c.high} HIGH`);
              if (c.medium > 0) addTerminalLine(`[~]    ${c.medium} MEDIUM`);
              if (c.low > 0) addTerminalLine(`[-]    ${c.low} LOW`);
              if (c.info > 0) addTerminalLine(`[i]    ${c.info} INFO`);
            } else if (event === "error") {
              setError(data.message);
              addTerminalLine(`[error] ${data.message}`);
            }
          }
        }
      } catch {
        setError("Connection lost. Please try again.");
        addTerminalLine("[error] Connection lost");
      }
    };

    startScan();
  }, [isOpen, url, addTerminalLine]);

  // Auto-scroll terminal
  useEffect(() => {
    if (terminalRef.current) {
      terminalRef.current.scrollTop = terminalRef.current.scrollHeight;
    }
  }, [terminalLines]);

  const percentComplete = currentStep
    ? Math.round((currentStep.currentStep / currentStep.totalSteps) * 100)
    : 0;

  if (!isOpen) return null;

  return (
    <AnimatePresence>
      <motion.div
        initial={{ opacity: 0 }}
        animate={{ opacity: 1 }}
        exit={{ opacity: 0 }}
        className="fixed inset-0 z-[100] flex items-center justify-center bg-gray-950/90 backdrop-blur-md p-4"
      >
        <motion.div
          initial={{ scale: 0.9, opacity: 0, y: 20 }}
          animate={{ scale: 1, opacity: 1, y: 0 }}
          transition={{ type: "spring", damping: 25, stiffness: 300 }}
          className="w-full max-w-3xl overflow-hidden rounded-3xl border border-gray-800 bg-gray-950 shadow-2xl"
        >
          {/* Header */}
          <div className="border-b border-gray-800 bg-gray-900/50 px-6 py-4">
            <div className="flex items-center justify-between">
              <div className="flex items-center gap-3">
                <div className="relative flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-500">
                  <Shield className="h-5 w-5 text-white" />
                  {!complete && !error && (
                    <motion.div
                      className="absolute inset-0 rounded-xl border-2 border-emerald-400"
                      animate={{ scale: [1, 1.3, 1], opacity: [1, 0, 1] }}
                      transition={{ duration: 2, repeat: Infinity }}
                    />
                  )}
                </div>
                <div>
                  <h2 className="font-semibold text-white">
                    {complete ? "Scan Complete" : error ? "Scan Failed" : "Scanning…"}
                  </h2>
                  <p className="text-sm text-gray-400 truncate max-w-md">{url}</p>
                </div>
              </div>

              {/* Score badge (when complete) */}
              {complete && (
                <motion.div
                  initial={{ scale: 0 }}
                  animate={{ scale: 1 }}
                  transition={{ type: "spring", delay: 0.3 }}
                  className={`flex h-14 w-14 items-center justify-center rounded-2xl font-bold text-xl ${
                    complete.score >= 80
                      ? "bg-emerald-500/20 text-emerald-400"
                      : complete.score >= 50
                        ? "bg-yellow-500/20 text-yellow-400"
                        : "bg-red-500/20 text-red-400"
                  }`}
                >
                  {complete.score}
                </motion.div>
              )}
            </div>
          </div>

          {/* Progress bar */}
          {!complete && !error && (
            <div className="px-6 pt-4">
              <div className="flex items-center justify-between mb-2">
                <span className="text-sm text-gray-400">
                  {currentStep?.label || "Initializing…"}
                </span>
                <span className="text-sm font-mono text-emerald-400">{percentComplete}%</span>
              </div>
              <div className="h-2 w-full overflow-hidden rounded-full bg-gray-800">
                <motion.div
                  className="h-full rounded-full bg-gradient-to-r from-emerald-500 to-cyan-500"
                  initial={{ width: "0%" }}
                  animate={{ width: `${percentComplete}%` }}
                  transition={{ duration: 0.5, ease: "easeOut" }}
                />
              </div>
            </div>
          )}

          {/* Check statuses grid */}
          <div className="grid grid-cols-4 gap-2 p-4 sm:grid-cols-4">
            {[
              { step: "crawl", label: "Crawl" },
              { step: "ssl", label: "SSL/TLS" },
              { step: "sensitive-files", label: "Files" },
              { step: "email", label: "Email" },
              { step: "robots", label: "Robots" },
              { step: "error-pages", label: "Errors" },
              { step: "directories", label: "Dirs" },
              { step: "api-probe", label: "APIs" },
              { step: "http-methods", label: "Methods" },
              { step: "sitemap", label: "Sitemap" },
              { step: "waf", label: "WAF" },
              { step: "redirects", label: "Redirects" },
              { step: "headers", label: "Headers" },
              { step: "cookies", label: "Cookies" },
              { step: "csp", label: "CSP" },
              { step: "html", label: "HTML" },
              { step: "source-maps", label: "Src Maps" },
              { step: "fingerprint", label: "Tech" },
            ].map((item) => {
              const done = progress.find((p) => p.step === item.step);
              const isRunning = currentStep?.step === item.step && currentStep.status === "running";
              const Icon = stepIcons[item.step] || Shield;
              const color = stepColors[item.step] || "text-gray-400";

              return (
                <motion.div
                  key={item.step}
                  initial={{ opacity: 0, scale: 0.8 }}
                  animate={{ opacity: 1, scale: 1 }}
                  className={`flex items-center gap-2 rounded-xl border px-3 py-2 text-xs transition-all ${
                    done
                      ? done.found && done.found > 0
                        ? "border-yellow-500/30 bg-yellow-500/10"
                        : "border-emerald-500/30 bg-emerald-500/10"
                      : isRunning
                        ? "border-cyan-500/50 bg-cyan-500/10"
                        : "border-gray-800 bg-gray-900/50"
                  }`}
                >
                  {isRunning ? (
                    <Loader2 className={`h-3.5 w-3.5 animate-spin ${color}`} />
                  ) : done ? (
                    done.found && done.found > 0 ? (
                      <AlertTriangle className="h-3.5 w-3.5 text-yellow-400" />
                    ) : (
                      <CheckCircle2 className="h-3.5 w-3.5 text-emerald-400" />
                    )
                  ) : (
                    <Icon className="h-3.5 w-3.5 text-gray-600" />
                  )}
                  <span
                    className={
                      done
                        ? "text-gray-200"
                        : isRunning
                          ? "text-cyan-300"
                          : "text-gray-600"
                    }
                  >
                    {item.label}
                  </span>
                  {done?.found !== undefined && done.found > 0 && (
                    <span className="ml-auto rounded-full bg-yellow-500/20 px-1.5 text-[10px] font-bold text-yellow-400">
                      {done.found}
                    </span>
                  )}
                </motion.div>
              );
            })}
          </div>

          {/* Terminal output */}
          <div className="mx-4 mb-4 overflow-hidden rounded-xl border border-gray-800 bg-gray-950">
            <div className="flex items-center gap-2 border-b border-gray-800 bg-gray-900/80 px-4 py-2">
              <div className="h-3 w-3 rounded-full bg-red-500/80" />
              <div className="h-3 w-3 rounded-full bg-yellow-500/80" />
              <div className="h-3 w-3 rounded-full bg-green-500/80" />
              <span className="ml-2 text-xs text-gray-500 font-mono">securesaas — scan output</span>
            </div>
            <div
              ref={terminalRef}
              className="h-48 overflow-y-auto p-4 font-mono text-xs leading-relaxed scrollbar-thin"
            >
              {terminalLines.map((line, i) => (
                <motion.div
                  key={i}
                  initial={{ opacity: 0, x: -10 }}
                  animate={{ opacity: 1, x: 0 }}
                  transition={{ duration: 0.15 }}
                  className={
                    line.startsWith("[error]")
                      ? "text-red-400"
                      : line.startsWith("[done]") || line.startsWith("[scan]")
                        ? "text-emerald-400"
                        : line.startsWith("[!!]")
                          ? "text-red-400 font-bold"
                          : line.startsWith("[!]")
                            ? "text-orange-400"
                            : line.startsWith("[~]")
                              ? "text-yellow-400"
                              : line.includes("⚠")
                                ? "text-yellow-300"
                                : line.includes("✓")
                                  ? "text-emerald-300"
                                  : line.startsWith("$")
                                    ? "text-cyan-400"
                                    : line.startsWith("─")
                                      ? "text-gray-700"
                                      : "text-gray-400"
                  }
                >
                  {line}
                </motion.div>
              ))}
              {!complete && !error && (
                <motion.span
                  animate={{ opacity: [1, 0, 1] }}
                  transition={{ duration: 0.8, repeat: Infinity }}
                  className="inline-block text-emerald-400"
                >
                  ▋
                </motion.span>
              )}
            </div>
          </div>

          {/* Stats footer */}
          {!complete && !error && (
            <div className="flex items-center justify-between border-t border-gray-800 px-6 py-3">
              <div className="flex gap-4 text-xs text-gray-500">
                <span>Steps: {currentStep?.currentStep || 0}/{currentStep?.totalSteps || 16}</span>
                <span>Issues: {totalFound}</span>
              </div>
              <div className="flex items-center gap-2 text-xs text-gray-500">
                <div className="h-2 w-2 animate-pulse rounded-full bg-emerald-500" />
                Scanning…
              </div>
            </div>
          )}

          {/* Complete summary */}
          {complete && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="border-t border-gray-800 px-6 py-4"
            >
              <div className="mb-4 flex flex-wrap items-center gap-3">
                {complete.critical > 0 && (
                  <span className="rounded-full bg-red-500/20 px-3 py-1 text-sm font-medium text-red-400">
                    {complete.critical} Critical
                  </span>
                )}
                {complete.high > 0 && (
                  <span className="rounded-full bg-orange-500/20 px-3 py-1 text-sm font-medium text-orange-400">
                    {complete.high} High
                  </span>
                )}
                {complete.medium > 0 && (
                  <span className="rounded-full bg-yellow-500/20 px-3 py-1 text-sm font-medium text-yellow-400">
                    {complete.medium} Medium
                  </span>
                )}
                {complete.low > 0 && (
                  <span className="rounded-full bg-blue-500/20 px-3 py-1 text-sm font-medium text-blue-400">
                    {complete.low} Low
                  </span>
                )}
                {complete.info > 0 && (
                  <span className="rounded-full bg-gray-500/20 px-3 py-1 text-sm font-medium text-gray-400">
                    {complete.info} Info
                  </span>
                )}
              </div>

              {verifiedLoggedIn ? (
                <button
                  onClick={() => router.push(`/scan/${complete.scanId}`)}
                  className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
                >
                  View Full Report
                  <ArrowRight className="h-4 w-4" />
                </button>
              ) : (
                <div className="space-y-3">
                  <div className="rounded-xl border border-amber-500/20 bg-amber-500/5 p-3 text-center">
                    <p className="text-sm text-amber-300">
                      Create a free account to view your full security report with detailed findings.
                    </p>
                  </div>
                  <button
                    onClick={() => {
                      // Store scan ID so we can redirect after registration
                      if (typeof window !== "undefined") {
                        sessionStorage.setItem("pendingScanId", complete.scanId);
                      }
                      router.push("/register");
                    }}
                    className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
                  >
                    <UserPlus className="h-4 w-4" />
                    Sign Up Free to View Report
                  </button>
                  <button
                    onClick={() => {
                      if (typeof window !== "undefined") {
                        sessionStorage.setItem("pendingScanId", complete.scanId);
                      }
                      router.push("/login");
                    }}
                    className="flex w-full items-center justify-center gap-2 rounded-xl border border-gray-700 px-6 py-3 text-sm text-gray-400 transition hover:bg-gray-800 hover:text-white"
                  >
                    Already have an account? Log in
                  </button>
                </div>
              )}
            </motion.div>
          )}

          {/* Error state */}
          {error && (
            <motion.div
              initial={{ opacity: 0, y: 10 }}
              animate={{ opacity: 1, y: 0 }}
              className="border-t border-gray-800 px-6 py-4"
            >
              <div className="mb-4 flex items-center gap-3 text-red-400">
                <XCircle className="h-5 w-5" />
                <span className="text-sm">{error}</span>
              </div>
              <button
                onClick={onClose}
                className="flex w-full items-center justify-center gap-2 rounded-xl border border-gray-700 px-6 py-3 font-medium text-gray-300 transition hover:bg-gray-800"
              >
                Close
              </button>
            </motion.div>
          )}
        </motion.div>
      </motion.div>
    </AnimatePresence>
  );
}
