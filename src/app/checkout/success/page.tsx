"use client";

import { useEffect, useState, useCallback } from "react";
import { useSearchParams, useRouter } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";
import {
  CheckCircle2,
  Shield,
  ArrowRight,
  Loader2,
  Zap,
  ShieldCheck,
  AlertTriangle,
} from "lucide-react";
import { Suspense } from "react";

function SuccessContent() {
  const searchParams = useSearchParams();
  const router = useRouter();
  const sessionId = searchParams.get("session_id");
  const [status, setStatus] = useState<"verifying" | "active" | "timeout">("verifying");
  const [plan, setPlan] = useState<string>("");
  const [credits, setCredits] = useState<number>(0);

  const pollPlan = useCallback(async () => {
    const maxAttempts = 15;
    let attempt = 0;

    while (attempt < maxAttempts) {
      attempt++;
      try {
        const res = await fetch("/api/user/plan");
        if (res.ok) {
          const data = await res.json();
          if (data.plan === "starter" || data.plan === "pro") {
            setPlan(data.plan);
            setCredits(data.credits);
            setStatus("active");
            return;
          }
        }
      } catch {
        // Retry
      }
      // Wait 2 seconds between polls
      await new Promise((r) => setTimeout(r, 2000));
    }
    // Timed out — webhook may be slow
    setStatus("timeout");
  }, []);

  useEffect(() => {
    pollPlan();
  }, [pollPlan]);

  if (status === "verifying") {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Loader2 className="mx-auto h-12 w-12 animate-spin text-emerald-400" />
          <p className="mt-4 text-lg text-gray-400">Activating your subscription...</p>
          <p className="mt-2 text-sm text-gray-600">This usually takes a few seconds</p>
        </div>
      </div>
    );
  }

  if (status === "timeout") {
    return (
      <div className="flex min-h-screen items-center justify-center px-4">
        <motion.div
          initial={{ opacity: 0, scale: 0.95 }}
          animate={{ opacity: 1, scale: 1 }}
          className="mx-auto max-w-md text-center"
        >
          <div className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-amber-500/10">
            <AlertTriangle className="h-10 w-10 text-amber-400" />
          </div>
          <h1 className="text-2xl font-bold">Almost there!</h1>
          <p className="mt-3 text-gray-400">
            Your payment was received but the subscription is still being set up. This can take a minute.
            Please check your dashboard shortly — your plan will be updated automatically.
          </p>
          {sessionId && (
            <p className="mt-2 text-xs text-gray-600">
              Session: {sessionId.slice(0, 20)}...
            </p>
          )}
          <div className="mt-8">
            <Link
              href="/dashboard"
              className="inline-flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
            >
              Go to Dashboard
              <ArrowRight className="h-4 w-4" />
            </Link>
          </div>
        </motion.div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="mx-auto max-w-lg text-center"
      >
        <motion.div
          initial={{ scale: 0 }}
          animate={{ scale: 1 }}
          transition={{ type: "spring", stiffness: 200, delay: 0.1 }}
          className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-emerald-500/10"
        >
          <CheckCircle2 className="h-10 w-10 text-emerald-400" />
        </motion.div>

        <h1 className="text-3xl font-bold">You&apos;re all set! 🎉</h1>
        <p className="mt-3 text-gray-400">
          Your <span className="font-semibold capitalize text-white">{plan}</span> plan is now active.
        </p>

        {/* Plan summary card */}
        <div className="mt-6 rounded-xl border border-emerald-500/20 bg-emerald-500/5 p-6 text-left">
          <div className="flex items-center gap-3 mb-4">
            <div className="flex h-10 w-10 items-center justify-center rounded-lg bg-gradient-to-br from-emerald-500 to-cyan-500">
              <ShieldCheck className="h-5 w-5 text-white" />
            </div>
            <div>
              <div className="font-semibold text-white capitalize">{plan} Plan</div>
              <div className="text-sm text-gray-400">Subscription active</div>
            </div>
          </div>
          <div className="space-y-2 text-sm">
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Scan credits loaded</span>
              <span className="flex items-center gap-1 font-semibold text-amber-400">
                <Zap className="h-3.5 w-3.5" />
                {credits}
              </span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Fix suggestions</span>
              <span className="font-semibold text-emerald-400">✓ Unlocked</span>
            </div>
            <div className="flex items-center justify-between">
              <span className="text-gray-400">Priority scanning</span>
              <span className="font-semibold text-emerald-400">✓ Enabled</span>
            </div>
          </div>
        </div>

        <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-center">
          <Link
            href="/dashboard"
            className="flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
          >
            Start Scanning
            <ArrowRight className="h-4 w-4" />
          </Link>
          <Link
            href="/"
            className="flex items-center justify-center gap-2 rounded-xl border border-gray-700 px-6 py-3 font-medium text-white transition hover:bg-gray-800"
          >
            Run a Scan Now
          </Link>
        </div>

        {sessionId && (
          <p className="mt-6 text-xs text-gray-600">
            Session: {sessionId.slice(0, 20)}...
          </p>
        )}
      </motion.div>
    </div>
  );
}

export default function CheckoutSuccessPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center">
          <Loader2 className="h-12 w-12 animate-spin text-emerald-400" />
        </div>
      }
    >
      <SuccessContent />
    </Suspense>
  );
}
