"use client";

import { useEffect, useState } from "react";
import { useSearchParams } from "next/navigation";
import Link from "next/link";
import { motion } from "framer-motion";
import { CheckCircle2, Shield, ArrowRight, Loader2 } from "lucide-react";
import { Suspense } from "react";

function SuccessContent() {
  const searchParams = useSearchParams();
  const sessionId = searchParams.get("session_id");
  const [loading, setLoading] = useState(true);

  useEffect(() => {
    // Brief delay to let the webhook process
    const timer = setTimeout(() => setLoading(false), 2000);
    return () => clearTimeout(timer);
  }, []);

  if (loading) {
    return (
      <div className="flex min-h-screen items-center justify-center">
        <div className="text-center">
          <Loader2 className="mx-auto h-12 w-12 animate-spin text-emerald-400" />
          <p className="mt-4 text-lg text-gray-400">Setting up your account...</p>
        </div>
      </div>
    );
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <motion.div
        initial={{ opacity: 0, scale: 0.95 }}
        animate={{ opacity: 1, scale: 1 }}
        className="mx-auto max-w-md text-center"
      >
        <div className="mx-auto mb-6 flex h-20 w-20 items-center justify-center rounded-full bg-emerald-500/10">
          <CheckCircle2 className="h-10 w-10 text-emerald-400" />
        </div>

        <h1 className="text-3xl font-bold">Welcome to the team! 🎉</h1>
        <p className="mt-3 text-gray-400">
          Your subscription is active and your credits have been loaded.
          Start scanning to find and fix security vulnerabilities.
        </p>

        {sessionId && (
          <p className="mt-2 text-xs text-gray-600">
            Session: {sessionId.slice(0, 20)}...
          </p>
        )}

        <div className="mt-8 flex flex-col gap-3 sm:flex-row sm:justify-center">
          <Link
            href="/dashboard"
            className="flex items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 px-6 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600"
          >
            Go to Dashboard
            <ArrowRight className="h-4 w-4" />
          </Link>
          <Link
            href="/pricing"
            className="flex items-center justify-center gap-2 rounded-xl border border-gray-700 px-6 py-3 font-medium text-white transition hover:bg-gray-800"
          >
            View Plan Details
          </Link>
        </div>
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
