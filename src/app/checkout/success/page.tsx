"use client";

import { useEffect, useState, useCallback } from "react";
import { useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";
import { Suspense } from "react";

function SuccessContent() {
  const searchParams = useSearchParams();
  const sessionId = searchParams.get("session_id");
  const [message, setMessage] = useState("Activating your subscription...");

  const activate = useCallback(async () => {
    if (!sessionId) {
      window.location.href = "/dashboard";
      return;
    }

    // Step 1: Call verify endpoint to activate the subscription directly
    try {
      setMessage("Activating your subscription...");
      await fetch("/api/stripe/verify", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ sessionId }),
      });
    } catch {
      // Even if verify fails, redirect — webhook may handle it
    }

    // Step 2: Hard redirect to dashboard (ensures fresh session load)
    setMessage("Redirecting to your dashboard...");
    await new Promise((r) => setTimeout(r, 500));
    window.location.href = "/dashboard";
  }, [sessionId]);

  useEffect(() => {
    activate();
  }, [activate]);

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center">
        <Loader2 className="mx-auto h-12 w-12 animate-spin text-emerald-400" />
        <p className="mt-4 text-lg text-gray-400">{message}</p>
      </div>
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
