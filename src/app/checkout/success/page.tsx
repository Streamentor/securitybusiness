"use client";

import { useEffect } from "react";
import { useSearchParams } from "next/navigation";
import { Loader2 } from "lucide-react";
import { Suspense } from "react";

function SuccessContent() {
  const searchParams = useSearchParams();
  const sessionId = searchParams.get("session_id");
  useEffect(() => {
    async function activate() {
      if (!sessionId) {
        window.location.href = "/dashboard";
        return;
      }
      try {
        await fetch("/api/stripe/verify", {
          method: "POST",
          headers: { "Content-Type": "application/json" },
          body: JSON.stringify({ sessionId }),
        });
      } catch {
        // The webhook can still complete activation if this request fails.
      }
      window.location.href = "/dashboard";
    }
    activate();
  }, [sessionId]);

  return (
    <div className="flex min-h-screen items-center justify-center">
      <div className="text-center">
        <Loader2 className="mx-auto h-10 w-10 animate-spin text-[var(--signal)]" />
        <p className="mt-4 text-sm text-[#8f99a7]">Activating your subscription…</p>
      </div>
    </div>
  );
}

export default function CheckoutSuccessPage() {
  return (
    <Suspense
      fallback={
        <div className="flex min-h-screen items-center justify-center">
          <Loader2 className="h-10 w-10 animate-spin text-[var(--signal)]" />
        </div>
      }
    >
      <SuccessContent />
    </Suspense>
  );
}
