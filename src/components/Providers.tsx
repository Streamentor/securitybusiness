"use client";

import { SessionProvider } from "next-auth/react";
import { useEffect } from "react";
import { captureAttribution } from "@/lib/attribution";

export default function Providers({ children }: { children: React.ReactNode }) {
  useEffect(() => {
    try {
      captureAttribution(window.location.href, document.referrer, sessionStorage);
    } catch {
      // Privacy settings can disable storage; the product must still work.
    }
  }, []);
  return <SessionProvider>{children}</SessionProvider>;
}
