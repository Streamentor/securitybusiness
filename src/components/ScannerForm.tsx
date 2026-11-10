"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import {validPendingScanId} from "@/lib/scan-auth-return";
import { Globe2, Search } from "lucide-react";
import ScanningOverlay from "@/components/ScanningOverlay";

export function ScannerForm({ compact = false }: { compact?: boolean }) {
  const [lastReport, setLastReport] = useState<string | null>(null);
  const [url, setUrl] = useState("");
  const [scanUrl, setScanUrl] = useState("");
  const [scanning, setScanning] = useState(false);

  useEffect(() => {
    const frame = requestAnimationFrame(() => {
    const target = new URLSearchParams(window.location.search).get("url");
    if (target && target.length <= 2048 && /^https?:\/\//i.test(target)) setUrl(target);
    try { setLastReport(validPendingScanId(sessionStorage.getItem("lastScanId") || sessionStorage.getItem("pendingScanId"))); } catch {}
    });
    return () => cancelAnimationFrame(frame);
  }, []);

  function startScan(event: React.FormEvent) {
    event.preventDefault();
    if (!url.trim()) return;
    const normalized = /^https?:\/\//i.test(url.trim()) ? url.trim() : `https://${url.trim()}`;
    setScanUrl(normalized);
    setScanning(true);
  }

  return (
    <>
      <p className="mb-3 text-xs leading-5 text-[#98a2b3]">Free scan, no card. Free account to see the full report. One fix included.</p>
      <form id={compact ? undefined : "scan"} data-scan-target onSubmit={startScan} className={`input-shell signal-shadow flex w-full gap-2 rounded-2xl p-2 ${compact ? "max-w-2xl" : "max-w-xl"}`}>
        <label className="flex min-w-0 flex-1 items-center gap-3 px-3" aria-label="Website URL">
          <Globe2 className="h-5 w-5 shrink-0 text-[#778191]" />
          <input value={url} onChange={(event) => setUrl(event.target.value)} placeholder="yourapp.com" className="min-w-0 flex-1 bg-transparent py-3 text-base text-white placeholder:text-[#657080] focus:outline-none" inputMode="url" autoCapitalize="none" autoCorrect="off" />
        </label>
        <button type="submit" disabled={!url.trim() || scanning} className="button-primary shrink-0 px-4 sm:px-6">
          <Search className="h-4 w-4" /> <span className="hidden sm:inline">Scan website</span><span className="sm:hidden">Scan</span>
        </button>
      </form>
      {lastReport && <Link href={`/scan/${lastReport}`} className="mt-3 inline-block text-sm text-[var(--signal)] underline underline-offset-4">Open your last report</Link>}
      <ScanningOverlay url={scanUrl} isOpen={scanning} onClose={() => { setScanning(false); setScanUrl(""); try { setLastReport(validPendingScanId(sessionStorage.getItem("lastScanId"))); } catch {} }} />
    </>
  );
}
