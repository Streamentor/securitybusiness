"use client";

import {useEffect, useRef} from "react";
import Link from "next/link";
import {ArrowUpRight, Clock3, LogIn, X, Zap} from "lucide-react";
import {authPageHref, type ScanLimit} from "@/lib/scan-journey";

export function ScanLimitDialog({limit, signedIn, onClose, returnTo = "/free-website-vulnerability-scanner#scan"}: {limit: ScanLimit; signedIn: boolean; onClose: () => void; returnTo?: string}) {
  const dialog = useRef<HTMLDialogElement>(null);
  useEffect(() => {const element = dialog.current; element?.showModal(); return () => element?.close();}, []);
  return <dialog ref={dialog} onCancel={onClose} aria-labelledby="scan-limit-title" aria-describedby="scan-limit-description" className="m-auto max-h-[calc(100dvh-2rem)] w-[calc(100%_-_2rem)] max-w-lg overflow-y-auto rounded-2xl border border-[#ff6b6b]/30 bg-[#0d1118] p-5 text-white shadow-2xl backdrop:bg-black/80 sm:p-7">
    <div className="flex items-start justify-between gap-4"><span className="flex h-11 w-11 items-center justify-center rounded-xl bg-amber-400/10 text-amber-200">{limit.rateLimited ? <Clock3 className="h-5 w-5" /> : <Zap className="h-5 w-5" />}</span><button type="button" onClick={onClose} aria-label="Close scan limit dialog" className="rounded-lg p-2 text-[#98a2b3] hover:bg-white/10 hover:text-white"><X className="h-5 w-5" /></button></div>
    <h2 id="scan-limit-title" className="mt-5 text-2xl font-semibold tracking-tight">{limit.rateLimited ? "You've reached the hourly scan limit." : "Ready to keep scanning?"}</h2>
    <p id="scan-limit-description" className="mt-3 text-sm leading-6 text-[#b7c0cd]">{limit.message}</p>
    <p className="mt-4 text-sm leading-6 text-[#98a2b3]">{limit.rateLimited ? `${limit.retryMinutes ? `Try again in about ${limit.retryMinutes} minutes. ` : "Try again later. "}Upgrading does not remove this hourly safety limit.` : "Starter and Pro add monthly scan credits, available fixes across your report, private repository scans and AI code review."}</p>
    {limit.rateLimited && <button type="button" onClick={onClose} className="button-primary mt-6 w-full">Back to {returnTo.startsWith("/scan/") ? "report" : "scanner"}</button>}
    {!signedIn && <Link href={authPageHref("login", {redirect: returnTo})} className={`${limit.rateLimited ? "button-secondary" : "button-primary"} mt-4 w-full`} onClick={onClose}><LogIn className="h-4 w-4" /> Sign in to check your scan allowance</Link>}
    <Link href="/pricing#paid-plans" className={`${!limit.rateLimited && signedIn ? "button-primary" : "button-secondary"} mt-3 w-full`} onClick={onClose}>View paid scan plans <ArrowUpRight className="h-4 w-4" /></Link>
    {!signedIn && <Link href={authPageHref("register", {redirect: returnTo})} className="mt-4 block text-center text-sm text-[#aeb8c5] underline underline-offset-4" onClick={onClose}>Create a free account</Link>}
  </dialog>;
}
