"use client";

import { Suspense, useEffect, useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { Github, Loader2, Lock, Mail, User } from "lucide-react";
import { authPageHref, authReturnHref, validPendingPlan } from "@/lib/scan-journey";
import { validPendingScanId, safeAuthRedirect } from "@/lib/scan-auth-return";
import { AuthFrame } from "@/components/AuthFrame";

function GoogleMark() {
  return <svg className="h-5 w-5" viewBox="0 0 24 24" aria-hidden><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09A6.6 6.6 0 0 1 5.49 12c0-.73.13-1.43.35-2.09V7.07H2.18A11 11 0 0 0 1 12c0 1.78.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>;
}

function writeSignupCookie(data: object) {
  document.cookie = `signup_referrer=${encodeURIComponent(JSON.stringify(data))};path=/;max-age=600;SameSite=Lax`;
}

function RegisterForm() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [emailUpdates, setEmailUpdates] = useState(false);
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [providerLoading, setProviderLoading] = useState<string | null>(null);
  useEffect(() => { try { localStorage.removeItem("pendingPlan"); } catch {} }, []);
  const router = useRouter();
  const searchParams = useSearchParams();

  function storeReferrerCookie() {
    const data = { pendingScanId: pendingScan(), emailUpdates, referrerUrl: sessionStorage.getItem("referrer_url") || "", utmSource: sessionStorage.getItem("utm_source") || "", utmMedium: sessionStorage.getItem("utm_medium") || "", utmCampaign: sessionStorage.getItem("utm_campaign") || "" };
    writeSignupCookie(data);
  }

  const selectedPlan = validPendingPlan(searchParams.get("plan"));
  const selectedFinding = validPendingScanId(searchParams.get("finding"));
  const scanId = validPendingScanId(searchParams.get("scan"));
  const returnTo = safeAuthRedirect(searchParams.get("redirect"));
  const switchHref = authPageHref("login", {scanId, finding: selectedFinding, plan: selectedPlan, redirect: returnTo});
  function pendingScan() {
    if (scanId) sessionStorage.setItem("pendingScanId", scanId);
    return scanId;
  }
  function callbackUrl() {
    return authReturnHref(pendingScan(), selectedFinding, selectedPlan, returnTo);
  }

  async function handleProvider(provider: "google" | "github") {
    setProviderLoading(provider);
    storeReferrerCookie();
    await signIn(provider, { callbackUrl: callbackUrl() });
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setLoading(true);
    const payload = { pendingScanId: pendingScan(), name, email, password, emailUpdates, referrerUrl: sessionStorage.getItem("referrer_url") || "", utmSource: sessionStorage.getItem("utm_source") || "", utmMedium: sessionStorage.getItem("utm_medium") || "", utmCampaign: sessionStorage.getItem("utm_campaign") || "" };
    try {
      const response = await fetch("/api/register", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify(payload) });
      const data = await response.json();
      if (!response.ok) { setError(data.error || "Account could not be created."); setLoading(false); return; }
      const loginHref = authPageHref("login", {scanId, finding: selectedFinding, plan: selectedPlan, redirect: returnTo});
      router.push(`${loginHref}${loginHref.includes("?") ? "&" : "?"}registered=true`);
    } catch {
      setError("Something went wrong. Please try again.");
      setLoading(false);
    }
  }

  return (
    <AuthFrame title={selectedPlan ? `Continue with ${selectedPlan === "starter" ? "Starter" : "Pro"}` : "Create your free account"} subtitle={selectedPlan ? "Create an account to review your selected plan before checkout. No payment is made when you register." : scanId ? "Open every affected page and finding description in your saved report. One available fix is included." : "Save your scans and review the findings. No card needed."}>
      {scanId && <Link href={authReturnHref(scanId, selectedFinding, null, "/dashboard")} className="mb-4 inline-block text-sm text-[#aeb8c5] underline">Back to your report</Link>}
      {error && <div className="mb-3 rounded-xl border border-[#ff6b6b]/20 bg-[#ff6b6b]/[0.07] px-4 py-3 text-sm text-[#ff9696]">{error}</div>}
      <label className="mb-4 flex items-start gap-2 text-sm text-[#98a2b3]"><input type="checkbox" checked={emailUpdates} onChange={e => setEmailUpdates(e.target.checked)} className="mt-1" /><span>Email me about my scans and ScanMySaaS. Optional. Unsubscribe anytime.</span></label>
      <div className="space-y-3">
        <button onClick={() => handleProvider("google")} disabled={Boolean(providerLoading)} className="button-secondary w-full"><GoogleMark />{providerLoading === "google" ? <Loader2 className="h-4 w-4 animate-spin" /> : "Continue with Google"}</button>
        <button onClick={() => handleProvider("github")} disabled={Boolean(providerLoading)} className="button-secondary w-full"><Github className="h-5 w-5" />{providerLoading === "github" ? <Loader2 className="h-4 w-4 animate-spin" /> : "Continue with GitHub"}</button>
      </div>
      <div className="my-6 flex items-center gap-3 text-[0.68rem] uppercase tracking-[.14em] text-[#5f6978]"><span className="h-px flex-1 bg-white/[0.08]" />or use email<span className="h-px flex-1 bg-white/[0.08]" /></div>
      <form onSubmit={handleSubmit} className="space-y-4">
        <label className="block text-sm font-medium text-[#c5ccd5]">Name<div className="input-shell mt-2 flex items-center gap-3 rounded-xl px-3.5"><User className="h-4 w-4 text-[#667180]" /><input value={name} onChange={(event) => setName(event.target.value)} required autoComplete="name" placeholder="Your name" className="w-full bg-transparent py-3.5 text-sm text-white placeholder:text-[#586372] focus:outline-none" /></div></label>
        <label className="block text-sm font-medium text-[#c5ccd5]">Email<div className="input-shell mt-2 flex items-center gap-3 rounded-xl px-3.5"><Mail className="h-4 w-4 text-[#667180]" /><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required autoComplete="email" placeholder="you@company.com" className="w-full bg-transparent py-3.5 text-sm text-white placeholder:text-[#586372] focus:outline-none" /></div></label>
        <label className="block text-sm font-medium text-[#c5ccd5]">Password<div className="input-shell mt-2 flex items-center gap-3 rounded-xl px-3.5"><Lock className="h-4 w-4 text-[#667180]" /><input type="password" minLength={8} value={password} onChange={(event) => setPassword(event.target.value)} required autoComplete="new-password" placeholder="At least 8 characters" className="w-full bg-transparent py-3.5 text-sm text-white placeholder:text-[#586372] focus:outline-none" /></div></label>
        <button type="submit" disabled={loading} className="button-primary w-full">{loading ? <Loader2 className="h-4 w-4 animate-spin" /> : selectedPlan ? `Create account and continue to ${selectedPlan === "starter" ? "Starter" : "Pro"}` : "Create free account"}</button>
      </form>
      <p className="mt-3 text-xs text-[#98a2b3]">If you opt in, we&apos;ll email you about your scans and ScanMySaaS. Unsubscribe anytime. <Link href="/privacy" className="underline">Privacy</Link>.</p>
      <p className="mt-4 text-center text-xs leading-5 text-[#667180]">By continuing, you agree to the <Link href="/terms" className="underline hover:text-white">Terms</Link> and <Link href="/privacy" className="underline hover:text-white">Privacy Policy</Link>.</p>
      <p className="mt-5 text-center text-sm text-[#7f8998]">Already have an account? <Link href={switchHref} onClick={pendingScan} className="font-medium text-white hover:text-[var(--signal)]">Sign in</Link></p>
    </AuthFrame>
  );
}

export default function RegisterPage() { return <Suspense fallback={<div className="p-8 text-center">Loading account form...</div>}><RegisterForm /></Suspense>; }
