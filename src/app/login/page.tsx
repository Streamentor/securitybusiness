"use client";

import { Suspense, useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { CheckCircle2, Github, Loader2, Lock, Mail } from "lucide-react";
import { pendingScanFrom, safeAuthRedirect } from "@/lib/scan-auth-return";
import { AuthFrame } from "@/components/AuthFrame";

function GoogleMark() {
  return <svg className="h-5 w-5" viewBox="0 0 24 24" aria-hidden><path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/><path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/><path d="M5.84 14.09A6.6 6.6 0 0 1 5.49 12c0-.73.13-1.43.35-2.09V7.07H2.18A11 11 0 0 0 1 12c0 1.78.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/><path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/></svg>;
}

function LoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [providerLoading, setProviderLoading] = useState<string | null>(null);
  const router = useRouter();
  const searchParams = useSearchParams();
  const registered = searchParams.get("registered");
  const redirectTo = searchParams.get("redirect");
  const authError = searchParams.get("error");
  const authErrorMessage = authError ? authError === "OAuthAccountNotLinked" ? "This email is already linked to another sign-in method." : "Sign-in failed. Please try again." : null;

  function pendingScan() {
    const id = pendingScanFrom(window.location.search, sessionStorage.getItem("pendingScanId"));
    if (id) sessionStorage.setItem("pendingScanId", id);
    return id;
  }
  function callbackUrl() {
    const pendingScanId = pendingScan();
    if (pendingScanId) return `/scan/${pendingScanId}`;
    const pendingPlan = localStorage.getItem("pendingPlan");
    if (pendingPlan) return `/pricing?checkout=${pendingPlan}`;
    return safeAuthRedirect(redirectTo);
  }

  async function handleProvider(provider: "google" | "github") {
    setProviderLoading(provider);
    await signIn(provider, { callbackUrl: callbackUrl() });
  }

  async function handleSubmit(event: React.FormEvent) {
    event.preventDefault();
    setError("");
    setLoading(true);
    try {
      const result = await signIn("credentials", { email, password, redirect: false });
      if (result?.error) {
        setError("The email or password is incorrect.");
        setLoading(false);
        return;
      }
      const pendingPlan = localStorage.getItem("pendingPlan");
      const pendingScanId = pendingScan();
      if (pendingPlan) {
        localStorage.removeItem("pendingPlan");
        if (pendingScanId) {
          const claimed = await fetch("/api/scan/claim", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scanId: pendingScanId }) }).catch(() => null);
          if (claimed?.ok) sessionStorage.removeItem("pendingScanId");
        }
        const response = await fetch("/api/stripe/checkout", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ plan: pendingPlan }) });
        const data = await response.json();
        if (data.url) { window.location.href = data.url; return; }
      }
      if (pendingScanId) {
        const claimed = await fetch("/api/scan/claim", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ scanId: pendingScanId }) }).catch(() => null);
        if (claimed?.ok) sessionStorage.removeItem("pendingScanId");
        router.push(`/scan/${pendingScanId}`);
      } else router.push(safeAuthRedirect(redirectTo));
      router.refresh();
    } catch {
      setError("Something went wrong. Please try again.");
      setLoading(false);
    }
  }

  return (
    <AuthFrame title="Welcome back" subtitle="Sign in to open your scan history, remaining credits, and remediation guides.">
      <div className="space-y-3">
        {registered && <div className="flex items-center gap-2 rounded-xl border border-[var(--signal)]/20 bg-[var(--signal)]/[0.06] px-4 py-3 text-sm text-[var(--signal)]"><CheckCircle2 className="h-4 w-4" /> Account created. Sign in to continue.</div>}
        {(error || authErrorMessage) && <div className="rounded-xl border border-[#ff6b6b]/20 bg-[#ff6b6b]/[0.07] px-4 py-3 text-sm text-[#ff9696]">{error || authErrorMessage}</div>}
        <button onClick={() => handleProvider("google")} disabled={Boolean(providerLoading)} className="button-secondary w-full"><GoogleMark />{providerLoading === "google" ? <Loader2 className="h-4 w-4 animate-spin" /> : "Continue with Google"}</button>
        <button onClick={() => handleProvider("github")} disabled={Boolean(providerLoading)} className="button-secondary w-full"><Github className="h-5 w-5" />{providerLoading === "github" ? <Loader2 className="h-4 w-4 animate-spin" /> : "Continue with GitHub"}</button>
      </div>
      <div className="my-6 flex items-center gap-3 text-[0.68rem] uppercase tracking-[.14em] text-[#5f6978]"><span className="h-px flex-1 bg-white/[0.08]" />or use email<span className="h-px flex-1 bg-white/[0.08]" /></div>
      <form onSubmit={handleSubmit} className="space-y-4">
        <label className="block text-sm font-medium text-[#c5ccd5]">Email<div className="input-shell mt-2 flex items-center gap-3 rounded-xl px-3.5"><Mail className="h-4 w-4 text-[#667180]" /><input type="email" value={email} onChange={(event) => setEmail(event.target.value)} required autoComplete="email" placeholder="you@company.com" className="w-full bg-transparent py-3.5 text-sm text-white placeholder:text-[#586372] focus:outline-none" /></div></label>
        <label className="block text-sm font-medium text-[#c5ccd5]">Password<div className="input-shell mt-2 flex items-center gap-3 rounded-xl px-3.5"><Lock className="h-4 w-4 text-[#667180]" /><input type="password" value={password} onChange={(event) => setPassword(event.target.value)} required autoComplete="current-password" placeholder="Your password" className="w-full bg-transparent py-3.5 text-sm text-white placeholder:text-[#586372] focus:outline-none" /></div></label>
        <button type="submit" disabled={loading} className="button-primary w-full">{loading ? <Loader2 className="h-4 w-4 animate-spin" /> : "Sign in"}</button>
      </form>
      <p className="mt-6 text-center text-sm text-[#7f8998]">New to ScanMySaaS? <Link href="/register" onClick={pendingScan} className="font-medium text-white hover:text-[var(--signal)]">Create an account</Link></p>
    </AuthFrame>
  );
}

export default function LoginPage() {
  return <Suspense fallback={<div className="flex min-h-screen items-center justify-center"><Loader2 className="h-6 w-6 animate-spin text-[var(--signal)]" /></div>}><LoginForm /></Suspense>;
}
