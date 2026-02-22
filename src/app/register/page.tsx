"use client";

import { useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter } from "next/navigation";
import Link from "next/link";
import { Shield, Loader2, Mail, Lock, User, Github } from "lucide-react";

export default function RegisterPage() {
  const [name, setName] = useState("");
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [githubLoading, setGithubLoading] = useState(false);
  const [googleLoading, setGoogleLoading] = useState(false);
  const router = useRouter();

  // Store referrer data in a cookie before OAuth redirects (sessionStorage won't survive the redirect)
  function storeReferrerCookie() {
    if (typeof window === "undefined") return;
    const data = {
      referrerUrl: sessionStorage.getItem("referrer_url") || "",
      utmSource: sessionStorage.getItem("utm_source") || "",
      utmMedium: sessionStorage.getItem("utm_medium") || "",
      utmCampaign: sessionStorage.getItem("utm_campaign") || "",
    };
    // Set cookie that expires in 10 minutes (enough for OAuth round-trip)
    document.cookie = `signup_referrer=${encodeURIComponent(JSON.stringify(data))};path=/;max-age=600;SameSite=Lax`;
  }

  async function handleGoogle() {
    setGoogleLoading(true);
    storeReferrerCookie();
    const pendingScanId = typeof window !== "undefined" ? sessionStorage.getItem("pendingScanId") : null;
    const callbackUrl = pendingScanId ? `/scan/${pendingScanId}` : "/dashboard";
    if (pendingScanId) sessionStorage.removeItem("pendingScanId");

    await signIn("google", { callbackUrl });
  }

  async function handleGitHub() {
    setGithubLoading(true);
    storeReferrerCookie();
    const pendingScanId = typeof window !== "undefined" ? sessionStorage.getItem("pendingScanId") : null;
    const callbackUrl = pendingScanId ? `/scan/${pendingScanId}` : "/dashboard";
    if (pendingScanId) sessionStorage.removeItem("pendingScanId");

    await signIn("github", { callbackUrl });
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    // Read referrer/UTM data stored from the landing page
    const referrerUrl = typeof window !== "undefined" ? sessionStorage.getItem("referrer_url") || "" : "";
    const utmSource = typeof window !== "undefined" ? sessionStorage.getItem("utm_source") || "" : "";
    const utmMedium = typeof window !== "undefined" ? sessionStorage.getItem("utm_medium") || "" : "";
    const utmCampaign = typeof window !== "undefined" ? sessionStorage.getItem("utm_campaign") || "" : "";

    try {
      const res = await fetch("/api/register", {
        method: "POST",
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ name, email, password, referrerUrl, utmSource, utmMedium, utmCampaign }),
      });

      const data = await res.json();

      if (!res.ok) {
        setError(data.error || "Something went wrong");
        setLoading(false);
        return;
      }

      // Auto sign in after registration
      // Check if there's a pending scan to redirect to
      const pendingScanId = typeof window !== "undefined" ? sessionStorage.getItem("pendingScanId") : null;
      if (pendingScanId) {
        sessionStorage.removeItem("pendingScanId");
        router.push(`/login?registered=true&redirect=/scan/${pendingScanId}`);
      } else {
        router.push("/login?registered=true");
      }
    } catch {
      setError("Something went wrong. Please try again.");
      setLoading(false);
    }
  }

  return (
    <div className="flex min-h-screen items-center justify-center px-4">
      <div className="w-full max-w-md">
        <div className="text-center">
          <Link href="/" className="inline-flex items-center gap-2">
            <div className="flex h-10 w-10 items-center justify-center rounded-xl bg-gradient-to-br from-emerald-500 to-cyan-500">
              <Shield className="h-5 w-5 text-white" />
            </div>
            <span className="text-2xl font-bold">
              Secure<span className="gradient-text">SaaS</span>
            </span>
          </Link>
          <h1 className="mt-6 text-2xl font-bold">Create your account</h1>
          <p className="mt-2 text-gray-400">Start securing your SaaS for free</p>
        </div>

        <div className="mt-8 space-y-5">
          {error && (
            <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
              {error}
            </div>
          )}

          {/* Google sign-up */}
          <button
            onClick={handleGoogle}
            disabled={googleLoading}
            className="flex w-full items-center justify-center gap-3 rounded-xl border border-gray-700 bg-gray-900 py-3 font-medium text-white transition hover:bg-gray-800 disabled:opacity-50"
          >
            {googleLoading ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <svg className="h-5 w-5" viewBox="0 0 24 24">
                <path d="M22.56 12.25c0-.78-.07-1.53-.2-2.25H12v4.26h5.92a5.06 5.06 0 0 1-2.2 3.32v2.77h3.57c2.08-1.92 3.28-4.74 3.28-8.1z" fill="#4285F4"/>
                <path d="M12 23c2.97 0 5.46-.98 7.28-2.66l-3.57-2.77c-.98.66-2.23 1.06-3.71 1.06-2.86 0-5.29-1.93-6.16-4.53H2.18v2.84C3.99 20.53 7.7 23 12 23z" fill="#34A853"/>
                <path d="M5.84 14.09c-.22-.66-.35-1.36-.35-2.09s.13-1.43.35-2.09V7.07H2.18C1.43 8.55 1 10.22 1 12s.43 3.45 1.18 4.93l2.85-2.22.81-.62z" fill="#FBBC05"/>
                <path d="M12 5.38c1.62 0 3.06.56 4.21 1.64l3.15-3.15C17.45 2.09 14.97 1 12 1 7.7 1 3.99 3.47 2.18 7.07l3.66 2.84c.87-2.6 3.3-4.53 6.16-4.53z" fill="#EA4335"/>
              </svg>
            )}
            Continue with Google
          </button>

          {/* GitHub sign-up */}
          <button
            onClick={handleGitHub}
            disabled={githubLoading}
            className="flex w-full items-center justify-center gap-3 rounded-xl border border-gray-700 bg-gray-900 py-3 font-medium text-white transition hover:bg-gray-800 disabled:opacity-50"
          >
            {githubLoading ? (
              <Loader2 className="h-5 w-5 animate-spin" />
            ) : (
              <Github className="h-5 w-5" />
            )}
            Continue with GitHub
          </button>

          {/* Divider */}
          <div className="relative">
            <div className="absolute inset-0 flex items-center">
              <div className="w-full border-t border-gray-700" />
            </div>
            <div className="relative flex justify-center text-sm">
              <span className="bg-gray-950 px-4 text-gray-500">or sign up with email</span>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
            <div>
              <label className="mb-2 block text-sm font-medium text-gray-300">Name</label>
              <div className="relative">
                <User className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                <input
                  type="text"
                  value={name}
                  onChange={(e) => setName(e.target.value)}
                  placeholder="John Doe"
                  required
                  className="w-full rounded-xl border border-gray-700 bg-gray-900 py-3 pl-10 pr-4 text-white placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
                />
              </div>
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-gray-300">Email</label>
              <div className="relative">
                <Mail className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                <input
                  type="email"
                  value={email}
                  onChange={(e) => setEmail(e.target.value)}
                  placeholder="you@example.com"
                  required
                  className="w-full rounded-xl border border-gray-700 bg-gray-900 py-3 pl-10 pr-4 text-white placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
                />
              </div>
            </div>

            <div>
              <label className="mb-2 block text-sm font-medium text-gray-300">Password</label>
              <div className="relative">
                <Lock className="absolute left-3 top-1/2 h-5 w-5 -translate-y-1/2 text-gray-500" />
                <input
                  type="password"
                  value={password}
                  onChange={(e) => setPassword(e.target.value)}
                  placeholder="At least 8 characters"
                  required
                  minLength={8}
                  className="w-full rounded-xl border border-gray-700 bg-gray-900 py-3 pl-10 pr-4 text-white placeholder:text-gray-500 focus:border-emerald-500 focus:outline-none focus:ring-1 focus:ring-emerald-500"
                />
              </div>
            </div>

            <button
              type="submit"
              disabled={loading}
              className="flex w-full items-center justify-center gap-2 rounded-xl bg-gradient-to-r from-emerald-500 to-cyan-500 py-3 font-medium text-white transition hover:from-emerald-600 hover:to-cyan-600 disabled:opacity-50"
            >
              {loading ? (
                <>
                  <Loader2 className="h-4 w-4 animate-spin" />
                  Creating account...
                </>
              ) : (
                "Create Account"
              )}
            </button>
          </form>
        </div>

        <p className="mt-6 text-center text-sm text-gray-400">
          Already have an account?{" "}
          <Link href="/login" className="text-emerald-400 hover:text-emerald-300">
            Sign in
          </Link>
        </p>
      </div>
    </div>
  );
}
