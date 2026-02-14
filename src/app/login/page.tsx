"use client";

import { Suspense, useState } from "react";
import { signIn } from "next-auth/react";
import { useRouter, useSearchParams } from "next/navigation";
import Link from "next/link";
import { Shield, Loader2, Mail, Lock, CheckCircle2, Github } from "lucide-react";

function LoginForm() {
  const [email, setEmail] = useState("");
  const [password, setPassword] = useState("");
  const [error, setError] = useState("");
  const [loading, setLoading] = useState(false);
  const [githubLoading, setGithubLoading] = useState(false);
  const router = useRouter();
  const searchParams = useSearchParams();
  const registered = searchParams.get("registered");
  const redirectTo = searchParams.get("redirect");
  const authError = searchParams.get("error");

  // Map NextAuth error codes to user-friendly messages
  const authErrorMessage = authError
    ? authError === "OAuthAccountNotLinked"
      ? "This email is already registered with a different sign-in method."
      : authError === "OAuthCallbackError"
        ? "GitHub sign-in was cancelled or failed. Please try again."
        : "Sign-in failed. Please try again."
    : null;

  async function handleGitHub() {
    setGithubLoading(true);
    // Determine where to redirect after sign-in
    const pendingScanId = typeof window !== "undefined" ? sessionStorage.getItem("pendingScanId") : null;
    const callbackUrl = pendingScanId ? `/scan/${pendingScanId}` : redirectTo || "/dashboard";
    if (pendingScanId) sessionStorage.removeItem("pendingScanId");

    await signIn("github", { callbackUrl });
  }

  async function handleSubmit(e: React.FormEvent) {
    e.preventDefault();
    setError("");
    setLoading(true);

    try {
      const result = await signIn("credentials", {
        email,
        password,
        redirect: false,
      });

      if (result?.error) {
        setError("Invalid email or password");
        setLoading(false);
        return;
      }

      // Check for pending plan (user selected a plan before registering)
      const pendingPlan = typeof window !== "undefined" ? localStorage.getItem("pendingPlan") : null;
      // Check for pending scan redirect or explicit redirect param
      const pendingScanId = typeof window !== "undefined" ? sessionStorage.getItem("pendingScanId") : null;

      if (pendingPlan) {
        localStorage.removeItem("pendingPlan");
        // Start checkout for the plan they chose
        try {
          const res = await fetch("/api/stripe/checkout", {
            method: "POST",
            headers: { "Content-Type": "application/json" },
            body: JSON.stringify({ plan: pendingPlan }),
          });
          const data = await res.json();
          if (data.url) {
            window.location.href = data.url;
            return;
          }
        } catch {
          // Fall through to dashboard if checkout fails
        }
        router.push("/dashboard");
      } else if (pendingScanId) {
        sessionStorage.removeItem("pendingScanId");
        router.push(`/scan/${pendingScanId}`);
      } else if (redirectTo) {
        router.push(redirectTo);
      } else {
        router.push("/dashboard");
      }
      router.refresh();
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
          <h1 className="mt-6 text-2xl font-bold">Welcome back</h1>
          <p className="mt-2 text-gray-400">Sign in to your account</p>
        </div>

        <div className="mt-8 space-y-5">
          {registered && (
            <div className="rounded-lg border border-emerald-500/20 bg-emerald-500/10 px-4 py-3 text-sm text-emerald-400 flex items-center gap-2">
              <CheckCircle2 className="h-4 w-4 shrink-0" />
              Account created! Sign in to view your scan results.
            </div>
          )}
          {authErrorMessage && (
            <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
              {authErrorMessage}
            </div>
          )}
          {error && (
            <div className="rounded-lg border border-red-500/20 bg-red-500/10 px-4 py-3 text-sm text-red-400">
              {error}
            </div>
          )}

          {/* GitHub sign-in */}
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
              <span className="bg-gray-950 px-4 text-gray-500">or sign in with email</span>
            </div>
          </div>

          <form onSubmit={handleSubmit} className="space-y-5">
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
                  placeholder="••••••••"
                  required
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
                  Signing in...
                </>
              ) : (
                "Sign In"
              )}
            </button>
          </form>
        </div>

        <p className="mt-6 text-center text-sm text-gray-400">
          Don&apos;t have an account?{" "}
          <Link href="/register" className="text-emerald-400 hover:text-emerald-300">
            Create one
          </Link>
        </p>
      </div>
    </div>
  );
}

export default function LoginPage() {
  return (
    <Suspense fallback={
      <div className="flex min-h-screen items-center justify-center">
        <Loader2 className="h-8 w-8 animate-spin text-emerald-500" />
      </div>
    }>
      <LoginForm />
    </Suspense>
  );
}
