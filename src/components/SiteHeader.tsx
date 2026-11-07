"use client";

import { useEffect, useState } from "react";
import Link from "next/link";
import { useSession } from "next-auth/react";
import { ArrowUpRight, LayoutDashboard, Menu, X, Zap } from "lucide-react";
import { Brand } from "@/components/Brand";

export function SiteHeader() {
  const { data: session, status } = useSession();
  const [credits, setCredits] = useState<number | null>(null);
  const [open, setOpen] = useState(false);
  const signedIn = status === "authenticated" && Boolean(session?.user);

  useEffect(() => {
    if (!signedIn) return;
    fetch("/api/user/plan")
      .then((response) => response.json())
      .then((data) => setCredits(data.credits ?? null))
      .catch(() => undefined);
  }, [signedIn]);

  const nav = [
    ["Repo scanner", "/repo-scan"],
    ["Vibe security", "/vibe-coding-security"],
    ["Demo", "/#demo"],
    ["Checks", "/#coverage"],
    ["Guides", "/guides"],
    ["Pricing", "/pricing"],
  ];

  return (
    <header className="sticky top-0 z-50 border-b border-white/[0.07] bg-[#07090d]/88 backdrop-blur-xl">
      <div className="app-shell flex h-[4.25rem] items-center justify-between">
        <Brand />
        <nav className="hidden items-center gap-7 lg:flex" aria-label="Primary navigation">
          {nav.map(([label, href]) => (
            <Link key={href} href={href} className="text-sm text-[#98a2b3] transition hover:text-white">
              {label}
            </Link>
          ))}
        </nav>
        <div className="hidden items-center gap-2 sm:flex">
          {signedIn ? (
            <>
              {credits !== null && (
                <span className="mr-1 inline-flex items-center gap-1.5 rounded-lg border border-white/10 px-3 py-2 text-xs text-[#c7ced8]">
                  <Zap className="h-3.5 w-3.5 text-[var(--amber)]" /> {credits} left
                </span>
              )}
              <Link href="/dashboard" className="button-primary">
                <LayoutDashboard className="h-4 w-4" /> Dashboard
              </Link>
            </>
          ) : (
            <>
              <Link href="/login" className="px-3 py-2 text-sm text-[#c7ced8] transition hover:text-white">Log in</Link>
              <Link href="/#scan" className="button-primary">Run a free scan <ArrowUpRight className="h-4 w-4" /></Link>
            </>
          )}
        </div>
        <button onClick={() => setOpen((value) => !value)} className="rounded-lg border border-white/10 p-2 text-white lg:hidden" aria-label="Toggle navigation" aria-expanded={open}>
          {open ? <X className="h-5 w-5" /> : <Menu className="h-5 w-5" />}
        </button>
      </div>
      {open && (
        <div className="app-shell border-t border-white/[0.07] py-4 lg:hidden">
          <nav className="grid gap-1" aria-label="Mobile navigation">
            {nav.map(([label, href]) => <Link key={href} href={href} onClick={() => setOpen(false)} className="rounded-lg px-3 py-2.5 text-sm text-[#c7ced8] hover:bg-white/5">{label}</Link>)}
            <div className="mt-2 grid grid-cols-2 gap-2">
              <Link href="/login" className="button-secondary">Log in</Link>
              <Link href={signedIn ? "/dashboard" : "/#scan"} className="button-primary">{signedIn ? "Dashboard" : "Free scan"}</Link>
            </div>
          </nav>
        </div>
      )}
    </header>
  );
}
