import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, BookOpen, CheckCircle2 } from "lucide-react";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";
import { GuideCover } from "@/components/visuals/GuideCover";
import { guides } from "@/lib/guides";

export const metadata: Metadata = {
  title: "SaaS Security Guides",
  description: "SaaS launch security checklists and practical guides to exposed secrets, Supabase RLS, GitHub Actions, security headers and production website checks.",
  alternates: { canonical: "/guides" },
};

export default function GuidesPage() {
  return (
    <main className="min-h-screen">
      <SiteHeader />
      <section className="app-shell py-16 sm:py-24">
        <div className="max-w-3xl">
          <p className="eyebrow">ScanMySaaS field guides</p>
          <h1 className="display-title mt-5 text-balance">Fix the surface your customers can see.</h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-[#98a2b3]">Practical guides for the checks that repeatedly matter in SaaS websites, source repositories, deployment workflows, and databases. Each one explains what the signal means, what to verify, and how to ship a safer change.</p>
        </div>
        <div className="mt-14 grid gap-4 lg:grid-cols-2">
          {guides.map((guide, index) => (
            <Link key={guide.slug} href={`/guides/${guide.slug}`} className={`group surface-muted rounded-2xl p-6 transition hover:border-white/20 hover:bg-white/[0.045] sm:p-8 ${index === 0 ? "lg:col-span-2 lg:grid lg:grid-cols-[1fr_auto] lg:items-end lg:gap-12" : ""}`}>
              <div>
                <GuideCover src={guide.cover} alt={guide.coverAlt} card />
                <div className="flex items-center gap-2 text-xs text-[#778191]"><BookOpen className="h-3.5 w-3.5 text-[var(--signal)]" />{guide.eyebrow}<span>·</span>{guide.readTime}</div>
                <h2 className="mt-5 text-2xl font-semibold tracking-[-0.035em] text-white sm:text-3xl">{guide.title}</h2>
                <p className="mt-4 max-w-2xl text-sm leading-7 text-[#8d97a5]">{guide.description}</p>
              </div>
              <span className="mt-7 inline-flex items-center gap-2 text-sm font-semibold text-[var(--signal)] lg:mt-0">Read guide <ArrowRight className="h-4 w-4 transition group-hover:translate-x-1" /></span>
            </Link>
          ))}
        </div>
        <div className="mt-12 rounded-2xl border border-[var(--signal)]/20 bg-[var(--signal)]/[0.045] p-6 sm:flex sm:items-center sm:justify-between sm:gap-8 sm:p-8">
          <div className="flex gap-4"><CheckCircle2 className="mt-1 h-5 w-5 shrink-0 text-[var(--signal)]" /><div><h2 className="font-semibold">Want the checks applied to your own site?</h2><p className="mt-2 text-sm leading-6 text-[#8f99a7]">Run the public scanner, then use the affected URLs to work through the right guide.</p></div></div>
          <Link href="/#scan" className="button-primary mt-6 shrink-0 sm:mt-0">Run a free scan <ArrowRight className="h-4 w-4" /></Link>
        </div>
      </section>
      <SiteFooter />
    </main>
  );
}
