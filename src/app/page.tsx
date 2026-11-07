"use client";

import Link from "next/link";
import {
  AlertTriangle,
  ArrowRight,
  ArrowUpRight,
  Bot,
  BookOpen,
  Braces,
  Check,
  ChevronDown,
  CircleDot,
  Clock3,
  Cookie,
  FileKey,
  Fingerprint,
  Github,
  Globe2,
  LockKeyhole,
  Radar,
  Search,
  ShieldCheck,
  Sparkles,
  TerminalSquare,
  Video,
  Waypoints,
} from "lucide-react";
import { ScannerForm } from "@/components/ScannerForm";
import { ToastContainer } from "@/components/Toast";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";
import { homeFaqs, productFeatures } from "@/lib/site-content";
import { guides } from "@/lib/guides";

const coverage = [
  { icon: LockKeyhole, title: "SSL & transport", copy: "SSL/TLS use, HTTPS redirects, HSTS, mixed content, and downgrade risks." },
  { icon: ShieldCheck, title: "Security headers", copy: "CSP, framing protection, MIME sniffing, permissions policy, referrers, and more." },
  { icon: FileKey, title: "Exposed files", copy: "Public environment files, Git metadata, backups, logs, source maps, and debug paths." },
  { icon: Cookie, title: "Cookies & forms", copy: "Secure, HttpOnly, and SameSite flags plus observable CSRF protection gaps." },
  { icon: Braces, title: "Client-side risk", copy: "Unsafe JavaScript patterns, detectable outdated libraries, and injection signals." },
  { icon: Fingerprint, title: "App exposure", copy: "Technology leakage, debug endpoints, GraphQL introspection, DNS and email signals, and CORS." },
  { icon: Bot, title: "AI discovery", copy: "llms.txt availability and a readable public resource map for compatible AI tools." },
  { icon: Globe2, title: "Crawl readiness", copy: "robots.txt, XML sitemap, canonical URL, homepage indexability, and security.txt." },
];

const SITE_URL = "https://www.scanmysaas.com";
const featureIcons = [Radar, Waypoints, TerminalSquare, Clock3, ShieldCheck, Search];

const homepageJsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "SoftwareApplication",
      "@id": `${SITE_URL}/#software-application`,
      name: "ScanMySaaS",
      url: SITE_URL,
      applicationCategory: "SecurityApplication",
      applicationSubCategory: "Website vulnerability scanner",
      operatingSystem: "Any",
      browserRequirements: "Requires a modern web browser",
      description:
        "A browser-based website vulnerability scanner for SaaS applications that crawls up to 25 pages and runs more than 60 automated security checks.",
      featureList: productFeatures.map((feature) => feature.title),
      isAccessibleForFree: true,
      offers: [
        { "@type": "Offer", name: "Free", price: "0", priceCurrency: "USD", url: `${SITE_URL}/pricing` },
        { "@type": "Offer", name: "Starter", price: "29", priceCurrency: "USD", url: `${SITE_URL}/pricing` },
        { "@type": "Offer", name: "Pro", price: "79", priceCurrency: "USD", url: `${SITE_URL}/pricing` },
      ],
    },
    {
      "@type": "FAQPage",
      "@id": `${SITE_URL}/#faq`,
      mainEntity: homeFaqs.map((faq) => ({
        "@type": "Question",
        name: faq.question,
        acceptedAnswer: { "@type": "Answer", text: faq.answer },
      })),
    },
  ],
};


function ReportPreview() {
  const findings = [
    { severity: "Critical", title: "Environment file is publicly accessible", location: "/.env", tone: "text-[#ff8787] bg-[#ff6b6b]/10" },
    { severity: "Medium", title: "Public source map reveals application code", location: "/_next/static/chunks/app.js.map", tone: "text-[#ffe066] bg-[#ffe066]/10" },
    { severity: "Medium", title: "Session cookie has no SameSite policy", location: "/login", tone: "text-[#ffe066] bg-[#ffe066]/10" },
  ];

  return (
    <div className="surface relative overflow-hidden rounded-[1.75rem]">
      <div className="flex items-center justify-between border-b border-white/[0.08] px-5 py-4">
        <div className="flex items-center gap-2 text-xs text-[#929cab]"><CircleDot className="h-3.5 w-3.5 text-[var(--signal)]" /> Example report</div>
        <div className="flex gap-1.5"><span className="h-2 w-2 rounded-full bg-white/10" /><span className="h-2 w-2 rounded-full bg-white/10" /><span className="h-2 w-2 rounded-full bg-white/10" /></div>
      </div>
      <div className="grid gap-5 p-5 sm:grid-cols-[9rem_1fr] sm:p-7">
        <div className="rounded-2xl border border-white/[0.08] bg-black/20 p-5 text-center">
          <div className="relative mx-auto flex h-24 w-24 items-center justify-center rounded-full border-[9px] border-[#ffbf69]/20 border-r-[#ffbf69]">
            <span className="text-3xl font-semibold tracking-[-0.05em]">64</span>
          </div>
          <p className="mt-3 text-sm font-medium text-[#ffcd8a]">Needs attention</p>
          <p className="mt-1 text-xs text-[#727d8c]">8 pages checked</p>
        </div>
        <div className="min-w-0">
          <div className="mb-4 flex items-start justify-between gap-4">
            <div><p className="text-sm font-semibold">app.acme.test</p><p className="mt-1 text-xs text-[#778191]">3 example findings · illustrative score</p></div>
            <span className="rounded-full bg-[var(--signal)]/10 px-2.5 py-1 text-[0.68rem] font-semibold text-[var(--signal)]">Complete</span>
          </div>
          <div className="space-y-2">
            {findings.map((finding) => (
              <div key={finding.title} className="grid grid-cols-[auto_1fr] gap-3 rounded-xl border border-white/[0.07] bg-white/[0.025] p-3.5">
                <AlertTriangle className={`mt-0.5 h-4 w-4 ${finding.tone.split(" ")[0]}`} />
                <div className="min-w-0"><div className="flex flex-wrap items-center gap-2"><p className="text-sm font-medium text-[#edf0f3]">{finding.title}</p><span className={`rounded px-1.5 py-0.5 text-[0.62rem] font-bold uppercase ${finding.tone}`}>{finding.severity}</span></div><p className="mt-1 truncate text-xs text-[#707b8a]">{finding.location}</p></div>
              </div>
            ))}
          </div>
        </div>
      </div>
      <div className="mx-5 mb-5 flex items-center justify-between rounded-xl border border-[var(--signal)]/15 bg-[var(--signal)]/[0.04] px-4 py-3 text-xs sm:mx-7 sm:mb-7">
        <span className="text-[#aab3bf]">Prioritized remediation is ready</span>
        <span className="font-semibold text-[var(--signal)]">View fixes →</span>
      </div>
    </div>
  );
}

export default function HomePage() {


  return (
    <main className="overflow-hidden">
      <script
        type="application/ld+json"
        dangerouslySetInnerHTML={{ __html: JSON.stringify(homepageJsonLd).replace(/</g, "\\u003c") }}
      />
      <SiteHeader />
      <ToastContainer />

      <section className="relative pb-20 pt-14 sm:pb-24 sm:pt-16">
        <div className="pointer-events-none absolute inset-0 -z-10 hairline-grid [mask-image:linear-gradient(to_bottom,black,transparent_78%)]" />
        <div className="app-shell grid items-center gap-14 lg:grid-cols-[0.88fr_1.12fr] lg:gap-16">
          <div>
            <div className="mb-7 inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5 text-xs text-[#b4bdc9]">
              <Sparkles className="h-3.5 w-3.5 text-[var(--signal)]" /> Free website vulnerability scan. No card required.
            </div>
            <h1 className="display-title text-balance">SaaS security scanner <span className="text-[var(--signal)]">before your next launch.</span></h1>
            <p className="mt-7 max-w-xl text-pretty text-lg leading-8 text-[#a0a9b6]">Shipping with Cursor, Claude, Codex or Lovable? Run a free website vulnerability scan on your deployed app. Find exposed files, unsafe headers and risky cookies, with affected URLs and a clear order for what to verify first.</p>
            <div className="mt-8"><ScannerForm /></div>
            <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-sm"><Link href="/repo-scan" className="inline-flex items-center gap-1.5 text-[var(--signal)] hover:underline"><Github className="h-4 w-4" /> GitHub repo scanner (public or private)</Link><Link href="/guides/saas-launch-security-checklist" className="text-[#a0a9b6] hover:text-white hover:underline">SaaS launch security checklist</Link></div>
            <div className="mt-4 flex flex-wrap gap-x-5 gap-y-2 text-xs text-[#778191]">
              <span className="inline-flex items-center gap-1.5"><Check className="h-3.5 w-3.5 text-[var(--signal)]" /> 60+ checks</span>
              <span className="inline-flex items-center gap-1.5"><Check className="h-3.5 w-3.5 text-[var(--signal)]" /> Up to 25 pages</span>
              <span className="inline-flex items-center gap-1.5"><Check className="h-3.5 w-3.5 text-[var(--signal)]" /> Readable report</span>
            </div>
          </div>
          <ReportPreview />
        </div>
      </section>

      <section id="demo" className="app-shell pb-20 sm:pb-24">
        <div className="grid gap-8 lg:grid-cols-[0.72fr_1.28fr] lg:items-center lg:gap-14">
          <div>
            <p className="eyebrow">Product demo</p>
            <h2 className="mt-4 text-balance text-3xl font-semibold leading-[1.04] tracking-[-0.045em] sm:text-4xl">See the scan before you run yours.</h2>
            <p className="mt-5 text-sm leading-7 text-[#8f99a7]">Watch the original walkthrough, then start with your own public URL. The report now adds clearer findings, affected pages, and a SaaS readiness view for TLS, crawl files, and AI discovery.</p>
            <div className="mt-6 flex flex-wrap gap-3 text-xs text-[#778191]"><span className="inline-flex items-center gap-1.5"><Video className="h-3.5 w-3.5 text-[var(--signal)]" /> Real product flow</span><span>·</span><span>No installation required</span></div>
          </div>
          <div className="surface signal-shadow overflow-hidden rounded-[1.5rem] p-2">
            <div className="aspect-video overflow-hidden rounded-[1.1rem] bg-black">
              <iframe className="h-full w-full" src="https://www.youtube-nocookie.com/embed/8wF8yVI161c?rel=0&modestbranding=1" title="ScanMySaaS website vulnerability scanner demo" loading="lazy" allow="accelerometer; autoplay; clipboard-write; encrypted-media; gyroscope; picture-in-picture; web-share" allowFullScreen />
            </div>
          </div>
        </div>
      </section>

      <section className="border-y border-white/[0.07] bg-white/[0.018]">
        <div className="app-shell grid grid-cols-2 divide-x divide-white/[0.07] sm:grid-cols-4">
          {[["60+", "vulnerability checks"], ["25", "pages per scan"], ["15", "security categories"], ["1", "free first scan"]].map(([value, label]) => <div key={label} className="px-4 py-7 text-center"><p className="text-2xl font-semibold tracking-[-0.04em] text-white">{value}</p><p className="mt-1 text-xs text-[#737e8d]">{label}</p></div>)}
        </div>
      </section>

      <section className="app-shell py-24 sm:py-32">
        <div className="relative overflow-hidden rounded-[2rem] border border-white/[0.09] bg-[#0b1017] p-7 sm:p-10 lg:grid lg:grid-cols-[0.82fr_1.18fr] lg:gap-16 lg:p-14">
          <div className="pointer-events-none absolute -right-24 -top-24 h-72 w-72 rounded-full bg-[var(--cobalt)]/10 blur-3xl" />
          <div className="relative">
            <p className="eyebrow">Built with Codex, Claude, or Cursor?</p>
            <h2 className="section-title mt-4 text-balance">Scan the code before the public app.</h2>
            <p className="mt-5 text-sm leading-7 text-[#8f99a7]">The website scanner sees what reached production. The repository scanner checks your public or private GitHub repository for committed environment files, secret patterns, risky GitHub Actions, exposed client keys, weak Supabase signals, and unsafe build settings. Verified findings can be copied as technical fix prompts for your coding agent.</p>
            <div className="mt-7 flex flex-col gap-3 sm:flex-row">
              <Link href="/repo-scan?tab=private" className="button-primary"><Github className="h-4 w-4" /> Connect your repository</Link>
              <Link href="/vibe-coding-security" className="button-secondary">Vibe coding security guide <ArrowRight className="h-4 w-4" /></Link>
            </div>
            <p className="mt-4 text-xs leading-5 text-[#667181]">Read-only GitHub App you control. No clone, package install, build, or code execution. Public repositories are free; private repositories are included in Starter and Pro.</p>
          </div>
          <div className="relative mt-10 grid gap-3 sm:grid-cols-2 lg:mt-0">
            {[
              [".env and credentials", "Flags committed environment files and high-confidence provider, database, and private-key patterns."],
              ["GitHub Actions", "Reviews token permissions, pull_request_target usage, secret output, and mutable third-party actions."],
              ["Supabase boundaries", "Looks for service-role exposure and migrations that create tables without visible RLS enablement."],
              ["Client and build risk", "Checks public secret prefixes, wildcard CORS, raw HTML sinks, eval, and production source maps."],
            ].map(([title, copy]) => <article key={title} className="rounded-2xl border border-white/[0.08] bg-black/20 p-5"><ShieldCheck className="h-4 w-4 text-[var(--signal)]" /><h3 className="mt-7 text-base font-semibold">{title}</h3><p className="mt-2 text-xs leading-5 text-[#828d9c]">{copy}</p></article>)}
          </div>
        </div>
      </section>

      <section id="product" className="app-shell py-24 sm:py-32">
        <div className="grid gap-12 lg:grid-cols-[0.72fr_1.28fr] lg:gap-20">
          <div className="lg:sticky lg:top-28 lg:self-start">
            <p className="eyebrow">More than a pass or fail</p>
            <h2 className="section-title mt-4 text-balance">A vulnerability report your team can actually use.</h2>
            <p className="mt-5 text-pretty leading-7 text-[#8f99a7]">Start with the affected URL and a prioritized finding. The free report includes one actionable fix when available; paid plans add remediation for the remaining issues.</p>
            <Link href="/register" className="button-secondary mt-7">Create free account <ArrowRight className="h-4 w-4" /></Link>
          </div>
          <div className="grid gap-4 sm:grid-cols-2">
            {productFeatures.map((item, index) => {
              const FeatureIcon = featureIcons[index];
              return (
                <article key={item.title} className="surface-muted rounded-2xl p-6 sm:p-7">
                  <div className="flex items-center justify-between"><FeatureIcon className="h-5 w-5 text-[var(--signal)]" /><span className="font-mono text-xs text-[#5f6a79]">{String(index + 1).padStart(2, "0")}</span></div>
                  <h3 className="mt-10 text-xl font-semibold tracking-[-0.025em]">{item.title}</h3>
                  <p className="mt-3 text-sm leading-6 text-[#8c96a4]">{item.copy}</p>
                </article>
              );
            })}
          </div>
        </div>
      </section>

      <section id="guides" className="border-y border-white/[0.07] bg-[#0a0e14] py-24 sm:py-32">
        <div className="app-shell">
          <div className="flex flex-col gap-6 md:flex-row md:items-end md:justify-between">
            <div className="max-w-2xl"><p className="eyebrow">SaaS security field guides</p><h2 className="section-title mt-4 text-balance">Understand the finding before changing production.</h2><p className="mt-5 text-sm leading-7 text-[#8f99a7]">Focused guides connect scanner output to a safer release plan across the public app, GitHub workflows, and database boundaries.</p></div>
            <Link href="/guides" className="button-secondary shrink-0">Browse all guides <ArrowRight className="h-4 w-4" /></Link>
          </div>
          <div className="mt-12 grid gap-4 md:grid-cols-2 xl:grid-cols-5">
            {guides.slice(0, 5).map((guide) => <Link key={guide.slug} href={`/guides/${guide.slug}`} className="group surface-muted flex min-h-64 flex-col rounded-2xl p-5 transition hover:border-white/20 hover:bg-white/[0.045]"><div className="flex items-center justify-between"><BookOpen className="h-4 w-4 text-[var(--signal)]" /><span className="text-[0.65rem] text-[#606b79]">{guide.readTime}</span></div><h3 className="mt-8 text-lg font-semibold leading-6 tracking-[-0.025em]">{guide.title}</h3><p className="mt-3 line-clamp-3 text-xs leading-5 text-[#7f8998]">{guide.description}</p><span className="mt-auto inline-flex items-center gap-1.5 pt-6 text-xs font-semibold text-[var(--signal)]">Read guide <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-1" /></span></Link>)}
          </div>
        </div>
      </section>

      <section id="workflow" className="border-y border-white/[0.07] bg-[#0a0e14] py-24 sm:py-32">
        <div className="app-shell">
          <div className="max-w-2xl"><p className="eyebrow">How it works</p><h2 className="section-title mt-4 text-balance">How does a web vulnerability scanner work?</h2><p className="mt-5 max-w-xl text-sm leading-7 text-[#8f99a7]">Start with a URL, let the automated scanner inspect the public surface, then use the report to decide what to verify and fix first.</p></div>
          <div className="mt-14 grid gap-px overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.08] md:grid-cols-3">
            {[
              { n: "01", title: "Point us at your app", copy: "Enter a public URL you own or are authorized to test." },
              { n: "02", title: "We inspect the surface", copy: "The crawler discovers pages and checks observable security signals." },
              { n: "03", title: "Work down the risk", copy: "Open the report, address priority findings, then run a fresh scan." },
            ].map((step) => <article key={step.n} className="bg-[#0d1219] p-7 sm:p-9"><p className="font-mono text-xs text-[var(--signal)]">STEP {step.n}</p><h3 className="mt-12 text-xl font-semibold">{step.title}</h3><p className="mt-3 text-sm leading-6 text-[#8f99a7]">{step.copy}</p></article>)}
          </div>
        </div>
      </section>

      <section id="coverage" className="app-shell py-24 sm:py-32">
        <div className="grid gap-10 lg:grid-cols-[0.75fr_1.25fr] lg:gap-20">
          <div><p className="eyebrow">Security coverage</p><h2 className="section-title mt-4 text-balance">What our website vulnerability scanner checks for.</h2><p className="mt-5 text-sm leading-7 text-[#8f99a7]">ScanMySaaS runs 60+ automated checks across the exposed web application. It tests public signals only—it does not log in, exploit targets, or replace a human security review.</p></div>
          <div className="divide-y divide-white/[0.08] border-y border-white/[0.08]">
            {coverage.map((item) => <div key={item.title} className="grid gap-3 py-5 sm:grid-cols-[2.2rem_12rem_1fr] sm:items-center"><item.icon className="h-5 w-5 text-[var(--cobalt)]" /><h3 className="text-sm font-semibold">{item.title}</h3><p className="text-sm leading-6 text-[#828d9c]">{item.copy}</p></div>)}
          </div>
        </div>
      </section>

      <section className="app-shell pb-24 sm:pb-32">
        <div className="relative overflow-hidden rounded-[2rem] border border-[var(--signal)]/20 bg-[var(--signal)] p-8 text-[#0a0d0b] sm:p-12 lg:grid lg:grid-cols-[1fr_auto] lg:items-end lg:gap-12">
          <div className="absolute -right-12 -top-20 h-60 w-60 rounded-full border-[36px] border-black/[0.05]" />
          <div className="relative"><p className="text-xs font-bold uppercase tracking-[.14em]">Your first scan is free</p><h2 className="mt-4 max-w-3xl text-balance text-3xl font-semibold leading-[1.02] tracking-[-0.05em] sm:text-5xl">Know what your launch left exposed.</h2><p className="mt-4 max-w-xl text-sm leading-6 text-black/60">No credit card. Use it on a website you own, keep the report, and decide what deserves attention.</p></div>
          <div className="relative mt-7 lg:mt-0"><Link href="#scan" className="inline-flex items-center gap-2 rounded-xl bg-[#090c0a] px-5 py-3 text-sm font-semibold text-white transition hover:-translate-y-0.5">Run the scan <ArrowUpRight className="h-4 w-4" /></Link></div>
        </div>
      </section>

      <section className="border-t border-white/[0.07] bg-[#0a0e14] py-24 sm:py-32">
        <div className="app-shell grid gap-12 lg:grid-cols-[0.8fr_1.2fr] lg:gap-20">
          <div><p className="eyebrow">Vulnerability scanner FAQ</p><h2 className="section-title mt-4">Before you scan your SaaS.</h2></div>
          <div className="divide-y divide-white/[0.08] border-y border-white/[0.08]">
            {homeFaqs.map((faq) => <details key={faq.question} className="group py-5"><summary className="flex cursor-pointer list-none items-center justify-between gap-4 text-base font-medium"><span>{faq.question}</span><ChevronDown className="h-4 w-4 shrink-0 text-[#707b8a] transition group-open:rotate-180" /></summary><p className="max-w-2xl pb-1 pt-4 text-sm leading-7 text-[#8f99a7]">{faq.answer}</p></details>)}
          </div>
        </div>
      </section>

      <SiteFooter />
    </main>
  );
}
