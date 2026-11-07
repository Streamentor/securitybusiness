import type { Metadata } from "next";
import Link from "next/link";
import { ArrowRight, ArrowUpRight, Bot, CheckCircle2, Cookie, Database, FileCode2, Github, Globe2, HardDrive, KeyRound, RefreshCw, ScanSearch, Server, ShieldAlert, ShieldCheck, Wand2 } from "lucide-react";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";
import { ScannerForm } from "@/components/ScannerForm";

const SITE_URL = "https://www.scanmysaas.com";
const PATH = "/lovable-security-scanner";

export const metadata: Metadata = {
  title: { absolute: "Lovable Security Scan: Find Security Issues in Your Lovable App" },
  description: "Free Lovable security scan for your live app and its GitHub repo: Supabase tables without RLS, leaked secret keys, missing headers and public source maps.",
  alternates: { canonical: PATH },
  openGraph: {
    title: "Lovable Security Scan: Find Security Issues in Your Lovable App",
    description: "Scan the live Lovable app and its GitHub repo for the security issues that show up in Lovable + Supabase projects.",
    url: PATH,
    type: "website",
  },
};

type Coverage = "Website scan" | "Repo scan" | "AI review" | "Manual test";

const coverageStyle: Record<Coverage, string> = {
  "Website scan": "border-sky-400/25 bg-sky-400/[0.07] text-sky-200",
  "Repo scan": "border-[var(--signal)]/30 bg-[var(--signal)]/[0.08] text-[var(--signal)]",
  "AI review": "border-violet-400/25 bg-violet-400/[0.07] text-violet-200",
  "Manual test": "border-white/15 bg-white/[0.04] text-[#aab3bf]",
};

const issueGroups: Array<{ severity: string; tone: string; summary: string; issues: Array<{ icon: typeof Database; title: string; copy: string; coverage: Coverage[] }> }> = [
  {
    severity: "Critical",
    tone: "text-red-300 border-red-400/30 bg-red-400/[0.08]",
    summary: "These are the gaps that expose user data.",
    issues: [
      { icon: Database, title: "Supabase tables without Row Level Security", copy: "If a table in the public schema is granted to the anon or authenticated role and RLS is off, anyone with the publishable key (it ships in every Lovable bundle) can read and write it through the Data API. Supabase stopped granting new tables to these roles automatically on October 30, 2026, but older tables keep their grants, and a migration that adds a grant without enabling RLS reopens the gap.", coverage: ["Repo scan", "Manual test"] },
      { icon: KeyRound, title: "Secret or service-role key in client code", copy: "The secret key (sb_secret_…) and the legacy service-role key bypass every RLS policy. If either lands in a VITE_ variable, a hardcoded string or a committed .env file, your whole database is public.", coverage: ["Repo scan"] },
    ],
  },
  {
    severity: "High",
    tone: "text-orange-300 border-orange-400/30 bg-orange-400/[0.08]",
    summary: "Exploitable once someone signs up or reads your JavaScript.",
    issues: [
      { icon: Server, title: "Edge functions and routes that trust the browser", copy: "A function that takes a user ID or role from the request body, or runs a service-role query without checking the signed-in user, lets one account act as another.", coverage: ["AI review", "Manual test"] },
      { icon: ShieldAlert, title: "RLS policies that are too permissive", copy: "RLS is on, but a policy like using (true), or one that checks login without checking ownership, still lets any user read or edit other users' rows.", coverage: ["Manual test"] },
      { icon: ShieldCheck, title: "Missing security headers and CSP", copy: "A strict Content-Security-Policy makes it harder to inject a script, which matters because a session kept in browser storage is readable by any script on the page. HSTS stops HTTPS downgrades, and frame protection stops clickjacking.", coverage: ["Website scan"] },
    ],
  },
  {
    severity: "Medium",
    tone: "text-amber-200 border-amber-300/30 bg-amber-300/[0.07]",
    summary: "Give attackers a map or a foothold.",
    issues: [
      { icon: FileCode2, title: "Public source maps", copy: "Production .map files rebuild your original source, including Supabase table names, internal routes and admin logic.", coverage: ["Website scan"] },
      { icon: Cookie, title: "Weak cookie flags", copy: "Session-like cookies without Secure, HttpOnly or SameSite are easier to steal or replay.", coverage: ["Website scan"] },
      { icon: HardDrive, title: "Storage buckets readable by anyone", copy: "Uploads such as invoices, avatars or documents in a public bucket, or a bucket without per-user policies, are downloadable by URL.", coverage: ["Manual test"] },
      { icon: Github, title: "Risky GitHub Actions and missing .gitignore rules", copy: "Workflows with write-all permissions, unpinned actions, or no rule keeping .env files out of the synced repository.", coverage: ["Repo scan"] },
    ],
  },
];

const steps = [
  { icon: Globe2, title: "Scan the published Lovable URL", copy: "Paste your lovable.app or custom domain above. The free website scan checks TLS, security headers, cookies, more than 40 sensitive paths and public source maps. Lovable apps render in the browser, so the crawler usually sees only the pages linked in the first HTML response, often just the home page." },
  { icon: Github, title: "Scan the GitHub repo Lovable syncs to", copy: "Connect GitHub in Lovable, then scan that repository. Public repos scan without an account; private repos connect through a read-only GitHub App on Starter or Pro. This is where RLS gaps and leaked keys show up." },
  { icon: Wand2, title: "Paste the fix prompt into Lovable", copy: "Every repo finding comes with a fix prompt you can paste into the Lovable chat, so the fix is made in the same project and syncs back to GitHub. On the free website scan, your one free fix includes a prompt; paid plans add one for every website finding." },
  { icon: RefreshCw, title: "Rescan to prove it is fixed", copy: "Run the website scan again after publishing. Resolved findings disappear, and the comparison shows what is new or still open. A free account gets one rescan of the same site within 7 days; after that, rescans use plan credits." },
];

const faqs = [
  { question: "Is Lovable secure?", answer: "The Lovable platform can be used to build secure apps, but security of the app you generate is your responsibility. Most incidents in Lovable apps come from the generated Supabase setup: tables without Row Level Security, policies that are too broad, privileged keys reachable from the browser, and server functions that trust user input. Check those before you put real user data in the app." },
  { question: "Doesn't Lovable already have a security scan?", answer: "Yes, and you should use it. Lovable's Quick scan checks database access rules, npm dependencies and MCP servers every time you publish, and flags tables without per-record access control. The Deep scan adds a code review and runs when you start it, from the Security view, the publish dialog or chat. ScanMySaaS is an independent second check with a different view: it scans the deployed app from the outside, the way a visitor or attacker sees it, including headers, cookies, TLS and exposed files that live on hosting rather than in code. It also reads the synced GitHub repository, so changes made outside Lovable in Cursor or Claude Code are covered, and gives you a report you can rescan and share." },
  { question: "How do I check if my Lovable app has RLS enabled?", answer: "With Lovable's built-in backend, open More, then Database, and review the policies on each table (Manage, then Policies). If you connected your own Supabase project, check the same tables in the Supabase dashboard. In code, every create table in drizzle/migrations (newer Lovable projects) or supabase/migrations (older ones) should have a matching enable row level security statement. For projects that use Supabase, the ScanMySaaS repo scan flags tables created in SQL migrations without one. Then test with two accounts: user A must not be able to read or change user B's rows." },
  { question: "Is the Supabase anon key in my Lovable app a problem?", answer: "No. The publishable key (sb_publishable_…, which replaces the legacy anon key) is designed to be public and will always be visible in a Lovable app's JavaScript. It is only safe when every exposed table has RLS with correct policies. The secret key (sb_secret_…, which replaces the legacy service_role key) is different: it bypasses RLS and must never appear in client code or the repository. Supabase is deprecating the legacy anon and service_role keys by the end of 2026, so this is a good moment to rotate to the new keys." },
  { question: "Can I scan a private Lovable GitHub repository?", answer: "Yes, on Starter or Pro. Sign in, install the ScanMySaaS GitHub App on the repository Lovable created, and pick it from the list. The app only requests read access to contents and metadata. The scan runs in the background, so you can leave the page and come back to the report." },
  { question: "Is the Lovable security scan free?", answer: "The first website scan and public repository scans are free, with no credit card. Private repositories and the AI logic review, which reads server routes and edge functions for missing authorization, are included in the paid plans." },
];

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebApplication",
      "@id": `${SITE_URL}${PATH}#application`,
      name: "ScanMySaaS Lovable Security Scanner",
      url: `${SITE_URL}${PATH}`,
      applicationCategory: "SecurityApplication",
      operatingSystem: "Any",
      isAccessibleForFree: true,
      offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
      description: "A security scan for apps built with Lovable: checks the published app and its GitHub repository for Supabase RLS gaps, exposed keys, missing headers and source maps.",
    },
    {
      "@type": "HowTo",
      "@id": `${SITE_URL}${PATH}#howto`,
      name: "How to run a Lovable security scan",
      step: steps.map((step, index) => ({ "@type": "HowToStep", position: index + 1, name: step.title, text: step.copy })),
    },
    { "@type": "FAQPage", "@id": `${SITE_URL}${PATH}#faq`, mainEntity: faqs.map((faq) => ({ "@type": "Question", name: faq.question, acceptedAnswer: { "@type": "Answer", text: faq.answer } })) },
    { "@type": "BreadcrumbList", itemListElement: [{ "@type": "ListItem", position: 1, name: "Home", item: SITE_URL }, { "@type": "ListItem", position: 2, name: "Lovable Security Scan", item: `${SITE_URL}${PATH}` }] },
  ],
};

function CoverageTag({ label }: { label: Coverage }) {
  return <span className={`inline-flex items-center rounded-full border px-2.5 py-1 text-[11px] font-medium ${coverageStyle[label]}`}>{label}</span>;
}

export default function LovableSecurityScannerPage() {
  return <main className="min-h-screen">
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />
    <SiteHeader />

    <section className="relative overflow-hidden border-b border-white/[0.07] py-16 sm:py-24">
      <div className="pointer-events-none absolute inset-0 -z-10 hairline-grid [mask-image:linear-gradient(to_bottom,black,transparent_82%)]" />
      <div className="pointer-events-none absolute -top-40 right-[-10%] -z-10 h-[28rem] w-[28rem] rounded-full bg-[var(--signal)]/[0.07] blur-3xl" />
      <div className="app-shell">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5 text-xs text-[#b4bdc9]"><ScanSearch className="h-3.5 w-3.5 text-[var(--signal)]" /> Built for Lovable + Supabase apps · free to start</div>
          <h1 className="display-title mt-7 text-balance">Lovable security scan <span className="text-[var(--signal)]">before your users find the gaps.</span></h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-[#9aa4b1]">Check the Lovable app you published and the GitHub repo it syncs to. Find Supabase tables without RLS, secret keys in client code, missing headers and public source maps, with a fix prompt you can paste straight into Lovable.</p>
        </div>
        <div className="mt-9"><ScannerForm /></div>
        <div className="mt-5 flex flex-wrap items-center gap-x-5 gap-y-2 text-xs text-[#778191]">
          {["Works with lovable.app and custom domains", "No credit card", "Only scan apps you own"].map((item) => <span key={item} className="inline-flex items-center gap-1.5"><CheckCircle2 className="h-3.5 w-3.5 text-[var(--signal)]" />{item}</span>)}
          <Link href="/repo-scan" className="inline-flex items-center gap-1.5 font-semibold text-[var(--signal)] hover:underline"><Github className="h-3.5 w-3.5" /> Scan the Lovable GitHub repo instead <ArrowRight className="h-3.5 w-3.5" /></Link>
        </div>
      </div>
    </section>

    <section className="app-shell py-20 sm:py-28">
      <div className="grid gap-6 lg:grid-cols-[1fr_auto] lg:items-end">
        <div className="max-w-2xl"><p className="eyebrow">By severity</p><h2 className="section-title mt-4 text-balance">Common Lovable security issues.</h2><p className="mt-5 text-sm leading-7 text-[#8f99a7]">Lovable apps share a recognizable stack: a React front end talking directly to Supabase. That makes the failure modes predictable. Each issue below is tagged with how it gets caught.</p></div>
        <div className="flex flex-wrap gap-2">{(Object.keys(coverageStyle) as Coverage[]).map((label) => <CoverageTag key={label} label={label} />)}</div>
      </div>
      <div className="mt-12 space-y-10">{issueGroups.map((group) => <div key={group.severity}>
        <div className="flex flex-wrap items-center gap-3"><span className={`rounded-md border px-2.5 py-1 font-mono text-xs font-semibold uppercase tracking-[.12em] ${group.tone}`}>{group.severity}</span><p className="text-sm text-[#7f8998]">{group.summary}</p></div>
        <div className="mt-5 grid gap-4 md:grid-cols-2">{group.issues.map((issue) => <article key={issue.title} className="surface-muted flex flex-col rounded-2xl p-6 sm:p-7">
          <issue.icon className="h-5 w-5 text-[var(--signal)]" />
          <h3 className="mt-4 text-lg font-semibold">{issue.title}</h3>
          <p className="mt-2 flex-1 text-sm leading-7 text-[#8f99a7]">{issue.copy}</p>
          <div className="mt-5 flex flex-wrap gap-2">{issue.coverage.map((label) => <CoverageTag key={label} label={label} />)}</div>
        </article>)}</div>
      </div>)}</div>
      <p className="mt-10 max-w-3xl text-xs leading-6 text-[#6f7a89]">Manual tests are things no outside scanner can prove, such as whether a policy blocks a second user. We list them because a clean scan is not the same as a safe app. The <Link href="/guides/supabase-security-for-vibe-coded-apps" className="text-[var(--signal)] hover:underline">Supabase security checklist</Link> walks through each test.</p>
    </section>

    <section className="border-y border-white/[0.07] bg-[#0a0e14] py-20 sm:py-28">
      <div className="app-shell">
        <div className="max-w-2xl"><p className="eyebrow">How it works</p><h2 className="mt-4 text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">Run a Lovable security scan in four steps.</h2></div>
        <ol className="mt-12 grid gap-px overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.08] sm:grid-cols-2 lg:grid-cols-4">{steps.map((step, index) => <li key={step.title} className="bg-[#0d1219] p-6 sm:p-8">
          <div className="flex items-center justify-between"><span className="font-mono text-xs text-[var(--signal)]">STEP {String(index + 1).padStart(2, "0")}</span><step.icon className="h-4 w-4 text-[#6f7a89]" /></div>
          <h3 className="mt-8 text-lg font-semibold">{step.title}</h3>
          <p className="mt-3 text-sm leading-6 text-[#87919f]">{step.copy}</p>
        </li>)}</ol>
      </div>
    </section>

    <section className="app-shell py-20 sm:py-28">
      <div className="grid gap-10 lg:grid-cols-[0.8fr_1.2fr] lg:gap-20">
        <div><p className="eyebrow">Second opinion</p><h2 className="mt-4 text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">Use Lovable&apos;s security scan. Then check from the outside.</h2></div>
        <div className="grid gap-4 sm:grid-cols-2">
          <article className="surface-muted rounded-2xl p-6"><h3 className="font-semibold">Lovable&apos;s security check</h3><ul className="mt-4 space-y-3 text-sm leading-6 text-[#8f99a7]">{["Quick scan of database rules and dependencies when you publish", "Deep scan of your code, started on demand", "Fixes run inside the same project"].map((item) => <li key={item} className="flex gap-2"><CheckCircle2 className="mt-1 h-3.5 w-3.5 shrink-0 text-[#6f7a89]" />{item}</li>)}</ul></article>
          <article className="rounded-2xl border border-[var(--signal)]/25 bg-[var(--signal)]/[0.05] p-6"><h3 className="font-semibold">ScanMySaaS</h3><ul className="mt-4 space-y-3 text-sm leading-6 text-[#b3bbc5]">{["Scans the deployed app from the outside: headers, cookies, TLS, exposed files", "Reads the synced GitHub repo, including edits made outside Lovable", "Shareable report, history and rescans to prove fixes"].map((item) => <li key={item} className="flex gap-2"><CheckCircle2 className="mt-1 h-3.5 w-3.5 shrink-0 text-[var(--signal)]" />{item}</li>)}</ul></article>
          <div className="flex items-start gap-3 rounded-2xl border border-white/[0.08] p-5 sm:col-span-2"><Bot className="mt-0.5 h-5 w-5 shrink-0 text-[var(--signal)]" /><p className="text-sm leading-6 text-[#8f99a7]">On paid plans, the AI logic review reads server routes and edge functions in the repository and flags code that changes data without checking who is signed in, with the exact file and line.</p></div>
        </div>
      </div>
    </section>

    <section className="border-t border-white/[0.07] bg-[#0a0e14] py-20 sm:py-28">
      <div className="app-shell grid gap-12 lg:grid-cols-[0.8fr_1.2fr] lg:gap-20">
        <div><p className="eyebrow">Lovable security FAQ</p><h2 className="mt-4 text-3xl font-semibold tracking-[-0.04em]">Questions before you launch.</h2><div className="mt-8 flex flex-col gap-3 text-sm"><Link href="/guides/vibe-coding-security-checklist" className="inline-flex items-center gap-2 text-[var(--signal)] hover:underline">Vibe coding security checklist <ArrowRight className="h-3.5 w-3.5" /></Link><Link href="/vibe-coding-security" className="inline-flex items-center gap-2 text-[var(--signal)] hover:underline">Security for other AI coding tools <ArrowRight className="h-3.5 w-3.5" /></Link><Link href="/pricing" className="inline-flex items-center gap-2 text-[var(--signal)] hover:underline">Plans for private repos <ArrowRight className="h-3.5 w-3.5" /></Link><Link href="/free-website-vulnerability-scanner" className="inline-flex items-center gap-2 text-[var(--signal)] hover:underline">Free website vulnerability scanner <ArrowRight className="h-3.5 w-3.5" /></Link></div></div>
        <div className="divide-y divide-white/[0.08] border-y border-white/[0.08]">{faqs.map((faq) => <details key={faq.question} className="group py-5"><summary className="flex cursor-pointer list-none items-center justify-between gap-4 font-medium">{faq.question}<span className="text-[#6e7988] transition group-open:rotate-45">+</span></summary><p className="max-w-2xl pt-4 text-sm leading-7 text-[#8f99a7]">{faq.answer}</p></details>)}</div>
      </div>
      <div className="app-shell mt-16 border-t border-white/[0.08] pt-8"><p className="text-xs font-semibold uppercase tracking-[.12em] text-[#697483]">Primary guidance</p><div className="mt-4 flex flex-wrap gap-x-6 gap-y-3 text-xs"><a href="https://supabase.com/docs/guides/database/postgres/row-level-security" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[#9aa4b1] hover:text-white">Supabase: Row Level Security <ArrowUpRight className="h-3.5 w-3.5" /></a><a href="https://supabase.com/docs/guides/api/api-keys" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[#9aa4b1] hover:text-white">Supabase: API keys <ArrowUpRight className="h-3.5 w-3.5" /></a><a href="https://docs.lovable.dev/features/security" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[#9aa4b1] hover:text-white">Lovable: Security <ArrowUpRight className="h-3.5 w-3.5" /></a><a href="https://docs.lovable.dev/features/database" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[#9aa4b1] hover:text-white">Lovable: Database <ArrowUpRight className="h-3.5 w-3.5" /></a><a href="https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[#9aa4b1] hover:text-white">Supabase: new tables no longer exposed automatically <ArrowUpRight className="h-3.5 w-3.5" /></a></div></div>
    </section>

    <section className="app-shell py-20">
      <div className="rounded-3xl border border-[var(--signal)]/20 bg-[var(--signal)]/[0.045] p-8 sm:p-12">
        <h2 className="max-w-2xl text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">Scan your Lovable app now.</h2>
        <p className="mt-4 max-w-xl text-sm leading-7 text-[#909aa8]">Start with the live URL. It needs no account.</p>
        <div className="mt-8"><ScannerForm compact /></div>
      </div>
    </section>
    <SiteFooter />
  </main>;
}
