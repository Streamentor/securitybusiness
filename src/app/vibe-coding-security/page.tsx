import type { Metadata } from "next";
import Link from "next/link";
import {
  ArrowRight,
  ArrowUpRight,
  Bot,
  Code2,
  Database,
  FileKey,
  Github,
  GitPullRequestArrow,
  Globe2,
  ShieldCheck,
} from "lucide-react";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";

const SITE_URL = "https://www.scanmysaas.com";

export const metadata: Metadata = {
  title: "Vibe Coding Security for AI-Built SaaS Apps",
  description: "Secure a vibe-coded app built with Codex, Claude, Cursor, or another AI coding agent. Scan GitHub secrets, workflows, Supabase RLS, client exposure, and the deployed website.",
  alternates: { canonical: "/vibe-coding-security" },
  openGraph: { type: "article", title: "Vibe Coding Security for AI-Built SaaS Apps", description: "A practical security workflow for AI-built SaaS apps, from GitHub repository checks to the deployed website.", url: "/vibe-coding-security" },
};

const boundaries = [
  { icon: FileKey, title: "Secrets", copy: "Environment files, provider tokens, database URLs, private keys, and public client variables." },
  { icon: ShieldCheck, title: "Authorization", copy: "Server routes and database rules that must separate users, roles, and tenants after login." },
  { icon: Database, title: "Data access", copy: "Supabase RLS, service-role placement, exposed tables, storage policies, and administrative clients." },
  { icon: GitPullRequestArrow, title: "CI and releases", copy: "GitHub Actions permissions, untrusted pull requests, mutable actions, and deployment secrets." },
  { icon: Globe2, title: "Public app", copy: "TLS, headers, cookies, exposed files, source maps, redirects, CORS, and browser-facing behavior." },
];

const faqs = [
  { question: "Is vibe coding insecure?", answer: "AI-assisted code is not automatically insecure. The risk appears when generated code is accepted without reviewing secrets, authorization, database access, workflows, dependencies, and production behavior. Treat generated code as unreviewed code and verify its security boundaries before release." },
  { question: "Can a website scanner find a committed .env file in GitHub?", answer: "Only if the file is also publicly deployed. The current ScanMySaaS repository scanner checks security-relevant files in the repository's current tree. GitHub secret scanning should remain enabled because it can also detect supported secrets in Git history, issues, pull requests, discussions, and wikis." },
  { question: "Does the public repository scanner execute code?", answer: "No. ScanMySaaS reads a bounded set of security-relevant text files from a public GitHub repository. It does not clone, install dependencies, run builds, or execute repository code." },
  { question: "How should private repositories be scanned?", answer: "Use a GitHub App with access limited to selected repositories and read-only metadata and contents permissions. Private repository support is planned for ScanMySaaS after the public read-only scanner is validated." },
];

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    { "@type": "Article", "@id": `${SITE_URL}/vibe-coding-security#article`, headline: "Vibe Coding Security for AI-Built SaaS Apps", description: "A practical security workflow for AI-built SaaS apps, from repository checks to the deployed website.", datePublished: "2026-08-13", dateModified: "2026-08-13", author: { "@type": "Organization", name: "ScanMySaaS Editorial Team", url: SITE_URL }, publisher: { "@type": "Organization", name: "ScanMySaaS", url: SITE_URL }, mainEntityOfPage: `${SITE_URL}/vibe-coding-security`, inLanguage: "en-US" },
    { "@type": "FAQPage", mainEntity: faqs.map((faq) => ({ "@type": "Question", name: faq.question, acceptedAnswer: { "@type": "Answer", text: faq.answer } })) },
    { "@type": "BreadcrumbList", itemListElement: [{ "@type": "ListItem", position: 1, name: "Home", item: SITE_URL }, { "@type": "ListItem", position: 2, name: "Vibe Coding Security", item: `${SITE_URL}/vibe-coding-security` }] },
  ],
};

export default function VibeCodingSecurityPage() {
  return <main className="min-h-screen">
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />
    <SiteHeader />
    <section className="relative overflow-hidden border-b border-white/[0.07] py-16 sm:py-24">
      <div className="pointer-events-none absolute inset-0 -z-10 hairline-grid [mask-image:linear-gradient(to_bottom,black,transparent_82%)]" />
      <div className="app-shell grid gap-12 lg:grid-cols-[0.9fr_1.1fr] lg:items-end lg:gap-16">
        <div><div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5 text-xs text-[#b4bdc9]"><Bot className="h-3.5 w-3.5 text-[var(--signal)]" /> Built with Codex, Claude, Cursor, or another coding agent</div><h1 className="display-title mt-7 text-balance">Vibe coding security <span className="text-[var(--signal)]">before users find the gaps.</span></h1></div>
        <div><p className="text-lg leading-8 text-[#9aa4b1]">A working AI-built app can still commit a live credential, trust the browser with an admin key, skip tenant isolation, or give a deployment workflow more access than it needs. Scan the repository and the public app as two separate attack surfaces.</p><div className="mt-7 flex flex-col gap-3 sm:flex-row"><Link href="/repo-scan" className="button-primary"><Github className="h-4 w-4" /> Scan a GitHub repository</Link><Link href="/#scan" className="button-secondary"><Globe2 className="h-4 w-4" /> Scan the deployed app</Link></div></div>
      </div>
    </section>

    <section className="app-shell py-20 sm:py-28">
      <div className="max-w-3xl"><p className="eyebrow">Five boundaries to verify</p><h2 className="section-title mt-4 text-balance">The code can pass tests and still cross the wrong boundary.</h2><p className="mt-5 text-sm leading-7 text-[#8f99a7]">Research on AI-generated code has found that functional success does not guarantee security. The useful response is a repeatable review at the places where authority changes hands.</p></div>
      <div className="mt-12 divide-y divide-white/[0.08] border-y border-white/[0.08]">{boundaries.map((boundary, index) => <article key={boundary.title} className="grid gap-3 py-6 sm:grid-cols-[2.5rem_2rem_13rem_1fr] sm:items-center"><boundary.icon className="h-5 w-5 text-[var(--signal)]" /><span className="font-mono text-xs text-[#596473]">{String(index + 1).padStart(2, "0")}</span><h3 className="font-semibold">{boundary.title}</h3><p className="text-sm leading-6 text-[#87919f]">{boundary.copy}</p></article>)}</div>
    </section>

    <section className="border-y border-white/[0.07] bg-[#0a0e14] py-20 sm:py-28">
      <div className="app-shell grid gap-10 lg:grid-cols-[0.75fr_1.25fr] lg:gap-20">
        <div><p className="eyebrow">A safer shipping loop</p><h2 className="mt-4 text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">Run the checks where the mistake is introduced.</h2><p className="mt-5 text-sm leading-7 text-[#8f99a7]">A production scan cannot see a private workflow file. A repository scan cannot prove that a CDN serves the right security headers. Use both.</p></div>
        <ol className="grid gap-px overflow-hidden rounded-2xl border border-white/[0.08] bg-white/[0.08] sm:grid-cols-2">{[
          ["01", "Before the first deployment", "Scan the repository. Rotate any committed secret before doing anything else."],
          ["02", "Before every merge", "Review workflow permissions, database migrations, and new server authorization paths."],
          ["03", "After production deploys", "Scan the live URL for TLS, headers, cookies, exposed files, source maps, and redirects."],
          ["04", "After a security fix", "Run a clean scan again. A deleted finding is evidence that the fix reached the public surface."],
        ].map(([number, title, copy]) => <li key={number} className="bg-[#0d1219] p-6 sm:p-8"><span className="font-mono text-xs text-[var(--signal)]">STEP {number}</span><h3 className="mt-8 text-lg font-semibold">{title}</h3><p className="mt-3 text-sm leading-6 text-[#87919f]">{copy}</p></li>)}</ol>
      </div>
    </section>

    <section className="app-shell py-20 sm:py-28">
      <div className="flex flex-col gap-6 sm:flex-row sm:items-end sm:justify-between"><div className="max-w-2xl"><p className="eyebrow">Practical security guides</p><h2 className="section-title mt-4">Fix the risky parts first.</h2></div><Link href="/guides" className="button-secondary">All guides <ArrowRight className="h-4 w-4" /></Link></div>
      <div className="mt-10 grid gap-4 lg:grid-cols-3">{[
        ["github-secret-scanning-for-vibe-coded-apps", "Committed .env or API key", "Rotate it, remove it from history, and stop the next leak before push."],
        ["github-actions-security-for-vibe-coded-apps", "AI-generated GitHub Actions", "Reduce token permissions and keep untrusted pull request code away from secrets."],
        ["supabase-security-for-vibe-coded-apps", "Supabase and tenant data", "Verify RLS, key placement, policies, storage, and server-side admin access."],
      ].map(([slug, title, copy]) => <Link key={slug} href={`/guides/${slug}`} className="group surface-muted rounded-2xl p-6"><Code2 className="h-5 w-5 text-[var(--signal)]" /><h3 className="mt-8 text-xl font-semibold tracking-[-0.025em]">{title}</h3><p className="mt-3 text-sm leading-6 text-[#87919f]">{copy}</p><span className="mt-6 inline-flex items-center gap-1.5 text-xs font-semibold text-[var(--signal)]">Read the guide <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-1" /></span></Link>)}</div>
    </section>

    <section className="border-t border-white/[0.07] bg-[#0a0e14] py-20">
      <div className="app-shell grid gap-12 lg:grid-cols-[0.8fr_1.2fr] lg:gap-20"><div><p className="eyebrow">Vibe coding security FAQ</p><h2 className="mt-4 text-3xl font-semibold tracking-[-0.04em]">What the scanners can and cannot prove.</h2></div><div className="divide-y divide-white/[0.08] border-y border-white/[0.08]">{faqs.map((faq) => <details key={faq.question} className="group py-5"><summary className="cursor-pointer list-none pr-6 font-medium">{faq.question}</summary><p className="max-w-2xl pt-4 text-sm leading-7 text-[#8f99a7]">{faq.answer}</p></details>)}</div></div>
      <div className="app-shell mt-16 border-t border-white/[0.08] pt-8"><p className="text-xs font-semibold uppercase tracking-[.12em] text-[#697483]">Research and primary guidance</p><div className="mt-4 flex flex-wrap gap-x-6 gap-y-3 text-xs"><a href="https://arxiv.org/abs/2512.03262" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[#9aa4b1] hover:text-white">Is Vibe Coding Safe? research paper <ArrowUpRight className="h-3.5 w-3.5" /></a><a href="https://docs.github.com/en/code-security/getting-started/github-security-features" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[#9aa4b1] hover:text-white">GitHub secret protection <ArrowUpRight className="h-3.5 w-3.5" /></a><a href="https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/" target="_blank" rel="noreferrer" className="inline-flex items-center gap-1.5 text-[#9aa4b1] hover:text-white">OWASP secure coding practices <ArrowUpRight className="h-3.5 w-3.5" /></a></div></div>
    </section>
    <SiteFooter />
  </main>;
}
