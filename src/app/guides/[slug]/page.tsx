import type { Metadata } from "next";
import Link from "next/link";
import { notFound } from "next/navigation";
import { ArrowLeft, ArrowRight, CheckCircle2, Clock3 } from "lucide-react";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";
import { getGuide, guides } from "@/lib/guides";

const SITE_URL = "https://www.scanmysaas.com";

export function generateStaticParams() {
  return guides.map((guide) => ({ slug: guide.slug }));
}

export async function generateMetadata({ params }: { params: Promise<{ slug: string }> }): Promise<Metadata> {
  const { slug } = await params;
  const guide = getGuide(slug);
  if (!guide) return {};
  return {
    title: guide.seoTitle ? { absolute: `${guide.seoTitle} | ScanMySaaS` } : guide.title,
    description: guide.description,
    alternates: { canonical: `/guides/${guide.slug}` },
    openGraph: { type: "article", title: guide.title, description: guide.description, url: `/guides/${guide.slug}`, publishedTime: guide.publishedAt || "2026-08-13", modifiedTime: guide.updatedAt || "2026-08-13" },
  };
}

export default async function GuidePage({ params }: { params: Promise<{ slug: string }> }) {
  const { slug } = await params;
  const guide = getGuide(slug);
  if (!guide) notFound();
  const related = guides.filter((item) => item.slug !== guide.slug).slice(0, 2);
  const isRepositoryGuide = guide.slug.includes("github-") || guide.slug.includes("supabase-");
  const url = `${SITE_URL}/guides/${guide.slug}`;
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      { "@type": "Article", "@id": `${url}#article`, headline: guide.title, description: guide.description, datePublished: guide.publishedAt || "2026-08-13", dateModified: guide.updatedAt || "2026-08-13", author: { "@type": "Organization", name: "ScanMySaaS Editorial Team", url: SITE_URL }, publisher: { "@type": "Organization", name: "ScanMySaaS", url: SITE_URL }, mainEntityOfPage: url, inLanguage: "en-US" },
      { "@type": "BreadcrumbList", itemListElement: [
        { "@type": "ListItem", position: 1, name: "Home", item: SITE_URL },
        { "@type": "ListItem", position: 2, name: "Guides", item: `${SITE_URL}/guides` },
        { "@type": "ListItem", position: 3, name: guide.title, item: url },
      ] },
    ],
  };

  return (
    <main className="min-h-screen">
      <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />
      <SiteHeader />
      <article>
        <header className="border-b border-white/[0.07]">
          <div className="app-shell py-14 sm:py-20">
            <Link href="/guides" className="inline-flex items-center gap-2 text-xs text-[#7f8998] hover:text-white"><ArrowLeft className="h-3.5 w-3.5" /> All guides</Link>
            <div className="mt-10 max-w-4xl">
              <p className="eyebrow">{guide.eyebrow}</p>
              <h1 className="mt-5 text-balance text-4xl font-semibold leading-[1.02] tracking-[-0.055em] sm:text-6xl">{guide.title}</h1>
              <p className="mt-6 max-w-3xl text-lg leading-8 text-[#9ba5b2]">{guide.description}</p>
              <div className="mt-7 flex flex-wrap items-center gap-4 text-xs text-[#727d8c]"><span>ScanMySaaS Editorial Team</span><span className="h-1 w-1 rounded-full bg-[#4f5966]" /><span className="inline-flex items-center gap-1.5"><Clock3 className="h-3.5 w-3.5" />{guide.readTime}</span><span>Updated {new Intl.DateTimeFormat("en-US", { month: "long", day: "numeric", year: "numeric", timeZone: "UTC" }).format(new Date(guide.updatedAt || "2026-08-13"))}</span></div>
            </div>
          </div>
        </header>

        <div className="app-shell grid gap-12 py-12 lg:grid-cols-[minmax(0,1fr)_17rem] lg:py-16">
          <div className="max-w-3xl">
            <div className="space-y-5 text-lg leading-8 text-[#b3bbc5]">{guide.intro.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}</div>
            <Link href={isRepositoryGuide ? "/repo-scan" : "/free-website-vulnerability-scanner"} className="mt-8 flex items-center justify-between gap-4 rounded-xl border border-white/[0.08] bg-white/[0.03] px-5 py-4 text-sm text-[#cfd6de] transition hover:border-[var(--signal)]/30 hover:text-white"><span>{isRepositoryGuide ? "Check your repository for these issues with the free GitHub repo scanner." : "Check your site for these issues with the free website vulnerability scanner."}</span><span className="shrink-0 font-semibold text-[var(--signal)]">Scan now →</span></Link>
            <div className="mt-12 space-y-12">
              {guide.sections.map((section) => (
                <section key={section.heading}>
                  <h2 className="text-2xl font-semibold tracking-[-0.035em] text-white sm:text-3xl">{section.heading}</h2>
                  <div className="mt-5 space-y-4 text-[0.98rem] leading-8 text-[#a3acb8]">{section.paragraphs.map((paragraph) => <p key={paragraph}>{paragraph}</p>)}</div>
                  {section.bullets && <ul className="mt-6 space-y-3">{section.bullets.map((bullet) => <li key={bullet} className="flex gap-3 text-sm leading-6 text-[#a3acb8]"><CheckCircle2 className="mt-1 h-4 w-4 shrink-0 text-[var(--signal)]" /><span>{bullet}</span></li>)}</ul>}
                </section>
              ))}
            </div>
            {guide.sources && <section className="mt-12 border-t border-white/[0.08] pt-8"><h2 className="text-lg font-semibold text-white">Primary source</h2><ul className="mt-4 space-y-3">{guide.sources.map((source) => <li key={source.url}><a href={source.url} target="_blank" rel="noreferrer" className="inline-flex items-center gap-2 text-sm text-[var(--signal)] hover:underline">{source.label} <ArrowRight className="h-3.5 w-3.5" /></a></li>)}</ul></section>}
            <div className="mt-14 rounded-2xl border border-[var(--signal)]/20 bg-[var(--signal)]/[0.045] p-6 sm:p-8"><p className="eyebrow">{isRepositoryGuide ? "Check your repository" : "Check your production site"}</p><h2 className="mt-3 text-2xl font-semibold tracking-[-0.03em]">See which of these issues are visible now.</h2><p className="mt-3 max-w-xl text-sm leading-6 text-[#909aa8]">{isRepositoryGuide ? "ScanMySaaS reads a bounded set of security-relevant files from a public GitHub repository. It never runs repository code or reveals matched secret values." : "ScanMySaaS checks the public surface and keeps the affected URL with every finding. Verify results before changing production."}</p><Link href={isRepositoryGuide ? "/repo-scan" : "/#scan"} className="button-primary mt-6">{isRepositoryGuide ? "Scan a public repository" : "Run a free scan"} <ArrowRight className="h-4 w-4" /></Link></div>
          </div>

          <aside className="lg:sticky lg:top-24 lg:self-start">
            <div className="surface-muted rounded-2xl p-5"><p className="text-xs font-semibold uppercase tracking-[.12em] text-[#6f7a89]">Related scanner checks</p><ul className="mt-5 space-y-3">{guide.relatedChecks.map((check) => <li key={check} className="flex gap-2 text-sm leading-5 text-[#aab3bf]"><CheckCircle2 className="mt-0.5 h-3.5 w-3.5 shrink-0 text-[var(--signal)]" />{check}</li>)}</ul></div>
          </aside>
        </div>
      </article>

      <section className="border-t border-white/[0.07] bg-[#0a0e14] py-16">
        <div className="app-shell"><p className="eyebrow">Keep reading</p><div className="mt-6 grid gap-4 md:grid-cols-2">{related.map((item) => <Link key={item.slug} href={`/guides/${item.slug}`} className="group surface-muted rounded-2xl p-6"><h2 className="text-xl font-semibold tracking-[-0.025em]">{item.title}</h2><p className="mt-3 text-sm leading-6 text-[#838e9d]">{item.description}</p><span className="mt-5 inline-flex items-center gap-2 text-xs font-semibold text-[var(--signal)]">Read guide <ArrowRight className="h-3.5 w-3.5 transition group-hover:translate-x-1" /></span></Link>)}</div></div>
      </section>
      <SiteFooter />
    </main>
  );
}
