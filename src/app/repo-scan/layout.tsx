import type { Metadata } from "next";
import { repoFaqs } from "@/lib/site-content";

const SITE_URL = "https://www.scanmysaas.com";

export const metadata: Metadata = {
  title: { absolute: "GitHub Repo Scanner: Scan Repos for Secrets & Vulnerabilities" },
  description: "Free GitHub repo scanner. Scan public or private repos (read-only) for committed .env files, API keys, risky GitHub Actions, Supabase RLS gaps and vulnerable dependencies.",
  alternates: { canonical: "/repo-scan" },
  openGraph: {
    title: "GitHub Repo Scanner for Secrets & Vulnerabilities | ScanMySaaS",
    description: "A read-only repository security scan for vibe-coded SaaS apps built with Codex, Claude, Cursor, and other AI coding tools.",
    url: "/repo-scan",
    type: "website",
  },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [{
  "@type": "WebApplication",
  "@id": `${SITE_URL}/repo-scan#application`,
  name: "ScanMySaaS GitHub Repository Scanner",
  url: `${SITE_URL}/repo-scan`,
  applicationCategory: "SecurityApplication",
  operatingSystem: "Any",
  isAccessibleForFree: true,
  description: "A read-only GitHub repo scanner for public and private repositories: committed secrets, risky workflows, client-code exposure, database configuration and vulnerable dependencies.",
  }, {
    "@type": "FAQPage",
    "@id": `${SITE_URL}/repo-scan#faq`,
    mainEntity: repoFaqs.map((faq) => ({ "@type": "Question", name: faq.question, acceptedAnswer: { "@type": "Answer", text: faq.answer } })),
  }],
};

export default function RepoScanLayout({ children }: { children: React.ReactNode }) {
  return <><script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />{children}</>;
}
