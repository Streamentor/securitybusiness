import type { Metadata } from "next";
import { repoFaqs } from "@/lib/site-content";

const SITE_URL = "https://www.scanmysaas.com";

export const metadata: Metadata = {
  title: { absolute: "GitHub Repo Security Scanner: Free Scan for Secrets & Vulnerabilities" },
  description: "GitHub repo scanner: free for public repos, private repos on paid plans. Finds committed .env files, API keys, risky Actions, RLS gaps and vulnerable deps.",
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
  description: "A read-only GitHub repo scanner. Public repositories are free; private repositories are included in Starter and Pro. Checks committed secrets, risky workflows, client-code exposure, Supabase RLS and vulnerable dependencies.",
  }, {
    "@type": "FAQPage",
    "@id": `${SITE_URL}/repo-scan#faq`,
    mainEntity: repoFaqs.map((faq) => ({ "@type": "Question", name: faq.question, acceptedAnswer: { "@type": "Answer", text: faq.answer } })),
  }],
};

export default function RepoScanLayout({ children }: { children: React.ReactNode }) {
  return <><script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />{children}</>;
}
