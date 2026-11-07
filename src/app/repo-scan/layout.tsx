import type { Metadata } from "next";

const SITE_URL = "https://www.scanmysaas.com";

export const metadata: Metadata = {
  title: "Free GitHub Repository Security Scanner",
  description: "Scan a public GitHub repository for committed environment files, hardcoded secrets, risky GitHub Actions, exposed client keys, source maps, and missing Supabase RLS signals.",
  alternates: { canonical: "/repo-scan" },
  openGraph: {
    title: "Free GitHub Repository Security Scanner | ScanMySaaS",
    description: "A read-only repository security scan for vibe-coded SaaS apps built with Codex, Claude, Cursor, and other AI coding tools.",
    url: "/repo-scan",
    type: "website",
  },
};

const jsonLd = {
  "@context": "https://schema.org",
  "@type": "WebApplication",
  "@id": `${SITE_URL}/repo-scan#application`,
  name: "ScanMySaaS GitHub Repository Scanner",
  url: `${SITE_URL}/repo-scan`,
  applicationCategory: "SecurityApplication",
  operatingSystem: "Any",
  isAccessibleForFree: true,
  description: "A read-only public GitHub repository scanner for common secret, workflow, client-code, and database configuration risks.",
};

export default function RepoScanLayout({ children }: { children: React.ReactNode }) {
  return <><script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />{children}</>;
}
