import type { Metadata } from "next";
import { pricingFaqs } from "@/lib/site-content";

export const metadata: Metadata = {
  title: { absolute: "Vulnerability Scanner Pricing: Free, $29 & $79 Plans | ScanMySaaS" },
  description:
    "Vulnerability scanner pricing: start free with a website scan and public repo scans. Starter $29/month (10 scans), Pro $79/month (30 scans) with private repo and AI code review.",
  alternates: {
    canonical: "https://www.scanmysaas.com/pricing",
  },
  openGraph: {
    title: "Vulnerability Scanner Pricing: Free, $29 & $79 Plans | ScanMySaaS",
    description:
      "Start with a free website security scan and one actionable fix. Upgrade for monthly credits, rollover, rescans, and remediation for all findings.",
    url: "https://www.scanmysaas.com/pricing",
  },
  robots: {
    index: true,
    follow: true,
  },
};

export default function PricingLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  const jsonLd = {
    "@context": "https://schema.org",
    "@type": "FAQPage",
    "@id": "https://www.scanmysaas.com/pricing#faq",
    mainEntity: pricingFaqs.map(([question, answer]) => ({ "@type": "Question", name: question, acceptedAnswer: { "@type": "Answer", text: answer } })),
  };
  return <><script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />{children}</>;
}
