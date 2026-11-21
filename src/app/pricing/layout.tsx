import type { Metadata } from "next";
import { pricingFaqs } from "@/lib/site-content";

export const metadata: Metadata = {
  title: { absolute: "Vulnerability Scanner Pricing: Free, $29 & $79 Plans | ScanMySaaS" },
  description:
    "Vulnerability scanner pricing: free website and public repo scans. Starter $29/mo (10 website scans) or Pro $79/mo (30) add private repos and AI logic review.",
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
  const SITE_URL = "https://www.scanmysaas.com";
  const monthly = (price: string) => ({ "@type": "UnitPriceSpecification", price, priceCurrency: "USD", unitText: "MONTH" });
  const jsonLd = {
    "@context": "https://schema.org",
    "@graph": [
      {
        "@type": "SoftwareApplication",
        "@id": `${SITE_URL}/#software-application`,
        name: "ScanMySaaS",
        url: SITE_URL,
        applicationCategory: "SecurityApplication",
        operatingSystem: "Any",
        offers: [
          { "@type": "Offer", name: "Free", price: "0", priceCurrency: "USD", url: `${SITE_URL}/pricing` },
          { "@type": "Offer", name: "Starter", price: "29", priceCurrency: "USD", url: `${SITE_URL}/pricing`, priceSpecification: monthly("29") },
          { "@type": "Offer", name: "Pro", price: "79", priceCurrency: "USD", url: `${SITE_URL}/pricing`, priceSpecification: monthly("79") },
        ],
      },
      {
        "@type": "FAQPage",
        "@id": `${SITE_URL}/pricing#faq`,
        mainEntity: pricingFaqs.map(([question, answer]) => ({ "@type": "Question", name: question, acceptedAnswer: { "@type": "Answer", text: answer } })),
      },
    ],
  };
  return <><script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />{children}</>;
}
