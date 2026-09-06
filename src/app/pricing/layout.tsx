import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Pricing — Website Vulnerability Scanner Plans",
  description:
    "Start with one free website scan and one actionable fix. Starter includes 10 monthly scan credits for $29; Pro includes 30 for $79. Compare plans and coverage.",
  alternates: {
    canonical: "https://www.scanmysaas.com/pricing",
  },
  openGraph: {
    title: "Pricing — Website Security Scanner Plans | ScanMySaaS",
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
  return children;
}
