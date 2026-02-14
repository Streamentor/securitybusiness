import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Pricing — Website Vulnerability Scanner Plans",
  description:
    "Choose the right vulnerability scanning plan for your needs. Free plan with 3 scans, Starter at $29/mo with fix suggestions, or Pro at $79/mo with unlimited scans, API access, and priority support.",
  alternates: {
    canonical: "https://scanmysaas.com/pricing",
  },
  openGraph: {
    title: "Pricing — Website Vulnerability Scanner Plans | SecureSaaS",
    description:
      "Affordable vulnerability scanning plans. Start free with 3 scans, or upgrade for unlimited scanning, fix suggestions, and PDF exports.",
    url: "https://scanmysaas.com/pricing",
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
