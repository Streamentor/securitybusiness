import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Scan Results — Vulnerability Report",
  description:
    "View detailed vulnerability scan results for your website. See severity ratings, vulnerability descriptions, and actionable fix suggestions to improve your web application security.",
  openGraph: {
    title: "Website Security Scan Report | ScanMySaaS",
    description:
      "Detailed website vulnerability scan results with severity ratings and fix suggestions.",
  },
  robots: {
    index: false,
    follow: true,
  },
};

export default function ScanLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
