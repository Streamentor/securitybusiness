import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Register — Start Free Vulnerability Scanning",
  description:
    "Create a free ScanMySaaS account and get one free scan credit. Check SSL, security headers, exposed files, risky cookies, and more. No credit card required.",
  alternates: {
    canonical: "https://www.scanmysaas.com/register",
  },
  openGraph: {
    title: "Register — Start a Free Website Security Scan | ScanMySaaS",
    description:
      "Create a free account and get a free scan credit to find vulnerabilities in your web applications.",
    url: "https://www.scanmysaas.com/register",
  },
  robots: {
    index: true,
    follow: true,
  },
};

export default function RegisterLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
