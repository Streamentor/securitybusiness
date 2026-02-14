import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Register — Start Free Vulnerability Scanning",
  description:
    "Create a free SecureSaaS account and get 3 free scan credits. Scan your website for vulnerabilities including XSS, CSRF, SSL issues, missing security headers, and more. No credit card required.",
  alternates: {
    canonical: "https://scanmysaas.com/register",
  },
  openGraph: {
    title: "Register — Start Free Vulnerability Scanning | SecureSaaS",
    description:
      "Create a free account and get 3 free scan credits to find vulnerabilities in your web applications.",
    url: "https://scanmysaas.com/register",
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
