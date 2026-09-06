import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description:
    "ScanMySaaS privacy policy — learn how Content Petit LLC collects, uses, and protects your data when you use our website security scanning service.",
  alternates: {
    canonical: "https://www.scanmysaas.com/privacy",
  },
  openGraph: {
    title: "Privacy Policy | ScanMySaaS",
    description:
      "Learn how we collect, use, and protect your data when you use ScanMySaaS.",
    url: "https://www.scanmysaas.com/privacy",
  },
};

export default function PrivacyLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
