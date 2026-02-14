import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Privacy Policy",
  description:
    "SecureSaaS privacy policy — learn how Content Petit LLC collects, uses, and protects your data when you use our website vulnerability scanning service.",
  alternates: {
    canonical: "https://scanmysaas.com/privacy",
  },
  openGraph: {
    title: "Privacy Policy | SecureSaaS",
    description:
      "Learn how we collect, use, and protect your data when you use SecureSaaS.",
    url: "https://scanmysaas.com/privacy",
  },
};

export default function PrivacyLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
