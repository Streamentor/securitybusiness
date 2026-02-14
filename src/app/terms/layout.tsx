import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms of Service",
  description:
    "SecureSaaS terms of service — the legal agreement governing your use of our website vulnerability scanning platform, operated by Content Petit LLC.",
  alternates: {
    canonical: "https://scanmysaas.com/terms",
  },
  openGraph: {
    title: "Terms of Service | SecureSaaS",
    description:
      "Terms and conditions for using the SecureSaaS vulnerability scanning platform.",
    url: "https://scanmysaas.com/terms",
  },
};

export default function TermsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
