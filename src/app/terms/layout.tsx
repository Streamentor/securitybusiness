import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Terms of Service",
  description:
    "ScanMySaaS terms of service — the legal agreement governing your use of our website security scanning platform, operated by Content Petit LLC.",
  alternates: {
    canonical: "https://www.scanmysaas.com/terms",
  },
  openGraph: {
    title: "Terms of Service | ScanMySaaS",
    description:
      "Terms and conditions for using the ScanMySaaS website security scanning platform.",
    url: "https://www.scanmysaas.com/terms",
  },
};

export default function TermsLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
