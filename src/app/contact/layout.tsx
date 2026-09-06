import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Contact Us",
  description:
    "Get in touch with the ScanMySaaS team. Contact Content Petit LLC for support, billing questions, feature requests, or partnership inquiries.",
  alternates: {
    canonical: "https://www.scanmysaas.com/contact",
  },
  openGraph: {
    title: "Contact Us | ScanMySaaS",
    description:
      "Reach out to the ScanMySaaS team for support, questions, or feedback.",
    url: "https://www.scanmysaas.com/contact",
  },
};

export default function ContactLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
