import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Contact Us",
  description:
    "Get in touch with the SecureSaaS team. Contact Content Petit LLC for support, billing questions, feature requests, or partnership inquiries.",
  alternates: {
    canonical: "https://scanmysaas.com/contact",
  },
  openGraph: {
    title: "Contact Us | SecureSaaS",
    description:
      "Reach out to the SecureSaaS team for support, questions, or feedback.",
    url: "https://scanmysaas.com/contact",
  },
};

export default function ContactLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
