import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Login — Access Your Security Dashboard",
  description:
    "Sign in to your SecureSaaS account to view vulnerability scan results, manage your web application security, and access detailed remediation reports.",
  alternates: {
    canonical: "https://scanmysaas.com/login",
  },
  openGraph: {
    title: "Login — Access Your Security Dashboard | SecureSaaS",
    description:
      "Sign in to your SecureSaaS account to view vulnerability scan results and manage web application security.",
    url: "https://scanmysaas.com/login",
  },
  robots: {
    index: true,
    follow: true,
  },
};

export default function LoginLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return children;
}
