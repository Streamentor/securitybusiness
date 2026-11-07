import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Login — Access Your Security Dashboard",
  description:
    "Sign in to your ScanMySaaS account to view scan results, manage website security checks, and access detailed remediation reports.",
  alternates: {
    canonical: "https://www.scanmysaas.com/login",
  },
  openGraph: {
    title: "Login — Access Your Security Dashboard | ScanMySaaS",
    description:
      "Sign in to your ScanMySaaS account to view scan results and manage website security checks.",
    url: "https://www.scanmysaas.com/login",
  },
  robots: {
    index: false,
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
