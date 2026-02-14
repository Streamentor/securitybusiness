import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Security Dashboard",
  description:
    "View and manage all your vulnerability scans. Monitor your web application security posture, track scan history, and access detailed remediation reports.",
  robots: {
    index: false,
    follow: false,
  },
};

export default function DashboardLayout({
  children,
}: {
  children: React.ReactNode;
}) {
  return <>{children}</>;
}
