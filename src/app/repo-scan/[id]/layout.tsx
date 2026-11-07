import type { Metadata } from "next";

export const metadata: Metadata = {
  title: "Repository scan",
  robots: { index: false, follow: false },
};

export default function RepoScanReportLayout({ children }: { children: React.ReactNode }) {
  return children;
}
