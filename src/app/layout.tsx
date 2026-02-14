import type { Metadata } from "next";
import { Inter } from "next/font/google";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "SecureSaaS - Website Security Scanner for SaaS Builders",
  description:
    "Free website security scanner for SaaS builders. Crawl your entire site and discover security vulnerabilities before hackers do. SSL, headers, XSS, CSRF and more.",
  keywords: "website security scanner, SaaS security, vulnerability scanner, free security audit",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-gray-950 text-white antialiased`}>
        {children}
      </body>
    </html>
  );
}
