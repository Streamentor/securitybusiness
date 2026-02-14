import type { Metadata } from "next";
import { Inter } from "next/font/google";
import Providers from "@/components/Providers";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

export const metadata: Metadata = {
  title: "Website Vulnerability Scanner — Free Security Scan for Web Apps | SecureSaaS",
  description:
    "Free website vulnerability scanner that crawls your web app to detect vulnerabilities, security issues, and misconfigurations. Run an automated security scan — check SSL, headers, XSS, CSRF, open ports, and more. No credit card needed.",
  keywords: "website vulnerability scanner, web vulnerability scanner, vulnerability scanning tool, free website security, security scan, web application vulnerability, website scanner, vulnerability detection",
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <body className={`${inter.className} bg-gray-950 text-white antialiased`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
