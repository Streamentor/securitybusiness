import type { Metadata, Viewport } from "next";
import Providers from "@/components/Providers";
import "./globals.css";

const SITE_URL = "https://www.scanmysaas.com";
const SITE_NAME = "ScanMySaaS";
const TITLE = "SaaS Security Scanner: Free Website & GitHub Repo Scan | ScanMySaaS";
const DESCRIPTION = "Free SaaS security scanner for apps built with Cursor, Claude, Codex or Lovable. Scan your website and GitHub repo for exposed files, secrets and risky headers.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),
  title: { default: TITLE, template: "%s | ScanMySaaS" },
  description: DESCRIPTION,
  applicationName: SITE_NAME,
  authors: [{ name: SITE_NAME, url: SITE_URL }],
  creator: SITE_NAME,
  publisher: SITE_NAME,
  category: "Technology",
  alternates: { canonical: SITE_URL },
  keywords: [
    "website security scanner",
    "website vulnerability scanner",
    "web vulnerability scanner",
    "free website vulnerability scanner",
    "SaaS security scanner",
    "SaaS scanner",
    "GitHub repo scanner",
    "repository security scanner",
    "vibe coding security scanner",
    "scan SaaS",
    "security headers check",
    "SSL checker",
    "web application security scan",
    "exposed files scanner",
  ],
  openGraph: {
    type: "website",
    locale: "en_US",
    url: SITE_URL,
    siteName: SITE_NAME,
    title: TITLE,
    description: DESCRIPTION,
    images: [{ url: "/og-image.png?v=20260906", width: 1200, height: 630, alt: "ScanMySaaS website security report" }],
  },
  twitter: { card: "summary_large_image", title: TITLE, description: DESCRIPTION, images: ["/og-image.png?v=20260906"] },
  robots: {
    index: true,
    follow: true,
    googleBot: { index: true, follow: true, "max-video-preview": -1, "max-image-preview": "large", "max-snippet": -1 },
  },
  icons: {
    icon: [
      { url: "/favicon.ico", sizes: "any" },
      { url: "/favicon-32x32.png", sizes: "32x32", type: "image/png" },
      { url: "/favicon-16x16.png", sizes: "16x16", type: "image/png" },
      { url: "/icon.svg", type: "image/svg+xml" },
    ],
    apple: "/apple-touch-icon.png",
  },
  manifest: "/site.webmanifest",
};

export const viewport: Viewport = {
  themeColor: "#07090d",
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
};

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": `${SITE_URL}/#organization`,
      name: SITE_NAME,
      alternateName: ["Scan My SaaS", "ScanMySaaS security scanner"],
      url: SITE_URL,
      logo: { "@type": "ImageObject", url: `${SITE_URL}/icon-512.png` },
    },
    {
      "@type": "WebSite",
      "@id": `${SITE_URL}/#website`,
      name: SITE_NAME,
      url: SITE_URL,
      description: DESCRIPTION,
      publisher: { "@id": `${SITE_URL}/#organization` },
      inLanguage: "en-US",
    },
  ],
};

export default function RootLayout({ children }: Readonly<{ children: React.ReactNode }>) {
  return (
    <html lang="en" className="dark">
      <head>
        <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />
      </head>
      <body className="bg-[#07090d] text-white antialiased [font-family:Inter,ui-sans-serif,system-ui,-apple-system,BlinkMacSystemFont,'Segoe_UI',sans-serif]">
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
