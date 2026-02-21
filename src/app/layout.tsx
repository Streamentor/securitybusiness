import type { Metadata, Viewport } from "next";
import { Inter } from "next/font/google";
import Providers from "@/components/Providers";
import "./globals.css";

const inter = Inter({ subsets: ["latin"] });

const SITE_URL = "https://scanmysaas.com";
const SITE_NAME = "SecureSaaS";
const TITLE_DEFAULT =
  "Website Vulnerability Scanner — Free Security Scan for Web Apps | SecureSaaS";
const DESCRIPTION =
  "Free website vulnerability scanner that crawls your web app to detect vulnerabilities, security issues, and misconfigurations. Run an automated security scan — check SSL, headers, XSS, CSRF, open ports, and more. No credit card needed.";

export const metadata: Metadata = {
  metadataBase: new URL(SITE_URL),

  /* ---- Core ---- */
  title: {
    default: TITLE_DEFAULT,
    template: "%s | SecureSaaS",
  },
  description: DESCRIPTION,
  keywords: [
    "website vulnerability scanner",
    "web vulnerability scanner",
    "vulnerability scanning tool",
    "free website security",
    "security scan",
    "web application vulnerability",
    "website scanner",
    "vulnerability detection",
    "OWASP scanner",
    "SaaS security scanner",
    "automated security testing",
    "website security checker",
    "web app security scan",
    "online vulnerability scanner",
    "security audit tool",
    "XSS scanner",
    "CSRF detection",
    "SSL checker",
    "security headers check",
    "penetration testing tool",
  ],
  applicationName: SITE_NAME,
  authors: [{ name: SITE_NAME, url: SITE_URL }],
  creator: SITE_NAME,
  publisher: SITE_NAME,
  category: "Technology",
  classification: "Security Software",

  /* ---- Canonical & Alternates ---- */
  alternates: {
    canonical: SITE_URL,
  },

  /* ---- Open Graph ---- */
  openGraph: {
    type: "website",
    locale: "en_US",
    url: SITE_URL,
    siteName: SITE_NAME,
    title: TITLE_DEFAULT,
    description: DESCRIPTION,
    images: [
      {
        url: "/og-image.png",
        width: 1200,
        height: 630,
        alt: "SecureSaaS — Website Vulnerability Scanner",
        type: "image/png",
      },
    ],
  },

  /* ---- Twitter / X ---- */
  twitter: {
    card: "summary_large_image",
    title: TITLE_DEFAULT,
    description: DESCRIPTION,
    images: ["/og-image.png"],
    creator: "@securesaas",
  },

  /* ---- Robots ---- */
  robots: {
    index: true,
    follow: true,
    googleBot: {
      index: true,
      follow: true,
      "max-video-preview": -1,
      "max-image-preview": "large",
      "max-snippet": -1,
    },
  },

  /* ---- Icons ---- */
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

  /* ---- Verification (add your IDs later) ---- */
  // verification: {
  //   google: "YOUR_GOOGLE_SITE_VERIFICATION",
  //   yandex: "YOUR_YANDEX_VERIFICATION",
  // },
};

export const viewport: Viewport = {
  themeColor: [
    { media: "(prefers-color-scheme: dark)", color: "#030712" },
    { media: "(prefers-color-scheme: light)", color: "#030712" },
  ],
  width: "device-width",
  initialScale: 1,
  maximumScale: 5,
};

/* ---- JSON-LD Structured Data ---- */
const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "Organization",
      "@id": `${SITE_URL}/#organization`,
      name: SITE_NAME,
      url: SITE_URL,
      logo: {
        "@type": "ImageObject",
        url: `${SITE_URL}/og-image.png`,
      },
      sameAs: [],
    },
    {
      "@type": "WebSite",
      "@id": `${SITE_URL}/#website`,
      url: SITE_URL,
      name: SITE_NAME,
      publisher: { "@id": `${SITE_URL}/#organization` },
      description: DESCRIPTION,
      potentialAction: {
        "@type": "SearchAction",
        target: `${SITE_URL}/?q={search_term_string}`,
        "query-input": "required name=search_term_string",
      },
    },
    {
      "@type": "WebApplication",
      "@id": `${SITE_URL}/#app`,
      name: SITE_NAME,
      url: SITE_URL,
      applicationCategory: "SecurityApplication",
      operatingSystem: "Any",
      description: DESCRIPTION,
      offers: [
        {
          "@type": "Offer",
          name: "Free Plan",
          price: "0",
          priceCurrency: "USD",
          description: "1 free scan credit with full vulnerability report",
        },
        {
          "@type": "Offer",
          name: "Starter Plan",
          price: "29",
          priceCurrency: "USD",
          billingIncrement: "P1M",
          description:
            "15 scans/month with fix suggestions and PDF exports",
        },
        {
          "@type": "Offer",
          name: "Pro Plan",
          price: "79",
          priceCurrency: "USD",
          billingIncrement: "P1M",
          description:
            "Unlimited scans with priority scanning, API access, and dedicated support",
        },
      ],
      aggregateRating: {
        "@type": "AggregateRating",
        ratingValue: "4.8",
        reviewCount: "124",
        bestRating: "5",
        worstRating: "1",
      },
    },
    {
      "@type": "FAQPage",
      "@id": `${SITE_URL}/#faq`,
      mainEntity: [
        {
          "@type": "Question",
          name: "How does a website vulnerability scanner work?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "A website vulnerability scanner is an automated tool that scans web applications for security flaws. It crawls your site, analyzes pages for known vulnerabilities like XSS, CSRF, missing security headers, SSL misconfigurations, and exposed files. SecureSaaS runs 60+ automated vulnerability checks and generates a report with severity ratings and fix suggestions.",
          },
        },
        {
          "@type": "Question",
          name: "What types of vulnerability does the scanner detect?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Our scanner covers a wide range of web application vulnerability categories: SSL/TLS issues, missing or misconfigured security headers, cross-site scripting (XSS), cross-site request forgery (CSRF), cookie security flaws, sensitive file exposure, outdated libraries with known vulnerabilities, CORS misconfigurations, open redirects, SPF/DMARC email security, and more — covering the OWASP top 10 risks.",
          },
        },
        {
          "@type": "Question",
          name: "Is SecureSaaS a free website vulnerability scanner?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes — every account starts with 1 free scan credit. Run a complete website vulnerability scanning session with full results, severity scores, and vulnerability descriptions at no cost. Upgrade to Starter ($29/mo) or Pro ($79/mo) to unlock fix suggestions, PDF exports, and more credits.",
          },
        },
        {
          "@type": "Question",
          name: "How is this different from Burp Suite or Nikto?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Burp Suite is a comprehensive web application scanner and testing tools platform built for penetration testers and security professionals. Nikto is an open source web server scanner focused on server-level checks. SecureSaaS provides automated scanning focused on web app security — no installation, no CLI, no steep learning curve. Think of it as application security testing made simple for developers.",
          },
        },
        {
          "@type": "Question",
          name: "Do I need penetration testing experience to use this?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Not at all. Unlike commercial tools that require expertise in penetration testing or security check configurations, SecureSaaS is designed for developers and SaaS builders. Just enter your URL and our security scanner handles the rest — vulnerability discovery, severity scoring, and actionable remedies you can implement immediately.",
          },
        },
        {
          "@type": "Question",
          name: "Does it reduce false positives?",
          acceptedAnswer: {
            "@type": "Answer",
            text: "Yes. Our scanner is tuned specifically for modern web apps and SaaS platforms, which significantly reduces false positives compared to generic scanning tools. Every finding includes context about why it matters and how to verify it, so your security teams can focus on real issues — not noise.",
          },
        },
      ],
    },
  ],
};

export default function RootLayout({
  children,
}: Readonly<{
  children: React.ReactNode;
}>) {
  return (
    <html lang="en" className="dark">
      <head>
        <script
          type="application/ld+json"
          dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd) }}
        />
      </head>
      <body className={`${inter.className} bg-gray-950 text-white antialiased`}>
        <Providers>{children}</Providers>
      </body>
    </html>
  );
}
