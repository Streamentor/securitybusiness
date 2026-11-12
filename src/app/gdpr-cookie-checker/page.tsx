import type { Metadata } from "next";
import Link from "next/link";
import { Accessibility, ArrowRight, Ban, Bot, CheckCircle2, Cookie, FileText, Globe2, MailCheck, ScanEye } from "lucide-react";
import { SiteHeader } from "@/components/SiteHeader";
import { SiteFooter } from "@/components/SiteFooter";
import { ScannerForm } from "@/components/ScannerForm";

const SITE_URL = "https://www.scanmysaas.com";
const PATH = "/gdpr-cookie-checker";

export const metadata: Metadata = {
  title: { absolute: "GDPR Cookie Checker: Website Privacy Scan | ScanMySaaS" },
  description: "Check your site for trackers that load before consent, a missing Reject button, privacy policy gaps and accessibility issues, with the URL for each finding.",
  alternates: { canonical: PATH },
  openGraph: {
    title: "GDPR Cookie Checker | ScanMySaaS",
    description: "Find trackers that load before consent, privacy policy gaps and accessibility issues on your SaaS website.",
    url: PATH,
    type: "website",
  },
};

const checks = [
  { icon: Cookie, plan: "Every plan", title: "Trackers and consent tools", copy: "Google Analytics, Google Ads, Meta Pixel, LinkedIn, TikTok, Hotjar, Clarity, PostHog and other tags found in your HTML, and whether a consent tool such as Cookiebot, Usercentrics or Google consent mode is there to control them." },
  { icon: ScanEye, plan: "Starter and Pro", title: "Real browser consent test", copy: "The page is opened in Chromium with no clicks. Tracking cookies set before consent are listed by name. Then the scanner clicks Reject, reloads, and checks that they do not come back. When ad pixels are present, a third visit sends the Global Privacy Control signal." },
  { icon: Ban, plan: "Starter and Pro", title: "Reject as easy as Accept", copy: "Flags a cookie banner that offers Accept on its first screen but no Reject or Necessary only button." },
  { icon: FileText, plan: "Every plan", title: "Privacy policy and terms", copy: "Looks for privacy and terms links in your footer, in English, German, French, Spanish, Italian and Serbian, then reads the policy and lists trackers on your site that it never names." },
  { icon: Bot, plan: "Pro", title: "AI privacy policy review", copy: "Checks the policy for the topics GDPR Article 13 lists: who you are, purposes, legal basis, recipients, transfers, retention, rights and complaints. The model only marks topics as covered or not; the finding text is fixed." },
  { icon: MailCheck, plan: "Every plan", title: "Forms", copy: "Email forms with no privacy notice next to them, and marketing checkboxes that are ticked by default." },
  { icon: Globe2, plan: "Every plan", title: "US opt-out link", copy: "When advertising pixels are present, checks for a \"Do Not Sell or Share\" or \"Your Privacy Choices\" link." },
  { icon: Accessibility, plan: "Every plan", title: "Accessibility basics", copy: "Images without alt text, form fields without labels, icon buttons without a name, a missing page language and disabled zoom. Starter and Pro add a contrast sample from the browser test." },
];

const limits = [
  "It is not legal advice and does not certify compliance. Whether a rule applies depends on where you and your users are, your company size and what data you process.",
  "The browser runs from a US data center. A banner shown only to EU visitors may not appear, so confirm a finding from an EU connection.",
  "A cookie declaration or banner rendered only by JavaScript is invisible to the HTML check on the free plan. The browser test on Starter and Pro sees it.",
  "Pages behind login, your backend processors and your data retention are not visible from outside.",
];

const faqs = [
  { question: "Is the GDPR cookie checker free?", answer: "Yes. Privacy and consent checks run inside the free website scan: trackers in your HTML, consent tool detection, privacy policy and terms links, the policy compared with your trackers, form checks and accessibility basics. The real browser consent test runs on Starter and Pro, and the AI privacy policy review on Pro." },
  { question: "Do these findings lower my security score?", answer: "No. Privacy, consent and accessibility findings appear in their own section of the report and do not change the security score." },
  { question: "How does the scanner know a cookie was set before consent?", answer: "On Starter and Pro it opens your homepage in a clean Chromium profile, waits for the page to load without clicking anything, and reads the cookies. Cookie names such as _ga, _gcl_au, _fbp or _hjSessionUser are matched to the service that sets them. Google consent mode pings without cookies are not counted." },
  { question: "Why does it say I have no cookie banner when I do?", answer: "Two common reasons: the banner is shown only to visitors in the EU, and the test browser is in the US, or the free HTML check cannot see a banner that JavaScript renders. Check from an EU connection, or run a paid scan with the browser test." },
  { question: "Is this a GDPR compliance certificate?", answer: "No. It finds common, visible problems with evidence for each one. A privacy lawyer should review your policy and setup if you have users in the EU, UK or California." },
];

const jsonLd = {
  "@context": "https://schema.org",
  "@graph": [
    {
      "@type": "WebApplication",
      "@id": `${SITE_URL}${PATH}#application`,
      name: "ScanMySaaS GDPR Cookie Checker",
      url: `${SITE_URL}${PATH}`,
      applicationCategory: "SecurityApplication",
      operatingSystem: "Any",
      isAccessibleForFree: true,
      offers: { "@type": "Offer", price: "0", priceCurrency: "USD" },
      description: "Checks a website for trackers that load before consent, missing reject buttons, privacy policy gaps and basic accessibility issues.",
    },
    { "@type": "FAQPage", "@id": `${SITE_URL}${PATH}#faq`, mainEntity: faqs.map((faq) => ({ "@type": "Question", name: faq.question, acceptedAnswer: { "@type": "Answer", text: faq.answer } })) },
    { "@type": "BreadcrumbList", itemListElement: [{ "@type": "ListItem", position: 1, name: "Home", item: SITE_URL }, { "@type": "ListItem", position: 2, name: "GDPR Cookie Checker", item: `${SITE_URL}${PATH}` }] },
  ],
};

export default function GdprCookieCheckerPage() {
  return <main className="min-h-screen">
    <script type="application/ld+json" dangerouslySetInnerHTML={{ __html: JSON.stringify(jsonLd).replace(/</g, "\\u003c") }} />
    <SiteHeader />
    <section className="relative overflow-hidden border-b border-white/[0.07] py-16 sm:py-24">
      <div className="pointer-events-none absolute inset-0 -z-10 hairline-grid [mask-image:linear-gradient(to_bottom,black,transparent_82%)]" />
      <div className="app-shell">
        <div className="max-w-3xl">
          <div className="inline-flex items-center gap-2 rounded-full border border-white/10 bg-white/[0.035] px-3 py-1.5 text-xs text-[#b4bdc9]"><Cookie className="h-3.5 w-3.5 text-[var(--signal)]" /> Part of every website scan</div>
          <h1 className="display-title mt-7 text-balance">GDPR cookie checker <span className="text-[var(--signal)]">for your SaaS website.</span></h1>
          <p className="mt-6 max-w-2xl text-lg leading-8 text-[#9aa4b1]">Most cookie banners fail quietly: Google Analytics and the Meta Pixel set their cookies before anyone clicks Accept. Enter your URL to see which trackers your site loads, whether they wait for consent, and what your privacy policy leaves out.</p>
        </div>
        <div className="mt-9 max-w-3xl"><ScannerForm /></div>
        <div className="mt-5 flex flex-wrap gap-x-5 gap-y-2 text-xs text-[#778191]">{["Trackers named by service", "Affected URL on every finding", "Does not change your security score", "Not legal advice"].map((item) => <span key={item} className="inline-flex items-center gap-1.5"><CheckCircle2 className="h-3.5 w-3.5 text-[var(--signal)]" />{item}</span>)}</div>
      </div>
    </section>

    <section className="app-shell py-20 sm:py-28">
      <div className="max-w-2xl"><p className="eyebrow">What it checks</p><h2 className="section-title mt-4 text-balance">Cookies, privacy policy, forms and accessibility</h2></div>
      <div className="mt-12 grid gap-4 md:grid-cols-2">{checks.map((check) => <article key={check.title} className="surface-muted flex flex-col rounded-2xl p-6 sm:p-7"><div className="flex items-center justify-between gap-3"><check.icon className="h-5 w-5 text-[var(--signal)]" /><span className="rounded-full border border-white/10 px-2.5 py-1 text-[0.66rem] font-semibold uppercase tracking-[.08em] text-[#8f99a7]">{check.plan}</span></div><h3 className="mt-4 text-lg font-semibold">{check.title}</h3><p className="mt-2 flex-1 text-sm leading-7 text-[#8f99a7]">{check.copy}</p></article>)}</div>
    </section>

    <section className="border-y border-white/[0.07] bg-[#0a0e14] py-20 sm:py-24">
      <div className="app-shell grid gap-12 lg:grid-cols-2 lg:gap-16">
        <div>
          <h2 className="text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">What a finding looks like</h2>
          <p className="mt-5 text-sm leading-7 text-[#8f99a7]">Each finding names the evidence, so you can check it yourself in DevTools before changing anything. For example: <span className="text-[#cbd3df]">&quot;On a first visit with no clicks, a real browser received these tracking cookies: _ga, _gcl_au, _fbp. A cookie banner was shown, but the cookies were already set.&quot;</span> The fix explains how to hold the tags back, with the Google consent mode snippet to paste.</p>
          <p className="mt-5 text-sm leading-7 text-[#8f99a7]">Read the full method in the <Link href="/guides/cookie-consent-for-saas" className="text-[var(--signal)] hover:underline">cookie consent guide</Link> and the <Link href="/guides/privacy-policy-checklist-for-saas" className="text-[var(--signal)] hover:underline">privacy policy checklist</Link>.</p>
        </div>
        <div>
          <h2 className="text-3xl font-semibold tracking-[-0.04em] sm:text-4xl">What it cannot tell you</h2>
          <ul className="mt-6 space-y-3">{limits.map((item) => <li key={item} className="flex gap-3 text-sm leading-6 text-[#a3acb8]"><span className="mt-2 h-1.5 w-1.5 shrink-0 rounded-full bg-[var(--amber)]" />{item}</li>)}</ul>
        </div>
      </div>
    </section>

    <section className="app-shell py-20 sm:py-28">
      <div className="max-w-2xl"><p className="eyebrow">FAQ</p><h2 className="section-title mt-4 text-balance">GDPR cookie checker FAQ</h2></div>
      <div className="mt-10 divide-y divide-white/[0.08] border-y border-white/[0.08]">{faqs.map((faq) => <details key={faq.question} className="group py-5"><summary className="flex cursor-pointer list-none items-center justify-between gap-4 text-base font-medium text-white">{faq.question}<span className="text-[#6e7988] transition group-open:rotate-45">+</span></summary><p className="mt-3 max-w-3xl text-sm leading-7 text-[#8f99a7]">{faq.answer}</p></details>)}</div>
      <p className="mt-8 text-sm text-[#8f99a7]">The same scan checks security too: see the <Link href="/free-website-vulnerability-scanner" className="text-[var(--signal)] hover:underline">free website vulnerability scanner</Link>, or compare <Link href="/pricing" className="text-[var(--signal)] hover:underline">plans</Link> for the browser consent test. <Link href="/" className="inline-flex items-center gap-1 text-[var(--signal)] hover:underline">Scan your site <ArrowRight className="h-3.5 w-3.5" /></Link></p>
    </section>
    <SiteFooter />
  </main>;
}
