import Link from "next/link";
import { ArrowUpRight } from "lucide-react";
import { Brand } from "@/components/Brand";

export function SiteFooter() {
  return (
    <footer className="border-t border-white/[0.07] bg-[#080b10]">
      <div className="app-shell grid gap-10 py-12 md:grid-cols-[1.4fr_1fr_1fr]">
        <div>
          <Brand />
          <p className="mt-4 max-w-sm text-sm leading-6 text-[#7f8998]">Fast, readable website security checks for SaaS founders and small product teams.</p>
          <a href="https://theresanaiforthat.com/ai/website-vulnerability-scanner-securesaas/?ref=featured&v=1092536" target="_blank" rel="noreferrer" className="mt-5 inline-flex items-center gap-1.5 text-xs font-medium text-[#aeb7c4] hover:text-white">Featured on There&apos;s An AI For That <ArrowUpRight className="h-3.5 w-3.5" /></a>
        </div>
        <div className="grid content-start gap-3 text-sm">
          <p className="eyebrow !text-[#778191]">Product</p>
          <Link href="/#product" className="text-[#aeb7c4] hover:text-white">Sample report</Link>
          <Link href="/repo-scan" className="text-[#aeb7c4] hover:text-white">GitHub repo scanner</Link>
          <Link href="/free-website-vulnerability-scanner" className="text-[#aeb7c4] hover:text-white">Free website vulnerability scanner</Link>
          <Link href="/vibe-coding-security" className="text-[#aeb7c4] hover:text-white">Vibe coding security</Link>
          <Link href="/lovable-security-scanner" className="text-[#aeb7c4] hover:text-white">Lovable security scan</Link>
          <Link href="/guides/vibe-coding-security-checklist" className="text-[#aeb7c4] hover:text-white">Vibe coding security checklist</Link>
          <Link href="/#coverage" className="text-[#aeb7c4] hover:text-white">Security checks</Link>
          <Link href="/#demo" className="text-[#aeb7c4] hover:text-white">Product demo</Link>
          <Link href="/guides" className="text-[#aeb7c4] hover:text-white">SaaS security guides</Link>
          <Link href="/pricing" className="text-[#aeb7c4] hover:text-white">Pricing</Link>
          <Link href="/dashboard" className="text-[#aeb7c4] hover:text-white">Dashboard</Link>
        </div>
        <div className="grid content-start gap-3 text-sm">
          <p className="eyebrow !text-[#778191]">Company</p>
          <Link href="/contact" className="text-[#aeb7c4] hover:text-white">Contact</Link>
          <Link href="/privacy" className="text-[#aeb7c4] hover:text-white">Privacy</Link>
          <Link href="/terms" className="text-[#aeb7c4] hover:text-white">Terms</Link>
        </div>
      </div>
      <div className="app-shell flex flex-col gap-2 border-t border-white/[0.07] py-5 text-xs text-[#6f7886] sm:flex-row sm:items-center sm:justify-between">
        <span>© {new Date().getFullYear()} ScanMySaaS. Built by Content Petit LLC.</span>
        <span>Automated checks are not a substitute for a penetration test.</span>
      </div>
    </footer>
  );
}
