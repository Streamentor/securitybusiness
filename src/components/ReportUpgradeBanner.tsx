import Link from "next/link";
import { ArrowUpRight } from "lucide-react";

/** Keep the paid next step in view without disguising a paid scan as free. */
export function ReportUpgradeBanner() {
  return <aside aria-label="Upgrade scan options" className="sticky top-0 z-30 border-b border-[var(--cobalt)]/30 bg-[#101624]/95 backdrop-blur-xl">
    <div className="app-shell flex items-center justify-between gap-3 py-3">
      <div className="min-w-0"><p className="text-xs font-semibold leading-5 text-white sm:text-sm">Go deeper with private repos and AI review.</p><p className="mt-0.5 hidden text-xs text-[#a7b2c4] sm:block">Unlock all available fix prompts and monthly scan credits.</p></div>
      <Link href="/pricing#plans" className="button-primary shrink-0 !min-h-11 !gap-1.5 !px-3 !py-2.5 !text-xs sm:!px-4 sm:!text-sm">Unlock maximum scan <ArrowUpRight className="h-3.5 w-3.5" /></Link>
    </div>
  </aside>;
}
