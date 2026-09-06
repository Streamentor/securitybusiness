import Link from "next/link";
import { Radar } from "lucide-react";

export function Brand({ href = "/", compact = false }: { href?: string; compact?: boolean }) {
  return (
    <Link href={href} className="group inline-flex items-center gap-2.5" aria-label="ScanMySaaS home">
      <span className="relative flex h-9 w-9 items-center justify-center overflow-hidden rounded-xl bg-[var(--signal)] text-[var(--ink)] transition-transform group-hover:-rotate-3">
        <Radar className="h-5 w-5" strokeWidth={2.4} />
        <span className="absolute right-1.5 top-1.5 h-1.5 w-1.5 rounded-full bg-[var(--cobalt)]" />
      </span>
      {!compact && (
        <span className="text-lg font-semibold tracking-[-0.035em] text-white">
          ScanMy<span className="text-[var(--signal)]">SaaS</span>
        </span>
      )}
    </Link>
  );
}
