import Link from "next/link";
import { ArrowLeft, Check, Radar } from "lucide-react";
import { Brand } from "@/components/Brand";

export function AuthFrame({ title, subtitle, children }: { title: string; subtitle: string; children: React.ReactNode }) {
  return (
    <main className="min-h-screen lg:grid lg:grid-cols-[0.82fr_1.18fr]">
      <section className="flex min-h-screen flex-col px-5 py-5 sm:px-10 sm:py-8 lg:px-14">
        <div className="flex items-center justify-between"><Brand /><Link href="/" className="inline-flex items-center gap-1.5 text-xs text-[#8993a1] hover:text-white"><ArrowLeft className="h-3.5 w-3.5" /> Back home</Link></div>
        <div className="mx-auto flex w-full max-w-md flex-1 flex-col justify-center py-14">
          <p className="eyebrow">Secure workspace</p>
          <h1 className="mt-4 text-4xl font-semibold tracking-[-0.045em]">{title}</h1>
          <p className="mt-3 text-sm leading-6 text-[#8e98a6]">{subtitle}</p>
          <div className="mt-8">{children}</div>
        </div>
      </section>
      <aside className="relative hidden overflow-hidden border-l border-white/[0.08] bg-[#0b1016] p-14 lg:flex lg:flex-col lg:justify-between">
        <div className="absolute inset-0 hairline-grid opacity-70 [mask-image:linear-gradient(to_bottom,black,transparent)]" />
        <div className="relative"><div className="inline-flex h-12 w-12 items-center justify-center rounded-2xl bg-[var(--signal)] text-[#090c0a]"><Radar className="h-6 w-6" /></div><p className="mt-10 max-w-lg text-balance text-4xl font-semibold leading-[1.06] tracking-[-0.05em]">A security report that ends in a to-do list.</p><p className="mt-5 max-w-lg text-sm leading-7 text-[#8e98a6]">Keep scan history, compare scores, and turn every paid finding into a practical remediation step.</p></div>
        <div className="relative grid gap-3 text-sm text-[#a7b0bc]">
          {['60+ automated checks', 'Up to 25 pages per scan', 'Prioritized findings', 'Subscriber-only remediation'].map((item) => <div key={item} className="flex items-center gap-2.5 border-t border-white/[0.08] pt-3"><span className="flex h-5 w-5 items-center justify-center rounded-full bg-[var(--signal)]/10"><Check className="h-3 w-3 text-[var(--signal)]" /></span>{item}</div>)}
        </div>
      </aside>
    </main>
  );
}
