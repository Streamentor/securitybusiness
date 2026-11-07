import type { ReactNode } from "react";
export function BrowserFrame({
  children,
  url = "scanmysaas.com/scan/…",
  sample = true,
}: {
  children: ReactNode;
  url?: string;
  sample?: boolean;
}) {
  return (
    <div className="overflow-hidden rounded-[18px] border border-white/[0.09] bg-[#0d1118] shadow-[0_16px_60px_-30px_rgba(185,255,102,.25)]">
      <div className="flex h-11 items-center gap-3 border-b border-white/[0.09] px-4">
        <span aria-hidden="true" className="flex shrink-0 gap-1.5">
          {["#ff6b6b", "#ffbf69", "#b9ff66"].map((c) => (
            <span
              key={c}
              style={{ background: c }}
              className="h-1.5 w-1.5 rounded-full opacity-70"
            />
          ))}
        </span>
        <span className="min-w-0 flex-1 truncate rounded-md bg-white/[0.04] px-3 py-1 font-mono text-[10px] text-[#98a2b3]">
          {url}
        </span>
        {sample && (
          <span className="shrink-0 rounded border border-[#b9ff66]/20 px-2 py-1 text-[9px] font-medium text-[#b9ff66]">
            Sample report
          </span>
        )}
      </div>
      {children}
    </div>
  );
}
