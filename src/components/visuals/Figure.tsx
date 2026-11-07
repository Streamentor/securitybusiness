import type { ReactNode } from "react";
export function Figure({
  children,
  caption,
  className = "",
}: {
  children: ReactNode;
  caption?: string;
  className?: string;
}) {
  return (
    <figure
      className={`mx-auto mt-10 w-full max-w-6xl scroll-mb-[110px] pb-[110px] sm:pb-0 ${className}`}
    >
      {children}
      {caption && (
        <figcaption className="mt-3 max-w-3xl text-[13px] leading-6 text-[#98a2b3]">
          {caption}
        </figcaption>
      )}
    </figure>
  );
}
