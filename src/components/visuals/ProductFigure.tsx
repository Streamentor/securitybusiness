import Image from "next/image";
import type { CSSProperties } from "react";
import { BrowserFrame } from "./BrowserFrame";
import { Figure } from "./Figure";
import { productAssets } from "./assets";
export function ProductFigure({
  id,
  priority = false,
  caption,
  sizes = "(max-width: 640px) 100vw, 900px",
}: {
  id: keyof typeof productAssets;
  priority?: boolean;
  caption?: string;
  sizes?: string;
}) {
  const asset = productAssets[id];
  if (!asset) return null;
  const mobile = asset.mobile;
  return (
    <Figure caption={caption || asset.caption}>
      <BrowserFrame
        url={
          asset.surface === "repo"
            ? "scanmysaas.com/repo-scan/…"
            : "scanmysaas.com/scan/…"
        }
      >
        <picture
          className="block w-full aspect-[var(--mobile-ratio)] sm:aspect-[var(--desktop-ratio)]"
          style={
            {
              "--desktop-ratio": `${asset.width}/${asset.height}`,
              "--mobile-ratio": mobile
                ? `${mobile.width}/${mobile.height}`
                : `${asset.width}/${asset.height}`,
            } as CSSProperties
          }
        >
          {mobile && <source media="(max-width: 639px)" srcSet={mobile.src} />}
          <Image
            src={asset.src}
            width={asset.width}
            height={asset.height}
            alt={asset.alt}
            sizes={sizes}
            priority={priority}
            className="h-full w-full object-contain"
          />
        </picture>
      </BrowserFrame>
    </Figure>
  );
}
