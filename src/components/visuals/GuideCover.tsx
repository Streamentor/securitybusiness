import Image from "next/image";
import { guideCoverAssets } from "./assets";
export function GuideCover({
  src,
  alt = "",
  priority = false,
  card = false,
}: {
  src?: string;
  alt?: string;
  priority?: boolean;
  card?: boolean;
}) {
  const size = src ? guideCoverAssets[src] : null;
  if (!src || !size) return null;
  return (
    <Image
      src={src}
      width={size.width}
      height={size.height}
      alt={alt}
      aria-hidden={alt ? undefined : true}
      sizes={
        card
          ? "(max-width: 1024px) 100vw, 600px"
          : "(max-width: 1024px) 100vw, 768px"
      }
      priority={priority}
      className={`${card ? "mb-6" : "mb-10"} aspect-video h-auto w-full rounded-[14px] border border-white/[0.09] object-cover`}
    />
  );
}
