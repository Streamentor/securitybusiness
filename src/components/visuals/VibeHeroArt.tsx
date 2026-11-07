import Image from "next/image";

export function VibeHeroArt() {
  return (
    <div className="mb-8 hidden overflow-hidden rounded-[18px] lg:block">
      <Image
        src="/images/art/vibe-coding-building.webp"
        width={1200}
        height={1200}
        sizes="600px"
        priority
        alt=""
        aria-hidden="true"
        className="max-h-[360px] w-full object-cover"
      />
    </div>
  );
}
