import { getGuide } from "@/lib/guides";
import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "ScanMySaaS security guide";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default async function Image({
  params,
}: {
  params: Promise<{ slug: string }>;
}) {
  const guide = getGuide((await params).slug);
  return openGraphCard(
    guide?.title ?? "SaaS security guides",
    "Practical checks for your repository, database and deployed app.",
  );
}
