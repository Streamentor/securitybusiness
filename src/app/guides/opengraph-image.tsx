import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "Fix the surface your customers can see.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return openGraphCard(
    "Fix the surface your customers can see.",
    "Understand the finding before changing production.",
  );
}
