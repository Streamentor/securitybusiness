import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "Vibe coding security scanner before users find the gaps.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return openGraphCard(
    "Vibe coding security scanner before users find the gaps.",
    "Review the boundaries between browser, server, database and release.",
  );
}
