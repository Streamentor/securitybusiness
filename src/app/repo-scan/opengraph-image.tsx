import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "GitHub repo scanner for vibe-coded apps.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return openGraphCard(
    "GitHub repo scanner for vibe-coded apps.",
    "Inspect one pinned commit for secrets, risky workflows and code issues.",
  );
}
