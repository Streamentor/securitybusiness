import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "Lovable security scan before your users find the gaps.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return openGraphCard(
    "Lovable security scan before your users find the gaps.",
    "Check the deployed app and the repository behind it.",
  );
}
