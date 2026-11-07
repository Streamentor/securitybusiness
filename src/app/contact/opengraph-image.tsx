import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "Contact Us";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return openGraphCard(
    "Contact Us",
    "Questions, feedback and support for ScanMySaaS.",
  );
}
