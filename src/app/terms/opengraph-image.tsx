import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "Terms of Service";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return openGraphCard(
    "Terms of Service",
    "The terms that apply when you use ScanMySaaS.",
  );
}
