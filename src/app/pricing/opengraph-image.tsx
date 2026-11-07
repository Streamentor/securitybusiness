import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "Pay for scans, not security theater.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return openGraphCard(
    "Pay for scans, not security theater.",
    "Website and repository scans, remediation and paid AI logic review.",
  );
}
