import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "Privacy Policy";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return openGraphCard(
    "Privacy Policy",
    "How ScanMySaaS handles scan data and selected repository contents.",
  );
}
