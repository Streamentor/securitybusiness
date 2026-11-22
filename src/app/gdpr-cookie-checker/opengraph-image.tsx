import { openGraphCard } from "@/components/visuals/OpenGraphCard";

export const alt = "GDPR cookie checker for your SaaS website.";
export const size = { width: 1200, height: 630 };
export const contentType = "image/png";

export default function Image() {
  return openGraphCard(
    "GDPR cookie checker for your SaaS website.",
    "Find trackers that load before consent, privacy policy gaps and accessibility issues.",
  );
}
