import type { MetadataRoute } from "next";
import { guides } from "@/lib/guides";

export default function sitemap(): MetadataRoute.Sitemap {
  const baseUrl = "https://www.scanmysaas.com";

  return [
    {
      url: baseUrl,
      lastModified: new Date("2026-11-07"),
      changeFrequency: "weekly",
      priority: 1,
    },
    {
      url: `${baseUrl}/pricing`,
      changeFrequency: "monthly",
      priority: 0.9,
    },
    {
      url: `${baseUrl}/register`,
      changeFrequency: "yearly",
      priority: 0.6,
    },
    {
      url: `${baseUrl}/privacy`,
      changeFrequency: "yearly",
      priority: 0.3,
    },
    {
      url: `${baseUrl}/terms`,
      changeFrequency: "yearly",
      priority: 0.3,
    },
    {
      url: `${baseUrl}/contact`,
      changeFrequency: "yearly",
      priority: 0.4,
    },
    {
      url: `${baseUrl}/guides`,
      lastModified: new Date("2026-09-06"),
      changeFrequency: "monthly",
      priority: 0.8,
    },
    {
      url: `${baseUrl}/free-website-vulnerability-scanner`,
      lastModified: new Date("2026-11-07"),
      changeFrequency: "monthly",
      priority: 0.9,
    },
    {
      url: `${baseUrl}/gdpr-cookie-checker`,
      lastModified: new Date("2026-11-12"),
      changeFrequency: "monthly",
      priority: 0.85,
    },
    {
      url: `${baseUrl}/repo-scan`,
      lastModified: new Date("2026-11-07"),
      changeFrequency: "weekly",
      priority: 0.9,
    },
    {
      url: `${baseUrl}/vibe-coding-security`,
      lastModified: new Date("2026-11-07"),
      changeFrequency: "monthly",
      priority: 0.85,
    },
    {
      url: `${baseUrl}/lovable-security-scanner`,
      lastModified: new Date("2026-11-07"),
      changeFrequency: "monthly",
      priority: 0.85,
    },
    ...guides.map((guide) => ({
      url: `${baseUrl}/guides/${guide.slug}`,
      lastModified: new Date(guide.updatedAt || "2026-08-13"),
      changeFrequency: "monthly" as const,
      priority: 0.75,
    })),
  ];
}
