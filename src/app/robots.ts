import type { MetadataRoute } from "next";

export default function robots(): MetadataRoute.Robots {
  const privatePaths = ["/api/", "/dashboard/", "/checkout/", "/admin/"];

  return {
    rules: [
      {
        userAgent: "*",
        allow: "/",
        disallow: privatePaths,
      },
      {
        userAgent: ["OAI-SearchBot", "GPTBot", "ClaudeBot", "anthropic-ai", "PerplexityBot"],
        allow: "/",
        disallow: privatePaths,
      },
    ],
    sitemap: "https://www.scanmysaas.com/sitemap.xml",
  };
}
