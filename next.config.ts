import type { NextConfig } from "next";
import path from "node:path";
import { fileURLToPath } from "node:url";

const projectRoot = path.dirname(fileURLToPath(import.meta.url));

const nextConfig: NextConfig = {
  reactCompiler: true,
  async headers() {
    return [{
      source: "/:path*",
      headers: [
        { key: "X-Content-Type-Options", value: "nosniff" },
        { key: "X-Frame-Options", value: "DENY" },
        { key: "Referrer-Policy", value: "strict-origin-when-cross-origin" },
        { key: "Permissions-Policy", value: "camera=(), microphone=(), geolocation=()" },
      ],
    }, {
      source: "/scan/:path*",
      headers: [{key: "Referrer-Policy", value: "no-referrer"}, {key: "X-Robots-Tag", value: "noindex, nofollow"}],
    }];
  },
  // Keep Turbopack scoped to this repository when it lives inside a larger
  // workspace with another package-lock.json and unrelated Next.js sources.
  turbopack: {
    root: projectRoot,
  },
};

export default nextConfig;
