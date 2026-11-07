export type ProductAsset = {
  src: string;
  width: number;
  height: number;
  alt: string;
  caption: string;
  surface: "website" | "repo";
  mobile?: { src: string; width: number; height: number };
};
// Populated only from inspected real captures. Missing optional captures render nothing.
export const productAssets: Partial<
  Record<
    | "website-report"
    | "website-finding"
    | "repo-report"
    | "repo-loader"
    | "rescan-comparison"
    | "private-repo-picker"
    | "ai-review-finding",
    ProductAsset
  >
> = {
  "website-report": {
    alt: "Website security report for stefbuilds.com showing its score, severity breakdown and seven scanned pages.",
    caption:
      "A real website scan: score, severity breakdown, scanned pages and prioritized findings.",
    surface: "website",
    src: "/images/product/website-report.webp",
    width: 1800,
    height: 1325,
    mobile: {
      src: "/images/product/website-report-mobile.webp",
      width: 716,
      height: 1281,
    },
  },
  "website-finding": {
    alt: "Expanded website finding with affected URL, observation, remediation and a copyable fix prompt.",
    caption:
      "Each finding has the affected URL, the fix and a prompt for your AI coding tool. Excerpt from a real scan.",
    surface: "website",
    src: "/images/product/website-finding.webp",
    width: 1800,
    height: 1283,
    mobile: {
      src: "/images/product/website-finding-mobile.webp",
      width: 716,
      height: 1440,
    },
  },
  "repo-report": {
    alt: "Repository report showing score, scan coverage and two findings with package-lock.json line references; private repository identity is outside the crop.",
    caption:
      "Findings point to the file and line. Real report excerpt; private repository identity omitted.",
    surface: "repo",
    src: "/images/product/repo-report.webp",
    width: 1800,
    height: 1134,
    mobile: {
      src: "/images/product/repo-report-mobile.webp",
      width: 716,
      height: 3074,
    },
  },
  "repo-loader": {
    alt: "A running scan of Streamentor/securitybusiness with seven stages, AI logic review active and the message You can leave this page.",
    caption: "Runs in the background. You can leave the page.",
    surface: "repo",
    src: "/images/product/repo-loader.webp",
    width: 1344,
    height: 1378,
    mobile: {
      src: "/images/product/repo-loader-mobile.webp",
      width: 716,
      height: 1664,
    },
  },
  "rescan-comparison": {
    alt: "Two scans of stefbuilds.com compared: zero resolved, zero new and four still-open finding groups, with score 91 unchanged.",
    caption:
      "Rescan after a fix and see what is resolved. This real comparison shows no changes between the two scans.",
    surface: "website",
    src: "/images/product/rescan-comparison.webp",
    width: 1800,
    height: 312,
    mobile: {
      src: "/images/product/rescan-comparison-mobile.webp",
      width: 716,
      height: 364,
    },
  },
  "private-repo-picker": {
    alt: "Connected GitHub App repository picker filtered to the public securitybusiness repository, with AI review enabled; private repository names are excluded.",
    caption:
      "Starter and Pro: connect GitHub and select a repository. Picker filtered to an owned public repository for this capture.",
    surface: "repo",
    src: "/images/product/private-repo-picker.webp",
    width: 1362,
    height: 1107,
    mobile: {
      src: "/images/product/private-repo-picker-mobile.webp",
      width: 716,
      height: 1276,
    },
  },
  "ai-review-finding": {
    alt: "AI finding marked Needs verification and high confidence, with a file and line, explanation and code evidence; private repository identity is outside the crop.",
    caption:
      "A real AI finding includes code evidence and is marked Needs verification. Excerpt; private repository identity omitted.",
    surface: "repo",
    src: "/images/product/ai-review-finding.webp",
    width: 1800,
    height: 671,
    mobile: {
      src: "/images/product/ai-review-finding-mobile.webp",
      width: 716,
      height: 901,
    },
  },
};
export const guideCoverAssets: Record<
  string,
  { width: number; height: number }
> = {
  "/images/guides/saas-launch-security-checklist.webp": {
    width: 1600,
    height: 900,
  },
  "/images/guides/security-headers-for-saas.webp": {
    width: 1600,
    height: 900,
  },
  "/images/guides/ssl-tls-checklist-for-saas.webp": {
    width: 1600,
    height: 900,
  },
  "/images/guides/robots-txt-and-sitemap-for-saas.webp": {
    width: 1600,
    height: 900,
  },
  "/images/guides/llms-txt-for-saas.webp": {
    width: 1600,
    height: 900,
  },
  "/images/guides/exposed-files-and-source-maps.webp": {
    width: 1600,
    height: 900,
  },
  "/images/guides/github-secret-scanning-for-vibe-coded-apps.webp": {
    width: 1600,
    height: 900,
  },
  "/images/guides/github-actions-security-for-vibe-coded-apps.webp": {
    width: 1600,
    height: 900,
  },
  "/images/guides/supabase-security-for-vibe-coded-apps.webp": {
    width: 1600,
    height: 900,
  },
  "/images/guides/vibe-coding-security-checklist.webp": {
    width: 1600,
    height: 900,
  },
};
