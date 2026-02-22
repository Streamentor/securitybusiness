/**
 * Classify a referrer URL into a human-readable source label.
 */
export function classifyReferrer(referrerUrl: string): string {
  if (!referrerUrl) return "direct";

  const lower = referrerUrl.toLowerCase();

  if (lower.includes("google.")) return "google";
  if (lower.includes("bing.")) return "bing";
  if (lower.includes("duckduckgo.")) return "duckduckgo";
  if (lower.includes("yahoo.")) return "yahoo";
  if (lower.includes("baidu.")) return "baidu";
  if (lower.includes("yandex.")) return "yandex";

  if (lower.includes("youtube.") || lower.includes("youtu.be")) return "youtube";
  if (lower.includes("twitter.") || lower.includes("x.com") || lower.includes("t.co")) return "twitter";
  if (lower.includes("facebook.") || lower.includes("fb.com")) return "facebook";
  if (lower.includes("linkedin.")) return "linkedin";
  if (lower.includes("reddit.")) return "reddit";
  if (lower.includes("instagram.")) return "instagram";
  if (lower.includes("tiktok.")) return "tiktok";
  if (lower.includes("pinterest.")) return "pinterest";

  if (lower.includes("github.")) return "github";
  if (lower.includes("producthunt.")) return "producthunt";
  if (lower.includes("taaft.")) return "taaft";
  if (lower.includes("theresanaiforthat.")) return "taaft";

  if (lower.includes("news.ycombinator")) return "hackernews";
  if (lower.includes("medium.")) return "medium";
  if (lower.includes("dev.to")) return "devto";
  if (lower.includes("substack.")) return "substack";

  // Try to extract hostname as source
  try {
    const hostname = new URL(referrerUrl).hostname.replace(/^www\./, "");
    return hostname;
  } catch {
    return "other";
  }
}
