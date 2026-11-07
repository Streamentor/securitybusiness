/**
 * Classify a referrer URL into a human-readable source label.
 */
const HOST_SOURCES: Array<[RegExp, string]> = [
  [/(^|\.)google\.[a-z.]+$/, "google"],
  [/(^|\.)bing\.com$/, "bing"],
  [/(^|\.)duckduckgo\.com$/, "duckduckgo"],
  [/(^|\.)yahoo\.[a-z.]+$/, "yahoo"],
  [/(^|\.)baidu\.com$/, "baidu"],
  [/(^|\.)yandex\.[a-z.]+$/, "yandex"],
  [/(^|\.)(youtube\.com|youtu\.be)$/, "youtube"],
  [/(^|\.)(twitter\.com|x\.com|t\.co)$/, "twitter"],
  [/(^|\.)(facebook\.com|fb\.com|fb\.me)$/, "facebook"],
  [/(^|\.)(linkedin\.com|lnkd\.in)$/, "linkedin"],
  [/(^|\.)(reddit\.com|redd\.it)$/, "reddit"],
  [/(^|\.)instagram\.com$/, "instagram"],
  [/(^|\.)tiktok\.com$/, "tiktok"],
  [/(^|\.)pinterest\.[a-z.]+$/, "pinterest"],
  [/(^|\.)github\.com$/, "github"],
  [/(^|\.)producthunt\.com$/, "producthunt"],
  [/(^|\.)(taaft\.com|theresanaiforthat\.com)$/, "taaft"],
  [/^news\.ycombinator\.com$/, "hackernews"],
  [/(^|\.)medium\.com$/, "medium"],
  [/(^|\.)dev\.to$/, "devto"],
  [/(^|\.)substack\.com$/, "substack"],
  [/(^|\.)stefbuilds\.com$/, "stefbuilds"],
  [/(^|\.)(chatgpt\.com|openai\.com)$/, "chatgpt"],
  [/(^|\.)(perplexity\.ai)$/, "perplexity"],
  [/(^|\.)(claude\.ai)$/, "claude"],
];

/**
 * Classify a referrer URL into a human-readable source label by exact hostname
 * (substring checks misfiled reddit.com as t.co and dropbox.com as x.com).
 */
export function classifyReferrer(referrerUrl: string): string {
  if (!referrerUrl) return "direct";
  let hostname: string;
  try { hostname = new URL(referrerUrl).hostname.toLowerCase().replace(/^www\./, ""); }
  catch { return "other"; }
  for (const [pattern, source] of HOST_SOURCES) if (pattern.test(hostname)) return source;
  return hostname;
}
