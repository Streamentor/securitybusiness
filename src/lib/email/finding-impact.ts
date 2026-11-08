import { redactSecrets } from "@/lib/secret-patterns";
export function safeText(value: unknown, limit = 220): string {
  return redactSecrets(typeof value === "string" ? value : "").replace(/[\r\n\t\x00-\x1f\x7f]/g, " ").replace(/[\u2013\u2014]/g, "-").replace(/[\u2018\u2019]/g, "'").replace(/[\u201c\u201d]/g, '"').replace(/\s+/g, " ").trim().slice(0, limit);
}
const IMPACTS: Record<string, string> = {
  "sensitive-file": "Anyone can request this file. If it contains credentials or private data, those values may be exposed.",
  "source-maps": "Public source maps can reveal source code and internal implementation details.",
  "directory-listing": "Visitors may be able to browse file names and download files that were not intended for public access.",
  "ssl": "A TLS configuration issue can affect the protection or trustworthiness of connections to your app.",
  "headers": "This response is missing a browser protection. The practical risk depends on the page and how it handles user content.",
  "csp": "The browser has fewer restrictions on which scripts or other resources this page can load.",
  "cookies": "A cookie protection is missing. Its impact depends on whether the cookie holds a session or other sensitive value.",
  "cors": "The cross-origin policy may allow another website to read responses. Exploitability depends on the data and authentication involved.",
  "csrf": "A missing request protection may let another website trigger an action, if the action relies on automatically sent credentials.",
  "xss": "The scanner found a potential script injection signal. Confirm it before treating it as exploitable.",
  "api-exposure": "This endpoint is publicly reachable. Check whether its responses or actions should require authentication.",
  "info-disclosure": "The public response reveals implementation information that may help someone understand your app.",
  "outdated-lib": "A detected library appears outdated. Confirm its version and whether relevant vulnerable features are used.",
  "redirect": "The redirect configuration needs review to confirm requests reach the intended destination safely.",
  "sri": "Third-party resources lack an integrity check, so the browser cannot verify their content against a pinned hash.",
  "http-methods": "The server advertises additional HTTP methods. Check whether any enabled method exposes unintended behavior.",
  "email": "An email authentication setting needs review to reduce the chance of messages being impersonated or rejected.",
};
/** Unknown/new finding types always use the scanner's own first sentence, never an invented consequence. */
export function findingImpact(finding: { type?: string; description?: string }): string {
  const fallback = safeText(finding.description || "Review this finding in your report to understand its scope and confirm whether a fix is needed.", 800).split(/(?<=[.!?])\s/)[0];
  return (IMPACTS[finding.type || ""] || fallback).split(/\s+/).slice(0, 25).join(" ");
}
