export type WebsiteFailureCode = "timeout" | "dns" | "tls" | "blocked" | "http-error" | "not-html" | "empty-html" | "response-too-large" | "redirect" | "network" | "internal";
export interface WebsiteFailure {
  code: WebsiteFailureCode;
  message: string;
  httpStatus?: number;
  provider?: "Cloudflare" | "Vercel";
}
export interface WebsiteCoverage {
  partial: boolean;
  pagesDiscovered: number;
  pagesAnalyzed: number;
  note: string;
}
export { websiteFailure } from "./website-scan-messages.mjs";
