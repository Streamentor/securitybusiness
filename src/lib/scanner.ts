import { AsyncLocalStorage } from "node:async_hooks";
import { websiteFailure } from "./website-scan-messages.mjs";
import type { WebsiteFailure, WebsiteCoverage } from "./website-scan-failure";
import * as cheerio from "cheerio";
import { lookup } from "node:dns/promises";
import { isIP } from "node:net";
import type { LookupFunction } from "node:net";
import { connect as connectTls } from "node:tls";
import { Agent } from "undici";
import type { ComplianceRunner } from "./compliance-runner";

export interface VulnerabilityResult {
  type: string;
  severity: "critical" | "high" | "medium" | "low" | "info";
  title: string;
  description: string;
  url: string;
  remedy: string;
}

interface ScanResult {
  url: string;
  score: number;
  vulnerabilities: VulnerabilityResult[];
  pagesScanned: number;
  coverage?: WebsiteCoverage;
}

export interface ScanProgress {
  step: string;
  label: string;
  status: "running" | "done" | "error";
  found?: number;
  totalSteps: number;
  currentStep: number;
  pagesDiscovered?: number;
}

export type ProgressCallback = (progress: ScanProgress) => void;

export class WebsiteScanError extends Error {
  readonly failure: WebsiteFailure;
  constructor(message: string, failure: WebsiteFailure = websiteFailure("network")) {
    super(message); this.name = "WebsiteScanError"; this.failure = failure;
  }
}
const scanBudget = new AsyncLocalStorage<{deadline: number; exhausted: boolean; failedRequests: number}>();
interface CrawledPage {url: string; html: string; headers: Headers}
function networkFailure(error: unknown, timedOut = false): WebsiteFailure {
  if (timedOut) return websiteFailure("timeout");
  const e = error as {code?: string; cause?: {code?: string}};
  const code = e?.cause?.code || e?.code || "";
  if (["ENOTFOUND", "EAI_AGAIN", "ENODATA"].includes(code)) return websiteFailure("dns");
  if (/CERT|TLS|SSL|SELF_SIGNED|UNABLE_TO_VERIFY/.test(code)) return websiteFailure("tls");
  if (/TIMEOUT|TIMEDOUT/.test(code)) return websiteFailure("timeout");
  return websiteFailure("network");
}


interface ReadinessItem {
  key: "tls" | "robots" | "sitemap" | "llms" | "security" | "canonical" | "indexability";
  label: string;
  status: "pass" | "warning" | "unknown";
  detail: string;
  url: string;
}

function isPrivateAddress(address: string): boolean {
  const normalized = address.toLowerCase().split("%")[0];
  if (normalized.startsWith("::ffff:")) return isPrivateAddress(normalized.slice(7));
  if (isIP(normalized) === 4) {
    const [a, b] = normalized.split(".").map(Number);
    return (
      a === 0 ||
      a === 10 ||
      a === 127 ||
      (a === 100 && b >= 64 && b <= 127) ||
      (a === 169 && b === 254) ||
      (a === 172 && b >= 16 && b <= 31) ||
      (a === 192 && (b === 0 || b === 168)) ||
      (a === 198 && (b === 18 || b === 19)) ||
      a >= 224
    );
  }
  if (isIP(normalized) === 6) {
    return (
      normalized === "::" ||
      normalized === "::1" ||
      normalized.startsWith("fc") ||
      normalized.startsWith("fd") ||
      /^fe[89ab]/.test(normalized) ||
      normalized.startsWith("ff")
    );
  }
  return true;
}

// Validate the addresses returned to the socket itself. A separate preflight
// DNS lookup cannot stop a hostname from rebinding between validation and fetch.
export function createPublicLookup(resolveHostname = (hostname: string) => lookup(hostname, { all: true, verbatim: true })): LookupFunction {
  return (hostname, options, callback) => {
    resolveHostname(hostname).then((addresses) => {
      if (!addresses.length || addresses.some(({ address }) => isPrivateAddress(address))) {
        callback(new Error("This hostname does not resolve exclusively to public addresses."), "");
        return;
      }
      const compatible = options.family === 4 || options.family === 6
        ? addresses.filter(({ family }) => family === options.family)
        : addresses;
      if (!compatible.length) {
        callback(new Error("No public address is available for the requested network family."), "");
        return;
      }
      callback(null, options.all ? compatible : compatible[0].address, compatible[0].family);
    }, (error) => callback(error instanceof Error ? error : new Error("Hostname resolution failed."), ""));
  };
}

const scanDispatcher = new Agent({ connect: { lookup: createPublicLookup() } });

export async function validateScanTarget(rawUrl: string): Promise<URL> {
  const target = new URL(rawUrl);
  if (target.protocol !== "http:" && target.protocol !== "https:") {
    throw new Error("Only HTTP and HTTPS websites can be scanned.");
  }
  if (target.username || target.password) {
    throw new Error("URLs with embedded credentials cannot be scanned.");
  }
  const rawHostname = target.hostname.toLowerCase().replace(/\.$/, "");
  const hostname = rawHostname.startsWith("[") && rawHostname.endsWith("]")
    ? rawHostname.slice(1, -1)
    : rawHostname;
  if (
    hostname === "localhost" ||
    hostname.endsWith(".localhost") ||
    hostname.endsWith(".local") ||
    hostname.endsWith(".internal") ||
    hostname.endsWith(".lan")
  ) {
    throw new Error("Private network targets cannot be scanned.");
  }
  if (isIP(hostname)) {
    if (isPrivateAddress(hostname)) throw new Error("Private network targets cannot be scanned.");
    return target;
  }
  let addresses: Array<{ address: string; family: number }>;
  try {
    addresses = await lookup(hostname, { all: true, verbatim: true });
  } catch (error) {
    throw new Error("The website hostname could not be resolved.", {cause: error});
  }
  if (!addresses.length || addresses.some(({ address }) => isPrivateAddress(address))) {
    throw new Error("This hostname does not resolve to a public address.");
  }
  return target;
}

export const MAX_SCAN_RESPONSE_BYTES = 2_000_000;

// ─── Helper: bounded fetch, including redirects and body reads ────
export async function safeFetch(
  url: string,
  opts: RequestInit & { timeout?: number; onFailure?: (failure: WebsiteFailure) => void; sameSiteRedirects?: boolean } = {}
): Promise<Response | null> {
  const {onFailure, sameSiteRedirects, timeout, ...fetchOptions} = opts;
  const budget = scanBudget.getStore();
  const remaining = budget ? budget.deadline - Date.now() : Infinity;
  if (remaining <= 0) { if (budget) {budget.exhausted = true; budget.failedRequests += 1;} onFailure?.(websiteFailure("timeout")); return null; }
  let failure: WebsiteFailure | undefined;
  const controller = new AbortController();
  let timer: ReturnType<typeof setTimeout>;
  const deadline = new Promise<never>((_, reject) => {
    timer = setTimeout(() => {
      controller.abort();
      reject(new Error("Scanner response deadline exceeded."));
    }, Math.min(timeout ?? 10000, remaining));
  });
  try {
    let currentUrl = url;
    const followRedirects = opts.redirect === undefined || opts.redirect === "follow";
    for (let redirectCount = 0; redirectCount <= 5; redirectCount += 1) {
      await Promise.race([validateScanTarget(currentUrl), deadline]);
      let response: Response | null = null;
      let reader: ReadableStreamDefaultReader<Uint8Array> | undefined;
      try {
        const requestOptions: RequestInit & { dispatcher: Agent } = {
          ...fetchOptions,
          dispatcher: scanDispatcher,
          cache: "no-store",
          redirect: "manual",
          signal: controller.signal,
          headers: {
            "User-Agent": "ScanMySaaS-Scanner/2.0 (Security Audit Tool)",
            ...(opts.headers as Record<string, string>),
          },
        };
        response = await Promise.race([fetch(currentUrl, requestOptions).then((result) => {
          if (controller.signal.aborted) {
            void result.body?.cancel().catch(() => undefined);
            throw new Error("Scanner response deadline exceeded.");
          }
          return result;
        }), deadline]);
        const location = response.headers.get("location");
        if (followRedirects && [301, 302, 303, 307, 308].includes(response.status) && location && redirectCount < 5) {
          // Redirect bodies are not inspected. Cancel before following, including
          // when the next URL subsequently fails private-target validation.
          void response.body?.cancel().catch(() => undefined);
          const nextUrl = new URL(location, currentUrl);
          if (sameSiteRedirects && nextUrl.hostname.replace(/^www\./, "") !== new URL(url).hostname.replace(/^www\./, "")) {
            failure = websiteFailure("redirect"); throw new Error("Cross-host crawl redirect");
          }
          currentUrl = nextUrl.toString();
          continue;
        }

        if (response.body && Number(response.headers.get("content-length")) > MAX_SCAN_RESPONSE_BYTES) {
          failure = websiteFailure("response-too-large");
          throw new Error("Scanner response exceeds the body byte limit.");
        }
        // Drain a clone while enforcing the deadline and decoded-byte limit.
        // The original keeps its native status, headers, URL and text/json/clone
        // semantics, with at most the bounded body buffered for existing callers.
        reader = response.clone().body?.getReader();
        let bytes = 0;
        if (reader) {
          while (true) {
            const chunk = await Promise.race([reader.read(), deadline]);
            if (chunk.done) break;
            bytes += chunk.value.byteLength;
            if (bytes > MAX_SCAN_RESPONSE_BYTES) { failure = websiteFailure("response-too-large"); throw new Error("Scanner response exceeds the body byte limit."); }
          }
        }
        if (budget && ([403, 429].includes(response.status) || response.headers.get("cf-mitigated") === "challenge" || response.headers.get("x-vercel-mitigated") === "challenge")) budget.failedRequests += 1;
        return response;
      } catch (error) {
        // Cancel both tee branches; awaiting only one can deadlock until the
        // other is canceled, and an upstream cancel handler can itself stall.
        void reader?.cancel().catch(() => undefined);
        void response?.body?.cancel().catch(() => undefined);
        throw error;
      } finally {
        reader?.releaseLock();
      }
    }
    return null;
  } catch (error) {
    if (budget && Date.now() >= budget.deadline) budget.exhausted = true;
    if (budget) budget.failedRequests += 1;
    onFailure?.(failure ?? networkFailure(error, controller.signal.aborted));
    return null;
  } finally {
    clearTimeout(timer!);
  }
}

// ─── Helper: DNS TXT lookup ────────────────────────────────────────
async function dnsLookupTxt(hostname: string): Promise<string[][]> {
  try {
    const dns = await import("dns");
    const { promisify } = await import("util");
    const resolveTxt = promisify(dns.resolveTxt);
    let timer: ReturnType<typeof setTimeout> | undefined;
    try {
      return await Promise.race([resolveTxt(hostname), new Promise<never>((_, reject) => {
        timer = setTimeout(() => reject(new Error("DNS response deadline exceeded")), Math.max(1, Math.min(5000, (scanBudget.getStore()?.deadline ?? Infinity) - Date.now())));
      })]);
    } finally { clearTimeout(timer); }
  } catch {
    return [];
  }
}

// ─── 1. Crawl / discover pages ────────────────────────────────────
export async function discoverPages(
  baseUrl: string,
  maxPages: number = 25,
  onPage?: (page: CrawledPage) => void,
  onFailure?: (failure: WebsiteFailure) => void,
  onIncomplete?: () => void,
): Promise<string[]> {
  const visited = new Set<string>();
  const toVisit = [baseUrl];
  const pages: string[] = [];
  const baseHost = new URL(baseUrl).hostname.replace(/^www\./, "");
  const crawlDeadline = Date.now() + 25000;

  while (toVisit.length > 0 && pages.length < maxPages) {
    if (Date.now() >= crawlDeadline) { onIncomplete?.(); break; }
    // Crawl up to 3 pages concurrently
    const batch = toVisit.splice(0, 3).filter((u) => !visited.has(u));
    if (batch.length === 0) break;

    const results = await Promise.allSettled(
      batch.map(async (batchUrl) => {
        if (visited.has(batchUrl)) return null;
        visited.add(batchUrl);

        const res = await safeFetch(batchUrl, { redirect: "follow", timeout: Math.min(12000, Math.max(1, crawlDeadline - Date.now())), sameSiteRedirects: true, onFailure });
        if (!res) { onIncomplete?.(); return null; }
        const provider = res.headers.has("cf-ray") ? "Cloudflare" : res.headers.has("x-vercel-id") ? "Vercel" : undefined;
        if (!res.ok || (res.headers.get("cf-mitigated") === "challenge" || res.headers.get("x-vercel-mitigated") === "challenge")) {
          const code = [401, 403, 429].includes(res.status) || (res.headers.get("cf-mitigated") === "challenge" || res.headers.get("x-vercel-mitigated") === "challenge") ? "blocked" : res.status >= 300 && res.status < 400 ? "redirect" : "http-error";
          onFailure?.(websiteFailure(code, res.status, provider)); onIncomplete?.(); return null;
        }
        const ct = res.headers.get("content-type") || "";
        if (!ct.toLowerCase().includes("text/html")) { onFailure?.(websiteFailure("not-html")); onIncomplete?.(); return null; }

        const html = await res.text();
        if (!html.trim()) { onFailure?.(websiteFailure("empty-html")); onIncomplete?.(); return null; }
        const finalUrl = res.url || batchUrl;
        onPage?.({url: batchUrl, html, headers: res.headers});
        const $ = cheerio.load(html);
        const links: string[] = [];

        $("a[href]").each((_, el) => {
          try {
            const href = $(el).attr("href");
            if (!href) return;
            const abs = new URL(href, finalUrl).toString().split("#")[0].split("?")[0];
            if (
              new URL(abs).hostname.replace(/^www\./, "") === baseHost &&
              !visited.has(abs) &&
              abs.startsWith("http")
            ) {
              links.push(abs);
            }
          } catch {
            /* invalid URL */
          }
        });

        return { url: batchUrl, links };
      })
    );

    for (const r of results) {
      if (r.status === "fulfilled" && r.value) {
        if (pages.length < maxPages) {
          pages.push(r.value.url);
        }
        for (const link of r.value.links) {
          if (!visited.has(link) && pages.length + toVisit.length < maxPages * 2) {
            toVisit.push(link);
          }
        }
      }
    }
  }

  return pages;
}

// ─── 2. SSL / TLS checks ──────────────────────────────────────────
async function checkSSL(url: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const parsed = new URL(url);

  if (parsed.protocol !== "https:") {
    vulns.push({
      type: "ssl",
      severity: "critical",
      title: "No HTTPS / SSL Certificate",
      description:
        "The website does not use HTTPS. All data is transmitted in plain text, exposing it to man-in-the-middle attacks.",
      url,
      remedy:
        "1. Install a free SSL certificate from Let's Encrypt using Certbot:\n\n   sudo apt install certbot python3-certbot-nginx\n   sudo certbot --nginx -d yourdomain.com\n\n2. Or if using a hosting provider (Vercel, Netlify, Cloudflare), enable HTTPS in your dashboard — it's usually one click.\n\n3. Force all traffic to HTTPS by adding a server-level redirect. In Nginx:\n\n   server {\n     listen 80;\n     server_name yourdomain.com;\n     return 301 https://$host$request_uri;\n   }",
    });
  }

  if (parsed.protocol === "https:") {
    const httpUrl = url.replace("https://", "http://");
    const res = await safeFetch(httpUrl, { redirect: "manual" });
    if (res && (res.status < 300 || res.status >= 400)) {
      vulns.push({
        type: "ssl",
        severity: "medium",
        title: "HTTP to HTTPS Redirect Missing",
        description:
          "The HTTP version of the site does not redirect to HTTPS.",
        url,
        remedy:
          "Add a 301 redirect from HTTP to HTTPS.\n\nNginx — add to your server block:\n\n   server {\n     listen 80;\n     server_name yourdomain.com www.yourdomain.com;\n     return 301 https://$host$request_uri;\n   }\n\nApache — add to .htaccess:\n\n   RewriteEngine On\n   RewriteCond %{HTTPS} off\n   RewriteRule ^(.*)$ https://%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\nNext.js (next.config.js):\n\n   async redirects() {\n     return [{ source: '/:path*', has: [{ type: 'header', key: 'x-forwarded-proto', value: 'http' }], destination: 'https://yourdomain.com/:path*', permanent: true }];\n   }\n\nVercel/Netlify/Cloudflare: HTTPS redirect is usually enabled by default — check your dashboard settings.",
      });
    }
  }

  if (parsed.protocol === "https:") {
    const res = await safeFetch(url, { redirect: "manual" });
    if (res && res.status >= 300 && res.status < 400) {
      const location = res.headers.get("location");
      if (location && location.startsWith("http://")) {
        vulns.push({
          type: "ssl",
          severity: "high",
          title: "HTTPS Downgrades to HTTP via Redirect",
          description: `The HTTPS page redirects to an HTTP URL (${location}), stripping TLS protection.`,
          url,
          remedy: "Your HTTPS page is redirecting users to an insecure HTTP URL — this strips TLS encryption mid-session.\n\n1. Find the redirect rule in your server config, application code, or CDN that sends users from HTTPS to HTTP and change the destination to use https://.\n\n2. In Nginx, check all 'return' and 'rewrite' directives — make sure none point to http://.\n\n3. In your application, audit any server-side redirects (e.g. res.redirect() in Express, redirect() in Django/Laravel) and ensure they use HTTPS URLs.\n\n4. If using a load balancer or reverse proxy, ensure it forwards the correct protocol headers (X-Forwarded-Proto) so your app knows the original request was HTTPS.",
        });
      }
    }
  }

  return vulns;
}

async function inspectTlsCertificate(url: string): Promise<{ item: ReadinessItem; vulnerabilities: VulnerabilityResult[] }> {
  const parsed = new URL(url);
  const certificateUrl = `https://${parsed.hostname}/`;
  const vulnerabilities: VulnerabilityResult[] = [];

  if (parsed.protocol !== "https:") {
    return {
      item: { key: "tls", label: "TLS certificate", status: "warning", detail: "The scanned URL does not use HTTPS.", url },
      vulnerabilities,
    };
  }

  try {
    await validateScanTarget(certificateUrl);
    const addresses = await lookup(parsed.hostname, { all: true, verbatim: true });
    const publicAddress = addresses.find(({ address }) => !isPrivateAddress(address));
    if (!publicAddress) throw new Error("No public address");

    return await new Promise((resolve) => {
      let settled = false;
      const finish = (item: ReadinessItem, extra: VulnerabilityResult[] = []) => {
        if (settled) return;
        settled = true;
        socket.destroy();
        resolve({ item, vulnerabilities: extra });
      };
      const socket = connectTls({
        host: publicAddress.address,
        port: 443,
        servername: parsed.hostname,
        rejectUnauthorized: false,
        timeout: 7000,
      });

      socket.once("secureConnect", () => {
        const certificate = socket.getPeerCertificate();
        if (!certificate?.valid_to) {
          finish({ key: "tls", label: "TLS certificate", status: "unknown", detail: "The certificate details could not be read.", url: certificateUrl });
          return;
        }

        const expiresAt = new Date(certificate.valid_to);
        const daysRemaining = Math.ceil((expiresAt.getTime() - Date.now()) / 86_400_000);
        if (!socket.authorized) {
          const finding: VulnerabilityResult = {
            type: "ssl",
            severity: "high",
            title: "TLS Certificate Is Not Trusted",
            description: `The certificate could not be verified by the scanner (${socket.authorizationError || "unknown trust error"}).`,
            url: certificateUrl,
            remedy: "Replace or renew the certificate with a certificate trusted by common browsers. Confirm that the full intermediate chain is served, that the certificate covers the production hostname, and that your CDN or load balancer is presenting the intended certificate. Test the public hostname again after deployment.",
          };
          finish({ key: "tls", label: "TLS certificate", status: "warning", detail: "The certificate is not trusted by the scanner.", url: certificateUrl }, [finding]);
          return;
        }

        if (daysRemaining <= 30) {
          const expired = daysRemaining < 0;
          const finding: VulnerabilityResult = {
            type: "ssl",
            severity: expired ? "critical" : daysRemaining <= 14 ? "high" : "medium",
            title: expired ? "TLS Certificate Has Expired" : "TLS Certificate Expires Soon",
            description: expired ? `The TLS certificate expired ${Math.abs(daysRemaining)} day(s) ago.` : `The TLS certificate expires in ${daysRemaining} day(s), on ${expiresAt.toISOString().slice(0, 10)}.`,
            url: certificateUrl,
            remedy: "Renew or replace the certificate before it interrupts customer access. Check the automated renewal job, DNS validation, and CDN or load balancer configuration. Add certificate-expiry monitoring so the team is alerted well before the next renewal window.",
          };
          finish({ key: "tls", label: "TLS certificate", status: "warning", detail: expired ? "The certificate has expired." : `Expires in ${daysRemaining} day(s).`, url: certificateUrl }, [finding]);
          return;
        }

        finish({ key: "tls", label: "TLS certificate", status: "pass", detail: `Trusted certificate, valid for ${daysRemaining} more day(s).`, url: certificateUrl });
      });
      socket.once("timeout", () => finish({ key: "tls", label: "TLS certificate", status: "unknown", detail: "The certificate check timed out.", url: certificateUrl }));
      socket.once("error", () => finish({ key: "tls", label: "TLS certificate", status: "unknown", detail: "The certificate could not be verified.", url: certificateUrl }));
    });
  } catch {
    return {
      item: { key: "tls", label: "TLS certificate", status: "unknown", detail: "The certificate could not be verified.", url: certificateUrl },
      vulnerabilities,
    };
  }
}

// ─── 3. Security headers ──────────────────────────────────────────
export function checkSecurityHeaders(
  url: string,
  headers: Headers
): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];

  const csp = headers.get("content-security-policy");
  if (!csp) {
    const reportOnly = headers.has("content-security-policy-report-only");
    vulns.push({
      type: "headers",
      severity: "medium",
      title: "Missing Content-Security-Policy Header",
      description: `No enforced CSP response header was observed. This is a defense-in-depth hardening opportunity; absence alone does not prove exploitable XSS or clickjacking.${reportOnly ? " A Report-Only policy is present, but it monitors violations without blocking them." : ""}`,
      url,
      remedy: `First test a Content-Security-Policy-Report-Only response header. Report-Only does not block scripts or resources and does not provide enforcement. The restrictive starter below will report legitimate inline scripts and external services until you tailor it.

Create a reporting endpoint you control, replace the placeholder URL, and verify reports arrive in your supported browsers. Use both response headers together:

   Reporting-Endpoints: csp-endpoint="https://your-domain.example/csp-reports"
   Content-Security-Policy-Report-Only: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; report-to csp-endpoint

Next.js — header entries inside next.config.js headers():

   { key: 'Reporting-Endpoints', value: 'csp-endpoint="https://your-domain.example/csp-reports"' },
   { key: 'Content-Security-Policy-Report-Only', value: "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; report-to csp-endpoint" }

Nginx:

   add_header Reporting-Endpoints 'csp-endpoint="https://your-domain.example/csp-reports"' always;
   add_header Content-Security-Policy-Report-Only "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; report-to csp-endpoint" always;

Test login, checkout, navigation, uploads and embeds in a production build. Review reports and allow only required services in the appropriate directives (scripts, connections, frames, styles, images and fonts).

Before enforcement, authorize required inline scripts with fresh unpredictable nonces per request, or hashes where your framework supports them. Next.js nonce integration requires dynamic rendering and coordinated request/response headers; review its caching implications. An enforced script-src 'self' alone can break Next.js inline scripts. Do not resolve this by broadly allowing unsafe-inline.

Only after testing, publish the tailored policy as Content-Security-Policy. Do not simply rename the starter header. Report-Only can remain alongside enforcement while you test further changes.`,
    });
  }

  if (!headers.get("x-frame-options") && !csp?.includes("frame-ancestors")) {
    vulns.push({ type: "headers", severity: "medium", title: "Missing X-Frame-Options Header", description: "Without X-Frame-Options, the site is vulnerable to clickjacking.", url, remedy: "Add the X-Frame-Options header to prevent your site from being embedded in iframes on malicious pages.\n\nRecommended value:\n\n   X-Frame-Options: DENY\n\nOr if you need to iframe your own site:\n\n   X-Frame-Options: SAMEORIGIN\n\nNext.js (next.config.js):\n\n   async headers() { return [{ source: '/:path*', headers: [{ key: 'X-Frame-Options', value: 'DENY' }] }]; }\n\nNginx:\n\n   add_header X-Frame-Options \"DENY\" always;\n\nApache (.htaccess):\n\n   Header always set X-Frame-Options \"DENY\"\n\nExpress.js:\n\n   app.use((req, res, next) => { res.setHeader('X-Frame-Options', 'DENY'); next(); });\n\nNote: If you already set frame-ancestors in your CSP, this header is redundant but still recommended for older browser support." });
  }

  if (!headers.get("x-content-type-options")) {
    vulns.push({ type: "headers", severity: "medium", title: "Missing X-Content-Type-Options Header", description: "Without this header, browsers may MIME-sniff responses.", url, remedy: "Add the X-Content-Type-Options header to prevent browsers from guessing the content type, which can lead to XSS attacks.\n\n   X-Content-Type-Options: nosniff\n\nNext.js (next.config.js):\n\n   async headers() { return [{ source: '/:path*', headers: [{ key: 'X-Content-Type-Options', value: 'nosniff' }] }]; }\n\nNginx:\n\n   add_header X-Content-Type-Options \"nosniff\" always;\n\nExpress.js:\n\n   app.use((req, res, next) => { res.setHeader('X-Content-Type-Options', 'nosniff'); next(); });" });
  }

  const hsts = headers.get("strict-transport-security");
  if (new URL(url).protocol === "https:" && !hsts) {
    vulns.push({ type: "headers", severity: "high", title: "Missing Strict-Transport-Security (HSTS)", description: "Without HSTS, browsers won't enforce HTTPS.", url, remedy: "Add the Strict-Transport-Security header to tell browsers to always use HTTPS for your domain, preventing SSL-stripping attacks.\n\nRecommended value:\n\n   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\nThis tells browsers to enforce HTTPS for 1 year, including all subdomains.\n\nNext.js (next.config.js):\n\n   async headers() { return [{ source: '/:path*', headers: [{ key: 'Strict-Transport-Security', value: 'max-age=31536000; includeSubDomains; preload' }] }]; }\n\nNginx:\n\n   add_header Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\" always;\n\nApache (.htaccess):\n\n   Header always set Strict-Transport-Security \"max-age=31536000; includeSubDomains; preload\"\n\nImportant: Only add 'preload' if you're ready to submit your domain to hstspreload.org — once added, it's very hard to undo." });
  } else if (hsts) {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/);
    if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 15768000) {
      vulns.push({ type: "headers", severity: "low", title: "HSTS max-age Too Short", description: `HSTS max-age is ${maxAgeMatch[1]} seconds. At least 6 months recommended.`, url, remedy: `Your HSTS max-age is set to ${maxAgeMatch[1]} seconds, which is too short. Browsers will stop enforcing HTTPS after this period.\n\nIncrease it to at least 31536000 (1 year):\n\n   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\nUpdate this in the same place you set the header (Nginx config, next.config.js headers, Apache .htaccess, or your middleware).` });
    }
  }

  if (!headers.get("referrer-policy")) {
    vulns.push({ type: "headers", severity: "low", title: "Missing Referrer-Policy Header", description: "May leak sensitive URL parameters via referrer headers.", url, remedy: "Add a Referrer-Policy header to control how much URL information is shared when users navigate away from your site.\n\nRecommended value:\n\n   Referrer-Policy: strict-origin-when-cross-origin\n\nThis sends the full URL for same-origin requests but only the origin (domain) for cross-origin requests, and nothing when downgrading from HTTPS to HTTP.\n\nAlternatives:\n- 'no-referrer' — never send referrer (most private, but breaks some analytics)\n- 'origin' — only send the domain, never the path\n\nNext.js / Nginx / Express — add alongside your other security headers:\n\n   { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }" });
  }

  if (!headers.get("permissions-policy")) {
    vulns.push({ type: "headers", severity: "low", title: "Missing Permissions-Policy Header", description: "Cannot restrict browser features (camera, mic, geolocation).", url, remedy: "Add a Permissions-Policy header to explicitly disable browser features your site doesn't need, reducing your attack surface.\n\nRecommended policy:\n\n   Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=(), usb=(), magnetometer=(), gyroscope=(), accelerometer=()\n\nThis disables camera, microphone, geolocation, and other sensitive APIs. If your app needs any of these, change () to (self) for that feature.\n\nNext.js (next.config.js):\n\n   { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=(), payment=()' }\n\nNginx:\n\n   add_header Permissions-Policy \"camera=(), microphone=(), geolocation=()\" always;" });
  }

  const server = headers.get("server");
  if (server && (server.includes("/") || /\d/.test(server))) {
    vulns.push({ type: "info-disclosure", severity: "low", title: "Server Version Disclosed", description: `Server header reveals: "${server}".`, url, remedy: `Your server is revealing its software and version ("${server}") which helps attackers target known vulnerabilities for that version.\n\nNginx — add to nginx.conf:\n\n   server_tokens off;\n\nApache — add to httpd.conf or .htaccess:\n\n   ServerTokens Prod\n   ServerSignature Off\n\nExpress.js:\n\n   app.disable('x-powered-by');\n\nIIS — add to web.config:\n\n   <system.webServer><security><requestFiltering removeServerHeader=\"true\" /></security></system.webServer>\n\nCloudflare/Vercel: These platforms typically handle this automatically.` });
  }

  const poweredBy = headers.get("x-powered-by");
  if (poweredBy) {
    vulns.push({ type: "info-disclosure", severity: "low", title: "Technology Disclosed via X-Powered-By", description: `X-Powered-By reveals: "${poweredBy}".`, url, remedy: `The X-Powered-By header is exposing your backend technology ("${poweredBy}"), making it easier for attackers to find known exploits.\n\nExpress.js:\n\n   app.disable('x-powered-by');\n   // or use Helmet: npm install helmet\n   const helmet = require('helmet');\n   app.use(helmet());\n\nPHP (php.ini):\n\n   expose_php = Off\n\nASP.NET (web.config):\n\n   <system.webServer><httpProtocol><customHeaders><remove name=\"X-Powered-By\" /></customHeaders></httpProtocol></system.webServer>\n\nNginx — add a proxy_hide_header directive:\n\n   proxy_hide_header X-Powered-By;\n\nApache:\n\n   Header always unset X-Powered-By` });
  }

  return vulns;
}

async function checkCorsPolicy(baseUrl: string): Promise<VulnerabilityResult[]> {
  const testOrigin = "https://untrusted-origin.scanmysaas.invalid";
  const response = await safeFetch(baseUrl, { timeout: 7000, headers: { Origin: testOrigin } });
  if (!response) return [];
  const allowedOrigin = response.headers.get("access-control-allow-origin") || "";
  const allowsCredentials = response.headers.get("access-control-allow-credentials")?.toLowerCase() === "true";
  if (allowedOrigin !== testOrigin || !allowsCredentials) return [];
  return [{
    type: "cors",
    severity: "high",
    title: "CORS Reflects an Untrusted Origin with Credentials",
    description: `The server reflected the scanner's unrelated Origin value (${testOrigin}) and also returned Access-Control-Allow-Credentials: true. This can let an attacker-controlled site read authenticated responses in a victim's browser.`,
    url: baseUrl,
    remedy: "Replace dynamic Origin reflection with an exact allowlist. Compare the parsed Origin against trusted production origins before returning Access-Control-Allow-Origin, send Access-Control-Allow-Credentials only on routes that require cookie-based cross-origin access, and add Vary: Origin when the response changes by origin. Add a regression test that sends an unrelated Origin and verifies that no permissive CORS headers are returned.",
  }];
}

// ─── 4. CSP deep analysis ──────────────────────────────────────────
type CSPPolicy = Map<string, string[]>;

/**
 * Parse a Content-Security-Policy header value. Multiple enforced policies may be
 * joined with commas; within one policy the FIRST occurrence of a directive wins
 * and later duplicates are ignored (W3C CSP3, "parse a serialized CSP").
 */
export function parseCSP(csp: string): CSPPolicy[] {
  return csp.split(",").map((serialized) => {
    const policy: CSPPolicy = new Map();
    for (const part of serialized.split(";")) {
      const tokens = part.trim().split(/\s+/).filter(Boolean);
      if (!tokens.length) continue;
      const name = tokens[0].toLowerCase();
      if (!policy.has(name)) policy.set(name, tokens.slice(1).map((source) => source.toLowerCase()));
    }
    return policy;
  }).filter((policy) => policy.size > 0);
}

const SCRIPT_FALLBACKS: Record<string, string[]> = {
  "script-src-elem": ["script-src-elem", "script-src", "default-src"],
  "script-src-attr": ["script-src-attr", "script-src", "default-src"],
  "script-src": ["script-src", "default-src"],
};

/** Sources that govern a script directive, or null when the policy does not restrict it. */
export function effectiveSources(policy: CSPPolicy, directive: string): string[] | null {
  for (const name of SCRIPT_FALLBACKS[directive] || [directive, "default-src"]) {
    const sources = policy.get(name);
    if (sources) return sources;
  }
  return null;
}

/** CSP3: 'unsafe-inline' is ignored when the same list has a nonce, a hash, or 'strict-dynamic'. */
export function allowsInlineScript(sources: string[] | null): boolean {
  if (!sources) return true;
  if (!sources.includes("'unsafe-inline'")) return false;
  return !sources.some((source) => source.startsWith("'nonce-") || /^'sha(?:256|384|512)-/.test(source) || source === "'strict-dynamic'");
}

export function analyzeCSP(url: string, csp: string): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];
  const policies = parseCSP(csp);
  if (!policies.length) return vulns;
  // A behaviour is permitted only if every enforced policy permits it.
  const every = (test: (policy: CSPPolicy) => boolean) => policies.every(test);
  const restrictsScripts = (policy: CSPPolicy) => effectiveSources(policy, "script-src-elem") !== null || effectiveSources(policy, "script-src-attr") !== null;
  const inlineAllowed = policies.some(restrictsScripts)
    && every((policy) => allowsInlineScript(effectiveSources(policy, "script-src-elem")) || allowsInlineScript(effectiveSources(policy, "script-src-attr")));
  const evalAllowed = every((policy) => {
    const sources = effectiveSources(policy, "script-src");
    return sources !== null && sources.includes("'unsafe-eval'");
  });
  const hasDirective = (name: string) => policies.some((p) => p.has(name));

  if (inlineAllowed) {
    vulns.push({ type: "csp", severity: "high", title: "CSP Allows Unsafe Inline Scripts", description: "The effective script policy allows inline scripts or inline event handlers ('unsafe-inline' without a nonce, hash or 'strict-dynamic'), which removes most CSP protection against injected scripts.", url, remedy: "The 'unsafe-inline' directive completely undermines CSP's XSS protection because it allows any injected <script> tag to execute. Replace it with nonces or hashes:\n\nUsing nonces (recommended):\n1. Generate a random nonce per request on the server\n2. Add it to your CSP header: script-src 'nonce-abc123'\n3. Add it to each script tag: <script nonce=\"abc123\">\n\nNext.js example (middleware.ts):\n\n   import { NextResponse } from 'next/server';\n   import crypto from 'crypto';\n   export function middleware(req) {\n     const nonce = crypto.randomBytes(16).toString('base64');\n     const csp = `script-src 'nonce-${nonce}' 'strict-dynamic';`;\n     const res = NextResponse.next();\n     res.headers.set('Content-Security-Policy', csp);\n     return res;\n   }\n\nUsing hashes:\n1. Hash each inline script: echo -n 'your script content' | openssl dgst -sha256 -binary | base64\n2. Add to CSP: script-src 'sha256-abc123...'\n\nNote: If you use a framework like React or Vue that requires inline scripts, use 'strict-dynamic' with nonces — it automatically trusts scripts loaded by your nonced scripts." });
  }
  if (evalAllowed) {
    vulns.push({ type: "csp", severity: "high", title: "CSP Allows Unsafe Eval", description: "CSP uses 'unsafe-eval', allowing dynamic code execution.", url, remedy: "'unsafe-eval' allows eval(), Function(), setTimeout('string'), and similar dynamic code execution — a common XSS attack vector. Remove it and refactor your code:\n\nCommon patterns to fix:\n\n1. Replace eval() with JSON.parse():\n   // Bad: eval('(' + data + ')');\n   // Good: JSON.parse(data);\n\n2. Replace new Function() with proper functions:\n   // Bad: const fn = new Function('a', 'b', 'return a + b');\n   // Good: const fn = (a, b) => a + b;\n\n3. Replace string-based setTimeout/setInterval:\n   // Bad: setTimeout('doSomething()', 1000);\n   // Good: setTimeout(doSomething, 1000);\n\n4. If a library requires eval (e.g., some template engines), consider switching to a CSP-compatible alternative. For example, use Handlebars precompiled templates instead of runtime compilation.\n\n5. For Angular apps, use AOT compilation instead of JIT to eliminate the need for unsafe-eval." });
  }

  const checkedDirectives = ["default-src", "script-src", "style-src", "img-src", "connect-src", "font-src", "object-src", "media-src", "frame-src"];
  for (const dir of checkedDirectives) {
    if (every((p) => Boolean(p.get(dir)?.includes("*")))) {
      vulns.push({ type: "csp", severity: "medium", title: `CSP Wildcard in ${dir}`, description: `${dir} uses a wildcard (*), allowing content from any source.`, url, remedy: `A wildcard (*) in ${dir} defeats the purpose of CSP for that resource type — any domain can serve content. Replace it with specific trusted domains.\n\nExample fix:\n\n   # Instead of:\n   ${dir} *\n\n   # Use specific origins:\n   ${dir} 'self' https://cdn.yourdomain.com https://fonts.googleapis.com\n\nCommon patterns:\n- script-src: 'self' plus your CDN and analytics domains\n- style-src: 'self' 'unsafe-inline' (if needed) plus font providers\n- img-src: 'self' data: plus your image CDN\n- connect-src: 'self' plus your API domains\n- font-src: 'self' plus font CDNs like fonts.gstatic.com\n\nTip: Use your browser's DevTools console — CSP violations are logged there, helping you identify exactly which domains to whitelist.` });
      break;
    }
  }

  const objectRestricted = policies.some((p) => {
    const sources = p.get("object-src") || p.get("default-src");
    return Boolean(sources && !sources.includes("*"));
  });
  if (!objectRestricted) {
    vulns.push({ type: "csp", severity: "medium", title: "CSP Does Not Restrict Object Sources", description: "Plugin content not restricted.", url, remedy: "Without restricting object-src, attackers can inject Flash, Java applets, or other plugin content that can execute arbitrary code and bypass your other CSP rules.\n\nAdd this to your CSP header:\n\n   object-src 'none'\n\nThis blocks all <object>, <embed>, and <applet> elements. Since Flash is dead and Java applets are obsolete, 'none' is almost always the right choice.\n\nFull CSP example with object-src:\n\n   Content-Security-Policy: default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self';\n\nIf you absolutely need to embed PDFs via <object>, use:\n\n   object-src 'self'" });
  }
  if (!hasDirective("base-uri")) {
    vulns.push({ type: "csp", severity: "low", title: "CSP Missing base-uri", description: "Attackers can use <base> tags to hijack URLs.", url, remedy: "Without base-uri, an attacker who can inject HTML (even without script execution) can add a <base href=\"https://evil.com\"> tag. This hijacks all relative URLs on the page — links, form actions, and script srcs will resolve against the attacker's domain.\n\nAdd this to your CSP header:\n\n   base-uri 'self'\n\nThis restricts <base> tags to only point to your own origin. In virtually all cases, 'self' is the correct value. Only omit this if you genuinely need <base> tags pointing to external domains (very rare).\n\nExample:\n\n   Content-Security-Policy: default-src 'self'; base-uri 'self'; script-src 'self';" });
  }
  if (!hasDirective("form-action")) {
    vulns.push({ type: "csp", severity: "low", title: "CSP Missing form-action", description: "Injected forms could submit to external servers.", url, remedy: "Without form-action, an attacker who injects a <form> can set its action to an external server, stealing user input (credentials, personal data) when the form is submitted.\n\nAdd this to your CSP header:\n\n   form-action 'self'\n\nThis ensures all form submissions go to your own origin only.\n\nIf you use third-party payment processors or OAuth redirects, whitelist those specific domains:\n\n   form-action 'self' https://checkout.stripe.com https://accounts.google.com\n\nFull example:\n\n   Content-Security-Policy: default-src 'self'; form-action 'self' https://checkout.stripe.com; base-uri 'self';" });
  }

  return vulns;
}

// ─── 5. Cookie security ───────────────────────────────────────────
interface ParsedCookie { name: string; attributes: Map<string, string> }

/** One entry per Set-Cookie header; never merge cookies before checking attributes. */
export function parseSetCookies(headers: Headers): ParsedCookie[] {
  const raw = typeof headers.getSetCookie === "function" ? headers.getSetCookie() : (headers.get("set-cookie") ? [headers.get("set-cookie")!] : []);
  return raw.map((line) => {
    const [pair, ...attributeParts] = line.split(";");
    const attributes = new Map<string, string>();
    for (const part of attributeParts) {
      const [key, ...value] = part.split("=");
      if (key.trim()) attributes.set(key.trim().toLowerCase(), value.join("=").trim().toLowerCase());
    }
    return { name: pair.split("=")[0].trim(), attributes };
  }).filter((cookie) => cookie.name)
    .filter((cookie, index, all) => all.findLastIndex((other) => other.name === cookie.name) === index);
}

function isSessionLikeCookie(name: string) {
  return /(?:sess|sid|auth|token|jwt|login|remember|account|user)/i.test(name);
}

export function checkCookies(url: string, headers: Headers): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];
  const cookies = parseSetCookies(headers);
  if (!cookies.length) return vulns;
  const isHttps = new URL(url).protocol === "https:";
  const missingHttpOnly = cookies.filter((cookie) => !cookie.attributes.has("httponly"));
  const sensitiveWithoutHttpOnly = missingHttpOnly.filter((cookie) => isSessionLikeCookie(cookie.name));
  const missingSecure = isHttps ? cookies.filter((cookie) => !cookie.attributes.has("secure")) : [];
  const missingSameSite = cookies.filter((cookie) => !cookie.attributes.has("samesite"));
  const parentDomain = cookies.filter((cookie) => (cookie.attributes.get("domain") || "").startsWith("."));
  const names = (list: ParsedCookie[]) => list.map((cookie) => cookie.name).slice(0, 8).join(", ");

  if (missingHttpOnly.length) vulns.push({ type: "cookies", severity: sensitiveWithoutHttpOnly.length ? "medium" : "low", title: "Cookies Without HttpOnly", description: `${missingHttpOnly.length} cookie(s) readable by JavaScript: ${names(missingHttpOnly)}.${sensitiveWithoutHttpOnly.length ? " At least one looks like a session or authentication cookie." : " None look like session cookies; confirm they hold no secrets."}`, url, remedy: "Without the HttpOnly flag, any JavaScript running on the page — including injected XSS scripts — can read cookies via document.cookie, stealing session tokens and authentication data.\n\nAdd the HttpOnly flag to all sensitive cookies:\n\nExpress.js:\n\n   res.cookie('session', token, {\n     httpOnly: true,\n     secure: true,\n     sameSite: 'lax'\n   });\n\nNext.js API route:\n\n   res.setHeader('Set-Cookie', 'session=abc123; HttpOnly; Secure; SameSite=Lax; Path=/');\n\nPHP:\n\n   setcookie('session', $token, [\n     'httponly' => true,\n     'secure' => true,\n     'samesite' => 'Lax'\n   ]);\n\nDjango (settings.py):\n\n   SESSION_COOKIE_HTTPONLY = True\n\nNote: Only cookies that need JavaScript access (like a CSRF token read by your frontend) should omit HttpOnly. Session cookies and auth tokens should always have it." });
  if (missingSecure.length) vulns.push({ type: "cookies", severity: "medium", title: "Cookies Without Secure Flag", description: `${missingSecure.length} cookie(s) may be sent over plain HTTP: ${names(missingSecure)}.`, url, remedy: "Without the Secure flag, cookies will be sent over unencrypted HTTP connections, allowing attackers on the same network (Wi-Fi sniffing, MITM attacks) to intercept session tokens.\n\nAdd the Secure flag to all cookies:\n\nExpress.js:\n\n   res.cookie('session', token, {\n     secure: true,\n     httpOnly: true,\n     sameSite: 'lax'\n   });\n\nNginx (proxy level):\n\n   proxy_cookie_flags ~ secure httponly;\n\nApache:\n\n   Header always edit Set-Cookie ^(.*)$ \"$1; Secure\"\n\nPHP (php.ini):\n\n   session.cookie_secure = 1\n\nDjango:\n\n   SESSION_COOKIE_SECURE = True\n   CSRF_COOKIE_SECURE = True\n\nRails:\n\n   Rails.application.config.session_store :cookie_store, secure: true\n\nImportant: The Secure flag requires HTTPS. Make sure your site fully supports HTTPS before enabling this, or cookies won't be sent at all." });
  if (missingSameSite.length) vulns.push({ type: "cookies", severity: "low", title: "Cookies Without SameSite", description: `${missingSameSite.length} cookie(s) rely on the browser default (Lax in modern browsers): ${names(missingSameSite)}.`, url, remedy: "Without the SameSite attribute, cookies are sent with every request to your site — even if the request originates from a malicious third-party site. This enables CSRF (Cross-Site Request Forgery) attacks.\n\nAdd SameSite to all cookies:\n\nRecommended values:\n- SameSite=Lax — cookies sent on top-level navigations (links) but NOT on cross-site POST/AJAX. Best for most session cookies.\n- SameSite=Strict — cookies never sent cross-site. Use for highly sensitive apps, but breaks login-via-link flows.\n- SameSite=None — cookies sent everywhere (must include Secure flag). Only use for legitimate cross-site scenarios like embedded widgets.\n\nExpress.js:\n\n   res.cookie('session', token, {\n     sameSite: 'lax',\n     httpOnly: true,\n     secure: true\n   });\n\nDjango:\n\n   SESSION_COOKIE_SAMESITE = 'Lax'\n\nPHP:\n\n   setcookie('session', $token, [\n     'samesite' => 'Lax',\n     'httponly' => true,\n     'secure' => true\n   ]);\n\nNote: Modern browsers default to Lax if SameSite is not specified, but older browsers send cookies everywhere. Explicitly setting SameSite protects all users." });
  if (parentDomain.length) vulns.push({ type: "cookies", severity: "low", title: "Cookie Scoped to Parent Domain", description: `Shared with every subdomain: ${names(parentDomain)}.`, url, remedy: "When a cookie's Domain attribute starts with a dot (e.g., Domain=.example.com), the cookie is shared across ALL subdomains — including any subdomain an attacker might control (e.g., compromised.example.com, user-content.example.com).\n\nThis means a compromised or untrusted subdomain can read and manipulate your session cookies.\n\nFix — scope cookies to the most specific domain:\n\n1. Remove the Domain attribute entirely (cookie defaults to exact host only):\n\n   Set-Cookie: session=abc123; Path=/; HttpOnly; Secure\n   // Without Domain=, this cookie is ONLY sent to the exact hostname\n\n2. If you must share across subdomains, minimize scope:\n\n   // Instead of Domain=.example.com (ALL subdomains)\n   // Use the most specific subdomain needed\n   Set-Cookie: session=abc123; Domain=app.example.com; Path=/; HttpOnly; Secure\n\n3. If your app runs on a shared hosting platform, never set Domain at all — let the browser default to the exact origin.\n\nBest practice: Use separate cookies for separate subdomains. Don't share session tokens across subdomains unless absolutely necessary." });

  return vulns;
}

/** Remove comments and string/template literals so sink names in text are not mistaken for code. */
export function stripJsLiteralsAndComments(code: string): string {
  let out = "";
  for (let i = 0; i < code.length; i++) {
    const ch = code[i];
    const next = code[i + 1];
    if (ch === "/" && next === "/") { while (i < code.length && code[i] !== "\n") i++; out += "\n"; continue; }
    if (ch === "/" && next === "*") { i += 2; while (i < code.length && !(code[i] === "*" && code[i + 1] === "/")) i++; i++; out += " "; continue; }
    if (ch === '"' || ch === "'" || ch === "`") {
      i++;
      while (i < code.length && code[i] !== ch) { if (code[i] === "\\") i++; i++; }
      out += '""';
      continue;
    }
    out += ch;
  }
  return out;
}

// ─── 6. HTML security checks ──────────────────────────────────────
export function checkHTMLSecurity(url: string, html: string): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];
  const $ = cheerio.load(html);

  // CSRF — evaluated per form. A missing visible token is a review signal, not proof.
  const tokenName = /(?:^|[_\-.[])(?:csrf|xsrf|_?token|authenticity_token|csrfmiddlewaretoken|__requestverificationtoken|_wpnonce|nonce)(?:$|[_\-.\]])/i;
  let formsWithoutToken = 0;
  $("form").each((_, form) => {
    const method = ($(form).attr("method") || "get").toLowerCase();
    if (!["post", "put", "patch", "delete"].includes(method)) return;
    const inputNames = $(form).find("input[name]").map((__, input) => $(input).attr("name") || "").get();
    // Next.js server actions carry $ACTION_ fields and are protected by an Origin check.
    if (inputNames.some((name) => tokenName.test(name) || name.startsWith("$ACTION_"))) return;
    formsWithoutToken += 1;
  });
  if (formsWithoutToken > 0) vulns.push({ type: "csrf", severity: "low", title: "Forms Without Visible CSRF Token", description: `${formsWithoutToken} state-changing form(s) have no visible anti-CSRF token. This is a review signal: SameSite cookies, Origin checks or framework protections may still block cross-site submissions.`, url, remedy: "Without CSRF (Cross-Site Request Forgery) protection, attackers can create a hidden form on their site that auto-submits to YOUR site using your logged-in user's session. This can change passwords, make purchases, or delete accounts — all without the user knowing.\n\nHow to fix by framework:\n\nNext.js / React (using server actions or API routes):\n1. Generate a CSRF token on the server and embed it in your form:\n\n   import crypto from 'crypto';\n   const csrfToken = crypto.randomBytes(32).toString('hex');\n   // Store in session/cookie, then embed in form:\n   <input type=\"hidden\" name=\"_csrf\" value={csrfToken} />\n\n2. Validate on submission:\n   if (req.body._csrf !== session.csrfToken) return res.status(403).json({ error: 'Invalid CSRF token' });\n\nExpress.js (using csurf or csrf-csrf):\n\n   npm install csrf-csrf\n\n   import { doubleCsrf } from 'csrf-csrf';\n   const { generateToken, doubleCsrfProtection } = doubleCsrf({ getSecret: () => 'your-secret' });\n   app.use(doubleCsrfProtection);\n   // In your form route:\n   app.get('/form', (req, res) => {\n     res.render('form', { csrfToken: generateToken(req, res) });\n   });\n\nDjango (built-in):\n   <!-- In your template -->\n   <form method=\"POST\">\n     {% csrf_token %}\n     ...\n   </form>\n\nLaravel (built-in):\n   <form method=\"POST\">\n     @csrf\n     ...\n   </form>\n\nRails (built-in):\n   <%= form_with do |f| %>\n     <!-- csrf_meta_tags automatically included -->\n   <% end %>\n\nAdditionally, setting SameSite=Lax on session cookies provides a strong layer of CSRF defense in modern browsers, as it prevents cookies from being sent on cross-site POST requests." });

  // Unsafe JS patterns
  const inlineScripts = $('script:not([src]):not([type="application/ld+json"]):not([type="application/json"])');
  let hasUnsafe = false;
  inlineScripts.each((_, s) => {
    const c = $(s).html() || "";
    if (!c.includes("__next_f.push") && /(?:document\.write\s*\(|\.innerHTML\s*=(?!=)|\beval\s*\(|\.outerHTML\s*=(?!=)|\.insertAdjacentHTML\s*\()/i.test(stripJsLiteralsAndComments(c))) hasUnsafe = true;
  });
  if (hasUnsafe) vulns.push({ type: "xss", severity: "medium", title: "Unsafe JavaScript Patterns", description: "Inline scripts call DOM sinks (document.write, innerHTML, eval). This is a review signal: it becomes XSS only if user-controlled data reaches the sink.", url, remedy: "These JavaScript patterns can introduce XSS (Cross-Site Scripting) vulnerabilities if they process any user-controlled data. Attackers can inject malicious scripts that steal cookies, redirect users, or deface your site.\n\nReplace each pattern with safer alternatives:\n\n1. innerHTML → textContent (for text) or DOM API (for elements):\n   // Bad: element.innerHTML = userInput;\n   // Good: element.textContent = userInput;\n   // If you need HTML: use DOMPurify to sanitize first:\n   import DOMPurify from 'dompurify';\n   element.innerHTML = DOMPurify.sanitize(userInput);\n\n2. document.write → DOM manipulation:\n   // Bad: document.write('<p>' + data + '</p>');\n   // Good: const p = document.createElement('p');\n   //       p.textContent = data;\n   //       document.body.appendChild(p);\n\n3. eval() → JSON.parse() or proper function calls:\n   // Bad: eval(serverResponse);\n   // Good: JSON.parse(serverResponse);\n\n4. outerHTML → replaceWith():\n   // Bad: el.outerHTML = newHTML;\n   // Good: const newEl = document.createElement('div');\n   //       newEl.textContent = data;\n   //       el.replaceWith(newEl);\n\n5. insertAdjacentHTML → insertAdjacentText or createElement:\n   // Bad: el.insertAdjacentHTML('beforeend', userInput);\n   // Good: el.insertAdjacentText('beforeend', userInput);\n\nFor React/Vue/Angular apps, these frameworks handle DOM escaping automatically — avoid using dangerouslySetInnerHTML (React) or v-html (Vue) with user data." });

  // Mixed content
  const httpRes = $('img[src^="http:"], script[src^="http:"], link[href^="http:"], iframe[src^="http:"]');
  if (httpRes.length > 0) vulns.push({ type: "ssl", severity: "medium", title: "Mixed Content Detected", description: `${httpRes.length} resource(s) loaded over HTTP.`, url, remedy: "Mixed content occurs when an HTTPS page loads resources (images, scripts, stylesheets, iframes) over plain HTTP. This allows attackers to intercept and modify those resources via man-in-the-middle attacks — potentially injecting malicious scripts into your page.\n\nFix — update all resource URLs to use HTTPS:\n\n1. Search and replace http:// → https:// in your source code:\n   <!-- Bad -->\n   <img src=\"http://cdn.example.com/image.jpg\" />\n   <script src=\"http://cdn.example.com/script.js\"></script>\n\n   <!-- Good -->\n   <img src=\"https://cdn.example.com/image.jpg\" />\n   <script src=\"https://cdn.example.com/script.js\"></script>\n\n2. Use protocol-relative or absolute HTTPS URLs:\n   <img src=\"//cdn.example.com/image.jpg\" />   <!-- protocol-relative -->\n   <img src=\"https://cdn.example.com/image.jpg\" /> <!-- explicit HTTPS, preferred -->\n\n3. Add upgrade-insecure-requests CSP directive to auto-upgrade HTTP to HTTPS:\n   Content-Security-Policy: upgrade-insecure-requests\n\n   Or as a meta tag:\n   <meta http-equiv=\"Content-Security-Policy\" content=\"upgrade-insecure-requests\">\n\n4. Check for resources set dynamically in JavaScript — search your code for http:// URLs in JS strings.\n\nNote: Browsers block 'active' mixed content (scripts, iframes) by default but only warn about 'passive' mixed content (images, video). Both should be fixed." });

  // SRI
  let missingIntegrity = 0;
  $("script[src]").each((_, el) => {
    try { const h = new URL($(el).attr("src") || "", url).hostname; if (h !== new URL(url).hostname && !$(el).attr("integrity")) missingIntegrity++; } catch { /* ignore */ }
  });
  $('link[rel="stylesheet"][href]').each((_, el) => {
    try { const h = new URL($(el).attr("href") || "", url).hostname; if (h !== new URL(url).hostname && !$(el).attr("integrity")) missingIntegrity++; } catch { /* ignore */ }
  });
  if (missingIntegrity > 0) vulns.push({ type: "sri", severity: "medium", title: "External Resources Without SRI", description: `${missingIntegrity} external resource(s) missing integrity attribute.`, url, remedy: "Subresource Integrity (SRI) ensures that files loaded from CDNs or third-party servers haven't been tampered with. Without it, a compromised CDN can serve malicious code to all your users.\n\nAdd integrity and crossorigin attributes to external scripts and stylesheets:\n\n   <script src=\"https://cdn.example.com/lib.js\"\n     integrity=\"sha384-oqVuAfXRKap7fdgcCY5uykM6+R9GqQ8K/uxy9rx7HNQlGYl1kPzQho1wx4JwY8wC\"\n     crossorigin=\"anonymous\"></script>\n\n   <link rel=\"stylesheet\" href=\"https://cdn.example.com/style.css\"\n     integrity=\"sha384-...\"\n     crossorigin=\"anonymous\">\n\nHow to generate SRI hashes:\n\n1. Using openssl:\n   cat file.js | openssl dgst -sha384 -binary | openssl base64 -A\n\n2. Using the SRI Hash Generator: https://www.srihash.org/\n\n3. Using npm:\n   npx ssri-hash https://cdn.example.com/lib.js\n\nFor bundlers:\n- Webpack: use the webpack-subresource-integrity plugin\n- Vite: use vite-plugin-sri\n\nNote: SRI only works for resources served with proper CORS headers (Access-Control-Allow-Origin). The crossorigin=\"anonymous\" attribute is required." });

  // Outdated libraries
  const depLibs: { name: string; version: string }[] = [];
  $("script[src]").each((_, el) => {
    const src = ($(el).attr("src") || "").toLowerCase();
    const jq = src.match(/jquery[.-](\d+\.\d+\.\d+)/);
    if (jq) { const [maj, min] = jq[1].split(".").map(Number); if (maj < 3 || (maj === 3 && min < 5)) depLibs.push({ name: "jQuery", version: jq[1] }); }
    if (src.includes("angular") && src.match(/angular[.-]1\./)) depLibs.push({ name: "AngularJS 1.x", version: "1.x" });
    const bs = src.match(/bootstrap[.-](\d+\.\d+\.\d+)/);
    if (bs && parseInt(bs[1]) < 4) depLibs.push({ name: "Bootstrap", version: bs[1] });
  });
  if (depLibs.length > 0) vulns.push({ type: "outdated-lib", severity: "medium", title: "Outdated JavaScript Libraries", description: `Detected: ${depLibs.map((l) => `${l.name} ${l.version}`).join(", ")}.`, url, remedy: "Outdated JavaScript libraries often contain known security vulnerabilities with public exploits. Attackers actively scan for sites using old versions.\n\nUpdate each library to the latest version:\n\n1. Check for updates:\n   npm outdated          # See what's behind\n   npm audit              # Check for known vulnerabilities\n   npm audit fix          # Auto-fix compatible updates\n   npm audit fix --force  # Fix breaking changes (test thoroughly!)\n\n2. Common upgrades:\n   - jQuery < 3.5: npm install jquery@latest (jQuery 3.5+ fixed major XSS in htmlPrefilter)\n   - AngularJS 1.x: Migrate to Angular 2+ (AngularJS is end-of-life since Dec 2021)\n   - Bootstrap < 4: npm install bootstrap@latest (Bootstrap 3 has known XSS in tooltip/popover)\n\n3. If upgrading breaks things, check migration guides:\n   - jQuery: https://jquery.com/upgrade-guide/\n   - Bootstrap: https://getbootstrap.com/docs/5.3/migration/\n\n4. Consider using a CDN with auto-updates like cdnjs or jsDelivr with semver ranges.\n\n5. Add automated dependency scanning:\n   - GitHub Dependabot (free, automatic PRs for security updates)\n   - Snyk: npx snyk test\n   - npm audit in CI/CD pipeline" });

  // Missing meta description
  if (!$('meta[name="description"]').length) vulns.push({ type: "seo", severity: "info", title: "Missing Meta Description", description: "No meta description tag.", url, remedy: "A missing meta description means search engines will auto-generate a snippet from your page content, which often looks poor in search results and reduces click-through rates.\n\nAdd a meta description to every page:\n\n   <meta name=\"description\" content=\"Your compelling page description here. Keep it between 150-160 characters for optimal display in search results.\" />\n\nNext.js App Router (layout.tsx or page.tsx):\n\n   export const metadata = {\n     description: 'Your page description here',\n   };\n\nNext.js Pages Router:\n\n   import Head from 'next/head';\n   <Head>\n     <meta name=\"description\" content=\"Your page description\" />\n   </Head>\n\nReact (react-helmet):\n\n   <Helmet>\n     <meta name=\"description\" content=\"Your page description\" />\n   </Helmet>\n\nBest practices:\n- Keep it between 150-160 characters\n- Include your primary keyword naturally\n- Write a unique description for each page\n- Make it compelling — it's your ad copy in search results\n- Don't stuff keywords — Google penalizes this" });

  // Sensitive comments
  let sensComments = 0;
  let match;
  const commentRe = /<!--([\s\S]*?)-->/g;
  while ((match = commentRe.exec(html)) !== null) {
    const c = match[1].toLowerCase();
    if (/\b(?:password|api[_-]?key|client[_-]?secret|access[_-]?token|private[_-]?key)\s*[:=]\s*["']?[^\s"']{8,}/i.test(c) && !/example|placeholder|changeme|your[_-]/i.test(c)) sensComments++;
  }
  if (sensComments > 0) vulns.push({ type: "info-disclosure", severity: "low", title: "Sensitive Info in HTML Comments", description: `${sensComments} comment(s) with sensitive keywords.`, url, remedy: "HTML comments are visible to anyone who views your page source. Comments containing passwords, API keys, database names, TODO/FIXME notes, or admin URLs give attackers valuable reconnaissance information.\n\nHow to fix:\n\n1. Search your codebase for HTML comments with sensitive content:\n   grep -rn '<!--' --include='*.html' --include='*.jsx' --include='*.tsx' --include='*.ejs' .\n\n2. Remove or move sensitive comments:\n   - Move TODO/FIXME items to your issue tracker (GitHub Issues, Jira)\n   - Move implementation notes to code comments (// or /* */) in server-side code\n   - Never leave API keys, credentials, or database info in any comments\n   - Remove debug comments before deploying\n\n3. Add a build step to strip HTML comments:\n\n   Webpack (html-webpack-plugin):\n     new HtmlWebpackPlugin({ minify: { removeComments: true } })\n\n   PostHTML:\n     npm install posthtml-remove-comments\n\n4. Add to your CI/CD pipeline — a pre-deploy check for sensitive patterns:\n\n   grep -rn '<!--.*\\(password\\|api_key\\|secret\\|database\\|admin\\|credential\\)' dist/\n   if [ $? -eq 0 ]; then echo 'Sensitive comments found!' && exit 1; fi" });

  // Forms over HTTP
  $("form[action]").each((_, f) => {
    const action = $(f).attr("action") || "";
    if (action.startsWith("http://")) vulns.push({ type: "ssl", severity: "high", title: "Form Submits Over HTTP", description: `Form posts to ${action} in plain text.`, url, remedy: "This form sends user data (potentially including passwords, credit cards, or personal information) over unencrypted HTTP. Anyone on the same network can intercept this data using simple tools like Wireshark.\n\nFix — change the form action to HTTPS:\n\n   <!-- Bad -->\n   <form action=\"http://example.com/submit\">\n\n   <!-- Good -->\n   <form action=\"https://example.com/submit\">\n\nIf the form action is dynamically generated:\n\n   // Bad\n   const formAction = `http://${domain}/api/submit`;\n   // Good\n   const formAction = `https://${domain}/api/submit`;\n\nIf the form has no action attribute, it submits to the current page URL. Make sure your page is served over HTTPS.\n\nAdditional steps:\n1. Ensure your entire site runs on HTTPS (see the SSL/TLS findings)\n2. Add the upgrade-insecure-requests CSP directive as a safety net:\n   Content-Security-Policy: upgrade-insecure-requests\n3. Set HSTS headers to prevent HTTP downgrade attacks\n4. Use form-action CSP directive to restrict where forms can submit:\n   Content-Security-Policy: form-action 'self' https:" });
  });

  // Source map references in HTML
  const srcMapRefs = html.match(/\/\/[#@]\s*sourceMappingURL=\S+/g);
  if (srcMapRefs && srcMapRefs.length > 0) {
    vulns.push({ type: "source-maps", severity: "medium", title: "Source Map References in HTML", description: `${srcMapRefs.length} source map reference(s) found, exposing original source code.`, url, remedy: "Source map references (//# sourceMappingURL=...) in your production HTML point to .map files that contain your entire original source code — including comments, variable names, and application logic. Attackers use this to understand your code structure and find vulnerabilities.\n\nRemove source maps from production builds:\n\nWebpack (webpack.config.js):\n   module.exports = {\n     mode: 'production',\n     devtool: false,  // Disables source maps entirely\n   };\n\nVite (vite.config.ts):\n   export default defineConfig({\n     build: { sourcemap: false }\n   });\n\nNext.js (next.config.js):\n   module.exports = {\n     productionBrowserSourceMaps: false, // Default is already false\n   };\n\nCreate React App (.env):\n   GENERATE_SOURCEMAPS=false\n\nIf you still need source maps for error monitoring (Sentry, Datadog):\n1. Generate source maps during build\n2. Upload them to your error monitoring service\n3. Delete the .map files before deploying\n4. Remove sourceMappingURL comments from the bundled JS:\n   sed -i 's/\\/\\/# sourceMappingURL=.*//g' dist/**/*.js" });
  }

  return vulns;
}

// ─── 7. Sensitive file exposure ───────────────────────────────────
export function matchesExpectedSensitiveFile(path: string, contentType: string, text: string) {
  const sample = text.slice(0, 120_000);
  const lower = sample.toLowerCase();
  if (path === "/.env") return /(?:^|\n)[A-Z][A-Z0-9_]{2,}\s*=\s*[^\n]+/.test(sample);
  if (path === "/.git/config") return /\[core\]|repositoryformatversion|\[remote\s+"origin"\]/i.test(sample);
  if (path === "/.git/HEAD") return /^(?:ref:\s+refs\/|[a-f0-9]{40}\s*$)/i.test(sample.trim());
  if (path === "/.DS_Store") return sample.includes("Bud1") || contentType.includes("octet-stream");
  if (path === "/wp-admin/") return /wp-login|wordpress|user_login|wp-admin/i.test(sample);
  if (path === "/server-status") return /apache server status|server version:|server uptime:/i.test(sample);
  if (path === "/phpinfo.php") return /php version|phpinfo\(\)|php logo/i.test(sample);
  if (path === "/.htaccess") return /rewriteengine|rewriterule|authname|deny from|require all|options\s+[+-]/i.test(sample);
  if (path.endsWith(".sql")) return /(?:create\s+table|insert\s+into|postgresql database dump|mysql dump)/i.test(sample);
  if (path.endsWith(".log")) return /(?:stack trace|traceback|fatal error|uncaught exception|\berror\b.*(?:at |line \d+))/i.test(sample);
  if (path === "/elmah.axd") return /error log for|elmah|error detail/i.test(sample);
  if (path === "/.svn/entries") return /(?:^|\n)(?:dir|file)\s*(?:\n|$)|svn:/i.test(sample);
  if (path === "/crossdomain.xml") return /<cross-domain-policy|<allow-access-from/i.test(sample);
  if (path === "/composer.json") return /"(?:require|autoload|config)"\s*:/i.test(sample);
  if (path === "/package.json") return /"(?:dependencies|devDependencies|scripts)"\s*:/i.test(sample);
  if (path === "/Dockerfile") return /(?:^|\n)\s*FROM\s+\S+/i.test(sample);
  if (path === "/docker-compose.yml") return /(?:^|\n)services\s*:\s*(?:\n|$)/i.test(sample);
  if (path === "/wp-config.php.bak") return /DB_(?:NAME|USER|PASSWORD|HOST)|AUTH_KEY|table_prefix/i.test(sample);
  return lower.length > 0;
}

async function checkSensitiveFiles(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];

  const files = [
    { path: "/.env", title: ".env File Exposed", severity: "critical" as const, desc: "Environment file with credentials is publicly accessible.", remedy: "Your .env file contains API keys, database passwords, and secrets — this is a critical exposure. Anyone can download it and access your entire infrastructure.\n\nImmediate actions:\n1. ROTATE ALL CREDENTIALS in the .env file immediately — they are compromised\n2. Block access to the file:\n\nNginx:\n   location ~ /\\.env { deny all; return 404; }\n\nApache (.htaccess):\n   <FilesMatch \"^\\.env\">\n     Deny from all\n   </FilesMatch>\n\nVercel/Netlify: These platforms don't serve dotfiles by default. If exposed, check your build output or static file serving config.\n\n3. Add .env to .gitignore if not already there\n4. Never commit .env files to version control\n5. Use platform environment variables (Vercel env, AWS Secrets Manager) instead of .env files in production" },
    { path: "/.git/config", title: "Git Repository Exposed", severity: "critical" as const, desc: ".git directory accessible — full source code downloadable.", remedy: "Your entire Git repository is publicly accessible. Attackers can download your complete source code, commit history (including deleted secrets), and branch information using tools like git-dumper.\n\nImmediate actions:\n1. Block access to .git directory:\n\nNginx:\n   location ~ /\\.git { deny all; return 404; }\n\nApache (.htaccess):\n   RedirectMatch 404 /\\.git\n\n2. Review your commit history for leaked secrets:\n   git log --all --full-history -p | grep -i 'password\\|secret\\|api_key\\|token'\n   Rotate any credentials found.\n\n3. If this is a deployment issue, ensure your deployment process only copies built files, not the .git directory.\n\n4. Consider using git-filter-repo to permanently remove secrets from history if the repo is public." },
    { path: "/.git/HEAD", title: "Git HEAD Exposed", severity: "critical" as const, desc: ".git/HEAD accessible, confirming repo exposure.", remedy: "The .git/HEAD file is accessible, confirming your entire Git repository can be reconstructed by attackers. They can use automated tools to download all objects and reconstruct your full source code.\n\nBlock the entire .git directory:\n\nNginx:\n   location ~ /\\.git { deny all; return 404; }\n\nApache (.htaccess):\n   RedirectMatch 404 /\\.git\n\nCaddy:\n   @git path /.git/*\n   respond @git 404\n\nAlso: Check that your deployment process doesn't copy the .git directory to production. Use rsync --exclude='.git' or a proper CI/CD build step." },
    { path: "/.DS_Store", title: ".DS_Store Exposed", severity: "low" as const, desc: "macOS file reveals directory structure.", remedy: ".DS_Store files are created by macOS Finder and contain directory listing information. While not directly dangerous, they reveal your file/folder structure, helping attackers map your application.\n\nFix:\n1. Block access:\n   Nginx: location ~ /\\.DS_Store { deny all; return 404; }\n   Apache: <FilesMatch \"^\\.DS_Store\"> Deny from all </FilesMatch>\n\n2. Add to .gitignore:\n   echo '.DS_Store' >> .gitignore\n   find . -name '.DS_Store' -delete\n   git rm --cached $(git ls-files -i -c --exclude='.DS_Store')\n\n3. Prevent macOS from creating them on network drives:\n   defaults write com.apple.desktopservices DSDontWriteNetworkStores true" },
    { path: "/wp-admin/", title: "WordPress Admin Exposed", severity: "medium" as const, desc: "WordPress admin panel publicly accessible.", remedy: "Your WordPress admin panel is accessible to anyone, making it a target for brute-force attacks and exploit attempts.\n\nRestrict access:\n1. Limit by IP (Nginx):\n   location /wp-admin {\n     allow 203.0.113.0/24;  # Your office IP\n     deny all;\n   }\n\n2. Add HTTP Basic Auth as extra layer:\n   Nginx:\n   location /wp-admin {\n     auth_basic \"Admin\";\n     auth_basic_user_file /etc/nginx/.htpasswd;\n   }\n\n3. Use a security plugin like Wordfence or iThemes Security to:\n   - Limit login attempts\n   - Enable 2FA\n   - Change the admin URL (wp-admin → custom path)\n\n4. Disable XML-RPC if not needed:\n   <FilesMatch \"xmlrpc\\.php\"> Deny from all </FilesMatch>" },
    { path: "/server-status", title: "Apache Status Exposed", severity: "medium" as const, desc: "Apache mod_status page accessible.", remedy: "Apache's mod_status page reveals active connections, request details, server uptime, CPU usage, and sometimes client IPs and requested URLs.\n\nRestrict access in Apache config:\n\n   <Location /server-status>\n     SetHandler server-status\n     Require ip 127.0.0.1 ::1\n     # Or your admin IP:\n     # Require ip 203.0.113.0/24\n   </Location>\n\nOr disable mod_status entirely if not needed:\n   sudo a2dismod status\n   sudo systemctl reload apache2\n\nAlso check for /server-info which reveals even more configuration details." },
    { path: "/phpinfo.php", title: "PHP Info Exposed", severity: "high" as const, desc: "phpinfo() page reveals server configuration.", remedy: "phpinfo() exposes your complete server configuration: PHP version, loaded modules, environment variables, server paths, and potentially sensitive configuration values. This is a goldmine for attackers.\n\nImmediate action:\n1. Delete the file: rm /var/www/html/phpinfo.php\n2. Search for other phpinfo files: find /var/www -name '*phpinfo*' -o -name '*info.php*'\n3. Block access as a safety net:\n   Nginx: location ~* phpinfo\\.php$ { deny all; return 404; }\n4. Disable phpinfo() in production (php.ini):\n   disable_functions = phpinfo, exec, system, passthru, shell_exec\n5. Never create phpinfo() files in production — use the CLI instead:\n   php -i | grep 'setting_name'" },
    { path: "/.htaccess", title: ".htaccess Exposed", severity: "medium" as const, desc: ".htaccess file readable.", remedy: "Your .htaccess file is readable, potentially revealing URL rewrite rules, authentication mechanisms, IP restrictions, and server configuration details.\n\nFix in Apache config (httpd.conf or apache2.conf):\n\n   <FilesMatch \"^\\.ht\">\n     Require all denied\n   </FilesMatch>\n\nThis should be the default in most Apache installations. If it's not working:\n1. Check that AllowOverride is properly set\n2. Ensure the FilesMatch directive is in the right context\n3. Restart Apache: sudo systemctl reload apache2\n\nNginx (if proxying to Apache):\n   location ~ /\\.ht { deny all; return 404; }" },
    { path: "/wp-config.php.bak", title: "WP Config Backup Exposed", severity: "critical" as const, desc: "WordPress config backup with credentials.", remedy: "A WordPress config backup file is publicly accessible. This file contains your database credentials, authentication keys, table prefix, and other sensitive configuration.\n\nImmediate actions:\n1. DELETE the backup file immediately\n2. ROTATE all credentials in wp-config.php:\n   - Database password\n   - AUTH_KEY, SECURE_AUTH_KEY, LOGGED_IN_KEY, NONCE_KEY and their SALT counterparts\n   - Generate new keys at: https://api.wordpress.org/secret-key/1.1/salt/\n3. Block backup file access:\n   Nginx: location ~* \\.(bak|old|orig|save|swp|tmp)$ { deny all; return 404; }\n   Apache: <FilesMatch \"\\.(bak|old|orig|save|swp|tmp)$\"> Deny from all </FilesMatch>\n4. Never create backups with predictable extensions in the web root" },
    { path: "/backup.sql", title: "SQL Backup Exposed", severity: "critical" as const, desc: "Database backup publicly accessible.", remedy: "Your database backup is publicly downloadable. This exposes ALL your data: user credentials, personal information, business data, and database structure.\n\nImmediate actions:\n1. DELETE the file from the web root immediately\n2. Assume ALL data in the backup is compromised:\n   - Force password resets for all users\n   - Rotate all API keys and secrets stored in the database\n   - Notify affected users if personal data was exposed (GDPR/CCPA requirement)\n3. Block SQL files:\n   Nginx: location ~* \\.(sql|sql\\.gz|sql\\.bz2|dump)$ { deny all; return 404; }\n   Apache: <FilesMatch \"\\.(sql|dump)$\"> Deny from all </FilesMatch>\n4. Store backups outside the web root (e.g., /var/backups/) or use cloud storage (S3 with encryption)\n5. Set up automated backups that go directly to secure storage, not the web directory" },
    { path: "/database.sql", title: "Database Dump Exposed", severity: "critical" as const, desc: "SQL dump publicly accessible.", remedy: "Your database dump is publicly downloadable. This exposes ALL your data: user credentials, personal information, business data, and database structure.\n\nImmediate actions:\n1. DELETE the file from the web root immediately\n2. Assume ALL data is compromised and follow incident response:\n   - Force password resets for all users\n   - Rotate all API keys and secrets\n   - Check legal obligations for data breach notification\n3. Block SQL files:\n   Nginx: location ~* \\.(sql|sql\\.gz|sql\\.bz2|dump)$ { deny all; return 404; }\n4. Never store database backups in the web root\n5. Use proper backup solutions: pg_dump to S3, mysqldump to encrypted cloud storage" },
    { path: "/debug.log", title: "Debug Log Exposed", severity: "medium" as const, desc: "Debug log reveals application internals.", remedy: "Debug logs can contain stack traces, SQL queries, file paths, user data, session tokens, and internal API calls — all valuable for attackers.\n\nFix:\n1. Move log files outside the web root:\n   # Instead of /var/www/html/debug.log\n   # Use /var/log/myapp/debug.log\n\n2. Block log files:\n   Nginx: location ~* \\.(log|logs)$ { deny all; return 404; }\n   Apache: <FilesMatch \"\\.(log|logs)$\"> Deny from all </FilesMatch>\n\n3. Disable debug logging in production:\n   - WordPress: define('WP_DEBUG_LOG', false); in wp-config.php\n   - Laravel: APP_DEBUG=false in .env\n   - Django: DEBUG = False in settings.py\n\n4. Configure your app to write logs to a proper logging service (CloudWatch, Datadog, Papertrail) instead of files" },
    { path: "/error.log", title: "Error Log Exposed", severity: "medium" as const, desc: "Error log reveals stack traces.", remedy: "Error logs expose stack traces, file paths, database query errors, and framework details — giving attackers a detailed map of your application internals.\n\nFix:\n1. Move log files outside the web root:\n   # Good: /var/log/myapp/error.log\n   # Bad: /var/www/html/error.log\n\n2. Block log file access:\n   Nginx: location ~* \\.(log|logs)$ { deny all; return 404; }\n   Apache: <FilesMatch \"\\.(log|logs)$\"> Deny from all </FilesMatch>\n\n3. Configure error logging to go to system logs:\n   PHP: error_log = /var/log/php/error.log (in php.ini)\n   Apache: ErrorLog /var/log/apache2/error.log\n   Nginx: error_log /var/log/nginx/error.log;\n\n4. Use a centralized logging service for production (Sentry, Datadog, etc.)" },
    { path: "/elmah.axd", title: "ELMAH Error Log Exposed", severity: "high" as const, desc: ".NET error handler exposed.", remedy: "ELMAH (Error Logging Modules and Handlers) exposes detailed error information including stack traces, server variables, request data, and potentially sensitive user input.\n\nRestrict access in web.config:\n\n   <location path=\"elmah.axd\">\n     <system.web>\n       <authorization>\n         <deny users=\"*\" />\n         <allow roles=\"Admin\" />\n       </authorization>\n     </system.web>\n   </location>\n\nOr restrict by IP:\n\n   <security>\n     <ipSecurity allowUnlisted=\"false\">\n       <add ipAddress=\"127.0.0.1\" allowed=\"true\" />\n       <add ipAddress=\"your.office.ip\" allowed=\"true\" />\n     </ipSecurity>\n   </security>\n\nBetter: Use elmah.io (cloud service) instead of the built-in handler, which removes the need for the public endpoint entirely." },
    { path: "/.svn/entries", title: "SVN Repository Exposed", severity: "critical" as const, desc: ".svn directory exposes source code.", remedy: "Your Subversion repository metadata is accessible. Attackers can reconstruct your entire source code, including commit history and potentially deleted files containing secrets.\n\nImmediate actions:\n1. Block .svn access:\n   Nginx: location ~ /\\.svn { deny all; return 404; }\n   Apache: RedirectMatch 404 /\\.svn\n\n2. Remove .svn directories from the web root:\n   find /var/www -name '.svn' -type d -exec rm -rf {} +\n\n3. Switch to a deployment method that doesn't include .svn:\n   - Use svn export instead of svn checkout for deployments\n   - Or better, switch to Git and use proper CI/CD pipelines\n\n4. Review source code for hardcoded credentials and rotate them" },
    { path: "/crossdomain.xml", title: "crossdomain.xml Exposed", severity: "medium" as const, desc: "Flash cross-domain policy found.", remedy: "crossdomain.xml is a Flash/Silverlight cross-domain policy file. While Flash is officially dead, an overly permissive policy can still be leveraged in edge cases.\n\nIf you don't use Flash/Silverlight (you shouldn't):\n   Delete the file: rm crossdomain.xml\n\nIf you must keep it, use the most restrictive policy:\n\n   <?xml version=\"1.0\"?>\n   <cross-domain-policy>\n     <site-control permitted-cross-domain-policies=\"none\"/>\n   </cross-domain-policy>\n\nNever use: <allow-access-from domain=\"*\"/> — this allows any domain to make cross-origin requests via Flash." },
    { path: "/composer.json", title: "Composer Config Exposed", severity: "medium" as const, desc: "PHP dependencies revealed.", remedy: "Your composer.json exposes all PHP dependencies and their versions, helping attackers identify known vulnerabilities in your stack.\n\nBlock access:\n   Nginx: location ~* (composer\\.json|composer\\.lock)$ { deny all; return 404; }\n   Apache: <FilesMatch \"composer\\.(json|lock)$\"> Deny from all </FilesMatch>\n\nBetter: Deploy only the vendor/ directory contents and your application code, not the project metadata files. Use a CI/CD pipeline that runs composer install during build and deploys only the result.\n\nAlso run: composer audit  to check for known vulnerabilities in your dependencies." },
    { path: "/package.json", title: "package.json Exposed", severity: "low" as const, desc: "Node.js dependencies revealed.", remedy: "Your package.json reveals all Node.js dependencies and their version constraints. While lower severity, it helps attackers identify known vulnerabilities to exploit.\n\nBlock access:\n   Nginx: location ~* (package\\.json|package-lock\\.json|yarn\\.lock)$ { deny all; return 404; }\n\nFor most deployments, package.json shouldn't be in the public directory at all. Ensure your build process only outputs built files to the public/served directory:\n   - Next.js: Only the .next/ folder should be served\n   - Express: Serve from a dist/ or public/ folder, not the project root\n   - Static sites: Build to dist/ and only deploy that folder\n\nAlso run: npm audit  to check for known vulnerabilities." },
    { path: "/Dockerfile", title: "Dockerfile Exposed", severity: "high" as const, desc: "Docker build config publicly accessible.", remedy: "Your Dockerfile reveals your entire build process: base images, installed packages, environment setup, internal ports, and potentially embedded secrets or commands.\n\nImmediate actions:\n1. Block access:\n   Nginx: location ~* (Dockerfile|docker-compose)  { deny all; return 404; }\n\n2. Ensure Dockerfile is NOT in your web root / served directory. Your deployment should only serve built application files.\n\n3. Review the Dockerfile for hardcoded secrets:\n   - Never use ENV for secrets in Dockerfiles (they're baked into image layers)\n   - Use Docker secrets or runtime environment variables instead\n   - Use multi-stage builds to keep build-time dependencies out of the final image\n\n4. If using a reverse proxy, ensure it only serves the intended paths." },
    { path: "/docker-compose.yml", title: "Docker Compose Exposed", severity: "high" as const, desc: "Service architecture and possibly credentials exposed.", remedy: "Your docker-compose.yml reveals your entire service architecture: databases, cache servers, internal service names, ports, volume mounts, and potentially environment variables with credentials.\n\nImmediate actions:\n1. Remove from web root or block access:\n   Nginx: location ~* docker-compose { deny all; return 404; }\n\n2. If credentials are in the file, rotate them immediately:\n   - Database passwords\n   - API keys\n   - Any environment variables with sensitive values\n\n3. Use .env files or Docker secrets for sensitive values instead of hardcoding:\n   # Bad: POSTGRES_PASSWORD=mysecretpassword\n   # Good: POSTGRES_PASSWORD=${DB_PASSWORD}  # from .env\n\n4. Ensure your deployment pipeline doesn't copy docker-compose.yml to served directories." },
    { path: "/.well-known/security.txt", title: "security.txt Found", severity: "info" as const, desc: "security.txt found — good practice. Review contents.", remedy: "Having a security.txt file is a security best practice (RFC 9116). It tells security researchers how to responsibly report vulnerabilities to you.\n\nMake sure your security.txt includes:\n\n   Contact: mailto:security@yourdomain.com\n   Expires: 2025-12-31T23:59:59.000Z\n   Preferred-Languages: en\n   Canonical: https://yourdomain.com/.well-known/security.txt\n\nOptional but recommended fields:\n   Policy: https://yourdomain.com/security-policy\n   Hiring: https://yourdomain.com/careers\n   Acknowledgments: https://yourdomain.com/hall-of-fame\n\nBest practices:\n- Keep the Expires date updated (no more than 1 year out)\n- Use a monitored email address for Contact\n- Consider signing the file with PGP\n- Place it at both /.well-known/security.txt and /security.txt" },
    { path: "/.well-known/openid-configuration", title: "OpenID Config Found", severity: "info" as const, desc: "OpenID Connect discovery document available.", remedy: "This is an OpenID Connect discovery endpoint — it's intentionally public and part of the OIDC specification. It allows client applications to discover your authentication server's configuration.\n\nThis is expected behavior if you're running an OAuth/OIDC provider. Review the document to ensure:\n\n1. The issuer URL is correct and uses HTTPS\n2. Only supported grant types and scopes are listed\n3. Token endpoints use HTTPS\n4. The JWKS URI is accessible and serving valid keys\n\nIf you are NOT running an OIDC provider and this endpoint is unexpected, investigate what service is exposing it — it may indicate an internal service that shouldn't be publicly accessible." },
  ];

  // Run ALL checks in parallel
  const checks = files.filter((file) => !["/.well-known/security.txt", "/.well-known/openid-configuration"].includes(file.path)).map(async (file) => {
    const fileUrl = new URL(file.path, baseUrl).toString();
    const res = await safeFetch(fileUrl, { redirect: "follow", timeout: 6000 });
    if (!res || res.status !== 200) return null;

    const ct = res.headers.get("content-type") || "";
    const nonHtml = !file.path.endsWith(".php") && !file.path.endsWith("/") && !file.path.endsWith(".axd");
    if (nonHtml && ct.includes("text/html")) return null;

    try {
      const text = await res.text();
      if (!text.trim() || !matchesExpectedSensitiveFile(file.path, ct, text)) return null;
    } catch { return null; }

    return { type: "sensitive-file", severity: file.severity, title: file.title, description: file.desc, url: fileUrl, remedy: file.remedy } as VulnerabilityResult;
  });

  const results = await Promise.all(checks);
  for (const r of results) { if (r) vulns.push(r); }
  return vulns;
}

// ─── 8. Email security (SPF / DMARC) ─────────────────────────────
async function checkEmailSecurity(url: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const domain = new URL(url).hostname.replace(/^www\./, "");

  const [spfRecords, dmarcRecords] = await Promise.all([
    dnsLookupTxt(domain),
    dnsLookupTxt(`_dmarc.${domain}`),
  ]);

  const hasSPF = spfRecords.some((r) => r.some((t) => t.startsWith("v=spf1")));
  if (!hasSPF) {
    vulns.push({ type: "email", severity: "medium", title: "Missing SPF Record", description: `No SPF record for ${domain}. Email spoofing possible.`, url, remedy: `Without an SPF (Sender Policy Framework) record, anyone can send emails that appear to come from ${domain}. Attackers use this for phishing — sending fake emails to your customers that look legitimate.\n\nAdd a TXT record to your DNS:\n\n   Name: ${domain}\n   Type: TXT\n   Value: v=spf1 include:_spf.google.com ~all\n\nCommon SPF configurations:\n- Google Workspace: v=spf1 include:_spf.google.com ~all\n- Microsoft 365: v=spf1 include:spf.protection.outlook.com ~all\n- SendGrid: v=spf1 include:sendgrid.net ~all\n- Multiple services: v=spf1 include:_spf.google.com include:sendgrid.net ~all\n- If you don't send email from this domain: v=spf1 -all\n\nSPF mechanisms explained:\n- ~all (softfail): Emails from unauthorized servers are marked suspicious but delivered\n- -all (hardfail): Emails from unauthorized servers are rejected — more secure but use after testing\n- +all: NEVER use this — it allows anyone to send as your domain\n\nAfter adding, verify with: dig TXT ${domain}` });
  } else {
    const spfTxt = spfRecords.flat().find((t) => t.startsWith("v=spf1"));
    if (spfTxt?.includes("+all")) {
      vulns.push({ type: "email", severity: "high", title: "SPF Allows All Senders (+all)", description: `SPF uses +all, allowing any server to send as ${domain}.`, url, remedy: `Your SPF record ends with +all, which explicitly allows ANY server in the world to send emails as ${domain}. This completely defeats the purpose of SPF.\n\nFix — change +all to ~all or -all in your DNS TXT record:\n\n   Current (dangerous): v=spf1 ... +all\n   Fixed (recommended): v=spf1 ... ~all   (softfail — marks unauthorized as suspicious)\n   Strictest:           v=spf1 ... -all   (hardfail — rejects unauthorized)\n\nSteps:\n1. Log into your DNS provider (Cloudflare, Route53, Namecheap, etc.)\n2. Find the TXT record for ${domain} that starts with v=spf1\n3. Change +all to ~all (start with softfail to avoid breaking legitimate email)\n4. Monitor for a week using DMARC reports to verify no legitimate email is affected\n5. Optionally upgrade to -all for maximum protection\n\nNote: Some online guides incorrectly suggest +all. This is never correct — it negates all SPF protection.` });
    }
  }

  const hasDMARC = dmarcRecords.some((r) => r.some((t) => t.startsWith("v=DMARC1")));
  if (!hasDMARC) {
    vulns.push({ type: "email", severity: "medium", title: "Missing DMARC Record", description: `No DMARC record for ${domain}.`, url, remedy: `Without DMARC (Domain-based Message Authentication, Reporting & Conformance), receiving email servers don't know what to do when SPF or DKIM checks fail. Attackers can freely spoof your domain for phishing.\n\nAdd a DMARC TXT record to your DNS:\n\n   Name: _dmarc.${domain}\n   Type: TXT\n   Value: v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain}; pct=100; adkim=s; aspf=s\n\nDMARC policies (start with quarantine, upgrade to reject):\n- p=none: Monitor only — spoofed emails still delivered (testing phase)\n- p=quarantine: Spoofed emails go to spam folder (recommended starting point)\n- p=reject: Spoofed emails are completely rejected (strongest protection)\n\nRecommended rollout:\n1. Start with p=none to collect reports without affecting email delivery\n2. Review DMARC reports for 2-4 weeks to identify legitimate senders\n3. Move to p=quarantine once confident\n4. Finally move to p=reject for maximum protection\n\nFree DMARC report analyzers:\n- dmarcian.com\n- mxtoolbox.com/dmarc.aspx\n- easydmarc.com\n\nAlso set up DKIM signing with your email provider for even stronger email authentication.` });
  } else {
    const dmarcTxt = dmarcRecords.flat().find((t) => t.startsWith("v=DMARC1"));
    if (dmarcTxt?.includes("p=none")) {
      vulns.push({ type: "email", severity: "low", title: "DMARC Policy Set to None", description: "DMARC p=none — spoofed emails won't be blocked.", url, remedy: `Your DMARC policy is set to p=none, which only monitors — it doesn't actually block spoofed emails. This is fine as a temporary testing phase, but should be upgraded.\n\nUpgrade path:\n1. Review your DMARC reports (sent to the rua= address) to confirm all legitimate email sources are properly authenticated with SPF and DKIM\n2. Upgrade to quarantine:\n   v=DMARC1; p=quarantine; rua=mailto:dmarc-reports@${domain}; pct=100\n3. After confirming no issues, upgrade to reject:\n   v=DMARC1; p=reject; rua=mailto:dmarc-reports@${domain}; pct=100\n\nYou can use pct= to gradually roll out stricter policies:\n   v=DMARC1; p=reject; pct=25; ...  (reject 25% of failing emails)\n   Then increase to 50, 75, 100 over weeks.\n\nCommon issues before upgrading:\n- Marketing emails sent through third-party services need SPF/DKIM alignment\n- Forwarded emails may fail DMARC — this is expected\n- Transactional email services (SendGrid, SES) need to be in your SPF record` });
    }
  }

  return vulns;
}

// ─── 9. robots.txt analysis ───────────────────────────────────────
async function checkRobotsTxt(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const robotsUrl = new URL("/robots.txt", baseUrl).toString();
  const res = await safeFetch(robotsUrl);
  if (!res || res.status !== 200) return vulns;
  const ct = res.headers.get("content-type") || "";
  if (ct.includes("text/html")) return vulns;
  const text = await res.text();
  if (!text.trim()) return vulns;

  const sensitivePatterns = ["/admin", "/login", "/dashboard", "/api", "/config", "/backup", "/database", "/secret", "/private", "/internal", "/staging", "/debug", "/phpMyAdmin", "/wp-admin", "/panel"];
  const exposed: string[] = [];
  for (const line of text.split("\n")) {
    const lower = line.toLowerCase().trim();
    if (lower.startsWith("disallow:")) {
      const path = lower.replace("disallow:", "").trim();
      for (const p of sensitivePatterns) { if (path.includes(p.toLowerCase())) { exposed.push(path); break; } }
    }
  }
  if (exposed.length > 0) vulns.push({ type: "info-disclosure", severity: "low", title: "Sensitive Paths in robots.txt", description: `Reveals: ${exposed.slice(0, 5).join(", ")}.`, url: robotsUrl, remedy: "Your robots.txt file is publicly readable (by design), and it lists sensitive paths like admin panels, APIs, or internal dashboards. While robots.txt tells search engines not to crawl these paths, attackers actively read robots.txt to discover hidden endpoints.\n\nFix — don't rely on robots.txt for security:\n\n1. Protect sensitive paths with proper authentication instead:\n   - Require login for /admin, /dashboard, /internal\n   - Use API keys or OAuth for /api endpoints\n\n2. Keep robots.txt simple — only list paths you want to hide from search results, not sensitive paths:\n   User-agent: *\n   Disallow: /api/\n   Sitemap: https://yourdomain.com/sitemap.xml\n\n3. If you want to hide pages from search results without revealing them in robots.txt, use the noindex meta tag instead:\n   <meta name=\"robots\" content=\"noindex, nofollow\">\n\n4. For truly sensitive paths, ensure they return 403/404 for unauthenticated users — that's your real security, not obscurity." });

  if (text.split("\n").some((l) => l.trim().toLowerCase() === "disallow: /")) {
    vulns.push({ type: "seo", severity: "info", title: "robots.txt Blocks All Crawling", description: "Disallow: / blocks all search engines.", url: robotsUrl, remedy: "Your robots.txt has 'Disallow: /' which tells ALL search engines to not crawl any page on your site. This means Google, Bing, and others won't index your site and it won't appear in search results.\n\nIf this is intentional (staging site, internal app):\n   This is fine. No action needed.\n\nIf this is a production site that should be indexed:\n   Replace with selective rules:\n\n   User-agent: *\n   Disallow: /api/\n   Disallow: /dashboard/\n   Disallow: /admin/\n   Allow: /\n\n   Sitemap: https://yourdomain.com/sitemap.xml\n\nCommon mistake: This often happens when a staging robots.txt is accidentally deployed to production. Check your deployment pipeline to ensure environment-specific robots.txt files.\n\nNext.js App Router — create src/app/robots.ts:\n\n   export default function robots() {\n     return {\n       rules: { userAgent: '*', allow: '/', disallow: ['/api/', '/dashboard/'] },\n       sitemap: 'https://yourdomain.com/sitemap.xml',\n     };\n   }" });
  }

  return vulns;
}

// ─── 10. Error page disclosure ────────────────────────────────────
async function checkErrorPages(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const errorUrl = new URL(`/this-page-does-not-exist-${Date.now()}`, baseUrl).toString();
  const res = await safeFetch(errorUrl);
  if (!res) return vulns;
  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("text/html")) return vulns;

  const html = await res.text();
  const lower = html.toLowerCase();
  const leaks = lower.includes("stack trace") || lower.includes("traceback") || lower.includes("exception") || lower.includes("syntax error") || lower.includes("fatal error") || lower.includes("debug mode") || lower.includes("django.") || lower.includes("laravel") || lower.includes("node_modules") || /file ["']?\/[a-z]/i.test(html);

  if (leaks) vulns.push({ type: "info-disclosure", severity: "medium", title: "Error Pages Reveal Details", description: "Error pages expose stack traces or framework info.", url: errorUrl, remedy: "Your error pages are exposing internal details like stack traces, file paths, framework versions, or database query errors. This gives attackers detailed knowledge of your tech stack and potential attack vectors.\n\nFix by framework:\n\nNext.js:\n- Error pages are handled automatically in production mode\n- Create custom error pages: src/app/not-found.tsx and src/app/error.tsx\n- Ensure NODE_ENV=production in your deployment\n\nExpress.js:\n   // Custom error handler (add AFTER all routes)\n   app.use((err, req, res, next) => {\n     console.error(err.stack); // Log internally\n     res.status(500).json({ error: 'Something went wrong' }); // Generic response\n   });\n\nDjango:\n   # settings.py\n   DEBUG = False  # CRITICAL for production\n   ALLOWED_HOSTS = ['yourdomain.com']\n   # Create templates/404.html and templates/500.html\n\nLaravel:\n   # .env\n   APP_DEBUG=false\n   # Create resources/views/errors/500.blade.php\n\nPHP:\n   # php.ini\n   display_errors = Off\n   log_errors = On\n   error_log = /var/log/php/error.log\n\nNginx custom error pages:\n   error_page 404 /404.html;\n   error_page 500 502 503 504 /50x.html;\n\nGeneral: Always log errors server-side but show users a generic 'Something went wrong' message." });
  if (res.status === 200) vulns.push({ type: "seo", severity: "info", title: "Soft 404 — Returns 200", description: "Non-existent pages return 200 instead of 404.", url: errorUrl, remedy: "Your server returns HTTP 200 (OK) for pages that don't exist, instead of 404 (Not Found). This confuses search engines — Google will try to index these non-existent pages, diluting your SEO and wasting your crawl budget.\n\nFix by framework:\n\nNext.js App Router:\n   Create src/app/not-found.tsx — Next.js automatically returns 404 status\n\nExpress.js:\n   // Add after all route definitions\n   app.use((req, res) => {\n     res.status(404).send('Page not found');\n   });\n\nNginx:\n   # Ensure your app returns proper status codes\n   # Don't use try_files with a fallback to index.html for all routes\n   # unless it's a SPA that handles routing client-side\n\nCommon causes:\n- Single Page Apps (React/Vue/Angular) that serve index.html for all routes — the SPA handles routing client-side but the server returns 200. Fix with server-side rendering or a catch-all that returns 404.\n- Catch-all middleware that renders a 'not found' page but forgets to set the status code\n- Custom error handling that returns res.send() instead of res.status(404).send()" });

  return vulns;
}

// ─── 11. Directory listing ────────────────────────────────────────
async function checkDirectoryListing(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const dirs = ["/images/", "/uploads/", "/assets/", "/static/", "/media/", "/files/", "/backup/", "/tmp/", "/css/", "/js/"];

  const checks = dirs.map(async (dir) => {
    const dirUrl = new URL(dir, baseUrl).toString();
    const res = await safeFetch(dirUrl, { timeout: 6000 });
    if (!res || res.status !== 200) return null;
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("text/html")) return null;
    const html = await res.text();
    const l = html.toLowerCase();
    if (l.includes("index of /") || l.includes("directory listing") || l.includes("<title>index of") || l.includes("parent directory</a>")) return dir;
    return null;
  });

  const results = await Promise.all(checks);
  const found = results.filter(Boolean);
  if (found.length > 0) vulns.push({ type: "directory-listing", severity: "medium", title: "Directory Listing Enabled", description: `Listing enabled at ${found.join(", ")}.`, url: new URL(found[0]!, baseUrl).toString(), remedy: "Directory listing allows anyone to browse your server's file structure, seeing every file in a directory. This exposes backup files, configuration files, and other sensitive data you didn't intend to be public.\n\nDisable directory listing:\n\nNginx:\n   # In your server block or location\n   autoindex off;  # This is the default, so check if someone enabled it\n\nApache:\n   # In .htaccess or httpd.conf\n   Options -Indexes\n\n   # Or per-directory:\n   <Directory /var/www/html/uploads>\n     Options -Indexes\n   </Directory>\n\nCaddy:\n   # Remove 'browse' directive from file_server\n   file_server  # Without 'browse'\n\nAlternatively, add an index file to each directory:\n   touch /var/www/html/uploads/index.html\n   touch /var/www/html/images/index.html\n\nBest practice: In addition to disabling directory listing, ensure sensitive files (backups, configs, logs) are stored outside the web root entirely." });

  return vulns;
}

// ─── 12. Technology fingerprinting ────────────────────────────────
function fingerprintTechnology(url: string, html: string, headers: Headers): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];
  const $ = cheerio.load(html);
  const detected: string[] = [];

  const gen = $('meta[name="generator"]').attr("content");
  if (gen) detected.push(`Generator: ${gen}`);

  if (html.includes("wp-content") || html.includes("wp-includes")) detected.push("WordPress");
  if (html.includes("__NEXT_DATA__") || html.includes("_next/static")) detected.push("Next.js");
  if (html.includes("__NUXT__") || html.includes("_nuxt/")) detected.push("Nuxt.js");
  if (html.includes("Drupal.settings")) detected.push("Drupal");
  if (html.includes("cdn.shopify.com")) detected.push("Shopify");
  if (html.includes("wix.com") || html.includes("wixstatic.com")) detected.push("Wix");
  if (html.includes("squarespace.com")) detected.push("Squarespace");
  if (html.includes("webflow.com")) detected.push("Webflow");
  if (html.includes("gatsby-")) detected.push("Gatsby");
  if (html.includes("__sveltekit")) detected.push("SvelteKit");
  if (html.includes("__remixContext")) detected.push("Remix");
  if (html.includes("data-astro")) detected.push("Astro");
  if (html.includes("__vue__")) detected.push("Vue.js");

  const php = headers.get("x-powered-by");
  if (php?.toLowerCase().includes("php")) detected.push(php);
  if (headers.get("x-aspnet-version")) detected.push(`ASP.NET ${headers.get("x-aspnet-version")}`);
  if (headers.get("x-drupal-cache")) detected.push("Drupal (cache)");

  if (detected.length > 0) vulns.push({ type: "fingerprint", severity: "info", title: "Technologies Detected", description: `Found: ${detected.join(", ")}.`, url, remedy: "Technology fingerprinting reveals your framework, CMS, and versions — helping attackers find known vulnerabilities specific to your stack. While not critical, reducing your fingerprint makes automated attacks less likely.\n\nReduce fingerprinting:\n\n1. Remove generator meta tags:\n   WordPress: add_filter('the_generator', '__return_empty_string');\n   Or remove <meta name=\"generator\"> from your theme's header.php\n\n2. Remove version info from headers (see Security Headers findings)\n\n3. Remove framework-specific identifiers:\n   - WordPress: Remove /wp-content/ and /wp-includes/ paths where possible\n   - Rename common paths like /wp-admin if using a security plugin\n\n4. Remove or customize default error pages and favicon (default favicons identify CMS)\n\n5. For JavaScript frameworks (Next.js, Nuxt, etc.):\n   These are inherently detectable via HTML patterns (__NEXT_DATA__, _nuxt/). This is generally acceptable — focus on keeping the framework updated rather than hiding it.\n\nNote: Security through obscurity is not real security. The best defense is keeping all software updated and properly configured, regardless of whether attackers know your stack." });

  return vulns;
}

// ─── 13. API endpoint probing ─────────────────────────────────────
async function checkAPIEndpoints(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];

  const apiPaths = [
    "/api", "/api/v1", "/api/v2", "/api/users", "/api/admin",
    "/api/config", "/api/health", "/api/status", "/api/debug",
    "/graphql",
    "/api/graphql", "/_debug", "/_profiler",
  ];

  const checks = apiPaths.map(async (path) => {
    const apiUrl = new URL(path, baseUrl).toString();
    const res = await safeFetch(apiUrl, { timeout: 6000 });
    if (!res || res.status === 404 || res.status === 403) return null;

    // GraphQL introspection
    if (path.includes("graphql") && res.status === 200) {
      const introRes = await safeFetch(apiUrl, {
        method: "POST", timeout: 6000,
        headers: { "Content-Type": "application/json" },
        body: JSON.stringify({ query: "{ __schema { types { name } } }" }),
      });
      if (introRes?.status === 200) {
        try { const b = await introRes.text(); if (b.includes("__schema")) return { type: "api-exposure", severity: "high" as const, title: "GraphQL Introspection Enabled", description: `GraphQL at ${path} exposes entire API schema.`, url: apiUrl, remedy: "GraphQL introspection allows anyone to query your entire API schema — every type, field, mutation, and relationship. Attackers use this to understand your data model and find attack vectors.\n\nDisable introspection in production:\n\nApollo Server:\n\n   const server = new ApolloServer({\n     typeDefs,\n     resolvers,\n     introspection: process.env.NODE_ENV !== 'production', // Only in dev\n   });\n\nExpress + express-graphql:\n\n   app.use('/graphql', graphqlHTTP({\n     schema,\n     graphiql: false, // Also disable the playground\n   }));\n   // Note: express-graphql doesn't have a built-in toggle — use a validation rule:\n   const { NoSchemaIntrospectionCustomRule } = require('graphql');\n\nYoga / Envelop:\n\n   import { useDisableIntrospection } from '@envelop/disable-introspection';\n   const yoga = createYoga({ plugins: [useDisableIntrospection()] });\n\nAlso:\n- Disable GraphiQL/Playground in production\n- Implement query depth limiting and complexity analysis\n- Use persisted queries to restrict allowed operations\n- Add authentication to your GraphQL endpoint" }; } catch { /* ignore */ }
      }
      return null;
    }

    // Debug endpoints
    if ((path.includes("debug") || path.includes("profiler")) && res.status === 200) {
      const debugBody = (await res.text()).slice(0, 150_000);
      if (!/(?:stack trace|traceback|uncaught exception|debug toolbar|profiler|node_modules|vendor\/[^\s]+\.php)/i.test(debugBody)) return null;
      return { type: "api-exposure", severity: "high" as const, title: "Debug Endpoint Exposed", description: `Debug/profiler at ${path}.`, url: apiUrl, remedy: "Debug and profiler endpoints expose internal application state, request/response details, database queries, performance data, and potentially sensitive configuration. These should NEVER be accessible in production.\n\nFix:\n\n1. Disable debug mode in production:\n   - Django: DEBUG = False in settings.py\n   - Laravel: APP_DEBUG=false in .env\n   - Flask: app.run(debug=False)\n   - Symfony: Remove _profiler routes in production config\n\n2. Remove debug endpoints entirely:\n\n   Express.js:\n   if (process.env.NODE_ENV !== 'production') {\n     app.use('/_debug', debugRouter);\n   }\n\n3. Block at the web server level as a safety net:\n   Nginx:\n   location ~* (debug|profiler|_debug|_profiler) {\n     deny all;\n     return 404;\n   }\n\n4. Use environment-based configuration to ensure debug features are only loaded in development.\n\n5. Set up proper monitoring (Datadog, New Relic, Sentry) instead of relying on exposed debug endpoints." };
    }

    // Health leaking info
    if ((path.includes("health") || path.includes("status")) && res.status === 200) {
      const ct = res.headers.get("content-type") || "";
      if (ct.includes("json")) {
        try { const b = await res.text(); if (b.includes("version") || b.includes("database")) return { type: "info-disclosure", severity: "low" as const, title: "Health Endpoint Reveals Details", description: `${path} reveals infrastructure info.`, url: apiUrl, remedy: "Your health/status endpoint is exposing internal details like software versions, database connection status, memory usage, or service names. Attackers use this to identify vulnerable versions and understand your infrastructure.\n\nFix — limit health responses to simple status:\n\n   // Bad — reveals too much:\n   {\n     \"status\": \"ok\",\n     \"version\": \"2.3.1\",\n     \"database\": \"PostgreSQL 14.2\",\n     \"redis\": \"connected\",\n     \"uptime\": \"14 days\"\n   }\n\n   // Good — minimal public response:\n   { \"status\": \"ok\" }\n\nIf you need detailed health checks for monitoring, create two endpoints:\n\n   // Public (no auth required)\n   app.get('/health', (req, res) => res.json({ status: 'ok' }));\n\n   // Internal (behind auth or IP whitelist)\n   app.get('/health/details', authMiddleware, (req, res) => {\n     res.json({ status: 'ok', version: '2.3.1', db: 'connected' });\n   });\n\nOr restrict the detailed endpoint:\n   Nginx:\n   location /api/health {\n     # Allow monitoring service IPs only\n     allow 10.0.0.0/8;\n     deny all;\n   }" }; } catch { /* ignore */ }
      }
    }

    return null;
  });

  const results = await Promise.all(checks);
  for (const r of results) { if (r) vulns.push(r); }
  return vulns;
}

// ─── 14. HTTP method testing ──────────────────────────────────────
async function checkHTTPMethods(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];

  const traceRes = await safeFetch(baseUrl, { method: "TRACE", timeout: 6000 });
  if (traceRes?.status === 200) {
    const body = await traceRes.text();
    if (body.includes("TRACE")) vulns.push({ type: "http-methods", severity: "medium", title: "TRACE Method Enabled (XST)", description: "TRACE enabled — Cross-Site Tracing possible.", url: baseUrl, remedy: "The TRACE method echoes back the received request, including headers — this means authentication cookies and tokens. Combined with XSS, this enables Cross-Site Tracing (XST), allowing attackers to steal HttpOnly cookies that JavaScript normally can't access.\n\nDisable TRACE:\n\nApache:\n   TraceEnable Off\n\nNginx (TRACE is disabled by default, but verify):\n   if ($request_method = TRACE) {\n     return 405;\n   }\n\nIIS (web.config):\n   <security>\n     <requestFiltering>\n       <verbs>\n         <add verb=\"TRACE\" allowed=\"false\" />\n       </verbs>\n     </requestFiltering>\n   </security>\n\nExpress.js:\n   // Express doesn't handle TRACE by default, but if using a custom server:\n   app.use((req, res, next) => {\n     if (req.method === 'TRACE') return res.status(405).end();\n     next();\n   });\n\nNote: TRACE should be disabled on all production servers. It has no legitimate use in production and only creates security risk." });
  }

  return vulns;
}

// ─── 15. Sitemap analysis ─────────────────────────────────────────
async function checkSitemap(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];

  for (const path of ["/sitemap.xml", "/sitemap_index.xml"]) {
    const sitemapUrl = new URL(path, baseUrl).toString();
    const res = await safeFetch(sitemapUrl, { timeout: 6000 });
    if (!res || res.status !== 200) continue;
    const text = await res.text();
    if (!text.includes("<url") && !text.includes("http")) continue;

    const sensitiveFound: string[] = [];
    for (const p of ["/admin", "/dashboard", "/config", "/internal", "/staging", "/debug", "/api/"]) {
      if (text.toLowerCase().includes(p)) sensitiveFound.push(p);
    }
    if (sensitiveFound.length > 0) vulns.push({ type: "info-disclosure", severity: "low", title: "Sensitive Paths in Sitemap", description: `Sitemap contains: ${sensitiveFound.join(", ")}.`, url: sitemapUrl, remedy: "Your sitemap.xml contains paths to admin panels, dashboards, APIs, or internal pages. While sitemaps are meant for search engines, they're also read by attackers for reconnaissance.\n\nFix:\n1. Remove sensitive paths from your sitemap. Only include pages you want indexed:\n\nNext.js App Router (src/app/sitemap.ts):\n\n   export default function sitemap() {\n     return [\n       { url: 'https://yourdomain.com/', lastModified: new Date() },\n       { url: 'https://yourdomain.com/pricing', lastModified: new Date() },\n       // DON'T include /admin, /dashboard, /api, /internal\n     ];\n   }\n\n2. For pages you want to exclude from search but don't care about hiding:\n   Add <meta name=\"robots\" content=\"noindex\"> to those pages instead of listing them in the sitemap.\n\n3. For dynamic sitemaps, filter out sensitive routes:\n   const publicRoutes = allRoutes.filter(r => \n     !r.startsWith('/admin') && \n     !r.startsWith('/dashboard') && \n     !r.startsWith('/api')\n   );\n\n4. Protect sensitive paths with proper authentication — hiding them from the sitemap is not security, it's obscurity." });
    break;
  }

  return vulns;
}

async function collectSaaSReadiness(baseUrl: string): Promise<VulnerabilityResult[]> {
  const root = new URL(baseUrl);
  const urls = {
    home: root.toString(),
    robots: new URL("/robots.txt", root).toString(),
    sitemap: new URL("/sitemap.xml", root).toString(),
    sitemapIndex: new URL("/sitemap_index.xml", root).toString(),
    llms: new URL("/llms.txt", root).toString(),
    securityWellKnown: new URL("/.well-known/security.txt", root).toString(),
    securityRoot: new URL("/security.txt", root).toString(),
  };

  const [homeRes, robotsRes, sitemapRes, sitemapIndexRes, llmsRes, securityWellKnownRes, securityRootRes, tls] = await Promise.all([
    safeFetch(urls.home, { timeout: 8000 }),
    safeFetch(urls.robots, { timeout: 6000 }),
    safeFetch(urls.sitemap, { timeout: 6000 }),
    safeFetch(urls.sitemapIndex, { timeout: 6000 }),
    safeFetch(urls.llms, { timeout: 6000 }),
    safeFetch(urls.securityWellKnown, { timeout: 6000 }),
    safeFetch(urls.securityRoot, { timeout: 6000 }),
    inspectTlsCertificate(baseUrl),
  ]);

  const readText = async (response: Response | null) => response?.ok ? (await response.text()).slice(0, 250_000) : "";
  const [home, robots, sitemap, sitemapIndex, llms, securityWellKnown, securityRoot] = await Promise.all([
    readText(homeRes), readText(robotsRes), readText(sitemapRes), readText(sitemapIndexRes), readText(llmsRes), readText(securityWellKnownRes), readText(securityRootRes),
  ]);

  const items: ReadinessItem[] = [tls.item];
  if (!robots) items.push({ key: "robots", label: "robots.txt", status: "warning", detail: "No readable robots.txt was found at the root.", url: urls.robots });
  else if (/^\s*disallow:\s*\/\s*$/im.test(robots)) items.push({ key: "robots", label: "robots.txt", status: "warning", detail: "The file appears to block crawling across the site.", url: urls.robots });
  else items.push({ key: "robots", label: "robots.txt", status: "pass", detail: /sitemap:/i.test(robots) ? "Available and includes a sitemap reference." : "Available, but it does not reference a sitemap.", url: urls.robots });

  const sitemapBody = sitemap || sitemapIndex;
  const sitemapUrl = sitemap ? urls.sitemap : urls.sitemapIndex;
  items.push(sitemapBody && /<(urlset|sitemapindex|url|sitemap)[\s>]/i.test(sitemapBody)
    ? { key: "sitemap", label: "XML sitemap", status: "pass", detail: "A readable XML sitemap was found.", url: sitemapUrl }
    : { key: "sitemap", label: "XML sitemap", status: "warning", detail: "No readable XML sitemap was found at the common locations.", url: urls.sitemap });

  items.push(llms && /(^|\n)#{1,3}\s+|https?:\/\//i.test(llms)
    ? { key: "llms", label: "llms.txt", status: "pass", detail: "An AI discovery file with structured content was found.", url: urls.llms }
    : { key: "llms", label: "llms.txt", status: "warning", detail: "Optional AI discovery file not found or not readable.", url: urls.llms });

  const securityBody = securityWellKnown || securityRoot;
  const securityUrl = securityWellKnown ? urls.securityWellKnown : urls.securityRoot;
  items.push(securityBody && /(^|\n)contact:/i.test(securityBody)
    ? { key: "security", label: "security.txt", status: "pass", detail: "A security contact file was found.", url: securityUrl }
    : { key: "security", label: "security.txt", status: "warning", detail: "No valid security.txt contact file was found.", url: urls.securityWellKnown });

  if (home && homeRes) {
    const $ = cheerio.load(home);
    const canonical = $('link[rel="canonical"]').attr("href");
    items.push(canonical
      ? { key: "canonical", label: "Canonical URL", status: "pass", detail: "The homepage declares a canonical URL.", url: new URL(canonical, urls.home).toString() }
      : { key: "canonical", label: "Canonical URL", status: "warning", detail: "The homepage has no canonical link element.", url: urls.home });
    const robotsMeta = $('meta[name="robots"]').attr("content") || "";
    const xRobots = homeRes.headers.get("x-robots-tag") || "";
    const blocked = /noindex/i.test(`${robotsMeta} ${xRobots}`);
    items.push({ key: "indexability", label: "Homepage indexability", status: blocked ? "warning" : "pass", detail: blocked ? "The homepage sends a noindex directive." : "No noindex directive was detected on the homepage.", url: urls.home });
  } else {
    items.push({ key: "canonical", label: "Canonical URL", status: "unknown", detail: "The homepage could not be read.", url: urls.home });
    items.push({ key: "indexability", label: "Homepage indexability", status: "unknown", detail: "The homepage could not be read.", url: urls.home });
  }

  return [
    ...tls.vulnerabilities,
    {
      type: "scan-meta",
      severity: "info",
      title: "SaaS readiness snapshot",
      description: JSON.stringify({ version: 1, items }),
      url: baseUrl,
      remedy: "",
    },
  ];
}

// ─── 16. WAF detection ────────────────────────────────────────────
async function detectWAF(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const res = await safeFetch(baseUrl, { timeout: 8000 });
  if (!res) return vulns;

  const h = res.headers;
  let waf: string | null = null;
  if (h.get("cf-ray")) waf = "Cloudflare";
  else if (h.get("x-sucuri-id")) waf = "Sucuri";
  else if (h.get("x-akamai-transformed")) waf = "Akamai";
  else if (h.get("x-aws-waf")) waf = "AWS WAF";
  else if ((h.get("server") || "").toLowerCase().includes("cloudflare")) waf = "Cloudflare";

  if (waf) {
    vulns.push({ type: "waf", severity: "info", title: `WAF Detected: ${waf}`, description: `${waf} WAF is protecting this site.`, url: baseUrl, remedy: "Great — you have a Web Application Firewall (WAF) in place. This provides an additional layer of protection against common attacks like SQL injection, XSS, and DDoS.\n\nTo maximize your WAF protection:\n\n1. Keep WAF rules updated — enable automatic rule updates if available\n2. Review WAF logs regularly for attack patterns\n3. Configure custom rules for your specific application\n4. Enable bot protection and rate limiting\n5. Set up alerting for blocked attacks above a threshold\n\nRemember: A WAF is a defense-in-depth layer, not a replacement for secure coding. Fix vulnerabilities in your application code even if a WAF is in place — WAFs can be bypassed." });
  }

  return vulns;
}

// ─── 17. Source map detection ─────────────────────────────────────
async function checkSourceMaps(baseUrl: string, pages: string[], snapshots: Map<string, CrawledPage>): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const checked = new Set<string>();

  for (const pageUrl of pages.slice(0, 3)) {
    const snapshot = snapshots.get(pageUrl);
    if (!snapshot) continue;
    const html = snapshot.html;
    const $ = cheerio.load(html);
    const scripts: string[] = [];

    $("script[src]").each((_, el) => {
      const src = $(el).attr("src");
      if (src?.endsWith(".js")) {
        try { const abs = new URL(src, pageUrl).toString(); if (!checked.has(abs)) { checked.add(abs); scripts.push(abs); } } catch { /* */ }
      }
    });

    const checks = scripts.slice(0, 5).map(async (s) => {
      const mapRes = await safeFetch(s + ".map", { timeout: 5000 });
      if (mapRes?.status === 200) {
        const mapCt = mapRes.headers.get("content-type") || "";
        if (mapCt.includes("json") || mapCt.includes("octet-stream")) return s + ".map";
      }
      return null;
    });

    const results = await Promise.all(checks);
    const found = results.filter(Boolean);
    if (found.length > 0) {
      vulns.push({ type: "source-maps", severity: "medium", title: "Source Maps Publicly Accessible", description: `${found.length} .map file(s) accessible.`, url: found[0]!, remedy: "Source map files (.map) contain your complete original source code — pre-minification, with comments, variable names, and application logic. Attackers can reconstruct your entire codebase and find vulnerabilities, hardcoded secrets, or business logic flaws.\n\nRemove source maps from production:\n\nWebpack:\n   module.exports = {\n     mode: 'production',\n     devtool: false,  // No source maps\n   };\n\nVite (vite.config.ts):\n   export default defineConfig({\n     build: { sourcemap: false }\n   });\n\nNext.js (next.config.js):\n   module.exports = {\n     productionBrowserSourceMaps: false, // Default is already false\n   };\n\nCreate React App (.env):\n   GENERATE_SOURCEMAPS=false\n\nIf you need source maps for error monitoring (Sentry, Datadog, Bugsnag):\n1. Generate source maps during build\n2. Upload them to your monitoring service via CLI:\n   npx @sentry/cli sourcemaps upload ./dist\n3. Delete .map files before deploying:\n   find dist -name '*.map' -delete\n4. Remove sourceMappingURL comments:\n   find dist -name '*.js' -exec sed -i 's/\\/\\/# sourceMappingURL=.*//g' {} +\n\nAs a safety net, block .map files at the web server:\n   Nginx: location ~* \\.map$ { deny all; return 404; }" });
      break;
    }
  }

  return vulns;
}

// ─── 18. Redirect chain analysis ──────────────────────────────────
async function checkRedirectChain(url: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const chain: string[] = [url];
  let current = url;
  let hops = 0;

  while (hops < 10) {
    const res = await safeFetch(current, { redirect: "manual", timeout: 6000 });
    if (!res || res.status < 300 || res.status >= 400) break;
    const loc = res.headers.get("location");
    if (!loc) break;
    const next = new URL(loc, current).toString();
    chain.push(next);
    current = next;
    hops++;
  }

  if (hops > 3) vulns.push({ type: "redirect", severity: "low", title: "Excessive Redirect Chain", description: `${hops} redirects: ${chain.slice(0, 4).join(" → ")}…`, url, remedy: "Excessive redirect chains slow down page loading (each redirect adds a full network round-trip), waste crawl budget with search engines, and can cause redirect loops. Most browsers give up after 20 redirects.\n\nFix — minimize redirects to at most 1-2 hops:\n\n1. Point directly to the final URL instead of chaining through intermediaries:\n   # Bad:  http://example.com → https://example.com → https://www.example.com → https://www.example.com/\n   # Good: http://example.com → https://www.example.com/  (single redirect)\n\n2. Common causes:\n   - HTTP → HTTPS → www → trailing slash (fix by consolidating into one redirect)\n   - Old URLs redirecting through multiple legacy paths\n   - Marketing redirects chaining through tracking services\n\n3. Nginx — single consolidated redirect:\n   server {\n     listen 80;\n     server_name example.com www.example.com;\n     return 301 https://www.example.com$request_uri;\n   }\n\n4. Update internal links and canonical URLs to point to the final destination directly.\n\n5. Use 301 (permanent) redirects for SEO — they pass link equity to the destination." });

  const hasHTTP = chain.some((u) => u.startsWith("http://"));
  const hasHTTPS = chain.some((u) => u.startsWith("https://"));
  if (hasHTTP && hasHTTPS && hops > 0) vulns.push({ type: "ssl", severity: "medium", title: "Mixed HTTP/HTTPS in Redirects", description: "Redirect chain mixes HTTP and HTTPS.", url, remedy: "Your redirect chain passes through both HTTP and HTTPS URLs. During the HTTP hop, the request (including cookies, headers, and potentially sensitive data) is transmitted in plain text — vulnerable to interception.\n\nFix — ensure the entire redirect chain uses HTTPS:\n\n1. The very first redirect should go to HTTPS:\n   # Bad:  http://example.com → http://www.example.com → https://www.example.com\n   # Good: http://example.com → https://www.example.com (HTTPS from the first hop)\n\n2. Nginx:\n   # Redirect all HTTP to HTTPS immediately\n   server {\n     listen 80;\n     server_name example.com www.example.com;\n     return 301 https://www.example.com$request_uri;\n   }\n\n3. Apache (.htaccess):\n   RewriteEngine On\n   RewriteCond %{HTTPS} off\n   RewriteRule ^ https://www.%{HTTP_HOST}%{REQUEST_URI} [L,R=301]\n\n4. Add HSTS headers to prevent future HTTP requests entirely:\n   Strict-Transport-Security: max-age=31536000; includeSubDomains; preload\n\n5. Check all internal redirects, canonical URLs, and link configurations to ensure they use https:// URLs." });

  return vulns;
}

// ─── Score calculation ─────────────────────────────────────────────
export function calculateScore(vulns: VulnerabilityResult[]): number {
  // Category-based scoring: each category has a weight and we calculate
  // how much of that category's budget is lost based on findings.
  // This prevents a site with many low/info issues from getting 0.

  const categoryWeights: Record<string, number> = {
    ssl: 15,
    headers: 12,
    csp: 8,
    cookies: 6,
    csrf: 8,
    xss: 10,
    "sensitive-file": 10,
    "info-disclosure": 4,
    cors: 5,
    email: 5,
    "api-exposure": 6,
    "http-methods": 3,
    waf: 0,
    redirect: 2,
    "source-maps": 3,
    "directory-listing": 3,
    "open-redirect": 4,
    "outdated-lib": 4,
    sri: 3,
    iframe: 1,
    seo: 0,
    // Privacy, consent and accessibility findings are reported beside the security score, not in it.
    privacy: 0,
    "cookies-consent": 0,
    accessibility: 0,
    fingerprint: 0,
    "scan-meta": 0,
  };

  const severityMultipliers: Record<string, number> = {
    critical: 1.0,
    high: 0.75,
    medium: 0.45,
    low: 0.2,
    info: 0.05,
  };

  // Group vulns by category
  const byCategory = new Map<string, VulnerabilityResult[]>();
  for (const v of vulns) {
    const cat = v.type;
    if (!byCategory.has(cat)) byCategory.set(cat, []);
    byCategory.get(cat)!.push(v);
  }

  let totalWeight = 0;
  let totalLost = 0;

  for (const [cat, weight] of Object.entries(categoryWeights)) {
    if (weight === 0) continue;
    totalWeight += weight;

    const catVulns = byCategory.get(cat);
    if (!catVulns || catVulns.length === 0) continue;

    // Take the worst severity multiplier in this category,
    // then add diminishing amounts for additional findings
    const sorted = [...catVulns].sort(
      (a, b) => (severityMultipliers[b.severity] ?? 0) - (severityMultipliers[a.severity] ?? 0)
    );

    let catLoss = 0;
    for (let i = 0; i < sorted.length; i++) {
      const mult = severityMultipliers[sorted[i].severity] ?? 0.1;
      // Diminishing returns: each additional finding in same category adds less
      const diminish = 1 / (1 + i * 0.6);
      catLoss += mult * diminish;
    }

    // Cap category loss at 100% of its weight
    const lost = Math.min(weight, weight * Math.min(catLoss, 1));
    totalLost += lost;
  }

  // Also handle unknown categories
  for (const [cat, catVulns] of byCategory) {
    if (cat in categoryWeights) continue;
    for (const v of catVulns) {
      const mult = severityMultipliers[v.severity] ?? 0.1;
      totalLost += 2 * mult; // small penalty for unknown categories
    }
  }

  const score = Math.round(((totalWeight - totalLost) / totalWeight) * 100);
  return Math.max(0, Math.min(100, score));
}

// ─── MAIN SCAN FUNCTION ───────────────────────────────────────────
export interface ScanOptions {
  /** Privacy, consent and accessibility checks. Injected by the API routes so the scanner core stays dependency-free. */
  compliance?: ComplianceRunner;
}

export async function scanWebsite(url: string, onProgress?: ProgressCallback, options: ScanOptions = {}): Promise<ScanResult> {
  return scanBudget.run({deadline: Date.now() + 90000, exhausted: false, failedRequests: 0}, () => scanWebsiteWithinBudget(url, onProgress, options));
}

function remainingBudget() {
  const budget = scanBudget.getStore();
  return budget ? budget.deadline - Date.now() : 60_000;
}

async function fetchComplianceHtml(pageUrl: string) {
  const res = await safeFetch(pageUrl, { timeout: 8000 });
  if (!res || !res.ok || !(res.headers.get("content-type") || "").includes("text/html")) return null;
  try { return { url: pageUrl, html: await res.text() }; } catch { return null; }
}
async function scanWebsiteWithinBudget(
  url: string,
  onProgress?: ProgressCallback,
  options: ScanOptions = {},
): Promise<ScanResult> {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  const allVulns: VulnerabilityResult[] = [];
  const totalSteps = 18;
  let currentStepNum = 0;

  const report = (
    label: string, stepName: string, status: "running" | "done" | "error",
    found?: number, pagesDiscovered?: number
  ) => {
    onProgress?.({
      step: stepName, label, status, found,
      totalSteps, currentStep: currentStepNum, pagesDiscovered,
    });
  };

  // ── Step 1: Discover pages ──────────────────────────────────────
  currentStepNum = 1;
  report("Discovering pages…", "crawl", "running");
  const snapshots = new Map<string, CrawledPage>();
  let initialFailure: WebsiteFailure | undefined;
  let incomplete = false;
  const pages = await discoverPages(url, 25, page => snapshots.set(page.url, page), failure => { initialFailure ??= failure; }, () => { incomplete = true; });
  if (pages.length === 0) {
    const failure = initialFailure ?? websiteFailure("network");
    throw new WebsiteScanError(failure.message, failure);
  }
  report(`Found ${pages.length} page(s)`, "crawl", "done", 0, pages.length);

  // The browser consent test (paid plans) runs beside the HTTP checks so it does not add to scan time.
  options.compliance?.start(pages[0], {
    timeoutMs: Math.max(5_000, Math.min(45_000, remainingBudget() - 25_000)),
    assertPublicHost: async (hostname) => { await validateScanTarget(`https://${hostname}/`); },
  });

  // ── Steps 2-7: Independent checks — PARALLEL BATCH 1 ──────────
  currentStepNum = 2;
  report("Checking SSL/TLS…", "ssl", "running");
  report("Probing sensitive files…", "sensitive-files", "running");
  report("Checking SPF & DMARC…", "email", "running");
  report("Analyzing robots.txt…", "robots", "running");
  report("Testing error pages…", "error-pages", "running");
  report("Checking directory listings…", "directories", "running");

  const [sslV, fileV, emailV, robotsV, errorV, dirV] = await Promise.all([
    checkSSL(url), checkSensitiveFiles(url), checkEmailSecurity(url),
    checkRobotsTxt(url), checkErrorPages(url), checkDirectoryListing(url),
  ]);

  allVulns.push(...sslV);
  currentStepNum = 2;
  report("SSL/TLS complete", "ssl", "done", sslV.length);

  allVulns.push(...fileV);
  currentStepNum = 3;
  report("Sensitive files complete", "sensitive-files", "done", fileV.length);

  allVulns.push(...emailV);
  currentStepNum = 4;
  report("Email security complete", "email", "done", emailV.length);

  allVulns.push(...robotsV);
  currentStepNum = 5;
  report("robots.txt complete", "robots", "done", robotsV.length);

  allVulns.push(...errorV);
  currentStepNum = 6;
  report("Error pages complete", "error-pages", "done", errorV.length);

  allVulns.push(...dirV);
  currentStepNum = 7;
  report("Directory listing complete", "directories", "done", dirV.length);

  // ── Steps 8-13: PARALLEL BATCH 2 (new deep checks) ────────────
  currentStepNum = 8;
  report("Probing API endpoints…", "api-probe", "running");
  report("Testing HTTP methods…", "http-methods", "running");
  report("Analyzing sitemap…", "sitemap", "running");
  report("Detecting WAF…", "waf", "running");
  report("Analyzing redirects…", "redirects", "running");
  report("Checking SaaS readiness…", "readiness", "running");

  const [apiV, methodV, sitemapV, wafV, redirectV, readinessV, corsV] = await Promise.all([
    checkAPIEndpoints(url), checkHTTPMethods(url), checkSitemap(url),
    detectWAF(url), checkRedirectChain(url), collectSaaSReadiness(url), checkCorsPolicy(url),
  ]);

  allVulns.push(...apiV);
  currentStepNum = 8;
  report("API scan complete", "api-probe", "done", apiV.length);

  allVulns.push(...methodV);
  allVulns.push(...corsV);
  currentStepNum = 9;
  report("HTTP methods and CORS complete", "http-methods", "done", methodV.length + corsV.length);

  allVulns.push(...sitemapV);
  currentStepNum = 10;
  report("Sitemap complete", "sitemap", "done", sitemapV.length);

  allVulns.push(...wafV);
  currentStepNum = 11;
  report("WAF detection complete", "waf", "done", wafV.length);

  allVulns.push(...redirectV);
  currentStepNum = 12;
  report("Redirect analysis complete", "redirects", "done", redirectV.length);

  allVulns.push(...readinessV);
  currentStepNum = 13;
  report("SaaS readiness complete", "readiness", "done", readinessV.filter((item) => item.type !== "scan-meta").length);

  // ── Steps 14-17: Per-page checks ──────────────────────────────
  currentStepNum = 14;
  report("Analyzing security headers…", "headers", "running");

  let pagesAnalyzed = 0;
  // Cookies are often set on login or app pages, not the homepage: collect them from every page.
  const cookieHeaders = new Headers();

  for (const pageUrl of pages) {
    // Analyze exactly the bounded HTML already read during discovery. A second
    // request used to discard good evidence when the origin later rate-limited us.
    const snapshot = snapshots.get(pageUrl);
    if (!snapshot) { incomplete = true; continue; }
    const res = snapshot;
    for (const cookie of res.headers.getSetCookie?.() ?? []) cookieHeaders.append("set-cookie", cookie);

    if (pagesAnalyzed === 0) {
      const headerVulns = checkSecurityHeaders(pageUrl, res.headers);
      allVulns.push(...headerVulns);
      report("Headers analyzed", "headers", "done", headerVulns.length);

      currentStepNum = 15;

      report("Scanning CSP…", "csp", "running");
      const csp = res.headers.get("content-security-policy");
      if (csp) {
        const cspVulns = analyzeCSP(pageUrl, csp);
        allVulns.push(...cspVulns);
        report("CSP complete", "csp", "done", cspVulns.length);
      } else {
        report("No CSP header", "csp", "done", 0);
      }
    }

    currentStepNum = 16;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("text/html")) {
      report(`Scanning ${new URL(pageUrl).pathname}…`, "html", "running");
      const html = snapshot.html;
      const htmlVulns = checkHTMLSecurity(pageUrl, html);
      allVulns.push(...htmlVulns);

      if (pagesAnalyzed === 0) {
        const techVulns = fingerprintTechnology(pageUrl, html, res.headers);
        allVulns.push(...techVulns);
      }
      pagesAnalyzed += 1;
    }
  }

  if (pagesAnalyzed === 0) {
    throw new WebsiteScanError("The website stopped returning readable HTML before analysis completed. Try again when it is reachable.");
  }

  report("HTML analysis complete", "html", "done", 0);

  report("Auditing cookies…", "cookies", "running");
  const cookieVulns = checkCookies(new URL(url).origin + "/", cookieHeaders);
  allVulns.push(...cookieVulns);
  report("Cookies complete", "cookies", "done", cookieVulns.length);

  // Source maps
  currentStepNum = 17;
  report("Checking source maps…", "source-maps", "running");
  const srcMapV = await checkSourceMaps(url, pages, snapshots);
  allVulns.push(...srcMapV);
  report("Source maps complete", "source-maps", "done", srcMapV.length);

  // Privacy, consent and accessibility
  currentStepNum = 18;
  if (options.compliance) {
    report("Checking privacy & consent…", "compliance", "running");
    const htmlPages = pages.flatMap((pageUrl) => {
      const snapshot = snapshots.get(pageUrl);
      return snapshot && (snapshot.headers.get("content-type") || "").includes("text/html") ? [{ url: pageUrl, html: snapshot.html }] : [];
    });
    const complianceV = await options.compliance.finish({ url, pages: htmlPages, fetchHtml: fetchComplianceHtml, remainingMs: remainingBudget })
      .catch(() => [] as VulnerabilityResult[]);
    allVulns.push(...complianceV);
    report("Privacy & consent complete", "compliance", "done", complianceV.filter((item) => item.type !== "scan-meta" && item.severity !== "info").length);
  }

  // Deduplicate
  const seen = new Set<string>();
  const unique = allVulns.filter((v) => {
    const key = `${v.title}-${v.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  const partial = incomplete || Boolean(scanBudget.getStore()?.exhausted) || Boolean(scanBudget.getStore()?.failedRequests);
  return { url, score: calculateScore(unique), vulnerabilities: unique, pagesScanned: pagesAnalyzed,
    coverage: {partial, pagesDiscovered: pages.length, pagesAnalyzed, note: partial
      ? "Some pages or checks could not be completed within the scan limits. This score uses observed findings only; unread checks are not proof of safety."
      : "Public website checks only. Up to 25 linked HTML pages; authenticated routes and repository code were not reviewed."},
  };
}

