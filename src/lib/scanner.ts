import * as cheerio from "cheerio";

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
}

export interface ScanProgress {
  step: string;
  label: string;
  status: "running" | "done" | "error";
  found?: number;          // vulnerabilities found in this step
  totalSteps: number;
  currentStep: number;
  pagesDiscovered?: number;
}

export type ProgressCallback = (progress: ScanProgress) => void;

// ─── Helper: safe fetch with timeout ───────────────────────────────
async function safeFetch(
  url: string,
  opts: RequestInit & { timeout?: number } = {}
): Promise<Response | null> {
  try {
    const controller = new AbortController();
    const timer = setTimeout(() => controller.abort(), opts.timeout ?? 10000);
    const res = await fetch(url, {
      ...opts,
      signal: controller.signal,
      headers: {
        "User-Agent": "SecureSaaS-Scanner/1.0 (Security Audit Tool)",
        ...(opts.headers as Record<string, string>),
      },
    });
    clearTimeout(timer);
    return res;
  } catch {
    return null;
  }
}

// ─── Helper: DNS TXT lookup ────────────────────────────────────────
async function dnsLookupTxt(hostname: string): Promise<string[][]> {
  try {
    const dns = await import("dns");
    const { promisify } = await import("util");
    const resolveTxt = promisify(dns.resolveTxt);
    return await resolveTxt(hostname);
  } catch {
    return [];
  }
}

// ─── 1. Crawl / discover pages ────────────────────────────────────
async function discoverPages(
  baseUrl: string,
  maxPages: number = 10
): Promise<string[]> {
  const visited = new Set<string>();
  const toVisit = [baseUrl];
  const pages: string[] = [];
  const baseHost = new URL(baseUrl).hostname;

  while (toVisit.length > 0 && pages.length < maxPages) {
    const url = toVisit.shift()!;
    if (visited.has(url)) continue;
    visited.add(url);

    const res = await safeFetch(url, { redirect: "follow" });
    if (!res || !res.ok) continue;

    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("text/html")) continue;

    pages.push(url);
    const html = await res.text();
    const $ = cheerio.load(html);

    $("a[href]").each((_, el) => {
      try {
        const href = $(el).attr("href");
        if (!href) return;
        const abs = new URL(href, url).toString().split("#")[0].split("?")[0];
        if (
          new URL(abs).hostname === baseHost &&
          !visited.has(abs) &&
          abs.startsWith("http")
        ) {
          toVisit.push(abs);
        }
      } catch {
        /* invalid URL */
      }
    });
  }

  return pages.length > 0 ? pages : [baseUrl];
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
        "Install an SSL/TLS certificate (Let's Encrypt is free). Configure your server to redirect all HTTP traffic to HTTPS.",
    });
  }

  // Check HTTP → HTTPS redirect
  if (parsed.protocol === "https:") {
    const httpUrl = url.replace("https://", "http://");
    const res = await safeFetch(httpUrl, { redirect: "manual" });
    if (res && (res.status < 300 || res.status >= 400)) {
      vulns.push({
        type: "ssl",
        severity: "medium",
        title: "HTTP to HTTPS Redirect Missing",
        description:
          "The HTTP version of the site does not redirect to HTTPS. Users who access via HTTP are not automatically upgraded to the secure version.",
        url,
        remedy:
          "Configure a 301 redirect from HTTP to HTTPS. Most hosting providers (Vercel, Netlify, Cloudflare) offer this automatically.",
      });
    }
  }

  return vulns;
}

// ─── 3. Security headers ──────────────────────────────────────────
function checkSecurityHeaders(
  url: string,
  headers: Headers
): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];

  // Content-Security-Policy
  const csp = headers.get("content-security-policy");
  if (!csp) {
    vulns.push({
      type: "headers",
      severity: "high",
      title: "Missing Content-Security-Policy Header",
      description:
        "CSP is not set. This header prevents XSS, clickjacking, and code injection attacks by restricting which content sources are allowed.",
      url,
      remedy:
        "Add a Content-Security-Policy header. Start with: `default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:;`",
    });
  }

  // X-Frame-Options
  if (
    !headers.get("x-frame-options") &&
    !csp?.includes("frame-ancestors")
  ) {
    vulns.push({
      type: "headers",
      severity: "medium",
      title: "Missing X-Frame-Options Header",
      description:
        "Without X-Frame-Options or CSP frame-ancestors, the site is vulnerable to clickjacking — an attacker can embed your site in an iframe on a malicious page.",
      url,
      remedy:
        "Add `X-Frame-Options: DENY` or `SAMEORIGIN`. In modern setups, use CSP's `frame-ancestors 'none'` directive instead.",
    });
  }

  // X-Content-Type-Options
  if (!headers.get("x-content-type-options")) {
    vulns.push({
      type: "headers",
      severity: "medium",
      title: "Missing X-Content-Type-Options Header",
      description:
        "Without this header, browsers may MIME-sniff responses, potentially executing malicious files as scripts.",
      url,
      remedy: "Add `X-Content-Type-Options: nosniff` to prevent MIME-sniffing.",
    });
  }

  // Strict-Transport-Security
  const hsts = headers.get("strict-transport-security");
  if (!hsts) {
    vulns.push({
      type: "headers",
      severity: "high",
      title: "Missing Strict-Transport-Security (HSTS) Header",
      description:
        "Without HSTS, browsers won't enforce HTTPS for your domain, leaving users vulnerable to SSL-stripping downgrade attacks.",
      url,
      remedy:
        "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload` to enforce HTTPS for one year.",
    });
  } else {
    // Check HSTS max-age is sufficient
    const maxAgeMatch = hsts.match(/max-age=(\d+)/);
    if (maxAgeMatch) {
      const maxAge = parseInt(maxAgeMatch[1]);
      if (maxAge < 15768000) {
        vulns.push({
          type: "headers",
          severity: "low",
          title: "HSTS max-age Too Short",
          description: `HSTS max-age is set to ${maxAge} seconds (${Math.round(maxAge / 86400)} days). For production sites, at least 6 months (15768000) is recommended.`,
          url,
          remedy:
            "Increase HSTS max-age to at least 31536000 (1 year). Add includeSubDomains and preload if possible.",
        });
      }
    }
  }

  // X-XSS-Protection
  if (!headers.get("x-xss-protection")) {
    vulns.push({
      type: "headers",
      severity: "low",
      title: "Missing X-XSS-Protection Header",
      description:
        "The X-XSS-Protection header provides an extra layer of XSS protection for older browsers. Modern browsers rely on CSP instead.",
      url,
      remedy:
        "Add `X-XSS-Protection: 1; mode=block`. Note: CSP is the modern replacement.",
    });
  }

  // Referrer-Policy
  if (!headers.get("referrer-policy")) {
    vulns.push({
      type: "headers",
      severity: "low",
      title: "Missing Referrer-Policy Header",
      description:
        "Without Referrer-Policy, your site may leak sensitive URL parameters in referrer headers when users navigate to external sites.",
      url,
      remedy:
        "Add `Referrer-Policy: strict-origin-when-cross-origin` or `no-referrer` for maximum privacy.",
    });
  }

  // Permissions-Policy
  if (!headers.get("permissions-policy")) {
    vulns.push({
      type: "headers",
      severity: "low",
      title: "Missing Permissions-Policy Header",
      description:
        "Without Permissions-Policy, you cannot restrict which browser features (camera, microphone, geolocation, payment) your site can access.",
      url,
      remedy:
        "Add `Permissions-Policy: camera=(), microphone=(), geolocation=(), payment=()` to disable unused features.",
    });
  }

  // Server info disclosure
  const server = headers.get("server");
  if (server && (server.includes("/") || /\d/.test(server))) {
    vulns.push({
      type: "info-disclosure",
      severity: "low",
      title: "Server Version Information Disclosed",
      description: `The Server header reveals: "${server}". Version information helps attackers identify known vulnerabilities for that specific version.`,
      url,
      remedy:
        "Remove or genericize the Server header. Most reverse proxies (Nginx, Cloudflare) can strip version info.",
    });
  }

  // X-Powered-By
  const poweredBy = headers.get("x-powered-by");
  if (poweredBy) {
    vulns.push({
      type: "info-disclosure",
      severity: "low",
      title: "Technology Stack Disclosed via X-Powered-By",
      description: `The X-Powered-By header reveals: "${poweredBy}". This helps attackers target framework-specific exploits.`,
      url,
      remedy:
        "Remove X-Powered-By. Express: `app.disable('x-powered-by')`. Next.js: `poweredByHeader: false` in next.config.js.",
    });
  }

  // CORS misconfiguration
  const acao = headers.get("access-control-allow-origin");
  if (acao === "*") {
    vulns.push({
      type: "cors",
      severity: "medium",
      title: "Overly Permissive CORS Policy",
      description:
        "Access-Control-Allow-Origin is set to '*', allowing any website to make requests to your API. If your endpoints handle sensitive data, this is a security risk.",
      url,
      remedy:
        "Restrict CORS to specific trusted origins instead of using wildcard '*'. Use your framework's CORS middleware to whitelist only your frontend domains.",
    });
  }

  // Check for Access-Control-Allow-Credentials with wildcard
  if (
    acao === "*" &&
    headers.get("access-control-allow-credentials") === "true"
  ) {
    vulns.push({
      type: "cors",
      severity: "high",
      title: "CORS Credentials with Wildcard Origin",
      description:
        "The server allows credentials (cookies/auth) with a wildcard origin. This is a critical CORS misconfiguration that can leak authentication data.",
      url,
      remedy:
        "Never use Access-Control-Allow-Origin: * with Access-Control-Allow-Credentials: true. Specify exact trusted origins.",
    });
  }

  // Cache-Control for sensitive pages
  const cacheControl = headers.get("cache-control");
  if (!cacheControl || (!cacheControl.includes("no-store") && !cacheControl.includes("private"))) {
    vulns.push({
      type: "headers",
      severity: "info",
      title: "Missing Cache-Control for Sensitive Content",
      description:
        "The page does not set restrictive Cache-Control headers. Sensitive pages may be cached by proxies or browsers, potentially exposing user data.",
      url,
      remedy:
        "For sensitive pages, add `Cache-Control: no-store, no-cache, must-revalidate, private`.",
    });
  }

  return vulns;
}

// ─── 4. CSP deep analysis ──────────────────────────────────────────
function analyzeCSP(url: string, csp: string): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];

  if (csp.includes("'unsafe-inline'") && csp.includes("script-src")) {
    vulns.push({
      type: "csp",
      severity: "high",
      title: "CSP Allows Unsafe Inline Scripts",
      description:
        "The CSP uses 'unsafe-inline' in script-src. This negates most XSS protection since attackers can inject inline scripts.",
      url,
      remedy:
        "Remove 'unsafe-inline' from script-src. Use nonces or hashes instead. Refactor inline scripts to external files.",
    });
  }

  if (csp.includes("'unsafe-eval'")) {
    vulns.push({
      type: "csp",
      severity: "high",
      title: "CSP Allows Unsafe Eval",
      description:
        "The CSP uses 'unsafe-eval', allowing eval(), Function(), and similar dynamic code execution — opening the door to code injection.",
      url,
      remedy:
        "Remove 'unsafe-eval' from CSP. Refactor code to avoid eval(), new Function(), setTimeout with strings.",
    });
  }

  // Wildcard sources
  const directives = [
    "default-src",
    "script-src",
    "style-src",
    "img-src",
    "connect-src",
    "font-src",
    "object-src",
    "media-src",
    "frame-src",
  ];
  for (const dir of directives) {
    const regex = new RegExp(`${dir}[^;]*\\*`, "i");
    if (regex.test(csp)) {
      vulns.push({
        type: "csp",
        severity: "medium",
        title: `CSP Wildcard in ${dir}`,
        description: `The CSP ${dir} directive uses a wildcard (*), allowing content from any source. This significantly weakens CSP protection.`,
        url,
        remedy: `Replace the wildcard in ${dir} with specific trusted domains. Use 'self' for same-origin resources.`,
      });
      break;
    }
  }

  // object-src unrestricted
  if (!csp.includes("object-src") || csp.match(/object-src[^;]*\*/)) {
    vulns.push({
      type: "csp",
      severity: "medium",
      title: "CSP Does Not Restrict Object/Plugin Sources",
      description:
        "The CSP does not restrict object-src. Plugin content (Flash, Java) can be used as an attack vector.",
      url,
      remedy:
        "Add `object-src 'none'` to your CSP to block plugin content.",
    });
  }

  // base-uri
  if (!csp.includes("base-uri")) {
    vulns.push({
      type: "csp",
      severity: "low",
      title: "CSP Missing base-uri Directive",
      description:
        "Without base-uri restriction, attackers can use <base> tags to hijack relative URLs.",
      url,
      remedy: "Add `base-uri 'self'` or `base-uri 'none'` to your CSP.",
    });
  }

  // form-action
  if (!csp.includes("form-action")) {
    vulns.push({
      type: "csp",
      severity: "low",
      title: "CSP Missing form-action Directive",
      description:
        "Without form-action restriction, injected forms could submit data to external servers.",
      url,
      remedy: "Add `form-action 'self'` to your CSP.",
    });
  }

  return vulns;
}

// ─── 5. Cookie security ───────────────────────────────────────────
function checkCookies(
  url: string,
  headers: Headers
): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];
  const setCookie = headers.get("set-cookie");
  if (!setCookie) return vulns;

  const lc = setCookie.toLowerCase();

  if (!lc.includes("httponly")) {
    vulns.push({
      type: "cookies",
      severity: "medium",
      title: "Cookies Without HttpOnly Flag",
      description:
        "Cookies are set without HttpOnly, allowing JavaScript to access them. This enables XSS-based cookie theft.",
      url,
      remedy: "Add the HttpOnly flag to all cookies that don't need JavaScript access.",
    });
  }

  if (!lc.includes("secure")) {
    vulns.push({
      type: "cookies",
      severity: "medium",
      title: "Cookies Without Secure Flag",
      description:
        "Cookies are set without the Secure flag. They can be transmitted over unencrypted HTTP connections.",
      url,
      remedy: "Add the Secure flag to ensure cookies are only sent over HTTPS.",
    });
  }

  if (!lc.includes("samesite")) {
    vulns.push({
      type: "cookies",
      severity: "medium",
      title: "Cookies Without SameSite Attribute",
      description:
        "Without SameSite, cookies are sent with cross-site requests, potentially enabling CSRF attacks.",
      url,
      remedy: "Set `SameSite=Lax` (recommended) or `SameSite=Strict` on all cookies.",
    });
  }

  if (lc.includes("domain=.")) {
    vulns.push({
      type: "cookies",
      severity: "low",
      title: "Cookie Domain Set to Parent Domain",
      description:
        "A cookie is scoped to a parent domain, making it accessible to all subdomains. If any subdomain is compromised, these cookies are exposed.",
      url,
      remedy: "Scope cookies to the most specific domain possible.",
    });
  }

  return vulns;
}

// ─── 6. HTML security checks ──────────────────────────────────────
function checkHTMLSecurity(
  url: string,
  html: string
): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];
  const $ = cheerio.load(html);

  // CSRF protection in forms
  const forms = $("form");
  if (forms.length > 0) {
    let hasCSRF = false;
    forms.each((_, form) => {
      const csrfInputs = $(form).find(
        'input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="authenticity"]'
      );
      if (csrfInputs.length > 0) hasCSRF = true;
    });

    if (!hasCSRF) {
      vulns.push({
        type: "csrf",
        severity: "high",
        title: "Forms Without CSRF Protection",
        description:
          "Forms were found without visible CSRF tokens. Attackers can trick authenticated users into submitting malicious requests (Cross-Site Request Forgery).",
        url,
        remedy:
          "Implement CSRF tokens in all forms. In Next.js, Server Actions include built-in CSRF protection. For API routes, use a CSRF library or SameSite cookies.",
      });
    }
  }

  // Unsafe JS patterns
  const inlineScripts = $("script:not([src])");
  let hasUnsafePatterns = false;
  inlineScripts.each((_, script) => {
    const content = $(script).html() || "";
    if (
      content.includes("document.write") ||
      content.includes("innerHTML") ||
      content.includes("eval(") ||
      content.includes("document.location") ||
      content.includes("outerHTML") ||
      content.includes("insertAdjacentHTML")
    ) {
      hasUnsafePatterns = true;
    }
  });

  if (hasUnsafePatterns) {
    vulns.push({
      type: "xss",
      severity: "high",
      title: "Potentially Unsafe JavaScript Patterns",
      description:
        "Inline scripts using dangerous patterns (document.write, innerHTML, eval, insertAdjacentHTML) were detected. These are common XSS attack vectors.",
      url,
      remedy:
        "Replace innerHTML with textContent. Avoid eval() and document.write(). Sanitize user inputs with DOMPurify. Use CSP to restrict inline scripts.",
    });
  }

  // target="_blank" without rel="noopener"
  let unsafeBlankLinks = 0;
  $('a[target="_blank"]').each((_, link) => {
    const rel = $(link).attr("rel") || "";
    if (!rel.includes("noopener")) unsafeBlankLinks++;
  });
  if (unsafeBlankLinks > 0) {
    vulns.push({
      type: "xss",
      severity: "low",
      title: 'Links with target="_blank" Missing rel="noopener"',
      description: `${unsafeBlankLinks} link(s) open in new tabs without rel="noopener". This exposes a reverse tabnabbing vulnerability.`,
      url,
      remedy: 'Add rel="noopener noreferrer" to all links with target="_blank".',
    });
  }

  // Password autocomplete
  const pwInputs = $('input[type="password"]');
  if (pwInputs.length > 0) {
    let noAutocomplete = false;
    pwInputs.each((_, el) => {
      const ac = $(el).attr("autocomplete");
      if (!ac || ac === "on") noAutocomplete = true;
    });
    if (noAutocomplete) {
      vulns.push({
        type: "info-disclosure",
        severity: "info",
        title: "Password Fields Allow Browser Autocomplete",
        description:
          "Password fields don't explicitly set autocomplete attributes. Browsers may cache credentials on shared computers.",
        url,
        remedy: 'Set autocomplete="current-password" or autocomplete="new-password" on password fields.',
      });
    }
  }

  // Mixed content
  const httpResources = $(
    'img[src^="http:"], script[src^="http:"], link[href^="http:"], iframe[src^="http:"], video[src^="http:"], audio[src^="http:"]'
  );
  if (httpResources.length > 0) {
    vulns.push({
      type: "ssl",
      severity: "medium",
      title: "Mixed Content Detected",
      description: `${httpResources.length} resource(s) are loaded over HTTP on an HTTPS page. This compromises the security of the entire page and triggers browser warnings.`,
      url,
      remedy: "Update all resource URLs to HTTPS. Add `upgrade-insecure-requests` to your CSP.",
    });
  }

  // Subresource Integrity (SRI) – external scripts & stylesheets
  let missingIntegrity = 0;

  $("script[src]").each((_, el) => {
    const src = $(el).attr("src") || "";
    try {
      const srcHost = new URL(src, url).hostname;
      const pageHost = new URL(url).hostname;
      if (srcHost !== pageHost && !$(el).attr("integrity")) missingIntegrity++;
    } catch { /* ignore */ }
  });

  $('link[rel="stylesheet"][href]').each((_, el) => {
    const href = $(el).attr("href") || "";
    try {
      const hrefHost = new URL(href, url).hostname;
      const pageHost = new URL(url).hostname;
      if (hrefHost !== pageHost && !$(el).attr("integrity")) missingIntegrity++;
    } catch { /* ignore */ }
  });

  if (missingIntegrity > 0) {
    vulns.push({
      type: "sri",
      severity: "medium",
      title: "External Resources Without Subresource Integrity",
      description: `${missingIntegrity} external script(s)/stylesheet(s) loaded from CDNs without the integrity attribute. If the CDN is compromised, malicious code will execute on your site.`,
      url,
      remedy:
        'Add integrity and crossorigin attributes: `<script src="cdn.js" integrity="sha384-..." crossorigin="anonymous">`',
    });
  }

  // Deprecated / vulnerable JS libraries
  const deprecatedLibs: { name: string; version: string }[] = [];

  $("script[src]").each((_, el) => {
    const src = ($(el).attr("src") || "").toLowerCase();

    // jQuery
    const jqMatch = src.match(/jquery[.-](\d+\.\d+\.\d+)/);
    if (jqMatch) {
      const [major, minor] = jqMatch[1].split(".").map(Number);
      if (major < 3 || (major === 3 && minor < 5)) {
        deprecatedLibs.push({ name: "jQuery", version: jqMatch[1] });
      }
    }

    // AngularJS 1.x
    if (src.includes("angular") && src.match(/angular[.-]1\./)) {
      const angMatch = src.match(/angular[.-](1\.\d+\.\d+)/);
      deprecatedLibs.push({ name: "AngularJS 1.x", version: angMatch ? angMatch[1] : "1.x" });
    }

    // Bootstrap < 4
    const bsMatch = src.match(/bootstrap[.-](\d+\.\d+\.\d+)/);
    if (bsMatch) {
      const [major] = bsMatch[1].split(".").map(Number);
      if (major < 4) deprecatedLibs.push({ name: "Bootstrap", version: bsMatch[1] });
    }

    // Moment.js (deprecated in favor of day.js / date-fns)
    if (src.includes("moment") && src.match(/moment[.-]\d/)) {
      deprecatedLibs.push({ name: "Moment.js", version: "deprecated" });
    }
  });

  // Also check inline script content for library version comments
  inlineScripts.each((_, script) => {
    const content = $(script).html() || "";
    const jqComment = content.match(/jQuery\s+v?(\d+\.\d+\.\d+)/);
    if (jqComment) {
      const [major, minor] = jqComment[1].split(".").map(Number);
      if (major < 3 || (major === 3 && minor < 5)) {
        deprecatedLibs.push({ name: "jQuery (inline)", version: jqComment[1] });
      }
    }
  });

  if (deprecatedLibs.length > 0) {
    const libList = deprecatedLibs.map((l) => `${l.name} ${l.version}`).join(", ");
    vulns.push({
      type: "outdated-lib",
      severity: "medium",
      title: "Outdated or Deprecated JavaScript Libraries",
      description: `Detected outdated libraries: ${libList}. These may contain known security vulnerabilities.`,
      url,
      remedy:
        "Update all libraries to latest versions. Replace deprecated ones (AngularJS → Angular, Moment.js → Day.js). Run `npm audit` to check for known CVEs.",
    });
  }

  // Open redirect parameters
  let openRedirectCount = 0;
  $("a[href], form[action]").each((_, el) => {
    const target = $(el).attr("href") || $(el).attr("action") || "";
    if (
      /[?&](redirect|url|next|return|returnUrl|goto|dest|destination|redir|target|continue)=/i.test(target)
    ) {
      openRedirectCount++;
    }
  });

  if (openRedirectCount > 0) {
    vulns.push({
      type: "open-redirect",
      severity: "medium",
      title: "Potential Open Redirect Parameters Detected",
      description: `${openRedirectCount} URL(s) contain redirect-like parameters (redirect=, url=, next=, etc.). If the server doesn't validate these, attackers can redirect users to malicious sites.`,
      url,
      remedy:
        "Validate and whitelist all redirect destinations on the server. Never redirect to user-supplied URLs without checking against an allowlist.",
    });
  }

  // Missing meta description (SEO)
  if (!$('meta[name="description"]').length) {
    vulns.push({
      type: "seo",
      severity: "info",
      title: "Missing Meta Description",
      description:
        "The page has no meta description tag. While not a security issue, this affects SEO and search result appearance.",
      url,
      remedy: '<meta name="description" content="Your page description">',
    });
  }

  // Sensitive info in HTML comments
  let sensitiveComments = 0;
  const commentRegex = /<!--([\s\S]*?)-->/g;
  let match;
  while ((match = commentRegex.exec(html)) !== null) {
    const comment = match[1].toLowerCase();
    if (
      comment.includes("password") ||
      comment.includes("api_key") ||
      comment.includes("apikey") ||
      comment.includes("secret") ||
      comment.includes("todo") ||
      comment.includes("fixme") ||
      comment.includes("hack") ||
      comment.includes("bug") ||
      comment.includes("database") ||
      comment.includes("admin") ||
      comment.includes("credential")
    ) {
      sensitiveComments++;
    }
  }

  if (sensitiveComments > 0) {
    vulns.push({
      type: "info-disclosure",
      severity: "low",
      title: "Sensitive Information in HTML Comments",
      description: `${sensitiveComments} HTML comment(s) contain potentially sensitive keywords (password, api_key, secret, admin, etc.). Comments are visible in page source.`,
      url,
      remedy:
        "Remove all HTML comments with sensitive info before deployment. Use build tools to strip comments automatically.",
    });
  }

  // Forms submitting over HTTP
  $("form[action]").each((_, form) => {
    const action = $(form).attr("action") || "";
    if (action.startsWith("http://")) {
      vulns.push({
        type: "ssl",
        severity: "high",
        title: "Form Submits Data Over HTTP",
        description: `A form action points to an HTTP URL (${action}). Form data including passwords will be sent in plain text.`,
        url,
        remedy: "Change all form action URLs to HTTPS.",
      });
    }
  });

  // External iframes without sandbox
  let untrustedIframes = 0;
  $("iframe[src]").each((_, el) => {
    const src = $(el).attr("src") || "";
    const sandbox = $(el).attr("sandbox");
    if (src.startsWith("http") && !sandbox) {
      try {
        const iframeHost = new URL(src).hostname;
        const pageHost = new URL(url).hostname;
        if (iframeHost !== pageHost) untrustedIframes++;
      } catch { /* ignore */ }
    }
  });

  if (untrustedIframes > 0) {
    vulns.push({
      type: "iframe",
      severity: "low",
      title: "External Iframes Without Sandbox Attribute",
      description: `${untrustedIframes} external iframe(s) loaded without sandbox attribute. Unsandboxed iframes can access your page's DOM.`,
      url,
      remedy:
        'Add sandbox attribute: `<iframe sandbox="allow-scripts allow-same-origin" src="...">`. Grant minimum permissions needed.',
    });
  }

  return vulns;
}

// ─── 7. Sensitive file exposure ───────────────────────────────────
async function checkSensitiveFiles(
  baseUrl: string
): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];

  const sensitiveFiles: {
    path: string;
    title: string;
    severity: "critical" | "high" | "medium" | "low";
    desc: string;
  }[] = [
    {
      path: "/.env",
      title: ".env File Exposed",
      severity: "critical",
      desc: "The .env file is publicly accessible. It typically contains database credentials, API keys, and secret tokens.",
    },
    {
      path: "/.git/config",
      title: "Git Repository Exposed",
      severity: "critical",
      desc: "The .git directory is accessible. Attackers can download your entire source code, history, and secrets.",
    },
    {
      path: "/.git/HEAD",
      title: "Git HEAD File Exposed",
      severity: "critical",
      desc: "The .git/HEAD file is accessible, confirming the entire Git repository may be downloadable.",
    },
    {
      path: "/.DS_Store",
      title: ".DS_Store File Exposed",
      severity: "low",
      desc: "A macOS .DS_Store file is accessible, revealing directory structure and filenames.",
    },
    {
      path: "/wp-admin/",
      title: "WordPress Admin Panel Exposed",
      severity: "medium",
      desc: "The WordPress admin panel is publicly accessible — a common target for brute-force attacks.",
    },
    {
      path: "/server-status",
      title: "Apache Server Status Exposed",
      severity: "medium",
      desc: "Apache mod_status page is accessible, revealing server info and current connections.",
    },
    {
      path: "/phpinfo.php",
      title: "PHP Info Page Exposed",
      severity: "high",
      desc: "A phpinfo() page is exposed, revealing PHP version, modules, configuration, and environment variables.",
    },
    {
      path: "/.htaccess",
      title: ".htaccess File Exposed",
      severity: "medium",
      desc: "The .htaccess file is accessible, revealing URL rewrite rules and auth configurations.",
    },
    {
      path: "/wp-config.php.bak",
      title: "WordPress Config Backup Exposed",
      severity: "critical",
      desc: "A WordPress config backup may contain database credentials and secret keys in plain text.",
    },
    {
      path: "/backup.sql",
      title: "Database Backup File Exposed",
      severity: "critical",
      desc: "A SQL backup file is publicly accessible, potentially containing the entire database.",
    },
    {
      path: "/database.sql",
      title: "Database Dump File Exposed",
      severity: "critical",
      desc: "A SQL dump file is publicly accessible, potentially containing all tables and user data.",
    },
    {
      path: "/debug.log",
      title: "Debug Log File Exposed",
      severity: "medium",
      desc: "A debug log file is accessible, revealing stack traces and internal application details.",
    },
    {
      path: "/error.log",
      title: "Error Log File Exposed",
      severity: "medium",
      desc: "An error log file is accessible, revealing internal application errors and stack traces.",
    },
    {
      path: "/elmah.axd",
      title: "ELMAH Error Log Exposed",
      severity: "high",
      desc: "The ELMAH error log handler is exposed, revealing detailed .NET application errors.",
    },
  ];

  const checks = sensitiveFiles.map(async (file) => {
    const fileUrl = new URL(file.path, baseUrl).toString();
    const res = await safeFetch(fileUrl, { redirect: "follow", timeout: 8000 });
    if (!res || res.status !== 200) return null;

    const ct = res.headers.get("content-type") || "";

    // Skip soft 404 (HTML response for non-HTML files)
    const nonHtmlFile =
      !file.path.endsWith(".php") &&
      !file.path.endsWith("/") &&
      !file.path.endsWith(".axd");
    if (nonHtmlFile && ct.includes("text/html")) return null;

    // Skip empty responses
    try {
      const text = await res.text();
      if (text.trim().length === 0) return null;
    } catch {
      return null;
    }

    return {
      type: "sensitive-file",
      severity: file.severity,
      title: file.title,
      description: file.desc,
      url: fileUrl,
      remedy:
        "Block access to this file via web server config. Nginx: `location ~ /\\. { deny all; }`. Vercel/Netlify: use rewrites to block sensitive paths.",
    } as VulnerabilityResult;
  });

  const results = await Promise.all(checks);
  for (const r of results) {
    if (r) vulns.push(r);
  }

  return vulns;
}

// ─── 8. Email security (SPF / DMARC) ─────────────────────────────
async function checkEmailSecurity(
  url: string
): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const domain = new URL(url).hostname.replace(/^www\./, "");

  // SPF check
  const spfRecords = await dnsLookupTxt(domain);
  const hasSPF = spfRecords.some((r) => r.some((txt) => txt.startsWith("v=spf1")));
  if (!hasSPF) {
    vulns.push({
      type: "email",
      severity: "medium",
      title: "Missing SPF Record",
      description: `No SPF record found for ${domain}. Without SPF, attackers can spoof emails from your domain.`,
      url,
      remedy: `Add a TXT record: \`v=spf1 include:_spf.google.com ~all\` (adjust for your email provider).`,
    });
  }

  // DMARC check
  const dmarcRecords = await dnsLookupTxt(`_dmarc.${domain}`);
  const hasDMARC = dmarcRecords.some((r) => r.some((txt) => txt.startsWith("v=DMARC1")));
  if (!hasDMARC) {
    vulns.push({
      type: "email",
      severity: "medium",
      title: "Missing DMARC Record",
      description: `No DMARC record found for ${domain}. Without DMARC, you have no policy for handling failed email authentication.`,
      url,
      remedy: `Add a TXT record at _dmarc.${domain}: \`v=DMARC1; p=quarantine; rua=mailto:dmarc@${domain}\``,
    });
  } else {
    const dmarcTxt = dmarcRecords.flat().find((t) => t.startsWith("v=DMARC1"));
    if (dmarcTxt && dmarcTxt.includes("p=none")) {
      vulns.push({
        type: "email",
        severity: "low",
        title: "DMARC Policy Set to None (Monitor Only)",
        description: `DMARC is configured but policy is "none" — failed authentication won't block spoofed emails.`,
        url,
        remedy: "Upgrade from p=none to p=quarantine or p=reject after monitoring reports.",
      });
    }
  }

  return vulns;
}

// ─── 9. robots.txt analysis ───────────────────────────────────────
async function checkRobotsTxt(
  baseUrl: string
): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const robotsUrl = new URL("/robots.txt", baseUrl).toString();
  const res = await safeFetch(robotsUrl);
  if (!res || res.status !== 200) return vulns;

  const ct = res.headers.get("content-type") || "";
  if (ct.includes("text/html")) return vulns; // soft 404

  const text = await res.text();
  if (!text.trim()) return vulns;

  const sensitivePatterns = [
    "/admin", "/login", "/dashboard", "/api", "/config", "/backup",
    "/database", "/db", "/secret", "/private", "/internal", "/staging",
    "/test", "/debug", "/phpMyAdmin", "/phpmyadmin", "/wp-admin",
    "/wp-login", "/panel", "/cPanel",
  ];

  const exposedPaths: string[] = [];
  for (const line of text.split("\n")) {
    const lower = line.toLowerCase().trim();
    if (lower.startsWith("disallow:")) {
      const path = lower.replace("disallow:", "").trim();
      for (const pattern of sensitivePatterns) {
        if (path.includes(pattern.toLowerCase())) {
          exposedPaths.push(path);
          break;
        }
      }
    }
  }

  if (exposedPaths.length > 0) {
    vulns.push({
      type: "info-disclosure",
      severity: "low",
      title: "Sensitive Paths Revealed in robots.txt",
      description: `robots.txt reveals potentially sensitive paths: ${exposedPaths.slice(0, 5).join(", ")}. This tells attackers exactly where to look.`,
      url: robotsUrl,
      remedy:
        "Protect sensitive paths with authentication instead of just listing them in robots.txt.",
    });
  }

  const blocksAll = text.split("\n").some((l) => l.trim().toLowerCase() === "disallow: /");
  if (blocksAll) {
    vulns.push({
      type: "seo",
      severity: "info",
      title: "robots.txt Blocks All Crawling",
      description: "robots.txt contains 'Disallow: /' which blocks all search engine crawling.",
      url: robotsUrl,
      remedy: "If intentional (staging), no action needed. For production, selectively allow public pages.",
    });
  }

  return vulns;
}

// ─── 10. Error page information disclosure ────────────────────────
async function checkErrorPages(
  baseUrl: string
): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];

  const randomPath = `/this-page-does-not-exist-${Date.now()}`;
  const errorUrl = new URL(randomPath, baseUrl).toString();
  const res = await safeFetch(errorUrl);
  if (!res) return vulns;

  const ct = res.headers.get("content-type") || "";
  if (!ct.includes("text/html")) return vulns;

  const html = await res.text();
  const lower = html.toLowerCase();

  const leaksInfo =
    lower.includes("stack trace") ||
    lower.includes("traceback") ||
    lower.includes("exception") ||
    lower.includes("syntax error") ||
    lower.includes("fatal error") ||
    lower.includes("debug mode") ||
    lower.includes("django.") ||
    lower.includes("laravel") ||
    lower.includes("aspnet_") ||
    lower.includes("at system.") ||
    lower.includes("at microsoft.") ||
    lower.includes("node_modules") ||
    lower.includes("at object.") ||
    lower.includes("at module.") ||
    /file ["']?\/[a-z]/i.test(html) ||
    /line \d+/i.test(lower);

  if (leaksInfo) {
    vulns.push({
      type: "info-disclosure",
      severity: "medium",
      title: "Error Pages Reveal Application Details",
      description:
        "Error pages reveal technical info (stack traces, framework details, file paths). Attackers use this to map your technology stack.",
      url: errorUrl,
      remedy:
        "Configure custom error pages. In Next.js, create app/not-found.tsx and error.tsx. Always set NODE_ENV=production.",
    });
  }

  if (res.status === 200) {
    vulns.push({
      type: "seo",
      severity: "info",
      title: "Soft 404 — Error Page Returns 200 Status",
      description:
        "Non-existent pages return HTTP 200 instead of 404. This confuses search engines.",
      url: errorUrl,
      remedy: "Ensure non-existent pages return 404. In Next.js, use notFound().",
    });
  }

  return vulns;
}

// ─── 11. Directory listing detection ──────────────────────────────
async function checkDirectoryListing(
  baseUrl: string
): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];

  const dirs = [
    "/images/", "/uploads/", "/assets/", "/static/",
    "/media/", "/files/", "/backup/", "/tmp/", "/css/", "/js/",
  ];

  for (const dir of dirs) {
    const dirUrl = new URL(dir, baseUrl).toString();
    const res = await safeFetch(dirUrl, { timeout: 6000 });
    if (!res || res.status !== 200) continue;

    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("text/html")) continue;

    const html = await res.text();
    const lower = html.toLowerCase();

    if (
      lower.includes("index of /") ||
      lower.includes("directory listing") ||
      lower.includes("<title>index of") ||
      lower.includes("[to parent directory]") ||
      lower.includes("parent directory</a>")
    ) {
      vulns.push({
        type: "directory-listing",
        severity: "medium",
        title: "Directory Listing Enabled",
        description: `Directory listing is enabled at ${dir}. Anyone can browse file contents, potentially exposing sensitive files.`,
        url: dirUrl,
        remedy: "Disable directory listing. Nginx: remove autoindex. Apache: `Options -Indexes`.",
      });
      break; // One finding is enough
    }
  }

  return vulns;
}

// ─── 12. Technology fingerprinting ────────────────────────────────
function fingerprintTechnology(
  url: string,
  html: string,
  headers: Headers
): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];
  const $ = cheerio.load(html);
  const detected: string[] = [];

  const generator = $('meta[name="generator"]').attr("content");
  if (generator) detected.push(`Generator: ${generator}`);

  if (html.includes("wp-content") || html.includes("wp-includes")) detected.push("WordPress");
  if (html.includes("__NEXT_DATA__") || html.includes("_next/static")) detected.push("Next.js");
  if (html.includes("__NUXT__") || html.includes("_nuxt/")) detected.push("Nuxt.js");
  if (html.includes("Drupal.settings") || html.includes("/sites/default/")) detected.push("Drupal");
  if (html.includes("cdn.shopify.com") || html.includes("Shopify.theme")) detected.push("Shopify");
  if (html.includes("wix.com") || html.includes("wixstatic.com")) detected.push("Wix");
  if (html.includes("squarespace.com")) detected.push("Squarespace");
  if (html.includes("webflow.com")) detected.push("Webflow");
  if (html.includes("gatsby-")) detected.push("Gatsby");
  if (html.includes("svelte") || html.includes("__sveltekit")) detected.push("SvelteKit");

  const phpVer = headers.get("x-powered-by");
  if (phpVer?.toLowerCase().includes("php")) detected.push(phpVer);
  if (headers.get("x-aspnet-version")) detected.push(`ASP.NET ${headers.get("x-aspnet-version")}`);

  if (detected.length > 0) {
    vulns.push({
      type: "fingerprint",
      severity: "info",
      title: "Technologies Detected",
      description: `Identified technologies: ${detected.join(", ")}. Technology fingerprinting helps attackers target known vulnerabilities in specific versions.`,
      url,
      remedy:
        "Remove generator meta tags, version headers, and minimize technology-specific patterns. While full hiding isn't possible, reducing the fingerprinting surface slows attackers.",
    });
  }

  return vulns;
}

// ─── Score calculation ─────────────────────────────────────────────
function calculateScore(vulns: VulnerabilityResult[]): number {
  let score = 100;

  for (const v of vulns) {
    switch (v.severity) {
      case "critical":
        score -= 25;
        break;
      case "high":
        score -= 15;
        break;
      case "medium":
        score -= 8;
        break;
      case "low":
        score -= 3;
        break;
      case "info":
        score -= 1;
        break;
    }
  }

  return Math.max(0, Math.min(100, score));
}

// ─── MAIN SCAN FUNCTION ───────────────────────────────────────────
export async function scanWebsite(
  url: string,
  onProgress?: ProgressCallback
): Promise<ScanResult> {
  // Normalize
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  const allVulns: VulnerabilityResult[] = [];
  const totalSteps = 12;
  let step = 0;

  const report = (label: string, stepName: string, status: "running" | "done" | "error", found?: number, pagesDiscovered?: number) => {
    onProgress?.({
      step: stepName,
      label,
      status,
      found,
      totalSteps,
      currentStep: step,
      pagesDiscovered,
    });
  };

  // 1. Discover pages
  step = 1;
  report("Discovering pages…", "crawl", "running");
  const pages = await discoverPages(url, 10);
  report(`Found ${pages.length} page(s)`, "crawl", "done", 0, pages.length);

  // 2. SSL/TLS
  step = 2;
  report("Checking SSL/TLS configuration…", "ssl", "running");
  const sslVulns = await checkSSL(url);
  allVulns.push(...sslVulns);
  report("SSL/TLS check complete", "ssl", "done", sslVulns.length);

  // 3. Sensitive files
  step = 3;
  report("Probing for exposed sensitive files…", "sensitive-files", "running");
  const sensitiveFileVulns = await checkSensitiveFiles(url);
  allVulns.push(...sensitiveFileVulns);
  report("Sensitive file scan complete", "sensitive-files", "done", sensitiveFileVulns.length);

  // 4. Email security
  step = 4;
  report("Checking SPF & DMARC records…", "email", "running");
  const emailVulns = await checkEmailSecurity(url);
  allVulns.push(...emailVulns);
  report("Email security check complete", "email", "done", emailVulns.length);

  // 5. robots.txt
  step = 5;
  report("Analyzing robots.txt…", "robots", "running");
  const robotsVulns = await checkRobotsTxt(url);
  allVulns.push(...robotsVulns);
  report("robots.txt analysis complete", "robots", "done", robotsVulns.length);

  // 6. Error pages
  step = 6;
  report("Testing error page disclosure…", "error-pages", "running");
  const errorPageVulns = await checkErrorPages(url);
  allVulns.push(...errorPageVulns);
  report("Error page check complete", "error-pages", "done", errorPageVulns.length);

  // 7. Directory listing
  step = 7;
  report("Checking for directory listings…", "directories", "running");
  const directoryVulns = await checkDirectoryListing(url);
  allVulns.push(...directoryVulns);
  report("Directory listing check complete", "directories", "done", directoryVulns.length);

  // 8-12. Per-page checks
  step = 8;
  report("Analyzing security headers…", "headers", "running");
  let headersDone = false;

  for (const pageUrl of pages) {
    const res = await safeFetch(pageUrl, { timeout: 15000 });
    if (!res) continue;

    // Header-based checks (first page only)
    if (pageUrl === pages[0]) {
      const headerVulns = checkSecurityHeaders(pageUrl, res.headers);
      allVulns.push(...headerVulns);

      step = 9;
      report("Auditing cookie security…", "cookies", "running");
      const cookieVulns = checkCookies(pageUrl, res.headers);
      allVulns.push(...cookieVulns);
      report("Cookie audit complete", "cookies", "done", cookieVulns.length);

      // CSP deep analysis
      step = 10;
      report("Deep-scanning Content-Security-Policy…", "csp", "running");
      const csp = res.headers.get("content-security-policy");
      if (csp) {
        const cspVulns = analyzeCSP(pageUrl, csp);
        allVulns.push(...cspVulns);
        report("CSP analysis complete", "csp", "done", cspVulns.length);
      } else {
        report("No CSP header found", "csp", "done", 0);
      }

      if (!headersDone) {
        report("Security headers analyzed", "headers", "done", headerVulns.length);
        headersDone = true;
      }
    }

    // HTML-based checks
    step = 11;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("text/html")) {
      report(`Scanning HTML on ${new URL(pageUrl).pathname}…`, "html", "running");
      const html = await res.text();
      const htmlVulns = checkHTMLSecurity(pageUrl, html);
      allVulns.push(...htmlVulns);

      // Technology fingerprinting (first page only)
      if (pageUrl === pages[0]) {
        step = 12;
        report("Fingerprinting technologies…", "fingerprint", "running");
        const techVulns = fingerprintTechnology(pageUrl, html, res.headers);
        allVulns.push(...techVulns);
        report("Technology scan complete", "fingerprint", "done", techVulns.length);
      }
    }
  }

  report("HTML analysis complete", "html", "done", 0);

  // Deduplicate by title + url
  const seen = new Set<string>();
  const uniqueVulns = allVulns.filter((v) => {
    const key = `${v.title}-${v.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return {
    url,
    score: calculateScore(uniqueVulns),
    vulnerabilities: uniqueVulns,
    pagesScanned: pages.length,
  };
}
