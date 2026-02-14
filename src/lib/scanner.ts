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
  found?: number;
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
        "User-Agent": "SecureSaaS-Scanner/2.0 (Security Audit Tool)",
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
  maxPages: number = 25
): Promise<string[]> {
  const visited = new Set<string>();
  const toVisit = [baseUrl];
  const pages: string[] = [];
  const baseHost = new URL(baseUrl).hostname;

  while (toVisit.length > 0 && pages.length < maxPages) {
    // Crawl up to 3 pages concurrently
    const batch = toVisit.splice(0, 3).filter((u) => !visited.has(u));
    if (batch.length === 0) break;

    const results = await Promise.allSettled(
      batch.map(async (batchUrl) => {
        if (visited.has(batchUrl)) return null;
        visited.add(batchUrl);

        const res = await safeFetch(batchUrl, { redirect: "follow", timeout: 8000 });
        if (!res || !res.ok) return null;

        const ct = res.headers.get("content-type") || "";
        if (!ct.includes("text/html")) return null;

        const html = await res.text();
        const $ = cheerio.load(html);
        const links: string[] = [];

        $("a[href]").each((_, el) => {
          try {
            const href = $(el).attr("href");
            if (!href) return;
            const abs = new URL(href, batchUrl).toString().split("#")[0].split("?")[0];
            if (
              new URL(abs).hostname === baseHost &&
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
          "Configure a 301 redirect from HTTP to HTTPS.",
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
          remedy: "Ensure all redirects stay on HTTPS.",
        });
      }
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

  const csp = headers.get("content-security-policy");
  if (!csp) {
    vulns.push({ type: "headers", severity: "high", title: "Missing Content-Security-Policy Header", description: "CSP is not set. This header prevents XSS, clickjacking, and code injection attacks.", url, remedy: "Add a Content-Security-Policy header." });
  }

  if (!headers.get("x-frame-options") && !csp?.includes("frame-ancestors")) {
    vulns.push({ type: "headers", severity: "medium", title: "Missing X-Frame-Options Header", description: "Without X-Frame-Options, the site is vulnerable to clickjacking.", url, remedy: "Add `X-Frame-Options: DENY` or `SAMEORIGIN`." });
  }

  if (!headers.get("x-content-type-options")) {
    vulns.push({ type: "headers", severity: "medium", title: "Missing X-Content-Type-Options Header", description: "Without this header, browsers may MIME-sniff responses.", url, remedy: "Add `X-Content-Type-Options: nosniff`." });
  }

  const hsts = headers.get("strict-transport-security");
  if (!hsts) {
    vulns.push({ type: "headers", severity: "high", title: "Missing Strict-Transport-Security (HSTS)", description: "Without HSTS, browsers won't enforce HTTPS.", url, remedy: "Add `Strict-Transport-Security: max-age=31536000; includeSubDomains; preload`." });
  } else {
    const maxAgeMatch = hsts.match(/max-age=(\d+)/);
    if (maxAgeMatch && parseInt(maxAgeMatch[1]) < 15768000) {
      vulns.push({ type: "headers", severity: "low", title: "HSTS max-age Too Short", description: `HSTS max-age is ${maxAgeMatch[1]} seconds. At least 6 months recommended.`, url, remedy: "Increase HSTS max-age to 31536000." });
    }
  }

  if (!headers.get("x-xss-protection")) {
    vulns.push({ type: "headers", severity: "low", title: "Missing X-XSS-Protection Header", description: "Extra XSS protection for older browsers is missing.", url, remedy: "Add `X-XSS-Protection: 1; mode=block`." });
  }

  if (!headers.get("referrer-policy")) {
    vulns.push({ type: "headers", severity: "low", title: "Missing Referrer-Policy Header", description: "May leak sensitive URL parameters via referrer headers.", url, remedy: "Add `Referrer-Policy: strict-origin-when-cross-origin`." });
  }

  if (!headers.get("permissions-policy")) {
    vulns.push({ type: "headers", severity: "low", title: "Missing Permissions-Policy Header", description: "Cannot restrict browser features (camera, mic, geolocation).", url, remedy: "Add `Permissions-Policy: camera=(), microphone=(), geolocation=()`." });
  }

  const server = headers.get("server");
  if (server && (server.includes("/") || /\d/.test(server))) {
    vulns.push({ type: "info-disclosure", severity: "low", title: "Server Version Disclosed", description: `Server header reveals: "${server}".`, url, remedy: "Remove or genericize the Server header." });
  }

  const poweredBy = headers.get("x-powered-by");
  if (poweredBy) {
    vulns.push({ type: "info-disclosure", severity: "low", title: "Technology Disclosed via X-Powered-By", description: `X-Powered-By reveals: "${poweredBy}".`, url, remedy: "Remove X-Powered-By header." });
  }

  const acao = headers.get("access-control-allow-origin");
  if (acao === "*") {
    vulns.push({ type: "cors", severity: "medium", title: "Overly Permissive CORS Policy", description: "Access-Control-Allow-Origin is set to '*'.", url, remedy: "Restrict CORS to specific trusted origins." });
  }
  if (acao === "*" && headers.get("access-control-allow-credentials") === "true") {
    vulns.push({ type: "cors", severity: "high", title: "CORS Credentials with Wildcard Origin", description: "Allows credentials with wildcard origin — critical misconfiguration.", url, remedy: "Never use * with credentials. Specify exact origins." });
  }

  const cacheControl = headers.get("cache-control");
  if (!cacheControl || (!cacheControl.includes("no-store") && !cacheControl.includes("private"))) {
    vulns.push({ type: "headers", severity: "info", title: "Missing Cache-Control for Sensitive Content", description: "Sensitive pages may be cached by proxies.", url, remedy: "Add `Cache-Control: no-store, private`." });
  }

  return vulns;
}

// ─── 4. CSP deep analysis ──────────────────────────────────────────
function analyzeCSP(url: string, csp: string): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];

  if (csp.includes("'unsafe-inline'") && csp.includes("script-src")) {
    vulns.push({ type: "csp", severity: "high", title: "CSP Allows Unsafe Inline Scripts", description: "CSP uses 'unsafe-inline' in script-src, negating XSS protection.", url, remedy: "Use nonces or hashes instead of 'unsafe-inline'." });
  }
  if (csp.includes("'unsafe-eval'")) {
    vulns.push({ type: "csp", severity: "high", title: "CSP Allows Unsafe Eval", description: "CSP uses 'unsafe-eval', allowing dynamic code execution.", url, remedy: "Remove 'unsafe-eval'. Refactor code to avoid eval()." });
  }

  const directives = ["default-src", "script-src", "style-src", "img-src", "connect-src", "font-src", "object-src", "media-src", "frame-src"];
  for (const dir of directives) {
    if (new RegExp(`${dir}[^;]*\\*`, "i").test(csp)) {
      vulns.push({ type: "csp", severity: "medium", title: `CSP Wildcard in ${dir}`, description: `${dir} uses a wildcard (*), allowing content from any source.`, url, remedy: `Replace wildcard in ${dir} with specific domains.` });
      break;
    }
  }

  if (!csp.includes("object-src") || csp.match(/object-src[^;]*\*/)) {
    vulns.push({ type: "csp", severity: "medium", title: "CSP Does Not Restrict Object Sources", description: "Plugin content not restricted.", url, remedy: "Add `object-src 'none'`." });
  }
  if (!csp.includes("base-uri")) {
    vulns.push({ type: "csp", severity: "low", title: "CSP Missing base-uri", description: "Attackers can use <base> tags to hijack URLs.", url, remedy: "Add `base-uri 'self'`." });
  }
  if (!csp.includes("form-action")) {
    vulns.push({ type: "csp", severity: "low", title: "CSP Missing form-action", description: "Injected forms could submit to external servers.", url, remedy: "Add `form-action 'self'`." });
  }

  return vulns;
}

// ─── 5. Cookie security ───────────────────────────────────────────
function checkCookies(url: string, headers: Headers): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];
  const setCookie = headers.get("set-cookie");
  if (!setCookie) return vulns;
  const lc = setCookie.toLowerCase();

  if (!lc.includes("httponly")) vulns.push({ type: "cookies", severity: "medium", title: "Cookies Without HttpOnly", description: "JavaScript can access cookies via XSS.", url, remedy: "Add HttpOnly flag." });
  if (!lc.includes("secure")) vulns.push({ type: "cookies", severity: "medium", title: "Cookies Without Secure Flag", description: "Cookies may be sent over HTTP.", url, remedy: "Add Secure flag." });
  if (!lc.includes("samesite")) vulns.push({ type: "cookies", severity: "medium", title: "Cookies Without SameSite", description: "Cookies sent with cross-site requests (CSRF risk).", url, remedy: "Set SameSite=Lax or Strict." });
  if (lc.includes("domain=.")) vulns.push({ type: "cookies", severity: "low", title: "Cookie Scoped to Parent Domain", description: "Cookie accessible to all subdomains.", url, remedy: "Scope to most specific domain." });

  return vulns;
}

// ─── 6. HTML security checks ──────────────────────────────────────
function checkHTMLSecurity(url: string, html: string): VulnerabilityResult[] {
  const vulns: VulnerabilityResult[] = [];
  const $ = cheerio.load(html);

  // CSRF
  const forms = $("form");
  if (forms.length > 0) {
    let hasCSRF = false;
    forms.each((_, form) => {
      if ($(form).find('input[name*="csrf"], input[name*="token"], input[name*="_token"], input[name*="authenticity"]').length > 0) hasCSRF = true;
    });
    if (!hasCSRF) vulns.push({ type: "csrf", severity: "high", title: "Forms Without CSRF Protection", description: "Forms lack visible CSRF tokens.", url, remedy: "Implement CSRF tokens in all forms." });
  }

  // Unsafe JS patterns
  const inlineScripts = $("script:not([src])");
  let hasUnsafe = false;
  inlineScripts.each((_, s) => {
    const c = $(s).html() || "";
    if (c.includes("document.write") || c.includes("innerHTML") || c.includes("eval(") || c.includes("outerHTML") || c.includes("insertAdjacentHTML")) hasUnsafe = true;
  });
  if (hasUnsafe) vulns.push({ type: "xss", severity: "high", title: "Unsafe JavaScript Patterns", description: "Dangerous patterns (document.write, innerHTML, eval) detected.", url, remedy: "Use textContent instead of innerHTML. Avoid eval()." });

  // target="_blank"
  let unsafeLinks = 0;
  $('a[target="_blank"]').each((_, l) => { if (!($(l).attr("rel") || "").includes("noopener")) unsafeLinks++; });
  if (unsafeLinks > 0) vulns.push({ type: "xss", severity: "low", title: 'target="_blank" Missing rel="noopener"', description: `${unsafeLinks} link(s) vulnerable to reverse tabnabbing.`, url, remedy: 'Add rel="noopener noreferrer".' });

  // Password autocomplete
  const pw = $('input[type="password"]');
  if (pw.length > 0) {
    let bad = false;
    pw.each((_, el) => { const ac = $(el).attr("autocomplete"); if (!ac || ac === "on") bad = true; });
    if (bad) vulns.push({ type: "info-disclosure", severity: "info", title: "Password Fields Allow Autocomplete", description: "Browsers may cache credentials.", url, remedy: 'Set autocomplete="current-password".' });
  }

  // Mixed content
  const httpRes = $('img[src^="http:"], script[src^="http:"], link[href^="http:"], iframe[src^="http:"]');
  if (httpRes.length > 0) vulns.push({ type: "ssl", severity: "medium", title: "Mixed Content Detected", description: `${httpRes.length} resource(s) loaded over HTTP.`, url, remedy: "Update all resource URLs to HTTPS." });

  // SRI
  let missingIntegrity = 0;
  $("script[src]").each((_, el) => {
    try { const h = new URL($(el).attr("src") || "", url).hostname; if (h !== new URL(url).hostname && !$(el).attr("integrity")) missingIntegrity++; } catch { /* ignore */ }
  });
  $('link[rel="stylesheet"][href]').each((_, el) => {
    try { const h = new URL($(el).attr("href") || "", url).hostname; if (h !== new URL(url).hostname && !$(el).attr("integrity")) missingIntegrity++; } catch { /* ignore */ }
  });
  if (missingIntegrity > 0) vulns.push({ type: "sri", severity: "medium", title: "External Resources Without SRI", description: `${missingIntegrity} external resource(s) missing integrity attribute.`, url, remedy: "Add integrity and crossorigin attributes." });

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
  if (depLibs.length > 0) vulns.push({ type: "outdated-lib", severity: "medium", title: "Outdated JavaScript Libraries", description: `Detected: ${depLibs.map((l) => `${l.name} ${l.version}`).join(", ")}.`, url, remedy: "Update all libraries. Run `npm audit`." });

  // Open redirects
  let redirectParams = 0;
  $("a[href], form[action]").each((_, el) => {
    const t = $(el).attr("href") || $(el).attr("action") || "";
    if (/[?&](redirect|url|next|return|returnUrl|goto|dest|redir|target|continue)=/i.test(t)) redirectParams++;
  });
  if (redirectParams > 0) vulns.push({ type: "open-redirect", severity: "medium", title: "Potential Open Redirect Parameters", description: `${redirectParams} URL(s) with redirect-like parameters.`, url, remedy: "Validate and whitelist redirect destinations." });

  // Missing meta description
  if (!$('meta[name="description"]').length) vulns.push({ type: "seo", severity: "info", title: "Missing Meta Description", description: "No meta description tag.", url, remedy: "Add <meta name='description'>." });

  // Sensitive comments
  let sensComments = 0;
  let match;
  const commentRe = /<!--([\s\S]*?)-->/g;
  while ((match = commentRe.exec(html)) !== null) {
    const c = match[1].toLowerCase();
    if (c.includes("password") || c.includes("api_key") || c.includes("secret") || c.includes("todo") || c.includes("fixme") || c.includes("database") || c.includes("admin") || c.includes("credential")) sensComments++;
  }
  if (sensComments > 0) vulns.push({ type: "info-disclosure", severity: "low", title: "Sensitive Info in HTML Comments", description: `${sensComments} comment(s) with sensitive keywords.`, url, remedy: "Remove sensitive HTML comments." });

  // Forms over HTTP
  $("form[action]").each((_, f) => {
    const action = $(f).attr("action") || "";
    if (action.startsWith("http://")) vulns.push({ type: "ssl", severity: "high", title: "Form Submits Over HTTP", description: `Form posts to ${action} in plain text.`, url, remedy: "Use HTTPS for form actions." });
  });

  // Unsandboxed iframes
  let unsafeIframes = 0;
  $("iframe[src]").each((_, el) => {
    const src = $(el).attr("src") || "";
    if (src.startsWith("http") && !$(el).attr("sandbox")) {
      try { if (new URL(src).hostname !== new URL(url).hostname) unsafeIframes++; } catch { /* ignore */ }
    }
  });
  if (unsafeIframes > 0) vulns.push({ type: "iframe", severity: "low", title: "External Iframes Without Sandbox", description: `${unsafeIframes} unsandboxed external iframe(s).`, url, remedy: "Add sandbox attribute to external iframes." });

  // Source map references in HTML
  const srcMapRefs = html.match(/\/\/[#@]\s*sourceMappingURL=\S+/g);
  if (srcMapRefs && srcMapRefs.length > 0) {
    vulns.push({ type: "source-maps", severity: "medium", title: "Source Map References in HTML", description: `${srcMapRefs.length} source map reference(s) found, exposing original source code.`, url, remedy: "Remove source maps in production." });
  }

  return vulns;
}

// ─── 7. Sensitive file exposure ───────────────────────────────────
async function checkSensitiveFiles(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];

  const files = [
    { path: "/.env", title: ".env File Exposed", severity: "critical" as const, desc: "Environment file with credentials is publicly accessible." },
    { path: "/.git/config", title: "Git Repository Exposed", severity: "critical" as const, desc: ".git directory accessible — full source code downloadable." },
    { path: "/.git/HEAD", title: "Git HEAD Exposed", severity: "critical" as const, desc: ".git/HEAD accessible, confirming repo exposure." },
    { path: "/.DS_Store", title: ".DS_Store Exposed", severity: "low" as const, desc: "macOS file reveals directory structure." },
    { path: "/wp-admin/", title: "WordPress Admin Exposed", severity: "medium" as const, desc: "WordPress admin panel publicly accessible." },
    { path: "/server-status", title: "Apache Status Exposed", severity: "medium" as const, desc: "Apache mod_status page accessible." },
    { path: "/phpinfo.php", title: "PHP Info Exposed", severity: "high" as const, desc: "phpinfo() page reveals server configuration." },
    { path: "/.htaccess", title: ".htaccess Exposed", severity: "medium" as const, desc: ".htaccess file readable." },
    { path: "/wp-config.php.bak", title: "WP Config Backup Exposed", severity: "critical" as const, desc: "WordPress config backup with credentials." },
    { path: "/backup.sql", title: "SQL Backup Exposed", severity: "critical" as const, desc: "Database backup publicly accessible." },
    { path: "/database.sql", title: "Database Dump Exposed", severity: "critical" as const, desc: "SQL dump publicly accessible." },
    { path: "/debug.log", title: "Debug Log Exposed", severity: "medium" as const, desc: "Debug log reveals application internals." },
    { path: "/error.log", title: "Error Log Exposed", severity: "medium" as const, desc: "Error log reveals stack traces." },
    { path: "/elmah.axd", title: "ELMAH Error Log Exposed", severity: "high" as const, desc: ".NET error handler exposed." },
    { path: "/.svn/entries", title: "SVN Repository Exposed", severity: "critical" as const, desc: ".svn directory exposes source code." },
    { path: "/crossdomain.xml", title: "crossdomain.xml Exposed", severity: "medium" as const, desc: "Flash cross-domain policy found." },
    { path: "/composer.json", title: "Composer Config Exposed", severity: "medium" as const, desc: "PHP dependencies revealed." },
    { path: "/package.json", title: "package.json Exposed", severity: "low" as const, desc: "Node.js dependencies revealed." },
    { path: "/Dockerfile", title: "Dockerfile Exposed", severity: "high" as const, desc: "Docker build config publicly accessible." },
    { path: "/docker-compose.yml", title: "Docker Compose Exposed", severity: "high" as const, desc: "Service architecture and possibly credentials exposed." },
    { path: "/.well-known/security.txt", title: "security.txt Found", severity: "info" as const, desc: "security.txt found — good practice. Review contents." },
    { path: "/.well-known/openid-configuration", title: "OpenID Config Found", severity: "info" as const, desc: "OpenID Connect discovery document available." },
  ];

  // Run ALL checks in parallel
  const checks = files.map(async (file) => {
    const fileUrl = new URL(file.path, baseUrl).toString();
    const res = await safeFetch(fileUrl, { redirect: "follow", timeout: 6000 });
    if (!res || res.status !== 200) return null;

    const ct = res.headers.get("content-type") || "";
    const nonHtml = !file.path.endsWith(".php") && !file.path.endsWith("/") && !file.path.endsWith(".axd");
    if (nonHtml && ct.includes("text/html")) return null;

    try { const text = await res.text(); if (text.trim().length === 0) return null; } catch { return null; }

    return { type: "sensitive-file", severity: file.severity, title: file.title, description: file.desc, url: fileUrl, remedy: "Block access to this file via web server config." } as VulnerabilityResult;
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
    vulns.push({ type: "email", severity: "medium", title: "Missing SPF Record", description: `No SPF record for ${domain}. Email spoofing possible.`, url, remedy: "Add SPF TXT record." });
  } else {
    const spfTxt = spfRecords.flat().find((t) => t.startsWith("v=spf1"));
    if (spfTxt?.includes("+all")) {
      vulns.push({ type: "email", severity: "high", title: "SPF Allows All Senders (+all)", description: `SPF uses +all, allowing any server to send as ${domain}.`, url, remedy: "Change +all to ~all or -all." });
    }
  }

  const hasDMARC = dmarcRecords.some((r) => r.some((t) => t.startsWith("v=DMARC1")));
  if (!hasDMARC) {
    vulns.push({ type: "email", severity: "medium", title: "Missing DMARC Record", description: `No DMARC record for ${domain}.`, url, remedy: `Add TXT at _dmarc.${domain}: v=DMARC1; p=quarantine` });
  } else {
    const dmarcTxt = dmarcRecords.flat().find((t) => t.startsWith("v=DMARC1"));
    if (dmarcTxt?.includes("p=none")) {
      vulns.push({ type: "email", severity: "low", title: "DMARC Policy Set to None", description: "DMARC p=none — spoofed emails won't be blocked.", url, remedy: "Upgrade to p=quarantine or p=reject." });
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
  if (exposed.length > 0) vulns.push({ type: "info-disclosure", severity: "low", title: "Sensitive Paths in robots.txt", description: `Reveals: ${exposed.slice(0, 5).join(", ")}.`, url: robotsUrl, remedy: "Protect paths with auth instead." });

  if (text.split("\n").some((l) => l.trim().toLowerCase() === "disallow: /")) {
    vulns.push({ type: "seo", severity: "info", title: "robots.txt Blocks All Crawling", description: "Disallow: / blocks all search engines.", url: robotsUrl, remedy: "For production, selectively allow public pages." });
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

  if (leaks) vulns.push({ type: "info-disclosure", severity: "medium", title: "Error Pages Reveal Details", description: "Error pages expose stack traces or framework info.", url: errorUrl, remedy: "Configure custom error pages." });
  if (res.status === 200) vulns.push({ type: "seo", severity: "info", title: "Soft 404 — Returns 200", description: "Non-existent pages return 200 instead of 404.", url: errorUrl, remedy: "Return proper 404 status codes." });

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
  if (found.length > 0) vulns.push({ type: "directory-listing", severity: "medium", title: "Directory Listing Enabled", description: `Listing enabled at ${found.join(", ")}.`, url: new URL(found[0]!, baseUrl).toString(), remedy: "Disable directory listing." });

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

  if (detected.length > 0) vulns.push({ type: "fingerprint", severity: "info", title: "Technologies Detected", description: `Found: ${detected.join(", ")}.`, url, remedy: "Remove generator tags and version headers." });

  return vulns;
}

// ─── 13. API endpoint probing ─────────────────────────────────────
async function checkAPIEndpoints(baseUrl: string): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];

  const apiPaths = [
    "/api", "/api/v1", "/api/v2", "/api/users", "/api/admin",
    "/api/config", "/api/health", "/api/status", "/api/debug",
    "/api/docs", "/api/swagger", "/swagger-ui.html", "/swagger.json",
    "/openapi.json", "/api-docs", "/graphql", "/graphiql",
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
        try { const b = await introRes.text(); if (b.includes("__schema")) return { type: "api-exposure", severity: "high" as const, title: "GraphQL Introspection Enabled", description: `GraphQL at ${path} exposes entire API schema.`, url: apiUrl, remedy: "Disable introspection in production." }; } catch { /* ignore */ }
      }
      return null;
    }

    // Swagger/OpenAPI
    if ((path.includes("swagger") || path.includes("openapi") || path.includes("api-docs")) && res.status === 200) {
      return { type: "api-exposure", severity: "medium" as const, title: "API Docs Publicly Accessible", description: `API documentation at ${path}.`, url: apiUrl, remedy: "Restrict API docs to authenticated users." };
    }

    // Debug endpoints
    if ((path.includes("debug") || path.includes("profiler")) && res.status === 200) {
      return { type: "api-exposure", severity: "high" as const, title: "Debug Endpoint Exposed", description: `Debug/profiler at ${path}.`, url: apiUrl, remedy: "Disable debug endpoints in production." };
    }

    // Health leaking info
    if ((path.includes("health") || path.includes("status")) && res.status === 200) {
      const ct = res.headers.get("content-type") || "";
      if (ct.includes("json")) {
        try { const b = await res.text(); if (b.includes("version") || b.includes("database")) return { type: "info-disclosure", severity: "low" as const, title: "Health Endpoint Reveals Details", description: `${path} reveals infrastructure info.`, url: apiUrl, remedy: "Limit health responses to simple OK/fail." }; } catch { /* ignore */ }
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

  const optRes = await safeFetch(baseUrl, { method: "OPTIONS", timeout: 6000 });
  if (optRes) {
    const allow = optRes.headers.get("allow") || optRes.headers.get("access-control-allow-methods") || "";
    const found = ["PUT", "DELETE", "TRACE", "PATCH"].filter((m) => allow.toUpperCase().includes(m));
    if (found.length > 0) vulns.push({ type: "http-methods", severity: "medium", title: "Dangerous HTTP Methods Allowed", description: `Allows: ${found.join(", ")}.`, url: baseUrl, remedy: "Restrict to GET, POST, HEAD." });
  }

  const traceRes = await safeFetch(baseUrl, { method: "TRACE", timeout: 6000 });
  if (traceRes?.status === 200) {
    const body = await traceRes.text();
    if (body.includes("TRACE")) vulns.push({ type: "http-methods", severity: "medium", title: "TRACE Method Enabled (XST)", description: "TRACE enabled — Cross-Site Tracing possible.", url: baseUrl, remedy: "Disable TRACE method." });
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
    if (sensitiveFound.length > 0) vulns.push({ type: "info-disclosure", severity: "low", title: "Sensitive Paths in Sitemap", description: `Sitemap contains: ${sensitiveFound.join(", ")}.`, url: sitemapUrl, remedy: "Remove sensitive paths from sitemap." });
    break;
  }

  return vulns;
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
    vulns.push({ type: "waf", severity: "info", title: `WAF Detected: ${waf}`, description: `${waf} WAF is protecting this site.`, url: baseUrl, remedy: "Good — keep WAF rules updated." });
  } else {
    vulns.push({ type: "waf", severity: "low", title: "No WAF Detected", description: "No Web Application Firewall detected.", url: baseUrl, remedy: "Consider adding Cloudflare (free tier) or AWS WAF." });
  }

  return vulns;
}

// ─── 17. Source map detection ─────────────────────────────────────
async function checkSourceMaps(baseUrl: string, pages: string[]): Promise<VulnerabilityResult[]> {
  const vulns: VulnerabilityResult[] = [];
  const checked = new Set<string>();

  for (const pageUrl of pages.slice(0, 3)) {
    const res = await safeFetch(pageUrl, { timeout: 8000 });
    if (!res?.ok) continue;
    const ct = res.headers.get("content-type") || "";
    if (!ct.includes("text/html")) continue;

    const html = await res.text();
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
      vulns.push({ type: "source-maps", severity: "medium", title: "Source Maps Publicly Accessible", description: `${found.length} .map file(s) accessible.`, url: found[0]!, remedy: "Delete .map files from production." });
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

  if (hops > 3) vulns.push({ type: "redirect", severity: "low", title: "Excessive Redirect Chain", description: `${hops} redirects: ${chain.slice(0, 4).join(" → ")}…`, url, remedy: "Reduce redirects. Point directly to final URL." });

  const hasHTTP = chain.some((u) => u.startsWith("http://"));
  const hasHTTPS = chain.some((u) => u.startsWith("https://"));
  if (hasHTTP && hasHTTPS && hops > 0) vulns.push({ type: "ssl", severity: "medium", title: "Mixed HTTP/HTTPS in Redirects", description: "Redirect chain mixes HTTP and HTTPS.", url, remedy: "Use HTTPS for all redirects." });

  return vulns;
}

// ─── Score calculation ─────────────────────────────────────────────
function calculateScore(vulns: VulnerabilityResult[]): number {
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
    waf: 2,
    redirect: 2,
    "source-maps": 3,
    "directory-listing": 3,
    "open-redirect": 4,
    "outdated-lib": 4,
    sri: 3,
    iframe: 1,
    seo: 0,
    fingerprint: 0,
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
export async function scanWebsite(
  url: string,
  onProgress?: ProgressCallback
): Promise<ScanResult> {
  if (!url.startsWith("http://") && !url.startsWith("https://")) {
    url = "https://" + url;
  }

  const allVulns: VulnerabilityResult[] = [];
  const totalSteps = 16;
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
  const pages = await discoverPages(url, 25);
  report(`Found ${pages.length} page(s)`, "crawl", "done", 0, pages.length);

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

  // ── Steps 8-12: PARALLEL BATCH 2 (new deep checks) ────────────
  currentStepNum = 8;
  report("Probing API endpoints…", "api-probe", "running");
  report("Testing HTTP methods…", "http-methods", "running");
  report("Analyzing sitemap…", "sitemap", "running");
  report("Detecting WAF…", "waf", "running");
  report("Analyzing redirects…", "redirects", "running");

  const [apiV, methodV, sitemapV, wafV, redirectV] = await Promise.all([
    checkAPIEndpoints(url), checkHTTPMethods(url), checkSitemap(url),
    detectWAF(url), checkRedirectChain(url),
  ]);

  allVulns.push(...apiV);
  currentStepNum = 8;
  report("API scan complete", "api-probe", "done", apiV.length);

  allVulns.push(...methodV);
  currentStepNum = 9;
  report("HTTP methods complete", "http-methods", "done", methodV.length);

  allVulns.push(...sitemapV);
  currentStepNum = 10;
  report("Sitemap complete", "sitemap", "done", sitemapV.length);

  allVulns.push(...wafV);
  currentStepNum = 11;
  report("WAF detection complete", "waf", "done", wafV.length);

  allVulns.push(...redirectV);
  currentStepNum = 12;
  report("Redirect analysis complete", "redirects", "done", redirectV.length);

  // ── Steps 13-16: Per-page checks ──────────────────────────────
  currentStepNum = 13;
  report("Analyzing security headers…", "headers", "running");

  for (const pageUrl of pages) {
    const res = await safeFetch(pageUrl, { timeout: 15000 });
    if (!res) continue;

    if (pageUrl === pages[0]) {
      const headerVulns = checkSecurityHeaders(pageUrl, res.headers);
      allVulns.push(...headerVulns);
      report("Headers analyzed", "headers", "done", headerVulns.length);

      currentStepNum = 14;
      report("Auditing cookies…", "cookies", "running");
      const cookieVulns = checkCookies(pageUrl, res.headers);
      allVulns.push(...cookieVulns);
      report("Cookies complete", "cookies", "done", cookieVulns.length);

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

    currentStepNum = 15;
    const ct = res.headers.get("content-type") || "";
    if (ct.includes("text/html")) {
      report(`Scanning ${new URL(pageUrl).pathname}…`, "html", "running");
      const html = await res.text();
      const htmlVulns = checkHTMLSecurity(pageUrl, html);
      allVulns.push(...htmlVulns);

      if (pageUrl === pages[0]) {
        const techVulns = fingerprintTechnology(pageUrl, html, res.headers);
        allVulns.push(...techVulns);
      }
    }
  }

  report("HTML analysis complete", "html", "done", 0);

  // Source maps
  currentStepNum = 16;
  report("Checking source maps…", "source-maps", "running");
  const srcMapV = await checkSourceMaps(url, pages);
  allVulns.push(...srcMapV);
  report("Source maps complete", "source-maps", "done", srcMapV.length);

  // Deduplicate
  const seen = new Set<string>();
  const unique = allVulns.filter((v) => {
    const key = `${v.title}-${v.url}`;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });

  return { url, score: calculateScore(unique), vulnerabilities: unique, pagesScanned: pages.length };
}
