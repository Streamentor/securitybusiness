import type { VulnerabilityResult } from "./scanner";

export const STACK_TITLE = "Detected website stack";
export const OTHER_SERVERS = "\n\nOther servers:\n";

export function detectWebsiteStack(headers: Headers, html: string) {
  const powered = headers.get("x-powered-by") ?? "";
  const server = headers.get("server") ?? "";
  const framework = /next\.js/i.test(powered) || /__NEXT_DATA__|\/_next\/static\//.test(html) ? "Next.js"
    : /wp-(?:content|includes)\//i.test(html) ? "WordPress"
    : /express/i.test(powered) ? "Express"
    : /asp\.net/i.test(powered) ? "ASP.NET"
    : /php/i.test(powered) ? "PHP" : undefined;
  const host = headers.has("x-vercel-id") || /^vercel$/i.test(server) ? "Vercel"
    : headers.has("x-nf-request-id") || /netlify/i.test(server) ? "Netlify"
    : headers.has("cf-ray") ? "Cloudflare" : undefined;
  const origin = /nginx/i.test(server) ? "nginx" : /apache/i.test(server) ? "Apache" : /microsoft-iis/i.test(server) ? "IIS" : undefined;
  return { framework, host, origin };
}

export function describeWebsiteStack(stack: ReturnType<typeof detectWebsiteStack>) {
  const app = stack.framework ?? stack.origin;
  return app && stack.host ? app + " on " + stack.host : app ?? stack.host;
}

type Remedy = { name: string; text: string };
export function specializeWebsiteRemedy(finding: VulnerabilityResult, stack: ReturnType<typeof detectWebsiteStack>): VulnerabilityResult {
  const options: Remedy[] = [];
  const add = (name: string, text: string) => options.push({ name, text });
  if (/X-Powered-By/.test(finding.title)) {
    add("Next.js", "Set poweredByHeader: false in next.config, redeploy, and check the public response headers.");
    add("Express", "Call app.disable('x-powered-by') on the Express app.");
    add("PHP", "Set expose_php = Off in php.ini and reload PHP.");
    add("ASP.NET", "Disable framework version headers in the application and remove X-Powered-By in IIS.");
    add("nginx", "At the proxy, use proxy_hide_header X-Powered-By or fastcgi_hide_header X-Powered-By for FastCGI.");
    add("Apache", "Use mod_headers to unset X-Powered-By on proxied and error responses.");
  } else if (finding.type === "csp" || /Strict-Transport-Security|HSTS/.test(finding.title)) {
    const csp = finding.type === "csp";
    const key = csp ? "Content-Security-Policy" : "Strict-Transport-Security";
    const verify = csp ? " Roll out a Report-Only policy first and check login, checkout, and embeds." : " Confirm HTTPS is reliable before increasing max-age or including subdomains.";
    add("Next.js", "Set " + key + " in headers() in next.config for the affected paths." + verify);
    add("Vercel", "If the policy is owned at the deployment layer, configure " + key + " in vercel.json headers." + verify);
    add("Netlify", "Set " + key + " in the published _headers file for static responses. For server-rendered responses, set it in the responding app." + verify);
    add("nginx", "Set " + key + " with add_header in the HTTPS virtual host and verify its inheritance." + verify);
    add("Apache", "Use mod_headers in the HTTPS virtual host to set " + key + "." + verify);
  } else if (/HTTPS.*Redirect|Redirect.*HTTPS/.test(finding.title)) {
    add("Vercel", "Check the custom domain and proxy settings. Vercel serves HTTPS and redirects HTTP at its edge for configured domains.");
    add("Netlify", "Verify the custom domain certificate and enable HTTPS enforcement in domain settings if available.");
    add("Next.js", "Enforce the HTTP-to-HTTPS redirect at the TLS-terminating host or reverse proxy. Test scheme and host preservation.");
    add("nginx", "Configure the port 80 virtual host to redirect to the canonical HTTPS origin, preserving the path and query.");
    add("Apache", "Set the canonical HTTPS redirect in the port 80 virtual host.");
  } else if (/TRACE/.test(finding.title) || finding.type === "directory-listing") {
    const trace = /TRACE/.test(finding.title);
    add("nginx", trace ? "Reject TRACE at the public reverse proxy and verify the upstream cannot be reached around it." : "Disable autoindex for the affected location and confirm the index is gone.");
    add("Apache", trace ? "Set TraceEnable off in the applicable server configuration." : "Set Options -Indexes on the affected directory.");
    add("Next.js", trace ? "Verify whether the public edge or proxy responds to TRACE. Next.js route handlers do not implement it as a supported method." : "Check the responding deployment or proxy and remove any custom directory index handler.");
    add("Vercel", "Trace the response to the edge, external proxy, or rewrites. Fix the behavior at the layer that actually returned it.");
  } else if (finding.type === "cookies" || finding.type === "cors") {
    const cookie = finding.type === "cookies";
    add("Next.js", cookie ? "Update the cookie options where the application, route handler or authentication library sets the cookie. Keep the scope and SameSite value compatible with the intended login flow." : "Set CORS at the relevant route and its OPTIONS handler. Return only allowlisted origins for credentialed requests.");
    add("Express", cookie ? "Use the appropriate Secure, HttpOnly, SameSite and host scope in res.cookie or the session middleware options." : "Set a route-specific origin allowlist in the CORS middleware.");
    add("nginx", cookie ? "Prefer fixing the issuing app. For a proxied cookie that you manage at nginx, review proxy_cookie_flags and cookie scope." : "Remove unconditional CORS headers from the proxy and validate the request origin before setting credentialed CORS headers.");
  }
  const index = [stack.framework, stack.host, stack.origin].map((name) => options.findIndex((item) => item.name === name)).find((match) => match >= 0);
  if (index === undefined) return finding;
  const first = options[index];
  const alternative = options.filter((item, i) => i !== index).map((item) => item.name + "\n" + item.text).join("\n\n");
  // Keep the directive-specific explanation when it contains no long platform examples.
  const detail = finding.type === "csp" ? finding.remedy.split("\n\n")[0] : "";
  return { ...finding, remedy: first.name + "\n" + first.text + (detail ? "\n\n" + detail : "") + (alternative ? OTHER_SERVERS + alternative : "") };
}
