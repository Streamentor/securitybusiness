import assert from "node:assert/strict";
import { registerHooks } from "node:module";
import "./scan-test-hook.mjs";

registerHooks({ resolve(specifier, context, nextResolve) {
  if (specifier === "node:dns/promises") return { url: "data:text/javascript,export const lookup=async()=>[{address:'203.0.113.1',family:4}];", shortCircuit: true };
  if (specifier === "dns") return { url: "data:text/javascript,export const resolveTxt=(hostname, callback)=>callback(null,[]);", shortCircuit: true };
  return nextResolve(specifier, context);
}});
const { collectSaaSReadiness, scanWebsite } = await import("../src/lib/scanner.ts");
const { findLegalPages, checkCompliance } = await import("../src/lib/compliance.ts");
const originalFetch = globalThis.fetch;
const originalNow = Date.now;
const root = "https://example.com/";
const www = "https://www.example.com/";
const html = '<html><head><link rel="canonical" href="/"></head><body><footer><a href="/privacy-policy-2">Privacy Policy</a></footer></body></html>';
const responseAt = (url, body, type) => {
  const response = new Response(body, { headers: { "Content-Type": type } });
  Object.defineProperty(response, "url", { value: url });
  return response;
};
let seen = [];
globalThis.fetch = async (input) => {
  const url = new URL(input);
  seen.push(url.toString());
  if (url.hostname === "example.com") return new Response(null, { status: 308, headers: { location: new URL(url.pathname, www).href } });
  if (url.pathname === "/") return responseAt(url.href, html, "text/html");
  if (url.pathname === "/robots.txt") return responseAt(url.href, "User-agent: *\nAllow: /", "text/plain");
  if (url.pathname === "/sitemap.xml") return responseAt(url.href, "<urlset></urlset>", "application/xml");
  if (url.pathname === "/privacy-policy-2") return responseAt(url.href, "<html><main>Privacy Policy</main></html>", "text/html");
  return new Response(null, { status: 404 });
};
try {
  const readiness = await collectSaaSReadiness(root);
  for (const key of ["robots", "sitemap", "canonical", "indexability"]) {
    const item = readiness.items.find((entry) => entry.key === key);
    assert.equal(item.status, "pass");
    assert.ok(item.url.startsWith(www));
  }
  assert.equal(findLegalPages([{ url: readiness.home.url, html: readiness.home.text }]).privacyUrl, www + "privacy-policy-2");
  const seenBeforeCrawl = seen.length;
  const runner = {
    findPrivacyLink: (pages) => findLegalPages(pages).privacyUrl,
    start() {},
    async finish(input) {
      const result = await checkCompliance(input.url, input.pages, input);
      assert.equal(result.policy?.url, www + "privacy-policy-2");
      assert.equal(result.checks.find((entry) => entry.key === "policy").status, "pass");
      return [];
    },
  };
  const scan = await scanWebsite(root, undefined, { compliance: runner });
  assert.equal(scan.url, www);
  await scan.runCompliance();
  assert.ok(seen.slice(seenBeforeCrawl).includes(www + "privacy-policy-2"));

  let clock = 0;
  Date.now = () => clock;
  const slowRoot = "http://203.0.113.1";
  globalThis.fetch = async (url) => {
    if (new URL(url).pathname === "/") {
      clock = 91_000;
      return responseAt(url, '<html><a href="/next">Next</a></html>', "text/html");
    }
    return new Response(null, { status: 503 });
  };
  const partial = await scanWebsite(slowRoot);
  const states = JSON.parse(partial.vulnerabilities.find((finding) => finding.title === "SaaS readiness snapshot").description).items;
  assert.equal(states.find((entry) => entry.key === "robots").status, "not_checked");
  assert.equal(states.find((entry) => entry.key === "robots").reason, "time_budget");
  assert.doesNotMatch(JSON.stringify(states), /No readable/);
  assert.equal(partial.coverage.partial, true);
} finally {
  globalThis.fetch = originalFetch;
  Date.now = originalNow;
}
console.log("Readiness states, time budget and apex-to-www checks passed.");
