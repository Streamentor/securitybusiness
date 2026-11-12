import assert from "node:assert/strict";
import http from "node:http";
import { existsSync } from "node:fs";
import { registerHooks } from "node:module";
import { fileURLToPath } from "node:url";

// Resolve "@/lib/x" and extensionless relative imports to TypeScript files, as Next.js does.
const sourceRoot = new URL("../src/", import.meta.url);
registerHooks({
  resolve(specifier, context, nextResolve) {
    const base = specifier.startsWith("@/") ? new URL(specifier.slice(2), sourceRoot) : specifier.startsWith(".") && context.parentURL?.startsWith("file:") ? new URL(specifier, context.parentURL) : null;
    if (base && !/\.[cm]?[jt]s$/.test(base.pathname) && existsSync(fileURLToPath(base) + ".ts")) return nextResolve(base.href + ".ts", context);
    return nextResolve(specifier, context);
  },
});

const compliance = await import("../src/lib/compliance.ts");
const ai = await import("../src/lib/compliance-ai.ts");
const types = await import("../src/lib/compliance-types.ts");
const scanner = await import("../src/lib/scanner.ts");

const noFetch = { fetchHtml: async () => null };
const page = (body, { lang = "en", head = "" } = {}) => `<!doctype html><html lang="${lang}"><head><meta name="viewport" content="width=device-width, initial-scale=1">${head}</head><body>${body}</body></html>`;
const footer = `<footer><a href="/privacy">Privacy Policy</a> <a href="/terms">Terms</a></footer>`;
const ga = `<script async src="https://www.googletagmanager.com/gtag/js?id=G-TEST123"></script><script>gtag('config', 'G-TEST123');</script>`;
const titles = (result) => result.findings.map((finding) => finding.title);

// Trackers with no consent tool: a medium HTML-only finding that names the tracker.
let result = await compliance.checkCompliance("https://example.com", [{ url: "https://example.com/", html: page(`<h1>Hi</h1>${footer}`, { head: ga }) }], noFetch);
assert.equal(result.noConsentToolFinding?.severity, "medium");
assert.match(result.noConsentToolFinding.description, /Google Analytics/);
assert.match(result.noConsentToolFinding.description, /JavaScript may not be visible/, "the HTML-only limit must be stated");
assert.ok(titles(result).includes("Tracking and analytics services detected"));

// The same page with Cookiebot, with Google consent mode, or with banner markup: no consent finding.
for (const extra of [`<script src="https://consent.cookiebot.com/uc.js" data-cbid="x"></script>`, `<script>gtag('consent', 'default', {analytics_storage: 'denied'});</script>`, `<div id="cookie-banner">We use cookies</div>`]) {
  result = await compliance.checkCompliance("https://example.com", [{ url: "https://example.com/", html: page(`<h1>Hi</h1>${extra}${footer}`, { head: ga }) }], noFetch);
  assert.equal(result.noConsentToolFinding, undefined, `consent signal must suppress the finding: ${extra.slice(0, 40)}`);
}

// A German footer link counts as a privacy policy.
result = await compliance.checkCompliance("https://example.de", [{ url: "https://example.de/", html: page(`<a href="/signup">Sign up</a><footer><a href="/datenschutz">Datenschutz</a><a href="/agb">AGB</a><a href="/impressum">Impressum</a></footer>`, { lang: "de" }) }], noFetch);
assert.deepEqual(titles(result).filter((title) => /Privacy Policy|Terms|Impressum/.test(title)), [], "Datenschutz, AGB and Impressum links must be recognized");

// No policy anywhere on a site with sign-up: high. Probing /privacy finds it: no finding.
const bare = [{ url: "https://example.com/", html: page(`<a href="/signup">Start free</a>`) }];
result = await compliance.checkCompliance("https://example.com", bare, noFetch);
assert.equal(result.findings.find((f) => f.title === "No Privacy Policy found")?.severity, "high");
assert.ok(titles(result).includes("No Terms of Service found"));
result = await compliance.checkCompliance("https://example.com", bare, { fetchHtml: async (url) => url.endsWith("/privacy") ? { url, html: page(`<main><h1>Privacy policy</h1><p>${"We collect your email. ".repeat(40)}</p></main>`) } : null });
assert.equal(titles(result).includes("No Privacy Policy found"), false, "a policy found by probing must not be reported missing");
assert.ok(titles(result).includes("Privacy Policy is not linked from the homepage"));

// A static brochure site with no forms, trackers or accounts gets no privacy-policy finding.
result = await compliance.checkCompliance("https://example.com", [{ url: "https://example.com/", html: page("<h1>Bakery</h1>") }], noFetch);
assert.equal(titles(result).includes("No Privacy Policy found"), false);

// Forms: pre-checked marketing box, email form without notice, login form ignored.
const forms = page(`${footer}
  <form><label for="e">Email</label><input id="e" type="email"><input id="n" type="checkbox" checked><label for="n">Send me the newsletter</label><button>Join</button></form>
  <div><form><label>Email <input type="email"></label><button>Subscribe</button></form><p>See our <a href="/privacy">Privacy Policy</a>.</p></div>`);
result = await compliance.checkCompliance("https://example.com", [{ url: "https://example.com/", html: forms }], noFetch);
assert.equal(result.findings.find((f) => f.title === "Marketing checkbox is pre-checked")?.severity, "medium");
const formFinding = result.findings.find((f) => f.title === "Email form without a privacy notice link");
assert.match(formFinding.description, /^1 form on this page/, "only the form without a nearby policy link counts");
result = await compliance.checkCompliance("https://example.com", [{ url: "https://example.com/", html: page(`${footer}<form><label>Email<input type="email"></label><label>Password<input type="password"></label><button>Log in</button></form><form><input type="checkbox"><label>newsletter</label></form>`) }], noFetch);
assert.equal(titles(result).some((t) => /pre-checked|Email form/.test(t)), false, "login forms and unchecked boxes are fine");

// Accessibility signals.
result = await compliance.checkCompliance("https://example.com", [{ url: "https://example.com/", html: `<html><head><meta name="viewport" content="width=device-width, user-scalable=no"></head><body>${footer}<img src="/hero.png"><img src="/line.svg" alt=""><input name="q"><button><svg></svg></button><button aria-label="Menu"><svg></svg></button></body></html>` }], noFetch);
for (const title of ["Images without alt text", "Form fields without labels", "Buttons or links without an accessible name", "Page language is not declared", "Pinch zoom is disabled"]) assert.ok(titles(result).includes(title), title);
assert.match(result.findings.find((f) => f.title === "Images without alt text").description, /^1 image/, "alt=\"\" is a valid decorative image");
assert.match(result.findings.find((f) => f.title === "Buttons or links without an accessible name").description, /^1 button/);

// Policy compared with trackers: names the vendor that is missing, accepts the one that is mentioned.
const hotjar = compliance.TRACKERS.find((t) => t.id === "hotjar"), gaSig = compliance.TRACKERS.find((t) => t.id === "google-analytics");
let policyFindings = compliance.checkPolicyAgainstTrackers({ url: "https://example.com/privacy", text: "We use Google Analytics and cookies to measure traffic." }, [gaSig, hotjar]);
assert.equal(policyFindings.length, 1);
assert.match(policyFindings[0].description, /Hotjar/);
assert.doesNotMatch(policyFindings[0].description, /Google Analytics/);
policyFindings = compliance.checkPolicyAgainstTrackers({ url: "https://example.com/privacy", text: "We use Google and Hotjar." }, [gaSig, hotjar]);
assert.deepEqual(policyFindings.map((f) => f.title), ["Privacy Policy does not mention cookies"]);

// Policy text reads the main content, not navigation or scripts.
assert.equal(compliance.policyText("<body><nav>Home</nav><script>x()</script><main> Policy  text </main></body>"), "Policy text");

// AI answers are accepted only as a complete list of known topics.
const keys = Object.keys(ai.POLICY_TOPICS);
assert.equal(ai.missingTopicsFrom({ topics: keys.slice(1).map((key) => ({ key, covered: true })) }), null, "an incomplete answer is discarded");
assert.equal(ai.missingTopicsFrom({ topics: [...keys.map((key) => ({ key, covered: true })), { key: "invented", covered: false }] }), null, "an unknown topic is discarded");
assert.deepEqual(ai.missingTopicsFrom({ topics: keys.map((key) => ({ key, covered: key !== "retention" })) }), ["retention"]);
const topicFinding = ai.policyTopicFinding("https://example.com/privacy", ["retention", "complaint"]);
assert.equal(topicFinding.severity, "low");
assert.match(topicFinding.description, /how long data is kept/);
assert.equal(ai.policyTopicFinding("https://example.com/privacy", []), null);
assert.equal(ai.policyReviewBody("gpt-5.6-luna", "x".repeat(50_000)).input[0].content[0].text.length, 30_000, "policy text is bounded");

// Compliance findings never change the security score.
const security = [{ type: "headers", severity: "medium", title: "Missing HSTS", description: "", url: "https://example.com/", remedy: "" }];
const withCompliance = [...security, ...result.findings, { type: "cookies-consent", severity: "high", title: "Tracking cookies are set before consent", description: "", url: "https://example.com/", remedy: "" }];
assert.equal(scanner.calculateScore(withCompliance), scanner.calculateScore(security));
assert.ok(types.isComplianceFinding({ type: "accessibility" }) && !types.isComplianceFinding({ type: "cookies" }));
assert.deepEqual(types.parseComplianceCoverage(JSON.stringify({ browser: "ran", ai: "plan", trackers: ["Hotjar", 4] })), { browser: "ran", ai: "plan", policyUrl: undefined, trackers: ["Hotjar"] });
assert.equal(types.parseComplianceCoverage("not json"), null);

// The free runner: HTML checks only, plus a coverage row the report reads.
const runnerModule = await import("../src/lib/compliance-runner.ts");
const free = runnerModule.createComplianceRunner({ plan: "free" });
free.start("https://example.com/", { timeoutMs: 1000, assertPublicHost: async () => {} });
const freeFindings = await free.finish({ url: "https://example.com/", pages: [{ url: "https://example.com/", html: page(`<h1>Hi</h1>${footer}`, { head: ga }) }], fetchHtml: async () => null, remainingMs: () => 60_000 });
assert.ok(freeFindings.some((f) => f.title === "Trackers found with no cookie consent tool"));
assert.deepEqual(types.parseComplianceCoverage(freeFindings.find((f) => f.title === types.COMPLIANCE_COVERAGE_TITLE).description), { browser: "plan", ai: "plan", policyUrl: undefined, trackers: ["Google Analytics / Google tag"] });

// Browser consent test against local pages. Skipped only when no Chromium is installed.
const browserModule = await import("../src/lib/compliance-browser.ts");
let secretHits = 0;
const banner = (reject) => `<div class="consent"><p>We use cookies to improve the site.</p><button id="accept">Accept all</button>${reject ? `<button id="reject" onclick="localStorage.setItem('consent','no')">Reject all</button>` : ""}</div>`;
const pages = {
  "/before": page(`${banner(false)}<script>gtag=function(){};gtag('config','G-TEST');document.cookie="_ga=GA1.1.1; path=/";fetch("http://localhost:PORT/secret").catch(()=>{});</script>`),
  "/respects": page(`${banner(true)}<script>if (localStorage.getItem('consent') === 'yes') document.cookie="_ga=GA1.1.1; path=/";</script>`),
  "/ignores": page(`${banner(true)}<script>setTimeout(()=>{ if (localStorage.getItem('consent') === 'no') document.cookie="_fbp=fb.1.1; path=/"; }, 50);</script>`),
};
const server = http.createServer((req, res) => {
  if (req.url === "/secret") { secretHits += 1; res.end("secret"); return; }
  res.writeHead(200, { "content-type": "text/html" });
  res.end((pages[req.url] || page("ok")).replace("PORT", String(server.address().port)));
});
await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
const base = `http://127.0.0.1:${server.address().port}`;
const options = { timeoutMs: 40_000, assertPublicHost: async (hostname) => { if (hostname !== "127.0.0.1") throw new Error("private"); } };
try {
  let run = await browserModule.runBrowserConsentCheck(`${base}/before`, options);
  if (run.status === "unavailable") {
    console.log("SKIP browser consent test: Chromium is not available here");
  } else {
    const bTitles = run.findings.map((f) => f.title);
    assert.ok(bTitles.includes("Tracking cookies are set before consent"), bTitles.join(" | "));
    assert.match(run.findings.find((f) => f.title === "Tracking cookies are set before consent").description, /_ga/);
    assert.ok(bTitles.includes("Cookie banner has no reject button on the first screen"));
    assert.equal(run.bannerFound, true);
    assert.ok(run.trackers.some((t) => t.id === "google-analytics"));
    assert.equal(secretHits, 0, "requests to hosts that fail the public-host check must be blocked");

    run = await browserModule.runBrowserConsentCheck(`${base}/respects`, options);
    assert.deepEqual(run.findings.filter((f) => f.type === "cookies-consent"), [], "a site that respects Reject has no consent findings");

    run = await browserModule.runBrowserConsentCheck(`${base}/ignores`, options);
    assert.ok(run.findings.some((f) => f.title === "Tracking cookies are set after Reject"), run.findings.map((f) => f.title).join(" | "));

    // The paid runner replaces the HTML-only "no consent tool" guess with the browser result.
    const paid = runnerModule.createComplianceRunner({ plan: "starter" });
    paid.start(`${base}/before`, options);
    const paidFindings = await paid.finish({ url: `${base}/before`, pages: [{ url: `${base}/before`, html: pages["/before"] }], fetchHtml: async () => null, remainingMs: () => 60_000 });
    assert.equal(paidFindings.some((f) => f.title === "Trackers found with no cookie consent tool"), false);
    assert.ok(paidFindings.some((f) => f.title === "Tracking cookies are set before consent"));
    assert.equal(types.parseComplianceCoverage(paidFindings.find((f) => f.title === types.COMPLIANCE_COVERAGE_TITLE).description).browser, "ran");
  }
} finally {
  server.close();
}

console.log("compliance checks verified");
