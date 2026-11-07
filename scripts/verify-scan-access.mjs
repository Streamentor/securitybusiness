import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";

// Next supplies the server-only and @/ aliases in production. Resolve them for
// these isolated Node tests without loading the framework or any credentials.
const sourceRoot = new URL("../src/", import.meta.url);
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") return { url: "data:text/javascript,export{}", shortCircuit: true };
    if (specifier.startsWith("@/")) return { url: new URL(`${specifier.slice(2)}.ts`, sourceRoot).href, shortCircuit: true };
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(sourceRoot.href) && url.endsWith(".ts")) {
      return { format: "module", source: stripTypeScriptTypes(readFileSync(new URL(url), "utf8"), { mode: "transform" }), shortCircuit: true };
    }
    return nextLoad(url, context);
  },
});


const { decideScanAccess, hostnameKey, allowScanRequest, VERIFICATION_WINDOW_MS } = await import("../src/lib/scan-access.ts");
const { compareScanFindings } = await import("../src/lib/scan-comparison.ts");
const { classifyReferrer } = await import("../src/lib/referrer.ts");
const { summarizeChannels } = await import("../src/lib/activation-metrics.ts");

const now = new Date("2026-11-07T12:00:00Z");
const daysAgo = (days) => new Date(now.getTime() - days * 24 * 60 * 60 * 1000);
const decide = (overrides) => decideScanAccess({ userId: null, plan: "free", credits: 0, targetUrl: "https://app.io/", priorFreeScans: [], now, ...overrides });

assert.equal(hostnameKey("https://WWW.App.io/x"), "app.io");

// Exact hostnames, not substrings
const unrelated = [{ userId: null, url: "https://myapp.io/", createdAt: daysAgo(1) }, { userId: "u2", url: "https://app.io.evil.example/", createdAt: daysAgo(1) }];
assert.equal(decide({ priorFreeScans: unrelated }).allowed, true, "myapp.io must not lock app.io");
assert.equal(decide({ targetUrl: "https://example.com/", priorFreeScans: [{ userId: null, url: "https://shop.example.com/", createdAt: daysAgo(1) }] }).allowed, true, "a subdomain must not lock the apex");

// Anonymous users: one free scan per hostname
assert.deepEqual(decide({}), { allowed: true, kind: "first", consumesCredit: false });
assert.equal(decide({ priorFreeScans: [{ userId: null, url: "https://www.app.io/", createdAt: daysAgo(30) }] }).allowed, false);

// A signed-in founder can spend their own credit even if someone else scanned the domain first
const strangerScanned = [{ userId: null, url: "https://app.io/", createdAt: daysAgo(2) }, { userId: "stranger", url: "https://app.io/", createdAt: daysAgo(1) }];
assert.deepEqual(decide({ userId: "founder", credits: 1, priorFreeScans: strangerScanned }), { allowed: true, kind: "first", consumesCredit: true });
assert.equal(decide({ userId: "founder", credits: 0, priorFreeScans: strangerScanned }).allowed, false, "no credit, no first scan");
const manyAccounts = ["a", "b", "c"].map((userId) => ({ userId, url: "https://app.io/", createdAt: daysAgo(1) }));
assert.equal(decide({ userId: "d", credits: 1, priorFreeScans: manyAccounts }).allowed, false, "multi-account abuse stays limited");

// One free verification rescan within 7 days, without spending a credit
const own = [{ userId: "founder", url: "https://app.io/", createdAt: daysAgo(2) }];
assert.deepEqual(decide({ userId: "founder", credits: 0, priorFreeScans: own }), { allowed: true, kind: "verification", consumesCredit: false });
const used = [...own, { userId: "founder", url: "https://app.io/", createdAt: daysAgo(1) }];
assert.match(decide({ userId: "founder", credits: 0, priorFreeScans: used }).error, /already used the free verification rescan/);
const expired = [{ userId: "founder", url: "https://app.io/", createdAt: new Date(now.getTime() - VERIFICATION_WINDOW_MS - 1000) }];
assert.match(decide({ userId: "founder", credits: 0, priorFreeScans: expired }).error, /available for 7 days/);

// Paid plans: credits only
assert.deepEqual(decide({ userId: "p", plan: "pro", credits: 3, priorFreeScans: manyAccounts }), { allowed: true, kind: "paid", consumesCredit: true });
assert.equal(decide({ userId: "p", plan: "starter", credits: 0 }).allowed, false);

// Rate limit: 3 anonymous scans per hour per network
const t0 = now.getTime();
assert.deepEqual([1, 2, 3, 4].map((i) => allowScanRequest("net-fixture", "anonymous", t0 + i)), [true, true, true, false]);
assert.equal(allowScanRequest("net-fixture", "anonymous", t0 + 60 * 60 * 1000 + 10), true, "the window expires");

// Comparison between two reports
const diff = compareScanFindings(
  [{ title: "Missing HSTS", url: "https://app.io/" }, { title: "Cookies Without HttpOnly", url: "https://app.io/" }],
  [{ title: "Cookies Without HttpOnly", url: "https://app.io/login" }, { title: "Mixed Content Detected", url: "https://app.io/" }],
);
assert.deepEqual(diff, { resolved: ["Missing HSTS"], added: ["Mixed Content Detected"], stillOpen: 1 });

// Attribution
assert.equal(classifyReferrer("https://www.reddit.com/r/SaaS"), "reddit", "reddit.com contains 't.co' but is not Twitter");
assert.equal(classifyReferrer("https://www.dropbox.com/"), "dropbox.com", "dropbox.com contains 'x.com' but is not X");
assert.equal(classifyReferrer("https://t.co/abc"), "twitter");
assert.equal(classifyReferrer("https://l.instagram.com/"), "instagram");
const channels = Object.fromEntries(summarizeChannels([{ referrerSource: "stefbuilds", _count: { _all: 2 } }, { referrerSource: "Instagram", _count: { _all: 1 } }, { referrerSource: "tiktok", _count: { _all: 1 } }], [], []).map((row) => [row.channel, row.registrations]));
assert.deepEqual(channels, { instagram: 1, stefbuilds: 2, tiktok: 1 }, "own channels must not collapse into 'other'");

console.log("Scan access, verification rescan, comparison and attribution checks passed.");
