import assert from "node:assert/strict";
import { generateKeyPairSync, createVerify } from "node:crypto";
import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";

// Synthetic fixtures only: no GitHub, database or credentials are contacted.
const sourceRoot = new URL("../src/", import.meta.url);
const shim = (source) => ({ url: `data:text/javascript,${encodeURIComponent(source)}`, shortCircuit: true });
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") return shim("export {}");
    if (specifier === "next/server") return nextResolve("next/server.js", context);
    if (specifier === "@/lib/db") return shim("export const prisma = new Proxy({}, { get: (_, key) => globalThis.ghFixture.db[key] });");
    if (specifier === "@/lib/auth") return shim("export const auth = async () => globalThis.ghFixture.session;");
    if (specifier === "@/lib/repo-store") return shim("export const ensureRepoTables = async () => {};");
    if (specifier.startsWith("@/")) return { url: new URL(`${specifier.slice(2)}.ts`, sourceRoot).href, shortCircuit: true };
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(sourceRoot.href) && url.endsWith(".ts")) return { format: "module", source: stripTypeScriptTypes(readFileSync(new URL(url), "utf8"), { mode: "transform" }), shortCircuit: true };
    return nextLoad(url, context);
  },
});

const { privateKey, publicKey } = generateKeyPairSync("rsa", { modulusLength: 2048, privateKeyEncoding: { type: "pkcs8", format: "pem" }, publicKeyEncoding: { type: "spki", format: "pem" } });
Object.assign(process.env, { GITHUB_APP_ID: "4242", GITHUB_APP_SLUG: "scanmysaas-test", GITHUB_APP_PRIVATE_KEY: privateKey.replace(/\n/g, "\\n"), GITHUB_APP_CLIENT_ID: "Iv1.fixture", GITHUB_APP_CLIENT_SECRET: "fixture-secret", AUTH_SECRET: "fixture-auth-secret" });

const fixture = { session: null, db: {}, upserts: [], created: [] };
globalThis.ghFixture = fixture;
const app = await import("../src/lib/github-app.ts");

// Private key formats
assert.equal(app.normalizePrivateKey(privateKey.replace(/\n/g, "\\n")), privateKey.trim());
assert.equal(app.normalizePrivateKey(Buffer.from(privateKey).toString("base64")), privateKey.trim());
const config = app.getGitHubAppConfig();
assert.ok(config, "all five variables enable the integration");
assert.equal(app.getGitHubAppConfig({ GITHUB_APP_ID: "1" }), null, "partial configuration keeps the feature hidden");

// RS256 app JWT
const jwt = app.createAppJwt(config, Date.UTC(2026, 10, 7));
const [h, p, sig] = jwt.split(".");
const verifier = createVerify("RSA-SHA256"); verifier.update(`${h}.${p}`);
assert.ok(verifier.verify(publicKey, Buffer.from(sig, "base64url")), "JWT signature must verify with the app public key");
const payload = JSON.parse(Buffer.from(p, "base64url").toString());
assert.equal(payload.iss, "4242");
assert.ok(payload.exp - payload.iat <= 600, "GitHub rejects app JWTs longer than 10 minutes");

// Signed connect state
const { state, nonce } = app.createConnectState("user-a");
app.verifyConnectState(state, { userId: "user-a", nonce });
assert.throws(() => app.verifyConnectState(state, { userId: "user-b", nonce }), /another session/, "state is bound to the user");
assert.throws(() => app.verifyConnectState(state, { userId: "user-a", nonce: "other" }), /another session/, "state is bound to the browser nonce");
assert.throws(() => app.verifyConnectState(state.replace(/.$/, (c) => c === "A" ? "B" : "A"), { userId: "user-a", nonce }), /could not be verified/, "tampered state is rejected");
const old = app.createConnectState("user-a", "fixture-auth-secret", Date.now() - 60 * 60 * 1000);
assert.throws(() => app.verifyConnectState(old.state, { userId: "user-a", nonce: old.nonce }), /expired/);

// Callback: only installations GitHub lists for the user's own token are linked
const realFetch = globalThis.fetch;
globalThis.fetch = async (url, init = {}) => {
  const target = String(url);
  if (target === "https://github.com/login/oauth/access_token") {
    const body = JSON.parse(init.body);
    assert.equal(body.client_secret, "fixture-secret");
    return Response.json(body.code === "good-code" ? { access_token: "user-token" } : { error: "bad_verification_code" });
  }
  if (target.startsWith("https://api.github.com/user/installations")) {
    assert.equal(init.headers.Authorization, "Bearer user-token");
    return Response.json({ installations: [{ id: 111, app_id: 4242, account: { login: "founder", type: "User" } }, { id: 222, app_id: 9999, account: { login: "other-app", type: "User" } }] });
  }
  throw new Error(`Unexpected request ${target}`);
};
fixture.db = { gitHubInstallation: { upsert: async (args) => { fixture.upserts.push(args); return {}; } } };
const { GET: callback } = await import("../src/app/api/github/callback/route.ts");
const { NextRequest } = await import("next/server.js");
const call = (query, cookieNonce) => callback(new NextRequest(`https://scanmysaas.example/api/github/callback?${query}`, { headers: cookieNonce ? { cookie: `gh_connect_nonce=${cookieNonce}` } : {} }));

fixture.session = { user: { id: "user-a" } };
const fresh = app.createConnectState("user-a");
let response = await call(`code=good-code&installation_id=999&setup_action=install&state=${encodeURIComponent(fresh.state)}`, fresh.nonce);
assert.match(response.headers.get("location"), /github=connected/);
assert.deepEqual(fixture.upserts.map((args) => [args.create.userId, args.create.installationId]), [["user-a", 111]], "the spoofable installation_id query value is ignored; other apps' installations are ignored");

fixture.upserts = [];
response = await call(`code=good-code&state=${encodeURIComponent(fresh.state)}`, "wrong-nonce");
assert.match(response.headers.get("location"), /github=expired/, "a different browser cannot complete the connection");
assert.equal(fixture.upserts.length, 0);
fixture.session = { user: { id: "attacker" } };
response = await call(`code=good-code&state=${encodeURIComponent(fresh.state)}`, fresh.nonce);
assert.match(response.headers.get("location"), /github=expired/, "another signed-in user cannot replay the state");
assert.equal(fixture.upserts.length, 0);
fixture.session = null;
response = await call(`code=good-code&state=x`, "x");
assert.match(response.headers.get("location"), /\/login/);
globalThis.fetch = realFetch;

// Jobs: entitlement and access
const jobs = await import("../src/lib/repo-scan-jobs.ts");
assert.equal(jobs.canScanPrivateRepositories({ plan: "free" }), false);
assert.equal(jobs.canScanPrivateRepositories({ plan: "starter" }), true);
assert.equal(jobs.canScanPrivateRepositories({ plan: "free", role: "admin" }), true);
const now = Date.now();
assert.equal(jobs.isStale({ status: "running", createdAt: new Date(now - 10 * 60_000), startedAt: new Date(now - 10 * 60_000) }, now), true);
assert.equal(jobs.isStale({ status: "running", createdAt: new Date(now - 60_000), startedAt: null }, now), false);
assert.equal(jobs.isStale({ status: "completed", createdAt: new Date(0), startedAt: null }, now), false);

let plan = "free";
let installations = [{ installationId: 111 }];
fixture.db = {
  user: { findUnique: async () => ({ plan, role: "user" }) },
  repoScan: { count: async () => 0, findMany: async () => [], create: async (args) => { fixture.created.push(args.data); return { id: "job-1" }; } },
  gitHubInstallation: { findMany: async () => installations },
};
globalThis.fetch = async (url, init = {}) => {
  const target = String(url);
  if (target.includes("/app/installations/111/access_tokens")) return Response.json({ token: "inst-token" });
  if (target.endsWith("/repos/founder/secret-app")) return init.headers?.Authorization === "Bearer inst-token" ? Response.json({ private: true }) : new Response("Not found", { status: 404 });
  if (target.endsWith("/repos/founder/open-app")) return Response.json({ private: false });
  if (target.endsWith("/repos/stranger/secret")) return new Response("Not found", { status: 404 });
  throw new Error(`Unexpected request ${target}`);
};
await assert.rejects(jobs.createRepoScanJob("user-a", "founder/secret-app"), (error) => error.status === 402 && /Starter and Pro/.test(error.message), "free plans cannot scan private repositories");
plan = "pro";
assert.deepEqual(await jobs.createRepoScanJob("user-a", "https://github.com/founder/secret-app/tree/release/v2"), { id: "job-1" });
assert.deepEqual([fixture.created[0].visibility, fixture.created[0].installationId, fixture.created[0].requestedRef], ["private", 111, "release/v2"]);
await assert.rejects(jobs.createRepoScanJob("user-a", "stranger/secret"), (error) => error.status === 404, "repositories the installation cannot see are refused");
plan = "free";
installations = [];
fixture.created = [];
await jobs.createRepoScanJob("user-a", "founder/open-app");
assert.equal(fixture.created[0].visibility, "public", "public repositories stay free for signed-in users");
fixture.db.repoScan.count = async () => 15;
await assert.rejects(jobs.createRepoScanJob("user-a", "founder/open-app"), (error) => error.status === 429);
globalThis.fetch = realFetch;

// Scanner: private reads use the contents API with the installation token and are never cached
const scanner = await import("../src/lib/github-scanner.ts");
const SHA = "c".repeat(40);
const seen = [];
globalThis.fetch = async (url, init = {}) => {
  const target = new URL(String(url));
  seen.push({ host: target.hostname, path: target.pathname, auth: init.headers?.Authorization });
  if (target.pathname === "/repos/founder/secret-app") return Response.json({ name: "secret-app", full_name: "founder/secret-app", html_url: "https://github.com/founder/secret-app", private: true, default_branch: "main", pushed_at: "t" });
  if (target.pathname.includes("/commits/")) return Response.json({ sha: SHA });
  if (target.pathname.includes("/git/trees/")) return Response.json({ truncated: false, tree: [{ path: "src/app/api/admin/route.ts", type: "blob", size: 40 }] });
  if (target.pathname.includes("/contents/")) return new Response("export const ok = true;");
  if (target.hostname === "api.osv.dev") return new Response("down", { status: 503 });
  throw new Error(`Unexpected request ${target}`);
};
await assert.rejects(scanner.scanPublicGitHubRepository("founder/secret-app"), /private/, "the anonymous scanner never reads private repositories");
seen.length = 0;
const stages = [];
const privateResult = await scanner.scanGitHubRepository("founder/secret-app", { accessToken: "inst-token", onStage: (stage) => { stages.push(stage); } });
assert.equal(privateResult.repository.visibility, "private");
assert.equal(privateResult.filesScanned, 1);
assert.ok(seen.filter((request) => request.host === "api.github.com").every((request) => request.auth === "Bearer inst-token"), "every GitHub request uses the installation token");
assert.equal(seen.some((request) => request.host === "raw.githubusercontent.com"), false, "private files are not fetched from raw.githubusercontent.com");
assert.deepEqual(stages, ["resolving", "reading-tree", "reading-files", "analyzing", "dependencies", "scoring"]);
const before = seen.length;
await scanner.scanGitHubRepository("founder/secret-app", { accessToken: "inst-token" });
assert.ok(seen.length > before + 3, "private results are not served from the shared cache");
globalThis.fetch = realFetch;

console.log("GitHub App, connection callback, repository job and private scanner checks passed.");
