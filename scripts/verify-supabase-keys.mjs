import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";

const sourceRoot = new URL("../src/", import.meta.url);
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") return { url: "data:text/javascript,export{}", shortCircuit: true };
    if (specifier.startsWith("@/")) return { url: new URL(`${specifier.slice(2)}.ts`, sourceRoot).href, shortCircuit: true };
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(sourceRoot.href) && url.endsWith(".ts")) return { format: "module", source: stripTypeScriptTypes(readFileSync(new URL(url), "utf8"), { mode: "transform" }), shortCircuit: true };
    return nextLoad(url, context);
  },
});

const { scanPublicGitHubRepository } = await import("../src/lib/github-scanner.ts");
const { redactSecrets } = await import("../src/lib/secret-patterns.ts");

// Synthetic, non-functional tokens built in the test. Never real credentials.
const b64 = (value) => Buffer.from(JSON.stringify(value)).toString("base64url");
const fakeJwt = (role) => `${b64({ alg: "HS256", typ: "JWT" })}.${b64({ iss: "supabase", ref: "fixtureproject", role, iat: 1700000000, exp: 2000000000 })}.${"x".repeat(43)}`;
const anonJwt = fakeJwt("anon");
const serviceJwt = fakeJwt("service_role");
const files = {
  ".gitignore": ".env*\n",
  "package.json": JSON.stringify({ dependencies: { "@supabase/supabase-js": "2.0.0" } }),
  "src/integrations/supabase/client.ts": `import { createClient } from "@supabase/supabase-js";\nconst SUPABASE_PUBLISHABLE_KEY = "${anonJwt}";\nexport const supabase = createClient("https://fixture.supabase.co", SUPABASE_PUBLISHABLE_KEY);\nconst pk = "sb_publishable_${"a".repeat(30)}";\n`,
  "src/admin.ts": `const SUPABASE_SERVICE_ROLE_KEY = "${serviceJwt}";\n`,
  "supabase/functions/sync/index.ts": `const key = "sb_secret_${"b".repeat(32)}";\n`,
};

const originalFetch = globalThis.fetch;
globalThis.fetch = async (url) => {
  const parsed = new URL(String(url));
  if (parsed.hostname === "api.github.com" && parsed.pathname.includes("/git/trees/")) return Response.json({ truncated: false, tree: Object.keys(files).map((path) => ({ path, type: "blob", size: files[path].length })) });
  if (parsed.hostname === "api.github.com" && parsed.pathname.includes("/commits/")) return Response.json({ sha: "a".repeat(40) });
  if (parsed.hostname === "api.github.com") return Response.json({ name: "fixture", full_name: "test/supabase-keys", html_url: "https://github.com/test/supabase-keys", private: false, default_branch: "main", pushed_at: "2026-11-07T10:00:00Z" });
  if (parsed.hostname === "raw.githubusercontent.com") {
    const path = Object.keys(files).find((item) => parsed.pathname.endsWith(`/${item}`));
    return path ? new Response(files[path]) : new Response("Not found", { status: 404 });
  }
  if (parsed.hostname === "api.osv.dev") return new Response("Unavailable", { status: 503 });
  throw new Error(`Unexpected fixture request: ${parsed.hostname}`);
};

try {
  const result = await scanPublicGitHubRepository("test/supabase-keys");
  const titles = result.findings.map((finding) => `${finding.file}: ${finding.title}`);
  assert.ok(titles.includes("src/admin.ts: Supabase service-role key committed"), `service-role JWT must be flagged: ${titles.join(" | ")}`);
  assert.ok(titles.includes("supabase/functions/sync/index.ts: Supabase secret key committed"), "sb_secret_ key must be flagged");
  assert.equal(result.findings.filter((finding) => finding.file === "src/admin.ts").length, 1, "service-role JWT must not be double-reported as a generic secret");
  assert.equal(result.findings.some((finding) => finding.file === "src/integrations/supabase/client.ts" && finding.category === "secrets"), false, "publishable/anon keys are public by design and must not be flagged");
  assert.equal(JSON.stringify(result).includes(serviceJwt), false, "report must never contain the key value");
  assert.equal(redactSecrets(`k=sb_secret_${"c".repeat(30)}`).includes("sb_secret_c"), false, "AI review input must redact sb_secret_ keys");
  console.log("verify-supabase-keys: ok");
} finally {
  globalThis.fetch = originalFetch;
}
