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


const { scanPublicGitHubRepository, parseGitHubRepository, riskScore } = await import("../src/lib/github-scanner.ts");
const originalFetch = globalThis.fetch;
const SHA = "a".repeat(40);
const rawRefs = new Set();
const treeRefs = [];
const rawPaths = [];

// URL parsing keeps the ref; branch names with "/" are tried longest-first.
assert.deepEqual(parseGitHubRepository("https://github.com/o/r").refCandidates, []);
assert.deepEqual(parseGitHubRepository("https://github.com/o/r/tree/codex/feature-x").refCandidates, ["codex/feature-x", "codex"]);
assert.deepEqual(parseGitHubRepository(`https://github.com/o/r/commit/${SHA}`).refCandidates, [SHA]);
assert.deepEqual(parseGitHubRepository("o/r@v1.2.3").refCandidates, ["v1.2.3"]);
assert.throws(() => parseGitHubRepository("o/r@feature/../../x"), /not valid/);

// Risk ranking prefers auth/API/payment code over UI and tests.
assert.ok(riskScore("src/app/api/stripe/webhook/route.ts") > riskScore("src/components/Button.tsx"));
assert.ok(riskScore("middleware.ts") > riskScore("src/lib/utils.ts"));

// Use only synthetic fixture responses. Never request a real repository or URL.
globalThis.fetch = async (url) => {
  const parsed = new URL(String(url));
  if (parsed.hostname === "api.github.com" && parsed.pathname.includes("/commits/")) {
    const ref = decodeURIComponent(parsed.pathname.split("/commits/")[1]);
    if (ref === "codex/feature-x") return Response.json({ sha: SHA });
    return new Response("Not found", { status: 404 });
  }
  if (parsed.hostname === "api.github.com" && parsed.pathname.includes("/git/trees/")) {
    treeRefs.push(decodeURIComponent(parsed.pathname.split("/git/trees/")[1]));
    return Response.json({ truncated: false, tree: [
      ...Array.from({ length: 90 }, (_, index) => ({ path: `src/components/c-${index}.tsx`, type: "blob", size: 10 })),
      { path: "src/app/api/stripe/webhook/route.ts", type: "blob", size: 9000 },
      { path: "src/lib/auth.ts", type: "blob", size: 8000 },
      { path: "middleware.ts", type: "blob", size: 7000 },
    ] });
  }
  if (parsed.hostname === "api.github.com") return Response.json({ name: "r", full_name: "o/r", html_url: "https://github.com/o/r", private: false, default_branch: "main", pushed_at: "2026-11-07T10:00:00Z" });
  if (parsed.hostname === "raw.githubusercontent.com") {
    const [, , , ref, ...path] = parsed.pathname.split("/");
    rawRefs.add(decodeURIComponent(ref));
    rawPaths.push(path.map(decodeURIComponent).join("/"));
    return new Response("export const ok = 1;");
  }
  if (parsed.hostname === "api.osv.dev") return new Response("Unavailable", { status: 503 });
  throw new Error(`Unexpected fixture request: ${parsed.hostname}`);
};

try {
  const result = await scanPublicGitHubRepository("https://github.com/o/r/tree/codex/feature-x");
  assert.equal(result.repository.ref, "codex/feature-x", "the branch from the URL must be scanned, not the default branch");
  assert.equal(result.repository.commitSha, SHA);
  assert.deepEqual(treeRefs, [SHA], "the tree must be read by commit SHA");
  assert.deepEqual([...rawRefs], [SHA], "every raw file must be read from the same commit");
  for (const file of ["src/app/api/stripe/webhook/route.ts", "src/lib/auth.ts", "middleware.ts"]) {
    assert.ok(rawPaths.includes(file), `high-risk file ${file} must be selected before tiny UI files`);
  }
  assert.equal(result.filesScanned, 60);
  assert.equal(result.coverage.skippedHighRiskFiles.length, 0, "no high-risk file should be skipped in this fixture");
  await assert.rejects(scanPublicGitHubRepository("https://github.com/o/r/tree/missing-branch"), /was not found/);
} finally {
  globalThis.fetch = originalFetch;
}

console.log("Repository ref pinning and risk selection checks passed.");
