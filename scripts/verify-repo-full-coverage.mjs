import assert from "node:assert/strict";
import "./scan-test-hook.mjs";
import { fixtureArchive } from "./fixture-repo-archive.mjs";

const { scanGitHubRepository } = await import("../src/lib/github-scanner.ts");
const sha = "a".repeat(40);
const source = Array.from({ length: 3000 }, (_, index) => ({
  path: "src/file-" + index + ".ts",
  content: index === 2499 ? "const fixture = 'sb_secret_" + "x".repeat(32) + "';" : "export const sample = 1;",
}));
source.push({ path: "src/api/large.ts", content: " ".repeat(400_000) });
source.push({ path: "node_modules/vendor.ts", content: "ignored" });
let archives = 0, downloads = 0;
const originalFetch = globalThis.fetch;
globalThis.fetch = async (input, init) => {
  const url = new URL(input);
  if (url.pathname.includes("/git/trees/")) return Response.json({ truncated: false, tree: source.map((file) => ({ path: file.path, type: "blob", size: Buffer.byteLength(file.content) })) });
  if (url.pathname.endsWith("/tarball/" + sha)) {
    archives++;
    assert.equal(new Headers(init.headers).get("authorization"), "Bearer synthetic-installation-token");
    return new Response(null, { status: 302, headers: { location: "https://codeload.github.com/fixture/secure-download" } });
  }
  if (url.hostname === "codeload.github.com") {
    downloads++;
    assert.equal(new Headers(init.headers).has("authorization"), false, "installation token must not follow the redirect");
    return fixtureArchive(source);
  }
  assert.equal(url.href, "https://api.github.com/repos/example/fixture");
  return Response.json({ name: "fixture", full_name: "example/fixture", private: true, default_branch: "main" });
};
try {
  const result = await scanGitHubRepository("example/fixture@" + sha, { accessToken: "synthetic-installation-token" });
  assert.equal(archives, 1);
  assert.equal(downloads, 1);
  assert.equal(result.coverage.candidateFiles, 3001);
  assert.equal(result.filesScanned, 3000);
  assert.equal(result.coverage.filesSkipped, 1);
  assert.deepEqual(result.coverage.skippedHighRiskFiles, ["src/api/large.ts"]);
  assert.ok(result.findings.some((finding) => finding.file === "src/file-2499.ts" && finding.category === "secrets"));
  assert.ok(!JSON.stringify(result).includes("x".repeat(32)), "no literal credential in the report");
} finally { globalThis.fetch = originalFetch; }
console.log("Full archive rule coverage and skipped-file checks passed.");
