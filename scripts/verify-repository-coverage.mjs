import assert from "node:assert/strict";
import "./scan-test-hook.mjs";
import { fixtureArchive } from "./fixture-repo-archive.mjs";
const { scanPublicGitHubRepository } = await import("../src/lib/github-scanner.ts");
const { queryKnownVulnerabilities } = await import("../src/lib/osv.ts");
const originalFetch = globalThis.fetch;
let pushedAt = "2026-09-06T10:00:00Z";
let treeReads = 0;
let unavailableFiles = false;
let osvAvailable = false;
const SHA = "f".repeat(40);
const files = [
  { path: ".gitignore", content: ".env*\n" },
  { path: "package.json", content: "{}" },
  ...Array.from({ length: 80 }, (_, index) => ({ path: 'src/file-' + index + '.ts', content: "export const safe = 1;" })),
];

// Use only synthetic fixture responses. Never request a real repository or URL.
globalThis.fetch = async (url) => {
  const parsed = new URL(String(url));
  if (parsed.pathname.includes("/commits/")) return Response.json({ sha: SHA });
  if (parsed.pathname.includes("/tarball/")) return unavailableFiles ? new Response(null, { status: 503 }) : fixtureArchive(files);
  if (parsed.hostname === "api.github.com" && parsed.pathname.includes("/git/trees/")) {
    treeReads += 1;
    return Response.json({ truncated: false, tree: [
      { path: ".gitignore", type: "blob", size: 8 },
      { path: "package.json", type: "blob", size: 10 },
      { path: "yarn.lock", type: "blob", size: 200 },
      { path: "large.ts", type: "blob", size: 400_000 },
      ...Array.from({ length: 80 }, (_, index) => ({ path: `src/file-${index}.ts`, type: "blob", size: 20 })),
    ] });
  }
  if (parsed.hostname === "api.github.com") return Response.json({ name: "fixture", full_name: "test/fixture", html_url: "https://github.com/test/fixture", private: false, default_branch: "main", pushed_at: pushedAt });
  if (parsed.hostname === "api.osv.dev") return osvAvailable ? Response.json({ results: [{}] }) : new Response("Unavailable", { status: 503 });
  throw new Error(`Unexpected fixture request: ${parsed.hostname}`);
};

try {
  const result = await scanPublicGitHubRepository("test/fixture");
  assert.equal(result.filesScanned, 82);
  assert.equal(result.coverage.candidateFiles, 83, "coverage includes the oversized supported file");
  assert.equal(result.coverage.filesSkipped, 1);
  assert.equal(result.truncated, true, "hitting a source-file limit must mark the scan incomplete");
  assert.equal(result.findings.some((finding) => finding.title === "JavaScript dependencies have no scanned lockfile"), false, "Yarn lockfile existence is known even though its content is not supported");

  await scanPublicGitHubRepository("test/fixture");
  assert.equal(treeReads, 1, "an unchanged repository can reuse a bounded cached report");
  pushedAt = "2026-09-06T10:01:00Z";
  await scanPublicGitHubRepository("test/fixture");
  assert.equal(treeReads, 2, "a push after a fix must invalidate the cached report");

  unavailableFiles = true;
  await assert.rejects(scanPublicGitHubRepository("test/unavailable"), /No supported repository files could be read/, "a total fetch failure must not produce a reassuring score");

  const dependency = { ecosystem: "npm", name: "fixture", version: "1.0.0", file: "package-lock.json", line: 1 };
  const unavailable = await queryKnownVulnerabilities([dependency]);
  assert.equal(unavailable.status, "unavailable");
  assert.equal(unavailable.dependenciesChecked, 0, "an OSV outage must not claim dependency versions were checked");
  osvAvailable = true;
  const available = await queryKnownVulnerabilities([dependency]);
  assert.equal(available.status, "checked");
  assert.equal(available.dependenciesChecked, 1, "a successful advisory response must count the checked version");
} finally {
  globalThis.fetch = originalFetch;
}

console.log("Repository coverage regression checks passed.");
