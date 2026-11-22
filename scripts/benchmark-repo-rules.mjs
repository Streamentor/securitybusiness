import "./scan-test-hook.mjs";

// Pass an existing read-only GitHub token via the environment. No file contents,
// findings, signed download URLs, or package coordinates leave this process.
const [repository] = process.argv.slice(2);
if (!repository || !process.env.SCAN_BENCHMARK_TOKEN) throw new Error("Specify a pinned repository and an existing GitHub token.");
const { scanGitHubRepository } = await import("../src/lib/github-scanner.ts");
const realFetch = globalThis.fetch;
globalThis.fetch = (url, init) => new URL(url).hostname === "api.osv.dev" ? Promise.resolve(new Response(null, { status: 503 })) : realFetch(url, init);
const start = performance.now();
const stages = {};
const result = await scanGitHubRepository(repository, {
  accessToken: process.env.SCAN_BENCHMARK_TOKEN,
  onStage: (stage) => { stages[stage] = Math.round(performance.now() - start); },
});
console.log(JSON.stringify({
  eligible: result.coverage.candidateFiles, rulesChecked: result.filesScanned,
  skipped: result.coverage.filesSkipped, skippedByReason: result.coverage.skippedByReason, bytesRead: result.bytesScanned, totalBlobs: result.filesInRepository,
  routes: result.routes?.length, peakRssMiB: Math.round(process.resourceUsage().maxRSS / 1024),
  elapsedMs: Math.round(performance.now() - start), stages,
}, null, 2));
