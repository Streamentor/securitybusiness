import assert from "node:assert/strict";

const scanner = await import("../src/lib/scanner.ts");
const prompts = await import("../src/lib/fix-prompt.ts");
const repoRules = await import("../src/lib/repo-security-rules.ts");

const strongHeaders = new Headers({
  "content-security-policy": "default-src 'self'; script-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'",
  "strict-transport-security": "max-age=31536000",
  "x-content-type-options": "nosniff",
  "referrer-policy": "strict-origin-when-cross-origin",
  "permissions-policy": "camera=(), microphone=()",
});
const strongFindings = scanner.checkSecurityHeaders("https://example.com", strongHeaders);
assert.equal(strongFindings.some((finding) => finding.title.includes("X-XSS-Protection")), false, "deprecated X-XSS-Protection must not be required");

const httpFindings = scanner.checkSecurityHeaders("http://example.com", new Headers());
assert.equal(httpFindings.some((finding) => finding.title.includes("HSTS")), false, "HSTS must not be required on an HTTP response");

const missingCsp = httpFindings.find((finding) => finding.title === "Missing Content-Security-Policy Header");
assert.equal(missingCsp?.severity, "medium", "missing CSP alone is a hardening signal, not proof of a high-severity exploit");
assert.match(missingCsp.description, /absence alone does not prove exploitable/);
assert.match(missingCsp.remedy, /Report-Only does not block/);
assert.match(missingCsp.remedy, /Reporting-Endpoints:/, "the starter must explain how to receive reports");
assert.match(missingCsp.remedy, /report-to csp-endpoint/);
assert.match(missingCsp.remedy, /Content-Security-Policy-Report-Only:/);
assert.match(missingCsp.remedy, /key: 'Content-Security-Policy-Report-Only'/);
assert.match(missingCsp.remedy, /add_header Content-Security-Policy-Report-Only /);
assert.doesNotMatch(missingCsp.remedy, /Content-Security-Policy:|key: ['"]Content-Security-Policy['"]|add_header Content-Security-Policy\s/, "no starter snippet may enable enforcement before tailoring and testing");
assert.match(missingCsp.remedy, /nonces per request, or hashes/);
assert.match(missingCsp.remedy, /dynamic rendering/);
assert.match(missingCsp.remedy, /can break Next\.js inline scripts/);
assert.match(missingCsp.remedy, /Only after testing, publish the tailored policy/);
const monitoringOnly = scanner.checkSecurityHeaders("https://example.com", new Headers({ "content-security-policy-report-only": "default-src 'self'; report-to csp-endpoint" })).find((finding) => finding.title === missingCsp.title);
assert.equal(monitoringOnly?.severity, "medium", "a monitoring-only policy must not be mistaken for enforced protection");
assert.match(monitoringOnly.description, /Report-Only policy is present/);
assert.equal(strongFindings.some((finding) => finding.title === missingCsp.title), false, "an enforced policy must not be reported as missing");

const styleInline = scanner.analyzeCSP("https://example.com", "default-src 'self'; script-src 'self'; style-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'");
assert.equal(styleInline.some((finding) => finding.title === "CSP Allows Unsafe Inline Scripts"), false, "style-src unsafe-inline must not be attributed to script-src");

const scriptInline = scanner.analyzeCSP("https://example.com", "default-src 'self'; script-src 'self' 'unsafe-inline'; object-src 'none'; base-uri 'self'; form-action 'self'");
assert.equal(scriptInline.some((finding) => finding.title === "CSP Allows Unsafe Inline Scripts"), true, "script-src unsafe-inline must be detected");

const getForm = scanner.checkHTMLSecurity("https://example.com", '<form method="get"><input name="q"></form><a href="https://other.example" target="_blank">Open</a>');
assert.equal(getForm.some((finding) => finding.type === "csrf"), false, "GET forms must not be reported as missing CSRF protection");
assert.equal(getForm.some((finding) => finding.title.includes("noopener")), false, "modern implicit noopener behavior must not be reported as missing");

const postForm = scanner.checkHTMLSecurity("https://example.com", '<form method="post"><input name="email"></form>');
assert.equal(postForm.some((finding) => finding.type === "csrf"), true, "state-changing forms without a visible token should remain a review signal");

const nextPayload = scanner.checkHTMLSecurity("https://example.com", '<script>self.__next_f.push([1,"documentation mentions element.innerHTML = value"])</script>');
assert.equal(nextPayload.some((finding) => finding.type === "xss"), false, "serialized Next.js payload text must not be treated as executable sink evidence");

assert.equal(scanner.matchesExpectedSensitiveFile("/.env", "text/plain", "<html>fallback page</html>"), false, "SPA fallbacks must not look like exposed environment files");
assert.equal(scanner.matchesExpectedSensitiveFile("/.env", "text/plain", "DATABASE_URL=postgres://example"), true, "environment-file signatures must still be detected");

// All HTTP responses here are local fixtures; these tests never contact a target.
const originalFetch = globalThis.fetch;
try {
  let calls = 0;
  globalThis.fetch = async (_url, options) => {
    calls += 1;
    assert.ok(options.dispatcher, "scanner requests must use the socket-level public-address guard");
    return new Response("Access denied", { status: 403, headers: { "content-type": "text/html" } });
  };
  await assert.rejects(scanner.scanWebsite("https://203.0.113.1"), scanner.WebsiteScanError, "an unreadable website must not receive a score or count as one scanned page");
  assert.equal(calls, 1, "an unreadable target must stop before additional probes");
  globalThis.fetch = async () => new Response("<html><body>Hello</body></html>", { headers: { "content-type": "text/html" } });
  assert.deepEqual(await scanner.discoverPages("https://203.0.113.1"), ["https://203.0.113.1"], "a reachable HTML page must still be discovered");
  globalThis.fetch = async () => new Response('{"ok":true}', { headers: { "content-type": "application/json" } });
  assert.deepEqual(await scanner.discoverPages("https://203.0.113.1"), [], "a JSON-only endpoint must not count as an HTML page");
} finally {
  globalThis.fetch = originalFetch;
}

const socketLookup = scanner.createPublicLookup(async () => [{ address: "203.0.113.1", family: 4 }]);
const resolveSocket = (lookup, options = {}) => new Promise((resolve, reject) => lookup("fixture.invalid", options, (error, address) => error ? reject(error) : resolve(address)));
assert.equal(await resolveSocket(socketLookup), "203.0.113.1", "a public destination must retain normal socket lookup behavior");
assert.deepEqual(await resolveSocket(socketLookup, { all: true }), [{ address: "203.0.113.1", family: 4 }], "multi-address lookup must return only the validated addresses");
for (const address of ["127.0.0.1", "10.0.0.1", "169.254.169.254", "::1", "fd00::1"]) {
  const reboundLookup = scanner.createPublicLookup(async () => [{ address, family: address.includes(":") ? 6 : 4 }]);
  await assert.rejects(resolveSocket(reboundLookup), /public addresses/, "a DNS rebind to a private destination must be rejected at socket resolution");
}
const mixedLookup = scanner.createPublicLookup(async () => [{ address: "203.0.113.1", family: 4 }, { address: "127.0.0.1", family: 4 }]);
await assert.rejects(resolveSocket(mixedLookup, { all: true }), /public addresses/, "a mixed public/private DNS answer must be rejected before address fallback");

const prompt = prompts.buildFixPrompt({ surface: "deployed website", title: "Missing CSP", severity: "high", category: "headers", target: "https://example.com", evidence: "Header absent" });
assert.match(prompt, /Treat it as a hypothesis/);
assert.match(prompt, /true positive, partial signal, or false positive/);
assert.match(prompt, /Do not expose secrets/);

const agentFindings = repoRules.analyzeAgentSecurityFile({
  path: ".claude/settings.json",
  content: JSON.stringify({
    permissions: { allow: ["Bash(*)"] },
    mcpServers: {
      remote: { url: "http://mcp.example.com", command: "npx", args: ["-y", "@example/server"], env: { API_TOKEN: "not-a-real-secret-for-tests" } },
    },
  }),
});
assert.equal(agentFindings.some((finding) => finding.title === "AI agent has unrestricted shell permission"), true, "broad agent shell permissions must be detected");
assert.equal(agentFindings.some((finding) => finding.title === "Remote MCP server uses unencrypted HTTP"), true, "remote plaintext MCP transport must be detected");
assert.equal(agentFindings.some((finding) => finding.title === "MCP package is executed without a pinned version"), true, "unpinned MCP packages must be detected");
assert.equal(agentFindings.some((finding) => finding.title === "Literal credential stored in MCP configuration"), true, "literal MCP credentials must be detected without returning their value");
assert.equal(JSON.stringify(agentFindings).includes("not-a-real-secret-for-tests"), false, "agent findings must redact literal credential values");

const urlCanary = "synthetic-secret-canary";
for (const url of [
  `http://mcp.example.com/?token=${urlCanary}`,
  `http://${urlCanary}-user:${urlCanary}-password@mcp.example.com/${urlCanary}-path?token=${urlCanary}-query#${urlCanary}-fragment`,
  `http://[invalid/${urlCanary}`,
]) {
  const findings = repoRules.analyzeAgentSecurityFile({ path: ".mcp.json", content: JSON.stringify({ mcpServers: { remote: { url } } }) });
  assert.equal(findings.some((finding) => finding.title === "Remote MCP server uses unencrypted HTTP"), true, "plaintext transport must still be flagged after URL redaction");
  assert.equal(JSON.stringify(findings).includes(urlCanary), false, "MCP URL credentials, paths, queries, and fragments must never enter findings");
  if (url.includes("mcp.example.com")) assert.match(findings[0].description, /http:\/\/mcp\.example\.com without TLS/, "only the sanitized origin is relevant evidence");
  for (const finding of findings) {
    const fixPrompt = prompts.buildFixPrompt({ surface: "source repository", title: finding.title, severity: finding.severity, category: finding.category, target: finding.file, repository: "owner/repo", evidence: finding.description, remediation: finding.remedy });
    assert.equal(fixPrompt.includes(urlCanary), false, "a copied single-finding prompt must not expose MCP URL credentials");
  }
  const auditPrompt = prompts.buildRepoAuditPrompt({ repository: "owner/repo", score: 87, findings: findings.map((finding) => ({ ...finding, target: finding.file, evidence: finding.description, remediation: finding.remedy })) });
  assert.equal(auditPrompt.includes(urlCanary), false, "a copied full-audit prompt must not expose MCP URL credentials");
}

const cleanLocalMcp = repoRules.analyzeAgentSecurityFile({ path: ".mcp.json", content: JSON.stringify({ mcpServers: { local: { url: "http://localhost:3000", command: "npx", args: ["-y", "@example/server@1.2.3"] } } }) });
assert.equal(cleanLocalMcp.some((finding) => finding.title.includes("unencrypted HTTP")), false, "localhost MCP transport must not be reported as remote plaintext traffic");
assert.equal(cleanLocalMcp.some((finding) => finding.title.includes("without a pinned version")), false, "exact MCP package versions must not be reported as unpinned");

const dependencyFiles = [
  { path: "package.json", content: JSON.stringify({ dependencies: { next: "15.0.0" } }) },
  { path: "package-lock.json", content: JSON.stringify({ packages: { "": { name: "demo", version: "1.0.0" }, "node_modules/next": { version: "15.0.0" }, "node_modules/@scope/pkg": { version: "2.1.0" } } }) },
];
const inventory = repoRules.extractDependencyInventory(dependencyFiles);
assert.deepEqual(inventory.dependencies.map((dependency) => `${dependency.name}@${dependency.version}`), ["next@15.0.0", "@scope/pkg@2.1.0"]);
assert.equal(inventory.manifests, 1);

const osvPayload = repoRules.buildOsvQueryBatch(inventory.dependencies);
assert.deepEqual(osvPayload.queries[0], { package: { ecosystem: "npm", name: "next" }, version: "15.0.0" });
const osvResults = repoRules.normalizeOsvBatchResponse({ results: [{ vulns: [{ id: "GHSA-test-0000" }] }, {}] }, inventory.dependencies);
assert.equal(osvResults?.[0].ids[0], "GHSA-test-0000");
assert.equal(repoRules.normalizeOsvBatchResponse({ wrong: [] }, inventory.dependencies), null, "unexpected OSV responses must fail closed at the integration boundary");
assert.equal(repoRules.normalizeOsvBatchResponse({ results: [null, {}] }, inventory.dependencies), null, "malformed advisory records must not be interpreted as zero vulnerabilities");
assert.equal(repoRules.normalizeOsvBatchResponse({ results: [{ vulns: [{ id: 42 }] }, {}] }, inventory.dependencies), null, "malformed advisory IDs must not be interpreted as valid matches");

const hygieneFindings = repoRules.analyzeDependencyHygiene([{ path: "package.json", content: JSON.stringify({ dependencies: { demo: "latest" } }) }]);
assert.equal(hygieneFindings.some((finding) => finding.title === "JavaScript dependencies have no scanned lockfile"), true);
assert.equal(hygieneFindings.some((finding) => finding.title === "Dependency uses a floating version"), true);
for (const lockfile of ["yarn.lock", "pnpm-lock.yaml", "bun.lockb", "package-lock.json"]) {
  const findings = repoRules.analyzeDependencyHygiene([{ path: "package.json", content: "{}" }], ["package.json", lockfile]);
  assert.equal(findings.some((finding) => finding.title === "JavaScript dependencies have no scanned lockfile"), false, `a present but unread ${lockfile} must not be reported as missing`);
}
assert.equal(repoRules.analyzeDependencyHygiene([{ path: "package.json", content: "{}" }], ["package.json"], false).length, 0, "a truncated repository tree cannot prove a lockfile is absent");

const fullPrompt = prompts.buildRepoAuditPrompt({ repository: "owner/repo", score: 72, findings: [{ title: "Unpinned MCP package", severity: "medium", category: "agent-security", target: ".mcp.json:4", evidence: "Package has no exact version", remediation: "Pin it" }] });
assert.match(fullPrompt, /true positive, partial signal, duplicate, or false positive/);
assert.match(fullPrompt, /credential exposure first/);
assert.match(fullPrompt, /Do not expose secrets/);

console.log("Scanner regression rules passed.");
