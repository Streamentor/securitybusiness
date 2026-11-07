import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createHash } from "node:crypto";
import { registerHooks, stripTypeScriptTypes } from "node:module";

const sourceRoot = new URL("../src/", import.meta.url);
const shim = (source) => ({ url: `data:text/javascript,${encodeURIComponent(source)}`, shortCircuit: true });
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "next/server") return shim("export const NextRequest = Request; export const NextResponse = { json: Response.json.bind(Response) };");
    if (specifier === "@/lib/db") return shim("export const prisma = globalThis.scanRemediationFixture.db;");
    if (specifier === "@/lib/auth") return shim("export const auth = async () => globalThis.scanRemediationFixture.session;");
    if (specifier === "@/lib/scanner") return shim("export class WebsiteScanError extends Error {} export const validateScanTarget = async value => new URL(value); export const scanWebsite = async () => ({score:40,pagesScanned:1,vulnerabilities:globalThis.scanRemediationFixture.findings});");
    if (specifier.startsWith("@/")) return { url: new URL(`${specifier.slice(2)}.ts`, sourceRoot).href, shortCircuit: true };
    return nextResolve(specifier, context);
  },
  load(url, context, nextLoad) {
    if (url.startsWith(sourceRoot.href) && url.endsWith(".ts")) return { format: "module", source: stripTypeScriptTypes(readFileSync(new URL(url), "utf8"), { mode: "transform" }), shortCircuit: true };
    return nextLoad(url, context);
  },
});

const { applyWebsiteRemediationAccess } = await import("../src/lib/scan-remediation.ts");
const makeFinding = (id, type, severity, remedy, title = id) => ({ id, type, severity, remedy, title, url: "https://example.com", description: `Fixture evidence for ${id}` });
const findings = [
  makeFinding("low", "headers", "low", "locked-low-steps"),
  makeFinding("metadata", "scan-meta", "critical", "metadata-steps"),
  makeFinding("informational", "seo", "info", "informational-steps"),
  makeFinding("legacy", "headers", "critical", "legacy-steps", "Missing X-XSS-Protection Header"),
  makeFinding("empty", "sensitive-file", "critical", "  "),
  makeFinding("high", "xss", "high", "locked-high-steps"),
  makeFinding("critical-header", "headers", "critical", "locked-critical-header-steps"),
  makeFinding("exposed-file", "sensitive-file", "critical", "included-exposed-file-steps"),
  makeFinding("invalid-severity", "sensitive-file", "toString", "invalid-severity-steps"),
];
const before = structuredClone(findings);
const assertOneFreeFix = (payload) => {
  const supplied = payload.filter((finding) => finding.remedy.trim());
  assert.equal(supplied.length, 1, "free reports must serialize exactly one actionable remediation");
  assert.equal(supplied[0].id, "exposed-file", "prioritize severity, then direct exposure before same-severity hardening");
  assert.equal(supplied[0].remediationAccess, "free");
  for (const finding of findings.filter((finding) => finding.id !== "exposed-file" && finding.remedy.trim())) {
    assert.equal(JSON.stringify(payload).includes(finding.remedy), false, "locked steps must be absent from the response, not visually blurred");
  }
};

for (const plan of [undefined, null, "free", "anonymous", "admin", { plan: "pro" }]) assertOneFreeFix(applyWebsiteRemediationAccess(findings, plan));
assertOneFreeFix(applyWebsiteRemediationAccess([...findings].reverse(), "free"));
assert.equal(applyWebsiteRemediationAccess([findings[7], findings[7]], "free").filter((finding) => finding.remedy).length, 1, "even repeated input references must not unlock multiple entries");
assert.equal(applyWebsiteRemediationAccess([findings[1], findings[2], findings[3], findings[4], findings[8]], "free").some((finding) => finding.remediationAccess === "free"), false, "metadata, informational/invalid severities, suppressed legacy checks and empty steps must not consume the free fix");
for (const plan of ["starter", "pro"]) {
  const paid = applyWebsiteRemediationAccess(findings, plan);
  assert.equal(paid.filter((finding) => finding.remedy.trim()).length, findings.filter((finding) => finding.remedy.trim()).length, "paid plans retain all existing implementation steps");
  assert.equal(paid.some((finding) => finding.remediationAccess === "free" || finding.remediationAccess === "locked"), false);
}
assert.deepEqual(findings, before, "redacting a free response must not mutate stored findings or a later paid response");

// Exercise both real route functions against isolated auth/DB/scanner fixtures.
// No environment secrets, database connections, scans or credit writes are used.
const fixture = {
  findings,
  session: null,
  plan: "free",
  credits: 1,
  existingDomain: false,
  reservations: 0,
  creations: 0,
};
const report = () => ({ id: "fixture-scan", url: "https://example.com", status: "completed", userId: null, overallScore: 40, vulnerabilities: fixture.findings });
fixture.db = {
  $executeRawUnsafe: async () => 0,
  websiteReportAccess: {findUnique: async () => ({creatorHash: createHash("sha256").update("a".repeat(43)).digest("hex")}), create: async () => ({})},
  user: {
    findUnique: async () => ({ plan: fixture.plan, credits: fixture.credits }),
    updateMany: async () => { fixture.reservations += 1; return { count: 1 }; },
    update: async () => ({}),
  },
  scan: {
    findUnique: async () => report(),
    findFirst: async () => fixture.existingDomain ? { id: "earlier-scan" } : null,
    findMany: async () => fixture.priorScans ?? (fixture.existingDomain ? [{ userId: null, url: "https://example.com/", createdAt: new Date() }] : []),
    create: async () => { fixture.creations += 1; return { id: "fixture-scan" }; },
    update: async () => report(),
  },
  vulnerability: { createMany: async () => ({ count: findings.length }) },
};
globalThis.scanRemediationFixture = fixture;
try {
  const { GET } = await import("../src/app/api/scan/[id]/route.ts");
  const { POST } = await import("../src/app/api/scan/route.ts");
  const getReport = () => GET(new Request("https://scanmysaas.example/api/scan/fixture-scan?plan=pro&findingId=low", {headers: {cookie: `scan-report-creator=${"a".repeat(43)}`}}), { params: Promise.resolve({ id: "fixture-scan" }) });
  const postScan = () => POST(new Request("https://scanmysaas.example/api/scan", { method: "POST", headers: { "Content-Type": "application/json" }, body: JSON.stringify({ url: "https://example.com", plan: "pro", canViewRemedies: true, findingId: "low" }) }));

  assertOneFreeFix((await (await getReport()).json()).vulnerabilities);
  assertOneFreeFix((await (await postScan()).json()).vulnerabilities);
  assert.equal(fixture.reservations, 0, "anonymous scan credit behavior must remain unchanged");

  fixture.session = { user: { id: "fixture-owner" } };
  assertOneFreeFix((await (await getReport()).json()).vulnerabilities);
  assertOneFreeFix((await (await postScan()).json()).vulnerabilities);
  assert.equal(fixture.reservations, 1, "an authenticated free scan still reserves its existing credit");
  for (const plan of ["starter", "pro"]) {
    fixture.plan = plan;
    for (const request of [getReport, postScan]) {
      const response = await request();
      assert.equal(response.status, 200);
      const data = await response.json();
      assert.equal(data.vulnerabilities.filter((finding) => finding.remedy.trim()).length, findings.filter((finding) => finding.remedy.trim()).length, "server-paid entitlements must retain all fixes on both API paths");
    }
  }
  fixture.plan = "free";
  assertOneFreeFix((await (await getReport()).json()).vulnerabilities);
  fixture.credits = 0;
  const creationsBefore = fixture.creations;
  assert.equal((await postScan()).status, 403, "the included remediation must not silently grant another scan credit");
  assert.equal(fixture.creations, creationsBefore);
  fixture.credits = 1;
  fixture.existingDomain = true;
  fixture.session = null;
  assert.equal((await postScan()).status, 403, "the existing free-domain scan restriction must remain enforced for anonymous scans");
  fixture.session = { user: { id: "fixture-owner" } };
  fixture.credits = 0;
  fixture.priorScans = [{ userId: "fixture-owner", url: "https://example.com/", createdAt: new Date() }];
  const reservationsBefore = fixture.reservations;
  const verification = await postScan();
  assert.equal(verification.status, 200, "the owner gets one free verification rescan within 7 days");
  assertOneFreeFix((await verification.json()).vulnerabilities);
  assert.equal(fixture.reservations, reservationsBefore, "the verification rescan must not spend a credit");
  fixture.priorScans = [...fixture.priorScans, { userId: "fixture-owner", url: "https://example.com/", createdAt: new Date() }];
  assert.equal((await postScan()).status, 403, "only one free verification rescan is allowed");
} finally {
  delete globalThis.scanRemediationFixture;
}

console.log("Free remediation entitlement and route regression checks passed.");
