import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import vm from "node:vm";
import ts from "typescript";

const require = createRequire(import.meta.url);

// Execute the real guard and route against isolated auth/DB fixtures. No network,
// database connection, production credentials or user records are accessed.
function loadTypeScript(path, dependencies) {
  const filename = new URL(path, import.meta.url).pathname;
  const source = readFileSync(filename, "utf8");
  const { outputText } = ts.transpileModule(source, { compilerOptions: { module: ts.ModuleKind.CommonJS, target: ts.ScriptTarget.ES2022 } });
  const exports = {};
  vm.runInNewContext(outputText, {
    exports,
    Date,
    require(name) {
      if (Object.hasOwn(dependencies, name)) return dependencies[name];
      throw new Error(`Unexpected dependency: ${name}`);
    },
  }, { filename });
  return exports;
}

const secretCanary = "https://private.example/path?token=METRICS_SECRET_CANARY";
const metrics = loadTypeScript("../src/lib/activation-metrics.ts", {});

async function runCase(session, storedRole) {
  let roleReads = 0;
  let aggregateReads = 0;
  const prisma = {
    user: {
      async findUnique() { roleReads += 1; return storedRole ? { role: storedRole } : null; },
      async groupBy(query) {
        aggregateReads += 1;
        const scans = query.where.scans?.some;
        if (scans?.status === "completed") return [{ referrerSource: "google", _count: { _all: 1 } }];
        if (scans) return [{ referrerSource: "google", _count: { _all: 2 } }, { referrerSource: secretCanary, _count: { _all: 1 } }];
        return [{ referrerSource: "google", _count: { _all: 3 } }, { referrerSource: secretCanary, _count: { _all: 2 } }];
      },
    },
    scan: {
      async groupBy() { aggregateReads += 1; return [{ status: "completed", _count: { _all: 2 } }, { status: secretCanary, _count: { _all: 1 } }]; },
      async count() { aggregateReads += 1; return 2; },
    },
  };
  const admin = loadTypeScript("../src/lib/admin.ts", { "@/lib/auth": { auth: async () => session }, "@/lib/db": { prisma } });
  const route = loadTypeScript("../src/app/api/admin/metrics/route.ts", {
    "next/server": require("next/server"),
    "@/lib/admin": admin,
    "@/lib/db": { prisma },
    "@/lib/activation-metrics": metrics,
  });
  const response = await route.GET();
  return { response, body: await response.json(), roleReads, aggregateReads };
}

for (const [session, role, expectedRoleReads] of [
  [null, "admin", 0],
  [{ user: { id: "fixture-user", role: "admin" } }, "user", 1],
  [{ user: { id: "deleted-fixture", role: "admin" } }, null, 1],
]) {
  const result = await runCase(session, role);
  assert.equal(result.response.status, 403, "anonymous, non-admin and stale accounts must be denied even if the session claims admin");
  assert.equal(result.roleReads, expectedRoleReads);
  assert.equal(result.aggregateReads, 0, "no aggregate product query may run before DB-verified admin authorization");
  assert.equal(result.response.headers.get("cache-control"), "private, no-store");
}

const admin = await runCase({ user: { id: "fixture-admin", role: "user" } }, "admin");
assert.equal(admin.response.status, 200, "the stored admin role is authoritative");
assert.equal(admin.response.headers.get("cache-control"), "private, no-store");
assert.ok(admin.aggregateReads > 0);
const serialized = JSON.stringify(admin.body);
assert.ok(!serialized.includes("METRICS_SECRET_CANARY"), "arbitrary source/status values must not leak in aggregate output");
assert.ok(!serialized.includes("fixture-admin"), "account identifiers must not appear in metrics");
assert.equal(admin.body.current.registrations, 5);
const other = admin.body.current.channelCohorts.find((row) => row.channel === "other");
assert.equal(other.registrations, 2, "unrecognized source counts must be retained in the safe other bucket");
assert.equal(admin.body.current.websiteScans.other, 1);
assert.equal(metrics.percent(0, 0), null, "no sample is unknown, not a zero-percent conversion");
assert.equal(admin.body.current.endExclusive, admin.body.observedAt);
assert.equal(admin.body.previous.endExclusive, admin.body.current.start);
assert.equal(new Date(admin.body.current.endExclusive) - new Date(admin.body.current.start), 30 * 86400000);

console.log("Activation metrics authorization and privacy checks passed.");
