import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { createRequire } from "node:module";
import vm from "node:vm";
import ts from "typescript";

const require = createRequire(import.meta.url);
function load(path, dependencies) {
  const filename = new URL(path, import.meta.url).pathname;
  const { outputText } = ts.transpileModule(readFileSync(filename, "utf8"), {
    compilerOptions: {
      module: ts.ModuleKind.CommonJS,
      target: ts.ScriptTarget.ES2022,
    },
  });
  const exports = {};
  vm.runInNewContext(
    outputText,
    {
      exports,
      Date,
      URL,
      require(name) {
        if (Object.hasOwn(dependencies, name)) return dependencies[name];
        throw new Error(`Unexpected dependency ${name}`);
      },
    },
    { filename },
  );
  return exports;
}
const metrics = load("../src/lib/registration-metrics.ts", {});
for (const range of [7, 30, 90])
  assert.equal(metrics.registrationDays(String(range)), range);
assert.equal(metrics.registrationDays(null), 30);
for (const range of ["0", "100000", "7.0", "7 OR 1=1", "30 "])
  assert.equal(metrics.registrationDays(range), null);
function rows(days) {
  return Array.from({ length: days * 2 }, (_, i) => ({
    date: new Date(Date.UTC(2026, 9, 1 + i)).toISOString().slice(0, 10),
    count: i === 0 ? 2 : i === days ? 5 : 0,
  }));
}
const summary = metrics.summarizeRegistrations(
  rows(7),
  7,
  "2026-10-14T12:00:00Z",
);
assert.equal(summary.current.total, 5);
assert.equal(summary.previous.total, 2);
assert.equal(summary.changePercent, 150);
assert.equal(summary.series.length, 7);
assert.equal(summary.series[1].count, 0, "zero days remain in the series");
assert.ok(
  summary.previous.end < summary.current.start,
  "periods cannot overlap",
);
const zero = metrics.summarizeRegistrations(
  rows(7).map((r) => ({ ...r, count: 0 })),
  7,
  "2026-10-14T12:00:00Z",
);
assert.equal(
  zero.changePercent,
  null,
  "zero previous denominator is not an invented 0% or Infinity",
);
assert.throws(() => metrics.summarizeRegistrations([], 7, "now"));
assert.throws(() =>
  metrics.summarizeRegistrations(
    rows(7).map((r) => ({ ...r, count: -1 })),
    7,
    "now",
  ),
);

async function run({
  session = { user: { id: "fixture-admin", role: "user" } },
  role = "admin",
  days = "7",
  fail = false,
} = {}) {
  let reads = 0,
    query = "",
    parameters = [];
  const prisma = {
    user: {
      async findUnique() {
        return role ? { role } : null;
      },
    },
    async $queryRaw(strings, ...values) {
      reads++;
      query = strings.join("?");
      parameters = values;
      if (fail) throw new Error("PRIVATE_DATABASE_CANARY");
      return rows(Number(days));
    },
  };
  const admin = load("../src/lib/admin.ts", {
    "@/lib/auth": { auth: async () => session },
    "@/lib/db": { prisma },
  });
  const route = load("../src/app/api/admin/registrations/route.ts", {
    "next/server": require("next/server"),
    "@/lib/admin": admin,
    "@/lib/db": { prisma },
    "@/lib/registration-metrics": metrics,
  });
  const response = await route.GET(
    new Request(
      `https://fixture.invalid/api/admin/registrations?days=${encodeURIComponent(days)}`,
    ),
  );
  return { response, body: await response.json(), reads, query, parameters };
}
for (const options of [
  { session: null },
  { role: "user", session: { user: { id: "stale", role: "admin" } } },
  { role: null },
]) {
  const r = await run(options);
  assert.equal(r.response.status, 403);
  assert.equal(r.reads, 0);
  assert.equal(r.response.headers.get("cache-control"), "private, no-store");
}
for (const range of ["0", "999999", "30 OR 1=1"]) {
  const r = await run({ days: range });
  assert.equal(r.response.status, 400);
  assert.equal(r.reads, 0);
}
for (const days of ["7", "30", "90"]) {
  const r = await run({ days });
  assert.equal(r.response.status, 200);
  assert.equal(r.reads, 1);
  assert.equal(r.body.series.length, Number(days));
  assert.equal(r.response.headers.get("cache-control"), "private, no-store");
  assert.match(r.query, /generate_series/);
  assert.match(r.query, /LEFT JOIN counts/);
  assert.match(r.query, /"createdAt" AT TIME ZONE 'UTC'/);
  assert.ok(r.parameters.includes("Europe/Belgrade"));
  assert.ok(r.parameters.includes(Number(days) * 2 - 1));
  assert.ok(!/email|hashedPassword|stripe|SELECT \*/i.test(r.query));
  assert.ok(!JSON.stringify(r.body).includes("fixture-admin"));
}
const failure = await run({ fail: true });
assert.equal(failure.response.status, 500);
assert.ok(!JSON.stringify(failure.body).includes("PRIVATE_DATABASE_CANARY"));
assert.ok(
  !Object.hasOwn(failure.body, "series"),
  "failed queries must not look like zero registrations",
);
console.log(
  "Registration ranges, aggregates, privacy, DB-verified admin access and failure states passed.",
);
