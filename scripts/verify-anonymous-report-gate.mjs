import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";
import { createHash } from "node:crypto";
const root = new URL("../src/", import.meta.url);
const shim = source => ({url: `data:text/javascript,${encodeURIComponent(source)}`, shortCircuit: true});
const token = "a".repeat(43), share = "b".repeat(43);
const hash = value => createHash("sha256").update(value).digest("hex");
const finding = (id, severity, type = "headers") => ({id, severity, type, title: `Finding ${id}`, url: `https://owned.invalid/private-${id}`, description: `evidence-${id}`, remedy: `fix-${id}`, futureEvidence: `future-${id}`});
const fixture = {session: null, plan: "free", userId: null, sql: [], accountCreates: 0, invalidProof: false, fail: false};
const findings = [finding("low", "low"), finding("high", "high"), finding("metadata", "info", "scan-meta")];
const scan = () => ({id: "fixture-scan", userId: fixture.userId, url: "https://owned.invalid", status: "completed", overallScore: 70, createdAt: new Date(), vulnerabilities: findings});
const ledger = new Map();
fixture.db = {
  $executeRawUnsafe: async (sql, ...args) => {
    if (fixture.fail) throw new Error("fixture unavailable");
    fixture.sql.push([sql, args]);
    if (sql.startsWith('INSERT INTO "ScanFunnel"')) {
      const row = ledger.get(args[0]) || {};
      if (sql.includes('"signupClickedAt"')) row.signup ??= true;
      if (sql.includes('"registeredAt"')) row.registered ??= args[1];
      if (sql.includes('"claimedAt"')) row.claimed ??= true;
      ledger.set(args[0], row);
    }
    return 1;
  },
  $queryRawUnsafe: async sql => sql.includes('FROM "ScanFunnelRollout"') ? [{startedAt: new Date("2026-11-08T12:00:00Z")}] : [{started: 4, completed: 3, signup: 2, registered: 1, claimed: 1, upgraded: 0}],
  websiteReportAccess: {findUnique: async () => ({creatorHash: fixture.invalidProof ? hash("c".repeat(43)) : hash(token), shareHash: hash(share)}), create: async () => ({})},
  user: {findUnique: async ({where}) => where.email ? null : {plan: fixture.plan}, create: async () => {fixture.accountCreates++; return {id: "new-user"};}, update: async () => ({})},
  scan: {findUnique: async () => scan(), findMany: async () => [], create: async () => scan(), update: async () => scan(), updateMany: async () => {fixture.userId = fixture.session.user.id; return {count: 1};}},
  vulnerability: {createMany: async () => ({})},
};
globalThis.anonymousGateFixture = fixture;
registerHooks({resolve(s, c, next) {
  if (s === "next/server") return next("next/server.js", c);
  if (s === "@/lib/db") return shim("export const prisma = globalThis.anonymousGateFixture.db;");
  if (s === "@/lib/auth") return shim("export const auth = async () => globalThis.anonymousGateFixture.session;");
  if (s === "bcryptjs") return shim("export const hash = async () => 'fixture-hash';");
  if (s === "@/lib/scanner") return shim(`export class WebsiteScanError extends Error {} export const validateScanTarget = async v => new URL(v); export const scanWebsite = async (url, progress) => {progress?.({step:'html',label:'Scanning /private-path...',status:'running',totalSteps:17,currentStep:10}); return {score:70,pagesScanned:1,vulnerabilities:${JSON.stringify(findings)}};};`);
  if (s === "@/lib/scan-gate") return shim("export const admitWebsiteScan = async () => ({ok:true,userId:globalThis.anonymousGateFixture.session?.user?.id || null,plan:globalThis.anonymousGateFixture.plan,creditReserved:false});");
  if (s.startsWith("@/")) return {url: new URL(`${s.slice(2)}.ts`, root).href, shortCircuit:true};
  return next(s,c);
}, load(u,c,next) {if (u.startsWith(root.href) && u.endsWith(".ts")) return {format:"module", source:stripTypeScriptTypes(readFileSync(new URL(u),"utf8"),{mode:"transform"}),shortCircuit:true}; return next(u,c);}});
globalThis.fetch = async () => {throw new Error("External calls forbidden");};
const {serializeWebsiteFindings} = await import("../src/lib/scan-remediation.ts");
const {pendingScanFrom,safeAuthRedirect} = await import("../src/lib/scan-auth-return.ts");
const {trackScanFunnel,scanFunnelMetrics} = await import("../src/lib/scan-funnel.ts");
const get = await import("../src/app/api/scan/[id]/route.ts");
const post = await import("../src/app/api/scan/route.ts");
const stream = await import("../src/app/api/scan/stream/route.ts");
const signup = await import("../src/app/api/scan/[id]/signup/route.ts");
const register = await import("../src/app/api/register/route.ts");
const claim = await import("../src/app/api/scan/claim/route.ts");
const origin = "https://scanmysaas.invalid";
const req = (path, method="GET", headers={}, body) => new Request(origin+path,{method,headers:{origin,cookie:`scan-report-creator=${token}`, ...headers},...(body?{body:JSON.stringify(body)}:{})});
const params = {params:Promise.resolve({id:"fixture-scan"})};
function assertPreview(rows) {
  assert.equal(rows.length,2,"hidden readiness metadata never leaves server");
  const full = rows.filter(row => !row.detailsLocked);
  assert.equal(full.length,1); assert.equal(full[0].id,"high");
  assert.equal(full[0].description,"evidence-high"); assert.equal(full[0].remedy,"fix-high");
  const locked = rows.find(row => row.detailsLocked);
  assert.deepEqual(Object.keys(locked).sort(),["id","title","severity","type","detailsLocked","remediationAccess"].sort());
  for (const secret of ["private-low","evidence-low","fix-low","future-low","evidence-metadata"]) assert.ok(!JSON.stringify(rows).includes(secret));
}
assertPreview(serializeWebsiteFindings(findings,"free",true));
assertPreview(serializeWebsiteFindings(findings,"pro",true));
assertPreview(serializeWebsiteFindings([...findings].reverse(),"free",true));
assert.equal(serializeWebsiteFindings([],"free",true).length,0);
const noFix = serializeWebsiteFindings(findings.map(row=>({...row,remedy:""})),"free",true);
assert.equal(noFix.filter(row=>!row.detailsLocked).length,1,"still show real evidence when no fix exists");
let res = await get.GET(req("/api/scan/fixture-scan"),params);
assert.equal(res.status,200);let data = await res.json();assert.equal(data.access.requiresAccount,true);assertPreview(data.vulnerabilities);
assertPreview((await(await post.POST(req("/api/scan","POST",{}, {url:"https://owned.invalid"}))).json()).vulnerabilities);
res = await stream.POST(req("/api/scan/stream","POST",{}, {url:"https://owned.invalid"}));
const events = await res.text();
assert.ok(!events.includes("private-path")); assert.ok(!events.includes("evidence-"));assert.ok(events.includes('"high":1'));
res = await get.GET(req("/api/scan/fixture-scan","GET",{"x-report-share-token":share}),params);
data = await res.json();assert.equal(data.access.requiresAccount,false);assert.equal(data.vulnerabilities[0].description,"evidence-low");assert.equal(data.vulnerabilities[0].remedy,"","sharing must not unlock paid remedies");
assert.equal((await get.GET(req("/api/scan/fixture-scan","GET",{cookie:"","x-report-share-token":"bad"}),params)).status,404);
fixture.session={user:{id:"owner"}};
data=await(await get.GET(req("/api/scan/fixture-scan"),params)).json();assert.equal(data.access.requiresAccount,false);assert.equal(data.vulnerabilities[0].url,"https://owned.invalid/private-low");
fixture.plan="pro";data=await(await get.GET(req("/api/scan/fixture-scan"),params)).json();assert.equal(data.vulnerabilities[0].remedy,"fix-low");
fixture.session=null;fixture.plan="free";
assert.equal((await signup.POST(req("/api/scan/fixture-scan/signup","POST",{origin:"https://evil.invalid"}),params)).status,403);
assert.equal((await signup.POST(req("/api/scan/fixture-scan/signup","POST",{cookie:""}),params)).status,404);
await Promise.all([1,2].map(()=>signup.POST(req("/api/scan/fixture-scan/signup","POST"),params)));
assert.equal(ledger.size,1);assert.equal(ledger.get("fixture-scan").signup,true);
let registered = await register.POST(req("/api/register","POST",{}, {name:"Fixture",email:"fixture@owned.invalid",password:"fixture-only",pendingScanId:"fixture-scan"}));
assert.equal(registered.status,201);assert.equal(ledger.get("fixture-scan").registered,"new-user");
const registeredEvents = fixture.sql.filter(([sql])=>sql.startsWith('INSERT INTO "ScanFunnel"') && sql.includes('"registeredAt"')).length;
fixture.invalidProof=true;
await trackScanFunnel("registered","fixture-scan","attacker",token);
assert.equal(fixture.sql.filter(([sql])=>sql.startsWith('INSERT INTO "ScanFunnel"') && sql.includes('"registeredAt"')).length,registeredEvents);
fixture.invalidProof=false;fixture.session={user:{id:"new-user"}};
res=await claim.POST(req("/api/scan/claim","POST",{}, {scanId:"fixture-scan"}));assert.equal(res.status,200);assert.equal(fixture.userId,"new-user");assert.equal(ledger.get("fixture-scan").claimed,true);
await trackScanFunnel("upgraded",undefined,"new-user");assert.ok(fixture.sql.some(([sql,args])=>sql.includes('UPDATE "ScanFunnel"')&&args[0]==="new-user"));
const metrics=await scanFunnelMetrics(new Date("2026-11-09T12:00:00Z"));assert.equal(metrics.partial,true);assert.equal(metrics.before.signup,null);assert.equal(metrics.before.registered,null);assert.equal(metrics.after.started,4);
fixture.fail=true;fixture.userId=null;
registered=await register.POST(req("/api/register","POST",{}, {name:"Fixture",email:"fixture2@owned.invalid",password:"fixture-only",pendingScanId:"fixture-scan"}));assert.equal(registered.status,201,"telemetry failure cannot fail a real registration");
assert.equal(pendingScanFrom("?scan=oauth-scan",null),"oauth-scan");assert.equal(pendingScanFrom("", "stored-scan"),"stored-scan");assert.equal(pendingScanFrom("?scan=https://evil.invalid",null),null);
assert.equal(safeAuthRedirect("//evil.invalid"),"/dashboard");assert.equal(safeAuthRedirect("/scan/fixture-scan"),"/scan/fixture-scan");
// OAuth only records new accounts after user creation; browser state is cleared after successful claim.
const oauth = readFileSync(new URL("../src/lib/auth.ts",import.meta.url),"utf8");
assert.ok(oauth.indexOf('trackScanFunnel("registered"') > oauth.indexOf('const newUser = await prisma.user.create'));
assert.ok(oauth.indexOf('trackScanFunnel("registered"') < oauth.indexOf('user.id = existingUser.id'));
const login = readFileSync(new URL("../src/app/login/page.tsx",import.meta.url),"utf8");assert.match(login,/if \(claimed\?\.ok\) sessionStorage.removeItem/);
console.log("Anonymous report gate, shared access, OAuth return and funnel checks passed.");
