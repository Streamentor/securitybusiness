import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {registerHooks,stripTypeScriptTypes} from "node:module";
const root = new URL("../src/",import.meta.url);
const fixture = {session:null, rows:new Map(), scan:{id:"scan-a",userId:"owner",status:"completed",url:"https://example.invalid",vulnerabilities:[],createdAt:new Date()}, db:{}};
globalThis.sharingFixture=fixture;
const shim=source=>({url:`data:text/javascript,${encodeURIComponent(source)}`,shortCircuit:true});
registerHooks({resolve(s,c,next){
 if(s==="next/server")return next("next/server.js",c);
 if(s==="@/lib/db")return shim("export const prisma=globalThis.sharingFixture.db;");
 if(s==="@/lib/scanner")return shim('export class WebsiteScanError extends Error {} export const validateScanTarget=async v=>new URL(v); export const scanWebsite=async()=>({score:100,pagesScanned:1,vulnerabilities:[]});');
 if(s==="@/lib/scan-gate")return shim('export const admitWebsiteScan=async()=>({ok:true,userId:null,plan:"free",creditReserved:false});');
 if(s==="@/lib/auth")return shim("export const auth=async()=>globalThis.sharingFixture.session;");
 if(s.startsWith("@/"))return {url:new URL(`${s.slice(2)}.ts`,root).href,shortCircuit:true};
 return next(s,c);
},load(u,c,next){if(u.startsWith(root.href)&&u.endsWith(".ts"))return{format:"module",source:stripTypeScriptTypes(readFileSync(new URL(u),"utf8"),{mode:"transform"}),shortCircuit:true};return next(u,c);}});
globalThis.fetch=async()=>{throw new Error("No external requests allowed");};
fixture.db={
 $executeRawUnsafe:async(sql)=>{assert.match(sql,/CREATE TABLE IF NOT EXISTS/);return 0;},
 websiteReportAccess:{
  findUnique:async({where})=>fixture.rows.get(where.scanId)||null,
  create:async({data})=>{fixture.rows.set(data.scanId,data);return data;},
  upsert:async({where,create,update})=>{const row=fixture.rows.get(where.scanId);fixture.rows.set(where.scanId,row?{...row,...update}:create);},
 },
 user:{findUnique:async()=>({plan:"free"})},
 scan:{findUnique:async()=>({...fixture.scan}),findFirst:async({where})=>where.id===fixture.scan.id&&where.userId===fixture.scan.userId?fixture.scan:null,findMany:async()=>[],updateMany:async({where,data})=>{if(where.id===fixture.scan.id&&where.userId===fixture.scan.userId){Object.assign(fixture.scan,data);return{count:1};}return{count:0};}},
};
const access=await import("../src/lib/report-access.ts");
const report=await import("../src/app/api/scan/[id]/route.ts");
const share=await import("../src/app/api/scan/[id]/share/route.ts");
const claim=await import("../src/app/api/scan/claim/route.ts");
const base="https://scanmysaas.example";
const params={params:Promise.resolve({id:"scan-a"})};
const req=(path,method="GET",headers={},body)=>new Request(base+path,{method,headers:{...(method!=="GET"?{Origin:base}:{}),...headers},...(body?{body:JSON.stringify(body)}:{})});
assert.equal((await report.GET(req("/api/scan/scan-a"),params)).status,404,"legacy ID alone is private");
fixture.session={user:{id:"other"}};
assert.equal((await report.GET(req("/api/scan/scan-a"),params)).status,404,"another paid/logged-in account cannot guess a report");
assert.equal((await share.POST(req("/api/scan/scan-a/share","POST"),params)).status,404);
fixture.session={user:{id:"owner"}};
assert.equal((await share.POST(req("/api/scan/scan-a/share","POST",{Origin:"https://attacker.invalid"}),params)).status,403);
const first=await(await share.POST(req("/api/scan/scan-a/share","POST"),params)).json();
const token=new URL(first.url).hash.slice(7);
assert.match(token,/^[A-Za-z0-9_-]{43}$/);
assert.ok(!JSON.stringify([...fixture.rows.values()]).includes(token),"only token hash is stored");
fixture.session=null;
let response=await report.GET(req("/api/scan/scan-a","GET",{"x-report-share-token":token}),params);
assert.equal(response.status,200);assert.match(response.headers.get("cache-control"),/no-store/);
let payload=await response.json();assert.equal(payload.access.shared,true);assert.equal(payload.userId,null);assert.equal(payload.comparison,null);
assert.ok(!JSON.stringify(payload).includes("shareHash"));
assert.equal((await report.GET(req("/api/scan/scan-a?share="+token),params)).status,404,"URL query token is not accepted");
fixture.session={user:{id:"owner"}};
const second=await(await share.POST(req("/api/scan/scan-a/share","POST"),params)).json();
const secondToken=new URL(second.url).hash.slice(7);assert.notEqual(token,secondToken);
fixture.session=null;
assert.equal((await report.GET(req("/api/scan/scan-a","GET",{"x-report-share-token":token}),params)).status,404,"replacement invalidates old link");
fixture.session={user:{id:"owner"}};
assert.equal((await share.DELETE(req("/api/scan/scan-a/share","DELETE"),params)).status,200);
fixture.session=null;
assert.equal((await report.GET(req("/api/scan/scan-a","GET",{"x-report-share-token":secondToken}),params)).status,404,"revocation is enforced on server");
fixture.session={user:{id:"owner"}};
assert.equal((await report.GET(req("/api/scan/scan-a"),params)).status,200,"owner retains access after revoke");
// Anonymous access and claim require a browser proof, not a share token or report ID.
fixture.scan.userId=null;
const creator=access.prepareCreator(req("/api/scan","POST"));
assert.match(creator.cookie,/HttpOnly; SameSite=Lax/);assert.match(creator.cookie,/Secure/);
await access.recordReportCreator("scan-a",creator.hash);
const cookie=creator.cookie.split(";")[0];
fixture.session=null;
assert.equal((await report.GET(req("/api/scan/scan-a","GET",{cookie}),params)).status,200);
assert.equal((await report.GET(req("/api/scan/scan-a"),params)).status,404);
fixture.session={user:{id:"claimant"}};
assert.equal((await claim.POST(req("/api/scan/claim","POST",{}, {scanId:"scan-a"}))).status,404);
assert.equal((await claim.POST(req("/api/scan/claim","POST",{cookie,Origin:"https://evil.invalid"}, {scanId:"scan-a"}))).status,403);
const claims=await Promise.all(["claimant","claimant"].map(()=>claim.POST(req("/api/scan/claim","POST",{cookie},{scanId:"scan-a"}))));
assert.equal(claims.filter(x=>x.status===200).length,1,"compare-and-set claims only once");
assert.equal(fixture.scan.userId,"claimant");
fixture.session=null;
assert.equal((await report.GET(req("/api/scan/scan-a","GET",{cookie}),params)).status,404,"creator cookie cannot access claimed report");
// Both website scan transports bind the anonymous report to an HttpOnly proof.
fixture.session=null;
fixture.scan.userId=null;
fixture.db.scan.create=async()=>({...fixture.scan});
fixture.db.scan.update=async()=>({...fixture.scan});
fixture.db.vulnerability={createMany:async()=>({count:0})};
const scanRoute=await import("../src/app/api/scan/route.ts");
const streamRoute=await import("../src/app/api/scan/stream/route.ts");
for(const route of [scanRoute,streamRoute]){
 const response=await route.POST(req("/api/scan","POST",{"content-type":"application/json"},{url:"https://example.invalid"}));
 assert.equal(response.status,200);
 const setCookie=response.headers.get("set-cookie");assert.match(setCookie,/HttpOnly/);
 const proof=setCookie.split(";")[0];
 const data=await response.text();assert.ok(!data.includes(proof.slice(proof.indexOf("=")+1)),"creator proof never enters JSON/SSE payload");
 assert.equal((await report.GET(req("/api/scan/scan-a","GET",{cookie:proof}),params)).status,200);
 assert.equal((await report.GET(req("/api/scan/scan-a"),params)).status,404);
}
console.log("Report ownership, browser proof, token rotation/revocation and claim regression checks passed.");
