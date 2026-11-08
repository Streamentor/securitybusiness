import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";
const root = new URL("../src/", import.meta.url);
const shim = source => ({url:`data:text/javascript,${encodeURIComponent(source)}`,shortCircuit:true});
const fixture = {saved:new Map(),updates:[], refunds:0, fail:false, diagnosticDown:false};
fixture.db = {
 $executeRawUnsafe:async sql=>{assert.match(sql,/CREATE TABLE IF NOT EXISTS/);return 0;},
 websiteScanDiagnostic:{upsert:async ({where,create,update})=>{if(fixture.diagnosticDown)throw new Error('unavailable');fixture.saved.set(where.scanId,fixture.saved.has(where.scanId)?{...fixture.saved.get(where.scanId),...update}:create);},findMany:async({where})=>[...fixture.saved.values()].filter(row=>where.scanId.in.includes(row.scanId))},
 scan:{create:async()=>({id:'fixture-scan'}),update:async({data})=>{fixture.updates.push(data);return {id:'fixture-scan',...data,vulnerabilities:[]};},updateMany:async({data})=>{fixture.updates.push(data);return {count:1};}},
 user:{update:async({data})=>{if(data.credits?.increment)fixture.refunds++;}},
};
globalThis.websiteDiagnosticsFixture=fixture;
registerHooks({resolve(s,c,next){
 if(s==='dns')return shim('export const resolveTxt=(hostname,callback)=>callback(null,[]);');
 if(s==='next/server')return next('next/server.js',c);
 if(s==='@/lib/db')return shim('export const prisma=globalThis.websiteDiagnosticsFixture.db;');
 if(s==='@/lib/auth')return shim('export const auth=async()=>globalThis.websiteDiagnosticsFixture.session || null;');
 if(s==='@/lib/scan-gate')return shim('export const admitWebsiteScan=async()=>({ok:true,userId:"fixture-user",plan:"free",creditReserved:true});');
 if(s==='@/lib/scanner')return shim(`import {websiteFailure} from '${new URL('../src/lib/website-scan-messages.mjs',import.meta.url).href}'; export class WebsiteScanError extends Error {constructor(){super('untrusted upstream secret');this.failure=websiteFailure('blocked',403,'Cloudflare');}} export const validateScanTarget=async v=>new URL(v); export const scanWebsite=async()=>{if(globalThis.websiteDiagnosticsFixture.fail)throw new WebsiteScanError();return {score:84,pagesScanned:1,vulnerabilities:[],coverage:{partial:true,pagesDiscovered:2,pagesAnalyzed:1,note:'One page could not be read.'}}};`);
 if(s.startsWith('@/'))return{url:new URL(s.slice(2)+'.ts',root).href,shortCircuit:true};return next(s,c);
},load(u,c,next){if(u.startsWith(root.href)&&u.endsWith('.ts'))return{format:'module',source:stripTypeScriptTypes(readFileSync(new URL(u),'utf8'),{mode:'transform'}),shortCircuit:true};return next(u,c);}});
globalThis.fetch=async()=>{throw new Error('External calls forbidden');};
const scanner=await import('../src/lib/scanner.ts');
const base='https://203.0.113.1';
// All fetches are fixture responses; even TLS calls are avoided by failing before checks.
for (const [response,code] of [
 [()=>new Response('blocked',{status:403,headers:{'cf-ray':'fixture'}}),'blocked'],
 [()=>new Response('challenge',{status:200,headers:{'content-type':'text/html','cf-mitigated':'challenge'}}),'blocked'],
 [()=>new Response('challenge',{status:200,headers:{'content-type':'text/html','x-vercel-mitigated':'challenge','x-vercel-id':'fixture'}}),'blocked'],
 [()=>new Response('{}',{headers:{'content-type':'application/json'}}),'not-html'],
 [()=>new Response('',{headers:{'content-type':'text/html'}}),'empty-html'],
 [()=>new Response('failed',{status:503}),'http-error'],
 [()=>new Response(null,{status:302,headers:{location:'https://other.invalid/parked'}}),'redirect'],
]) {
 globalThis.fetch=async()=>response();
 await assert.rejects(scanner.scanWebsite(base),e=>e instanceof scanner.WebsiteScanError && e.failure.code===code);
}
for (const [cause,code] of [['ENOTFOUND','dns'],['CERT_HAS_EXPIRED','tls'],['ETIMEDOUT','timeout'],['ECONNREFUSED','network']]) {
 globalThis.fetch=async()=>{throw Object.assign(new Error('fetch failed'),{cause:{code:cause}});};
 await assert.rejects(scanner.scanWebsite(base),e=>e.failure.code===code);
}
let diagnostic;
globalThis.fetch=async()=>new Response(new ReadableStream({start(c){c.enqueue(new TextEncoder().encode('a'));}}));
assert.equal(await scanner.safeFetch(base,{timeout:10,onFailure:d=>{diagnostic=d;}}),null);assert.equal(diagnostic.code,'timeout');
globalThis.fetch=async()=>new Response('body',{headers:{'content-length':String(scanner.MAX_SCAN_RESPONSE_BYTES+1)}});
await scanner.safeFetch(base,{onFailure:d=>{diagnostic=d;}});assert.equal(diagnostic.code,'response-too-large');
// Retain an actual page snapshot and continue when one linked page is unavailable.
let rootCalls=0, partial=false;const snapshots=new Map();
globalThis.fetch=async url=>{if(url===base){rootCalls++;return new Response('<html><a href="/blocked">one</a><script>el.innerHTML = location.hash</script></html>',{headers:{'content-type':'text/html'}});}return new Response('denied',{status:403});};
const pages=await scanner.discoverPages(base,25,p=>snapshots.set(p.url,p),()=>{},()=>{partial=true;});
assert.deepEqual(pages,[base]);assert.equal(rootCalls,1);assert.equal(partial,true);assert.ok(scanner.checkHTMLSecurity(base,snapshots.get(base).html).some(f=>f.type==='xss'));
// Full real scanner pipeline: the initial HTML succeeds, all later root reads
// are blocked. This used to throw at the second per-page analysis request.
const httpBase='http://203.0.113.1'; let reads=0;
globalThis.fetch=async url=>{if(url===httpBase && reads++===0)return new Response('<html><a href="/blocked">one</a><script>el.innerHTML = location.hash</script></html>',{headers:{'content-type':'text/html'}});return new Response('denied',{status:403});};
let result=await scanner.scanWebsite(httpBase);
assert.equal(result.pagesScanned,1);assert.equal(result.coverage.partial,true);assert.ok(result.vulnerabilities.some(f=>f.type==='xss'),'retain the evidence from the successful first response');
// A scan reaching its request budget keeps already read evidence and reports partial.
const originalNow=Date.now;let clock=0;Date.now=()=>clock;reads=0;
try {
 globalThis.fetch=async url=>{if(url===httpBase && reads++===0){clock=90001;return new Response('<html><script>el.innerHTML = location.hash</script></html>',{headers:{'content-type':'text/html'}});}throw new Error('request must not run after budget');};
 result=await scanner.scanWebsite(httpBase);assert.equal(result.pagesScanned,1);assert.equal(result.coverage.partial,true);assert.ok(result.vulnerabilities.some(f=>f.type==='xss'));
} finally {Date.now=originalNow;}
const direct=await import('../src/app/api/scan/route.ts');const stream=await import('../src/app/api/scan/stream/route.ts');
const request=path=>new Request('https://scanmysaas.invalid'+path,{method:'POST',headers:{'content-type':'application/json'},body:JSON.stringify({url:base})});
let response=await direct.POST(request('/api/scan'));let data=await response.json();assert.equal(response.status,200);assert.equal(data.coverage.partial,true);assert.equal(data.totalPages,2);assert.equal(data.pagesScanned,1);assert.equal(fixture.saved.get('fixture-scan').partial,true);
fixture.fail=true;response=await direct.POST(request('/api/scan'));data=await response.json();assert.equal(response.status,422);assert.equal(data.code,'blocked');assert.match(data.error,/403.*Cloudflare/);assert.ok(!data.error.includes('secret'));assert.equal(fixture.saved.get('fixture-scan').failureCode,'blocked');assert.ok(fixture.updates.at(-1).completedAt instanceof Date);assert.equal(fixture.refunds,1);
response=await stream.POST(request('/api/scan/stream'));const events=await response.text();assert.match(events,/"code":"blocked"/);assert.ok(!events.includes('secret'));assert.equal(fixture.refunds,2);
fixture.fail=false;fixture.diagnosticDown=true;response=await direct.POST(request('/api/scan'));assert.equal(response.status,200,'diagnostics failure must not discard a completed result');
// A partial report must not turn unread findings into resolved findings.
fixture.diagnosticDown=false;fixture.session={user:{id:'fixture-user'}};
fixture.db.user.findUnique=async()=>({plan:'free'});
fixture.db.websiteReportAccess={findUnique:async()=>null};
fixture.db.scan.findUnique=async()=>({id:'fixture-scan',url:base,userId:'fixture-user',status:'completed',overallScore:84,createdAt:new Date(),vulnerabilities:[]});
fixture.db.scan.findMany=async()=>{throw new Error('A partial scan must not build a comparison');};
fixture.saved.set('fixture-scan',{scanId:'fixture-scan',partial:true,coverageNote:'Fixture partial scan'});
const report=await import('../src/app/api/scan/[id]/route.ts');
response=await report.GET(new Request('https://scanmysaas.invalid/api/scan/fixture-scan'),{params:Promise.resolve({id:'fixture-scan'})});
assert.equal(response.status,200);data=await response.json();assert.equal(data.comparison,null);assert.equal(data.diagnostic.partial,true);
console.log('Website failure classification, snapshot retention, partial coverage, persistence and refunds passed.');
