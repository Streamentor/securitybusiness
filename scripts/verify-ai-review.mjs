import assert from "node:assert/strict";
import { readFileSync } from "node:fs";
import { registerHooks, stripTypeScriptTypes } from "node:module";

// Every HTTP and DB operation below is a synthetic fixture. No credentials loaded.
const fixture = {session: {user: {id: "user-a"}}, user: {plan: "starter", role: "user"}, enabled: true, charged: 0, updates: [], job: null};
globalThis.aiFixture = fixture;
const sourceRoot = new URL("../src/", import.meta.url);
const shim = (source) => ({url: `data:text/javascript,${encodeURIComponent(source)}`, shortCircuit: true});
registerHooks({
  resolve(specifier, context, nextResolve) {
    if (specifier === "server-only") return shim("export {}");
    if (specifier === "next/server") return nextResolve("next/server.js", context);
    if (specifier === "@/lib/db") return shim("export const prisma = new Proxy({}, {get: (_,key) => globalThis.aiFixture.db[key]});");
    if (specifier === "@/lib/auth") return shim("export const auth = async () => globalThis.aiFixture.session;");
    if (specifier === "@/lib/repo-store") return shim("export const ensureRepoTables = async () => {};");
    if (specifier.startsWith("@/")) return {url: new URL(`${specifier.slice(2)}.ts`,sourceRoot).href, shortCircuit:true};
    return nextResolve(specifier,context);
  },
  load(url,context,nextLoad) {
    if (url.startsWith(sourceRoot.href) && url.endsWith(".ts")) return {format:"module",source:stripTypeScriptTypes(readFileSync(new URL(url),"utf8"),{mode:"transform"}),shortCircuit:true};
    return nextLoad(url,context);
  },
});
const ai = await import("../src/lib/ai-review.ts");
const store = await import("../src/lib/ai-review-store.ts");
const {redactSecrets} = await import("../src/lib/secret-patterns.ts");
const files = [{path:"src/app/api/invoices/route.ts",content:'export async function GET(req) {\n  const id = req.query.id;\n  return db.invoice.findUnique({where: {id}});\n}'}];
const finding = {file:files[0].path,line:3,title:"Invoice ownership is not verified",severity:"high",category:"authorization",evidence:"return db.invoice.findUnique({where: {id}});",why:"The handler reads an invoice selected by the caller without checking the owner.",fix:"Require a session and include its user ID in the invoice query.",confidence:"high"};
const valid = ai.validateAIFindings({findings:[finding]},files);
assert.equal(valid.length,1); assert.equal(valid[0].source,"ai");
for (const data of [{}, {findings:"bad"}, {findings:[{...finding,severity:"urgent"}]}, {findings:[{...finding,line:"3"}]}, {findings:[{...finding,extra:true}]}]) assert.throws(()=>ai.validateAIFindings(data,files),/schema/);
for (const row of [{...finding,file:".env"},{...finding,line:0},{...finding,line:999},{...finding,evidence:"invented code"}]) assert.equal(ai.validateAIFindings({findings:[row]},files).length,0);
assert.equal(ai.validateAIFindings({findings:[finding]},files,valid).length,0,"deduplicate nearby matching rule findings");
const secret = "sk-"+"x".repeat(36);
const secretFile = [{path:"src/app/api/key/route.ts",content:`const OPENAI_API_KEY = "${secret}";`}];
const redacted = ai.validateAIFindings({findings:[{...finding,file:secretFile[0].path,line:1,evidence:secretFile[0].content,why:`Credential ${secret}`,title:`Leaked ${secret}`,fix:`Rotate ${secret}`} ]},secretFile);
assert.equal(redacted.length,1); assert.ok(!JSON.stringify(redacted).includes(secret));
for (const canary of ["ghp_"+"a".repeat(36),"AKIA"+"A".repeat(16),"postgres://foo:bar@db.invalid/db","eyJhbGciOiJIUzI1NiJ9.abcdefghijk.lmnopqrstuv"]) assert.ok(!redactSecrets(canary).includes(canary));
assert.equal(ai.eligibleReviewFile("src/generated/client.ts"),false);
assert.equal(ai.eligibleReviewFile("tests/auth.ts"),false);
assert.equal(ai.eligibleReviewFile(".env"),false);
assert.equal(ai.scoreReviewedFindings([{...valid[0],confidence:"low"}]).score,100);
assert.equal(ai.scoreReviewedFindings(valid).score,94);
assert.equal(ai.scoreReviewedFindings([{...valid[0],confidence:"medium"}]).score,97);
assert.equal(ai.scoreReviewedFindings([{...valid[0],source:"rule"}]).score,87);
assert.equal(ai.scoreReviewedFindings(Array.from({length:15}, () => ({...valid[0],severity:"critical"}))).score,80,"unverified AI aggregate penalty is capped at twenty");
assert.equal(ai.scoreReviewedFindings([{...valid[0],source:"rule"}, ...Array.from({length:15},()=>({...valid[0],severity:"critical"}))]).score,67,"rule penalty is not capped");
assert.equal(ai.resultForEntitlement({findings:Array.from({length:15},()=>({...valid[0],severity:"critical"})),score:0,risk:"critical"},true).score,80,"old paid results are rescored on read");
const free = ai.resultForEntitlement({findings:valid,score:94,risk:"moderate",aiReview:{status:"completed",note:"secret details"}},false);
assert.equal(free.findings.length,0); assert.equal(free.score,100); assert.match(free.aiReview.note,/1 potential logic issue/); assert.ok(!JSON.stringify(free).includes(finding.evidence));

const savedEnv = {...process.env};
Object.assign(process.env,{OPENAI_API_KEY:"fixture-not-a-key",OPENAI_REVIEW_MODEL:"gpt-5.6-luna"});
delete process.env.AI_REVIEW_ENABLED;
const originalFetch = globalThis.fetch;
let calls=0, apiFails=false, lastBody, reserved=0, settled=0;
const meter={reserve:async(tokens)=>{reserved=tokens;return true;},settle:async(_reserved,charged)=>{settled=charged;}};
const reply = () => Response.json({status:"completed",usage:{input_tokens:250,output_tokens:100},output:[{type:"message",content:[{type:"output_text",text:JSON.stringify({findings:[finding]})}]}]});
globalThis.fetch=async(url,init)=>{
  assert.equal(String(url),"https://api.openai.com/v1/responses","no unmocked network destination"); calls++; lastBody=JSON.parse(init.body);
  assert.equal(lastBody.store,false); assert.equal(lastBody.model,"gpt-5.6-luna"); assert.equal(lastBody.text.format.strict,true); assert.equal(lastBody.text.format.type,"json_schema");
  assert.ok(!init.body.includes(secret),"credentials are redacted before transmission");
  if(apiFails) return new Response("fixture error",{status:503});
  return reply();
};
try {
  const outcome=await ai.reviewRepositoryWithAI({user:{plan:"starter"},files:[...files,...secretFile],findings:[]},meter);
  assert.equal(outcome.status,"completed"); assert.equal(outcome.findings.length,1); assert.equal(outcome.inputTokens,250); assert.equal(outcome.outputTokens,100); assert.equal(settled,350); assert.ok(reserved>350);
  const before=calls;
  await ai.reviewRepositoryWithAI({user:{plan:"free"},files,findings:[]},meter); assert.equal(calls,before,"free plans never call OpenAI");
  await ai.reviewRepositoryWithAI({user:{plan:"pro",enabled:false},files,findings:[]},meter); assert.equal(calls,before,"opt-out prevents transmission");
  const capped=await ai.reviewRepositoryWithAI({user:{plan:"starter"},files,findings:[]},{...meter,reserve:async()=>false}); assert.equal(capped.status,"skipped"); assert.match(capped.note,/monthly token budget/); assert.equal(calls,before);
  apiFails=true;
  const failed=await ai.reviewRepositoryWithAI({user:{plan:"starter"},files,findings:[]},meter); assert.equal(failed.status,"failed"); assert.match(failed.note,/rule-based checks completed/i); assert.equal(settled,reserved,"ambiguous usage retains reservation");
  apiFails=false;
  const callsBeforeDeadline=calls;
  const noTime=await ai.reviewRepositoryWithAI({user:{plan:"pro"},files,findings:[],timeoutMs:10},meter);
  assert.equal(noTime.status,"skipped");assert.equal(calls,callsBeforeDeadline);
  process.env.VERCEL_ENV="preview";
  await ai.reviewRepositoryWithAI({user:{plan:"pro"},files,findings:[]},meter);assert.equal(calls,callsBeforeDeadline,"preview never sends repository contents");
  delete process.env.VERCEL_ENV;
  const budget=ai.reviewConfig({plan:"pro"});
  const manyFiles=Array.from({length:20},(_,i)=>({path:`src/app/api/route${i}.ts`,content:"export const sample = 1;\n".repeat(180)}));
  const batches=ai.prepareReviewBatches(manyFiles,budget);
  assert.ok(batches.length<=2 && batches.length>0);
  assert.ok(batches.reduce((sum,b)=>sum+Buffer.byteLength(JSON.stringify(b.body),"utf8"),0)<=budget.inputBudget);
  let concurrent=0,maxConcurrent=0;
  globalThis.fetch=async()=>{concurrent++;maxConcurrent=Math.max(maxConcurrent,concurrent);await new Promise(resolve=>setTimeout(resolve,5));concurrent--;return Response.json({status:"completed",usage:{input_tokens:100,output_tokens:30},output:[{type:"message",content:[{type:"output_text",text:'{"findings":[]}'}]}]});};
  await ai.reviewRepositoryWithAI({user:{plan:"pro"},files:manyFiles,findings:[]},meter);
  assert.ok(maxConcurrent<=2);

  // Atomic shared monthly budget, including two concurrent callers and cap-zero.
  fixture.db={
    $queryRaw:async(strings,...values)=>{assert.match(strings.join("?"),/ON CONFLICT[\s\S]*WHERE/); const tokens=values[2],cap=values[5];assert.equal(values[3],tokens);assert.equal(values[4],tokens); if(fixture.charged+tokens>cap)return[]; fixture.charged+=tokens;return[{userId:"user-a"}];},
    $executeRaw:async(_strings,...values)=>{fixture.charged-=values[0];return 1;},
    aIReviewPreference:{findUnique:async()=>({enabled:fixture.enabled}),upsert:async(args)=>{fixture.enabled=args.update.enabled;}},
    user:{findUnique:async()=>fixture.user},
    repoScan:{updateMany:async()=>{if(fixture.job.status!=="queued")return {count:0};fixture.job.status="running";return {count:1};},findUnique:async()=>fixture.job,findFirst:async(args)=>{assert.equal(args.where.userId,"user-a");assert.equal(args.where.id,"job-1");return fixture.job;},update:async(args)=>{fixture.updates.push(args.data);return Object.assign(fixture.job,args.data);}},
  };
  assert.equal(await store.reserveAIReviewTokens("user-a","2026-11",1,0),false);
  assert.deepEqual(await Promise.all([store.reserveAIReviewTokens("user-a","2026-11",60,100),store.reserveAIReviewTokens("user-a","2026-11",60,100)]),[true,false]);
  await store.settleAIReviewTokens("user-a","2026-11",60,25); assert.equal(fixture.charged,25);
  assert.equal(await store.reserveAIReviewTokens("user-a","2026-11",70,100),true);assert.equal(fixture.charged,95);

  // Run the actual background job with fixture GitHub responses and a failing AI API.
  const sha="a".repeat(40);
  fixture.charged=0;
  fixture.job={id:"job-1",userId:"user-a",repository:"owner/app",requestedRef:null,installationId:null,status:"queued",createdAt:new Date(),startedAt:null};
  globalThis.fetch=async(url)=>{
    const target=new URL(String(url));
    if(target.hostname==="api.openai.com"){calls++;return new Response("fixture failure",{status:503});}
    if(target.pathname==="/repos/owner/app")return Response.json({name:"app",full_name:"owner/app",html_url:"https://github.com/owner/app",private:false,default_branch:"main",pushed_at:"t"});
    if(target.pathname.includes("/commits/"))return Response.json({sha});
    if(target.pathname.includes("/git/trees/"))return Response.json({truncated:false,tree:[{path:files[0].path,type:"blob",size:100}]});
    if(target.hostname==="raw.githubusercontent.com")return new Response(files[0].content);
    if(target.hostname==="api.osv.dev")return Response.json({results:[]});
    throw new Error("Unexpected fixture destination");
  };
  const jobs=await import("../src/lib/repo-scan-jobs.ts");
  await jobs.runRepoScanJob("job-1");
  assert.equal(fixture.job.status,"completed"); assert.match(fixture.job.result.aiReview.note,/rule-based checks completed/i); assert.ok(fixture.updates.some((r)=>r.stage==="ai-review"));
  assert.ok(!JSON.stringify(fixture.job).includes(files[0].content),"raw source is never stored");
  const publicRoute=await import("../src/app/api/repo-scan/route.ts");
  const {NextRequest:PublicRequest}=await import("next/server.js");
  const beforePublic=calls;
  const publicResponse=await publicRoute.POST(new PublicRequest("https://fixture.invalid/api/repo-scan",{method:"POST",headers:{"content-type":"application/json"},body:JSON.stringify({repository:"owner/app",authorized:true})}));
  const publicBody=await publicResponse.json();assert.equal(publicResponse.status,200);assert.equal(publicBody.aiReview.status,"locked");assert.equal(publicBody.findings.some(f=>f.source==="ai"),false);assert.equal(calls,beforePublic,"anonymous public scans never call OpenAI");

  // Actual owner-only GET response rechecks current plan after a downgrade.
  fixture.job.result.findings.push(...valid); fixture.job.result.aiReview={status:"completed",note:"private AI note"};
  fixture.user={plan:"free",role:"user"};
  const {GET}=await import("../src/app/api/repo-scans/[id]/route.ts");
  const {NextRequest}=await import("next/server.js");
  let response=await GET(new NextRequest("https://fixture.invalid/api/repo-scans/job-1"),{params:Promise.resolve({id:"job-1"})});
  const body=await response.json(); assert.equal(response.status,200); assert.equal(body.result.findings.some((f)=>f.source==="ai"),false); assert.ok(!JSON.stringify(body).includes("private AI note")); assert.equal(body.aiModel,null);
  // Opt-out endpoint uses the session user, validates Origin, and rejects injected IDs.
  fixture.user={plan:"pro",role:"user"};
  const preferences=await import("../src/app/api/repo-scans/preferences/route.ts");
  response=await preferences.PATCH(new NextRequest("https://fixture.invalid/api/repo-scans/preferences",{method:"PATCH",headers:{origin:"https://evil.invalid","content-type":"application/json"},body:JSON.stringify({enabled:false})}));assert.equal(response.status,403);
  response=await preferences.PATCH(new NextRequest("https://fixture.invalid/api/repo-scans/preferences",{method:"PATCH",headers:{origin:"https://fixture.invalid","content-type":"application/json"},body:JSON.stringify({enabled:false,userId:"other"})}));assert.equal(response.status,400);
  response=await preferences.PATCH(new NextRequest("https://fixture.invalid/api/repo-scans/preferences",{method:"PATCH",headers:{origin:"https://fixture.invalid","content-type":"application/json"},body:JSON.stringify({enabled:false})}));assert.equal(response.status,200);assert.equal(fixture.enabled,false);
  fixture.user={plan:"free",role:"user"};
  fixture.job.status="running";fixture.job.startedAt=new Date(Date.now()-10*60_000);
  response=await GET(new NextRequest("https://fixture.invalid/api/repo-scans/job-1"),{params:Promise.resolve({id:"job-1"})});
  const staleBody=await response.json();assert.equal(staleBody.result.findings.some(f=>f.source==="ai"),false,"stale-job responses also redact AI details after downgrade");
  fixture.session=null;
  response=await GET(new NextRequest("https://fixture.invalid/api/repo-scans/job-1"),{params:Promise.resolve({id:"job-1"})}); assert.equal(response.status,401);
} finally {globalThis.fetch=originalFetch; for(const key of Object.keys(process.env)) if(!(key in savedEnv))delete process.env[key]; Object.assign(process.env,savedEnv);}
console.log("AI review verified: schema/evidence, references, secrets, deduplication, entitlement, usage reservations, opt-out, Responses contract and job fallback.");
