// Explicit manual benchmark, NOT a fixture test. Never run from CI or verification scripts.
import {readFileSync,writeFileSync,mkdirSync} from "node:fs";
import {registerHooks,stripTypeScriptTypes} from "node:module";
if(!process.argv.includes("--allow-real-api") || !process.env.OPENAI_API_KEY) throw new Error("Manual benchmark requires --allow-real-api and a local API key.");
const root=new URL("../src/",import.meta.url);
registerHooks({resolve(specifier,context,nextResolve){if(specifier==="server-only")return{url:"data:text/javascript,export{}",shortCircuit:true};if(specifier.startsWith("@/"))return{url:new URL(`${specifier.slice(2)}.ts`,root).href,shortCircuit:true};return nextResolve(specifier,context);},load(url,context,nextLoad){if(url.startsWith(root.href)&&url.endsWith(".ts"))return{format:"module",source:stripTypeScriptTypes(readFileSync(new URL(url),"utf8"),{mode:"transform"}),shortCircuit:true};return nextLoad(url,context);}});
const {scanGitHubRepository,riskScore}=await import("../src/lib/github-scanner.ts");
const {redactSecrets}=await import("../src/lib/secret-patterns.ts");
const {reviewRepositoryWithAI}=await import("../src/lib/ai-review.ts");
// The handoff authorizes only Stefan-owned repositories. Keep this list explicit.
const requested=process.argv.filter(arg=>arg.startsWith("--repo=")).map(arg=>arg.slice(7));
const repositories=requested.length?requested:["Streamentor/securitybusiness","stefanautomateed/securitybusiness"];
if(repositories.some(repo=>!/^(?:Streamentor|stefanautomateed)\/[A-Za-z0-9_.-]+$/.test(repo))) throw new Error("Only explicitly authorized Stefan-owned repositories may be benchmarked.");
mkdirSync("benchmark-results",{recursive:true});
const measurements=[];
for(const repository of repositories){
 let files=[];
 const start=Date.now();
 const rules=await scanGitHubRepository(repository,{accessToken:process.env.GITHUB_SCANNER_TOKEN,onFilesLoaded:(loaded)=>{files=[...loaded].sort((a,b)=>riskScore(b.path)-riskScore(a.path));}});
 const aiStart=Date.now();
 const originalFetch=globalThis.fetch;
 const proposed=[];
 globalThis.fetch=async(url,options)=>{
   const response=await originalFetch(url,options);
   if(String(url)==="https://api.openai.com/v1/responses" && response.ok){
     const data=await response.clone().json();
     const text=(data.output||[]).filter(item=>item.type==="message").flatMap(item=>item.content||[]).filter(part=>part.type==="output_text").map(part=>part.text||"").join("");
     try {proposed.push(...JSON.parse(redactSecrets(text)).findings||[]);} catch { /* invalid output stays a failed review */ }
   }
   return response;
 };
 const result=await reviewRepositoryWithAI({user:{plan:"pro"},files,findings:rules.findings},{reserve:async()=>true,settle:async()=>{}});
 globalThis.fetch=originalFetch;
 // Usage is real; cost is a conservative estimate at verified Standard prices,
 // treating all input as a cache write (1.25x) until invoice details are available.
 const price=process.env.OPENAI_REVIEW_MODEL==="gpt-5.6-terra"?{input:2,output:12}:{input:.2,output:1.2};
 const measurement={repository,commitSha:rules.repository.commitSha,model:result.model,status:result.status,note:result.note,filesReviewed:result.filesReviewed,inputTokens:result.inputTokens,outputTokens:result.outputTokens,estimatedUpperCostUSD:(result.inputTokens*price.input*1.25+result.outputTokens*price.output)/1_000_000,aiDurationMs:Date.now()-aiStart,totalDurationMs:Date.now()-start,aiFindings:result.findings.length,modelProposals:proposed.length,droppedOrDuplicate:Math.max(0,proposed.length-result.findings.length),qualityClassification:"Pending independent manual verification; not a measured precision rate."};
 measurements.push(measurement);
 writeFileSync(`benchmark-results/${repository.replaceAll("/","--")}.json`,JSON.stringify({measurement,findings:result.findings,modelProposals:proposed},null,2));
 // Never log source, evidence, credentials or provider error bodies.
 console.log(JSON.stringify(measurement));
 files=[];
}
writeFileSync("benchmark-results/measurements.json",JSON.stringify(measurements,null,2));
