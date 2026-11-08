import assert from 'node:assert/strict';
import { readFileSync } from 'node:fs';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
const root = new URL('../src/', import.meta.url);
const shim = source => ({url:`data:text/javascript,${encodeURIComponent(source)}`,shortCircuit:true});
const fixture={db:{},session:null,context:null};globalThis.journeyFixture=fixture;
registerHooks({
 resolve(s,c,next){
  if(s==='server-only')return shim('export {}');
  if(s==='next/server')return next('next/server.js',c);
  if(s==='@/lib/db')return shim('export const prisma=new Proxy({}, {get:(_,k)=>globalThis.journeyFixture.db[k]});');
  if(s==='@/lib/auth')return shim('export const auth=async()=>globalThis.journeyFixture.session;');
  if(s==='@/lib/email/context')return shim('export const loadEmailContext=async()=>globalThis.journeyFixture.context;');
  if(s.startsWith('@/'))return{url:new URL(s.slice(2)+'.ts',root).href,shortCircuit:true};return next(s,c);
 },
 load(url,c,next){if(url.startsWith(root.href)&&url.endsWith('.ts'))return{format:'module',source:stripTypeScriptTypes(readFileSync(new URL(url),'utf8'),{mode:'transform'}),shortCircuit:true};return next(url,c);}
});
globalThis.fetch=async()=>{throw new Error('No external requests in journey fixtures');};
Object.assign(process.env,{VERCEL_ENV:'production',EMAIL_SEQUENCE_MODE:'live',EMAIL_SEQUENCE_START_AT:'2026-01-01T00:00:00Z'});
const {emailJourney,nextEmail}=await import('../src/lib/email/journey.ts');
const {dueEmail,DAY}=await import('../src/lib/email/policy.ts');
const now=new Date('2026-02-01T12:00Z');
const c={userId:'fixture',email:'alex@example.com',name:'Alex Founder',plan:'free',createdAt:now,consentAt:now,optedOut:false,suppressed:false,signupSource:null,scan:{id:'scan',domain:'example.com',score:80,anchor:now,createdAt:now,completedAt:now,critical:0,high:1,medium:2,openCount:3,lockedCount:2,top3:[],rescanAvailable:true,deadline:new Date(+now+7*DAY),rescanned:false,resolved:0,stillOpen:3,added:0}};
const start=new Date(process.env.EMAIL_SEQUENCE_START_AT);
const fresh=emailJourney(c,[],now,start,'live');assert.equal(fresh.state,'due');assert.equal(fresh.next.key,'welcome_report');assert.equal(fresh.used,0);
const cancelled = emailJourney(c,[{emailKey:'welcome_report',status:'cancelled',createdAt:now}],now,start,'live');
assert.equal(cancelled.used,0);assert.notEqual(cancelled.next?.key,'welcome_report','cancelled unique key cannot be re-reserved');
const history=[{id:'send1',emailKey:'welcome_report',status:'delivered',createdAt:now,updatedAt:now}];
const future=nextEmail(c,history,new Date(+now+DAY));assert.ok(future);assert.ok(+new Date(future.at)-+now>=44*3600000);assert.equal(dueEmail(c,history,new Date(future.at)),future.key,'forecast uses sender policy');
for(const patch of [{plan:'pro'},{optedOut:true},{suppressed:true},{consentAt:null},{createdAt:new Date('2025-01-01')}]){const j=emailJourney({...c,...patch},history,new Date(+now+DAY),start,'live');assert.equal(j.state,'excluded');assert.equal(j.next,null);assert.equal(j.steps.find(s=>s.key==='welcome_report').state,'delivered','history retained when sending stops');}
assert.equal(emailJourney(c,[],now,start,'dry-run').state,'paused');
const repo={id:'repo',count:2,visibility:'public'};
const repositoryOnly=emailJourney({...c,scan:undefined,repo},[],now,start,'live');assert.equal(repositoryOnly.next,null);assert.match(repositoryOnly.steps.find(s=>s.key==='first_scan_nudge').reason,/already scanned/);
const clean=emailJourney({...c,repo,scan:{...c.scan,high:0}},history,new Date(+now+DAY),start,'live');assert.equal(clean.steps.find(s=>s.key==='clean_outside').state,'skipped');assert.equal(clean.next.key,'repo_findings');
const completed=emailJourney(c,Array.from({length:6},(_,i)=>({emailKey:'key'+i,status:'sent',createdAt:now})),now,start,'live');assert.equal(completed.state,'complete');assert.equal(completed.next,null);
const ambiguous=emailJourney(c,[{...history[0],status:'unknown'}],new Date(+now+DAY),start,'live');assert.match(ambiguous.steps.find(s=>s.key==='welcome_report').reason,/not retried/);
const expired=emailJourney(c,[],new Date(+now+20*DAY),start,'live');assert.equal(expired.next,null);assert.equal(expired.steps.find(s=>s.key==='welcome_report').state,'expired');
const {NextRequest}=await import('next/server.js');
const route=await import('../src/app/api/admin/emails/users/route.ts');
let reads=0;fixture.db={$executeRawUnsafe:async()=>{reads++;},user:{findUnique:async()=>({role:'user'})}};
assert.equal((await route.GET(new NextRequest('https://www.scanmysaas.com/api/admin/emails/users'))).status,403);assert.equal(reads,0,'unauthenticated requests do not initialize or read journey tables');
fixture.session={user:{id:'admin'}};assert.equal((await route.GET(new NextRequest('https://www.scanmysaas.com/api/admin/emails/users'))).status,403);assert.equal(reads,0);
fixture.db={...fixture.db,$queryRaw:async()=>[],user:{findUnique:async()=>({role:'admin'}),count:async()=>1,findMany:async args=>{assert.equal(args.take,20);assert.equal(args.skip,0);assert.ok(args.where.AND);return[{id:'fixture',email:c.email,name:c.name,plan:'free',createdAt:now,emailPreference:{consentAt:now,marketingOptOut:false,suppressed:false,lastSequenceCheckAt:null},emailSends:history}];}},emailSend:{count:async()=>1,findMany:async()=>history},emailTestSend:{findMany:async()=>[{emailKey:'first_scan_nudge',mode:'test',status:'delivery',createdAt:now}]},emailPreference:{findUnique:async()=>({consentAt:now})},emailConversion:{findUnique:async()=>null},emailEvent:{findMany:async()=>[{sendId:'send1',eventType:'Delivery',createdAt:now}]}};
const response=await route.GET(new NextRequest('https://www.scanmysaas.com/api/admin/emails/users?q=alex'));assert.equal(response.status,200);assert.match(response.headers.get('cache-control'),/no-store/);const list=await response.json();assert.equal(list.users[0].used,1);assert.equal(list.users[0].last.emailKey,'welcome_report');assert.equal(list.total,1);
assert.equal((await route.GET(new NextRequest('https://www.scanmysaas.com/api/admin/emails/users?filter=bad'))).status,400);
fixture.context=c;const detail=await(await route.GET(new NextRequest('https://www.scanmysaas.com/api/admin/emails/users?userId=fixture'))).json();assert.equal(detail.journey.used,1,'admin tests never advance real sequence');assert.equal(detail.tests.length,1);assert.equal(detail.events[0].eventType,'Delivery');assert.equal(detail.sends[0].sesMessageId,undefined,'provider identifiers not exposed');
fixture.context=null;assert.equal((await route.GET(new NextRequest('https://www.scanmysaas.com/api/admin/emails/users?userId=missing'))).status,404);
console.log('Email journeys: policy forecasts, branches, exits, caps, history, admin authorization, paging, privacy and test/live separation passed.');
