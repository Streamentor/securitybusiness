import assert from 'node:assert/strict';
import { readFileSync, writeFileSync, mkdtempSync, rmSync } from 'node:fs';
import { tmpdir } from 'node:os';
import { join } from 'node:path';
import { execFileSync } from 'node:child_process';
import { createSign } from 'node:crypto';
import { registerHooks, stripTypeScriptTypes } from 'node:module';
// Synthetic data only. All network, SES, auth and database operations are mocked.
const root = new URL('../src/', import.meta.url);
const shim = source => ({ url: `data:text/javascript,${encodeURIComponent(source)}`, shortCircuit: true });
const fx = { db: {}, context: null, session: null, commands: [], sends: [], prefs: new Map(), events: new Set(), fail: false };
globalThis.emailFixture = fx;
registerHooks({
  resolve(s, c, next) {
    if (s === 'server-only') return shim('export {}');
    if (s === 'next/server') return next('next/server.js', c);
    if (s === '@/lib/db') return shim('export const prisma = new Proxy({}, {get: (_,k) => globalThis.emailFixture.db[k]});');
    if (s === '@/lib/auth') return shim('export const auth = async () => globalThis.emailFixture.session;');
    if (s === '@/lib/email/context') return shim('export const loadEmailContext = async () => globalThis.emailFixture.context;');
    if (s === '@aws-sdk/client-sesv2') return shim(`export class SendEmailCommand {constructor(input){this.input=input}}; export class SESv2Client {constructor(config){globalThis.emailFixture.clientConfig=config} async send(command){globalThis.emailFixture.commands.push(command.input); if(globalThis.emailFixture.fail) throw new Error('fixture timeout'); return {MessageId:'ses-'+globalThis.emailFixture.commands.length}} destroy(){}}`);
    if (s.startsWith('@/')) return {url: new URL(s.slice(2)+'.ts', root).href, shortCircuit:true};
    return next(s,c);
  },
  load(url,c,next) { if(url.startsWith(root.href)&&url.endsWith('.ts')) return {format:'module',source:stripTypeScriptTypes(readFileSync(new URL(url),'utf8'),{mode:'transform'}),shortCircuit:true};return next(url,c); }
});
Object.assign(process.env, {VERCEL_ENV:'production', EMAIL_SEQUENCE_MODE:'live', EMAIL_SEQUENCE_START_AT:'2026-01-01T00:00:00Z', EMAIL_UNSUBSCRIBE_SECRET:'fixture-only-'.repeat(4), AWS_SES_REGION:'eu-central-1', AWS_SES_ACCESS_KEY_ID:'fixture', AWS_SES_SECRET_ACCESS_KEY:'fixture', EMAIL_FROM:'Stefan from ScanMySaaS <stefan@scanmysaas.com>', EMAIL_REPLY_TO:'founder@example.com', EMAIL_POSTAL_ADDRESS:'Example Company, 123 Test Street, Test City', AWS_SES_SNS_TOPIC_ARN:'arn:aws:sns:eu-central-1:123456789012:fixture', CRON_SECRET:'fixture-cron'});
globalThis.fetch = async () => {throw new Error('Unexpected external fetch');};
const {eligible,dueEmail,humanTime,MIN_GAP,DAY} = await import('../src/lib/email/policy.ts');
const {renderEmail} = await import('../src/lib/email/templates.ts');
const {EMAIL_KEYS} = await import('../src/lib/email/types.ts');
const {unsubscribeToken,verifyUnsubscribeToken} = await import('../src/lib/email/tokens.ts');
const {findingImpact} = await import('../src/lib/email/finding-impact.ts');
const {PLANS} = await import('../src/lib/stripe.ts');
const {sequenceMode} = await import('../src/lib/email/config.ts');
const {sendEmail} = await import('../src/lib/email/ses.ts');
const {reserveSend,EMAIL_DDL} = await import('../src/lib/email/store.ts');
const now = new Date('2026-02-01T12:00:00Z');
const finding = {title:'Exposed configuration file',path:'/.env',severity:'high',impact:'Anyone can request this file. If it contains credentials, they may be exposed.'};
const context = () => ({userId:'fixture-user',email:'fixture@example.com',name:'Alex Founder',plan:'free',createdAt:now,signupSource:null,optedOut:false,suppressed:false,consentAt:now,scan:{id:'fixture-scan',domain:'example.com',score:71,createdAt:now,completedAt:now,anchor:now,openCount:3,lockedCount:2,critical:0,high:1,medium:2,top:finding,top3:[finding,{...finding,severity:'medium',title:'Missing CSP',path:'/'}],rescanAvailable:true,deadline:new Date(+now+7*DAY),rescanned:false,resolved:0,added:0,stillOpen:3},repo:{id:'fixture-repo',count:2,visibility:'public',top:{...finding,path:'src/route.ts:14'}}});
const c = context();
assert.ok(eligible(c,new Date('2026-01-01')));
for(const change of [{plan:'starter'},{plan:'pro'},{optedOut:true},{suppressed:true},{consentAt:null},{email:'bad'},{createdAt:new Date('2025-01-01')}]) assert.equal(eligible({...c,...change},new Date('2026-01-01')),false);
assert.equal(eligible(c,null),false);
assert.equal(dueEmail(c,[],now),'welcome_report');
assert.equal(dueEmail({...c,repo:undefined,scan:{...c.scan,partial:true,high:0}},[{emailKey:'welcome_report',createdAt:now,status:'sent'}],new Date(+now+2*DAY)),null,'partial coverage must not trigger a clean-outside claim');
assert.equal(dueEmail(c,[{emailKey:'welcome_report',createdAt:now,status:'sent'}],new Date(+now+DAY)),null,'44 hour cap wins over day 1');
const day2=humanTime(c,new Date(+now+MIN_GAP));
assert.equal(dueEmail({...c,repo:undefined,scan:{...c.scan,high:0}},[{emailKey:'welcome_report',createdAt:now,status:'sent'}],day2),'clean_outside');
assert.equal(dueEmail(c,[{emailKey:'welcome_report',createdAt:now,status:'sent'}],day2),'still_open');
const day3=humanTime(c,new Date(+now+3*DAY));
assert.equal(dueEmail(c,[{emailKey:'still_open',createdAt:new Date(+now-DAY),status:'sent'}],day3),'repo_findings');
assert.equal(dueEmail({...c,repo:undefined},[{emailKey:'clean_outside',createdAt:new Date(+now-DAY),status:'sent'}],day3),null);
assert.equal(dueEmail({...c,scan:undefined,repo:undefined},[],humanTime(c,new Date(+now+DAY))),'first_scan_nudge');
// Completed repo scans must remove acquisition prompts for that same action.
assert.equal(dueEmail({...c,scan:undefined},[],humanTime(c,new Date(+now+DAY))),null,'repo-only user is not unactivated');
assert.equal(dueEmail({...c,scan:{...c.scan,high:0}},[{emailKey:'welcome_report',createdAt:now,status:'sent'}],day2),null,'clean website plus completed repo needs no repo invitation');
assert.equal(dueEmail({...c,repo:{...c.repo,count:0,top:undefined}},[{emailKey:'still_open',createdAt:new Date(+now-DAY),status:'sent'}],day3),null,'clean completed repo does not get repo_gap');
const day5=humanTime(c,new Date(+now+5*DAY));
assert.equal(dueEmail(c,[],day5),'rescan_expiring');
assert.equal(dueEmail({...c,scan:{...c.scan,rescanAvailable:false}},[],day5),null);
assert.equal(dueEmail({...c,scan:{...c.scan,deadline:new Date(+day5+4*DAY)}},[],day5),null);
assert.equal(dueEmail(c,Array.from({length:6},(_,i)=>({emailKey:String(i),createdAt:new Date(+now-DAY),status:'sent'})),day5),null);
assert.equal(humanTime({...c,createdAt:new Date('2026-02-01T02:00Z')},new Date('2026-02-02T00:00Z')).getUTCHours(),8);
assert.equal(+humanTime(c,now),+humanTime(c,now));
const previewSections = [];
for(const key of EMAIL_KEYS) {
  const email=renderEmail(key,c,process.env.EMAIL_POSTAL_ADDRESS);
  previewSections.push(`## ${key}\n\nSubject: ${email.subject}\n\n\`\`\`text\n${email.text}\n\`\`\``);
  const words=email.body.split(/\s+/).length;
  assert.ok(words>=60&&words<=170,`${key}: ${words} words`);
  assert.ok(email.subject.length<55,key);
  assert.doesNotMatch(email.text,/\{\{|undefined|[\u2013\u2014\u2018-\u201d]/);
  assert.doesNotMatch(email.html,/<img|<style|<table|<script/);
  assert.ok(email.text.includes(email.unsubscribeUrl));
  assert.equal(verifyUnsubscribeToken(new URL(email.unsubscribeUrl).searchParams.get('t')),c.userId);
  for(const match of email.text.matchAll(/https:\/\/[^\s]+/g)) assert.equal(new URL(match[0]).hostname,'www.scanmysaas.com');
}
if (process.env.EMAIL_FIXTURE_OUTPUT) writeFileSync(process.env.EMAIL_FIXTURE_OUTPUT, "# Synthetic email previews\n\nAll names, domains, findings and addresses below are fixtures, not customer data. No emails were sent.\n\n" + previewSections.join("\n\n"));
assert.match(renderEmail("welcome_report", {...c,scan:{...c.scan,domain:"long-subdomain-for-a-realistic-app.example.com"}}, process.env.EMAIL_POSTAL_ADDRESS).subject, /71\/100/);
assert.doesNotMatch(renderEmail('welcome_report',{...c,scan:{...c.scan,top:undefined}},process.env.EMAIL_POSTAL_ADDRESS).body,/Check your public GitHub repo next/,'welcome acknowledges existing repo scan even when website is clean');
assert.match(renderEmail('welcome_report',{...c,repo:undefined,scan:{...c.scan,top:undefined}},process.env.EMAIL_POSTAL_ADDRESS).body,/Check your public GitHub repo next/,'new repo invitation remains available before any repo scan');
assert.match(renderEmail('welcome_report',{...c,scan:{...c.scan,partial:true}},process.env.EMAIL_POSTAL_ADDRESS).body,/scan was partial/);
assert.match(renderEmail('last_note',{...c,scan:{...c.scan,rescanned:true,comparisonUnavailable:true,resolved:999}},process.env.EMAIL_POSTAL_ADDRESS).body,/cannot reliably say/);
const readable = renderEmail('welcome_report', {...c,name:'Streamentor'}, process.env.EMAIL_POSTAL_ADDRESS);
assert.ok(readable.body.startsWith('Hi,\n'), 'OAuth handles use a neutral greeting');
assert.ok(renderEmail('welcome_report', c, process.env.EMAIL_POSTAL_ADDRESS).body.startsWith('Hi Alex,\n'));
assert.match(readable.html, /<a href="https:\/\/www\.scanmysaas\.com\/scan\/[^"]+">Open your report<\/a>/);
assert.match(readable.html, /<p><a href="[^"]+">Unsubscribe<\/a><\/p>\n<p>ScanMySaaS,/);
assert.doesNotMatch(readable.html, />https:\/\//, 'visible labels never expose full URLs');
assert.ok(readable.text.includes(readable.unsubscribeUrl), 'plain text keeps full URLs');
assert.ok(readable.html.includes('&amp;utm_medium='), 'query parameters remain escaped in hrefs');
const paid=renderEmail('what_paid_unlocks',c,process.env.EMAIL_POSTAL_ADDRESS);
for(const value of [PLANS.starter.price/100,PLANS.starter.credits,PLANS.starter.maxRollover,PLANS.pro.price/100,PLANS.pro.credits]) assert.ok(paid.text.includes(String(value)));
assert.equal(verifyUnsubscribeToken('bad'),null);
assert.equal(verifyUnsubscribeToken(unsubscribeToken(c.userId).replace(/.$/,'!')),null);
const scanner=readFileSync(new URL('../src/lib/scanner.ts',import.meta.url),'utf8');
for(const [,type] of scanner.matchAll(/type:\s*"([a-z-]+)"/g)) assert.ok(findingImpact({type,description:'A scanner finding. More details.'}).split(/\s+/).length<=25);
assert.equal(findingImpact({type:'new-future-type',description:'Concrete first sentence. Another sentence.'}),'Concrete first sentence.');
await sendEmail(c.email,renderEmail('welcome_report',c,process.env.EMAIL_POSTAL_ADDRESS),'fixture-send');
const sent=fx.commands.at(-1);assert.equal(sent.ConfigurationSetName,'scanmysaas-onboarding');assert.ok(sent.Content.Simple.Body.Text);assert.ok(sent.Content.Simple.Body.Html);
assert.equal(sent.Content.Simple.Headers.find(h=>h.Name==='List-Unsubscribe-Post').Value,'List-Unsubscribe=One-Click');
assert.ok(sent.Content.Simple.Headers.find(h=>h.Name==='List-Unsubscribe').Value.includes('mailto:'));
assert.equal(fx.clientConfig.maxAttempts,1);
process.env.VERCEL_ENV='preview';assert.equal(sequenceMode(),'off');process.env.VERCEL_ENV='production';
let queue=Promise.resolve();
const transaction=async fn=>{const prev=queue;let release;queue=new Promise(r=>release=r);await prev;try{return await fn(fx.db)}finally{release()}};
const prefDefault = id=>({userId:id,marketingOptOut:false,suppressed:false,consentAt:now});
fx.prefs.set(c.userId,prefDefault(c.userId));
fx.db={
 $executeRawUnsafe:async()=>0,$queryRaw:async()=>[{id:c.userId,locked:true}],$transaction:transaction,
 $executeRaw:async(strings,...args)=>{if(strings.join('').includes('pg_advisory'))return 1;if(fx.events.has(args[0]))return 0;fx.events.add(args[0]);return 1},
 user:{findUnique:async()=>fx.context?{id:c.userId,email:fx.context.email,plan:fx.context.plan,createdAt:fx.context.createdAt,emailPreference:fx.prefs.get(c.userId)}:null,findFirst:async()=>null},
 emailPreference:{findUnique:async({where})=>fx.prefs.get(where.userId),upsert:async({where,create,update})=>{const p=fx.prefs.has(where.userId)?{...fx.prefs.get(where.userId),...update}:create;fx.prefs.set(where.userId,p);return p}},
 emailSend:{count:async()=>0,findMany:async()=>fx.sends,create:async({data})=>{if(fx.sends.some(s=>s.userId===data.userId&&s.emailKey===data.emailKey))throw new Error('duplicate');fx.sends.push(data);return data},update:async({where,data})=>Object.assign(fx.sends.find(s=>s.id===where.id),data),findFirst:async()=>fx.sends[0]||null,findUnique:async({where})=>fx.sends.find(s=>s.id===where.id)},
 emailTestSend:{findFirst:async()=>null,update:async()=>{}},
};
fx.context=c;
fx.db.emailSend.count=async()=>50;assert.equal(await reserveSend(c.userId,'still_open',day2),null,'rolling global 50/hour cap');fx.db.emailSend.count=async()=>0;
const reservations=await Promise.all([reserveSend(c.userId,'still_open',day2),reserveSend(c.userId,'still_open',day2)]);
assert.equal(reservations.filter(Boolean).length,1,'overlapping reservations consume one key');
assert.equal(await reserveSend(c.userId,'repo_gap',day2),null,'different keys also respect 44h');
const {processEmailUser}=await import('../src/lib/email/worker.ts');
fx.sends=[];fx.fail=true;const originalError=console.error;console.error=()=>{};
await processEmailUser(c.userId,now);assert.equal(fx.sends[0].status,'unknown');const attempts=fx.commands.length;await processEmailUser(c.userId,now);assert.equal(fx.commands.length,attempts,'ambiguous timeout never retries');fx.fail=false;
fx.sends=[];fx.context={...c,plan:'pro'};await processEmailUser(c.userId,now);assert.equal(fx.sends.length,0);
fx.context=c;let reads=0;fx.db.user.findUnique=async()=>({id:c.userId,email:c.email,plan:++reads?'pro':'free',createdAt:c.createdAt,emailPreference:fx.prefs.get(c.userId)});
await processEmailUser(c.userId,now);assert.equal(fx.sends[0].status,'cancelled','upgrade after schedule blocks provider send');
fx.db.user.findUnique=async()=>({id:c.userId,email:c.email,plan:'free',createdAt:c.createdAt,emailPreference:fx.prefs.get(c.userId)});
fx.sends=[];const beforeParallel=fx.commands.length;
await Promise.all([processEmailUser(c.userId,now),processEmailUser(c.userId,now)]);
assert.equal(fx.commands.length-beforeParallel,1,'overlapping workers send exactly once');
fx.sends=[];fx.prefs.get(c.userId).suppressed=true;const beforeSuppressed=fx.commands.length;
await processEmailUser(c.userId,now);assert.equal(fx.commands.length,beforeSuppressed,'suppression rechecked just before send');
fx.prefs.get(c.userId).suppressed=false;
const attribution=await import('../src/lib/email/attribution.ts');
let conversion;
fx.db.emailConversion={upsert:async a=>{conversion=a.create;return a.create}};
fx.sends=[{id:'conversion-send',userId:c.userId,emailKey:'still_open',status:'sent',createdAt:now}];
assert.deepEqual(await attribution.checkoutEmailAttribution(c.userId,'unknown',now),{});
assert.equal((await attribution.checkoutEmailAttribution(c.userId,'still_open',now)).email_send_id,'conversion-send');
await attribution.recordEmailConversion({checkoutId:'checkout-fixture',userId:c.userId,campaign:'still_open',sendId:'conversion-send',paidAt:new Date(+now+DAY)});assert.equal(conversion.checkoutId,'checkout-fixture');
conversion=null;await attribution.recordEmailConversion({checkoutId:'late-checkout',userId:c.userId,campaign:'still_open',sendId:'conversion-send',paidAt:new Date(+now+8*DAY)});assert.equal(conversion,null);

const {NextRequest}=await import('next/server.js');
const unsub=await import('../src/app/api/email/unsubscribe/route.ts');
assert.equal((await unsub.POST(new NextRequest('https://www.scanmysaas.com/api/email/unsubscribe?t=bad',{method:'POST'}))).status,400);
const unsubUrl='https://www.scanmysaas.com/api/email/unsubscribe?t='+unsubscribeToken(c.userId);
const response=await unsub.POST(new NextRequest(unsubUrl,{method:'POST'}));assert.equal(response.status,200);assert.equal(await response.text(),'');assert.equal(fx.prefs.get(c.userId).marketingOptOut,true);
assert.match(await (await unsub.GET(new NextRequest(unsubUrl))).text(),/You're unsubscribed/);
assert.equal(fx.prefs.get(c.userId).marketingOptOut,true,'GET never resubscribes');
// Verify real RSA signatures using a short-lived synthetic certificate; no AWS access.
const folder=mkdtempSync(join(tmpdir(),'ses-signature-fixture-'));
try {
 execFileSync('openssl',['req','-x509','-newkey','rsa:2048','-nodes','-keyout',join(folder,'key.pem'),'-out',join(folder,'cert.pem'),'-days','1','-subj','/CN=fixture'],{stdio:'ignore'});
 const pem=readFileSync(join(folder,'cert.pem'),'utf8'),privateKey=readFileSync(join(folder,'key.pem'),'utf8');
 const sns=await import('../src/lib/email/sns.ts');
 let fetches=0;globalThis.fetch=async()=>{fetches++;return new Response(pem)};
 const m={Type:'Notification',Message:JSON.stringify({eventType:'Complaint',mail:{messageId:'ses-fixture',tags:{send_id:['event-send']}}}),MessageId:'fixture-event',TopicArn:process.env.AWS_SES_SNS_TOPIC_ARN,Timestamp:new Date().toISOString(),SignatureVersion:'2',Signature:'',SigningCertURL:'https://sns.eu-central-1.amazonaws.com/SimpleNotificationService-fixture.pem'};
 const signer=createSign('RSA-SHA256');signer.update(sns.snsCanonical(m));m.Signature=signer.sign(privateKey,'base64');
 await sns.verifySnsMessage(m);
 await assert.rejects(()=>sns.verifySnsMessage({...m,Signature:'invalid'}));
 await assert.rejects(()=>sns.verifySnsMessage({...m,TopicArn:m.TopicArn+'wrong'}));
 const count=fetches;await assert.rejects(()=>sns.verifySnsMessage({...m,SigningCertURL:'https://sns.eu-central-1.amazonaws.com.attacker.test/cert.pem'}));assert.equal(fetches,count);
 fx.sends=[{id:'event-send',userId:c.userId,emailKey:'welcome_report',status:'sent',createdAt:now}];
 await sns.handleSnsMessage(m);assert.equal(fx.prefs.get(c.userId).suppressed,true);assert.equal(fx.sends[0].status,'complaint');
 await sns.handleSnsMessage({...m,MessageId:'delivery-event',Message:JSON.stringify({eventType:'Delivery',mail:{messageId:'ses-fixture',tags:{send_id:['event-send']}}})});assert.equal(fx.sends[0].status,'complaint','late Delivery cannot undo complaint');
 assert.ok(EMAIL_DDL.every(sql=>!/DROP|TRUNCATE/.test(sql)));
}finally{rmSync(folder,{recursive:true,force:true});console.error=originalError;}
const adminRoute=await import('../src/app/api/admin/emails/route.ts');
fx.session=null;assert.equal((await adminRoute.GET()).status,403);
assert.equal((await adminRoute.POST(new NextRequest('https://www.scanmysaas.com/api/admin/emails',{method:'POST',headers:{origin:'https://attacker.invalid'}}))).status,403);
const prefRoute=await import('../src/app/api/email/preferences/route.ts');
assert.equal((await prefRoute.GET()).status,401);
assert.equal((await prefRoute.POST(new NextRequest('https://www.scanmysaas.com/api/email/preferences',{method:'POST',headers:{origin:'https://attacker.invalid'}}))).status,403);
const cronRoute=await import('../src/app/api/cron/email-sequence/route.ts');
assert.equal((await cronRoute.GET(new NextRequest('https://www.scanmysaas.com/api/cron/email-sequence'))).status,401);
process.env.EMAIL_SEQUENCE_MODE='off';
const off=await cronRoute.GET(new NextRequest('https://www.scanmysaas.com/api/cron/email-sequence',{headers:{authorization:'Bearer fixture-cron'}}));
assert.deepEqual(await off.json(),{mode:'off',examined:0,sent:0});
console.log('Email sequence: eligibility, branches, timing, rendering, prices, headers, concurrency, fallback, unsubscribe and SNS verified.');
