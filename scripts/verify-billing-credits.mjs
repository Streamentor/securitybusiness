import assert from "node:assert/strict";
import {readFileSync} from "node:fs";
import {registerHooks,stripTypeScriptTypes} from "node:module";
const root=new URL("../src/",import.meta.url);
const f={ledger:new Set(),credits:5,periodEnd:new Date("2026-03-01"),fail:false,owner:true,tail:Promise.resolve(),db:{},event:null};
globalThis.creditFixture=f;
const shim=s=>({url:`data:text/javascript,${encodeURIComponent(s)}`,shortCircuit:true});
registerHooks({resolve(s,c,next){
 if(s==="next/server")return shim("export const NextResponse={json:Response.json.bind(Response)}; export const after=(task)=>globalThis.creditFixture.after.push(task);");
 if(s==="server-only")return shim("export {};");
 if(s==="@/lib/db")return shim("export const prisma=globalThis.creditFixture.db;");
 if(s==="@/lib/stripe")return shim('export const PLANS={pro:{name:"Pro"},starter:{name:"Starter"}}; export const getCreditsForPlan=p=>p==="pro"?30:p==="starter"?10:0; export const getPlanFromPriceId=id=>id==="price_fixture"?"pro":null; export const stripe={webhooks:{constructEvent:()=>{if(globalThis.creditFixture.invalidSignature)throw Error("bad signature");return globalThis.creditFixture.event;}},subscriptions:{retrieve:async()=>({metadata:{plan:"pro"},items:{data:[{current_period_end:1775001600}]}})}};');
 if(s==="@aws-sdk/client-sesv2")return shim('export class SendEmailCommand{constructor(input){this.input=input;}} export class SESv2Client{async send(command){globalThis.creditFixture.emails.push(command.input);return {MessageId:"ses_fixture"};} destroy(){}}');
 if(s.startsWith("@/"))return{url:new URL(`${s.slice(2)}.ts`,root).href,shortCircuit:true};
 return next(s,c);
},load(u,c,next){if(u.startsWith(root.href)&&u.endsWith(".ts"))return{format:"module",source:stripTypeScriptTypes(readFileSync(new URL(u),"utf8"),{mode:"transform"}),shortCircuit:true};return next(u,c);}});
globalThis.fetch=async()=>{throw Error("No network allowed");};
f.db={
 $executeRawUnsafe:async(sql)=>{assert.match(sql,/"invoiceId" TEXT PRIMARY KEY/);return 0;},
 $transaction:async(callback)=>{
  let release;const before=f.tail;f.tail=new Promise(r=>{release=r;});await before;
  const saved={ledger:new Set(f.ledger),credits:f.credits,periodEnd:f.periodEnd};
  try{return await callback({$executeRaw:async(parts,...values)=>{
   const sql=parts.join("?");
   if(sql.startsWith('INSERT')){assert.match(sql,/ON CONFLICT \("invoiceId"\) DO NOTHING/);if(f.ledger.has(values[0]))return 0;f.ledger.add(values[0]);return 1;}
   assert.match(sql,/LEAST\("credits" \+ \?, \?\)/);assert.match(sql,/GREATEST\("currentPeriodEnd", \?\)/);
   if(f.fail)throw Error("fixture rollback");if(!f.owner)return 0;
   f.credits=Math.min(f.credits+values[0],values[1]);if(values[2]>f.periodEnd)f.periodEnd=values[2];return 1;
  }});}catch(e){Object.assign(f,saved);throw e;}finally{release();}
 },
};
const {grantInvoiceCredits}=await import("../src/lib/billing-credit-store.ts");
const input={invoiceId:"in_a",subscriptionId:"sub_fixture",credits:30,periodEnd:new Date("2026-04-01")};
const results=await Promise.all(Array.from({length:12},()=>grantInvoiceCredits(input)));
assert.equal(results.filter(Boolean).length,1);assert.equal(f.credits,35,"concurrent repeats credit one invoice once");
f.credits-=1;
assert.equal(await grantInvoiceCredits(input),false);assert.equal(f.credits,34,"retries cannot refill spent credits");
await grantInvoiceCredits({...input,invoiceId:"in_b",periodEnd:new Date("2026-02-01")});assert.equal(f.credits,60,"existing rollover cap preserved");assert.equal(f.periodEnd.toISOString(),"2026-04-01T00:00:00.000Z");
f.fail=true;await assert.rejects(grantInvoiceCredits({...input,invoiceId:"in_retry"}));assert.equal(f.ledger.has("in_retry"),false,"failed credit mutation rolls back invoice marker");
f.fail=false;assert.equal(await grantInvoiceCredits({...input,invoiceId:"in_retry"}),true);
f.owner=false;await assert.rejects(grantInvoiceCredits({...input,invoiceId:"in_missing"}));assert.equal(f.ledger.has("in_missing"),false);f.owner=true;
const route=await import("../src/app/api/stripe/webhook/route.ts");
const request=signature=>new Request("https://example.invalid/api/stripe/webhook",{method:"POST",headers:signature?{"stripe-signature":"fixture"}:{},body:"fixture raw body"});
assert.equal((await route.POST(request(false))).status,400);
const originalError=console.error;console.error=()=>{};
try{f.invalidSignature=true;assert.equal((await route.POST(request(true))).status,400);}finally{f.invalidSignature=false;console.error=originalError;}
f.credits=0;
for(const id of ["evt_one","evt_two"]){f.event={id,type:"invoice.paid",data:{object:{id:"in_event_duplicate",billing_reason:"subscription_cycle",parent:{subscription_details:{subscription:"sub_fixture"}}}}};assert.equal((await route.POST(request(true))).status,200);}
assert.equal(f.credits,30,"different Stripe event IDs for same invoice do not double grant");
f.event.data.object.billing_reason="subscription_create";f.event.data.object.id="in_first";await route.POST(request(true));assert.equal(f.credits,30,"first invoice still belongs to checkout fulfillment");
console.log("Invoice identity, parallel retries, atomic rollback, rollover and signed webhook regression checks passed.");

Object.assign(process.env, {
  VERCEL_ENV: "production", PLAN_PURCHASE_EMAIL_TO: "owner@example.invalid", AWS_SES_REGION: "eu-central-1",
  EMAIL_FROM: "Stefan from ScanMySaaS <stefan@scanmysaas.com>", EMAIL_REPLY_TO: "stefan@scanmysaas.com",
  AWS_SES_ACCESS_KEY_ID: "fixture", AWS_SES_SECRET_ACCESS_KEY: "fixture",
});
const outbox = new Map();
f.after = [];
f.emails = [];
f.db.$executeRaw = async (parts, ...values) => {
  const sql = parts.join("?");
  if (sql.startsWith("INSERT")) {
    const [invoiceId, plan, amountPaid, currency] = values;
    if (!outbox.has(invoiceId)) outbox.set(invoiceId, { invoiceId, plan, amountPaid: BigInt(amountPaid), currency, status: "pending", attempts: 0 });
  } else {
    assert.match(sql, /"status" = 'sent'/);
    outbox.get(values[1]).status = "sent";
  }
  return 1;
};
f.db.$queryRaw = async (parts, invoiceId) => {
  assert.match(parts.join("?"), /FOR UPDATE SKIP LOCKED/);
  const row = outbox.get(invoiceId);
  if (!row || row.status !== "pending") return [];
  row.status = "sending";
  return [{ ...row, attempts: ++row.attempts }];
};
const invoice = {
  id: "in_purchase", livemode: true, status: "paid", billing_reason: "subscription_create",
  amount_paid: 7900, currency: "usd", lines: { data: [{ pricing: { price_details: { price: "price_fixture" } } }] },
};
const paidEvent = (object, livemode = true) => ({ type: "invoice.paid", livemode, data: { object } });
for (const event of [
  paidEvent(invoice, false),
  paidEvent({ ...invoice, amount_paid: 0 }),
  paidEvent({ ...invoice, status: "open" }),
  paidEvent({ ...invoice, lines: { data: [] } }),
]) {
  f.event = event;
  assert.equal((await route.POST(request(true))).status, 200);
}
assert.equal(outbox.size, 0, "test, unpaid, free and unrelated invoices do not queue alerts");
f.event = paidEvent(invoice);
const purchaseResponses = await Promise.all(Array.from({ length: 4 }, () => route.POST(request(true))));
assert.ok(purchaseResponses.every((response) => response.status === 200));
assert.equal(f.emails.length, 0, "paid webhook persists the task before delivery");
assert.equal(outbox.size, 1);
await Promise.all(f.after.map((task) => task()));
assert.equal(f.emails.length, 1, "webhook retries and concurrent workers produce one confirmed delivery");
assert.equal(outbox.get(invoice.id).status, "sent");
assert.deepEqual(f.emails[0].Destination.ToAddresses, ["owner@example.invalid"]);
assert.match(f.emails[0].Content.Simple.Subject.Data, /New Pro purchase/);
assert.match(f.emails[0].Content.Simple.Body.Text.Data, /USD\s+79\.00/);
assert.match(f.emails[0].Content.Simple.Body.Text.Data, /dashboard\.stripe\.com\/invoices\/in_purchase/);
assert.equal(f.emails[0].Content.Simple.Headers, undefined, "internal alert is outside the customer sequence");
console.log("Plan purchase notification eligibility, signed webhook, outbox dedupe and SES envelope passed.");
