import "server-only";
import type Stripe from "stripe";
import { prisma } from "@/lib/db";
import { getPlanFromPriceId, PLANS } from "@/lib/stripe";
import { sendingConfig, validEmail } from "@/lib/email/config";
import { sendPlanPurchaseEmail } from "@/lib/email/ses";

interface Purchase {
  invoiceId: string;
  plan: "starter" | "pro";
  amountPaid: number;
  currency: string;
}

let ready: Promise<unknown> | undefined;
function ensurePurchaseEmailTable() {
  return ready ??= prisma.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS "PlanPurchaseEmail" (
    "invoiceId" TEXT PRIMARY KEY,
    "plan" TEXT NOT NULL,
    "amountPaid" BIGINT NOT NULL,
    "currency" TEXT NOT NULL,
    "status" TEXT NOT NULL DEFAULT 'pending',
    "attempts" INTEGER NOT NULL DEFAULT 0,
    "retryAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "messageId" TEXT
  )`).catch((error) => { ready = undefined; throw error; });
}

function recipient() {
  const address = process.env.PLAN_PURCHASE_EMAIL_TO?.trim();
  return process.env.VERCEL_ENV === "production" && address && validEmail(address) ? address : null;
}

function purchaseFromInvoice(invoice: Stripe.Invoice): Purchase | null {
  if (!invoice.livemode || invoice.billing_reason !== "subscription_create" || invoice.status !== "paid"
    || !Number.isSafeInteger(invoice.amount_paid) || invoice.amount_paid <= 0) return null;
  for (const item of invoice.lines?.data ?? []) {
    const price = item.pricing?.price_details?.price;
    const plan = price ? getPlanFromPriceId(typeof price === "string" ? price : price.id) : null;
    if (plan) return { invoiceId: invoice.id, plan, amountPaid: invoice.amount_paid, currency: invoice.currency };
  }
  return null;
}

/** The same Stripe invoice may arrive more than once, even with different event IDs. */
export async function queuePlanPurchaseEmail(invoice: Stripe.Invoice) {
  const purchase = recipient() ? purchaseFromInvoice(invoice) : null;
  if (!purchase) return null;
  await ensurePurchaseEmailTable();
  await prisma.$executeRaw`INSERT INTO "PlanPurchaseEmail" ("invoiceId", "plan", "amountPaid", "currency")
    VALUES (${purchase.invoiceId}, ${purchase.plan}, ${purchase.amountPaid}, ${purchase.currency})
    ON CONFLICT ("invoiceId") DO NOTHING`;
  return purchase.invoiceId;
}

export async function drainPlanPurchaseEmails(invoiceId?: string) {
  const to = recipient();
  if (!to) return;
  sendingConfig();
  await ensurePurchaseEmailTable();
  // Claim outside the email request. Multiple Stripe deliveries and the cron
  // can run concurrently, but only one worker gets each pending invoice.
  const rows = await prisma.$queryRaw<Array<Omit<Purchase, "amountPaid"> & { amountPaid: bigint; attempts: number }>>`
    WITH candidates AS (
      SELECT "invoiceId" FROM "PlanPurchaseEmail"
      WHERE "status" = 'pending' AND "retryAt" <= CURRENT_TIMESTAMP
        AND (${invoiceId ?? null}::text IS NULL OR "invoiceId" = ${invoiceId ?? null})
      ORDER BY "retryAt" ASC LIMIT 4 FOR UPDATE SKIP LOCKED
    )
    UPDATE "PlanPurchaseEmail" AS e SET "status" = 'sending', "attempts" = e."attempts" + 1
    FROM candidates AS c WHERE e."invoiceId" = c."invoiceId"
    RETURNING e."invoiceId", e."plan", e."amountPaid", e."currency", e."attempts"`;

  await Promise.all(rows.map(async (purchase) => {
    const plan = PLANS[purchase.plan].name;
    const currency = purchase.currency.toUpperCase();
    const money = new Intl.NumberFormat("en-US", { style: "currency", currency, currencyDisplay: "code" });
    const digits = money.resolvedOptions().maximumFractionDigits ?? 2;
    const amount = money.format(Number(purchase.amountPaid) / 10 ** digits);
    let messageId: string;
    try {
      messageId = await sendPlanPurchaseEmail(
        to,
        `ScanMySaaS: New ${plan} purchase`,
        `A new ScanMySaaS ${plan} subscription was paid.\n\nAmount paid: ${amount}\nStripe invoice: https://dashboard.stripe.com/invoices/${encodeURIComponent(purchase.invoiceId)}`,
        purchase.invoiceId,
      );
    } catch (error) {
      // An explicit throttle means SES rejected the request. Timeout or
      // transport failures can still have sent, so don't retry automatically.
      const statusCode = (error as { $metadata?: { httpStatusCode?: number } } | null)?.$metadata?.httpStatusCode;
      const status = statusCode === 429 && purchase.attempts < 6 ? "pending" : statusCode && statusCode >= 400 && statusCode < 500 ? "failed" : "unknown";
      await prisma.$executeRaw`UPDATE "PlanPurchaseEmail" SET "status" = ${status},
        "retryAt" = CURRENT_TIMESTAMP + INTERVAL '10 minutes' WHERE "invoiceId" = ${purchase.invoiceId}`;
      console.error("Plan purchase email could not be confirmed:", status);
      return;
    }
    await prisma.$executeRaw`UPDATE "PlanPurchaseEmail" SET "status" = 'sent', "messageId" = ${messageId}
      WHERE "invoiceId" = ${purchase.invoiceId}`;
  }));
}
