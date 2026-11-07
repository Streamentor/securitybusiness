import { prisma } from "@/lib/db";

let ready: Promise<unknown> | null = null;
function ensureCreditLedger() {
  return ready ??= prisma.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS "InvoiceCreditGrant" (
    "invoiceId" TEXT PRIMARY KEY,
    "subscriptionId" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).catch((error) => { ready = null; throw error; });
}

/** Invoice identity (not event identity) and balance change commit or roll back together. */
export async function grantInvoiceCredits(input: {invoiceId: string; subscriptionId: string; credits: number; periodEnd: Date | null}) {
  if (!input.invoiceId || !input.subscriptionId || !Number.isSafeInteger(input.credits) || input.credits <= 0) throw new Error("Invalid invoice credit grant");
  await ensureCreditLedger();
  return prisma.$transaction(async (tx) => {
    const inserted = await tx.$executeRaw`INSERT INTO "InvoiceCreditGrant" ("invoiceId", "subscriptionId")
      VALUES (${input.invoiceId}, ${input.subscriptionId}) ON CONFLICT ("invoiceId") DO NOTHING`;
    if (!inserted) return false;
    // SQL uses the locked, current balance, preserving concurrent credit consumption.
    const updated = await tx.$executeRaw`UPDATE "User" SET
      "credits" = LEAST("credits" + ${input.credits}, ${input.credits * 2}),
      "currentPeriodEnd" = GREATEST("currentPeriodEnd", ${input.periodEnd}),
      "updatedAt" = CURRENT_TIMESTAMP
      WHERE "stripeSubscriptionId" = ${input.subscriptionId}`;
    if (updated !== 1) throw new Error("Invoice subscription owner unavailable");
    return true;
  });
}
