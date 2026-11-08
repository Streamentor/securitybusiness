import "server-only";
import { randomUUID } from "node:crypto";
import { prisma } from "@/lib/db";
import type { Prisma } from "@/generated/prisma/client";
import type { EmailKey } from "@/lib/email/types";
export const EMAIL_DDL = [
  `CREATE TABLE IF NOT EXISTS "EmailSequenceRun" ("id" TEXT PRIMARY KEY, "mode" TEXT NOT NULL, "status" TEXT NOT NULL, "startedAt" TIMESTAMP(3) NOT NULL, "completedAt" TIMESTAMP(3) NOT NULL, "examined" INTEGER NOT NULL DEFAULT 0, "sent" INTEGER NOT NULL DEFAULT 0)`,
  `CREATE INDEX IF NOT EXISTS "EmailSequenceRun_startedAt_idx" ON "EmailSequenceRun" ("startedAt")`,
  `CREATE TABLE IF NOT EXISTS "EmailConversion" ("userId" TEXT PRIMARY KEY REFERENCES "User"("id") ON DELETE CASCADE, "checkoutId" TEXT NOT NULL UNIQUE, "emailKey" TEXT NOT NULL, "sendId" TEXT NOT NULL, "paidAt" TIMESTAMP(3) NOT NULL)`,
  `CREATE TABLE IF NOT EXISTS "EmailPreference" ("userId" TEXT PRIMARY KEY REFERENCES "User"("id") ON DELETE CASCADE, "marketingOptOut" BOOLEAN NOT NULL DEFAULT false, "optOutAt" TIMESTAMP(3), "suppressed" BOOLEAN NOT NULL DEFAULT false, "suppressedReason" TEXT, "consentAt" TIMESTAMP(3), "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
  `ALTER TABLE "EmailPreference" ADD COLUMN IF NOT EXISTS "consentAt" TIMESTAMP(3)`,
  `ALTER TABLE "EmailPreference" ADD COLUMN IF NOT EXISTS "lastSequenceCheckAt" TIMESTAMP(3)`,
  `CREATE TABLE IF NOT EXISTS "EmailSend" ("id" TEXT PRIMARY KEY, "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE, "emailKey" TEXT NOT NULL, "sesMessageId" TEXT, "status" TEXT NOT NULL, "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP, "updatedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "EmailSend_userId_emailKey_key" ON "EmailSend" ("userId", "emailKey")`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "EmailSend_sesMessageId_key" ON "EmailSend" ("sesMessageId")`,
  `CREATE INDEX IF NOT EXISTS "EmailSend_createdAt_idx" ON "EmailSend" ("createdAt")`,
  `CREATE TABLE IF NOT EXISTS "EmailEvent" ("id" TEXT PRIMARY KEY, "sendId" TEXT, "eventType" TEXT NOT NULL, "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE TABLE IF NOT EXISTS "EmailTestSend" ("id" TEXT PRIMARY KEY, "adminId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE, "userId" TEXT NOT NULL REFERENCES "User"("id") ON DELETE CASCADE, "emailKey" TEXT NOT NULL, "mode" TEXT NOT NULL, "sesMessageId" TEXT, "status" TEXT NOT NULL, "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP)`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "EmailTestSend_dry_key" ON "EmailTestSend" ("userId", "emailKey", "mode") WHERE "mode" = 'dry-run'`,
];
let ready: Promise<void> | null = null;
export function ensureEmailTables(): Promise<void> {
  if (!ready) ready = (async () => { for (const sql of EMAIL_DDL) await prisma.$executeRawUnsafe(sql); })().catch(e => { ready = null; throw e; });
  return ready;
}
/** Lock the user row in every sending/preferences path. An upgrade or delete serializes with the send transaction. */
export async function lockEmailUser(tx: Prisma.TransactionClient, userId: string) {
  const rows = await tx.$queryRaw<Array<{ id: string }>>`SELECT "id" FROM "User" WHERE "id" = ${userId} FOR UPDATE`;
  return rows.length > 0;
}
export async function setEmailPreference(userId: string, enabled: boolean) {
  await ensureEmailTables();
  return prisma.$transaction(async tx => {
    if (!await lockEmailUser(tx, userId)) return false;
    await tx.emailPreference.upsert({ where: { userId }, create: { userId, marketingOptOut: !enabled, optOutAt: enabled ? null : new Date(), consentAt: enabled ? new Date() : null }, update: { marketingOptOut: !enabled, optOutAt: enabled ? null : new Date(), ...(enabled ? { consentAt: new Date() } : {}) } });
    return true;
  });
}
export async function reserveSend(userId: string, emailKey: EmailKey, now: Date) {
  await ensureEmailTables();
  return prisma.$transaction(async tx => {
    if (!await lockEmailUser(tx, userId)) return null;
    await tx.$executeRaw`SELECT pg_advisory_xact_lock(785217902)`;
    if (await tx.emailSend.count({ where: { createdAt: { gte: new Date(+now - 3_600_000) }, status: { not: "cancelled" } } }) >= 50) return null;
    const history = await tx.emailSend.findMany({ where: { userId, status: { not: "cancelled" } }, orderBy: { createdAt: "desc" } });
    if (history.length >= 6 || history.some(s => s.emailKey === emailKey) || (history[0] && +now - +history[0].createdAt < 44 * 3_600_000)) return null;
    const id = randomUUID();
    await tx.emailSend.create({ data: { id, userId, emailKey, status: "sending", createdAt: now } });
    return id;
  });
}

/** Health telemetry never stores recipients, message bodies or exception details. */
export async function recordSequenceRun(mode: string, status: string, startedAt: Date, examined = 0, sent = 0) {
  try {
    await ensureEmailTables();
    await prisma.$executeRaw`INSERT INTO "EmailSequenceRun" ("id", "mode", "status", "startedAt", "completedAt", "examined", "sent") VALUES (${randomUUID()}, ${mode}, ${status}, ${startedAt}, ${new Date()}, ${examined}, ${sent})`;
  } catch { console.error("Email cron health record unavailable"); }
}
