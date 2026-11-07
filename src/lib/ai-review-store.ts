import { prisma } from "@/lib/db";
import { ensureRepoTables } from "@/lib/repo-store";

export async function getAIReviewPreference(userId: string) {
  await ensureRepoTables();
  const preference = await prisma.aIReviewPreference.findUnique({where: {userId}});
  return preference?.enabled ?? true;
}
/** One atomic debit shared by all instances. A crashed job retains its reservation. */
export async function reserveAIReviewTokens(userId: string, month: string, tokens: number, cap: number) {
  await ensureRepoTables();
  if (!Number.isSafeInteger(tokens) || tokens <= 0 || tokens > cap) return false;
  const rows = await prisma.$queryRaw<{userId: string}[]>`
    INSERT INTO "AIReviewUsage" ("userId", "month", "chargedTokens")
    VALUES (${userId}, ${month}, ${tokens})
    ON CONFLICT ("userId", "month") DO UPDATE
    SET "chargedTokens" = "AIReviewUsage"."chargedTokens" + ${tokens}
    WHERE "AIReviewUsage"."chargedTokens" + ${tokens} <= ${cap}
    RETURNING "userId"`;
  return rows.length === 1;
}
export async function settleAIReviewTokens(userId: string, month: string, reserved: number, charged: number) {
  // Only release the unused part. Failed/unknown API usage is charged at the upper bound.
  const release = Math.max(0, reserved - charged);
  if (release) await prisma.$executeRaw`
    UPDATE "AIReviewUsage" SET "chargedTokens" = GREATEST(0, "chargedTokens" - ${release})
    WHERE "userId" = ${userId} AND "month" = ${month}`;
}
