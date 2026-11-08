import { prisma } from "@/lib/db";
import { ensureReportAccess, tokenHash } from "@/lib/report-access";
import { validPendingScanId } from "@/lib/scan-auth-return";

let ready: Promise<unknown> | null = null;
export function ensureScanFunnel() {
  return ready ??= (async () => {
    await ensureReportAccess();
    await prisma.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS "ScanFunnel" (
      "scanId" TEXT PRIMARY KEY REFERENCES "Scan"("id") ON DELETE CASCADE,
      "signupClickedAt" TIMESTAMP(3), "registeredAt" TIMESTAMP(3),
      "registeredUserId" TEXT, "claimedAt" TIMESTAMP(3), "upgradedAt" TIMESTAMP(3)
    )`);
    await prisma.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS "ScanFunnelRollout" (
      "id" INTEGER PRIMARY KEY CHECK ("id" = 1), "startedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
    )`);
    await prisma.$executeRawUnsafe(`INSERT INTO "ScanFunnelRollout" ("id") VALUES (1) ON CONFLICT DO NOTHING`);
  })().catch(error => { ready = null; throw error; });
}

/** Telemetry must never block registration, claiming, or billing. No PII in logs. */
export async function trackScanFunnel(event: "signup" | "registered" | "claimed" | "upgraded", scanId?: unknown, userId?: string, creatorProof?: string) {
  try {
    await ensureScanFunnel();
    if (event === "upgraded") {
      if (userId) await prisma.$executeRawUnsafe(`UPDATE "ScanFunnel" SET "upgradedAt" = CURRENT_TIMESTAMP WHERE "registeredUserId" = $1 AND "upgradedAt" IS NULL AND "claimedAt" IS NOT NULL`, userId);
      return;
    }
    const id = validPendingScanId(scanId);
    if (!id) return;
    // signup and registered are tied to the actual anonymous browser, not a supplied ID.
    if (event === "signup" || event === "registered") {
      if (!creatorProof || !/^[A-Za-z0-9_-]{43}$/.test(creatorProof)) return;
      const proof = await prisma.websiteReportAccess.findUnique({where: {scanId: id}});
      if (proof?.creatorHash !== tokenHash(creatorProof)) return;
      const scan = await prisma.scan.findUnique({where: {id}, select: {userId: true}});
      if (!scan || scan.userId) return;
    } else {
      const scan = await prisma.scan.findUnique({where: {id}, select: {userId: true}});
      if (!userId || scan?.userId !== userId) return;
    }
    if (event === "signup") await prisma.$executeRawUnsafe(`INSERT INTO "ScanFunnel" ("scanId", "signupClickedAt") VALUES ($1, CURRENT_TIMESTAMP) ON CONFLICT ("scanId") DO UPDATE SET "signupClickedAt" = COALESCE("ScanFunnel"."signupClickedAt", EXCLUDED."signupClickedAt")`, id);
    if (event === "registered" && userId) await prisma.$executeRawUnsafe(`INSERT INTO "ScanFunnel" ("scanId", "registeredAt", "registeredUserId") VALUES ($1, CURRENT_TIMESTAMP, $2) ON CONFLICT ("scanId") DO UPDATE SET "registeredAt" = COALESCE("ScanFunnel"."registeredAt", EXCLUDED."registeredAt"), "registeredUserId" = COALESCE("ScanFunnel"."registeredUserId", EXCLUDED."registeredUserId")`, id, userId);
    if (event === "claimed") await prisma.$executeRawUnsafe(`INSERT INTO "ScanFunnel" ("scanId", "claimedAt") VALUES ($1, CURRENT_TIMESTAMP) ON CONFLICT ("scanId") DO UPDATE SET "claimedAt" = COALESCE("ScanFunnel"."claimedAt", EXCLUDED."claimedAt")`, id);
  } catch { console.error("Scan funnel event unavailable"); }
}

export async function scanFunnelMetrics(now = new Date()) {
  await ensureScanFunnel();
  const [rollout] = await prisma.$queryRawUnsafe<Array<{startedAt: Date}>>(`SELECT "startedAt" FROM "ScanFunnelRollout" WHERE "id" = 1`);
  const start = rollout.startedAt;
  const days = 14 * 86400000;
  const end = new Date(Math.min(start.getTime() + days, now.getTime()));
  async function cohort(from: Date, to: Date) {
    const [row] = await prisma.$queryRawUnsafe<Array<{started: number; completed: number; signup: number; registered: number; claimed: number; upgraded: number}>>(`SELECT
      COUNT(*)::int AS "started",
      COUNT(*) FILTER (WHERE s."status" = 'completed')::int AS "completed",
      COUNT(*) FILTER (WHERE f."signupClickedAt" IS NOT NULL)::int AS "signup",
      COUNT(*) FILTER (WHERE f."registeredAt" IS NOT NULL)::int AS "registered",
      COUNT(*) FILTER (WHERE s."userId" IS NOT NULL)::int AS "claimed",
      COUNT(*) FILTER (WHERE f."upgradedAt" IS NOT NULL)::int AS "upgraded"
      FROM "Scan" s JOIN "WebsiteReportAccess" a ON a."scanId" = s."id" AND a."creatorHash" IS NOT NULL
      LEFT JOIN "ScanFunnel" f ON f."scanId" = s."id"
      WHERE s."createdAt" >= $1 AND s."createdAt" < $2`, from, to);
    return {...row, from: from.toISOString(), to: to.toISOString()};
  }
  const before = await cohort(new Date(start.getTime() - days), start);
  const after = await cohort(start, end);
  return {startedAt: start.toISOString(), partial: end.getTime() < start.getTime() + days, before: {...before, signup: null, registered: null, upgraded: null}, after};
}
