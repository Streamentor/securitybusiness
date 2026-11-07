import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin";
import { prisma } from "@/lib/db";
import { percent, summarizeChannels, summarizeStatuses } from "@/lib/activation-metrics";

const RESPONSE_HEADERS = { "Cache-Control": "private, no-store" };
const WINDOW_DAYS = 30;

async function readWindow(start: Date, end: Date) {
  const createdAt = { gte: start, lt: end };
  const websiteScan = { createdAt, OR: [{ userId: null }, { user: { role: { not: "admin" } } }] };
  const newUser = { createdAt, role: { not: "admin" } };
  const readableScan = { createdAt, status: "completed", pagesScanned: { gt: 0 } };
  const [registrations, startedUsers, completedUsers, statuses, readableCompleted, anonymousStatuses] = await Promise.all([
    prisma.user.groupBy({ by: ["referrerSource"], where: newUser, _count: { _all: true } }),
    prisma.user.groupBy({ by: ["referrerSource"], where: { ...newUser, scans: { some: { createdAt } } }, _count: { _all: true } }),
    prisma.user.groupBy({ by: ["referrerSource"], where: { ...newUser, scans: { some: readableScan } }, _count: { _all: true } }),
    prisma.scan.groupBy({ by: ["status"], where: websiteScan, _count: { _all: true } }),
    prisma.scan.count({ where: { ...websiteScan, status: "completed", pagesScanned: { gt: 0 } } }),
    prisma.scan.groupBy({ by: ["status"], where: { createdAt, userId: null }, _count: { _all: true } }),
  ]);
  const scanTotals = summarizeStatuses(statuses);
  return {
    start: start.toISOString(),
    endExclusive: end.toISOString(),
    registrations: registrations.reduce((sum, row) => sum + row._count._all, 0),
    channelCohorts: summarizeChannels(registrations, startedUsers, completedUsers),
    websiteScans: { ...scanTotals, readableCompleted, readableCompletionPercent: percent(readableCompleted, scanTotals.accepted) },
    unclaimedAnonymousWebsiteScans: summarizeStatuses(anonymousStatuses),
  };
}

/** Aggregate product outcomes only; intentionally separate from the raw admin lists. */
export async function GET() {
  try {
    const check = await requireAdmin();
    if (!check.authorized) return NextResponse.json({ error: check.error }, { status: 403, headers: RESPONSE_HEADERS });

    const now = new Date();
    const currentStart = new Date(now.getTime() - WINDOW_DAYS * 24 * 60 * 60 * 1000);
    const previousStart = new Date(currentStart.getTime() - WINDOW_DAYS * 24 * 60 * 60 * 1000);
    // Fixed windows and aggregate-only queries bound the report surface. No raw
    // user, URL, finding, credential, billing identifier or arbitrary source is returned.
    const current = await readWindow(currentStart, now);
    const previous = await readWindow(previousStart, currentStart);
    return NextResponse.json({
      schemaVersion: 1,
      observedAt: now.toISOString(),
      windowDays: WINDOW_DAYS,
      current,
      previous,
      limitations: [
        "Website scan counts are stored attempts, not button clicks; validation, credit and domain rejections are not counted.",
        "Statuses are observed now for scans created in each window, so late completion can change earlier cohorts.",
        "Readable means a completed record with pagesScanned > 0; historical records before scanner corrections may overstate actual coverage.",
        "Channel cohorts are new non-admin registrations with linked website scans created in the same window, including later-claimed anonymous scans; they do not establish event order.",
        "Attribution is the stored registration source, not visitor traffic or the source of every scan; unknown sources are grouped as other.",
        "Unclaimed anonymous scans have no channel attribution. Claiming a report can change historical ownership counts.",
        "Admin-owned activity is excluded; other internal or test accounts cannot be distinguished automatically.",
        "Repository scans, prompt copies, verified fixes, repeat same-app tests and payment revenue are not measured by this endpoint.",
        "Adjacent rolling 30-day cohorts are descriptive snapshots; different follow-up time and changing attribution coverage limit comparisons.",
      ],
    }, { headers: RESPONSE_HEADERS });
  } catch {
    return NextResponse.json({ error: "Failed to fetch aggregate metrics" }, { status: 500, headers: RESPONSE_HEADERS });
  }
}
