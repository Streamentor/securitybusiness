import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin";
import { prisma } from "@/lib/db";
import type { Prisma } from "@/generated/prisma/client";
import { reportHeaders } from "@/lib/report-access";
import { ensureEmailTables } from "@/lib/email/store";
import { loadEmailContext } from "@/lib/email/context";
import { sequenceMode, startAt } from "@/lib/email/config";
import { eligibilityReason } from "@/lib/email/policy";
import { emailJourney } from "@/lib/email/journey";
export const maxDuration = 60;
export async function GET(req: NextRequest) {
  const access = await requireAdmin();
  if (!access.authorized) return NextResponse.json({ error: access.error }, { status: 403, headers: reportHeaders });
  try {
    await ensureEmailTables();
    const mode = sequenceMode(), start = startAt(), now = new Date();
    const id = req.nextUrl.searchParams.get("userId");
    if (id) {
      if (id.length > 200) return NextResponse.json({ error: "Invalid user ID" }, { status: 400, headers: reportHeaders });
      const c = await loadEmailContext(id);
      if (!c) return NextResponse.json({ error: "User not found" }, { status: 404, headers: reportHeaders });
      const [sends, tests, preference, conversion] = await Promise.all([
        prisma.emailSend.findMany({ where: { userId: id }, orderBy: { createdAt: "asc" }, select: { id: true, emailKey: true, status: true, createdAt: true, updatedAt: true } }),
        prisma.emailTestSend.findMany({ where: { userId: id }, orderBy: { createdAt: "desc" }, take: 20, select: { emailKey: true, mode: true, status: true, createdAt: true } }),
        prisma.emailPreference.findUnique({ where: { userId: id }, select: { consentAt: true, optOutAt: true, suppressedReason: true, lastSequenceCheckAt: true } }),
        prisma.emailConversion.findUnique({ where: { userId: id }, select: { emailKey: true, paidAt: true } }),
      ]);
      const events = sends.length ? await prisma.emailEvent.findMany({ where: { sendId: { in: sends.map(s => s.id) } }, orderBy: { createdAt: "desc" }, take: 50, select: { sendId: true, eventType: true, createdAt: true } }) : [];
      return NextResponse.json({ mode, startAt: start, asOf: now, user: { id, name: c.name, email: c.email, plan: c.plan, createdAt: c.createdAt, domain: c.scan?.domain || null, websiteScanned: !!c.scan, repoScanned: !!c.repo, repoFindings: c.repo?.count ?? null }, preference, conversion, journey: emailJourney(c, sends, now, start, mode), sends, events, tests }, { headers: reportHeaders });
    }
    const query = (req.nextUrl.searchParams.get("q") || "").trim().slice(0, 120);
    const page = Math.min(10000, Math.max(1, Number(req.nextUrl.searchParams.get("page")) || 1));
    if (!Number.isInteger(page)) return NextResponse.json({ error: "Invalid page" }, { status: 400, headers: reportHeaders });
    const filter = req.nextUrl.searchParams.get("filter") || "all";
    const enrolled: Prisma.UserWhereInput = { plan: "free", ...(start ? { createdAt: { gte: start } } : { id: "__not_configured__" }), emailPreference: { is: { consentAt: { not: null }, marketingOptOut: false, suppressed: false } } };
    const filters: Record<string, Prisma.UserWhereInput> = { all: {}, enrolled, sent: { emailSends: { some: { status: { not: "cancelled" } } } }, unsubscribed: { emailPreference: { is: { marketingOptOut: true } } }, suppressed: { emailPreference: { is: { suppressed: true } } }, paid: { plan: { not: "free" } } };
    if (!Object.hasOwn(filters, filter)) return NextResponse.json({ error: "Invalid filter" }, { status: 400, headers: reportHeaders });
    const where: Prisma.UserWhereInput = { AND: [filters[filter], ...(query ? [{ OR: [{ email: { contains: query, mode: "insensitive" as const } }, { name: { contains: query, mode: "insensitive" as const } }, { id: query }] }] : [])] };
    const [total, users, eligibleAccounts, sentCount, deliveredCount, unknownCount, runs] = await Promise.all([
      prisma.user.count({ where }),
      prisma.user.findMany({ where, orderBy: [{ createdAt: "desc" }, { id: "desc" }], skip: (page - 1) * 20, take: 20, select: { id: true, email: true, name: true, plan: true, createdAt: true, emailPreference: { select: { marketingOptOut: true, suppressed: true, suppressedReason: true, consentAt: true, lastSequenceCheckAt: true } }, emailSends: { orderBy: { createdAt: "desc" }, select: { emailKey: true, status: true, createdAt: true } } } }),
      prisma.user.count({ where: enrolled }), prisma.emailSend.count({ where: { status: { not: "cancelled" } } }), prisma.emailSend.count({ where: { status: "delivered" } }), prisma.emailSend.count({ where: { status: { in: ["unknown", "sending"] } } }),
      prisma.$queryRaw<Array<{ id: string; mode: string; status: string; startedAt: Date; completedAt: Date; examined: number; sent: number }>>`SELECT * FROM "EmailSequenceRun" ORDER BY "startedAt" DESC LIMIT 5`,
    ]);
    return NextResponse.json({ mode, startAt: start, asOf: now, page, pageSize: 20, total, metrics: { eligibleAccounts, sentCount, deliveredCount, unknownCount }, runs, users: users.map(u => {
      const p = u.emailPreference, used = u.emailSends.filter(s => s.status !== "cancelled");
      const reason = eligibilityReason({ ...u, optedOut: p?.marketingOptOut ?? false, suppressed: p?.suppressed ?? false, consentAt: p?.consentAt ?? null }, start);
      return { id: u.id, email: u.email, name: u.name, plan: u.plan, createdAt: u.createdAt, status: reason ? "excluded" : used.length >= 6 ? "complete" : mode === "live" ? "enrolled" : "paused", reason: reason || (used.length >= 6 ? "Six-message limit reached" : "Open timeline for the next eligible step"), used: used.length, last: used[0] || null, lastCheckedAt: p?.lastSequenceCheckAt || null };
    }) }, { headers: reportHeaders });
  } catch { console.error("Email journey admin read failed"); return NextResponse.json({ error: "Could not load email journeys. Retry shortly." }, { status: 503, headers: reportHeaders }); }
}
