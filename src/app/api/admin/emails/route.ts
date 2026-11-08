import { NextRequest, NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin";
import { prisma } from "@/lib/db";
import { sameOrigin, reportHeaders } from "@/lib/report-access";
import { ensureEmailTables } from "@/lib/email/store";
import { sequenceMode } from "@/lib/email/config";
import { loadEmailContext } from "@/lib/email/context";
import { renderEmail } from "@/lib/email/templates";
import { sendAdminTest } from "@/lib/email/worker";
import { EMAIL_KEYS, type EmailKey } from "@/lib/email/types";
export async function GET() {
  const access = await requireAdmin(); if (!access.authorized) return NextResponse.json({ error: access.error }, { status: 403 });
  await ensureEmailTables();
  const [counts, recent, unsubscribes, suppressed, events, tests, conversions] = await Promise.all([
    prisma.emailSend.groupBy({ by: ["emailKey", "status"], _count: true }),
    prisma.emailSend.findMany({ orderBy: { createdAt: "desc" }, take: 50, select: { id: true, userId: true, emailKey: true, status: true, createdAt: true } }),
    prisma.emailPreference.count({ where: { marketingOptOut: true } }), prisma.emailPreference.count({ where: { suppressed: true } }),
    prisma.emailEvent.groupBy({ by: ["eventType"], _count: true }),
    prisma.emailTestSend.findMany({ orderBy: { createdAt: "desc" }, take: 50, select: { id: true, emailKey: true, mode: true, status: true, createdAt: true } }),
    prisma.emailConversion.groupBy({ by: ["emailKey"], _count: true }),
  ]);
  return NextResponse.json({ conversions, mode: sequenceMode(), keys: EMAIL_KEYS, counts, recent, unsubscribes, suppressed, events, tests }, { headers: reportHeaders });
}
export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  const access = await requireAdmin(); if (!access.authorized) return NextResponse.json({ error: access.error }, { status: 403 });
  try {
    const data = await req.json();
    if (typeof data.userId !== "string" || data.userId.length > 200 || !EMAIL_KEYS.includes(data.key) || !["preview", "test"].includes(data.action)) return NextResponse.json({ error: "Choose a user, email key and action" }, { status: 400 });
    const c = await loadEmailContext(data.userId); if (!c) return NextResponse.json({ error: "User not found" }, { status: 404 });
    if (data.action === "preview") {
      const email = renderEmail(data.key as EmailKey, c, process.env.EMAIL_POSTAL_ADDRESS || "[postal address required before sending]");
      return NextResponse.json({ subject: email.subject, text: email.text }, { headers: reportHeaders });
    }
    const sent = await sendAdminTest(c, data.key, "test", access.userId);
    return NextResponse.json({ sent, note: "Test delivery targets your admin address only." }, { headers: reportHeaders });
  } catch { return NextResponse.json({ error: "Email unavailable: check the selected user's scan and sending configuration" }, { status: 400 }); }
}
