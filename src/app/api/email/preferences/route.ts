import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { sameOrigin, reportHeaders } from "@/lib/report-access";
import { ensureEmailTables, setEmailPreference } from "@/lib/email/store";
export async function GET() {
  const session = await auth(); if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  await ensureEmailTables();
  const pref = await prisma.emailPreference.findUnique({ where: { userId: session.user.id } });
  return NextResponse.json({ enabled: !!pref?.consentAt && !pref.marketingOptOut, suppressed: pref?.suppressed || false }, { headers: reportHeaders });
}
export async function POST(req: NextRequest) {
  if (!sameOrigin(req)) return NextResponse.json({ error: "Forbidden" }, { status: 403 });
  const session = await auth(); if (!session?.user?.id) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  try {
    const data = await req.json(); if (typeof data.enabled !== "boolean") return NextResponse.json({ error: "enabled must be boolean" }, { status: 400 });
    if (!await setEmailPreference(session.user.id, data.enabled)) return NextResponse.json({ error: "Account not found" }, { status: 404 });
    return GET();
  } catch { return NextResponse.json({ error: "Unable to save preference" }, { status: 503 }); }
}
