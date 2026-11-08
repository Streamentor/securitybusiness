import { NextRequest, NextResponse } from "next/server";
import { equalSecret, sequenceMode } from "@/lib/email/config";
import { runEmailSequence } from "@/lib/email/worker";
import { recordSequenceRun } from "@/lib/email/store";
export const maxDuration = 60;
export async function GET(req: NextRequest) {
  const secret = process.env.CRON_SECRET;
  if (!secret || !equalSecret(req.headers.get("authorization") || "", `Bearer ${secret}`)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  const began = new Date();
  try {
    const result = await runEmailSequence();
    if (result.mode !== "off") await recordSequenceRun(result.mode, "completed", began, result.examined, result.sent);
    return NextResponse.json(result, { headers: { "Cache-Control": "private, no-store" } });
  } catch {
    if (sequenceMode() !== "off") await recordSequenceRun(sequenceMode(), "failed", began);
    console.error("Email cron failed"); return NextResponse.json({ error: "Email sequence unavailable" }, { status: 503 });
  }
}
