import { NextRequest, NextResponse } from "next/server";
import { equalSecret } from "@/lib/email/config";
import { runEmailSequence } from "@/lib/email/worker";
export const maxDuration = 60;
export async function GET(req: NextRequest) {
  const secret = process.env.CRON_SECRET;
  if (!secret || !equalSecret(req.headers.get("authorization") || "", `Bearer ${secret}`)) return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
  try { return NextResponse.json(await runEmailSequence(), { headers: { "Cache-Control": "private, no-store" } }); }
  catch { console.error("Email cron failed"); return NextResponse.json({ error: "Email sequence unavailable" }, { status: 503 }); }
}
