import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin";
import { scanFunnelMetrics } from "@/lib/scan-funnel";
const headers = {"Cache-Control": "private, no-store"};
export async function GET() {
  const check = await requireAdmin();
  if (!check.authorized) return NextResponse.json({error: check.error}, {status: 403, headers});
  try { return NextResponse.json(await scanFunnelMetrics(), {headers}); }
  catch { return NextResponse.json({error: "Scan funnel unavailable"}, {status: 503, headers}); }
}
