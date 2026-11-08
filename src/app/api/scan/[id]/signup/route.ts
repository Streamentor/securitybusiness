import { NextRequest, NextResponse } from "next/server";
import { creatorToken, sameOrigin, reportHeaders, reportPermission } from "@/lib/report-access";
import { prisma } from "@/lib/db";
import { trackScanFunnel } from "@/lib/scan-funnel";

export async function POST(req: NextRequest, {params}: {params: Promise<{id: string}>}) {
  if (!sameOrigin(req)) return NextResponse.json({error: "Forbidden"}, {status: 403, headers: reportHeaders});
  const {id} = await params;
  const scan = await prisma.scan.findUnique({where: {id}, select: {id: true, userId: true}});
  if (!scan || !(await reportPermission(req, scan)).canClaim) return NextResponse.json({error: "Scan not found"}, {status: 404, headers: reportHeaders});
  await trackScanFunnel("signup", id, undefined, creatorToken(req));
  return new NextResponse(null, {status: 204, headers: reportHeaders});
}
