import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { ensureReportAccess, newReportToken, reportHeaders, sameOrigin, tokenHash } from "@/lib/report-access";

async function changeLink(request: NextRequest, id: string, enable: boolean) {
  if (!sameOrigin(request)) return NextResponse.json({error: "Forbidden"}, {status: 403, headers: reportHeaders});
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({error: "Unauthorized"}, {status: 401, headers: reportHeaders});
  const scan = await prisma.scan.findFirst({where: {id, userId: session.user.id}, select: {id: true}});
  if (!scan) return NextResponse.json({error: "Scan not found"}, {status: 404, headers: reportHeaders});
  await ensureReportAccess();
  const token = enable ? newReportToken() : null;
  await prisma.websiteReportAccess.upsert({where: {scanId: id}, create: {scanId: id, shareHash: token ? tokenHash(token) : null}, update: {shareHash: token ? tokenHash(token) : null}});
  // Fragment stays out of HTTP access logs and Referer; the page sends it in a header.
  return NextResponse.json({enabled: enable, url: token ? `${new URL(request.url).origin}/scan/${encodeURIComponent(id)}#share=${token}` : null}, {headers: reportHeaders});
}
export async function POST(request: NextRequest, {params}: {params: Promise<{id: string}>}) {
  try { return await changeLink(request, (await params).id, true); }
  catch { return NextResponse.json({error: "Could not create sharing link"}, {status: 503, headers: reportHeaders}); }
}
export async function DELETE(request: NextRequest, {params}: {params: Promise<{id: string}>}) {
  try { return await changeLink(request, (await params).id, false); }
  catch { return NextResponse.json({error: "Could not revoke sharing link"}, {status: 503, headers: reportHeaders}); }
}
