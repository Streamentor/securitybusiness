import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { ensureRepoTables } from "@/lib/repo-store";
import { canReviewWithAI } from "@/lib/ai-review";
import { getAIReviewPreference } from "@/lib/ai-review-store";

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({error: "Sign in first."}, {status: 401});
  try {
    const user = await prisma.user.findUnique({where: {id: session.user.id}, select: {plan: true, role: true}});
    return NextResponse.json({eligible: !!user && canReviewWithAI(user), enabled: await getAIReviewPreference(session.user.id)}, {headers: {"Cache-Control": "private, no-store"}});
  } catch { return NextResponse.json({error: "AI settings could not be loaded."}, {status: 503}); }
}
export async function PATCH(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({error: "Sign in first."}, {status: 401});
  // Reject cross-origin mutations; the user ID always comes from the session.
  if (request.headers.get("origin") !== new URL(request.url).origin) return NextResponse.json({error: "Invalid origin."}, {status: 403});
  const body = await request.json().catch(() => null);
  if (typeof body?.enabled !== "boolean" || Object.keys(body).length !== 1) return NextResponse.json({error: "Choose whether AI review is enabled."}, {status: 400});
  try {
    await ensureRepoTables();
    await prisma.aIReviewPreference.upsert({where: {userId: session.user.id}, create: {userId: session.user.id, enabled: body.enabled}, update: {enabled: body.enabled}});
    return NextResponse.json({enabled: body.enabled}, {headers: {"Cache-Control": "private, no-store"}});
  } catch { return NextResponse.json({error: "AI settings could not be saved."}, {status: 503}); }
}
