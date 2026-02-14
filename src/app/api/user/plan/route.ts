import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

export async function GET() {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({
        plan: "anonymous",
        credits: 0,
        scansUsed: 0,
        hasSubscription: false,
        currentPeriodEnd: null,
      });
    }

    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: {
        plan: true,
        credits: true,
        scansUsed: true,
        stripeSubscriptionId: true,
        currentPeriodEnd: true,
        email: true,
        name: true,
        createdAt: true,
      },
    });

    if (!user) {
      return NextResponse.json({
        plan: "anonymous",
        credits: 0,
        scansUsed: 0,
        hasSubscription: false,
        currentPeriodEnd: null,
      });
    }

    return NextResponse.json({
      plan: user.plan,
      credits: user.credits,
      scansUsed: user.scansUsed,
      hasSubscription: !!user.stripeSubscriptionId,
      currentPeriodEnd: user.currentPeriodEnd?.toISOString() || null,
      email: user.email,
      name: user.name,
      memberSince: user.createdAt.toISOString(),
    });
  } catch {
    return NextResponse.json({
      plan: "anonymous",
      credits: 0,
      scansUsed: 0,
      hasSubscription: false,
      currentPeriodEnd: null,
    });
  }
}
