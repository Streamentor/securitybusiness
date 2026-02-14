import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { stripe } from "@/lib/stripe";
import { getSiteUrl } from "@/lib/utils";

export async function POST() {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: "You must be logged in." },
        { status: 401 }
      );
    }

    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { stripeCustomerId: true },
    });

    if (!user?.stripeCustomerId) {
      return NextResponse.json(
        { error: "No billing account found. Subscribe to a plan first." },
        { status: 400 }
      );
    }

    const portalSession = await stripe.billingPortal.sessions.create({
      customer: user.stripeCustomerId,
      return_url: `${getSiteUrl()}/dashboard`,
    });

    return NextResponse.json({ url: portalSession.url });
  } catch (error) {
    console.error("Portal error:", error);
    return NextResponse.json(
      { error: "Failed to create billing portal session." },
      { status: 500 }
    );
  }
}
