import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { stripe, getCreditsForPlan } from "@/lib/stripe";

/**
 * POST /api/stripe/verify
 *
 * Fallback for when the Stripe webhook fails (e.g. signature mismatch).
 * The checkout success page calls this with the session_id so we can
 * verify the payment directly with Stripe and activate the subscription.
 */
export async function POST(req: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json({ error: "Not authenticated" }, { status: 401 });
    }

    const { sessionId } = await req.json();
    if (!sessionId) {
      return NextResponse.json({ error: "Missing session_id" }, { status: 400 });
    }

    // Retrieve the checkout session from Stripe
    const checkoutSession = await stripe.checkout.sessions.retrieve(sessionId);

    if (checkoutSession.payment_status !== "paid") {
      return NextResponse.json({ error: "Payment not completed" }, { status: 400 });
    }

    // Verify this checkout belongs to the logged-in user
    const userId = checkoutSession.metadata?.userId;
    if (userId !== session.user.id) {
      return NextResponse.json({ error: "Session mismatch" }, { status: 403 });
    }

    const plan = checkoutSession.metadata?.plan;
    if (!plan) {
      return NextResponse.json({ error: "Missing plan metadata" }, { status: 400 });
    }

    // Check if user is already upgraded (webhook may have succeeded after all)
    const user = await prisma.user.findUnique({
      where: { id: userId },
      select: { plan: true },
    });

    if (user?.plan === plan) {
      // Already activated — nothing to do
      return NextResponse.json({ status: "already_active", plan });
    }

    // Activate the subscription
    const subscriptionId = checkoutSession.subscription as string;
    const subscription = await stripe.subscriptions.retrieve(subscriptionId);

    const credits = getCreditsForPlan(plan);
    const periodEnd = subscription.items.data[0]?.current_period_end;

    await prisma.user.update({
      where: { id: userId },
      data: {
        plan,
        credits,
        stripeCustomerId: checkoutSession.customer as string,
        stripeSubscriptionId: subscriptionId,
        stripePriceId: subscription.items.data[0]?.price.id,
        currentPeriodEnd: periodEnd ? new Date(periodEnd * 1000) : null,
      },
    });

    return NextResponse.json({ status: "activated", plan, credits });
  } catch (error) {
    console.error("Verify error:", error);
    return NextResponse.json(
      { error: "Failed to verify checkout session" },
      { status: 500 }
    );
  }
}
