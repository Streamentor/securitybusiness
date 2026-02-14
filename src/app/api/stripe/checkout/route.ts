import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { stripe, getPriceId, PlanKey, PLANS } from "@/lib/stripe";
import { getSiteUrl } from "@/lib/utils";

export async function POST(req: NextRequest) {
  try {
    const session = await auth();
    if (!session?.user?.id) {
      return NextResponse.json(
        { error: "You must be logged in to subscribe." },
        { status: 401 }
      );
    }

    const { plan } = await req.json();

    if (!plan || !(plan in PLANS)) {
      return NextResponse.json(
        { error: "Invalid plan. Choose 'starter' or 'pro'." },
        { status: 400 }
      );
    }

    const planKey = plan as PlanKey;

    const user = await prisma.user.findUnique({
      where: { id: session.user.id },
      select: { email: true, stripeCustomerId: true, plan: true },
    });

    if (!user) {
      return NextResponse.json(
        { error: "Session expired. Please log out and log in again." },
        { status: 401 }
      );
    }

    // Don't allow subscribing to the same plan
    if (user.plan === planKey) {
      return NextResponse.json(
        { error: "You are already on this plan." },
        { status: 400 }
      );
    }

    // Get or create Stripe customer
    let customerId = user.stripeCustomerId;
    if (!customerId) {
      const customer = await stripe.customers.create({
        email: user.email,
        metadata: { userId: session.user.id },
      });
      customerId = customer.id;

      await prisma.user.update({
        where: { id: session.user.id },
        data: { stripeCustomerId: customerId },
      });
    }

    const priceId = getPriceId(planKey);

    const siteUrl = getSiteUrl();

    // Create checkout session
    const checkoutSession = await stripe.checkout.sessions.create({
      customer: customerId,
      mode: "subscription",
      payment_method_types: ["card"],
      line_items: [{ price: priceId, quantity: 1 }],
      metadata: {
        userId: session.user.id,
        plan: planKey,
      },
      success_url: `${siteUrl}/checkout/success?session_id={CHECKOUT_SESSION_ID}`,
      cancel_url: `${siteUrl}/pricing`,
      subscription_data: {
        metadata: {
          userId: session.user.id,
          plan: planKey,
        },
      },
    });

    return NextResponse.json({ url: checkoutSession.url });
  } catch (error) {
    console.error("Checkout error:", error);
    return NextResponse.json(
      { error: "Failed to create checkout session." },
      { status: 500 }
    );
  }
}
