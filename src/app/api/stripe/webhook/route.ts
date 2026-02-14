import { NextRequest, NextResponse } from "next/server";
import { stripe, getCreditsForPlan, getPlanFromPriceId } from "@/lib/stripe";
import { prisma } from "@/lib/db";
import Stripe from "stripe";

export async function POST(req: NextRequest) {
  const body = await req.text();
  const signature = req.headers.get("stripe-signature");

  if (!signature) {
    return NextResponse.json({ error: "No signature" }, { status: 400 });
  }

  let event: Stripe.Event;

  try {
    event = stripe.webhooks.constructEvent(
      body,
      signature,
      process.env.STRIPE_WEBHOOK_SECRET!
    );
  } catch (err) {
    console.error("Webhook signature verification failed:", err);
    return NextResponse.json({ error: "Invalid signature" }, { status: 400 });
  }

  try {
    switch (event.type) {
      case "checkout.session.completed": {
        const session = event.data.object as Stripe.Checkout.Session;
        await handleCheckoutCompleted(session);
        break;
      }

      case "invoice.paid": {
        const invoice = event.data.object as Stripe.Invoice;
        await handleInvoicePaid(invoice);
        break;
      }

      case "customer.subscription.deleted": {
        const subscription = event.data.object as Stripe.Subscription;
        await handleSubscriptionDeleted(subscription);
        break;
      }

      case "customer.subscription.updated": {
        const subscription = event.data.object as Stripe.Subscription;
        await handleSubscriptionUpdated(subscription);
        break;
      }

      default:
        break;
    }
  } catch (error) {
    console.error("Webhook handler error:", error);
    return NextResponse.json({ error: "Webhook handler failed" }, { status: 500 });
  }

  return NextResponse.json({ received: true });
}

/**
 * First-time checkout completed — activate subscription, set plan, grant credits
 */
async function handleCheckoutCompleted(session: Stripe.Checkout.Session) {
  const userId = session.metadata?.userId;
  const plan = session.metadata?.plan;

  if (!userId || !plan) {
    console.error("Missing metadata in checkout session:", session.id);
    return;
  }

  const subscriptionId = session.subscription as string;
  const subscription = await stripe.subscriptions.retrieve(subscriptionId);

  const credits = getCreditsForPlan(plan);
  const periodEnd = subscription.items.data[0]?.current_period_end;

  await prisma.user.update({
    where: { id: userId },
    data: {
      plan,
      credits,
      stripeCustomerId: session.customer as string,
      stripeSubscriptionId: subscriptionId,
      stripePriceId: subscription.items.data[0]?.price.id,
      currentPeriodEnd: periodEnd ? new Date(periodEnd * 1000) : null,
    },
  });
}

/**
 * Recurring invoice paid — replenish credits (with rollover cap)
 */
async function handleInvoicePaid(invoice: Stripe.Invoice) {
  // Skip the first invoice (already handled by checkout.session.completed)
  if (invoice.billing_reason === "subscription_create") return;

  // In newer Stripe API, subscription info is in invoice.parent.subscription_details
  const subscriptionId =
    (invoice.parent?.subscription_details?.subscription as string) ?? null;
  if (!subscriptionId) return;

  const subscription = await stripe.subscriptions.retrieve(subscriptionId);
  const plan = subscription.metadata?.plan;

  if (!plan) {
    console.error("Missing plan metadata on subscription:", subscriptionId);
    return;
  }

  const user = await prisma.user.findFirst({
    where: { stripeSubscriptionId: subscriptionId },
    select: { id: true, credits: true },
  });

  if (!user) {
    console.error("No user found for subscription:", subscriptionId);
    return;
  }

  const monthlyCredits = getCreditsForPlan(plan);
  const maxRollover = monthlyCredits * 2;
  const newCredits = Math.min(user.credits + monthlyCredits, maxRollover);
  const periodEnd = subscription.items.data[0]?.current_period_end;

  await prisma.user.update({
    where: { id: user.id },
    data: {
      credits: newCredits,
      currentPeriodEnd: periodEnd ? new Date(periodEnd * 1000) : null,
    },
  });
}

/**
 * Subscription canceled — downgrade to free plan
 */
async function handleSubscriptionDeleted(subscription: Stripe.Subscription) {
  const user = await prisma.user.findFirst({
    where: { stripeSubscriptionId: subscription.id },
    select: { id: true },
  });

  if (!user) return;

  await prisma.user.update({
    where: { id: user.id },
    data: {
      plan: "free",
      stripeSubscriptionId: null,
      stripePriceId: null,
      currentPeriodEnd: null,
    },
  });
}

/**
 * Subscription updated (plan change) — handle upgrades/downgrades
 */
async function handleSubscriptionUpdated(subscription: Stripe.Subscription) {
  const priceId = subscription.items.data[0]?.price.id;
  if (!priceId) return;

  const plan = getPlanFromPriceId(priceId) ?? subscription.metadata?.plan;
  if (!plan) return;

  const user = await prisma.user.findFirst({
    where: { stripeSubscriptionId: subscription.id },
    select: { id: true, plan: true, credits: true },
  });

  if (!user) return;

  // Only act if the plan actually changed
  if (user.plan !== plan) {
    const newCredits = getCreditsForPlan(plan);
    // On upgrade, grant the difference in credits
    const creditAdjustment =
      user.plan === "starter" && plan === "pro"
        ? Math.max(newCredits - 10, 0)
        : newCredits;

    const periodEnd = subscription.items.data[0]?.current_period_end;

    await prisma.user.update({
      where: { id: user.id },
      data: {
        plan,
        credits: user.credits + creditAdjustment,
        stripePriceId: priceId,
        currentPeriodEnd: periodEnd ? new Date(periodEnd * 1000) : null,
      },
    });
  }
}
