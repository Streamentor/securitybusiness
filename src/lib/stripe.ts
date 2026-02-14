import Stripe from "stripe";

export const stripe = new Stripe(process.env.STRIPE_SECRET_KEY!, {
  apiVersion: "2026-01-28.clover",
  typescript: true,
});

// ── Stripe Product & Price IDs (created in Stripe Dashboard) ──────────
export const PLANS = {
  starter: {
    name: "Starter",
    productId: "prod_TygHziMgZ7eu60",
    priceId: "price_1T0ivOPIdNed8lkP3I0Ms4pR",
    price: 2900, // $29/mo in cents
    credits: 10,
    maxRollover: 20,
  },
  pro: {
    name: "Pro",
    productId: "prod_TygJufW81WaHZZ",
    priceId: "price_1T0iwcPIdNed8lkPVGj8duZ0",
    price: 7900, // $79/mo in cents
    credits: 30,
    maxRollover: 60,
  },
} as const;

export type PlanKey = keyof typeof PLANS;

/**
 * Get the Stripe price ID for a plan
 */
export function getPriceId(planKey: PlanKey): string {
  return PLANS[planKey].priceId;
}

/**
 * Get credits for a plan key
 */
export function getCreditsForPlan(planKey: string): number {
  if (planKey in PLANS) {
    return PLANS[planKey as PlanKey].credits;
  }
  return 0;
}

/**
 * Resolve plan key from a Stripe price ID
 */
export function getPlanFromPriceId(priceId: string): PlanKey | null {
  for (const [key, plan] of Object.entries(PLANS)) {
    if (plan.priceId === priceId) return key as PlanKey;
  }
  return null;
}
