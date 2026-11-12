import { getAIReviewPreference, reserveAIReviewTokens, settleAIReviewTokens } from "@/lib/ai-review-store";
import { createComplianceRunner } from "@/lib/compliance-runner";
import type { ScanOptions } from "@/lib/scanner";

/** Plan-based compliance options for a website scan. The AI policy review shares the repo AI token budget. */
export async function complianceScanOptions(userId: string | null, plan: string): Promise<ScanOptions> {
  if (!userId) return { compliance: createComplianceRunner({ plan: "free" }) };
  if (plan !== "pro") return { compliance: createComplianceRunner({ plan }) };
  const month = new Date().toISOString().slice(0, 7);
  const aiEnabled = await getAIReviewPreference(userId).catch(() => true);
  return {
    compliance: createComplianceRunner({
      plan,
      aiEnabled,
      aiMeter: {
        reserve: (tokens, cap) => reserveAIReviewTokens(userId, month, tokens, cap),
        settle: (reserved, charged) => settleAIReviewTokens(userId, month, reserved, charged),
      },
    }),
  };
}
