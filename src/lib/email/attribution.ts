import "server-only";
import { prisma } from "@/lib/db";
import { ensureEmailTables } from "@/lib/email/store";
import { EMAIL_KEYS, type EmailKey } from "@/lib/email/types";
/** Self-reported UTM association, checked against an actual send. Not proof of causation. */
export async function checkoutEmailAttribution(userId: string, campaign: unknown, now = new Date()): Promise<Record<string, string>> {
  if (typeof campaign !== "string" || !EMAIL_KEYS.includes(campaign as EmailKey)) return {};
  await ensureEmailTables();
  const send = await prisma.emailSend.findFirst({ where: { userId, emailKey: campaign, status: { in: ["sent", "delivered"] }, createdAt: { gte: new Date(+now - 7 * 86_400_000), lte: now } }, orderBy: { createdAt: "desc" } });
  return send ? { email_campaign: campaign, email_send_id: send.id } : {};
}
export async function recordEmailConversion(input: { checkoutId: string; userId: string; campaign: string; sendId: string; paidAt: Date }) {
  if (!EMAIL_KEYS.includes(input.campaign as EmailKey) || !Number.isFinite(+input.paidAt)) return;
  await ensureEmailTables();
  const send = await prisma.emailSend.findFirst({ where: { id: input.sendId, userId: input.userId, emailKey: input.campaign, status: { in: ["sent", "delivered", "complaint", "bounced"] } } });
  if (!send || +input.paidAt < +send.createdAt || +input.paidAt - +send.createdAt > 7 * 86_400_000) return;
  await prisma.emailConversion.upsert({ where: { userId: input.userId }, create: { userId: input.userId, checkoutId: input.checkoutId, emailKey: input.campaign, sendId: input.sendId, paidAt: input.paidAt }, update: {} });
}
