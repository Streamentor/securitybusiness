import "server-only";
import { createVerify, X509Certificate } from "node:crypto";
import { prisma } from "@/lib/db";
import { ensureEmailTables, lockEmailUser } from "@/lib/email/store";
export interface SnsMessage { Type: string; Message: string; MessageId: string; TopicArn: string; Timestamp: string; SignatureVersion: string; Signature: string; SigningCertURL: string; Subject?: string; SubscribeURL?: string; Token?: string }
export function snsCanonical(m: SnsMessage): string {
  const fields = m.Type === "Notification" ? ["Message", "MessageId", ...(m.Subject !== undefined ? ["Subject"] : []), "Timestamp", "TopicArn", "Type"] : ["Message", "MessageId", "SubscribeURL", "Timestamp", "Token", "TopicArn", "Type"];
  return fields.map(k => `${k}\n${m[k as keyof SnsMessage]}\n`).join("");
}
function snsHost() { const region = process.env.AWS_SES_REGION || ""; if (!/^[a-z]{2}-[a-z]+-\d$/.test(region)) throw new Error("SNS region missing"); return `sns.${region}.amazonaws.com`; }
function safeSnsUrl(value: string, certificate: boolean): URL {
  const url = new URL(value);
  if (url.protocol !== "https:" || url.hostname !== snsHost() || url.port || url.username || url.password || url.hash || (certificate && (!/^\/SimpleNotificationService-[A-Za-z0-9_-]+\.pem$/.test(url.pathname) || url.search))) throw new Error("Invalid SNS URL");
  return url;
}
async function readBounded(response: Response, max: number) {
  if (!response.ok || Number(response.headers.get("content-length")) > max || !response.body) throw new Error("SNS fetch failed");
  const reader = response.body.getReader(); let text = "", size = 0;
  try { while (true) { const { done, value } = await reader.read(); if (done) break; size += value.length; if (size > max) throw new Error("SNS response too large"); text += Buffer.from(value).toString("utf8"); } } finally { await reader.cancel(); }
  return text;
}
const certificates = new Map<string, { pem: string; expires: number }>();
export async function verifySnsMessage(input: unknown): Promise<SnsMessage> {
  if (!input || typeof input !== "object") throw new Error("Invalid SNS message");
  const m = input as SnsMessage;
  const required = ["Type", "Message", "MessageId", "TopicArn", "Timestamp", "SignatureVersion", "Signature", "SigningCertURL"] as const;
  if (required.some(k => typeof m[k] !== "string" || !m[k]) || !["Notification", "SubscriptionConfirmation"].includes(m.Type) || !["1", "2"].includes(m.SignatureVersion)) throw new Error("Invalid SNS message");
  const topic = process.env.AWS_SES_SNS_TOPIC_ARN;
  if (!topic || m.TopicArn !== topic || !topic.startsWith(`arn:aws:sns:${process.env.AWS_SES_REGION}:`)) throw new Error("Unexpected SNS topic");
  const timestamp = Date.parse(m.Timestamp);
  if (!Number.isFinite(timestamp) || timestamp > Date.now() + 5 * 60_000 || timestamp < Date.now() - 30 * 86_400_000) throw new Error("Invalid SNS timestamp");
  if (m.Subject !== undefined && typeof m.Subject !== "string") throw new Error("Invalid SNS subject");
  if (m.Type === "SubscriptionConfirmation" && (typeof m.Token !== "string" || typeof m.SubscribeURL !== "string")) throw new Error("Invalid SNS confirmation");
  const certUrl = safeSnsUrl(m.SigningCertURL, true);
  let cached = certificates.get(certUrl.href);
  if (!cached || cached.expires <= Date.now()) {
    const response = await fetch(certUrl, { redirect: "error", signal: AbortSignal.timeout(5_000) });
    const pem = await readBounded(response, 24_000); const cert = new X509Certificate(pem);
    if (Date.parse(cert.validFrom) > Date.now() || Date.parse(cert.validTo) <= Date.now()) throw new Error("Expired SNS certificate");
    cached = { pem, expires: Math.min(Date.now() + 3_600_000, Date.parse(cert.validTo)) };
    if (certificates.size >= 8) certificates.clear(); certificates.set(certUrl.href, cached);
  }
  const verifier = createVerify(m.SignatureVersion === "2" ? "RSA-SHA256" : "RSA-SHA1"); verifier.update(snsCanonical(m));
  if (!verifier.verify(cached.pem, Buffer.from(m.Signature, "base64"))) throw new Error("Invalid SNS signature");
  return m;
}
export async function handleSnsMessage(m: SnsMessage) {
  if (m.Type === "SubscriptionConfirmation") {
    const url = safeSnsUrl(m.SubscribeURL!, false);
    if (url.pathname !== "/" || url.searchParams.get("Action") !== "ConfirmSubscription" || url.searchParams.get("TopicArn") !== m.TopicArn || url.searchParams.get("Token") !== m.Token) throw new Error("Invalid SNS confirmation URL");
    const response = await fetch(url, { redirect: "error", signal: AbortSignal.timeout(5_000) });
    await readBounded(response, 32_000); return;
  }
  const event = JSON.parse(m.Message) as { eventType?: string; notificationType?: string; mail?: { messageId?: string; tags?: Record<string, string[]> }; bounce?: { bounceType?: string } };
  const kind = event.eventType || event.notificationType;
  if (!kind || !["Bounce", "Complaint", "Reject", "Delivery"].includes(kind) || typeof event.mail?.messageId !== "string") throw new Error("Unsupported SES event");
  await ensureEmailTables();
  const tagged = event.mail.tags?.send_id?.[0];
  const send = await prisma.emailSend.findFirst({ where: { OR: [{ sesMessageId: event.mail.messageId }, ...(typeof tagged === "string" ? [{ id: tagged }] : [])] } });
  const test = send ? null : await prisma.emailTestSend.findFirst({ where: { OR: [{ sesMessageId: event.mail.messageId }, ...(typeof tagged === "string" ? [{ id: tagged }] : [])] } });
  // Test messages belong to the admin recipient, never the user whose preview was rendered.
  const recipient = send?.userId || test?.adminId;
  const suppress = kind === "Complaint" || kind === "Reject" || (kind === "Bounce" && event.bounce?.bounceType === "Permanent");
  await prisma.$transaction(async tx => {
    if (recipient && !await lockEmailUser(tx, recipient)) return;
    const inserted = await tx.$executeRaw`INSERT INTO "EmailEvent" ("id", "sendId", "eventType") VALUES (${m.MessageId}, ${send?.id || test?.id || null}, ${kind}) ON CONFLICT ("id") DO NOTHING`;
    if (!inserted || !recipient) return;
    if (suppress) await tx.emailPreference.upsert({ where: { userId: recipient }, create: { userId: recipient, suppressed: true, suppressedReason: kind }, update: { suppressed: true, suppressedReason: kind } });
    if (send) {
      const current = await tx.emailSend.findUnique({ where: { id: send.id } });
      const terminal = ["bounced", "complaint", "rejected"].includes(current?.status || "");
      const status = kind === "Complaint" ? "complaint" : kind === "Reject" ? "rejected" : kind === "Bounce" ? "bounced" : "delivered";
      if (!terminal || suppress) await tx.emailSend.update({ where: { id: send.id }, data: { status, sesMessageId: event.mail!.messageId } });
    } else if (test) await tx.emailTestSend.update({ where: { id: test.id }, data: { status: kind.toLowerCase(), sesMessageId: event.mail!.messageId } });
  });
}
