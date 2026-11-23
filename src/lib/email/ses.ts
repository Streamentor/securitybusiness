import "server-only";
import { SESv2Client, SendEmailCommand, type Message } from "@aws-sdk/client-sesv2";
import { deliveryConfig, sendingConfig, validEmail } from "@/lib/email/config";
import type { RenderedEmail } from "@/lib/email/types";

async function sendMessage(cfg: ReturnType<typeof sendingConfig>, to: string, message: Message, tag: { Name: string; Value: string }) {
  if (!validEmail(to) || /[\r\n]/.test(message.Subject?.Data ?? "")) throw new Error("Invalid email envelope");
  const client = new SESv2Client({ region: cfg.region, maxAttempts: 1, credentials: { accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID!, secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY! } });
  try {
    const result = await client.send(new SendEmailCommand({
      FromEmailAddress: cfg.from, ReplyToAddresses: [cfg.replyTo], Destination: { ToAddresses: [to] }, ConfigurationSetName: cfg.configurationSet,
      EmailTags: [tag],
      Content: { Simple: message },
    }), { abortSignal: AbortSignal.timeout(8_000) });
    if (!result.MessageId) throw new Error("SES response missing message id");
    return result.MessageId;
  } finally { client.destroy(); }
}

export function sendEmail(to: string, email: RenderedEmail, sendId: string, subjectPrefix = "") {
  const cfg = deliveryConfig();
  return sendMessage(cfg, to, {
    Subject: { Data: subjectPrefix + email.subject, Charset: "UTF-8" },
    Body: { Text: { Data: email.text, Charset: "UTF-8" }, Html: { Data: email.html, Charset: "UTF-8" } },
    Headers: [
      { Name: "List-Unsubscribe", Value: `<${email.unsubscribeUrl}>, <mailto:${cfg.replyTo}?subject=unsubscribe>` },
      { Name: "List-Unsubscribe-Post", Value: "List-Unsubscribe=One-Click" },
    ],
  }, { Name: "send_id", Value: sendId });
}

export function sendPlanPurchaseEmail(to: string, subject: string, text: string, invoiceId: string) {
  return sendMessage(sendingConfig(), to, {
    Subject: { Data: subject, Charset: "UTF-8" },
    Body: { Text: { Data: text, Charset: "UTF-8" } },
  }, { Name: "purchase_invoice", Value: invoiceId });
}
