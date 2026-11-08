import "server-only";
import { SESv2Client, SendEmailCommand } from "@aws-sdk/client-sesv2";
import { deliveryConfig, validEmail } from "@/lib/email/config";
import type { RenderedEmail } from "@/lib/email/types";
export async function sendEmail(to: string, email: RenderedEmail, sendId: string, subjectPrefix = "") {
  const cfg = deliveryConfig();
  if (!validEmail(to) || /[\r\n]/.test(subjectPrefix)) throw new Error("Invalid recipient");
  const client = new SESv2Client({ region: cfg.region, maxAttempts: 1, credentials: { accessKeyId: process.env.AWS_SES_ACCESS_KEY_ID!, secretAccessKey: process.env.AWS_SES_SECRET_ACCESS_KEY! } });
  try {
    const result = await client.send(new SendEmailCommand({
      FromEmailAddress: cfg.from, ReplyToAddresses: [cfg.replyTo], Destination: { ToAddresses: [to] }, ConfigurationSetName: cfg.configurationSet,
      EmailTags: [{ Name: "send_id", Value: sendId }],
      Content: { Simple: { Subject: { Data: subjectPrefix + email.subject, Charset: "UTF-8" }, Body: { Text: { Data: email.text, Charset: "UTF-8" }, Html: { Data: email.html, Charset: "UTF-8" } }, Headers: [
        { Name: "List-Unsubscribe", Value: `<${email.unsubscribeUrl}>, <mailto:${cfg.replyTo}?subject=unsubscribe>` },
        { Name: "List-Unsubscribe-Post", Value: "List-Unsubscribe=One-Click" },
      ] } },
    }), { abortSignal: AbortSignal.timeout(8_000) });
    if (!result.MessageId) throw new Error("SES response missing message id");
    return result.MessageId;
  } finally { client.destroy(); }
}
