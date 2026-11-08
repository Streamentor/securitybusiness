import "server-only";
import { createHmac } from "node:crypto";
import { equalSecret, ORIGIN } from "@/lib/email/config";
function secret() { const key = process.env.EMAIL_UNSUBSCRIBE_SECRET || ""; if (Buffer.byteLength(key) < 32) throw new Error("Email unsubscribe secret missing"); return key; }
export function unsubscribeToken(userId: string): string {
  const id = Buffer.from(userId).toString("base64url");
  return `${id}.${createHmac("sha256", secret()).update(`unsubscribe:v1:${id}`).digest("base64url")}`;
}
export function verifyUnsubscribeToken(token: string): string | null {
  if (token.length > 512 || !/^[A-Za-z0-9_-]+\.[A-Za-z0-9_-]{43}$/.test(token)) return null;
  const encoded = token.split(".")[0]; const id = Buffer.from(encoded, "base64url").toString();
  if (!id || Buffer.from(id).toString("base64url") !== encoded) return null;
  return equalSecret(token, unsubscribeToken(id)) ? id : null;
}
export function unsubscribeUrl(userId: string) { return `${ORIGIN}/api/email/unsubscribe?t=${unsubscribeToken(userId)}`; }
