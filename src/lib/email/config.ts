import "server-only";
import { timingSafeEqual } from "node:crypto";
export const ORIGIN = "https://www.scanmysaas.com";
export type SequenceMode = "off" | "dry-run" | "live";
export function sequenceMode(): SequenceMode {
  if (process.env.VERCEL_ENV !== "production") return "off";
  return process.env.EMAIL_SEQUENCE_MODE === "live" ? "live" : process.env.EMAIL_SEQUENCE_MODE === "dry-run" ? "dry-run" : "off";
}
export function startAt(): Date | null {
  const value = process.env.EMAIL_SEQUENCE_START_AT;
  if (!value || !/^\d{4}-\d\d-\d\dT/.test(value)) return null;
  const date = new Date(value); return Number.isFinite(+date) ? date : null;
}
export function equalSecret(left: string, right: string): boolean {
  const a = Buffer.from(left), b = Buffer.from(right);
  return a.length === b.length && timingSafeEqual(a, b);
}
export function validEmail(value: string): boolean { return value.length <= 254 && /^[^\s<>@]+@[^\s<>@]+\.[^\s<>@]+$/.test(value); }
export function deliveryConfig() {
  const region = process.env.AWS_SES_REGION || "";
  const from = process.env.EMAIL_FROM || "";
  const replyTo = process.env.EMAIL_REPLY_TO || "";
  const address = process.env.EMAIL_POSTAL_ADDRESS || "";
  if (!/^[a-z]{2}-[a-z]+-\d$/.test(region) || !/^Stefan from ScanMySaaS <[^<>\r\n]+@scanmysaas\.com>$/.test(from) || !validEmail(replyTo) || !address.trim() || /[\r\n]/.test(address) || !process.env.AWS_SES_ACCESS_KEY_ID || !process.env.AWS_SES_SECRET_ACCESS_KEY || !process.env.AWS_SES_SNS_TOPIC_ARN) throw new Error("Email configuration incomplete");
  return { region, from, replyTo, address, configurationSet: "scanmysaas-onboarding" };
}
