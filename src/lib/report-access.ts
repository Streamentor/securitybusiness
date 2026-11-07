import { createHash, randomBytes, timingSafeEqual } from "node:crypto";
import type { NextRequest } from "next/server";
import { prisma } from "@/lib/db";

const CREATOR_COOKIE = "scan-report-creator";
let ready: Promise<unknown> | null = null;
export function ensureReportAccess() {
  return ready ??= prisma.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS "WebsiteReportAccess" (
    "scanId" TEXT PRIMARY KEY REFERENCES "Scan"("id") ON DELETE CASCADE,
    "creatorHash" TEXT,
    "shareHash" TEXT
  )`).catch((error) => { ready = null; throw error; });
}
export const newReportToken = () => randomBytes(32).toString("base64url");
export const tokenHash = (token: string) => createHash("sha256").update(token).digest("hex");
function matches(token: string | null | undefined, hash: string | null | undefined) {
  return Boolean(token && /^[A-Za-z0-9_-]{43}$/.test(token) && hash && /^[a-f0-9]{64}$/.test(hash) && timingSafeEqual(Buffer.from(tokenHash(token), "hex"), Buffer.from(hash, "hex")));
}
export function creatorToken(request: NextRequest) {
  // Parse standard headers too, so this boundary is easy to exercise with Request fixtures.
  return request.headers.get("cookie")?.split(";").map((part) => part.trim()).find((part) => part.startsWith(`${CREATOR_COOKIE}=`))?.slice(CREATOR_COOKIE.length + 1);
}
export function prepareCreator(request: NextRequest) {
  const existing = creatorToken(request);
  const token = existing && /^[A-Za-z0-9_-]{43}$/.test(existing) ? existing : newReportToken();
  return {hash: tokenHash(token), cookie: `${CREATOR_COOKIE}=${token}; Path=/; HttpOnly; SameSite=Lax; Max-Age=2592000${new URL(request.url).protocol === "https:" ? "; Secure" : ""}`};
}
export async function recordReportCreator(scanId: string, hash: string) {
  await ensureReportAccess();
  await prisma.websiteReportAccess.create({data: {scanId, creatorHash: hash}});
}
export async function reportPermission(request: NextRequest, scan: {id: string; userId: string | null}, userId?: string) {
  await ensureReportAccess();
  const access = await prisma.websiteReportAccess.findUnique({where: {scanId: scan.id}});
  const owner = Boolean(userId && scan.userId === userId);
  const creator = !scan.userId && matches(creatorToken(request), access?.creatorHash);
  const shared = matches(request.headers.get("x-report-share-token"), access?.shareHash);
  return {allowed: owner || creator || shared, owner, canClaim: creator, shared, sharingEnabled: owner && Boolean(access?.shareHash)};
}
export function sameOrigin(request: NextRequest) {
  return request.headers.get("origin") === new URL(request.url).origin;
}
export const reportHeaders = {"Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow"};
