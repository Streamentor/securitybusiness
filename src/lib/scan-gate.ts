import type { NextRequest } from "next/server";
import { createHash } from "node:crypto";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";
import { allowScanRequest, decideScanAccess, hostnameKey } from "@/lib/scan-access";

export type ScanGateResult =
  | { ok: true; userId: string | null; plan: string; creditReserved: boolean; kind: "first" | "verification" | "paid" }
  | { ok: false; status: number; error: string; retryAfter?: number };

function clientIdentity(request: NextRequest) {
  const address = (request.headers.get("x-forwarded-for") || request.headers.get("x-real-ip") || "unknown").split(",")[0].trim().slice(0, 96);
  return createHash("sha256").update(address).digest("hex").slice(0, 24);
}

/**
 * Shared admission control for website scans: identity, rate limit, free-plan
 * domain rules, the one free verification rescan, and atomic credit reservation.
 */
export async function admitWebsiteScan(request: NextRequest, normalizedUrl: string): Promise<ScanGateResult> {
  let userId: string | null = null;
  let plan = "free";
  let credits = 0;
  try {
    const session = await auth();
    if (session?.user?.id) {
      const user = await prisma.user.findUnique({ where: { id: session.user.id }, select: { plan: true, credits: true } });
      // A stale session for a deleted user is treated as anonymous.
      if (user) { userId = session.user.id; plan = user.plan; credits = user.credits; }
    }
  } catch (error) {
    console.error("Auth error (non-fatal):", error instanceof Error ? error.message : "unknown");
  }

  const allowed = userId ? allowScanRequest(userId, "user") : allowScanRequest(clientIdentity(request), "anonymous");
  if (!allowed) {
    return { ok: false, status: 429, error: userId ? "Too many scans in the last hour. Try again later." : "Too many scans from this network in the last hour. Sign in or try again later.", retryAfter: 3600 };
  }

  let priorFreeScans: Array<{ userId: string | null; url: string; createdAt: Date }> = [];
  if (plan !== "starter" && plan !== "pro") {
    try {
      priorFreeScans = await prisma.scan.findMany({
        where: { url: { contains: hostnameKey(normalizedUrl) }, status: "completed", OR: [{ userId: null }, { user: { plan: "free" } }] },
        select: { userId: true, url: true, createdAt: true },
        orderBy: { createdAt: "asc" },
        take: 200,
      });
    } catch (error) {
      // Fail closed for anonymous users so a database hiccup cannot remove the abuse limit.
      console.error("Domain check failed:", error instanceof Error ? error.message : "unknown");
      if (!userId) return { ok: false, status: 503, error: "The scan service is busy. Please try again in a moment." };
    }
  }

  const decision = decideScanAccess({ userId, plan, credits, targetUrl: normalizedUrl, priorFreeScans, now: new Date() });
  if (!decision.allowed) return { ok: false, status: decision.status, error: decision.error };

  let creditReserved = false;
  if (userId && decision.consumesCredit) {
    // Reserve atomically before starting expensive work so parallel requests cannot spend one credit twice.
    const reservation = await prisma.user.updateMany({ where: { id: userId, credits: { gt: 0 } }, data: { credits: { decrement: 1 } } });
    if (reservation.count === 0) return { ok: false, status: 403, error: "No scan credits remaining. Please upgrade your plan." };
    creditReserved = true;
  }
  return { ok: true, userId, plan, creditReserved, kind: decision.kind };
}
