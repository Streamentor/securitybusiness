import { NextRequest, NextResponse } from "next/server";
import { resultForEntitlement } from "@/lib/ai-review";
import { createHash } from "node:crypto";
import { GitHubScannerError, scanPublicGitHubRepository } from "@/lib/github-scanner";

export const maxDuration = 60;

const WINDOW_MS = 10 * 60 * 1000;
const MAX_SCANS_PER_WINDOW = 5;
const attempts = new Map<string, number[]>();

function clientAddress(request: NextRequest) {
  const address = (request.headers.get("x-forwarded-for") || "unknown").split(",")[0].trim().slice(0, 96);
  return createHash("sha256").update(address).digest("hex").slice(0, 24);
}

function allowRequest(address: string) {
  const now = Date.now();
  const recent = (attempts.get(address) || []).filter((time) => now - time < WINDOW_MS);
  if (recent.length >= MAX_SCANS_PER_WINDOW) return false;
  recent.push(now);
  attempts.set(address, recent);
  if (attempts.size > 2_000) {
    for (const [key, values] of attempts) if (!values.some((time) => now - time < WINDOW_MS)) attempts.delete(key);
  }
  return true;
}

export async function POST(request: NextRequest) {
  const address = clientAddress(request);
  if (!allowRequest(address)) {
    return NextResponse.json({ error: "Too many repository scans. Try again in 10 minutes.", code: "rate_limited" }, { status: 429, headers: { "Retry-After": "600" } });
  }

  let body: unknown;
  try { body = await request.json(); }
  catch { return NextResponse.json({ error: "The request body must be valid JSON.", code: "invalid_request" }, { status: 400 }); }
  const repository = typeof body === "object" && body !== null && "repository" in body ? String((body as { repository: unknown }).repository || "") : "";
  const authorized = typeof body === "object" && body !== null && "authorized" in body && (body as { authorized: unknown }).authorized === true;
  if (!authorized) return NextResponse.json({ error: "Confirm that you own the repository or have permission to scan it.", code: "authorization_required" }, { status: 400 });

  try {
    return NextResponse.json(resultForEntitlement(await scanPublicGitHubRepository(repository), false));
  } catch (error) {
    if (error instanceof GitHubScannerError) {
      const status = error.code === "rate_limited" ? 429 : error.code === "upstream_unavailable" ? 502 : 400;
      return NextResponse.json({ error: error.message, code: error.code }, { status, headers: error.retryAfter ? { "Retry-After": String(error.retryAfter) } : undefined });
    }
    console.error("Repository scan failed:", error instanceof Error ? error.message : "Unknown error");
    return NextResponse.json({ error: "The repository scan failed. Try again in a moment.", code: "scan_failed" }, { status: 500 });
  }
}
