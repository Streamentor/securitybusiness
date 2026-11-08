import { NextRequest } from "next/server";
import { verifyUnsubscribeToken } from "@/lib/email/tokens";
import { setEmailPreference } from "@/lib/email/store";
const headers = { "Cache-Control": "private, no-store", "Referrer-Policy": "no-referrer", "X-Robots-Tag": "noindex, nofollow", "Content-Security-Policy": "default-src 'none'; form-action 'self'; base-uri 'none'; frame-ancestors 'none'" };
async function optOut(req: NextRequest) {
  const token = req.nextUrl.searchParams.get("t") || "";
  const id = verifyUnsubscribeToken(token);
  if (!id) return false;
  // A valid token for a deleted account still succeeds without recreating it.
  await setEmailPreference(id, false); return true;
}
export async function POST(req: NextRequest) {
  try { return new Response(null, { status: await optOut(req) ? 200 : 400, headers }); }
  catch { return new Response(null, { status: 503, headers }); }
}
export async function GET(req: NextRequest) {
  try {
    if (!await optOut(req)) return new Response("Invalid unsubscribe link", { status: 400, headers });
    return new Response(`<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Email updates | ScanMySaaS</title><body><main><h1>You're unsubscribed from ScanMySaaS emails</h1><p>You can choose to receive email updates again in your signed-in dashboard. Suppressed addresses cannot be re-enabled here.</p><form action="/dashboard" method="get"><button type="submit">Resubscribe in dashboard</button></form></main></body></html>`, { headers: { ...headers, "Content-Type": "text/html; charset=utf-8" } });
  } catch { return new Response("Unable to update preferences. Please try again.", { status: 503, headers }); }
}
