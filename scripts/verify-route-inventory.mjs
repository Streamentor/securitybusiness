import assert from "node:assert/strict";
import "./scan-test-hook.mjs";
const { inventoryRepoRoutes, prioritizeRepoReview } = await import("../src/lib/repo-route-inventory.ts");
const files = [
  ["app/api/purge/route.ts", 'export async function POST() { return Response.json({}); }'],
  ["app/api/secure/route.ts", 'export async function GET() { await auth(); return Response.json({}); }'],
  ["app/api/stripe/webhook/route.ts", 'export async function POST() { stripe.webhooks.constructEvent(); }'],
  ["app/api/twilio/webhook/route.ts", 'export async function POST() { /* validateRequest() */ }'],
  ["app/api/admin/stats/route.ts", 'export async function GET() { return Response.json({}); }'],
  ["middleware.ts", 'export default withAuth(() => {}); export const config = { matcher: "/api/admin/:path*" };'],
  ["app/api/helper/route.ts", 'import { requireUser } from "../../../lib/auth"; export async function GET() { await requireUser(); }'],
  ["lib/auth.ts", 'export function requireUser() { return auth(); }'],
  ["app/api/status/route.ts", 'export async function GET() { return Response.json({}); }'],
  ["app/api/mixed/route.ts", 'export async function GET() { await auth(); }\nexport async function POST() {}'],
].map(([path, content]) => ({ path, content }));
const { routes, findings } = inventoryRepoRoutes(files);
const route = (path, method) => routes.find((item) => item.path === path && (!method || item.method === method));
assert.equal(findings.find((row) => row.file.includes("/purge/")).severity, "high");
assert.equal(route("/api/secure").status, "auth-checked");
assert.equal(route("/api/stripe/webhook").status, "public-by-design");
assert.equal(findings.find((row) => row.file.includes("/twilio/")).severity, "high");
assert.equal(route("/api/admin/stats").status, "auth-checked");
assert.equal(route("/api/helper").status, "auth-checked");
assert.equal(route("/api/mixed", "POST").status, "no-auth-seen");
assert.equal(findings.find((row) => row.file.includes("/status/")).severity, "medium");
const ranked = prioritizeRepoReview(files, routes, () => 0, () => true);
assert.match(ranked[0].path, /mixed|purge|twilio/);
assert.ok(ranked.find((file) => file.path.includes("/helper/")).context.some((file) => file.path === "lib/auth.ts"));
console.log("Route inventory and AI priority checks passed.");
