import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { authorizeUrl, createConnectState, getGitHubAppConfig, installUrl } from "@/lib/github-app";
import { ensureRepoTables } from "@/lib/repo-store";

const NONCE_COOKIE = "gh_connect_nonce";

/** Start the GitHub App install (or authorize-only, for accounts that already installed it). */
export async function GET(request: NextRequest) {
  const origin = request.nextUrl.origin;
  if (!getGitHubAppConfig()) return NextResponse.redirect(new URL("/repo-scan?github=unavailable", origin));
  const session = await auth();
  if (!session?.user?.id) return NextResponse.redirect(new URL(`/login?callbackUrl=${encodeURIComponent("/repo-scan?tab=private")}`, origin));

  const { state, nonce } = createConnectState(session.user.id);
  const mode = request.nextUrl.searchParams.get("mode");
  const target = mode === "authorize" ? authorizeUrl(state, new URL("/api/github/callback", origin).toString()) : installUrl(state);
  const response = NextResponse.redirect(target);
  response.cookies.set(NONCE_COOKIE, nonce, { httpOnly: true, secure: origin.startsWith("https://"), sameSite: "lax", path: "/api/github", maxAge: 15 * 60 });
  return response;
}

/** Disconnect: remove the links in ScanMySaaS. Uninstalling on GitHub removes the app's access entirely. */
export async function DELETE() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Sign in first." }, { status: 401 });
  await ensureRepoTables();
  await prisma.gitHubInstallation.deleteMany({ where: { userId: session.user.id } });
  return NextResponse.json({ ok: true, uninstallUrl: "https://github.com/settings/installations" });
}
