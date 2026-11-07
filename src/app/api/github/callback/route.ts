import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { exchangeOAuthCode, GitHubAppError, listUserInstallations, verifyConnectState } from "@/lib/github-app";
import { ensureRepoTables } from "@/lib/repo-store";

/**
 * GitHub redirects here after install/authorize with ?code&state (and an
 * installation_id hint). The installation_id query value is never trusted: we
 * only link installations GitHub lists for the user's own OAuth token.
 */
export async function GET(request: NextRequest) {
  const origin = request.nextUrl.origin;
  const done = (status: string) => {
    const response = NextResponse.redirect(new URL(`/repo-scan?tab=private&github=${status}`, origin));
    response.cookies.delete({ name: "gh_connect_nonce", path: "/api/github" });
    return response;
  };
  const session = await auth();
  if (!session?.user?.id) return NextResponse.redirect(new URL(`/login?callbackUrl=${encodeURIComponent("/repo-scan?tab=private")}`, origin));

  const params = request.nextUrl.searchParams;
  const code = params.get("code");
  const state = params.get("state");
  if (params.get("setup_action") === "request") return done("requested");
  if (!code || !state) return done("cancelled");

  try {
    verifyConnectState(state, { userId: session.user.id, nonce: request.cookies.get("gh_connect_nonce")?.value || "" });
    const userToken = await exchangeOAuthCode(code);
    const installations = await listUserInstallations(userToken);
    if (!installations.length) return done("no-installation");
    await ensureRepoTables();
    for (const installation of installations) {
      await prisma.gitHubInstallation.upsert({
        where: { userId_installationId: { userId: session.user.id, installationId: installation.installationId } },
        create: { userId: session.user.id, ...installation },
        update: { accountLogin: installation.accountLogin, accountType: installation.accountType },
      });
    }
    return done("connected");
  } catch (error) {
    if (!(error instanceof GitHubAppError)) console.error("GitHub callback failed:", error instanceof Error ? error.message : "unknown");
    return done(error instanceof GitHubAppError && error.code === "invalid_state" ? "expired" : "error");
  }
}
