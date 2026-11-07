import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { getGitHubAppConfig, GitHubAppError, listInstallationRepositories, type InstallationRepository } from "@/lib/github-app";
import { ensureRepoTables } from "@/lib/repo-store";

export async function GET() {
  if (!getGitHubAppConfig()) return NextResponse.json({ error: "Private repository connections are not available yet." }, { status: 503 });
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Sign in first." }, { status: 401 });
  await ensureRepoTables();
  const installations = await prisma.gitHubInstallation.findMany({ where: { userId: session.user.id }, select: { id: true, installationId: true, accountLogin: true } });
  const repositories: Array<InstallationRepository & { account: string }> = [];
  const revoked: string[] = [];
  for (const installation of installations) {
    try {
      for (const repo of await listInstallationRepositories(installation.installationId)) repositories.push({ ...repo, account: installation.accountLogin });
    } catch (error) {
      if (error instanceof GitHubAppError && error.code === "no_access") {
        // The app was uninstalled on GitHub: drop the stale link.
        revoked.push(installation.accountLogin);
        await prisma.gitHubInstallation.delete({ where: { id: installation.id } }).catch(() => undefined);
      } else {
        console.error("Listing repositories failed:", error instanceof Error ? error.message : "unknown");
      }
    }
  }
  repositories.sort((a, b) => (b.pushedAt || "").localeCompare(a.pushedAt || ""));
  return NextResponse.json({ repositories, revoked });
}
