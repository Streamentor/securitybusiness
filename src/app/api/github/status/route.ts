import { NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";
import { getGitHubAppConfig } from "@/lib/github-app";
import { ensureRepoTables } from "@/lib/repo-store";
import { canScanPrivateRepositories } from "@/lib/repo-scan-jobs";

export async function GET() {
  const configured = Boolean(getGitHubAppConfig());
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ configured, signedIn: false, connected: false, installations: [], canScanPrivate: false });
  const user = await prisma.user.findUnique({ where: { id: session.user.id }, select: { plan: true, role: true } });
  let installations: Array<{ accountLogin: string; accountType: string }> = [];
  if (configured) {
    try {
      await ensureRepoTables();
      installations = await prisma.gitHubInstallation.findMany({ where: { userId: session.user.id }, select: { accountLogin: true, accountType: true }, orderBy: { createdAt: "asc" } });
    } catch (error) {
      console.error("GitHub status failed:", error instanceof Error ? error.message : "unknown");
    }
  }
  return NextResponse.json({
    configured,
    signedIn: true,
    connected: installations.length > 0,
    installations,
    plan: user?.plan ?? "free",
    canScanPrivate: user ? canScanPrivateRepositories(user) : false,
  });
}
