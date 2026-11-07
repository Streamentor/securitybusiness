import { prisma } from "@/lib/db";

/**
 * The project has no Prisma migration history, so the two additive tables used by
 * repository connections and background repository scans are created idempotently
 * on first use. Existing tables are never altered.
 */
const STATEMENTS = [
  `CREATE TABLE IF NOT EXISTS "GitHubInstallation" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "installationId" INTEGER NOT NULL,
    "accountLogin" TEXT NOT NULL,
    "accountType" TEXT NOT NULL,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "updatedAt" TIMESTAMP(3) NOT NULL,
    CONSTRAINT "GitHubInstallation_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "GitHubInstallation_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE
  )`,
  `CREATE UNIQUE INDEX IF NOT EXISTS "GitHubInstallation_userId_installationId_key" ON "GitHubInstallation"("userId", "installationId")`,
  `CREATE INDEX IF NOT EXISTS "GitHubInstallation_installationId_idx" ON "GitHubInstallation"("installationId")`,
  `CREATE TABLE IF NOT EXISTS "RepoScan" (
    "id" TEXT NOT NULL,
    "userId" TEXT NOT NULL,
    "repository" TEXT NOT NULL,
    "requestedRef" TEXT,
    "commitSha" TEXT,
    "visibility" TEXT NOT NULL DEFAULT 'public',
    "installationId" INTEGER,
    "status" TEXT NOT NULL DEFAULT 'queued',
    "stage" TEXT,
    "score" INTEGER,
    "risk" TEXT,
    "findingsCount" INTEGER,
    "result" JSONB,
    "error" TEXT,
    "createdAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP,
    "startedAt" TIMESTAMP(3),
    "completedAt" TIMESTAMP(3),
    CONSTRAINT "RepoScan_pkey" PRIMARY KEY ("id"),
    CONSTRAINT "RepoScan_userId_fkey" FOREIGN KEY ("userId") REFERENCES "User"("id") ON DELETE CASCADE ON UPDATE CASCADE
  )`,
  `CREATE INDEX IF NOT EXISTS "RepoScan_userId_createdAt_idx" ON "RepoScan"("userId", "createdAt")`,
];

let ready: Promise<void> | null = null;

export function ensureRepoTables(): Promise<void> {
  if (!ready) {
    ready = (async () => {
      for (const statement of STATEMENTS) await prisma.$executeRawUnsafe(statement);
    })().catch((error) => {
      ready = null; // retry on the next request
      throw error;
    });
  }
  return ready;
}
