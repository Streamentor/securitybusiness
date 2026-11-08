import { prisma } from "@/lib/db";
import type { WebsiteFailure, WebsiteCoverage } from "@/lib/website-scan-failure";

let ready: Promise<unknown> | null = null;
export function ensureWebsiteDiagnostics() {
  return ready ??= prisma.$executeRawUnsafe(`CREATE TABLE IF NOT EXISTS "WebsiteScanDiagnostic" (
    "scanId" TEXT PRIMARY KEY REFERENCES "Scan"("id") ON DELETE CASCADE,
    "failureCode" TEXT, "failureMessage" TEXT, "httpStatus" INTEGER, "provider" TEXT,
    "partial" BOOLEAN NOT NULL DEFAULT FALSE, "pagesDiscovered" INTEGER, "pagesAnalyzed" INTEGER,
    "coverageNote" TEXT, "finishedAt" TIMESTAMP(3) NOT NULL DEFAULT CURRENT_TIMESTAMP
  )`).catch(error => {ready = null; throw error;});
}
export async function saveWebsiteDiagnostic(scanId: string, data: {failure?: WebsiteFailure; coverage?: WebsiteCoverage}) {
  try {
    await ensureWebsiteDiagnostics();
    await prisma.websiteScanDiagnostic.upsert({where: {scanId}, create: {scanId, failureCode: data.failure?.code, failureMessage: data.failure?.message, httpStatus: data.failure?.httpStatus, provider: data.failure?.provider, partial: data.coverage?.partial ?? false, pagesDiscovered: data.coverage?.pagesDiscovered, pagesAnalyzed: data.coverage?.pagesAnalyzed, coverageNote: data.coverage?.note}, update: {failureCode: data.failure?.code ?? null, failureMessage: data.failure?.message ?? null, httpStatus: data.failure?.httpStatus ?? null, provider: data.failure?.provider ?? null, partial: data.coverage?.partial ?? false, pagesDiscovered: data.coverage?.pagesDiscovered ?? null, pagesAnalyzed: data.coverage?.pagesAnalyzed ?? null, coverageNote: data.coverage?.note ?? null, finishedAt: new Date()}});
  } catch { console.error("Website scan diagnostics could not be saved"); }
}
export async function readWebsiteDiagnostics(scanIds: string[]) {
  try {
    await ensureWebsiteDiagnostics();
    return await prisma.websiteScanDiagnostic.findMany({where: {scanId: {in: scanIds}}});
  } catch { console.error("Website scan diagnostics unavailable"); return []; }
}
