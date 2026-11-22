import { prisma } from "@/lib/db";
import { COMPLIANCE_COVERAGE_TITLE, unavailableCompliance } from "@/lib/compliance-types";
import type { VulnerabilityResult } from "@/lib/scanner";

export async function finishWebsiteCompliance(scanId: string, pending: VulnerabilityResult, run: () => Promise<VulnerabilityResult[]>) {
  try {
    const results = await run();
    const coverage = results.find((result) => result.type === "scan-meta" && result.title === COMPLIANCE_COVERAGE_TITLE);
    const description = coverage?.description ?? JSON.stringify(unavailableCompliance("error"));
    await prisma.$transaction(async (db) => {
      const updated = await db.vulnerability.updateMany({
        where: { scanId, type: "scan-meta", title: COMPLIANCE_COVERAGE_TITLE, description: pending.description },
        data: { description },
      });
      if (updated.count) {
        const findings = results.filter((finding) => finding.type !== "scan-meta");
        if (findings.length) await db.vulnerability.createMany({ data: findings.map((finding) => ({ ...finding, scanId })) });
      }
    });
  } catch {
    await prisma.vulnerability.updateMany({
      where: { scanId, type: "scan-meta", title: COMPLIANCE_COVERAGE_TITLE, description: pending.description },
      data: { description: JSON.stringify(unavailableCompliance("error")) },
    }).catch(() => console.error("Website compliance result could not be saved."));
  }
}
