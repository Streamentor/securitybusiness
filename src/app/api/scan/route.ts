import { NextRequest, NextResponse } from "next/server";
import { saveWebsiteDiagnostic } from "@/lib/website-scan-diagnostics";
import { websiteFailure } from "@/lib/website-scan-failure";
import { prisma } from "@/lib/db";
import { scanWebsite, validateScanTarget, WebsiteScanError } from "@/lib/scanner";
import { prepareCreator, recordReportCreator } from "@/lib/report-access";
import { auth } from "@/lib/auth";
import { admitWebsiteScan } from "@/lib/scan-gate";
import { serializeWebsiteFindings } from "@/lib/scan-remediation";

export const maxDuration = 120;

export async function POST(req: NextRequest) {
  let userId: string | null = null;
  let userPlan = "free";
  let creditReserved = false;
  try {
    const { url } = await req.json();

    if (!url) {
      return NextResponse.json({ error: "URL is required" }, { status: 400 });
    }

    // Validate URL format
    let normalizedUrl = url;
    if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
      normalizedUrl = "https://" + normalizedUrl;
    }

    try {
      normalizedUrl = (await validateScanTarget(normalizedUrl)).toString();
    } catch (error) {
      return NextResponse.json(
        { error: error instanceof Error ? error.message : "Invalid URL format" },
        { status: 400 }
      );
    }

    const admission = await admitWebsiteScan(req, normalizedUrl);
    if (!admission.ok) {
      return NextResponse.json({ error: admission.error }, { status: admission.status, headers: admission.retryAfter ? { "Retry-After": String(admission.retryAfter) } : undefined });
    }
    userId = admission.userId;
    userPlan = admission.plan;
    creditReserved = admission.creditReserved;

    const creator = !userId ? prepareCreator(req) : null;

    // Create scan record
    const scan = await prisma.scan.create({
      data: {
        url: normalizedUrl,
        status: "running",
        userId,
      },
    });

    if (creator) await recordReportCreator(scan.id, creator.hash);

    // Run the scan
    try {
      const results = await scanWebsite(normalizedUrl);

      // Save vulnerabilities in batch
      if (results.vulnerabilities.length > 0) {
        await prisma.vulnerability.createMany({
          data: results.vulnerabilities.map((vuln) => ({
            scanId: scan.id,
            type: vuln.type,
            severity: vuln.severity,
            title: vuln.title,
            description: vuln.description,
            url: vuln.url,
            remedy: vuln.remedy,
          })),
        });
      }

      // Update scan record
      const updatedScan = await prisma.scan.update({
        where: { id: scan.id },
        data: {
          status: "completed",
          overallScore: results.score,
          pagesScanned: results.pagesScanned,
          totalPages: results.coverage?.pagesDiscovered ?? results.pagesScanned,
          completedAt: new Date(),
        },
        include: {
          vulnerabilities: true,
        },
      });

      await saveWebsiteDiagnostic(scan.id, {coverage: results.coverage});

      // The credit was reserved before the scan; only update usage here.
      if (userId) {
        await prisma.user.update({
          where: { id: userId },
          data: { scansUsed: { increment: 1 } },
        });
      }

    if (process.env.VERCEL_ENV === "production" && ["live", "dry-run"].includes(process.env.EMAIL_SEQUENCE_MODE || "") && userId) {
      const { after } = await import("next/server");
      const emailUserId = userId;
      after(async () => { const { maybeSendWelcome } = await import("@/lib/email/worker"); await maybeSendWelcome(emailUserId); });
    }

      return NextResponse.json({
        ...updatedScan,
        coverage: results.coverage,
        vulnerabilities: serializeWebsiteFindings(updatedScan.vulnerabilities, userPlan, !userId),
      }, {headers: {"Cache-Control": "private, no-store", ...(creator ? {"Set-Cookie": creator.cookie} : {})}});
    } catch (scanError) {
      const failure = scanError instanceof WebsiteScanError ? scanError.failure : websiteFailure("internal");
      console.error(`Scan execution error: ${failure.code}`);
      if (userId && creditReserved) {
        await prisma.user.update({
          where: { id: userId },
          data: { credits: { increment: 1 } },
        }).catch(() => undefined);
        creditReserved = false;
      }
      await prisma.scan.update({
        where: { id: scan.id },
        data: { status: "failed", completedAt: new Date() },
      });

      await saveWebsiteDiagnostic(scan.id, {failure});
      return NextResponse.json(
        { error: failure.message, code: failure.code },
        { status: scanError instanceof WebsiteScanError ? 422 : 500, headers: {"Cache-Control": "private, no-store", ...(creator ? {"Set-Cookie": creator.cookie} : {})} }
      );
    }
  } catch (outerError) {
    console.error("Scan API error:", outerError);
    if (userId && creditReserved) {
      await prisma.user.update({
        where: { id: userId },
        data: { credits: { increment: 1 } },
      }).catch(() => undefined);
    }
    return NextResponse.json(
      { error: "Something went wrong. Please try again." },
      { status: 500 }
    );
  }
}

export async function GET() {
  try {
    const session = await auth();

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const scans = await prisma.scan.findMany({
      where: { userId: session.user.id },
      select: {
        id: true,
        url: true,
        status: true,
        overallScore: true,
        pagesScanned: true,
        createdAt: true,
        vulnerabilities: {
          select: { id: true, severity: true, type: true },
        },
      },
      orderBy: { createdAt: "desc" },
    });

    return NextResponse.json(scans);
  } catch {
    return NextResponse.json(
      { error: "Something went wrong" },
      { status: 500 }
    );
  }
}
