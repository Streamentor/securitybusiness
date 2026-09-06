import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { scanWebsite, validateScanTarget, WebsiteScanError } from "@/lib/scanner";
import { auth } from "@/lib/auth";
import { applyWebsiteRemediationAccess } from "@/lib/scan-remediation";

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

    // Get user session (optional - free scans without login)
    try {
      const session = await auth();
      if (session?.user?.id) {
        const user = await prisma.user.findUnique({
          where: { id: session.user.id },
          select: { plan: true, credits: true },
        });
        if (user) {
          if (user.credits <= 0) {
            return NextResponse.json(
              { error: "No scan credits remaining. Please upgrade your plan." },
              { status: 403 }
            );
          }
          userId = session.user.id;
          userPlan = user.plan;
        }
      }
    } catch (e) {
      console.error("Auth error (non-fatal):", e);
    }

    // ── Domain abuse prevention ──
    // Free/anonymous users can only scan a domain once across ALL accounts.
    if (userPlan === "free") {
      try {
        const parsedUrl = new URL(normalizedUrl);
        const domain = parsedUrl.hostname.replace(/^www\./, "");

        const existingScan = await prisma.scan.findFirst({
          where: {
            url: { contains: domain },
            status: "completed",
            OR: [{ userId: null }, { user: { plan: "free" } }],
          },
          select: { id: true },
        });

        if (existingScan) {
          return NextResponse.json(
            { error: "This domain has already been scanned on a free plan. Upgrade to Starter or Pro for unlimited scans of any domain." },
            { status: 403 }
          );
        }
      } catch {
        // If domain check fails, allow the scan to proceed
      }
    }

    if (userId) {
      const reservation = await prisma.user.updateMany({
        where: { id: userId, credits: { gt: 0 } },
        data: { credits: { decrement: 1 } },
      });
      if (reservation.count === 0) {
        return NextResponse.json(
          { error: "No scan credits remaining. Please upgrade your plan." },
          { status: 403 }
        );
      }
      creditReserved = true;
    }

    // Create scan record
    const scan = await prisma.scan.create({
      data: {
        url: normalizedUrl,
        status: "running",
        userId,
      },
    });

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
          totalPages: results.pagesScanned,
          completedAt: new Date(),
        },
        include: {
          vulnerabilities: true,
        },
      });

      // The credit was reserved before the scan; only update usage here.
      if (userId) {
        await prisma.user.update({
          where: { id: userId },
          data: { scansUsed: { increment: 1 } },
        });
      }

      return NextResponse.json({
        ...updatedScan,
        vulnerabilities: applyWebsiteRemediationAccess(updatedScan.vulnerabilities, userPlan),
      });
    } catch (scanError) {
      console.error("Scan execution error:", scanError);
      if (userId && creditReserved) {
        await prisma.user.update({
          where: { id: userId },
          data: { credits: { increment: 1 } },
        }).catch(() => undefined);
        creditReserved = false;
      }
      await prisma.scan.update({
        where: { id: scan.id },
        data: { status: "failed" },
      });

      return NextResponse.json(
        { error: scanError instanceof WebsiteScanError ? scanError.message : "Failed to scan the website. Please check the URL and try again." },
        { status: scanError instanceof WebsiteScanError ? 422 : 500 }
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
