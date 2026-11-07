import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";
import { applyWebsiteRemediationAccess, isVisibleWebsiteFinding } from "@/lib/scan-remediation";
import { compareScanFindings } from "@/lib/scan-comparison";
import { isSameHost, hostnameKey } from "@/lib/scan-access";

export async function GET(
  req: NextRequest,
  { params }: { params: Promise<{ id: string }> }
) {
  try {
    const { id } = await params;

    const session = await auth();
    const user = session?.user?.id
      ? await prisma.user.findUnique({
          where: { id: session.user.id },
          select: { plan: true },
        })
      : null;

    const scan = await prisma.scan.findUnique({
      where: { id },
      include: {
        vulnerabilities: {
          orderBy: [
            { severity: "asc" },
            { createdAt: "asc" },
          ],
        },
      },
    });

    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    // Owners see what changed since their previous completed scan of the same hostname.
    let comparison = null;
    if (session?.user?.id && scan.userId === session.user.id && scan.status === "completed") {
      try {
        const key = hostnameKey(scan.url);
        const candidates = await prisma.scan.findMany({
          where: { userId: session.user.id, status: "completed", createdAt: { lt: scan.createdAt }, url: { contains: key } },
          orderBy: { createdAt: "desc" },
          take: 10,
          select: { id: true, url: true, overallScore: true, createdAt: true, vulnerabilities: { select: { type: true, title: true, url: true } } },
        });
        const previous = candidates.find((candidate) => isSameHost(candidate.url, key));
        if (previous) {
          comparison = {
            previousScanId: previous.id,
            previousScore: previous.overallScore,
            previousCreatedAt: previous.createdAt,
            ...compareScanFindings(previous.vulnerabilities.filter(isVisibleWebsiteFinding), scan.vulnerabilities.filter(isVisibleWebsiteFinding)),
          };
        }
      } catch (error) {
        console.error("Scan comparison failed:", error instanceof Error ? error.message : "unknown");
      }
    }

    return NextResponse.json({
      ...scan,
      comparison,
      // Never send locked implementation steps and rely on a client-side blur.
      vulnerabilities: applyWebsiteRemediationAccess(scan.vulnerabilities, user?.plan),
    });
  } catch {
    return NextResponse.json(
      { error: "Something went wrong" },
      { status: 500 }
    );
  }
}
