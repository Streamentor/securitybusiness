import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { auth } from "@/lib/auth";
import { applyWebsiteRemediationAccess } from "@/lib/scan-remediation";

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

    return NextResponse.json({
      ...scan,
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
