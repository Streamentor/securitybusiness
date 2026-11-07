import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";
import { reportPermission, sameOrigin, reportHeaders } from "@/lib/report-access";
import { auth } from "@/lib/auth";

/**
 * POST /api/scan/claim
 * Links an anonymous (unclaimed) scan to the authenticated user.
 * This is called after a user runs a scan anonymously, then registers/logs in.
 */
export async function POST(req: NextRequest) {
  try {
    if (!sameOrigin(req)) return NextResponse.json({error: "Forbidden"}, {status: 403, headers: reportHeaders});
    const session = await auth();

    if (!session?.user?.id) {
      return NextResponse.json({ error: "Unauthorized" }, { status: 401 });
    }

    const { scanId } = await req.json();

    if (!scanId) {
      return NextResponse.json(
        { error: "scanId is required" },
        { status: 400 }
      );
    }

    // Find the scan — only claim it if it has no owner (userId is null)
    const scan = await prisma.scan.findUnique({
      where: { id: scanId },
      select: { id: true, userId: true },
    });

    if (!scan) {
      return NextResponse.json({ error: "Scan not found" }, { status: 404 });
    }

    // If the scan already belongs to this user, just return success
    if (scan.userId === session.user.id) {
      return NextResponse.json({ message: "Scan already belongs to you", claimed: true });
    }

    // If the scan belongs to someone else, deny the request
    if (scan.userId !== null) {
      return NextResponse.json(
        { error: "This scan belongs to another user" },
        { status: 403 }
      );
    }

    const access = await reportPermission(req, scan, session.user.id);
    if (!access.canClaim) return NextResponse.json({error: "Scan not found"}, {status: 404, headers: reportHeaders});
    // Compare-and-set stops two accounts racing to claim the same anonymous scan.
    const claimed = await prisma.scan.updateMany({
      where: {id: scanId, userId: null}, data: {userId: session.user.id},
    });
    if (claimed.count !== 1) return NextResponse.json({error: "Scan already claimed"}, {status: 409, headers: reportHeaders});

    return NextResponse.json({ message: "Scan claimed successfully", claimed: true });
  } catch (error) {
    console.error("Scan claim error:", error);
    return NextResponse.json(
      { error: "Something went wrong" },
      { status: 500 }
    );
  }
}
