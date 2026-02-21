import { NextRequest, NextResponse } from "next/server";
import { prisma } from "@/lib/db";

export async function GET(req: NextRequest) {
  const { searchParams } = new URL(req.url);
  const score = parseInt(searchParams.get("score") || "", 10);

  if (isNaN(score) || score < 0 || score > 100) {
    return NextResponse.json({ error: "Valid score required" }, { status: 400 });
  }

  try {
    // Count total completed scans and scans with a lower score
    const [totalScans, lowerScans] = await Promise.all([
      prisma.scan.count({
        where: { status: "completed", overallScore: { not: null } },
      }),
      prisma.scan.count({
        where: {
          status: "completed",
          overallScore: { not: null, lt: score },
        },
      }),
    ]);

    // Need at least 5 scans to show a meaningful percentile
    if (totalScans < 5) {
      return NextResponse.json({ percentile: null, totalScans });
    }

    const percentile = Math.round((lowerScans / totalScans) * 100);

    return NextResponse.json({ percentile, totalScans });
  } catch {
    return NextResponse.json({ error: "Failed to calculate percentile" }, { status: 500 });
  }
}
