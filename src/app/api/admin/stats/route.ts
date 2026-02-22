import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin";
import { prisma } from "@/lib/db";

export async function GET() {
  const check = await requireAdmin();
  if (!check.authorized) {
    return NextResponse.json({ error: check.error }, { status: 403 });
  }

  try {
    const now = new Date();
    const thirtyDaysAgo = new Date(now.getTime() - 30 * 24 * 60 * 60 * 1000);
    const sevenDaysAgo = new Date(now.getTime() - 7 * 24 * 60 * 60 * 1000);

    // Run all queries in parallel
    const [
      totalUsers,
      usersLast30d,
      usersLast7d,
      totalScans,
      scansLast30d,
      scansLast7d,
      planBreakdown,
      recentUsers,
      recentScans,
      vulnerabilityStats,
      referrerBreakdown,
    ] = await Promise.all([
      // Total users
      prisma.user.count(),

      // Users registered in last 30 days
      prisma.user.count({
        where: { createdAt: { gte: thirtyDaysAgo } },
      }),

      // Users registered in last 7 days
      prisma.user.count({
        where: { createdAt: { gte: sevenDaysAgo } },
      }),

      // Total scans
      prisma.scan.count(),

      // Scans in last 30 days
      prisma.scan.count({
        where: { createdAt: { gte: thirtyDaysAgo } },
      }),

      // Scans in last 7 days
      prisma.scan.count({
        where: { createdAt: { gte: sevenDaysAgo } },
      }),

      // Plan breakdown
      prisma.user.groupBy({
        by: ["plan"],
        _count: { plan: true },
      }),

      // Recent users (last 20)
      prisma.user.findMany({
        orderBy: { createdAt: "desc" },
        take: 20,
        select: {
          id: true,
          name: true,
          email: true,
          role: true,
          plan: true,
          credits: true,
          scansUsed: true,
          stripeCustomerId: true,
          stripeSubscriptionId: true,
          stripePriceId: true,
          currentPeriodEnd: true,
          referrerSource: true,
          createdAt: true,
          updatedAt: true,
          _count: { select: { scans: true } },
        },
      }),

      // Recent scans (last 20)
      prisma.scan.findMany({
        orderBy: { createdAt: "desc" },
        take: 20,
        select: {
          id: true,
          url: true,
          status: true,
          overallScore: true,
          totalPages: true,
          pagesScanned: true,
          createdAt: true,
          completedAt: true,
          userId: true,
          user: { select: { name: true, email: true } },
          _count: { select: { vulnerabilities: true } },
        },
      }),

      // Vulnerability severity breakdown
      prisma.vulnerability.groupBy({
        by: ["severity"],
        _count: { severity: true },
      }),

      // Referrer source breakdown
      prisma.user.groupBy({
        by: ["referrerSource"],
        _count: { referrerSource: true },
      }),
    ]);

    // Format plan breakdown into a map
    const plans: Record<string, number> = {};
    for (const p of planBreakdown) {
      plans[p.plan] = p._count.plan;
    }

    // Format vulnerability stats
    const vulnBySeverity: Record<string, number> = {};
    for (const v of vulnerabilityStats) {
      vulnBySeverity[v.severity] = v._count.severity;
    }

    // Format referrer source stats
    const trafficSources: Record<string, number> = {};
    for (const r of referrerBreakdown) {
      const source = r.referrerSource || "unknown";
      trafficSources[source] = r._count.referrerSource;
    }

    // Revenue estimate: count paying users
    const payingUsers = (plans["starter"] || 0) + (plans["pro"] || 0);
    const estimatedMRR =
      (plans["starter"] || 0) * 29 + (plans["pro"] || 0) * 79;

    return NextResponse.json({
      overview: {
        totalUsers,
        usersLast30d,
        usersLast7d,
        totalScans,
        scansLast30d,
        scansLast7d,
        payingUsers,
        estimatedMRR,
        conversionRate:
          totalUsers > 0
            ? ((payingUsers / totalUsers) * 100).toFixed(1)
            : "0",
      },
      plans,
      vulnBySeverity,
      trafficSources,
      recentUsers,
      recentScans,
    });
  } catch (error) {
    console.error("Admin stats error:", error);
    return NextResponse.json(
      { error: "Failed to fetch admin stats" },
      { status: 500 }
    );
  }
}
