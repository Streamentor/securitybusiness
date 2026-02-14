import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { scanWebsite, ScanProgress, VulnerabilityResult } from "@/lib/scanner";
import { auth } from "@/lib/auth";

export const maxDuration = 120; // Allow up to 2 minutes for Vercel

export async function POST(req: NextRequest) {
  const { url } = await req.json();

  if (!url) {
    return new Response(JSON.stringify({ error: "URL is required" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Validate URL
  let normalizedUrl = url;
  if (!normalizedUrl.startsWith("http://") && !normalizedUrl.startsWith("https://")) {
    normalizedUrl = "https://" + normalizedUrl;
  }

  try {
    new URL(normalizedUrl);
  } catch {
    return new Response(JSON.stringify({ error: "Invalid URL format" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  // Check authentication (optional — anonymous scans are allowed)
  let userId: string | null = null;
  try {
    const session = await auth();
    if (session?.user?.id) {
      // Verify user still exists in DB (handles stale JWT after DB reset)
      const user = await prisma.user.findUnique({
        where: { id: session.user.id },
        select: { credits: true, plan: true },
      });
      if (user) {
        if (user.credits <= 0) {
          return new Response(
            JSON.stringify({ error: "No scan credits remaining. Please upgrade your plan." }),
            { status: 403, headers: { "Content-Type": "application/json" } }
          );
        }
        userId = session.user.id;
      }
      // If user not found in DB, treat as anonymous (stale session)
    }
  } catch {
    // Auth error — proceed as anonymous
  }

  // Create the readable stream
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      function send(event: string, data: unknown) {
        controller.enqueue(
          encoder.encode(`event: ${event}\ndata: ${JSON.stringify(data)}\n\n`)
        );
      }

      try {
        // Create scan record
        const scan = await prisma.scan.create({
          data: {
            url: normalizedUrl,
            status: "running",
            userId,
          },
        });

        send("scan-created", { scanId: scan.id });

        // Run scan with progress callbacks
        const results = await scanWebsite(normalizedUrl, (progress: ScanProgress) => {
          send("progress", progress);
        });

        send("progress", {
          step: "saving",
          label: "Saving results to database…",
          status: "running",
          totalSteps: 17,
          currentStep: 17,
        });

        // Save vulnerabilities
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
        await prisma.scan.update({
          where: { id: scan.id },
          data: {
            status: "completed",
            overallScore: results.score,
            pagesScanned: results.pagesScanned,
            totalPages: results.pagesScanned,
            completedAt: new Date(),
          },
        });

        // Update user scan count and deduct credit
        if (userId) {
          await prisma.user.update({
            where: { id: userId },
            data: {
              scansUsed: { increment: 1 },
              credits: { decrement: 1 },
            },
          });
        }

        send("complete", {
          scanId: scan.id,
          score: results.score,
          totalVulnerabilities: results.vulnerabilities.length,
          pagesScanned: results.pagesScanned,
          critical: results.vulnerabilities.filter((v: VulnerabilityResult) => v.severity === "critical").length,
          high: results.vulnerabilities.filter((v: VulnerabilityResult) => v.severity === "high").length,
          medium: results.vulnerabilities.filter((v: VulnerabilityResult) => v.severity === "medium").length,
          low: results.vulnerabilities.filter((v: VulnerabilityResult) => v.severity === "low").length,
          info: results.vulnerabilities.filter((v: VulnerabilityResult) => v.severity === "info").length,
        });
      } catch (error) {
        console.error("Stream scan error:", error);
        send("error", {
          message: "Scan failed. Please check the URL and try again.",
        });
      } finally {
        controller.close();
      }
    },
  });

  return new Response(stream, {
    headers: {
      "Content-Type": "text/event-stream",
      "Cache-Control": "no-cache, no-transform",
      Connection: "keep-alive",
    },
  });
}
