import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { scanWebsite, ScanProgress } from "@/lib/scanner";
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

  // Get user session (optional)
  let userId: string | null = null;
  try {
    const session = await auth();
    userId = session?.user?.id || null;
  } catch {
    // Non-fatal
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

        // Update user scan count
        if (userId) {
          await prisma.user.update({
            where: { id: userId },
            data: { scansUsed: { increment: 1 } },
          });
        }

        send("complete", {
          scanId: scan.id,
          score: results.score,
          totalVulnerabilities: results.vulnerabilities.length,
          pagesScanned: results.pagesScanned,
          critical: results.vulnerabilities.filter((v) => v.severity === "critical").length,
          high: results.vulnerabilities.filter((v) => v.severity === "high").length,
          medium: results.vulnerabilities.filter((v) => v.severity === "medium").length,
          low: results.vulnerabilities.filter((v) => v.severity === "low").length,
          info: results.vulnerabilities.filter((v) => v.severity === "info").length,
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
