import { NextRequest } from "next/server";
import { prisma } from "@/lib/db";
import { scanWebsite, ScanProgress, validateScanTarget, VulnerabilityResult, WebsiteScanError } from "@/lib/scanner";
import { admitWebsiteScan } from "@/lib/scan-gate";

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
    normalizedUrl = (await validateScanTarget(normalizedUrl)).toString();
  } catch (error) {
    return new Response(JSON.stringify({ error: error instanceof Error ? error.message : "Invalid URL format" }), {
      status: 400,
      headers: { "Content-Type": "application/json" },
    });
  }

  const admission = await admitWebsiteScan(req, normalizedUrl);
  if (!admission.ok) {
    return new Response(JSON.stringify({ error: admission.error }), {
      status: admission.status,
      headers: { "Content-Type": "application/json", ...(admission.retryAfter ? { "Retry-After": String(admission.retryAfter) } : {}) },
    });
  }
  const userId = admission.userId;
  let creditReserved = admission.creditReserved;

  // Create the readable stream
  const encoder = new TextEncoder();
  const stream = new ReadableStream({
    async start(controller) {
      let scanId: string | null = null;
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
        scanId = scan.id;

        send("scan-created", { scanId: scan.id });

        // Run scan with progress callbacks
        const results = await scanWebsite(normalizedUrl, (progress: ScanProgress) => {
          send("progress", progress);
        });

        send("progress", {
          step: "saving",
          label: "Saving results to database…",
          status: "running",
          totalSteps: 18,
          currentStep: 18,
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

        // The credit was reserved before the scan; only update usage here.
        if (userId) {
          await prisma.user.update({
            where: { id: userId },
            data: {
              scansUsed: { increment: 1 },
            },
          });
        }

        const actionable = results.vulnerabilities.filter((v: VulnerabilityResult) => v.type !== "scan-meta");
        send("complete", {
          scanId: scan.id,
          score: results.score,
          totalVulnerabilities: actionable.length,
          pagesScanned: results.pagesScanned,
          critical: actionable.filter((v: VulnerabilityResult) => v.severity === "critical").length,
          high: actionable.filter((v: VulnerabilityResult) => v.severity === "high").length,
          medium: actionable.filter((v: VulnerabilityResult) => v.severity === "medium").length,
          low: actionable.filter((v: VulnerabilityResult) => v.severity === "low").length,
          info: actionable.filter((v: VulnerabilityResult) => v.severity === "info").length,
        });
      } catch (error) {
        console.error("Stream scan error:", error);
        if (scanId) {
          await prisma.scan.updateMany({
            where: { id: scanId, status: "running" },
            data: { status: "failed" },
          }).catch(() => undefined);
        }
        if (userId && creditReserved) {
          await prisma.user.update({
            where: { id: userId },
            data: { credits: { increment: 1 } },
          }).catch(() => undefined);
          creditReserved = false;
        }
        send("error", {
          message: error instanceof WebsiteScanError ? error.message : "Scan failed. Please check the URL and try again.",
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
