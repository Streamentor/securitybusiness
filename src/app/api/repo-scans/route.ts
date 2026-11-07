import { NextRequest, NextResponse, after } from "next/server";
import { auth } from "@/lib/auth";
import { GitHubScannerError } from "@/lib/github-scanner";
import { createRepoScanJob, listRepoScansForUser, RepoJobError, runRepoScanJob } from "@/lib/repo-scan-jobs";

// The scan continues after the response for up to this long.
export const maxDuration = 120;

export async function POST(request: NextRequest) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Sign in to save repository scans.", code: "unauthorized" }, { status: 401 });
  let body: unknown;
  try { body = await request.json(); } catch { return NextResponse.json({ error: "The request body must be valid JSON." }, { status: 400 }); }
  const input = typeof body === "object" && body !== null && "repository" in body ? String((body as { repository: unknown }).repository || "").trim() : "";
  const authorized = typeof body === "object" && body !== null && (body as { authorized?: unknown }).authorized === true;
  if (!input) return NextResponse.json({ error: "Choose a repository to scan." }, { status: 400 });
  if (!authorized) return NextResponse.json({ error: "Confirm that you own the repository or have permission to scan it.", code: "authorization_required" }, { status: 400 });

  try {
    const job = await createRepoScanJob(session.user.id, input);
    // Runs after the response: the browser can leave and come back to /repo-scan/<id>.
    after(() => runRepoScanJob(job.id));
    return NextResponse.json({ id: job.id }, { status: 202 });
  } catch (error) {
    if (error instanceof RepoJobError) return NextResponse.json({ error: error.message, code: error.code }, { status: error.status });
    if (error instanceof GitHubScannerError) return NextResponse.json({ error: error.message, code: error.code }, { status: 400 });
    console.error("Creating repository scan failed:", error instanceof Error ? error.message : "unknown");
    return NextResponse.json({ error: "The scan could not be started. Try again in a moment." }, { status: 500 });
  }
}

export async function GET() {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Sign in first." }, { status: 401 });
  try {
    return NextResponse.json(await listRepoScansForUser(session.user.id));
  } catch (error) {
    console.error("Listing repository scans failed:", error instanceof Error ? error.message : "unknown");
    return NextResponse.json([], { status: 200 });
  }
}
