import { NextRequest, NextResponse } from "next/server";
import { auth } from "@/lib/auth";
import { getRepoScanForUser } from "@/lib/repo-scan-jobs";

export async function GET(_request: NextRequest, { params }: { params: Promise<{ id: string }> }) {
  const session = await auth();
  if (!session?.user?.id) return NextResponse.json({ error: "Sign in to view this report." }, { status: 401 });
  const { id } = await params;
  // Owner-only: private repository reports are never shared by link.
  const job = await getRepoScanForUser(id, session.user.id);
  if (!job) return NextResponse.json({ error: "Scan not found." }, { status: 404 });
  return NextResponse.json(job, { headers: { "Cache-Control": "no-store" } });
}
