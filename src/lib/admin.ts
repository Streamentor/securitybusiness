import { auth } from "@/lib/auth";
import { prisma } from "@/lib/db";

/**
 * Check if the current session user is an admin.
 * Always verifies against the DB (not just the JWT) for safety.
 */
export async function requireAdmin() {
  const session = await auth();

  if (!session?.user?.id) {
    return { authorized: false as const, error: "Not authenticated" };
  }

  const user = await prisma.user.findUnique({
    where: { id: session.user.id },
    select: { role: true },
  });

  if (!user || user.role !== "admin") {
    return { authorized: false as const, error: "Forbidden" };
  }

  return { authorized: true as const, userId: session.user.id };
}
