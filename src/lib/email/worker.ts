import "server-only";
import { randomUUID } from "node:crypto";
import { prisma } from "@/lib/db";
import { sequenceMode, startAt, deliveryConfig, validEmail } from "@/lib/email/config";
import { loadEmailContext } from "@/lib/email/context";
import { eligible, dueEmail } from "@/lib/email/policy";
import { ensureEmailTables, lockEmailUser, reserveSend } from "@/lib/email/store";
import { renderEmail } from "@/lib/email/templates";
import { sendEmail } from "@/lib/email/ses";
import type { EmailContext, EmailKey } from "@/lib/email/types";
export async function processEmailUser(userId: string, now = new Date()): Promise<boolean> {
  const mode = sequenceMode(), start = startAt(); if (mode === "off" || !start) return false;
  const cfg = deliveryConfig();
  const c = await loadEmailContext(userId, now); if (!c || !eligible(c, start)) return false;
  const history = mode === "dry-run"
    ? await prisma.emailTestSend.findMany({ where: { userId, mode: "dry-run" }, orderBy: { createdAt: "desc" } })
    : await prisma.emailSend.findMany({ where: { userId }, orderBy: { createdAt: "desc" } });
  const key = dueEmail(c, history, now); if (!key) return false;
  // Validate before reserving, so incomplete templates never consume a key.
  const email = renderEmail(key, c, cfg.address);
  if (mode === "dry-run") return sendAdminTest(c, key, "dry-run");
  const id = await reserveSend(userId, key, now); if (!id) return false;
  // Reservation is already durable. Never retry an ambiguous provider outcome.
  try {
    return await prisma.$transaction(async tx => {
      if (!await lockEmailUser(tx, userId)) return false;
      const fresh = await tx.user.findUnique({ where: { id: userId }, include: { emailPreference: true } });
      if (!fresh || fresh.email !== c.email || fresh.plan !== "free" || fresh.emailPreference?.marketingOptOut || fresh.emailPreference?.suppressed || !fresh.emailPreference?.consentAt || sequenceMode() !== "live" || !startAt() || +fresh.createdAt < +startAt()!) {
        await tx.emailSend.update({ where: { id }, data: { status: "cancelled" } }); return false;
      }
      try {
        const sesMessageId = await sendEmail(fresh.email, email, id);
        await tx.emailSend.update({ where: { id }, data: { status: "sent", sesMessageId } });
        return true;
      } catch {
        await tx.emailSend.update({ where: { id }, data: { status: "unknown" } });
        console.error("Email send outcome unknown; automatic retry disabled"); return false;
      }
    }, { maxWait: 5_000, timeout: 15_000 });
  } catch { console.error("Email send finalization failed; reservation retained"); return false; }
}
export async function sendAdminTest(c: EmailContext, key: EmailKey, mode: "test" | "dry-run", adminId?: string): Promise<boolean> {
  if (sequenceMode() === "off") throw new Error("Email sending is off");
  await ensureEmailTables();
  const admin = await prisma.user.findFirst({ where: { role: "admin", ...(adminId ? { id: adminId } : {}) }, orderBy: { createdAt: "asc" }, include: { emailPreference: true } });
  if (!admin || !validEmail(admin.email) || admin.emailPreference?.suppressed || admin.emailPreference?.marketingOptOut) throw new Error("Admin test recipient unavailable");
  const cfg = deliveryConfig(); const email = renderEmail(key, c, cfg.address); const id = randomUUID();
  // Limit manual test sending too. Partial unique index isolates dry-run from live history.
  const reserved = await prisma.$transaction(async tx => {
    await lockEmailUser(tx, admin.id);
    const recent = await tx.emailTestSend.count({ where: { adminId: admin.id, createdAt: { gte: new Date(Date.now() - 3_600_000) } } });
    if (recent >= 50) return false;
    if (mode === "dry-run" && await tx.emailTestSend.findFirst({ where: { userId: c.userId, emailKey: key, mode } })) return false;
    await tx.emailTestSend.create({ data: { id, adminId: admin.id, userId: c.userId, emailKey: key, mode, status: "sending" } }); return true;
  });
  if (!reserved) return false;
  try {
    return await prisma.$transaction(async tx => {
      if (!await lockEmailUser(tx, admin.id)) return false;
      const fresh = await tx.user.findUnique({ where: { id: admin.id }, include: { emailPreference: true } });
      if (!fresh || fresh.role !== "admin" || !validEmail(fresh.email) || fresh.emailPreference?.suppressed || fresh.emailPreference?.marketingOptOut || sequenceMode() === "off") {
        await tx.emailTestSend.update({ where: { id }, data: { status: "cancelled" } }); return false;
      }
      try {
        const sesMessageId = await sendEmail(fresh.email, email, id, `[${mode} → ${c.email}] `);
        await tx.emailTestSend.update({ where: { id }, data: { status: "sent", sesMessageId } }); return true;
      } catch {
        await tx.emailTestSend.update({ where: { id }, data: { status: "unknown" } }); console.error("Admin test send outcome unknown"); return false;
      }
    }, { maxWait: 5_000, timeout: 15_000 });
  } catch { console.error("Admin test finalization failed; reservation retained"); return false; }
}
export async function runEmailSequence() {
  const mode = sequenceMode(), start = startAt();
  if (mode === "off" || !start) return { mode, examined: 0, sent: 0 };
  deliveryConfig(); await ensureEmailTables();
  const began = Date.now(); let examined = 0, sent = 0;
  // One PostgreSQL advisory transaction lock elects a single cron coordinator.
  return prisma.$transaction(async tx => {
    const [lock] = await tx.$queryRaw<Array<{ locked: boolean }>>`SELECT pg_try_advisory_xact_lock(785217901) AS locked`;
    if (!lock?.locked) return { mode, examined: 0, sent: 0 };
    const users = await tx.user.findMany({ where: { plan: "free", createdAt: { gte: new Date(Math.max(+start, began - 33 * 86_400_000)) }, emailPreference: { is: { consentAt: { not: null }, marketingOptOut: false, suppressed: false } } }, orderBy: [{ emailPreference: { lastSequenceCheckAt: { sort: "asc", nulls: "first" } } }, { createdAt: "asc" }], take: 500, select: { id: true } });
    for (const u of users) {
      if (sent >= 50 || Date.now() - began > 45_000) break;
      examined++;
      try { await prisma.emailPreference.update({ where: { userId: u.id }, data: { lastSequenceCheckAt: new Date() } }); if (await processEmailUser(u.id)) sent++; } catch { console.error("Email candidate skipped: validation or configuration failed"); }
    }
    return { mode, examined, sent };
  }, { timeout: 60_000, maxWait: 1_000 });
}
/** Off/preview paths perform no reads or sends. Failures cannot fail registration or scans. */
export async function maybeSendWelcome(userId: string) {
  if (sequenceMode() === "off") return;
  try { await processEmailUser(userId); } catch { console.error("Welcome email skipped"); }
}
