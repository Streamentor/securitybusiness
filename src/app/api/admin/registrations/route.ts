import { NextResponse } from "next/server";
import { requireAdmin } from "@/lib/admin";
import { prisma } from "@/lib/db";
import {
  REGISTRATION_TIMEZONE,
  registrationDays,
  summarizeRegistrations,
  type RegistrationDay,
} from "@/lib/registration-metrics";

const headers = { "Cache-Control": "private, no-store" };

export async function GET(request: Request) {
  try {
    const check = await requireAdmin();
    if (!check.authorized)
      return NextResponse.json(
        { error: check.error },
        { status: 403, headers },
      );
    const days = registrationDays(
      new URL(request.url).searchParams.get("days"),
    );
    if (!days)
      return NextResponse.json(
        { error: "Choose 7, 30 or 90 days." },
        { status: 400, headers },
      );
    const now = new Date();
    // Prisma DateTime is a UTC timestamp without time zone. Boundaries and
    // buckets use calendar dates in Belgrade, including 23/25-hour DST days.
    // Only aggregate counts leave the database, never user records or emails.
    const rows = await prisma.$queryRaw<RegistrationDay[]>`
      WITH clock AS (
        SELECT (${now}::timestamptz AT TIME ZONE ${REGISTRATION_TIMEZONE})::date AS today
      ), bounds AS (
        SELECT today - ${days * 2 - 1}::int AS first_day, today FROM clock
      ), counts AS (
        SELECT (("createdAt" AT TIME ZONE 'UTC') AT TIME ZONE ${REGISTRATION_TIMEZONE})::date AS day,
               COUNT(*)::int AS count
        FROM "User", bounds
        WHERE "createdAt" >= ((first_day::timestamp AT TIME ZONE ${REGISTRATION_TIMEZONE}) AT TIME ZONE 'UTC')
          AND "createdAt" < (${now}::timestamptz AT TIME ZONE 'UTC')
        GROUP BY 1
      )
      SELECT to_char(series.day, 'YYYY-MM-DD') AS date, COALESCE(counts.count, 0)::int AS count
      FROM bounds, LATERAL generate_series(0, ${days * 2 - 1}::int) AS day_offset(n)
      CROSS JOIN LATERAL (SELECT first_day + day_offset.n AS day) AS series
      LEFT JOIN counts ON counts.day = series.day
      ORDER BY series.day
    `;
    return NextResponse.json(
      summarizeRegistrations(rows, days, now.toISOString()),
      { headers },
    );
  } catch {
    return NextResponse.json(
      { error: "Registration data could not be loaded." },
      { status: 500, headers },
    );
  }
}
