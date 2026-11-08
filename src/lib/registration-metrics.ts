export const REGISTRATION_TIMEZONE = "Europe/Belgrade";
export type RegistrationDays = 7 | 30 | 90;
export interface RegistrationDay {
  date: string;
  count: number;
}
export interface RegistrationMetrics {
  days: RegistrationDays;
  timezone: string;
  observedAt: string;
  current: { start: string; end: string; total: number };
  previous: { start: string; end: string; total: number };
  changePercent: number | null;
  series: RegistrationDay[];
}
export function registrationDays(
  value: string | null,
): RegistrationDays | null {
  if (value === null || value === "30") return 30;
  return value === "7" ? 7 : value === "90" ? 90 : null;
}
export function summarizeRegistrations(
  rows: RegistrationDay[],
  days: RegistrationDays,
  observedAt: string,
): RegistrationMetrics {
  if (
    rows.length !== days * 2 ||
    rows.some(
      (row) =>
        !/^\d{4}-\d{2}-\d{2}$/.test(row.date) ||
        !Number.isSafeInteger(row.count) ||
        row.count < 0,
    )
  )
    throw new Error("Invalid registration aggregates");
  const previous = rows.slice(0, days),
    current = rows.slice(days);
  const total = (items: RegistrationDay[]) =>
    items.reduce((sum, row) => sum + row.count, 0);
  const currentTotal = total(current),
    previousTotal = total(previous);
  return {
    days,
    timezone: REGISTRATION_TIMEZONE,
    observedAt,
    current: {
      start: current[0].date,
      end: current.at(-1)!.date,
      total: currentTotal,
    },
    previous: {
      start: previous[0].date,
      end: previous.at(-1)!.date,
      total: previousTotal,
    },
    changePercent: previousTotal
      ? Math.round(((currentTotal - previousTotal) / previousTotal) * 1000) / 10
      : null,
    series: current,
  };
}
