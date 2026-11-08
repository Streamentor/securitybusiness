"use client";

import { useEffect, useState, useSyncExternalStore } from "react";
import { RefreshCw, Loader2 } from "lucide-react";
import type {
  RegistrationDays,
  RegistrationMetrics,
} from "@/lib/registration-metrics";

function subscribeToWidth(change: () => void) {
  const media = window.matchMedia("(max-width: 639px)");
  media.addEventListener("change", change);
  return () => media.removeEventListener("change", change);
}

function label(date: string) {
  return new Date(`${date}T12:00:00Z`).toLocaleDateString("en-GB", {
    day: "numeric",
    month: "short",
    timeZone: "UTC",
  });
}

export function AdminRegistrationChart() {
  const narrow = useSyncExternalStore(
    subscribeToWidth,
    () => window.matchMedia("(max-width: 639px)").matches,
    () => false,
  );
  const plotWidth = narrow ? 340 : 900;
  const plotSpan = plotWidth - 50;
  const [days, setDays] = useState<RegistrationDays>(30);
  const [attempt, setAttempt] = useState(0);
  const [data, setData] = useState<RegistrationMetrics | null>(null);
  const [loading, setLoading] = useState(true);
  const [error, setError] = useState(false);
  const [selected, setSelected] = useState("");

  useEffect(() => {
    const controller = new AbortController();
    let active = true;
    async function load() {
      try {
        const response = await fetch(`/api/admin/registrations?days=${days}`, {
          cache: "no-store",
          signal: controller.signal,
        });
        if (!response.ok) throw new Error("Unavailable");
        const body: RegistrationMetrics = await response.json();
        if (active) {
          setData(body);
          setLoading(false);
        }
      } catch {
        if (active) {
          setError(true);
          setLoading(false);
        }
      }
    }
    load();
    return () => {
      active = false;
      controller.abort();
    };
  }, [days, attempt]);

  function reload(range = days) {
    setLoading(true);
    setError(false);
    setData(null);
    setDays(range);
    setAttempt((n) => n + 1);
  }
  const current =
    data?.series.find((day) => day.date === selected) ?? data?.series.at(-1);
  const ceiling = data
    ? Math.max(
        4,
        Math.ceil(Math.max(...data.series.map((d) => d.count)) / 4) * 4,
      )
    : 4;

  return (
    <section
      aria-labelledby="registration-chart-title"
      className="rounded-xl border border-gray-800 bg-gray-900 p-5"
    >
      <div className="flex flex-wrap items-start justify-between gap-4">
        <div>
          <h2
            id="registration-chart-title"
            className="text-base font-semibold text-white"
          >
            Registrations by day
          </h2>
          <p className="mt-1 text-xs leading-5 text-gray-400">
            Calendar days · Europe/Belgrade · includes admin accounts
          </p>
        </div>
        <div className="flex gap-2">
          <div
            role="group"
            aria-label="Registration date range"
            className="flex rounded-lg border border-gray-700 p-1"
          >
            {([7, 30, 90] as const).map((range) => (
              <button
                key={range}
                type="button"
                aria-pressed={days === range}
                onClick={() => reload(range)}
                className={`rounded-md px-3 py-1.5 text-xs font-medium focus-visible:outline-2 focus-visible:outline-emerald-400 ${days === range ? "bg-gray-700 text-white" : "text-gray-400 hover:text-white"}`}
              >
                {range} days
              </button>
            ))}
          </div>
          <button
            type="button"
            onClick={() => reload()}
            disabled={loading}
            aria-label="Refresh registrations"
            className="rounded-lg border border-gray-700 px-3 text-gray-300 hover:bg-gray-800 disabled:opacity-50"
          >
            <RefreshCw aria-hidden="true" className="h-4 w-4" />
          </button>
        </div>
      </div>
      {loading ? (
        <div
          role="status"
          className="flex min-h-80 items-center justify-center gap-2 text-sm text-gray-400"
        >
          <Loader2 aria-hidden="true" className="h-4 w-4 animate-spin" />
          Loading registrations…
        </div>
      ) : error || !data ? (
        <div
          role="alert"
          className="flex min-h-80 flex-col items-center justify-center gap-3 text-sm text-gray-400"
        >
          <p>Registration data could not be loaded.</p>
          <button
            onClick={() => reload()}
            className="rounded-lg border border-gray-700 px-4 py-2 text-white"
          >
            Try again
          </button>
        </div>
      ) : (
        <>
          <div className="mt-5 grid gap-4 sm:grid-cols-3">
            <div>
              <p className="text-xs text-gray-400">
                {label(data.current.start)} – {label(data.current.end)}
              </p>
              <p className="mt-1 text-2xl font-semibold text-white">
                {data.current.total}
                <span className="ml-2 text-xs font-normal text-gray-400">
                  new accounts
                </span>
              </p>
            </div>
            <div>
              <p className="text-xs text-gray-400">
                Previous {days} days · {label(data.previous.start)} –{" "}
                {label(data.previous.end)}
              </p>
              <p className="mt-1 text-xl text-white">
                {data.previous.total}
                <span
                  className={`ml-2 text-xs ${data.changePercent !== null && data.changePercent > 0 ? "text-emerald-400" : "text-gray-400"}`}
                >
                  {data.changePercent === null
                    ? "No previous registrations"
                    : `${data.changePercent > 0 ? "+" : ""}${data.changePercent}%`}
                </span>
              </p>
            </div>
            <div aria-live="polite">
              <p className="text-xs text-gray-400">
                {current && label(current.date)}
                {current?.date === data.current.end ? " · today so far" : ""}
              </p>
              <p className="mt-1 text-xl text-white">
                {current?.count ?? "—"}
                <span className="ml-2 text-xs text-gray-400">
                  registrations
                </span>
              </p>
            </div>
          </div>
          {data.current.total === 0 && (
            <p className="mt-4 text-sm text-gray-400">
              No registrations in this period.
            </p>
          )}
          <p className="mt-4 text-xs text-gray-500">
            Today is incomplete; the previous period contains full days. Hover
            or focus a bar for its count. Use arrow keys to move between days.
          </p>
          <div className="mt-3 overflow-x-auto">
            <svg
              role="group"
              aria-label={`Daily registrations from ${data.current.start} to ${data.current.end}. ${data.current.total} new accounts. Full values are in the daily table below.`}
              viewBox={`0 0 ${plotWidth} 260`}
              className="h-64 w-full"
            >
              {[0, 1, 2, 3, 4].map((tick) => (
                <g key={tick}>
                  <line
                    x1="38"
                    x2={plotWidth - 12}
                    y1={218 - tick * 48}
                    y2={218 - tick * 48}
                    stroke="#263142"
                  />
                  <text
                    x="29"
                    y={223 - tick * 48}
                    textAnchor="end"
                    fontSize="13"
                    fill="#9ca3af"
                  >
                    {(ceiling / 4) * tick}
                  </text>
                </g>
              ))}
              {data.series.map((day, i) => {
                const step = plotSpan / data.series.length,
                  x = 38 + i * step + 1,
                  height = (day.count / ceiling) * 192;
                return (
                  <g key={day.date}>
                    <rect
                      role="button"
                      aria-label={`${label(day.date)}: ${day.count} registrations`}
                      tabIndex={current?.date === day.date ? 0 : -1}
                      x={x}
                      y="24"
                      width={Math.max(2, step - 2)}
                      height="194"
                      fill="transparent"
                      className="cursor-pointer focus:outline-2 focus:outline-emerald-400"
                      onMouseEnter={() => setSelected(day.date)}
                      onFocus={() => setSelected(day.date)}
                      onClick={() => setSelected(day.date)}
                      onKeyDown={(event) => {
                        const next =
                          event.key === "ArrowLeft"
                            ? Math.max(0, i - 1)
                            : event.key === "ArrowRight"
                              ? Math.min(data.series.length - 1, i + 1)
                              : event.key === "Home"
                                ? 0
                                : event.key === "End"
                                  ? data.series.length - 1
                                  : null;
                        if (next !== null) {
                          event.preventDefault();
                          const bars = event.currentTarget
                            .closest("svg")
                            ?.querySelectorAll<SVGRectElement>(
                              'rect[role="button"]',
                            );
                          bars?.[next]?.focus();
                        }
                      }}
                    />
                    <rect
                      aria-hidden="true"
                      pointerEvents="none"
                      x={x}
                      y={218 - Math.max(height, 2)}
                      width={Math.max(2, step - 2)}
                      height={Math.max(height, 2)}
                      rx="2"
                      fill={
                        current?.date === day.date
                          ? "#b9ff66"
                          : day.count
                            ? "#34d399"
                            : "#4b5563"
                      }
                    />
                  </g>
                );
              })}
              {[
                ...new Set([
                  0,
                  Math.floor((days - 1) / 3),
                  Math.floor(((days - 1) * 2) / 3),
                  days - 1,
                ]),
              ].map((i) => (
                <text
                  key={i}
                  x={38 + ((i + 0.5) * plotSpan) / days}
                  y="245"
                  textAnchor={
                    i === 0 ? "start" : i === days - 1 ? "end" : "middle"
                  }
                  fontSize="13"
                  fill="#9ca3af"
                >
                  {label(data.series[i].date)}
                </text>
              ))}
            </svg>
          </div>
          <details className="mt-2">
            <summary className="cursor-pointer text-xs font-medium text-gray-300">
              Daily registration table
            </summary>
            <div className="mt-3 max-h-64 overflow-auto">
              <table className="w-full text-left text-sm">
                <caption className="sr-only">
                  Registrations by calendar day in Europe/Belgrade
                </caption>
                <thead className="sticky top-0 bg-gray-900 text-gray-400">
                  <tr>
                    <th scope="col" className="py-2">
                      Date
                    </th>
                    <th scope="col" className="py-2 text-right">
                      Registrations
                    </th>
                  </tr>
                </thead>
                <tbody>
                  {data.series
                    .slice()
                    .reverse()
                    .map((day) => (
                      <tr key={day.date} className="border-t border-gray-800">
                        <th
                          scope="row"
                          className="py-2 font-normal text-gray-300"
                        >
                          {day.date}
                          {day.date === data.current.end
                            ? " (today so far)"
                            : ""}
                        </th>
                        <td className="py-2 text-right text-white">
                          {day.count}
                        </td>
                      </tr>
                    ))}
                </tbody>
              </table>
            </div>
          </details>
          <p className="mt-4 text-xs text-gray-500">
            Updated{" "}
            {new Date(data.observedAt).toLocaleString("en-GB", {
              timeZone: data.timezone,
            })}{" "}
            · calendar totals can differ from the rolling 7/30-day cards above.
            Test accounts are not identified separately.
          </p>
        </>
      )}
    </section>
  );
}
