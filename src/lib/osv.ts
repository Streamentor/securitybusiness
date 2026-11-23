import "server-only";

import { buildOsvQueryBatch, normalizeOsvBatchResponse } from "@/lib/repo-security-rules";
import type { DependencyCoordinate } from "@/lib/repo-security-rules";
import type { OsvAdvisory } from "@/lib/osv-advisory";

const OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_TIMEOUT_MS = 8_000;

export interface OsvScanResult {
  status: "checked" | "partial" | "unavailable" | "not-detected";
  dependenciesChecked: number;
  matches: Array<{ dependency: DependencyCoordinate; ids: string[]; advisories?: Map<string, OsvAdvisory> }>;
}

export async function queryKnownVulnerabilities(dependencies: DependencyCoordinate[], inventoryTruncated = false): Promise<OsvScanResult> {
  if (!dependencies.length) return { status: "not-detected", dependenciesChecked: 0, matches: [] };
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), OSV_TIMEOUT_MS);
  try {
    const response = await fetch(OSV_QUERY_BATCH_URL, {
      method: "POST",
      headers: { "Content-Type": "application/json", "User-Agent": "ScanMySaaS-Dependency-Scanner/1.0" },
      body: JSON.stringify(buildOsvQueryBatch(dependencies)),
      signal: controller.signal,
      cache: "no-store",
    });
    if (!response.ok) return { status: "unavailable", dependenciesChecked: 0, matches: [] };
    const normalized = normalizeOsvBatchResponse(await response.json(), dependencies);
    if (!normalized) return { status: "unavailable", dependenciesChecked: 0, matches: [] };
    const matches = normalized.filter((result) => result.ids.length);
    const ids = [...new Set(matches.flatMap((result) => result.ids))];
    const advisories = new Map<string, OsvAdvisory>();
    const queue = ids.filter((id) => /^[A-Za-z0-9._-]{1,100}$/.test(id)).slice(0, 48);
    await Promise.all(Array.from({ length: Math.min(6, queue.length) }, async () => {
      while (queue.length && !controller.signal.aborted) {
        const id = queue.shift()!;
        try {
          const detail = await fetch("https://api.osv.dev/v1/vulns/" + encodeURIComponent(id), { signal: controller.signal, cache: "no-store" });
          if (detail.ok) {
            const item = await detail.json() as OsvAdvisory;
            if (item.id === id) advisories.set(id, item);
          }
        } catch { /* Batch matches remain valid if advisory details time out. */ }
      }
    }));
    return {
      status: inventoryTruncated || normalized.some((result) => result.paginated) || advisories.size !== ids.length ? "partial" : "checked",
      dependenciesChecked: dependencies.length,
      matches: matches.map(({ dependency, ids }) => ({ dependency, ids, advisories })),
    };
  } catch {
    return { status: "unavailable", dependenciesChecked: 0, matches: [] };
  } finally {
    clearTimeout(timer);
  }
}
