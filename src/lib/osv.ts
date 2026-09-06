import "server-only";

import { buildOsvQueryBatch, normalizeOsvBatchResponse } from "@/lib/repo-security-rules";
import type { DependencyCoordinate } from "@/lib/repo-security-rules";

const OSV_QUERY_BATCH_URL = "https://api.osv.dev/v1/querybatch";
const OSV_TIMEOUT_MS = 8_000;

export interface OsvScanResult {
  status: "checked" | "partial" | "unavailable" | "not-detected";
  dependenciesChecked: number;
  matches: Array<{ dependency: DependencyCoordinate; ids: string[] }>;
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
    return {
      status: inventoryTruncated || normalized.some((result) => result.paginated) ? "partial" : "checked",
      dependenciesChecked: dependencies.length,
      matches: normalized.filter((result) => result.ids.length).map(({ dependency, ids }) => ({ dependency, ids })),
    };
  } catch {
    return { status: "unavailable", dependenciesChecked: 0, matches: [] };
  } finally {
    clearTimeout(timer);
  }
}
