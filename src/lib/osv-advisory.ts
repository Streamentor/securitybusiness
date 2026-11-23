import type { DependencyCoordinate } from "./repo-security-rules";
import type { RepoFinding, RepoSeverity } from "./github-scanner";

export interface OsvAdvisory {
  id: string;
  database_specific?: { severity?: string };
  severity?: Array<{ type: string; score: string }>;
  affected?: Array<{
    package?: { ecosystem: string; name: string };
    database_specific?: { severity?: string };
    ranges?: Array<{ type: string; events: Array<{ introduced?: string; fixed?: string; last_affected?: string; limit?: string }> }>;
  }>;
}

const levels: RepoSeverity[] = ["low", "medium", "high", "critical"];
function cvssScore(vector: string) {
  if (/^(?:\d(?:\.\d)?|10(?:\.0)?)$/.test(vector)) return Number(vector);
  if (!vector.startsWith("CVSS:3.")) return undefined;
  const metrics = new Map(vector.split("/").slice(1).map((entry) => entry.split(":") as [string, string]));
  const get = (name: string, values: Record<string, number>) => values[metrics.get(name) ?? ""];
  const changed = metrics.get("S") === "C";
  const scope = metrics.get("S");
  if (scope !== "U" && scope !== "C") return undefined;
  const iss = 1 - (1 - get("C", { H: .56, L: .22, N: 0 })) * (1 - get("I", { H: .56, L: .22, N: 0 })) * (1 - get("A", { H: .56, L: .22, N: 0 }));
  const impact = changed ? 7.52 * (iss - .029) - 3.25 * (iss - .02) ** 15 : 6.42 * iss;
  const exploitability = 8.22 * get("AV", { N: .85, A: .62, L: .55, P: .2 }) * get("AC", { L: .77, H: .44 })
    * get("PR", { N: .85, L: changed ? .68 : .62, H: changed ? .5 : .27 }) * get("UI", { N: .85, R: .62 });
  return Number.isFinite(impact + exploitability) ? impact <= 0 ? 0 : Math.ceil(Math.min(10, (changed ? 1.08 : 1) * (impact + exploitability)) * 10 - 1e-8) / 10 : undefined;
}

function compareStable(a: string, b: string) {
  const item = (value: string) => /^v?(\d+)\.(\d+)\.(\d+)(?:\+[\w.-]+)?$/.exec(value)?.slice(1).map(Number);
  const [left, right] = [item(a), item(b)];
  if (!left || !right) return undefined;
  return left.reduce((result, value, index) => result || value - right[index], 0);
}

function nearestKnownFix(affected: NonNullable<OsvAdvisory["affected"]>, dependency: DependencyCoordinate) {
  const fixes: string[] = [];
  for (const entry of affected) for (const range of entry.ranges ?? []) {
    if (range.type !== "SEMVER" && range.type !== "ECOSYSTEM") continue;
    let affectedHere = false;
    for (const event of range.events) {
      if (event.introduced !== undefined) affectedHere = event.introduced === "0" || (compareStable(event.introduced, dependency.version) ?? 1) <= 0;
      if (event.fixed !== undefined) {
        if (affectedHere && (compareStable(event.fixed, dependency.version) ?? 0) > 0) fixes.push(event.fixed);
        affectedHere = false;
      }
      if (event.last_affected !== undefined || event.limit !== undefined) affectedHere = false;
    }
  }
  return fixes.sort((a, b) => compareStable(a, b) ?? 0)[0];
}

export function formatDependencyFinding(dependency: DependencyCoordinate, ids: readonly string[], advisories: ReadonlyMap<string, OsvAdvisory>): Omit<RepoFinding, "id"> {
  const ratings: RepoSeverity[] = [];
  const fixes: string[] = [];
  for (const id of ids) {
    const advisory = advisories.get(id);
    if (!advisory) continue;
    const affected = (advisory.affected ?? []).filter((item) => item.package?.ecosystem === dependency.ecosystem && item.package.name === dependency.name);
    const reported = (advisory.database_specific?.severity ?? affected.find((item) => item.database_specific?.severity)?.database_specific?.severity ?? "").toLowerCase();
    const tag = reported === "moderate" ? "medium" : reported;
    if (levels.includes(tag as RepoSeverity)) ratings.push(tag as RepoSeverity);
    else {
      const scores = (advisory.severity ?? []).map((entry) => cvssScore(entry.score)).filter((score): score is number => score !== undefined);
      if (scores.length) {
        const score = Math.max(...scores);
        ratings.push(score >= 9 ? "critical" : score >= 7 ? "high" : score >= 4 ? "medium" : "low");
      }
    }
    const fix = nearestKnownFix(affected, dependency);
    if (fix) fixes.push(fix);
  }
  const highest = Math.max(0, ...ratings.map((rating) => levels.indexOf(rating)));
  const severity = levels[Math.max(0, highest - (dependency.devOnly ? 1 : 0))];
  const allFixes = fixes.length === ids.length ? fixes.sort((a, b) => compareStable(b, a) ?? 0)[0] : undefined;
  const direct = dependency.direct === true ? "Direct dependency." : dependency.direct === false ? "Transitive dependency." : "Dependency relationship unavailable.";
  const safeNpmName = /^(?:@[a-z\d._-]+\/)?[a-z\d._-]+$/i.test(dependency.name);
  const dev = dependency.devOnly ? " The lockfile marks this as dev/build tooling; check your packaging to confirm it is not shipped to users. Priority is reduced one level." : "";
  const upgrade = allFixes && dependency.ecosystem === "npm" && safeNpmName
    ? dependency.direct ? " Run npm install " + (dependency.devOnly ? "--save-dev " : "") + dependency.name + "@" + allFixes + " and regenerate the lockfile."
      : " Run npm explain " + dependency.name + " to identify the parent dependency, then upgrade the parent and verify the resolved version."
    : allFixes && dependency.ecosystem === "PyPI" && /^[A-Za-z\d_.-]+$/.test(dependency.name)
      ? " Update the pinned requirement to " + dependency.name + "==" + allFixes + " and reinstall with pip."
      : allFixes && dependency.ecosystem === "Go" && /^[A-Za-z\d._/-]+$/.test(dependency.name)
        ? " Run go get " + dependency.name + "@v" + allFixes.replace(/^v/, "") + " and review the go.mod diff."
        : allFixes && dependency.ecosystem === "crates.io" && /^[A-Za-z\d_-]+$/.test(dependency.name)
          ? " Run cargo update -p " + dependency.name + " --precise " + allFixes + " after checking Cargo.toml constraints."
          : "";
  return {
    severity, category: "dependencies", file: dependency.file, line: dependency.line,
    title: "Known advisories for " + dependency.name + "@" + dependency.version,
    description: ids.length + " advisory match(es) on this version. " + direct + dev
      + (ratings.length ? " Highest advisory severity available: " + levels[highest] + "." : " Advisory severity was unavailable.")
      + " " + ids.slice(0, 6).join(", "),
    remedy: (allFixes ? "Nearest fixed version covering the returned advisories: " + allFixes + "." : fixes.length
      ? "Known fixed version(s) for some advisories: " + [...new Set(fixes)].join(", ") + ". Open the remaining advisories to verify a common fixed version."
      : "A fixed version could not be confirmed from the advisory data.") + upgrade + " Check the resolved lockfile and test before deploying.",
    referenceUrl: ids[0] ? "https://osv.dev/vulnerability/" + encodeURIComponent(ids[0]) : undefined,
  };
}
