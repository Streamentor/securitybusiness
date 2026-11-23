import assert from "node:assert/strict";
import "./scan-test-hook.mjs";
const { extractDependencyInventory } = await import("../src/lib/repo-security-rules.ts");
const { formatDependencyFinding } = await import("../src/lib/osv-advisory.ts");

const { dependencies } = extractDependencyInventory([{ path: "package-lock.json", content: JSON.stringify({
  packages: { "": { devDependencies: { lint: "1.0.0" } }, "node_modules/minimatch": { version: "3.1.1", dev: true } },
}, null, 2) }]);
const advisory = (id, fixed) => ({
  id, database_specific: { severity: "MODERATE" },
  affected: [{ package: { name: "minimatch", ecosystem: "npm" }, ranges: [{ type: "SEMVER", events: [{ introduced: "0" }, { fixed }, { introduced: "4.0.0" }, { fixed: "4.0.9" }] }] }],
});
const advisories = new Map([["GHSA-fixture-one", advisory("GHSA-fixture-one", "3.1.2")], ["GHSA-fixture-two", advisory("GHSA-fixture-two", "3.1.3")]]);
const finding = formatDependencyFinding(dependencies[0], [...advisories.keys()], advisories);
assert.equal(finding.severity, "low");
assert.match(finding.description, /2 advisory match/);
assert.match(finding.description, /Transitive dependency/);
assert.match(finding.description, /dev\/build tooling/);
assert.match(finding.remedy, /3\.1\.3/);
assert.match(finding.remedy, /npm explain minimatch/);
const vector = { ...advisory("CVE-fixture", "3.1.2"), database_specific: undefined, severity: [{ type: "CVSS_V3", score: "CVSS:3.1/AV:N/AC:L/PR:N/UI:N/S:U/C:H/I:H/A:H" }] };
assert.equal(formatDependencyFinding({ ...dependencies[0], devOnly: false }, [vector.id], new Map([[vector.id, vector]])).severity, "critical");
console.log("OSV severity, grouping and fixed version checks passed.");
