export interface ComparableFinding {
  title: string;
  url: string;
}

/**
 * Compare two reports of the same site by finding title. Page URLs are ignored so
 * a crawl that reaches different pages does not turn one issue into "new" plus "resolved".
 */
export function compareScanFindings(previous: readonly ComparableFinding[], current: readonly ComparableFinding[]) {
  const before = new Set(previous.map((finding) => finding.title));
  const after = new Set(current.map((finding) => finding.title));
  const resolved = [...before].filter((title) => !after.has(title)).sort();
  const added = [...after].filter((title) => !before.has(title)).sort();
  const stillOpen = [...after].filter((title) => before.has(title)).length;
  return { resolved, added, stillOpen };
}
