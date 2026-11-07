const CHANNEL_ALIASES: Record<string, string> = {
  direct: "direct", google: "google", bing: "bing", duckduckgo: "duckduckgo",
  producthunt: "producthunt", product_hunt: "producthunt", "producthunt.com": "producthunt",
  taaft: "taaft", taaft_feat: "taaft", "theresanaiforthat.com": "taaft",
  saashub: "saashub", "saashub.com": "saashub", toolhunt: "toolhunt", "toolhunt.io": "toolhunt", "toolhunt.dev": "toolhunt",
  peerpush: "peerpush", "peerpush.com": "peerpush",
  submitstartup: "submitstartup", "submitstartup.io": "submitstartup",
  tinylaunch: "tinylaunch", "tinylaunch.com": "tinylaunch",
  launchingnext: "launchingnext", launching_next: "launchingnext", "launchingnext.com": "launchingnext",
  cursor_forum: "cursor_forum", "forum.cursor.com": "cursor_forum",
  reddit: "reddit", vibecodedevs: "reddit", sideproject: "reddit",
  facebook: "facebook", github: "github", youtube: "youtube", twitter: "twitter",
  linkedin: "linkedin", hackernews: "hackernews", unknown: "unknown",
  instagram: "instagram", ig: "instagram", "instagram.com": "instagram",
  tiktok: "tiktok", "tiktok.com": "tiktok",
  stefbuilds: "stefbuilds", "stefbuilds.com": "stefbuilds",
  lovable: "lovable", "lovable.dev": "lovable",
  chatgpt: "ai_assistants", perplexity: "ai_assistants", claude: "ai_assistants",
  medium: "medium", devto: "devto", substack: "substack", "x.com": "twitter", x: "twitter",
};

export interface SourceCount {
  referrerSource: string | null;
  _count: { _all: number };
}

/** Never expose arbitrary UTM/referrer strings in an aggregate response. */
function channelFor(source: string | null): string {
  const normalized = source?.trim().toLowerCase();
  if (!normalized) return "unknown";
  return Object.hasOwn(CHANNEL_ALIASES, normalized) ? CHANNEL_ALIASES[normalized] : "other";
}

export function percent(numerator: number, denominator: number): number | null {
  return denominator > 0 ? Math.round(numerator / denominator * 1000) / 10 : null;
}

export function summarizeChannels(registrations: SourceCount[], started: SourceCount[], completed: SourceCount[]) {
  const channels = new Map<string, { channel: string; registrations: number; usersWithAcceptedWebsiteScan: number; usersWithReadableCompletedWebsiteScan: number }>();
  for (const [rows, key] of [
    [registrations, "registrations"],
    [started, "usersWithAcceptedWebsiteScan"],
    [completed, "usersWithReadableCompletedWebsiteScan"],
  ] as const) {
    for (const row of rows) {
      const channel = channelFor(row.referrerSource);
      const summary = channels.get(channel) ?? { channel, registrations: 0, usersWithAcceptedWebsiteScan: 0, usersWithReadableCompletedWebsiteScan: 0 };
      summary[key] += row._count._all;
      channels.set(channel, summary);
    }
  }
  return [...channels.values()].sort((a, b) => a.channel.localeCompare(b.channel)).map((row) => ({
    ...row,
    registeredUserActivationPercent: percent(row.usersWithReadableCompletedWebsiteScan, row.registrations),
  }));
}

export function summarizeStatuses(rows: Array<{ status: string; _count: { _all: number } }>) {
  const totals = { pending: 0, running: 0, completed: 0, failed: 0, other: 0 };
  for (const row of rows) {
    const status = row.status === "pending" || row.status === "running" || row.status === "completed" || row.status === "failed" ? row.status : "other";
    totals[status] += row._count._all;
  }
  return { accepted: Object.values(totals).reduce((sum, count) => sum + count, 0), ...totals };
}
