// Voice: Stefan, first person. Short sentences, no hype, emoji or exclamation marks.
// Fear must come from the user's dated scan, never a claim of current exploitation.
// One idea and primary CTA; no invented urgency, results, promises or timing.
import { PLANS } from "@/lib/stripe";
import { ORIGIN } from "@/lib/email/config";
import { unsubscribeUrl } from "@/lib/email/tokens";
import { safeText } from "@/lib/email/finding-impact";
import type { EmailContext, EmailKey, RenderedEmail } from "@/lib/email/types";
export function emailLink(path: string, key: EmailKey): string {
  const url = new URL(path, ORIGIN);
  if (url.origin !== ORIGIN) throw new Error("Invalid email link");
  url.searchParams.set("utm_source", "email"); url.searchParams.set("utm_medium", "onboarding"); url.searchParams.set("utm_campaign", key);
  return url.href;
}
function date(d: Date) { return d.toLocaleDateString("en-US", { timeZone: "UTC", month: "short", day: "numeric", year: "numeric" }); }
function htmlEscape(s: string) { return s.replace(/&/g, "&amp;").replace(/</g, "&lt;").replace(/>/g, "&gt;").replace(/"/g, "&quot;"); }
function linkLabel(url: string): string {
  const path = new URL(url).pathname;
  if (path === "/api/email/unsubscribe") return "Unsubscribe";
  if (path.startsWith("/repo-scan/")) return "Open your repository report";
  if (path.startsWith("/scan/")) return "Open your report";
  if (path === "/pricing") return "See Starter and Pro";
  if (path === "/repo-scan") return "Scan your repository";
  return "Scan your app";
}
export function minimalHtml(text: string): string {
  // Escape text and hrefs separately. Full URLs stay in the plain-text alternative.
  const links = /(?:Open your report: |See Starter: |Unsubscribe: |Plans: |Review your saved report: )?(https:\/\/www\.scanmysaas\.com\/[^\s<>"']*)/g;
  return text.split(/\n+/).map(paragraph => {
    let html = "", last = 0;
    for (const match of paragraph.matchAll(links)) {
      html += htmlEscape(paragraph.slice(last, match.index));
      html += `<a href="${htmlEscape(match[1])}">${linkLabel(match[1])}</a>`;
      last = match.index! + match[0].length;
    }
    return `<p>${html}${htmlEscape(paragraph.slice(last))}</p>`;
  }).join("\n");
}
function greeting(name: string, email: string): string {
  const cleaned = safeText(name, 70);
  const parts = cleaned.split(/\s+/);
  // A single OAuth handle is not reliable evidence of a person's first name.
  const person = parts.length >= 2 && parts.every(p => /^[\p{L}][\p{L}'-]+$/u.test(p))
    && !/\b(team|support|admin|labs|studio|company|llc|inc)\b/i.test(cleaned)
    && parts[0].toLowerCase() !== email.split("@")[0].toLowerCase();
  return person ? `Hi ${parts[0][0].toUpperCase() + parts[0].slice(1)},` : "Hi,";
}
export function renderEmail(key: EmailKey, c: EmailContext, address: string): RenderedEmail {
  if (!address.trim() || /[\r\n]/.test(address)) throw new Error("Postal address required");
  const hi = greeting(c.name, c.email);
  const s = c.scan, domain = safeText(s?.domain || "your app", 160);
  const shortDomain = domain.length <= 25 ? domain : "your app";
  const report = s ? emailLink(`/scan/${encodeURIComponent(s.id)}`, key) : "";
  const pricing = emailLink("/pricing", key), repo = emailLink("/repo-scan", key);
  const scan = emailLink((c.signupSource || "").toLowerCase().includes("lovable") ? "/lovable-security-scanner" : "/free-website-vulnerability-scanner#scan", key);
  let subject = "", copy = "";
  if (key === "first_scan_nudge") {
    subject = "1 quick check for your app";
    copy = `You created a ScanMySaaS account but haven't completed a website scan yet. The next step is a URL you own.

Paste the URL of an app you own. The report lists the checks, findings by severity, and affected pages, so you can decide what to fix first. No card is needed: ${scan}

If you're building with Lovable or Supabase, the public website is only one part of the picture. The database rules and server routes also deserve a look. Start with the website report, then connect the code when you're ready.

If you're unsure which URL to use, reply and tell me what you're building.`;
  } else if (key === "first_scan_last") {
    subject = "1 last note about your first scan";
    copy = `One last note. You have a ScanMySaaS account, but no completed website scan yet. If you're still building, save this for when you have an app URL to check. Your first scan doesn't need a card, and it can help you choose one concrete fix before you launch. Scan an app you own here: ${scan}

I'll stop these reminders here. If something blocked you, a short reply would help me improve it.`;
  } else {
    if (!s) throw new Error("Completed website scan required");
    const top = s.top;
    switch (key) {
      case "welcome_report":
        subject = domain.length <= 25 ? `your ${domain} report is saved` : `your scan report is saved (${s.score}/100)`;
        copy = `Your scan of ${domain} is saved. Score: ${s.score}/100, with ${s.critical} critical, ${s.high} high and ${s.medium} medium findings.

${top ? `The issue I'd review first is "${top.title}" on ${top.path}. ${top.impact}` : "The public checks found no actionable issues. That is a useful starting point, but it doesn't verify the application logic inside your repository."}

${top || c.repo ? `Open your report: ${report}` : `Check your public GitHub repo next: ${repo}`}

${s.rescanAvailable ? `You have one free verification rescan of this host until ${date(s.deadline)} (UTC). Run it after you deploy a fix to compare the results.` : "A website scan covers publicly observable behavior. It cannot confirm that private routes enforce ownership or database permissions."}

If anything in the report doesn't make sense, reply. I read every one.`;
        break;
      case "still_open":
        subject = `${s.openCount} issues in your ${shortDomain} scan`;
        copy = `Your latest scan of ${domain} reported ${s.openCount} actionable issues. These are the highest-priority findings to review:

${s.top3.map(f => `- ${f.severity}: ${f.title} (${f.path})`).join("\n")}

The scanner found these through public requests, without logging in. This is a record of that scan, not a check that they're still present today. A rescan can confirm fixes.

${s.lockedCount ? `Your free report unlocks one fix. ${s.lockedCount} more finding fixes are locked. Starter adds their fix steps and ready-to-paste prompts for your coding agent.` : "Your report shows the available fix guidance. Starter also adds private repository scans and an AI review of server logic."}

See Starter: ${pricing}`;
        break;
      case "clean_outside":
        subject = `0 high findings on ${shortDomain}`;
        copy = `Your latest scan of ${domain} found no critical or high findings. That's a good start for the public checks it ran. It doesn't mean the whole app is secure.

Some problems need a look inside the code: a secret committed to GitHub, a migration without row level security, or an admin route that skips a role check. A website request alone can't reliably verify those boundaries.

You can scan a public GitHub repo for free: ${repo}

For private repos, Starter connects a read-only GitHub App. It also includes an AI review looking for logic mistakes such as missing ownership checks. AI findings need verification before you change code.`;
        break;
      case "repo_gap":
        subject = `3 things your website scan can't see`;
        copy = `A website scan only sees what ${domain} shows to public requests. A few important mistakes need a look inside the repository:

- a secret key committed in a source file
- a Supabase migration without row level security
- a GitHub Action that runs untrusted code with excessive permissions

The repo scanner checks selected files and points findings to a file and line. Public repositories are free: ${repo}

If the code is private, Starter connects it through a read-only GitHub App. It can read files, never change them, and you can revoke access on GitHub. These checks complement the website report; neither scan proves the app is secure.`;
        break;
      case "repo_findings": {
        const r = c.repo; if (!r?.top || !r.count) throw new Error("Repo findings required");
        subject = `${r.count} findings in your repo`;
        copy = `Your repository report contains ${r.count} findings. One to review first is "${r.top.title}" at ${r.top.path}.

${r.top.impact}

Open the finding and confirm the code context before changing anything. Each repository finding includes fix guidance and a prompt for your coding agent. AI findings are potential issues marked "Needs verification", not confirmed vulnerabilities.

${r.visibility === "public" ? `Review your saved report: ${emailLink(`/repo-scan/${encodeURIComponent(r.id)}`, key)}` : `Starter includes private repository scans and AI review: ${pricing}`}

The next useful step is one confirmed fix, followed by another scan. If the finding doesn't look right, reply with the part that's confusing. Please don't email secrets or private source code.`;
        break;
      }
      case "rescan_expiring":
        subject = `1 free rescan ends ${date(s.deadline).replace(/, \d{4}/, "")}`;
        copy = `Your free verification rescan of ${domain} is available until ${date(s.deadline)} (UTC). It is unused as I write this. After that window, another scan needs plan credits.

If you've deployed a fix, run the rescan from your report. The comparison shows which finding groups are resolved, new, or still reported: ${report}

The latest report lists ${s.openCount} actionable issues. I haven't rechecked the site since that scan, so those numbers may change when you scan again.

If you haven't started yet, review the unlocked fix first. Your coding agent's prompt asks it to check the issue before editing. One verified fix is a useful first step.`;
        break;
      case "what_paid_unlocks":
        subject = `what $${PLANS.starter.price / 100} gets you for ${shortDomain}`;
        copy = `Here's what changes on Starter ($${PLANS.starter.price / 100}/month) for ${domain}:

- fix steps and coding-agent prompts for every actionable website finding, instead of one unlocked fix
- ${PLANS.starter.credits} scan credits each month, with unused credits rolling over up to ${PLANS.starter.maxRollover}
- private GitHub repositories through a read-only GitHub App
- AI review of selected server files for potential ownership and role-check mistakes

Your latest website scan lists ${s.openCount} actionable findings. A rescan comparison is available on free too; it isn't a paid-only feature.

Pro is $${PLANS.pro.price / 100}/month with ${PLANS.pro.credits} credits. Subscribers can manage or cancel billing from the dashboard. Plans: ${pricing}

Not sure it's useful for your app? Reply with what you're building and I'll tell you honestly.`;
        break;
      case "last_note":
        subject = `1 last note on ${shortDomain}`;
        copy = `This is my last email about your ${domain} report.

${s.rescanned ? `The comparison with the previous scan shows ${s.resolved} resolved finding groups, ${s.added} new groups, and ${s.stillOpen} still reported groups.` : `The scan from ${date(s.createdAt)} lists ${s.openCount} actionable issues. You haven't rescanned this host, so I can't tell whether fixes are deployed.`}

If you fixed them already, great. A rescan can check the public surface again. If not, start with the unlocked fix in your report. Starter adds the remaining fix steps and coding-agent prompts: ${pricing}

Either way, thanks for trying ScanMySaaS. If something didn't work for you, a one-line reply would help me improve it. You can also turn off these emails using the link below.`;
        break;
    }
  }
  const body = `${hi}\n\n${copy}\n\nStefan`;
  const unsub = unsubscribeUrl(c.userId);
  const footer = `${s ? `You're getting this because you created a ScanMySaaS account and scanned ${domain}.` : "You're getting this because you created a ScanMySaaS account and opted in to email updates."}\n\nUnsubscribe: ${unsub}\n\nScanMySaaS, ${safeText(address, 400)}`;
  const text = `${body}\n\n${footer}`;
  const words = body.split(/\s+/).length;
  if (words < 60 || words > 170) throw new Error("Email body outside length budget");
  if (!subject || subject.length >= 55 || /[\r\n]/.test(subject) || /\{\{|undefined|[\u2013\u2014\u2018-\u201d]/.test(text) || /[\u2013\u2014]/.test(subject)) throw new Error("Email rendering validation failed");
  return { subject, body, text, html: minimalHtml(text), unsubscribeUrl: unsub };
}
