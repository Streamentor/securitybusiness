# Synthetic email previews

All names, domains, findings and addresses below are fixtures, not customer data. No emails were sent.

## welcome_report

Subject: your example.com report is saved

```text
Hi Alex,

Your scan of example.com is saved. Score: 71/100, with 0 critical, 1 high and 2 medium findings.

The issue I'd review first is "Exposed configuration file" on /.env. Anyone can request this file. If it contains credentials, they may be exposed.

Open your report: https://www.scanmysaas.com/scan/fixture-scan?utm_source=email&utm_medium=onboarding&utm_campaign=welcome_report

You have one free verification rescan of this host until Feb 8, 2026 (UTC). Run it after you deploy a fix to compare the results.

If anything in the report doesn't make sense, reply. I read every one.

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```

## still_open

Subject: 3 issues in your example.com scan

```text
Hi Alex,

Your latest scan of example.com reported 3 actionable issues. These are the highest-priority findings to review:

- high: Exposed configuration file (/.env)
- medium: Missing CSP (/)

The scanner found these through public requests, without logging in. This is a record of that scan, not a check that they're still present today. A rescan can confirm fixes.

Your free report unlocks one fix. 2 more finding fixes are locked. Starter adds their fix steps and ready-to-paste prompts for your coding agent.

See Starter: https://www.scanmysaas.com/pricing?utm_source=email&utm_medium=onboarding&utm_campaign=still_open

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```

## clean_outside

Subject: 0 high findings on example.com

```text
Hi Alex,

Your latest scan of example.com found no critical or high findings. That's a good start for the public checks it ran. It doesn't mean the whole app is secure.

Some problems need a look inside the code: a secret committed to GitHub, a migration without row level security, or an admin route that skips a role check. A website request alone can't reliably verify those boundaries.

You can scan a public GitHub repo for free: https://www.scanmysaas.com/repo-scan?utm_source=email&utm_medium=onboarding&utm_campaign=clean_outside

For private repos, Starter connects a read-only GitHub App. It also includes an AI review looking for logic mistakes such as missing ownership checks. AI findings need verification before you change code.

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```

## repo_gap

Subject: 3 things a example.com scan can't see

```text
Hi Alex,

A website scan only sees what example.com shows to public requests. A few important mistakes need a look inside the repository:

- a secret key committed in a source file
- a Supabase migration without row level security
- a GitHub Action that runs untrusted code with excessive permissions

The repo scanner checks selected files and points findings to a file and line. Public repositories are free: https://www.scanmysaas.com/repo-scan?utm_source=email&utm_medium=onboarding&utm_campaign=repo_gap

If the code is private, Starter connects it through a read-only GitHub App. It can read files, never change them, and you can revoke access on GitHub. These checks complement the website report; neither scan proves the app is secure.

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```

## repo_findings

Subject: 2 findings in your repo

```text
Hi Alex,

Your repository report contains 2 findings. One to review first is "Exposed configuration file" at src/route.ts:14.

Anyone can request this file. If it contains credentials, they may be exposed.

Open the finding and confirm the code context before changing anything. Each repository finding includes fix guidance and a prompt for your coding agent. AI findings are potential issues marked "Needs verification", not confirmed vulnerabilities.

Review your saved report: https://www.scanmysaas.com/repo-scan/fixture-repo?utm_source=email&utm_medium=onboarding&utm_campaign=repo_findings

The next useful step is one confirmed fix, followed by another scan. If the finding doesn't look right, reply with the part that's confusing. Please don't email secrets or private source code.

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```

## rescan_expiring

Subject: 1 free rescan ends Feb 8

```text
Hi Alex,

Your free verification rescan of example.com is available until Feb 8, 2026 (UTC). It is unused as I write this. After that window, another scan needs plan credits.

If you've deployed a fix, run the rescan from your report. The comparison shows which finding groups are resolved, new, or still reported: https://www.scanmysaas.com/scan/fixture-scan?utm_source=email&utm_medium=onboarding&utm_campaign=rescan_expiring

The latest report lists 3 actionable issues. I haven't rechecked the site since that scan, so those numbers may change when you scan again.

If you haven't started yet, review the unlocked fix first. Your coding agent's prompt asks it to check the issue before editing. One verified fix is a useful first step.

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```

## what_paid_unlocks

Subject: what $29 gets you for example.com

```text
Hi Alex,

Here's what changes on Starter ($29/month) for example.com:

- fix steps and coding-agent prompts for every actionable website finding, instead of one unlocked fix
- 10 scan credits each month, with unused credits rolling over up to 20
- private GitHub repositories through a read-only GitHub App
- AI review of selected server files for potential ownership and role-check mistakes

Your latest website scan lists 3 actionable findings. A rescan comparison is available on free too; it isn't a paid-only feature.

Pro is $79/month with 30 credits. Subscribers can manage or cancel billing from the dashboard. Plans: https://www.scanmysaas.com/pricing?utm_source=email&utm_medium=onboarding&utm_campaign=what_paid_unlocks

Not sure it's useful for your app? Reply with what you're building and I'll tell you honestly.

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```

## last_note

Subject: 1 last note on example.com

```text
Hi Alex,

This is my last email about your example.com report.

The scan from Feb 1, 2026 lists 3 actionable issues. You haven't rescanned this host, so I can't tell whether fixes are deployed.

If you fixed them already, great. A rescan can check the public surface again. If not, start with the unlocked fix in your report. Starter adds the remaining fix steps and coding-agent prompts: https://www.scanmysaas.com/pricing?utm_source=email&utm_medium=onboarding&utm_campaign=last_note

Either way, thanks for trying ScanMySaaS. If something didn't work for you, a one-line reply would help me improve it. You can also turn off these emails using the link below.

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```

## first_scan_nudge

Subject: 1 quick check for your app

```text
Hi Alex,

You created a ScanMySaaS account but haven't completed a website scan yet. The next step is a URL you own.

Paste the URL of an app you own. The report lists the checks, findings by severity, and affected pages, so you can decide what to fix first. No card is needed: https://www.scanmysaas.com/free-website-vulnerability-scanner?utm_source=email&utm_medium=onboarding&utm_campaign=first_scan_nudge#scan

If you're building with Lovable or Supabase, the public website is only one part of the picture. The database rules and server routes also deserve a look. Start with the website report, then connect the code when you're ready.

If you're unsure which URL to use, reply and tell me what you're building.

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```

## first_scan_last

Subject: 1 last note about your first scan

```text
Hi Alex,

One last note. You have a ScanMySaaS account, but no completed website scan yet. If you're still building, save this for when you have an app URL to check. Your first scan doesn't need a card, and it can help you choose one concrete fix before you launch. Scan an app you own here: https://www.scanmysaas.com/free-website-vulnerability-scanner?utm_source=email&utm_medium=onboarding&utm_campaign=first_scan_last#scan

I'll stop these reminders here. If something blocked you, a short reply would help me improve it.

Stefan

You're getting this because you created a ScanMySaaS account and scanned example.com.
Unsubscribe: https://www.scanmysaas.com/api/email/unsubscribe?t=Zml4dHVyZS11c2Vy.mGoxK8b05BTExxZDdhFg1KKnOLpY4js2JUliuC3uM6Q
ScanMySaaS, Example Company, 123 Test Street, Test City
```