# ScanMySaaS landing page audit (2026-11-07)

Scope: 7 marketing pages in `/home/claude/securitybusiness`. No repo files were edited. The live site (www.scanmysaas.com) was fetched on 2026-11-07, and its titles, meta descriptions and H1s match the source exactly, so every line reference below points at what is in production right now.

## Ground truth summary (what the code actually does)

Website scanner (`src/lib/scanner.ts`)
- Crawl: `discoverPages(url, 25)` (scanner.ts:1352). It follows `<a href>` links found in the **server HTML** only (scanner.ts:261-275). A client-rendered SPA (Lovable, Bolt, plain Vite React) usually exposes only the start page.
- Response headers and CSP are checked on the **first** HTML page only (`if (pagesAnalyzed === 0)`, scanner.ts:1450-1465). HTML checks (CSRF, inline DOM sinks, mixed content, SRI, outdated libs, HTML comments, forms over HTTP, source-map refs) run on every crawled page. Cookies are gathered from `Set-Cookie` on every crawled page (scanner.ts:1446-1448). Source-map probing covers the first 3 pages, 5 scripts each (scanner.ts:1172, 1186).
- Finding types: 75 distinct `title:` strings in scanner.ts, plus 2 TLS expiry titles built in a ternary (scanner.ts:417). Leaving out info and SEO items (security.txt found, OpenID config found, technologies detected, WAF detected, readiness snapshot, missing meta description, robots blocks all, soft 404), there are about 69 security finding types. **"60+ checks" holds up.**
- Emitted categories (`type:`): ssl, headers, csp, cookies, csrf, xss, sensitive-file, info-disclosure, cors, email, api-exposure, http-methods, redirect, source-maps, directory-listing, outdated-lib, sri, plus non-scored seo, fingerprint, waf, scan-meta. That is **17 scored categories**. `open-redirect` and `iframe` show up in the score weights (scanner.ts:1259, 1262) but no check ever emits them.
- Sensitive path probes: 20 files (scanner.ts:796-819, minus the 2 well-known files skipped at :823), 10 directories (:928), 13 API/debug/GraphQL paths (:986-990) = **43 probed paths**. Exposed files are confirmed by content (`matchesExpectedSensitiveFile`, :769-791). Source maps are confirmed by content-type only (:1191-1193).
- Non-GET requests: a `TRACE` to the base URL (:1038) and a `POST` GraphQL introspection query (:997-1001). There is also one request carrying a fake `Origin` header for the CORS check (:519-522).
- CORS: the only thing flagged is an untrusted Origin reflected together with `Allow-Credentials: true` (:519-541). A wildcard `*` is not flagged by the website scan.
- Outdated libraries: only jQuery < 3.5, AngularJS 1.x and Bootstrap < 4 loaded from a `script src` (:729-738).
- No open-redirect test, no SQLi/XSS payload testing, no authenticated crawling.
- TLS: trust plus expiry within 30 days (:356-437). The llms.txt check is in readiness (:1108-1110).
- Fix prompts on website reports: `CopyPromptButton` renders only when `canViewRemedy` (src/app/scan/[id]/page.tsx:89). Free users get **one** remedy (`applyWebsiteRemediationAccess`, src/lib/scan-remediation.ts:32-48). Paid users get all of them.
- Rescan comparison (resolved / added / still open) is computed for **any owner** rescanning the same host, free plan included (src/app/api/scan/[id]/route.ts:43-66).

Free limits (`src/lib/scan-access.ts`, `src/lib/scan-gate.ts`)
- Anonymous: one free scan per hostname. It uses no credit, and a hostname already scanned on the free plan is blocked for anonymous users (scan-access.ts:49-54).
- Free account: `credits @default(1)` (prisma/schema.prisma:21). One **verification rescan within 7 days** of the first scan of that host (scan-access.ts:6, 56-68). At most 3 free accounts per hostname (:8, 71-74).
- Rate limits: 3 website scans per hour per anonymous network, 20 per hour per signed-in user (:81).
- The API error strings promise "unlimited scans" on Starter/Pro (scan-access.ts:51, 73). That is **wrong**, because paid plans are credit-metered (scan-access.ts:41-42). It isn't on an audited page, but users do see it.

Plans (`src/lib/stripe.ts`, `src/lib/billing-credit-store.ts`)
- Starter $29/mo, 10 credits, rollover cap 20. Pro $79/mo, 30 credits, cap 60 (stripe.ts:26-42). The cap is enforced as `LEAST(credits + n, n*2)` (billing-credit-store.ts:23).
- Credits are only spent on website scans. Repo scans never touch credits (no credit logic in src/lib/repo-scan-jobs.ts or src/app/api/repo-scan/route.ts).
- No team, seat or member model in prisma/schema.prisma.

Repo scanner (`src/lib/github-scanner.ts`, `secret-patterns.ts`, `repo-security-rules.ts`)
- Reads up to 60 files (github-scanner.ts:11), 240 KB per file, 6 MB total (:12-14), from one pinned commit (:494-500). Trees over 100,000 entries are refused (:501). No Git history.
- Priority order (`candidatePriority`, :211-221): `.env*` / `.pem` / `.key` / `.npmrc` → workflows and agent files → lockfiles, Supabase and migrations, `.sql` → `.gitignore` / `package.json` / next and vite configs → everything else, sorted by `riskScore` (middleware +6; api/routes, auth, payments +4).
- Secret patterns: 11 provider and format regexes (secret-patterns.ts:4-14), service_role JWT decode (github-scanner.ts:302), `NEXT_PUBLIC_`/`VITE_`/`REACT_APP_` secret-like names (:306), generic secret-like literals (:314-316).
- Actions: write-all, missing `permissions`, pull_request_target + PR checkout, unpinned actions, secret echo (:320-341).
- Supabase RLS: runs only if some scanned file mentions `@supabase/supabase-js`, `supabase/migrations` or `supabase.co` (:408). It then checks every scanned `.sql` file for `create table` without a matching `enable row level security` (:410-421). It does **not** look at GRANTs.
- Dependencies (OSV): `package-lock.json` / `npm-shrinkwrap.json`, `requirements*.txt` lines pinned with `==`, `go.mod`, `Cargo.lock` (repo-security-rules.ts:163-205). pnpm, Yarn and Bun lockfiles are only used to suppress the "no lockfile" finding (:135). They are **not** parsed for OSV. Max 180 dependencies (:28).
- Agent / MCP rules: repo-security-rules.ts:56-130.
- Every repo finding has an ungated "Copy fix prompt" (src/components/RepoReport.tsx:78).
- Rule-based scans have **no** ownership, IDOR, webhook-signature or paid-feature-on-client checks. Those come only from the AI review.
- Rate limits: anonymous public scans 5 per 10 min (src/app/api/repo-scan/route.ts:8-9). Signed-in users 15 per hour, 2 concurrent (repo-scan-jobs.ts:10-11).
- Private repos are Starter/Pro only (repo-scan-jobs.ts:9, 91). The GitHub App token is `contents: read, metadata: read` (src/lib/github-app.ts:154).

AI review (`src/lib/ai-review.ts`)
- Starter/Pro/admin only (:36-38). Sent to OpenAI with `store: false` (:61), secrets redacted first (:64), at most 2 batches within a 60k-token input budget per scan (:46, 75-77). Default monthly caps: Starter 600k tokens, Pro 2M (:48-50), env-overridable. **Confirm the production env values before publishing any number.**
- Instructions target owner/tenant checks, UI-only paid access, admin roles, webhook signatures, SSRF and similar (:35).

External facts verified (primary sources)
- Lovable security docs (https://docs.lovable.dev/features/security): a Quick scan (database access rules and settings, npm dependency audit, MCP server check) "runs automatically every time you publish", and the publish dialog starts it when opened. The Deep scan adds code review for access control, unauthenticated endpoints, leaked secrets and more. It does not run automatically, and it can be started from the project Security view, the workspace Security center, the publish dialog or chat. The Quick scan's database review "flags tables without per-record access control".
- Lovable database docs (https://docs.lovable.dev/features/database.md): the built-in backend records migrations under `drizzle/migrations/`. "Projects with earlier migration files keep them under `supabase/migrations/`." Tables are viewed in More → Database.
- Supabase API keys (https://supabase.com/docs/guides/api/api-keys): `sb_publishable_` is safe to expose. `sb_secret_` "bypasses every Row Level Security policy". anon and service_role are the legacy versions. "Supabase is deprecating the anon and service_role keys by the end of 2026."
- Supabase RLS (https://supabase.com/docs/guides/database/postgres/row-level-security): "A table in an exposed schema without RLS is readable and writable by any role with a grant on it." "A secret key bypasses RLS only when the request carries no user access token."
- **Supabase breaking change** (https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically): new public tables are no longer granted to anon/authenticated automatically. This became the default for new projects from May 30, 2026 and was **applied to all existing projects on October 30, 2026**. Existing tables keep their grants.
- arXiv 2512.03262, "Is Vibe Coding Safe? Benchmarking Vulnerability of Agent-Generated Code in Real-World Tasks" (Zhao et al.): "Although 57% of the solutions from SWE-Agent with Claude 4 Sonnet are functionally correct, only 11.8% are secure."
- The OWASP Secure Coding Practices Quick Reference Guide is **archived** (https://owasp.org/www-project-secure-coding-practices-quick-reference-guide/). Its content moved to the OWASP Developer Guide (https://owasp.org/www-project-developer-guide/). OWASP Top 10:2025 is at https://top10.owasp.org/2025/ (A01 Broken Access Control, A02 Security Misconfiguration, A03 Software Supply Chain Failures, A04 Cryptographic Failures, A05 Injection, A06 Insecure Design, A07 Authentication Failures, A08 Software or Data Integrity Failures, A09 Security Logging and Alerting Failures, A10 Mishandling of Exceptional Conditions).
- GitHub security features page (https://docs.github.com/en/code-security/getting-started/github-security-features) loads (200). Secret scanning and push protection are "Available for public repositories by default."
- CVE-2025-48757: "An insufficient database Row-Level Security (RLS) policy in Lovable through 2025-04-15 allows remote unauthenticated attackers..." Published May 30, 2025. **Disputed by Lovable** (https://www.sentinelone.com/vulnerability-database/cve-2025-48757/).

Competitor and SERP notes
- "free website vulnerability scanner": results are listicles (getastra, zerothreat, dev.to, kitemetric) and tool pages (immuniweb, secably). Secably's page uses a Quick vs Deep split, states scan time ("about 15 seconds"), lists SPF/DMARC/DKIM, headers, CORS and exposed files, and puts OWASP Top 10 testing (SQLi, XSS, SSRF) in a paid tier. Listicles compare tools on what they actively test (OWASP Top 10), scan limits and signup needs. Our page has no OWASP mapping, no "what we don't test" section, no example report and no scan duration.
- "saas security scanner": the SERP is **mixed intent**. Much of it is SSPM (scanning SaaS tenants such as Salesforce, AppOmni, Palo Alto SaaS Security) plus "best SaaS vulnerability scanners" listicles (Beagle Security, getastra, indusface). The homepage FAQ "What is a SaaS security scanner?" already sets the meaning. Keep it, and use the variant "SaaS vulnerability scanner" once.
- Lovable / vibe SERP: competitors include securityscanner.dev ("Lovable vs Bolt vs Replit RLS" data post), symbioticsec ("we scanned 1,072 vibe-coded apps"), vibecheck, vibeappscanner, and dev.to posts by people who scanned Lovable apps. They win on **original data** ("we scanned N apps"). We publish none.

---

## 1. Homepage (`src/app/page.tsx`, `src/app/layout.tsx`, `src/lib/site-content.ts`)

**Priority: 8/10.** This is the main keyword page. Its FAQ (also emitted as FAQPage JSON-LD) carries one false claim and two overpromises, and three of its headings compete with the free scanner page.

### A) Fact check

| # | Quoted claim (file:line) | Verdict | Correct fact / source |
|---|---|---|---|
| 1 | "60+ checks" / "60+ vulnerability checks" / "more than 60 automated security checks" (page.tsx:153, 180, 63; site-content.ts:15) | CORRECT | About 69 security finding types (scanner.ts, see summary) |
| 2 | "Up to 25 pages" / "25 pages per scan" (page.tsx:154, 180) | CORRECT, slight overpromise | scanner.ts:1352. Headers and CSP are checked on the first page only (scanner.ts:1450). SPAs often yield 1 page (scanner.ts:261) |
| 3 | "15 security categories" (page.tsx:180) | WRONG / unsupported | No 15 anywhere in code. 17 scored categories are emitted, and 19 non-zero weights exist (scanner.ts:1242-1266) |
| 4 | "1 free first scan" (page.tsx:180) | CORRECT | scan-access.ts:49-54, schema.prisma:21 |
| 5 | "Free website vulnerability scan. No card required." (page.tsx:146) | CORRECT | anonymous scans allowed |
| 6 | "with affected URLs and a clear order for what to verify first" (page.tsx:149) | CORRECT | scan-remediation.ts:29-37 orders findings |
| 7 | FAQ: "...CORS mistakes, open redirects, source maps..." (site-content.ts:25) | **WRONG** | No open-redirect check. `open-redirect` is only a weight key (scanner.ts:1259). The redirect checks are HTTP→HTTPS missing, HTTPS downgrade, mixed redirect chain and >3 hops (scanner.ts:1210-1234, 302-354) |
| 8 | FAQ: repo scanner "finds issues ... such as committed .env files, API keys in code, unsafe workflows and missing ownership checks, with the exact file and line" (site-content.ts:10) | OVERPROMISE | Ownership checks come only from the paid AI review (ai-review.ts:35-38). Rule-based scanning has none |
| 9 | FAQ: "Paid plans add remediation for all findings, monthly credits, rescans, saved history, and score trends." (site-content.ts:30) | WRONG (partly) | Free accounts get saved history (pricing table says so too, pricing/page.tsx:130), a verification rescan (scan-access.ts:60) and the rescan comparison (api/scan/[id]/route.ts:44). The dashboard shows score deltas for all plans (src/app/dashboard/page.tsx:175) |
| 10 | FAQ: "on paid plans, an AI review of authorization logic" (site-content.ts:4) | CORRECT | ai-review.ts:36-38 |
| 11 | "Read-only GitHub App you control. No clone, package install, build, or code execution." (page.tsx:195) | CORRECT | github-app.ts:154. Files are fetched over raw/contents API (github-scanner.ts:235-275) |
| 12 | "Public repositories are free; private repositories are included in Starter and Pro." (page.tsx:195) | CORRECT | repo-scan-jobs.ts:9, 91 |
| 13 | "Verified findings can be copied as technical fix prompts" (page.tsx:190) | OVERPROMISE (wording) | Findings are pattern matches, not verified. AI findings are labelled "Needs verification" (RepoReport.tsx:72). Every repo finding does have a prompt (RepoReport.tsx:78) |
| 14 | Repo cards: ".env and credentials", "GitHub Actions", "Supabase boundaries", "Client and build risk" (page.tsx:199-202) | CORRECT | github-scanner.ts:289-421 |
| 15 | "The free report includes one actionable fix when available; paid plans add remediation for the remaining issues." (page.tsx:213) | CORRECT | scan-remediation.ts:44 |
| 16 | Coverage "Client-side risk: Unsafe JavaScript patterns, detectable outdated libraries, and injection signals." (page.tsx:41) | OVERPROMISE | No injection testing. Inline-script DOM sinks only (scanner.ts:704-712). Outdated libs = jQuery<3.5, AngularJS 1.x, Bootstrap<4 (:729-738) |
| 17 | Coverage "SSL & transport ... downgrade risks" (page.tsx:37) | CORRECT | scanner.ts:302-354, 1229-1233 |
| 18 | Coverage "Exposed files ... logs, source maps, and debug paths" (page.tsx:39) | CORRECT | scanner.ts:796-819, 1168-1207, 986-1031 |
| 19 | Coverage "App exposure: ... DNS and email signals, and CORS" (page.tsx:42) | CORRECT (narrow) | DNS = SPF/DMARC TXT only (scanner.ts:845-876). CORS = reflected origin with credentials only (:519-541) |
| 20 | Coverage "AI discovery: llms.txt availability" (page.tsx:43) | CORRECT | scanner.ts:1108-1110 |
| 21 | Coverage "Crawl readiness: robots.txt, XML sitemap, canonical URL, homepage indexability, and security.txt" (page.tsx:44) | CORRECT | scanner.ts:1069-1145 |
| 22 | Example report: "Session cookie has no SameSite policy", **Medium** (page.tsx:89) | WRONG (illustrative) | The real finding "Cookies Without SameSite" is **low** severity (scanner.ts:661) |
| 23 | JSON-LD offers Starter "29", Pro "79" (page.tsx:68-69) | CORRECT, incomplete | stripe.ts:28, 36. Monthly billing period is missing |
| 24 | "It tests public signals only... it does not log in, exploit targets" (page.tsx:258) | CORRECT | No auth or exploit code in scanner.ts |
| 25 | "How is ScanMySaaS different from Burp Suite or Nikto?" (site-content.ts:33-36) | CORRECT (no false claim about those tools) | |

### B) AI-writing tells (worst offenders)
- The "before" tic. 5 of the 9 headline strings use it: "SaaS security scanner before your next launch." (H1), "See the scan before you run yours.", "Scan the code before the public app.", "Understand the finding before changing production.", "Before you scan your SaaS." Repetition this mechanical reads as a template.
- Em dash: "It tests public signals only—it does not log in" (page.tsx:258).
- Diff-anchored writing (#30): "The report now adds clearer findings, affected pages, and a SaaS readiness view for TLS, crawl files, and AI discovery." (page.tsx:167). This is changelog voice on a landing page, and it ends in a rule-of-three.
- Negation eyebrows and punchlines (#9): "More than a pass or fail" (page.tsx:211), "A vulnerability report your team can actually use." (page.tsx:212), "Know what your launch left exposed." (page.tsx:268).
- Rule of three: "Find exposed files, unsafe headers and risky cookies" (page.tsx:149), "Use it on a website you own, keep the report, and decide what deserves attention." (page.tsx:268), "across the public app, GitHub workflows, and database boundaries" (page.tsx:234).
- Abstract filler: "Focused guides connect scanner output to a safer release plan" (page.tsx:234).
- Uniform scaffolding (S6/#38): every section is eyebrow → H2 → one paragraph → card grid. The `#guides` and `#workflow` sections even share the same background classes back to back (page.tsx:231, 243).
- Register gate: leave the stat strip, form and button microcopy alone.

### C) SEO
- Title "SaaS Security Scanner: Free Website & GitHub Repo Scan | ScanMySaaS" (layout.tsx:7): good. Keyword is first, 68 chars.
- Meta description (layout.tsx:8): 160 chars, keyword first. OK.
- H1 contains "SaaS security scanner". Good.
- H2s: none say "SaaS security scanner". Three target the free page's keyword instead: "How does a web vulnerability scanner work?" (page.tsx:245), "What our website vulnerability scanner checks for." (page.tsx:258), and the FAQ questions "How does a website vulnerability scanner work?" (site-content.ts:18) and "Is ScanMySaaS a free website vulnerability scanner?" (site-content.ts:28). JSON-LD also sets `applicationSubCategory: "Website vulnerability scanner"` (page.tsx:59). **This is the main cannibalization of /free-website-vulnerability-scanner.**
- Internal links: the body has no link to /free-website-vulnerability-scanner, /lovable-security-scanner or /pricing (only the footer has them). The guide strip shows `guides.slice(0, 5)` (page.tsx:238): launch checklist, headers, SSL, robots/sitemap, llms.txt. Those are the two weakest commercial guides, while the Supabase, secret-scanning and 47-check vibe checklist guides are hidden.
- SERP intent: half of "saas security scanner" results are SSPM (scanning SaaS tenants). The FAQ definition at site-content.ts:3-5 is good. Keep it as the first FAQ.
- FAQPage schema: Google has shown FAQ rich results mainly for government/health sites since 2023, so it won't earn stars. It is harmless, but it puts the wrong "open redirects" claim into structured data.

### D) Usefulness gaps (all true per code)
- What the scan does not do: no login, no SQLi/XSS payloads, headers checked on the first page, SPAs crawl only server-linked pages.
- The free tier in one line: anonymous scan, then a free account keeps the report and adds one verification rescan within 7 days, with a resolved / new / still-open comparison.
- A real example report. The illustrative one uses a wrong severity.

### Exact edit instructions
1. site-content.ts:25. Replace `"...exposed environment or backup files, CORS mistakes, open redirects, source maps, outdated client-side libraries, unsafe JavaScript patterns, and other publicly observable web application risks."` with `"...exposed environment, Git and backup files, CORS that reflects untrusted origins, redirect problems (no HTTP to HTTPS redirect, HTTPS downgrades, long redirect chains), public source maps, outdated jQuery, AngularJS or Bootstrap builds, unsafe inline JavaScript, and SPF and DMARC records."`
2. page.tsx:180. Replace `["15", "security categories"]` with `["43", "sensitive paths probed"]` (20 files + 10 directories + 13 API/debug paths, scanner.ts:796-990) or `["17", "finding categories"]`. If the probe list changes, update the number.
3. site-content.ts:10. Replace `"...such as committed .env files, API keys in code, unsafe workflows and missing ownership checks, with the exact file and line."` with `"...such as committed .env files, API keys in code and unsafe GitHub Actions, with the exact file and line. On Starter and Pro, an AI review also looks for missing ownership checks in server code."`
4. site-content.ts:30. Replace the last sentence `"Paid plans add remediation for all findings, monthly credits, rescans, saved history, and score trends."` with `"A free account keeps the report and gives you one free rescan of the same site within 7 days, with a list of what was fixed and what is new. Paid plans add remediation for every finding and monthly credits for more scans."`
5. page.tsx:190. Replace `"Verified findings can be copied as technical fix prompts for your coding agent."` with `"Each finding has a fix prompt you can copy into your coding agent."`
6. page.tsx:167. Replace `"Watch the original walkthrough, then start with your own public URL. The report now adds clearer findings, affected pages, and a SaaS readiness view for TLS, crawl files, and AI discovery."` with `"Watch a real scan, then run one on your own public URL. The report sorts findings by severity, shows the page where each was found, and adds a readiness check for the TLS certificate, robots.txt, sitemap and llms.txt."`
7. page.tsx:258. Replace `"It tests public signals only—it does not log in, exploit targets, or replace a human security review."` with `"It reads what is public. It does not log in, send attack payloads, or replace a human security review."`
8. page.tsx:245. Change H2 `"How does a web vulnerability scanner work?"` to `"How does a SaaS security scanner work?"`.
9. page.tsx:258. Change H2 `"What our website vulnerability scanner checks for."` to `"What the SaaS security scanner checks on your live app."` Then add one sentence linking the free page: `Just need the website check? Use the <Link href="/free-website-vulnerability-scanner">free website vulnerability scanner</Link>.`
10. site-content.ts:18-21. Delete the FAQ `"How does a website vulnerability scanner work?"`. It duplicates the workflow section and the FAQ at :23. Change :28 question to `"Is the SaaS security scanner free?"` and keep the answer.
11. page.tsx:59. Change `applicationSubCategory: "Website vulnerability scanner"` to `"SaaS security scanner"`.
12. page.tsx:41. Replace copy with `"Unsafe DOM sinks in inline scripts (innerHTML, document.write, eval), old jQuery, AngularJS 1.x and Bootstrap 3 builds, and third-party scripts without integrity hashes."`
13. page.tsx:89. Either change the tone to Low, or swap the example to `{ severity: "Medium", title: "Session cookie readable by JavaScript (no HttpOnly)", location: "/login" }`. That matches scanner.ts:659, where session-like cookies are medium.
14. page.tsx:151. Add a third link to the hero link row: `<Link href="/lovable-security-scanner">Lovable security scan</Link>`.
15. page.tsx:238. Replace `guides.slice(0, 5)` with an explicit list in this order: `saas-launch-security-checklist`, `vibe-coding-security-checklist`, `supabase-security-for-vibe-coded-apps`, `github-secret-scanning-for-vibe-coded-apps`, `security-headers-for-saas`.
16. Break the "before" pattern. Change `"See the scan before you run yours."` (:166) to `"Watch a real scan."`. Change `"Understand the finding before changing production."` (:234) to `"Guides for the findings you will see."`. Keep the H1. Change `"Before you scan your SaaS."` (:275) to `"SaaS security scanner FAQ"`. That adds the keyword in an H2.
17. page.tsx:211-212. Change the eyebrow `"More than a pass or fail"` to `"The report"`. Change the H2 `"A vulnerability report your team can actually use."` to `"Findings sorted by severity, each with the page it came from."`
18. site-content.ts:66-69 (`productFeatures` "Rescans and score trends"). Append `" Free accounts get one verification rescan within 7 days; later rescans use credits."`
19. page.tsx:68-69. Add `priceSpecification: { "@type": "UnitPriceSpecification", price: "29", priceCurrency: "USD", unitText: "MONTH" }` (and 79 for Pro) to the offers.
20. Optional, outside the audited pages: fix "unlimited scans" in scan-access.ts:51 and :73 to `"upgrade to Starter or Pro for monthly scan credits"`.

---

## 2. /free-website-vulnerability-scanner

**Priority: 9/10.** It targets the biggest keyword (3.6k/mo), and the page is thin: about 600 words, 3 H2s. Two claims are wrong, the homepage cannibalizes it, and it lacks what ranking pages cover (OWASP mapping, limits, scan time, what isn't tested).

### A) Fact check

| # | Quoted claim (page.tsx:line) | Verdict | Correct fact / source |
|---|---|---|---|
| 1 | "Check up to 25 pages" (meta, :13; :71) | CORRECT | scanner.ts:1352 (same SPA caveat) |
| 2 | "No signup or credit card to start." (:13) | CORRECT | scan-access.ts:49-54 |
| 3 | "Certificate trust and expiry, HTTPS redirects, HSTS and mixed content." (:24) | CORRECT | scanner.ts:302-437, 467-476, 715 |
| 4 | "Content-Security-Policy evaluated the way browsers enforce it" (:25) | MOSTLY CORRECT | parseCSP handles multiple policies and first-directive-wins (scanner.ts:539-575). First page only |
| 5 | "...confirmed by content, not just a 200 status." (:26) | CORRECT for files, not for source maps | scanner.ts:769-791. Source maps are checked by content-type only (:1191) |
| 6 | "Secure, HttpOnly and SameSite checked for every cookie across crawled pages, plus forms without a visible CSRF token." (:27) | CORRECT (Set-Cookie headers only; cookies set by JS are invisible) | scanner.ts:1446-1448, 648-664, 693-702 |
| 7 | "Unsafe DOM sinks in inline scripts, outdated JavaScript libraries and resources loaded without integrity checks." (:28) | CORRECT, narrow | Only 3 libraries are detected (scanner.ts:729-738) |
| 8 | "Debug endpoints, GraphQL introspection, permissive CORS, directory listings, TRACE, DNS and email security records." (:29) | CORRECT | scanner.ts:983-1046, 519-541, 926-948, 845-876. "Permissive CORS" = reflected origin + credentials |
| 9 | "...reported separately from the security score." (:30) | CORRECT | `seo: 0`, `"scan-meta": 0` weights (scanner.ts:1263-1265) |
| 10 | **"Findings come with a prompt you can paste into Cursor, Claude or Codex to verify and fix the issue."** (:31) | **WRONG for free users** | The prompt renders only with a viewable remedy (scan/[id]/page.tsx:89). The free report has one (scan-remediation.ts:44) |
| 11 | FAQ: "one prioritized fix ... Creating a free account lets you keep the report and run one free rescan within 7 days" (:35) | CORRECT | scan-access.ts:6, 60; claim route src/app/api/scan/claim/route.ts |
| 12 | FAQ: "Most scans finish in well under a minute." (:36) | UNVERIFIABLE | No timing data in code. Page fetches are sequential with a 15 s timeout (scanner.ts:1442) |
| 13 | **FAQ: "The scan only sends ordinary read requests that any visitor or search engine could send, plus a small number of checks for known sensitive paths."** (:37) | **WRONG** | It also sends `TRACE` (scanner.ts:1038), a `POST` GraphQL introspection query (:997-1001) and a forged `Origin` header (:521). It probes 43 paths |
| 14 | FAQ: "It does not log in, submit forms, run exploits or try to change data." (:37) | CORRECT | |
| 15 | FAQ: GitHub repo scanner "reads your repository for committed secrets, risky workflows and missing authorization checks" (:38) | OVERPROMISE | Authorization checks are paid AI review only (ai-review.ts:36) |
| 16 | "...routes without ownership checks are invisible from the outside. The GitHub repo scanner reads your code..." (:85) | OVERPROMISE (implied free) | Same as #15 |
| 17 | "60+ automated checks" (:74) | CORRECT | |

### B) AI-writing tells
- Negative parallelisms: "You get a prioritized report with the affected URLs, not a wall of noise." (:71), "confirmed by content, not just a 200 status" (:26).
- Parallel slogans: "A website scan sees what is public. Your repository shows the rest." (:85), eyebrow "Outside and inside" (:85).
- Vague H2: "Website security checks that matter for a real app." (:79). It inflates significance and skips the keyword.
- Rule of three: "deploy the change and run a rescan" chain (:39). That one is acceptable.
- Structure: 8 cards of identical shape followed by FAQ. No section is longer than the others (S7, flat escalation).

### C) SEO
- Title (:12): "Free Website Vulnerability Scanner: Online Security Scan | ScanMySaaS". Good.
- Meta description (:13) is 191 chars and will be truncated. Shorten it (see edits).
- H1 (:70) "Free website vulnerability scanner for your live app." Good.
- H2s: "Website security checks that matter for a real app.", "A website scan sees what is public. Your repository shows the rest.", "Free vulnerability scan questions." Only one H2 has a partial keyword. Add an H2 with "website vulnerability scanner" and one on what it doesn't test.
- Cannibalized by the homepage (see Homepage C).
- Missing internal links: none to /guides/security-headers-for-saas, /guides/exposed-files-and-source-maps, /guides/ssl-tls-checklist-for-saas or /lovable-security-scanner. Only the checklist and pricing are linked (:93).
- Competitors cover OWASP Top 10 mapping, active tests (SQLi, XSS), scan time, daily limits, Quick vs Deep tiers and DKIM. We should say plainly what we do **not** test and map our checks to OWASP Top 10:2025. That is honest, and it fits listicle-style queries.

### D) Usefulness gaps (true per code)
- "What the free scan does not test": no SQL injection or XSS payloads, no login, no pages behind auth, no open-redirect test. Headers are checked on the first page. SPAs: only pages linked in server HTML are crawled.
- Limits: one free scan per domain without an account. A free account adds one verification rescan within 7 days. Up to 3 scans per hour per network without an account.
- Exactly what is probed: 20 sensitive files (list them: /.env, /.git/config, /.git/HEAD, /backup.sql, /database.sql, /phpinfo.php, /Dockerfile, /docker-compose.yml, ...), 10 directories, 13 API/debug paths.
- An example finding with the remediation text (any remedy from scanner.ts works, e.g. the CSP Report-Only rollout at scanner.ts:451-476).

### Exact edit instructions
1. :13 meta description. Replace with `"Free website vulnerability scanner. Scan up to 25 pages for exposed files, missing security headers, cookie flags, SSL and CORS issues. No signup or card."` (154 chars).
2. :31. Replace the card copy with `"Your free fix comes with a prompt you can paste into Cursor, Claude or Codex. Paid plans add a fix and a prompt for every finding."`
3. :37. Replace the answer with: `"The scan sends ordinary GET requests to up to 25 of your pages and to 43 known sensitive paths such as /.env, /.git/config and /graphql. It also sends one TRACE request, one request with a test Origin header to check CORS, and a read-only GraphQL introspection query if a GraphQL endpoint responds. It does not log in, submit your forms, send attack payloads or change data. Scan only websites you own or are authorized to test."`
4. :36. Remove "Most scans finish in well under a minute" unless it can be backed. <!-- NEEDS SPECIFIC: median scan duration from production Scan records --> Safe interim text: `"Scan time depends on how fast your pages respond. The scanner reads at most 25 pages and waits up to 15 seconds for each."`
5. :38 and :85. Replace `"missing authorization checks"` / `"routes without ownership checks"` with `"...committed secrets and risky workflows. On Starter and Pro, an AI review also reads server routes for missing ownership checks."`
6. :71. Replace `"You get a prioritized report with the affected URLs, not a wall of noise."` with `"The report lists each finding by severity with the URL where it was seen."`
7. :79. Change H2 `"Website security checks that matter for a real app."` to `"What the free website vulnerability scanner checks"`.
8. Add a new section after the checks grid. H2: `"What the free scan does not test"`. Body (true per scanner.ts): no login or pages behind auth; no SQL injection, XSS or other attack payloads; no open-redirect test; security headers are read from the first page; single-page apps: the crawler follows links in the server HTML, so a React or Vite SPA often shows one page. Link to /repo-scan for code-level issues.
9. Add a new section, H2 `"OWASP Top 10:2025 coverage"`, as a 3-column table (category / what we check / not checked). A02 Security Misconfiguration: headers, CSP, CORS reflection, directory listing, debug endpoints, GraphQL introspection, TRACE, exposed files, error pages. A04 Cryptographic Failures: TLS trust and expiry, HTTPS redirect, HSTS, mixed content, Secure cookie flag, forms posting over HTTP. A03 Software Supply Chain Failures: outdated jQuery/AngularJS/Bootstrap, third-party scripts without SRI. A05 Injection: review signals only (inline DOM sinks, CSP unsafe-inline), no payload testing. A01 Broken Access Control and A07 Authentication Failures: not tested from outside (cookie flags only), so point to the repo scan's paid AI review and the checklist guide. Source: https://top10.owasp.org/2025/.
10. Add a "How it works" H2 using the keyword: `"How the website vulnerability scanner works"`, in 3 steps: crawl up to 25 pages, probe 43 sensitive paths and read headers/TLS/DNS, report sorted by severity with one free fix.
11. Link each card to its guide. SSL and HTTPS → /guides/ssl-tls-checklist-for-saas. Security headers → /guides/security-headers-for-saas. Exposed files → /guides/exposed-files-and-source-maps. Crawl readiness → /guides/robots-txt-and-sitemap-for-saas.
12. :93. Add `or the <Link href="/lovable-security-scanner">Lovable security scan</Link>` to the closing links sentence.
13. :85. Change H2 `"A website scan sees what is public. Your repository shows the rest."` to `"Scan the GitHub repo behind the site"`, and drop the eyebrow "Outside and inside".

---

## 3. /repo-scan (`page.tsx`, `layout.tsx`, `repoFaqs`, `repoScanSteps`)

**Priority: 7/10.** This is the most accurate page. The main problems: a misleading "free ... private" meta description, an imprecise dependency claim, and no limits section.

### A) Fact check

| # | Quoted claim | Verdict | Correct fact / source |
|---|---|---|---|
| 1 | **Meta: "Free GitHub repo scanner. Scan public or private repos (read-only)..."** (layout.tsx:8) | **MISLEADING** | Private repos need Starter/Pro (repo-scan-jobs.ts:9, 91) |
| 2 | "Reads up to 60 security-relevant files from one pinned commit, highest-risk first. It does not search full Git history." (page.tsx:105) | CORRECT | github-scanner.ts:11, 494-500 |
| 3 | Step 2: "up to 60 security-relevant files ... highest-risk first: middleware, API routes, auth, payments, configs and workflows" (site-content.ts:73) | IMPRECISE | Real order: .env/keys/.npmrc → workflows and agent files → lockfiles, migrations, .sql → .gitignore/package.json/next and vite config → source ranked by risk (github-scanner.ts:211-221, 198-209) |
| 4 | "Exact versions from npm, Python, Go, and Rust lock data checked against the OSV advisory database." (page.tsx:33) | PARTLY WRONG | npm = package-lock.json/npm-shrinkwrap only. Python = `==` lines in requirements*.txt (not a lockfile). Go = go.mod (not go.sum). pnpm/Yarn/Bun lockfiles are not parsed (repo-security-rules.ts:163-205). Cap of 180 deps (:28) |
| 5 | "Agent permissions, remote MCP transport, unpinned tool packages, destructive commands, and secret-transfer paths." (page.tsx:34) | CORRECT | repo-security-rules.ts:67-130 |
| 6 | "Supabase service-role exposure and SQL migrations that create tables without visible RLS enablement." (page.tsx:32) | CORRECT, with caveats | Runs only if the repo references supabase-js or supabase.co (github-scanner.ts:408). Ignores GRANTs, so after Supabase's Oct 30, 2026 change a flagged table may not be API-exposed |
| 7 | "Broad token permissions, mutable action tags, secret output, and dangerous pull_request_target flows." (page.tsx:30) | CORRECT | github-scanner.ts:320-341 |
| 8 | "Public environment secrets, raw HTML sinks, dynamic code execution, wildcard CORS, and source maps." (page.tsx:31) | CORRECT | github-scanner.ts:306, 369-394 |
| 9 | "We never execute repository code" / "Secret values stay out of the report" (page.tsx:88) | CORRECT | secret-patterns.ts:1, 30-39 |
| 10 | "Free, no account needed. Sign in to save reports." (page.tsx:100) | CORRECT | api/repo-scan/route.ts (anonymous) |
| 11 | FAQ: "On Starter and Pro an AI review also reads the riskiest files for authorization and business-logic gaps." (site-content.ts:80) | CORRECT | ai-review.ts:36, 71-72 |
| 12 | FAQ: "returns findings ... usually within a minute" (site-content.ts:84) | UNVERIFIABLE | Jobs can run up to 6 min before being marked stale (repo-scan-jobs.ts:13). AI review has a 110 s budget (:132) |
| 13 | FAQ: "It can only read repository contents and metadata and cannot write to your code. Files are read in memory ... only the report is saved" (site-content.ts:92) | CORRECT | github-app.ts:154. Private results are never cached (github-scanner.ts:496) |
| 14 | FAQ: "It reads a bounded set of text files from one commit through the GitHub API" (site-content.ts:96) | MOSTLY CORRECT | Public repos are read from raw.githubusercontent (github-scanner.ts:223, 252), private ones through the contents API |
| 15 | FAQ: "GitHub's tools focus on known secret formats and dependency alerts." (site-content.ts:100) | CORRECT (fair) | GitHub docs page above |
| 16 | Step 3: "Each finding ... comes with a fix prompt for Cursor, Claude or Codex." (site-content.ts:74) | CORRECT | RepoReport.tsx:78 |
| 17 | JSON-LD description "public and private repositories" + `isAccessibleForFree: true` (layout.tsx:28-29) | MISLEADING (same as #1) | |

### B) AI-writing tells
- "The mistakes hidden behind a working demo." (page.tsx:112). An aphorism heading in place of a keyword heading.
- "Check a public or private repository for the mistakes AI coding agents cannot see after deployment" (page.tsx:87). This is muddled: the agents aren't what "sees" after deployment. Then a five-item list.
- Parallel slogan pair: "Scan the repository before launch. Scan the public app after launch." (page.tsx:113) plus the eyebrow "Two scans, two surfaces".
- Otherwise the page is plain and specific. The form microcopy ("Reading repository security files...") is fine. Leave it.

### C) SEO
- Title "GitHub Repo Security Scanner: Free Scan for Secrets & Vulnerabilities" (layout.tsx:7) is 68 chars and has both target keywords. Good. No brand (absolute title). Acceptable.
- Meta description is 171 chars and makes the misleading private claim. Rewrite (edit 1).
- H1 "GitHub repo scanner for vibe-coded apps." Good.
- H2s: "The mistakes hidden behind a working demo.", "Scan the repository before launch...", "Scan a repo in three steps.", "Questions about scanning your repository." None says "GitHub repo security scanner". Rename the first.
- Internal links: no link to /pricing (private repos are a paid feature), /lovable-security-scanner, or the secret-scanning / Actions / Supabase guides.
- No cannibalization problem. The homepage title says "GitHub Repo Scan", which is fine.

### D) Usefulness gaps (true per code)
- A limits box: 60 files, 240 KB per file, 6 MB total, repos up to 100,000 tree entries, no Git history (a secret deleted in a later commit is not found; link /guides/github-secret-scanning-for-vibe-coded-apps). pnpm/Yarn/Bun lockfiles are not checked against OSV yet. Rate limits: 5 public scans per 10 minutes without an account; 15 per hour and 2 at a time when signed in.
- Which secret formats are detected: private keys, AWS, GitHub (classic and fine-grained), Stripe live/restricted/webhook, Google API, Slack, Supabase `sb_secret_` and service_role JWTs, OpenAI project/service/admin keys, DB URLs with passwords.
- That repo scans do not use website credits.

### Exact edit instructions
1. layout.tsx:8. Replace the meta description with `"Free GitHub repo scanner for public repos, private repos on paid plans. Finds committed .env files, API keys, risky GitHub Actions, RLS gaps and vulnerable deps."` (161 chars).
2. layout.tsx:28. Change the JSON-LD description to `"A read-only GitHub repo scanner. Public repositories are free; private repositories are included in Starter and Pro. Checks committed secrets, risky workflows, client-code exposure, Supabase RLS and vulnerable dependencies."`
3. page.tsx:33. Replace with `"Exact versions from package-lock.json, pinned requirements.txt lines, go.mod and Cargo.lock, checked against the OSV advisory database. pnpm, Yarn and Bun lockfiles are not read yet."`
4. site-content.ts:73. Replace `"...highest-risk first: middleware, API routes, auth, payments, configs and workflows."` with `"...in this order: environment and key files, GitHub workflows and agent configs, lockfiles and SQL migrations, build configs, then source files ranked by risk (middleware, API routes, auth and payment code)."`
5. page.tsx:87. Replace `"the mistakes AI coding agents cannot see after deployment"` with `"the mistakes a website scan cannot see"`.
6. page.tsx:112. Change H2 `"The mistakes hidden behind a working demo."` to `"What the GitHub repo security scanner checks"`.
7. Add a section after the steps: H2 `"Scan limits"`, with the limits from D) as a short list. Link "Git history" to /guides/github-secret-scanning-for-vibe-coded-apps.
8. page.tsx:32. Append `" Supabase now requires an explicit grant before new tables reach the Data API, so confirm a flagged table is granted to anon or authenticated before treating it as public."` (source: Supabase changelog 45329).
9. site-content.ts:84. Remove "usually within a minute" or back it with data. <!-- NEEDS SPECIFIC: median repo scan duration -->
10. page.tsx:121 (closing links). Add `<Link href="/pricing">private repo plans</Link>` and `<Link href="/lovable-security-scanner">Lovable security scan</Link>`.
11. Add FAQ to repoFaqs: `"Do repository scans use scan credits?"` → `"No. Credits are only used for website scans. Public repository scans are free, and private repository scans are included in Starter and Pro."` (true: no credit logic in repo routes).

---

## 4. /vibe-coding-security

**Priority: 5/10.** Content is mostly accurate but generic. One outdated citation, one overpromise in the meta, a stale dateModified, and it competes with the vibe checklist guide.

### A) Fact check

| # | Quoted claim | Verdict | Correct fact / source |
|---|---|---|---|
| 1 | Meta: "Scan your GitHub repo and live site for secrets, Supabase RLS gaps and missing auth checks." (:23) | OVERPROMISE | Auth checks are paid AI review only (ai-review.ts:36) |
| 2 | "Research on AI-generated code has found that functional success does not guarantee security." (:64) | CORRECT but vague | arXiv 2512.03262: 57% functionally correct vs 11.8% secure (SWE-Agent + Claude 4 Sonnet) |
| 3 | Link "OWASP secure coding practices" → owasp.org/www-project-secure-coding-practices-quick-reference-guide/ (:100) | **OUTDATED** | The project is archived and moved into the OWASP Developer Guide |
| 4 | Link "GitHub secret protection" → github-security-features (:100) | CORRECT (the page loads; it covers Secret Protection) | |
| 5 | Link "Is Vibe Coding Safe? research paper" → arXiv 2512.03262 (:100) | CORRECT | |
| 6 | FAQ: "The ScanMySaaS GitHub repo scanner reads security-relevant files from one pinned commit ... flags committed .env files, private keys and API keys with the file and line. Keep GitHub secret scanning and push protection enabled" (:37) | CORRECT | github-scanner.ts:396-400; GitHub docs |
| 7 | FAQ: "It does not clone the repository, install dependencies, run builds or execute repository code." (:38) | CORRECT | |
| 8 | FAQ: "with read-only contents and metadata permissions. ScanMySaaS works this way on Starter and Pro ... an AI review checks the riskiest files for missing authorization and business-logic gaps." (:39) | CORRECT | github-app.ts:154; ai-review.ts |
| 9 | By-tool cards: "Claude Code and Codex: ... webhook handlers that skip signature verification or idempotency"; "Any Next.js or React app: ... paid features enforced only on the client"; "Cursor: API routes that read or update a record by ID without checking it belongs to the signed-in user" (:83-86) | OK as "what to check". Implied scanning = paid AI only | Rule-based scanner has none of these. ai-review.ts:35 covers them on paid plans |
| 10 | JSON-LD `datePublished: "2026-08-13", dateModified: "2026-08-13"` (:45) | OUTDATED | The page has changed since (Lovable link to a page created today). Set to the real last-edit date |
| 11 | Step 04: "A deleted finding is evidence that the fix reached the public surface." (:75) | CORRECT (if rescanned) | api/scan/[id]/route.ts:44 |
| 12 | "Bolt" grouped with Lovable as Supabase stacks (:83) | UNVERIFIABLE generalization | Bolt supports several backends. Soften |

### B) AI-writing tells
- Abstract aphorism: "The useful response is a repeatable review at the places where authority changes hands." (:64). The same section's H2: "The code can pass tests and still cross the wrong boundary." (#32).
- Staccato contrast: "A production scan cannot see a private workflow file. A repository scan cannot prove that a CDN serves the right security headers. Use both." (:70) (#31).
- Vague attribution: "Research on AI-generated code has found..." (#5). The citation exists two screens lower and should be inline.
- Rule-of-three and lists everywhere: "secrets, authorization, database access, workflows, dependencies, and production behavior" (:36). Five boundaries, four steps, four tools, three guides, four FAQs. Every block is the same shape (S6).
- The H1 tail "before users find the gaps" is repeated on the Lovable H1.
- "Treat generated code as unreviewed code and verify its security boundaries before release." (:36). A restated takeaway (S1).

### C) SEO
- Title "Vibe Coding Security Scanner for AI-Built Apps | ScanMySaaS" (:22). It contains "vibe coding security". OK.
- Meta (:23) is 185 chars, too long, and overpromises.
- H1 (:57) "Vibe coding security scanner before users find the gaps." Same tail as the Lovable H1 (lovable page.tsx:121). Make them distinct.
- **Cannibalization:** /guides/vibe-coding-security-checklist (seoTitle "Vibe Coding Security Checklist: 47 Checks Before You Ship (2026)", guides.ts:569) also targets "vibe coding security". Split intent: this page = scanner/tool, guide = checklist. This page already links the guide (:81). Make sure the guide links back with the anchor "vibe coding security scanner".
- Article schema author "ScanMySaaS Editorial Team" (:45) is weak for E-E-A-T. Use a real named person if there is one. <!-- NEEDS SPECIFIC: real author name -->
- Thin on unique data. Competitors rank with "we scanned N vibe-coded apps" posts. Any aggregate stat from our own scans would need real data. <!-- NEEDS SPECIFIC: aggregate stats from production scans, if Stefan wants to publish them -->

### D) Usefulness gaps
- Which parts are free (website scan, public repo scan) and which are paid (private repos, AI ownership review), next to each boundary.
- Concrete numbers from the cited paper.
- Supabase's Oct 30, 2026 grant change, which shifts how RLS mistakes show up.

### Exact edit instructions
1. :23 meta. Replace with `"Vibe coding security for apps built with Lovable, Cursor, Bolt, Claude Code or Codex. Free scans of your GitHub repo and live site for secrets and RLS gaps."` (156 chars).
2. :64. Replace `"Research on AI-generated code has found that functional success does not guarantee security. The useful response is a repeatable review at the places where authority changes hands."` with `"In the SusVibes benchmark (<a href="https://arxiv.org/abs/2512.03262">Zhao et al.</a>), 57% of the solutions from SWE-Agent with Claude 4 Sonnet were functionally correct, but only 11.8% were secure. Check these five places, where a user, a key or a workflow gets more access than it should."`
3. :100. Replace the OWASP link with `<a href="https://top10.owasp.org/2025/">OWASP Top 10:2025</a>` (or the Developer Guide at https://owasp.org/www-project-developer-guide/).
4. :45. Set `dateModified` to the actual date of the latest content change (at least 2026-11-07, since the Lovable link was added).
5. :57. Change H1 to `"Vibe coding security: scan the repo and the live app"`.
6. :64 H2 `"The code can pass tests and still cross the wrong boundary."` → `"Five places to check in an AI-built app"`.
7. :70. Replace `"A production scan cannot see a private workflow file. A repository scan cannot prove that a CDN serves the right security headers. Use both."` with `"The website scan reads what your host serves: headers, TLS, cookies and exposed files. The repo scan reads workflows, migrations and keys that never reach the browser. You need both."`
8. :39 and the by-tool section (:81). Add one sentence after the by-tool intro: `"The free repo scan finds committed secrets, risky workflows and tables without RLS. Ownership checks, webhook signatures and paid features enforced only in the browser are covered by the AI review on Starter and Pro."`
9. :83. Change `"Lovable and Bolt with Supabase"` to `"Lovable (and Bolt projects that use Supabase)"`.
10. :36. Delete `"Treat generated code as unreviewed code and verify its security boundaries before release."` The answer already makes the point.

---

## 5. /pricing (`page.tsx`, `layout.tsx`, `pricingFaqs`)

**Priority: 6/10.** Prices, credits and rollover are all correct. The problems: the H1 has no keyword, the Pro list is misleading or redundant, "10 scans" is ambiguous, and two badges can't be verified.

### A) Fact check

| # | Quoted claim | Verdict | Correct fact / source |
|---|---|---|---|
| 1 | "$29 per month", "10 credits / month", "Up to 20"; "$79", "30 credits / month", "Up to 60" (page.tsx:27-44, 135) | CORRECT | stripe.ts:26-42; billing-credit-store.ts:23 |
| 2 | Meta: "Starter $29/month (10 scans), Pro $79/month (30 scans) with private repo and AI code review." (layout.tsx:7) | AMBIGUOUS | Credits = **website** scans only. Repo scans are not metered. The feature is called "AI logic review" everywhere else |
| 3 | Free: "Up to 25 pages", "60+ automated checks", "One actionable fix, when found", "One free rescan to verify your fix", "Public GitHub repository scans" (:22) | CORRECT | rescan needs an account (scan-access.ts:49-60) |
| 4 | Starter: "Private GitHub repository scans (read-only)", "AI logic review (monthly token limits)", "Step-by-step remediation", "Resolved / new findings after each rescan", "Scan history and score trends", "Credits roll over" (:34) | CORRECT | Note: resolved/new comparison also works on the free verification rescan (api/scan/[id]/route.ts:44) |
| 5 | **Pro: "Background scans saved to your dashboard"** (:46) | MISLEADING | Any signed-in user's repo scan runs in the background and is saved (repo-scan/page.tsx:59-66, comment "Signed-in users get a saved report") |
| 6 | Pro: "Everything in Starter" + "Private GitHub repository scans (read-only)" + "Step-by-step remediation" + "Score trends" (:46) | REDUNDANT | Already included via "Everything in Starter" |
| 7 | Pro summary "For teams checking multiple apps and environments." (:41) | OVERPROMISE | No team/seat model in prisma/schema.prisma |
| 8 | Table "AI logic review: Monthly token limit / Higher monthly token limit" (:134) | CORRECT | ai-review.ts:48-50 (600k vs 2M default; confirm prod env) |
| 9 | Table "Saved scan history: ✓ ✓ ✓" (:130) | CORRECT | Contradicts homepage FAQ site-content.ts:30 (fix the homepage) |
| 10 | Table "Free verification rescan: Within 7 days / Uses credits / Uses credits" (:131) | CORRECT | scan-access.ts:41-42, 60 |
| 11 | "Existing subscriber prices stay unchanged" (:95) | UNVERIFIABLE | Nothing in code shows a price change or grandfathering logic |
| 12 | "Most popular" badge on Starter (:103) | UNVERIFIABLE | No data in code |
| 13 | FAQ: "Starter is $29 per month with 10 website scan credits, and Pro is $79 per month with 30 credits. Both include private repository scans, remediation for every finding and the AI logic review" (site-content.ts:105) | CORRECT | |
| 14 | FAQ: "One credit runs a new crawl and security report for one website." (:107) | CORRECT | scan-gate.ts:157-161 |
| 15 | FAQ: "New monthly credits are added up to that cap." (:108) | CORRECT | billing-credit-store.ts:23 |
| 16 | FAQ: "selected source files are sent to OpenAI for analysis using store: false ... You can opt out in your dashboard ... If AI is unavailable or the budget is exhausted, your rule-based report still completes." (:111) | CORRECT | ai-review.ts:61, 119-120; AIReviewPreference.tsx |
| 17 | FAQ: "Subscribers can open the Stripe billing portal from the dashboard" (:112) | CORRECT | src/app/api/stripe/portal |
| 18 | FAQ: "It is an automated outside-in assessment" (:113) | INCOMPLETE | The repo scan is inside-out |
| 19 | Free "1 scan credit" (:19) | CORRECT for accounts | An anonymous first scan uses no credit (scan-access.ts:53) |

### B) AI-writing tells
- Negative-parallel H1: "Pay for scans, not security theater." (:93).
- "No fine print." (:145). A punchline H2 that says nothing.
- "Find an issue and try one practical fix." (:18). Fine as microcopy.
- Em dash as a table placeholder: `rollover: "—"` (:20). This is UI, but use "None" for consistency with the no-dash rule.
- Register gate: the plan cards and comparison table are product microcopy. Keep them plain. Only the H1, the subhead and the FAQ heading need work.

### C) SEO
- Title "Vulnerability Scanner Pricing: Free, $29 & $79 Plans | ScanMySaaS". Good.
- Meta is 177 chars. Trim it.
- H1 "Pay for scans, not security theater." has no keyword. The H2s are plan names plus "What changes when you upgrade" and "No fine print."
- Schema: FAQPage only. Add a Product/SoftwareApplication with Offers (monthly UnitPriceSpecification) to match the homepage JSON-LD.
- Cannibalization: the FAQ "Is there a free vulnerability scanner?" (site-content.ts:106) overlaps the free page. Add a link to /free-website-vulnerability-scanner in the visible copy. FAQ answers are plain strings, so add a sentence with a Link under the FAQ list.
- No competitor price comparison. Adding one would need verified competitor prices. <!-- NEEDS SPECIFIC: current competitor prices with sources, if wanted -->

### D) Usefulness gaps (true per code)
- "Do repo scans use credits?" No.
- What a free visitor gets without an account: one scan per domain, report kept only if they sign up.
- AI review budget in plain terms (2 batches per scan, monthly token cap), once prod values are confirmed.

### Exact edit instructions
1. layout.tsx:7. Replace the meta with `"Vulnerability scanner pricing: free website and public repo scans. Starter $29/mo (10 website scans), Pro $79/mo (30). Both add private repos and AI logic review."` (162 chars; trim "Both" if needed).
2. page.tsx:93. Change H1 to `"Vulnerability scanner pricing"` and move `"Pay for scans, not security theater."` into the eyebrow at :92, or drop it.
3. page.tsx:46. Replace the Pro features with `["Everything in Starter", "30 credits a month", "Rollover up to 60 credits", "Higher monthly AI review limit"]`. Remove "Background scans saved to your dashboard", the duplicate "Private GitHub repository scans (read-only)", "Step-by-step remediation" and "Score trends". If the token caps are confirmed in production, the last item can read "AI review: 2M tokens a month (Starter: 600k)". <!-- NEEDS SPECIFIC: confirm AI_REVIEW_PRO_MONTHLY_TOKENS / AI_REVIEW_STARTER_MONTHLY_TOKENS in prod -->
4. page.tsx:41. Replace `"For teams checking multiple apps and environments."` with `"For founders running several apps, or staging and production."`
5. page.tsx:22. Add `"What was fixed and what is new on your rescan"` after "One free rescan to verify your fix".
6. page.tsx:20. Change `rollover: "—"` to `rollover: "None"`.
7. page.tsx:95. Remove "Existing subscriber prices stay unchanged" unless a price change actually happened. <!-- NEEDS SPECIFIC: was there a price change? --> Remove "Most popular" (:103) unless signup data supports it.
8. site-content.ts:113. Replace `"It is an automated outside-in assessment, not a certification or penetration test."` with `"It is an automated scan of your public site and, if you run it, your repository. It is not a certification or a penetration test."`
9. Add to pricingFaqs: `["Do repository scans use credits?", "No. Credits are only used for website scans. Public repository scans are free on every plan, and private repository scans are included in Starter and Pro."]`
10. page.tsx:145. Change H2 `"No fine print."` to `"Pricing FAQ"`. Below the FAQ list, add `Only need one check? Try the <Link href="/free-website-vulnerability-scanner">free website vulnerability scanner</Link>.`
11. layout.tsx. Add a SoftwareApplication JSON-LD with three Offers (0, 29, 79 USD; paid ones with `priceSpecification: { "@type": "UnitPriceSpecification", unitText: "MONTH" }`).

---

## 6. /guides (index)

**Priority: 3/10.** Low traffic on its own, but it is the hub for internal links and is under-used.

### A) Fact check
| # | Quoted claim | Verdict | Note |
|---|---|---|---|
| 1 | "Practical guides for the checks that repeatedly matter in SaaS websites, source repositories, deployment workflows, and databases." (:22) | CORRECT (the 10 guides cover these) | guides.ts |
| 2 | "Run the public scanner, then use the affected URLs to work through the right guide." (:37) | CORRECT | |
| 3 | Guide card "Vibe coding security checklist: 47 checks before you ship" (from guides.ts:568) | Not verified (out of scope). Count the bullets in guides.ts:567-703 before relying on "47" | |

### B) AI-writing tells
- H1 "Fix the surface your customers can see." (:21). An aphorism, no keyword, and wrong for half the guides (repo, Actions, Supabase aren't customer-visible).
- Rule of three: "Each one explains what the signal means, what to verify, and how to ship a safer change." (:22).
- Eyebrow "ScanMySaaS field guides" is fine.

### C) SEO
- Title "SaaS Security Guides | ScanMySaaS". Short. Add the vibe-coding angle.
- H1 has no keyword. The guide cards are H2s (fine).
- There is no grouping by surface and no ItemList/CollectionPage schema.
- No link to /lovable-security-scanner, /repo-scan or /vibe-coding-security. The bottom CTA only offers the website scan (:38), though 4 of the 10 guides are repo or database topics.
- The first (featured) card is `guides[0]` = launch checklist. Fine.

### Exact edit instructions
1. :9. Title → `"SaaS Security Guides for Vibe-Coded Apps"`.
2. :21. H1 → `"SaaS security guides for vibe-coded apps"`.
3. :22. Replace with `"Ten guides for the problems the scanners find: what each finding means, how to confirm it, and how to fix it on your live site, in your GitHub repo and in Supabase."`
4. Group the cards under three H2s: `"Live website"` (security headers, SSL/TLS, exposed files and source maps, robots/sitemap, llms.txt), `"GitHub repo"` (secret scanning, GitHub Actions), `"Database and app logic"` (Supabase, vibe coding checklist). Keep the launch checklist featured on top. Demote the card headings to H3.
5. :35-39 CTA box. Add a second button `<Link href="/repo-scan">Scan a GitHub repo</Link>` and a text link `<Link href="/lovable-security-scanner">Lovable security scan</Link>`.
6. Add `CollectionPage` + `ItemList` JSON-LD listing the 10 guide URLs.

---

## 7. /lovable-security-scanner (new today; lighter pass)

**Priority: 8/10.** High-intent keyword, and the page is already live and in the sitemap. But its central RLS claim went out of date on Oct 30, 2026. It points users to a Supabase dashboard that Lovable Cloud users don't have, ignores Lovable's newer `drizzle/migrations/` folder, and promises a fix prompt for every website finding and 25-page crawls that a Lovable SPA won't get.

### A) Fact check

| # | Quoted claim (page.tsx:line) | Verdict | Correct fact / source |
|---|---|---|---|
| 1 | **"A table created in a SQL migration without ALTER TABLE … ENABLE ROW LEVEL SECURITY can be read through the Supabase Data API by anyone holding the public publishable (anon) key, which ships in every Lovable bundle."** (:38) | **OUTDATED / incomplete** | Since Oct 30, 2026 (all projects; May 30 for new ones), new public tables are not granted to anon/authenticated automatically. Exposure needs a grant plus RLS off. Older tables keep their grants. When exposed, the table is "readable **and writable**" (Supabase changelog 45329; RLS docs) |
| 2 | "The secret key (sb_secret_…) and the legacy service-role key bypass every RLS policy." (:39) | CORRECT (nuance) | api-keys doc: "bypasses every Row Level Security policy". RLS doc: only when no user access token is attached |
| 3 | "These are the issues behind most real Lovable data leaks." (:36) | UNVERIFIABLE ("most") | Cite CVE-2025-48757 (insufficient RLS in Lovable apps, disputed by Lovable) instead of "most" |
| 4 | "Without Content-Security-Policy, clickjacking protection and HSTS, a single injected script can read session tokens stored in the browser." (:49) | PARTLY WRONG (causal mix-up) | CSP limits script injection. Frame protection stops clickjacking. HSTS stops downgrade. None of the three stops an injected script from reading tokens; that happens because the session sits in browser storage. Whether Lovable hosting lets users set headers is unconfirmed by primary docs |
| 5 | **"Paste your lovable.app or custom domain above. The free website scan checks headers, cookies, SSL, exposed files and source maps on up to 25 pages."** (:66) | OVERPROMISE | Lovable apps are client-rendered. The crawler follows `<a href>` in server HTML only (scanner.ts:261-275), so it usually finds 1 page. Headers are read on the first page regardless (scanner.ts:1450) |
| 6 | "Public repos scan without an account; private repos connect through a read-only GitHub App." (:67) | CORRECT, incomplete | Private repos need Starter/Pro (repo-scan-jobs.ts:91) |
| 7 | "This is where RLS gaps and leaked keys show up." (:67) | CORRECT, with caveat | The RLS check runs only if the repo references `@supabase/supabase-js`, `supabase/migrations` or `supabase.co` (github-scanner.ts:408). Unverified whether Lovable Cloud projects using drizzle/migrations contain those strings. <!-- NEEDS SPECIFIC: test-scan a current Lovable Cloud repo --> |
| 8 | **"Every finding comes with a prompt you can paste into the Lovable chat"** (:68) | **WRONG for website findings on free** | Repo findings: yes (RepoReport.tsx:78). Website: only the free fix, or all on paid (scan/[id]/page.tsx:89; scan-remediation.ts:44) |
| 9 | "Run the scan again after publishing. Resolved findings disappear from the report, and the comparison shows what is new or still open." (:69) | CORRECT for website scans, incomplete | A free account gets 1 verification rescan within 7 days (scan-access.ts:60). No comparison exists for repo scans |
| 10 | FAQ: "Lovable runs a Quick scan of database rules and dependencies when you open the publish dialog, and a Deep scan of your code that you start yourself from the Security view." (:74) | MOSTLY CORRECT, incomplete | Quick scan also runs "automatically every time you publish" and includes an MCP server check. Deep scan can also start from the publish dialog, Security center or chat (docs.lovable.dev/features/security) |
| 11 | FAQ: "...headers, cookies, TLS and exposed files that live on hosting rather than in code. It also reads the synced GitHub repository, so changes made outside Lovable in Cursor or Claude Code are covered, and gives you a report you can rescan and share." (:74) | CORRECT | Website reports have share links (src/lib/report-access.ts:37-38) |
| 12 | FAQ: "In the Supabase dashboard, open Table Editor and look for tables marked as unrestricted or without RLS. In code, every create table statement in supabase/migrations should be followed by an enable row level security statement." (:75) | **OUTDATED** for Lovable's built-in backend | Lovable Cloud tables are in More → Database. New migrations are under `drizzle/migrations/`; older ones under `supabase/migrations/` (docs.lovable.dev/features/database.md). The Supabase dashboard applies only to "your own Supabase project". The "unrestricted" label could not be verified in Supabase docs |
| 13 | FAQ: "The ScanMySaaS repo scan flags tables created in migrations without visible RLS enablement." (:75) | CORRECT (any .sql file, see #7) | github-scanner.ts:410-421 |
| 14 | FAQ: "publishable key (sb_publishable_…, which replaces the legacy anon key) is designed to be public ... secret key (sb_secret_…, which replaces the legacy service_role key) ... bypasses RLS" (:76) | CORRECT | Supabase api-keys doc |
| 15 | FAQ: "Supabase is retiring the legacy anon and service_role keys by the end of 2026" (:76) | CORRECT (wording) | Doc: "deprecating ... by the end of 2026" |
| 16 | FAQ: "install the ScanMySaaS GitHub App ... only requests read access to contents and metadata. The scan runs in the background" (:77) | CORRECT; missing that it needs a paid plan | github-app.ts:154; repo-scan-jobs.ts:91 |
| 17 | FAQ: "The first website scan and public repository scans are free ... Private repositories and the AI logic review ... are included in the paid plans." (:78) | CORRECT | |
| 18 | Lovable column: "Quick scan of database rules and dependencies when you publish" / "Deep scan of your code, started on demand" / "Fixes run inside the same project" (:164) | CORRECT | Lovable docs |
| 19 | "On paid plans, the AI logic review reads server routes and edge functions in the repository and flags code that changes data without checking who is signed in" (:166) | CORRECT | ai-review.ts:35, riskScore `functions`/`edge-functions` (github-scanner.ts:201) |
| 20 | "Start with the live URL. It takes under a minute and needs no account." (:182) | UNVERIFIABLE (time) | |
| 21 | "Risky GitHub Actions and missing .gitignore rules: Workflows with write-all permissions, unpinned actions, or no rule keeping .env files out" (:60) | CORRECT | github-scanner.ts:320-341, 425-435 |
| 22 | "Storage buckets readable by anyone" tagged Manual test (:59) | CORRECT (no storage check exists) | |
| 23 | "RLS policies that are too permissive" tagged Manual test (:48) | CORRECT (no policy analysis in code) | |

### B) AI-writing tells
- The H1 tail "before your users find the gaps." (:121) duplicates the vibe page H1.
- "That makes the failure modes predictable." (:134). Stated without evidence.
- "We list them because a clean scan is not the same as a safe app." (:146). A negative-parallel aphorism, though it is earned here. Keep it or tighten it.
- Heading pair "Use Lovable's security scan. Then check from the outside." (:162). Fine.
- Severity summaries are tidy, one line per tier. The page has better structural variety than the others (tagged coverage, manual-test honesty). That is a sign of human-sounding writing. Preserve it.

### C) SEO
- Title (:12) "Lovable Security Scan: Find Security Issues in Your Lovable App" (63 chars). Has both keywords. Good.
- Meta (:13) is 202 chars. Trim it.
- H1 has "Lovable security scan". The H2 "Common Lovable security issues." matches "lovable security issues". Good.
- Missing keyword variants worth an H2 or FAQ: "Lovable Cloud" (Lovable's built-in backend name) and "is Lovable safe" (already covered by the FAQ "Is Lovable secure?").
- Internal links: links /repo-scan, the Supabase guide, the vibe checklist, /vibe-coding-security and /pricing. Good. Add /free-website-vulnerability-scanner.
- HowTo schema step 3 repeats the wrong "Every finding comes with a prompt" text (HowTo is built from `steps`, :99), so fixing `steps` fixes the schema too.

### D) Usefulness gaps (true per sources)
- Lovable Cloud vs own Supabase project: where to check policies in each.
- The Supabase grant change. It changes what an RLS-less table means for new tables.
- A plain statement that a Lovable SPA scan usually covers one page.
- Honest overlap: Lovable's Quick scan already flags tables without per-record access control.

### Exact edit instructions
1. :38. Replace the copy with: `"If a table in the public schema is granted to the anon or authenticated role and RLS is off, anyone with the publishable key (it ships in every Lovable bundle) can read and write it through the Data API. Supabase stopped granting new tables to these roles automatically (new projects from May 30, 2026, all projects from October 30, 2026), but older tables keep their grants, and a migration that adds a grant without enabling RLS reopens the gap."` Add a source link to https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically in the "Primary guidance" row (:176).
2. :36. Replace `"These are the issues behind most real Lovable data leaks."` with `"Missing or weak RLS was behind CVE-2025-48757, a 2025 report of exposed data in Lovable apps (Lovable disputes the CVE)."` and link https://nvd.nist.gov/vuln/detail/CVE-2025-48757.
3. :49. Replace the copy with: `"A strict Content-Security-Policy makes it harder to inject a script, which matters because a Supabase session kept in browser storage is readable by any script on the page. HSTS stops HTTPS downgrades, and frame protection stops clickjacking."` <!-- NEEDS SPECIFIC: link the Supabase Auth doc that states where the browser client stores the session; and confirm whether Lovable hosting lets users set response headers --> If Lovable hosting cannot set headers, say so and point to a custom-domain proxy (Cloudflare etc.) only if verified.
4. :66. Replace with `"Paste your lovable.app or custom domain above. The free website scan checks TLS, security headers, cookies, 43 known sensitive paths and public source maps. Lovable apps render in the browser, so the crawler usually sees only the pages linked in the first HTML response, often just the home page."`
5. :67. Change `"private repos connect through a read-only GitHub App."` to `"private repos connect through a read-only GitHub App on Starter or Pro."`
6. :68. Replace with `"Every repo finding comes with a fix prompt you can paste into the Lovable chat, so the fix is made in the same project and syncs back to GitHub. On the free website scan, your one free fix includes a prompt; paid plans add prompts for every website finding."`
7. :69. Append `" A free account gets one rescan of the same site within 7 days; after that, rescans use plan credits."`
8. :74. Replace `"Lovable runs a Quick scan of database rules and dependencies when you open the publish dialog, and a Deep scan of your code that you start yourself from the Security view."` with `"Lovable's Quick scan checks database access rules, npm dependencies and MCP servers every time you publish, and it flags tables without per-record access control. The Deep scan adds a code review and runs when you start it (from the Security view, the publish dialog or chat)."`
9. :75. Replace with `"If you use Lovable's built-in backend, open More, then Database, and review the policies on each table. If you connected your own Supabase project, check the same in the Supabase dashboard. In code, every create table in drizzle/migrations (newer Lovable projects) or supabase/migrations (older ones) should have a matching enable row level security statement. The ScanMySaaS repo scan flags tables created in SQL migrations without one. Then test with two accounts: user A must not be able to read or change user B's rows."` <!-- NEEDS SPECIFIC: confirm the repo RLS check fires on a current Lovable Cloud repo (github-scanner.ts:408 requires a supabase-js / supabase.co reference) -->
10. :76. Change `"Supabase is retiring the legacy anon and service_role keys by the end of 2026"` to `"Supabase is deprecating the legacy anon and service_role keys by the end of 2026"`.
11. :77. Change `"Yes. Sign in, install the ScanMySaaS GitHub App"` to `"Yes, on Starter or Pro. Sign in, install the ScanMySaaS GitHub App"`.
12. :121. Change H1 to `"Lovable security scan for your live app and its GitHub repo"`.
13. :13. Meta → `"Free Lovable security scan for your live app and its GitHub repo: Supabase tables without RLS, leaked secret keys, missing headers and public source maps."` (154 chars).
14. :182. Replace `"It takes under a minute and needs no account."` with `"It needs no account."` (unless timing data exists).
15. :173 links column. Add `<Link href="/free-website-vulnerability-scanner">Free website vulnerability scanner</Link>`.
16. Add FAQ `"Does this work with Lovable Cloud?"` → `"Yes. The website scan works on any published Lovable URL, and the repo scan reads the GitHub repository Lovable syncs to, including SQL migrations under drizzle/migrations or supabase/migrations."` Use this only after verifying point 9's NEEDS SPECIFIC.

---

## Cross-page issues

- **Cannibalization:** "website vulnerability scanner" is targeted by the homepage (2 H2s, 2 FAQs, JSON-LD subcategory), the free page, and the pricing FAQ. "vibe coding security" is targeted by /vibe-coding-security and /guides/vibe-coding-security-checklist. Both fixes are in the edits above.
- **Duplicate H1 tails:** vibe ("before users find the gaps") and Lovable ("before your users find the gaps").
- **The same overpromise on 4 pages:** the repo scan "finds missing ownership/authorization checks" on homepage FAQ (site-content.ts:10), free page (:38, :85), vibe meta (:23). It is paid AI only.
- **Fix-prompt overpromise:** free page (:31) and Lovable (:68).
- **Unverifiable timings:** "well under a minute" (free :36), "usually within a minute" (site-content.ts:84), "under a minute" (Lovable :182). Pull median durations from production or remove them.
- **Original data gap:** competitors win Lovable/vibe SERPs with "we scanned N apps" posts. ScanMySaaS has the scan data in its DB (Scan, Vulnerability, RepoScan tables). An aggregate, anonymized stats page is the biggest content opportunity, but it needs real numbers. <!-- NEEDS SPECIFIC -->
- **API copy bug (not on audited pages):** "unlimited scans" (scan-access.ts:51, 73) contradicts credit metering.

## Recommended order of pages to fix

1. **/free-website-vulnerability-scanner (9)**. Biggest keyword, two wrong claims (non-GET requests, fix prompts), thin. Add the "does not test" and OWASP sections.
2. **Homepage (8)**. Remove "open redirects" and "15 categories", fix the ownership and saved-history claims, de-cannibalize the H2s and FAQs, reorder the guide strip.
3. **/lovable-security-scanner (8)**. Out-of-date RLS exposure claim after Supabase's Oct 30, 2026 change, Lovable Cloud and drizzle paths, SPA crawl and fix-prompt promises. It is live and indexed now, so fix it soon. Run one test scan on a real Lovable Cloud repo first (NEEDS SPECIFIC in item 9).
4. **/repo-scan (7)**. Meta "free ... private" fix, dependency-coverage accuracy, limits section.
5. **/pricing (6)**. H1 keyword, Pro list cleanup, "10 website scans", repo-credits FAQ, Offer schema.
6. **/vibe-coding-security (5)**. OWASP link, research numbers, meta overpromise, dateModified, H1.
7. **/guides (3)**. H1/title keyword, grouping, repo and Lovable CTAs.
