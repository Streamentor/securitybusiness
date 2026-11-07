# ScanMySaaS guides audit (2026-11-07)

Scope: all 10 guides in `src/lib/guides.ts` plus the template `src/app/guides/[slug]/page.tsx`. Product claims checked against `src/lib/scanner.ts`, `src/lib/github-scanner.ts`, `src/lib/secret-patterns.ts`, `src/lib/scan-access.ts`, `src/lib/stripe.ts`, `src/lib/ai-review.ts`, `public/llms.txt`, `src/app/repo-scan/*`. External claims checked against primary sources fetched today. No repo files were edited.

Legend: CORRECT / WRONG / OUTDATED (as of Nov 2026) / PARTIAL (true but misleading or incomplete) / UNVERIFIABLE.

## 0. Summary ranking (priority 10 = fix first)

| Rank | Guide | Priority | Main reason |
|---|---|---|---|
| 1 | supabase-security-for-vibe-coded-apps | 9 | Misses the Supabase Data API grant change that applied to all existing projects on 2026-10-30; one test bullet is now wrong; outdated getUser advice; terminology in description |
| 2 | ssl-tls-checklist-for-saas | 8 | Nothing on 2026 certificate lifetime cuts (200 days since 2026-03-15), Let's Encrypt expiry emails ended, 45-day LE certs; redirect advice conflicts with HSTS preload rule; thin, no sources/dates |
| 3 | vibe-coding-security-checklist | 8 | New money page; product overclaims (Git history, CSP "the way browsers enforce it"); Stripe success-page bullet contradicts Stripe docs; no links to the deeper guides it references |
| 4 | robots-txt-and-sitemap-for-saas | 7 | One invented Search Console warning; sitemap priority advice Google ignores; seoTitle promises "Blocked by robots.txt" but only one of the three reports is covered |
| 5 | security-headers-for-saas | 7 | Thin (about 400 words, labelled 8 min); description promises Referrer-Policy and Permissions-Policy, body has neither; no sources/dates/snippets; HSTS advice contradicts the scanner's own remedy |
| 6 | Template (page.tsx) | 7 | Affects every guide: outdated "public GitHub repository" CTA, "Primary source" singular, related guides are always the first two, no body links possible, inflated read times |
| 7 | github-actions-security-for-vibe-coded-apps | 6 | Missing the 2025-12-08 pull_request_target change, Aug 2025 SHA-pinning policy, Oct 2026 workflow lockfiles; "verified artifact" wording vs GitHub's "treat artifacts as untrusted" |
| 8 | github-secret-scanning-for-vibe-coded-apps | 6 | Correct but generic; misses push-protection defaults, Secret Protection for private repos, git-filter-repo and GitHub Support steps; weak OWASP PDF source; no dates |
| 9 | saas-launch-security-checklist | 5 | Strongest guide. Outdated private-repo sentence; add Supabase grant step; Stripe source URL variant changed; cannibalizes vibe checklist via seoTitle |
| 10 | exposed-files-and-source-maps | 5 | Accurate but thin; no snippets/test commands; implies broader env-file coverage than the scanner has |
| 11 | llms-txt-for-saas | 4 | Mostly correct; "plain-text" vs Markdown spec; llms-full.txt is not in the llmstxt.org spec; scanner claim about link reachability is not what ScanMySaaS does |

---

## T. Template: `src/app/guides/[slug]/page.tsx` (priority 7)

### Fact / product check

| Claim (quote) | Verdict | Correct fact / evidence |
|---|---|---|
| Repo CTA box: "ScanMySaaS reads a bounded set of security-relevant files from a public GitHub repository." (page.tsx:77) | OUTDATED | Private repos are supported on Starter and Pro through a read-only GitHub App: `github-scanner.ts:490` (private requires access token), `public/llms.txt` ("Private GitHub repositories can be connected on Starter and Pro through a read-only GitHub App"), `src/app/repo-scan/layout.tsx:8` ("Scan public or private repos (read-only)"). |
| "It never runs repository code or reveals matched secret values." (page.tsx:77) | CORRECT | No execution path in `github-scanner.ts`; values redacted via `secret-patterns.ts:30-38`; descriptions never include values (`github-scanner.ts:316`). |
| Website CTA: "checks the public surface and keeps the affected URL with every finding" | CORRECT | Every `VulnerabilityResult` carries `url` (`scanner.ts`). |
| "Primary source" heading (page.tsx:76) | Copy bug | Rendered for lists of 2 to 8 sources. Should be plural. |
| Read times (`readTime`) | WRONG (inflated) | Approximate body word counts: security-headers 398 words "8 min", ssl-tls 368 "7 min", llms 359 "6 min", exposed-files 369 "8 min", github-secret 434 "8 min", github-actions 414 "9 min", supabase 930 "12 min", vibe checklist 1139 "11 min". At about 230 wpm these are 2 to 5 minutes. Inflated read times are a trust tell. |
| Default dates: `guide.publishedAt \|\| "2026-08-13"` and `guide.updatedAt \|\| "2026-08-13"` (page.tsx:23, 37, 58) | PARTIAL | Six guides have no dates and all show "Updated August 13, 2026" even though content is older or unchanged. Fine if true, but any edit below must also set `updatedAt`. |
| `related = guides.filter(...).slice(0, 2)` (page.tsx:31) | SEO issue | Every guide links to the same two guides (saas-launch and security-headers). The vibe checklist, Supabase, robots, llms guides never appear as "Keep reading" on any other guide. |
| Sections are plain strings | SEO issue | Body cannot contain links. The vibe checklist says "The Supabase security checklist covers each step." with no link. |

### Exact edit instructions (template)

1. page.tsx:77, change repo CTA copy from `"ScanMySaaS reads a bounded set of security-relevant files from a public GitHub repository. It never runs repository code or reveals matched secret values."` to `"ScanMySaaS reads a bounded set of security-relevant files from a public repository, or a private one on Starter and Pro through a read-only GitHub App. It never runs repository code or reveals matched secret values."` (Source: `public/llms.txt`, `github-scanner.ts:490`.)
2. page.tsx:76, change `Primary source` to `{guide.sources.length > 1 ? "Sources" : "Source"}`.
3. Add an optional `related?: string[]` (slugs) field to `Guide` in guides.ts and in page.tsx use `const related = (guide.related?.map(getGuide).filter(Boolean) ?? guides.filter((item) => item.slug !== guide.slug).slice(0, 2))`. Suggested `related` values are listed in each guide's SEO notes below.
4. Add an optional `links?: Array<{ label: string; href: string }>` to `GuideSection` and render it under the bullets as a small "Related" line with `<Link>`. This is the only way to place contextual internal links (product pages and guides) without converting the content to MDX. Each guide's edits below say which links to add.
5. Correct `readTime` on every guide to `Math.max(2, Math.round(words / 230))` minutes after the content edits, or compute it at render time from the text instead of storing it.
6. When you implement the edits below, set `updatedAt: "2026-11-07"` (or the deploy date) on each guide whose content actually changes, and add `publishedAt` for the six undated guides only if you know the real first publish date. Do not invent one; if unknown, keep the fallback.

---

## 1. supabase-security-for-vibe-coded-apps (priority 9)

Target query: "supabase security checklist", "supabase rls checklist". Top results (search 2026-11-07): dev.to "Supabase RLS checklist for AI-built Next.js apps", bastion.tech "Supabase Security Best Practices for Production Apps", unicoconnect "The Supabase RLS Security Checklist for 2026", vibe-eval.com "Supabase security checklist". Current seoTitle "Supabase Security: RLS, API Keys & Storage Checklist (2026)" fits.

### Fact check

| Claim (quote) | Verdict | Correct fact and source |
|---|---|---|
| "Supabase says Row Level Security must be enabled on tables in an exposed schema such as public." | CORRECT | RLS docs: "Enable RLS on every table in an exposed schema." https://supabase.com/docs/guides/database/postgres/row-level-security |
| "Tables created in the dashboard receive RLS by default, but raw SQL migrations need an explicit ALTER TABLE statement." | CORRECT (not on the cited RLS page) | Dashboard default reported here: https://www.createwith.com/tool/supabase/updates/supabase-enables-rls-by-default-for-dashboard-created-tables . The RLS page now also points to event triggers "To enable RLS automatically on every new table". |
| Whole guide: no mention of table GRANTs | OUTDATED (major) | Supabase changelog: "New tables in the public schema will no longer be exposed to the Data API automatically." Default for new projects from 2026-05-30; "On October 30, 2026 the setting will be applied it to all existing projects." Without `grant`, PostgREST returns code 42501 "permission denied for table". Migrations must now include grants plus RLS. https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically |
| Bullet: "Anonymous request to a private table: returns no rows, not an error you ignore." | WRONG since 2026-10-30 | A table with no `anon` grant now returns HTTP error 42501. That error is a correct denial. Pass = no rows or 42501, Fail = rows returned. Same changelog. |
| "Supabase publishable keys (sb_publishable_…) and legacy anon keys are intended for public clients when RLS is correct. Secret keys (sb_secret_…) and legacy service-role keys bypass RLS" | CORRECT | https://supabase.com/docs/guides/getting-started/api-keys ("Publishable keys ... low privileges", secret keys "bypass Row Level Security"). Nuance worth adding: RLS docs say "A secret key bypasses RLS only when the request carries no user access token." Also "A secret key doesn't work in a browser" (Supabase returns 401 by User-Agent). |
| "Supabase is retiring the legacy anon and service_role keys by the end of 2026." | CORRECT (wording) | API keys page: "Supabase is deprecating the anon and service_role keys by the end of 2026." No exact removal date published. Use "deprecating". |
| "Create the new publishable and secret keys, deploy them, then disable the legacy keys in Settings > API Keys." | CORRECT | Migration guide steps 1 to 7; legacy keys "stay valid until you disable them in the Settings > API Keys section". Deactivation is reversible. https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys |
| "If a service-role key was ever committed, treat the switch as a rotation." | PARTIAL | Creating new keys does not disable legacy ones (same page). It is a rotation only after the legacy key is disabled. Say so. |
| "Read the user from supabase.auth.getUser() with the request's token" | OUTDATED | supabase-js reference: getClaims "Prefer this method over GoTrueClient.getUser which always sends a request to the Auth server for each JWT." Verifies locally with asymmetric signing keys. https://supabase.com/docs/reference/javascript/auth-getclaims . getUser is still valid when you need a live user lookup. |
| Edge functions guidance (no mention of verify_jwt or new key env vars) | OUTDATED / incomplete | Migration guide: new env vars `SUPABASE_PUBLISHABLE_KEYS` and `SUPABASE_SECRET_KEYS` (JSON keyed by name); send keys only in the `apikey` header; for functions receiving these keys "set verify_jwt = false and authorize the request in your own code". |
| "Storage objects are rows in storage.objects and follow the same RLS model." | CORRECT | https://supabase.com/docs/guides/storage/security/access-control |
| "A public bucket serves every file to anyone with the URL." | CORRECT | Same page (public buckets "already publicly accessible"). Uploads still need INSERT policy. Advisor lint 0025 "public bucket allows listing" exists. |
| "for example a folder named after auth.uid()" | CORRECT in substance | Supabase example uses `(storage.foldername(name))[1] = (select auth.jwt()->>'sub')`. Give the exact snippet. |
| "Functions declared SECURITY DEFINER run with the privileges of their owner and can bypass RLS." | CORRECT | RLS page: "A security definer function in an exposed schema is callable over the Data API with the creator's privileges." |
| "set a fixed search_path" | CORRECT, be specific | RLS page: "Set search_path = '' on every security definer function and schema-qualify the names inside it." |
| "Create views with security_invoker = true so the caller's RLS applies." | CORRECT, add version | "In Postgres 15 and above"; views "bypass RLS by default because they are usually created with the postgres user." |
| "Revoke execute on sensitive functions from anon" | PARTIAL | Advisor lints 0028/0029 flag security definer functions executable by anon and authenticated. Postgres grants EXECUTE to PUBLIC by default, so revoke from `public` too (standard Postgres behavior). |
| "Run Supabase's Security Advisor" | CORRECT | Lints include 0013 rls disabled in public, 0008 rls enabled no policy, 0010 security definer view, 0011 function search path mutable, 0024 permissive rls policy. Source URL in guide redirects: `/docs/guides/database/database-advisors` now 301s to https://supabase.com/docs/guides/observability/advisors |
| "Test as anon, as a signed-in user, as another tenant, and with no session." | PARTIAL | "anon" and "no session" are the same test with the publishable key. Replace with publishable key only / user A / user B / member vs admin. |
| "the first two items cause most real data leaks" | UNVERIFIABLE | No source. Remove or attribute. |
| Product: "scan the repository so new migrations are checked" / "Repository scan shows no tables created without RLS and no secret keys in client code." | PARTIAL | `github-scanner.ts:407-423` flags `create table` without a matching `enable row level security` in scanned SQL. It does not check GRANTs, policies, views or functions, and reads at most 60 files (`github-scanner.ts:11`). Secret detection: `sb_secret_` (`secret-patterns.ts:10`), service_role JWT (`github-scanner.ts:303`), public-prefix names (`github-scanner.ts:306`). Accurate if "bounded" is stated. |
| Description: "anon vs service-role keys" | OUTDATED terminology | Use "publishable vs secret keys (and legacy anon/service_role)". |
| Sources resolve | 3 of 4 OK | database-advisors redirects (see above). secure-data page exists (updated 2026-09-03) and supports "publishable key is safe to expose with RLS enabled". |

### AI-writing tells
- Tailing negations: "Check migrations, not only the current dashboard state."; "not from a field the browser sends"; "returns no rows, not an error you ignore."
- Restated takeaway (S1): "The denied case is the test that matters."; "The service key will not repair a missing authorization check."
- Aphorism/significance: "The safety of that design depends on Row Level Security and the difference between..."
- Uniform scaffolding: 7 sections, each 1 paragraph + 3 or 4 bullets.
- Unsupported stat-like claim: "the first two items cause most real data leaks".
- No em dashes. Good.

### SEO notes
- H1 "Supabase security checklist for vibe-coded apps" is fine. Competitors (unicoconnect, vibe-eval, bastion) all include SQL snippets and policy examples. This guide has none. Add them (below); that is the biggest ranking gap.
- The new grants change is fresh (2026-10-30) and dev.to already ranks posts on it ("Supabase Data API exposure changes on 30 October: grant tables explicitly"). Adding an H2 on it is a timely ranking opportunity.
- Internal links to add: /repo-scan (scan migrations), /lovable-security-scanner (Lovable uses Supabase), /vibe-coding-security, guides saas-launch-security-checklist (section 3) and github-secret-scanning-for-vibe-coded-apps (rotation). Set `related: ["vibe-coding-security-checklist", "github-secret-scanning-for-vibe-coded-apps"]`.
- Cannibalization: overlaps saas-launch section 3 and vibe checklist section 4. Make this the canonical Supabase page; the other two should link here.

### Exact edit instructions
1. `description`: replace `"Row Level Security, anon vs service-role keys, tenant-aware policies, storage buckets, edge functions and how to test each one."` with `"Row Level Security, table grants, publishable vs secret keys, tenant-aware policies, storage buckets, edge functions and how to test each one."`
2. intro[1]: delete `" in the order below: the first two items cause most real data leaks"` and end the sentence after `"on a project you own"`. Then add `", in the order below."` (Unsourced claim.)
3. Insert a new section after "Enable RLS on every exposed table", heading `"Grant table access explicitly (required since October 30, 2026)"`, paragraphs:
   - `"Supabase changed how new tables reach the Data API. New tables in the public schema are no longer exposed automatically: this became the default for new projects on May 30, 2026 and was applied to all existing projects on October 30, 2026. Existing tables keep their current grants. A new table without a GRANT returns error 42501, permission denied for table."`
   - `"Put the grant, the RLS statement and the policies in the same migration, and grant only what each role needs. A table that only signed-in users read should not get a grant to anon."`
   - bullet (code text): `"grant select on public.your_table to anon; (only for public data)"`, `"grant select, insert, update, delete on public.your_table to authenticated;"`, `"alter table public.your_table enable row level security;"`, `"Then create one policy per operation that needs it."`
   - Source to add: `{ label: "Supabase changelog: tables not exposed to the Data API automatically", url: "https://supabase.com/changelog/45329-breaking-change-tables-not-exposed-to-data-and-graphql-api-automatically" }`
4. Section "Enable RLS on every exposed table", bullet 3: replace `"Test as anon, as a signed-in user, as another tenant, and with no session."` with `"Test with only the publishable key (no session), as user A, as user B in another tenant, and as a member against admin-only rows."`
5. Same section, paragraph: append `"To catch tables that an AI tool creates in raw SQL, Supabase documents event triggers that enable RLS automatically on new tables."` (Source: RLS page.)
6. Section "A policy must match the tenant model": add a code-style bullet list with the Supabase-documented performance pattern: `"Wrap auth.uid() as (select auth.uid()) in policies so Postgres evaluates it once per statement."` and an UPDATE note: `"UPDATE needs a matching SELECT policy, and the WITH CHECK clause decides what the updated row may look like, so a user cannot move a row to another tenant."` (Source: RLS page.) Delete the sentence `"The denied case is the test that matters."` and fold it into the previous sentence: `"Write tests that create two tenants and attempt every read and write across the boundary; the denied cases are the ones to keep in CI."`
7. Section "Keep privileged keys on the server", paragraph 2: replace `"Supabase is retiring the legacy anon and service_role keys by the end of 2026. Create the new publishable and secret keys, deploy them, then disable the legacy keys in Settings > API Keys. If a service-role key was ever committed, treat the switch as a rotation."` with `"Supabase is deprecating the legacy anon and service_role keys by the end of 2026. Creating publishable and secret keys does not disable the legacy ones: they stay valid until you turn them off in Settings > API Keys. Replace the anon key in client code, the service_role key in backend code, Database Webhooks and CI, confirm nothing still uses the legacy keys, then deactivate them. If a service_role key was ever committed, the leak is only closed once the legacy key is deactivated."` Add after: `"Supabase rejects a secret key sent from a browser with 401, but a leaked secret key still works from any other tool, so rotate it."` (Source: api-keys and migration pages.)
8. Section "Review server routes and edge functions too", bullet 1: replace `"Read the user from supabase.auth.getUser() with the request's token, not from a field the browser sends."` with `"Verify the request's access token on the server with supabase.auth.getClaims() (verified locally when the project uses asymmetric JWT signing keys) or getUser(), and take the user ID from the verified claims, never from the request body."` Add a bullet: `"For Edge Functions called with the new API keys, read them from SUPABASE_SECRET_KEYS or SUPABASE_PUBLISHABLE_KEYS, send them only in the apikey header, set verify_jwt = false and authorize the request in your own code."` (Sources: getClaims reference, migration guide.)
9. Section "Lock down storage buckets": replace `"for example a folder named after auth.uid()."` with `"for example a policy on storage.objects with bucket_id = 'documents' and (storage.foldername(name))[1] = (select auth.jwt()->>'sub'), so each user can only write inside a folder named after their user ID."`
10. Section "Check database functions and views", bullets: replace `"Prefer SECURITY INVOKER functions; when DEFINER is required, set a fixed search_path and check auth.uid() inside."` with `"Prefer SECURITY INVOKER functions. When DEFINER is required, set search_path = '' and schema-qualify every name, and check auth.uid() inside."`; replace `"Create views with security_invoker = true so the caller's RLS applies."` with `"On Postgres 15 and later, create views with security_invoker = true so the caller's RLS applies; otherwise keep the view out of exposed schemas."`; replace `"Revoke execute on sensitive functions from anon when they are not meant to be public."` with `"Revoke execute on sensitive functions from public, anon and authenticated when they are not meant to be called over the Data API."`
11. Section "Test it like an attacker would", paragraph: replace `"The anon key and project URL are in your JavaScript"` with `"The publishable (or legacy anon) key and project URL are in your JavaScript"`. Add a test command paragraph: `"From a terminal: curl 'https://YOUR_PROJECT.supabase.co/rest/v1/YOUR_TABLE?select=*' -H 'apikey: YOUR_PUBLISHABLE_KEY'. For a private table the result must be an empty array or a 42501 permission error. Repeat with a user's access token in an Authorization: Bearer header to test user A against user B's rows."` Bullet 1: replace with `"Publishable-key request to a private table: an empty array or a 42501 permission error, never rows."` Bullet 4: replace `"Repository scan shows no tables created without RLS and no secret keys in client code."` with `"Repository scan shows no migration that creates a table without enabling RLS and no Supabase secret or service_role key committed. The scan reads a bounded set of files and does not judge policy logic or grants."` (Code: `github-scanner.ts:11, 407-423`.)
12. sources: change `https://supabase.com/docs/guides/database/database-advisors` to `https://supabase.com/docs/guides/observability/advisors`; add `{ label: "Supabase: Migrating to publishable and secret API keys", url: "https://supabase.com/docs/guides/getting-started/migrating-to-new-api-keys" }` and the changelog link from step 3.
13. Set `related: ["vibe-coding-security-checklist", "github-secret-scanning-for-vibe-coded-apps"]` and section links to `/repo-scan` and `/lovable-security-scanner`.

---

## 2. ssl-tls-checklist-for-saas (priority 8)

Target query: "ssl tls checklist", "ssl certificate checklist saas", "https redirect hsts checklist". Result pages are mostly vendor checklists (SSL Labs-style). This guide has no seoTitle-matching depth and no sources.

### Fact check

| Claim (quote) | Verdict | Correct fact and source |
|---|---|---|
| "If your platform renews certificates automatically, alerting still matters." | CORRECT, under-explained | Let's Encrypt ended expiration notification emails in 2025: https://letsencrypt.org/2025/06/26/expiration-notification-service-has-ended . LE says "Set up monitoring to alert you if a renewal doesn't happen when expected." https://letsencrypt.org/2025/12/02/from-90-to-45 |
| No mention of certificate lifetime changes | OUTDATED (major) | CA/B Forum SC-081v3: max validity 200 days for certs issued on or after 2026-03-15, 100 days from 2027-03-15, 47 days from 2029-03-15; SAN validation reuse falls to 10 days. https://cabforum.org/2025/04/11/ballot-sc081v3-introduce-schedule-of-reducing-validity-and-data-reuse-periods/ and schedule: https://sectigostore.com/blog/47-day-ssl-certificate-validity/ |
| No mention of Let's Encrypt changes | OUTDATED | LE: opt-in `tlsserver` profile 45-day certs from 2026-05-13; default `classic` profile 64 days from 2027-02-10; 45 days from 2028-02-16; "renewing at a hardcoded interval of 60 days will no longer be sufficient"; recommends ARI. https://letsencrypt.org/2025/12/02/from-90-to-45 |
| "An HTTP request should move straight to the final HTTPS hostname. Avoid a chain that first adds www, then adds HTTPS" | PARTIAL / conflicts | hstspreload.org requirement: "Redirect from HTTP to HTTPS on the same host, if you are listening on port 80." For apex domains that will be preloaded, http://example.com must go to https://example.com first, then to www. https://hstspreload.org/ |
| "Check the production hostname with Server Name Indication, confirm the certificate chain is trusted" | CORRECT | Scanner does exactly this: TLS socket with servername, `authorized` check (`scanner.ts:356-433`). |
| "Many SaaS apps terminate TLS at a CDN... trust forwarded protocol headers only from known proxies" | CORRECT | General practice; scanner remedy also mentions X-Forwarded-Proto (`scanner.ts:347`). |
| "Set session cookies with Secure, HttpOnly, and an intentional SameSite policy." | CORRECT | OWASP Session Management cheat sheet. |
| "Search rendered HTML and CSS for http:// assets or form actions." | CORRECT | Scanner checks img/script/link/iframe http: (`scanner.ts:715-716`) and http form actions (`scanner.ts:756`). It does not parse CSS files. |
| "Confirm webhooks and API callbacks use current TLS endpoints." | VAGUE | Concrete fact available: Stripe webhooks "support only TLS versions v1.2 and v1.3". https://docs.stripe.com/webhooks |
| "A short first max-age makes mistakes recoverable." | CORRECT | MDN: max-age=0 disables; browsers ignore HSTS over HTTP. https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security . Note scanner reports "HSTS max-age Too Short" (low) below 15768000 s (`scanner.ts:493`), so a staged rollout will show that finding. |
| No mention of TLS protocol versions | Gap | Vercel supports TLS 1.2 and 1.3 only and redirects HTTP with 308: https://vercel.com/docs/cdn-security/encryption . ScanMySaaS does not check protocol versions (no such check in scanner.ts). |
| Product: expiry monitoring | Product note | Scanner warns at `daysRemaining <= 30` (`scanner.ts:412`). A healthy 90-day LE cert renewed at two thirds of life sits near 30 days; 64-day (2027) and 45-day (2028) certs will routinely be under 30 days. Consider scaling the threshold to a fraction of lifetime (valid_from to valid_to). Not a guide edit. |
| "Treat TLS as a path... Every hop matters." | style | See tells. |
| Dates / sources | Missing | No publishedAt, updatedAt or sources. |

### AI-writing tells
- "not X, it's Y" opener: "A valid padlock is the beginning of transport security, not the end."
- Staccato close: "Every hop matters."
- Tailing negation: "Redirects are a fallback, not a substitute for correct links."
- Uniform shape: 4 sections, 2 bullet lists of exactly 4.
- Low specificity (S4): no named tool, command, date, or provider.

### SEO notes
- No seoTitle. Title "SSL and TLS checklist for a production SaaS" is fine; add seoTitle `"SSL/TLS Checklist for SaaS (2026): Certificate Expiry, Redirects, HSTS"` and mention "200-day certificates" since it is a 2026 query trend.
- Thin (368 words). Competitors cover: protocol versions, certificate monitoring, CAA, mixed content, testing tools. Add a test-commands section.
- HSTS is covered in both this guide and security-headers. Keep the rollout details in security-headers and link from here.
- Links: /free-website-vulnerability-scanner, guide security-headers-for-saas. `related: ["security-headers-for-saas", "exposed-files-and-source-maps"]`.

### Exact edit instructions
1. Add `seoTitle: "SSL/TLS Checklist for SaaS (2026): Certificates, Redirects & HSTS"`, `updatedAt` on deploy.
2. intro[0]: replace `"A valid padlock is the beginning of transport security, not the end."` with `"A valid padlock only tells you the certificate checked out for that one request."` intro[1]: delete `"Every hop matters."`
3. Insert new first section, heading `"Plan for shorter certificate lifetimes"`, paragraph: `"Public TLS certificates are getting shorter. Under CA/Browser Forum ballot SC-081v3, certificates issued from March 15, 2026 can be valid for at most 200 days, from March 15, 2027 at most 100 days, and from March 15, 2029 at most 47 days. Let's Encrypt plans to move its default certificates from 90 days to 64 days on February 10, 2027 and to 45 days on February 16, 2028, and says a hardcoded 60-day renewal interval will no longer be enough. Renewal has to be automated, ideally with ACME Renewal Information (ARI)."` Second paragraph: `"Let's Encrypt stopped sending expiration reminder emails in 2025, so do not rely on an inbox to warn you. Monitor the certificate your public hostname actually serves."` Sources: the three URLs above.
4. Section "Verify the certificate as a customer sees it": add bullet `"Check it from a terminal: openssl s_client -connect example.com:443 -servername example.com </dev/null 2>/dev/null | openssl x509 -noout -subject -issuer -dates"` and bullet `"Serve TLS 1.2 and 1.3 only. Vercel, for example, supports exactly these two versions; Stripe webhooks also require TLS 1.2 or later."` (Sources: Vercel encryption doc, Stripe webhooks doc.)
5. Section "Make the first redirect secure and direct", paragraph 1: replace `"An HTTP request should move straight to the final HTTPS hostname. Avoid a chain that first adds www, then adds HTTPS, then changes a trailing slash. Each extra hop is slower and creates another configuration surface."` with `"Keep the redirect chain short: no more than one hop per change of scheme or hostname. If you plan to submit the domain to the HSTS preload list, the preload rules require http://example.com to redirect to https://example.com on the same host first; only then redirect to www. Avoid extra hops for trailing slashes or tracking parameters."` Add `"Test it with curl -sIL http://example.com and read each Location header. Most platforms (Vercel uses a 308) redirect HTTP to HTTPS for you."` Paragraph 2: replace `"Redirects are a fallback, not a substitute for correct links."` with `"Redirects only catch the links you missed."` Sources: hstspreload.org, Vercel doc.
6. Section "Check the layers behind the proxy", bullet 3: replace `"Confirm webhooks and API callbacks use current TLS endpoints."` with `"Confirm webhook and callback endpoints accept TLS 1.2 or later with a publicly trusted certificate; Stripe, for example, will not deliver to anything else."`
7. Section "Add HSTS after the route is clean": append `"ScanMySaaS reports HSTS below about six months (15768000 seconds) as a low finding, which is expected during a staged rollout. See the security headers guide for the full sequence."` (Code: `scanner.ts:493`.) Add a link to /guides/security-headers-for-saas.
8. Add `sources`: SC-081v3 ballot URL, Let's Encrypt 45-day post, LE expiration emails ended post, MDN HSTS, hstspreload.org.

---

## 3. vibe-coding-security-checklist (priority 8)

Target query: "vibe coding security checklist". Top results: Replit docs "Vibe code security checklist", Astra "Vibe Coding Security Checklist: Stress-Test Your AI-Built App in 10 Minutes", Cleveroad "Vibe Coding Security Check: How to Audit an AI-Built App Before Deployment", Fingerprint (Nov 2025), bsscommerce, GitHub boxed-dev. Title "47 checks" is accurate (I counted 47 bullets: 5+5+4+5+4+6+4+3+3+4+4).

### Fact / product check

| Claim (quote) | Verdict | Evidence |
|---|---|---|
| "Automated: the GitHub repo scan flags committed .env files, Supabase secret and service-role keys, Stripe, OpenAI, AWS and GitHub tokens, private keys, hardcoded secrets and secret-looking public variables, without showing the value." | CORRECT | `secret-patterns.ts:4-14` (private key, AKIA, gh*_, sk_live_, sb_secret_, sk-proj/svcacct/admin, github_pat_, rk_live/whsec, DB URLs), `github-scanner.ts:303` (service_role JWT), `:306` (public prefixes), `:316` (hardcoded secret), `:398-399` (.env). Note: Stripe test keys (sk_test_) and legacy OpenAI `sk-` keys without a prefix are not flagged as findings. |
| Bullet under that sentence: "No .env file, private key or database URL is committed, including in Git history." | PARTIAL (product overclaim by placement) | The repo scan reads one commit's tree only (`github-scanner.ts:495-500`); `public/llms.txt`: "The scanner does not search full Git history." Mark history as manual. |
| "Supabase secret (service-role), Stripe secret and OpenAI keys are only read in server code." | PARTIAL | Secret key and service_role key are different keys (new vs legacy). https://supabase.com/docs/guides/getting-started/api-keys |
| ".gitignore covers .env* and GitHub push protection is on." | CORRECT | Scanner checks .gitignore (`github-scanner.ts:429-433`). Push protection for users is on by default and on by default for public repos: https://docs.github.com/en/code-security/getting-started/github-security-features |
| "Logging out invalidates the session on the server, not only in the browser." | PARTIAL | With JWT access tokens (Supabase), sign-out revokes the refresh token but an issued access token stays valid until it expires. OWASP Session Management supports server-side invalidation for session IDs. Phrase as "revokes the refresh token/session and access tokens are short-lived". |
| "On paid plans, the AI logic review reads server routes in the repository and flags handlers that change data without an authorization check." | CORRECT | `ai-review.ts`: `canReviewWithAI` = starter, pro or admin; instructions target "missing owner/tenant checks, UI-only paid access, missing admin roles or webhook signatures..." Reviews a bounded, risk-ranked subset (two batches). |
| "Automated: the repo scan flags Supabase tables created in migrations without Row Level Security." | CORRECT | `github-scanner.ts:407-423`. Does not check the new GRANT requirement. |
| "RLS is enabled on every table in an exposed schema." | CORRECT, incomplete | Add grants (Supabase changelog 45329). |
| "Stripe webhooks verify the signature before doing anything." | CORRECT | https://docs.stripe.com/webhooks (raw body required). |
| "Webhook handlers are idempotent, so a retried event does not grant credits twice." | CORRECT | Stripe: "Webhook endpoints might occasionally receive the same event more than once." |
| "Access is granted after a confirmed payment event, not after a redirect to a success page." | PARTIAL / contradicts Stripe | Stripe recommends webhooks AND also running the same fulfillment on the landing page server-side by retrieving the Checkout Session and checking payment_status: "To optimize your payment flow and guarantee immediate fulfillment when your customer is present, trigger fulfillment from your landing page as well." https://docs.stripe.com/checkout/fulfillment?ui=full-page |
| "CORS allows only your own origins, and never * together with credentials." | PARTIAL | Browsers already refuse `*` with credentials; the real bug is reflecting any Origin with `Access-Control-Allow-Credentials: true`, which the website scan tests (`scanner.ts:519-532`). |
| "Automated: the website scan checks TLS, HTTPS redirects, HSTS and evaluates the Content-Security-Policy the way browsers enforce it." | PARTIAL (overclaim) | CSP evaluation handles multiple policies and nonce/hash/strict-dynamic (`scanner.ts:579-596`), but only the header on the first readable HTML page (`scanner.ts:1449-1457`); `<meta>` CSP is ignored. Say "checks the CSP header on the first page it reads". |
| "Automated: the website scan requests known sensitive paths and confirms exposures by content, not just a 200 status." | CORRECT | `scanner.ts:769-842` (`matchesExpectedSensitiveFile`). |
| "/.env, /.git/config and database dumps return 404." | PARTIAL | 403 is also fine. Scanner probes only `/.env` (not .env.local, .env.production), `/backup.sql`, `/database.sql` (`scanner.ts:797-807`). |
| "Debug endpoints, GraphQL introspection and directory listings are off in production." | CORRECT and automated | `scanner.ts:984-1015` (introspection, /_debug, /_profiler), `scanner.ts:928-944`. The section text does not say these are automated; it could. |
| "Automated: the website scan checks every cookie it sees across crawled pages." | CORRECT with limit | Up to 25 pages (`scanner.ts:1352`), Set-Cookie collected per page (`:1447`). Only unauthenticated pages, so post-login cookies are not seen. |
| "Session cookies are Secure, HttpOnly and SameSite=Lax or Strict." | CORRECT | OWASP Session Management. |
| "Automated: the repo scan flags write-all workflow tokens, unpinned actions, pull_request_target workflows that run untrusted code, and known vulnerable dependencies." | CORRECT | `github-scanner.ts:322-336`, OSV `:522-535`. Also flags missing permissions (`:325`) and agent configs (`repo-security-rules.ts:74-91`), which the "Agent and MCP configuration" bullet could claim as automated. |
| Sources | OK | All four resolve. OWASP Top 10 2025 is the current edition (A01 Broken Access Control). |
| Date publishedAt/updatedAt 2026-11-07 | CORRECT | |

### AI-writing tells
- Tailing negations in 9 bullets: "rotated, not just deleted", "on the server, not only in the browser", "not by hiding a link", "not only in the UI", "not after a redirect to a success page", "by content, not just a 200 status", "never from the request body".
- Restated/aphoristic: "Security is not a one-time pass. A new prompt can undo an old fix."; "Payment code is where a small mistake becomes free usage or double charges."; "Treat every input as hostile".
- Formula "AI coding tools build what you ask for. They rarely add what you did not ask for" (setup/punchline). "The app works, so it looks finished." staccato.
- Uniform structure: 11 sections of one short paragraph plus 3 to 6 bullets; the "Automated:" label repeated 6 times.
- Unsourced superlative: "The most common serious bug in vibe-coded apps is an endpoint that loads a record by ID..." (no source). OWASP lists Broken Access Control as A01, which could support a softer claim.

### SEO notes
- Title and H1 match the query; competitors' titles promise a time ("10 minutes") or audit. Keep "47 checks".
- Missing what competitor pages have: copy-paste test commands, per-tool notes (Lovable, Bolt, Cursor), a downloadable/printable list. Add a short "How to test in 10 minutes" block with curl commands (below).
- Internal links: this is the hub. Link /vibe-coding-security, /lovable-security-scanner, /repo-scan, /free-website-vulnerability-scanner, and guides supabase (section 4), github-secret (section 1), github-actions (section 10), security-headers (section 7), exposed-files (section 8), saas-launch (section 3). Currently zero links.
- Cannibalization: saas-launch seoTitle "(2026, Vibe-Coded Apps)" competes for the same query family; product page /vibe-coding-security also targets "vibe coding security". Make this guide target "checklist", the product page target "scanner/security", and remove "Vibe-Coded Apps" from the saas-launch seoTitle.
- `isRepositoryGuide` is false here, so the CTA goes to the website scanner; half the automated checks are repo checks. Consider showing both CTAs.

### Exact edit instructions
1. Section 1 bullet 1: replace `"No .env file, private key or database URL is committed, including in Git history."` with `"No .env file, private key or database URL is committed. Check Git history yourself (for example with git log --all -- .env); the repo scan reads only the current commit."` (Code: `github-scanner.ts:495-500`; llms.txt.)
2. Section 1 bullet 3: replace `"Supabase secret (service-role), Stripe secret and OpenAI keys are only read in server code."` with `"Supabase secret keys (and the legacy service_role key), Stripe secret keys and OpenAI keys are only read in server code."`
3. Section 2 bullet 4: replace `"Logging out invalidates the session on the server, not only in the browser."` with `"Logging out revokes the server-side session or refresh token, and access tokens are short-lived, so a copied token stops working soon after logout."`
4. Section 3 paragraph: replace `"The most common serious bug in vibe-coded apps is an endpoint that loads a record by ID without checking it belongs to the signed-in user."` with `"Broken access control is the top risk in the OWASP Top 10, and in AI-built apps it usually looks like an endpoint that loads a record by ID without checking it belongs to the signed-in user."` (Source: OWASP Top 10, already cited.)
5. Section 4 bullets: add after bullet 1 `"New tables have explicit GRANTs: since October 30, 2026 Supabase no longer exposes new public tables to the Data API automatically."` (This makes 48 checks; either rename the title to 48 or merge this into bullet 1: `"RLS is enabled and grants are explicit on every table in an exposed schema."` Recommended: merge, keep 47.) Replace paragraph sentence `"The Supabase security checklist covers each step."` with a link (template edit 4) to /guides/supabase-security-for-vibe-coded-apps.
6. Section 5 bullet 4: replace `"Access is granted after a confirmed payment event, not after a redirect to a success page."` with `"Access is granted only when your server confirms payment: from the webhook, or on the success page by retrieving the Checkout Session server-side and checking payment_status. Opening the success URL alone grants nothing."` (Source: Stripe fulfillment doc; add it to sources as `https://docs.stripe.com/checkout/fulfillment?ui=full-page`.)
7. Section 6 bullet 4: replace `"CORS allows only your own origins, and never * together with credentials."` with `"CORS allows only an explicit list of your own origins and never reflects an arbitrary Origin together with Access-Control-Allow-Credentials: true."` Then add to the section paragraph: `"Automated: the website scan sends an unrelated Origin and flags a credentialed reflection."` (Code: `scanner.ts:519-532`.)
8. Section 7 paragraph: replace `"Automated: the website scan checks TLS, HTTPS redirects, HSTS and evaluates the Content-Security-Policy the way browsers enforce it."` with `"Automated: the website scan checks the certificate, the HTTP to HTTPS redirect and HSTS, and evaluates the Content-Security-Policy header on the first page it reads, including nonces, hashes and multiple policies. A CSP set only in a meta tag is not evaluated."` (Code: `scanner.ts:356-433, 1449-1457, 579-596`.)
9. Section 8 bullet 1: replace `"/.env, /.git/config and database dumps return 404."` with `"/.env, /.git/config and database dumps return 404 or 403. Test variants the scanner does not request, such as /.env.local and /.env.production, with curl -s -o /dev/null -w '%{http_code}' https://your-domain/.env.local."` Paragraph: append `"It also probes for GraphQL introspection, common debug endpoints and directory listings."`
10. Section 9 paragraph: replace `"Automated: the website scan checks every cookie it sees across crawled pages."` with `"Automated: the website scan checks every cookie set on the up to 25 public pages it crawls. Cookies set only after login need a manual check in DevTools."`
11. Section 10 bullet 4: append `" The repo scan flags agent instruction files with destructive commands, pipe-to-shell installs or unrestricted shell permissions."` (Code: `repo-security-rules.ts:74-91`.)
12. Section 11: replace `"Security is not a one-time pass. A new prompt can undo an old fix."` with `"A new prompt can undo an old fix."`
13. intro[0]: replace `"The app works, so it looks finished."` with nothing (delete).
14. Add sources: Supabase changelog 45329, Stripe fulfillment, GitHub security features. Set `related: ["supabase-security-for-vibe-coded-apps", "saas-launch-security-checklist"]`.

---

## 4. robots-txt-and-sitemap-for-saas (priority 7)

Target query: the seoTitle targets "blocked by robots.txt" errors. Top results for "sitemap contains urls which are blocked by robots.txt fix": KeyCDN support, dev.to, Linkbot "Submitted URL Blocked by robots.txt (How to Fix It)", Moz forum. Linkbot/KeyCDN titles name the exact Search Console message.

### Fact check

| Claim (quote) | Verdict | Correct fact and source |
|---|---|---|
| "A disallowed path is still public. Anyone can read robots.txt, and a URL may still be indexed from links elsewhere." | CORRECT | Google block-indexing doc: a blocked page "can then still appear in search results, such as when other pages link to it." https://developers.google.com/search/docs/crawling-indexing/block-indexing |
| "Use noindex on a public page when the goal is to keep that page out of search results." / "allow crawling and serve a noindex directive, because a blocked page cannot show its noindex." | CORRECT | Same doc: noindex works only if the page "must not be blocked by a robots.txt file". |
| "Do not block CSS or JavaScript needed to render public pages." | CORRECT | Google robots guidance. |
| "Search Console reports this when a URL listed in your sitemap matches a Disallow rule" ("Sitemap contains URLs which are blocked by robots.txt") | CORRECT | Listed in the Sitemaps report: "Sitemap contains urls which are blocked by robots.txt". https://support.google.com/webmasters/answer/7451001 |
| "A related warning is a sitemap that robots.txt does not reference." | WRONG | No such warning. The Sitemaps report "does not show any sitemaps discovered through a robots.txt reference". Same URL. Referencing the sitemap in robots.txt is optional good practice. |
| "make sure that URL returns 200 on the same host and protocol as your canonical pages." | PARTIAL | Google robots.txt spec: the Sitemap URL "doesn't have to be on the same host as the robots.txt file." https://developers.google.com/search/docs/crawling-indexing/robots/robots_txt . Same-host is a safe default, not a requirement. |
| "(most specific matching rule wins)" | CORRECT, incomplete | "crawlers use the most specific rule based on the length of the rule path. In case of conflicting rules... Google uses the least restrictive rule." Same URL. |
| "Login may be crawlable but rarely needs high sitemap priority." | WRONG premise | "Google ignores <priority> and <changefreq> values." https://developers.google.com/search/docs/crawling-indexing/sitemaps/build-sitemap |
| "Include canonical, indexable URLs that return a successful response." | CORRECT | Build-sitemap doc. Missing: lastmod must reflect real significant updates; 50,000 URLs / 50 MB limits. |
| "Keep production robots.txt available at the root hostname." | CORRECT | Add: 4xx (except 429) = no restrictions; 5xx can stop crawling for 12 hours; 500 KiB limit. Same robots doc. |
| Missing: "Indexed, though blocked by robots.txt" and "Blocked by robots.txt" in the Page indexing report | Gap | seoTitle promises "Blocked by robots.txt" errors, which are Page indexing statuses, not the sitemap warning. |
| Product relation | Note | ScanMySaaS flags robots.txt that lists /admin, /login, /dashboard, /api etc. as low "Sensitive Paths in robots.txt" (`scanner.ts:888-897`) and `Disallow: /` (`:900`); readiness reports a missing Sitemap line as "Available, but it does not reference a sitemap" (`:1100`). The guide does not mention either, and the site's own `src/app/robots.ts` disallows /api/, /dashboard/, /admin/, which its own scanner flags. Worth a sentence. |
| updatedAt 2026-11-07, no publishedAt | OK | Displays "Updated November 7, 2026". |

### AI-writing tells
- Opening triad and "Neither file protects a private page." restatement.
- "The sitemap should agree with the page." (aphorism) and "The two files disagree" (restated).
- Uniform bullets of four.

### SEO notes
- seoTitle "robots.txt & Sitemap for SaaS: Fix "Blocked by robots.txt" Errors" vs H1 "robots.txt and XML sitemaps for SaaS websites": the H1 does not mention the fix. Add a section for each of the three Search Console messages so the page satisfies the title.
- Add Next.js `app/robots.ts` and `app/sitemap.ts` snippets (this repo uses both) and a Vercel preview-deployment note (preview URLs should not be indexed).
- Links: /free-website-vulnerability-scanner (readiness snapshot checks robots/sitemap/llms), guide llms-txt-for-saas. `related: ["llms-txt-for-saas", "exposed-files-and-source-maps"]`.

### Exact edit instructions
1. Section "Fix "Sitemap contains URLs which are blocked by robots.txt"", paragraph 3: replace `"A related warning is a sitemap that robots.txt does not reference. Add a Sitemap: line with the absolute URL of your canonical sitemap, for example Sitemap: https://www.example.com/sitemap.xml, and make sure that URL returns 200 on the same host and protocol as your canonical pages."` with `"While you are in robots.txt, add a Sitemap: line with the absolute URL of your sitemap, for example Sitemap: https://www.example.com/sitemap.xml. Search Console does not warn when this line is missing, but it helps other crawlers find the file. The URL can be on another host, though keeping it on your canonical host is simpler."` (Sources: Search Console sitemaps report help; Google robots.txt spec.)
2. Same section bullet 1: replace `"Test each reported URL against your robots.txt rules (most specific matching rule wins)."` with `"Test each reported URL with URL Inspection in Search Console. Google applies the most specific (longest) matching rule and, when an Allow and a Disallow tie, the less restrictive one."`
3. Section "Separate product and marketing surfaces" bullet 2: replace `"Login may be crawlable but rarely needs high sitemap priority."` with `"Login can stay crawlable but does not need to be in the sitemap. Google ignores the priority and changefreq fields, so leave them out rather than tuning them."`
4. Add a section after the sitemap-warning section, heading `"Fix "Blocked by robots.txt" and "Indexed, though blocked by robots.txt""`, paragraph: `"These come from the Page indexing report, not the Sitemaps report. "Blocked by robots.txt" means Google did not crawl the URL because a rule matched. If the page should rank, narrow the rule. "Indexed, though blocked by robots.txt" means Google indexed the URL from links without crawling it. If you want it out of search, remove the Disallow rule so Google can crawl the page and see a noindex directive; a blocked page can stay in results when other pages link to it."` <!-- verify exact Page indexing status labels in Search Console before publishing; the two quoted names are the long-standing labels --> Source: https://developers.google.com/search/docs/crawling-indexing/block-indexing
5. Section "Use robots.txt for crawl guidance, not access control" add bullets: `"Keep the file under 500 KiB; Google ignores content beyond that."` and `"A robots.txt that returns 5xx can pause Google's crawling of the site; a 404 means no restrictions."` (Source: Google robots.txt spec.)
6. Section "Build a sitemap from pages worth indexing": append `"Set lastmod only when the page content changes significantly; Google uses it only when it is consistently accurate. One sitemap file is limited to 50,000 URLs or 50 MB uncompressed."` (Source: build-sitemap doc.)
7. Add to section "Use robots.txt for crawl guidance": `"Listing /admin or /dashboard in robots.txt tells everyone those routes exist. ScanMySaaS reports this as a low finding; it is acceptable when the routes are protected by authentication, and the readiness snapshot also checks that robots.txt references a sitemap."` (Code: `scanner.ts:888-900, 1100`.)
8. Section "Test the files after deployment": add Next.js snippet bullet: `"In Next.js, generate both from app/robots.ts and app/sitemap.ts so the sitemap is built from the same route list as the site."` and `"Fetch them: curl -s https://www.example.com/robots.txt and curl -sI https://www.example.com/sitemap.xml (expect 200 and an XML content type)."`
9. Add sources: the four Google URLs above plus the Search Console sitemaps help page.

---

## 5. security-headers-for-saas (priority 7)

Target query: "http security headers checklist", "security headers next.js". Results include Next.js docs security-headers page, vibe-eval "Vercel security checklist", unpwned. Competitors give copy-paste config.

### Fact check

| Claim (quote) | Verdict | Correct fact and source |
|---|---|---|
| "Strict-Transport-Security tells supporting browsers to return over HTTPS after the first secure visit." | CORRECT | MDN HSTS: does not take effect "until the browser has made at least one secure connection"; header ignored over HTTP. https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Strict-Transport-Security |
| "frame-ancestors in CSP, or X-Frame-Options for older clients, limits clickjacking" | CORRECT | MDN frame-ancestors: similar to X-Frame-Options DENY "which is also supported in older browsers"; frame-ancestors "does not fall back to the default-src setting" and is "not supported in the <meta> element". https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy/frame-ancestors |
| "Begin with Content-Security-Policy-Report-Only, collect violations" | CORRECT, incomplete | MDN: report-only "is not supported inside a <meta> element"; reports are only sent if `report-to` (with Reporting-Endpoints) or deprecated `report-uri` is set; recommends both. https://developer.mozilla.org/en-US/docs/Web/HTTP/Reference/Headers/Content-Security-Policy-Report-Only |
| "Nonces or hashes are a better long-term answer for inline scripts." | CORRECT | Next.js 16 docs (local node_modules/next/dist/docs/01-app/02-guides/content-security-policy.md): nonces via `proxy.ts`, require dynamic rendering; experimental SRI hashes keep static generation. |
| "Preload is a separate commitment and is difficult to undo quickly." | CORRECT | hstspreload.org: "inclusion in the preload list cannot easily be undone." Requirements: max-age >= 31536000, includeSubDomains, preload, same-host redirect. |
| "keep the server-side HTTP to HTTPS redirect... a new visitor can still arrive over HTTP" | CORRECT | MDN HSTS first-visit weakness. |
| Description: "...MIME sniffing, referrer policy, and permissions policy" | WRONG (body mismatch) | The body never covers Referrer-Policy or Permissions-Policy. The scanner does check both (`scanner.ts:499, 503`). |
| "Start with a shorter max-age on the primary host." | CORRECT, conflicts with product | Scanner's HSTS remedy recommends `max-age=31536000; includeSubDomains; preload` outright (`scanner.ts:490`) and flags < 15768000 s (`:493`). On Vercel, custom domains already get `max-age=63072000` by default (https://vercel.com/docs/cdn-security/encryption), so many readers already have HSTS. |
| "A CDN, reverse proxy, or hosting platform can add, remove, or duplicate them." | CORRECT | Scanner reads headers from the first HTML page only (`scanner.ts:1449`). |
| Dates / sources | Missing | No dates, no sources. |

### AI-writing tells
- "Security headers are small response headers with an outsized job." (significance inflation)
- "The hard part is not adding every possible header. It is choosing..." (not X, it's Y)
- "four headers deserve attention first. They cover transport, framing, content interpretation, and script execution." (enumerated restatement)
- "They may make the report quiet while leaving much of the original risk in place."
- Headings "Do not enable HSTS by reflex", "A sensible release check" are generic.

### SEO notes
- 398 words labelled "8 min read". Competitor pages carry the full header list with values and framework config. Add a copy-paste block for Next.js (`next.config.ts headers()`), Vercel (`vercel.json`), Netlify (`_headers`), and a curl test. This is the single biggest usefulness gap across all guides.
- seoTitle "HTTP Security Headers Checklist for SaaS (CSP, HSTS, X-Frame)": "X-Frame" is an odd keyword; use "X-Frame-Options".
- Links: /free-website-vulnerability-scanner, /lovable-security-scanner (Lovable sites), guides ssl-tls (HSTS) and vibe checklist. `related: ["ssl-tls-checklist-for-saas", "vibe-coding-security-checklist"]`. The scan result page already deep-links header findings here (`src/app/scan/[id]/page.tsx:62`), so the page must answer every header finding the scanner emits (CSP, X-Frame-Options, nosniff, HSTS, Referrer-Policy, Permissions-Policy, server disclosure).

### Exact edit instructions
1. seoTitle: `"HTTP Security Headers Checklist for SaaS (CSP, HSTS, X-Frame-Options)"`.
2. intro[0]: replace `"Security headers are small response headers with an outsized job. They tell a browser"` with `"Security headers tell a browser"`. intro[1]: replace `"The hard part is not adding every possible header. It is choosing a safe order, measuring what breaks, and avoiding a copied policy that does not match your product."` with `"Most of the work is choosing an order, measuring what breaks, and not pasting a policy written for someone else's product."`
3. Section 1: add bullets `"Referrer-Policy: strict-origin-when-cross-origin sends only the origin to other sites, so tokens or IDs in URLs do not leak through the Referer header."` and `"Permissions-Policy turns off browser features you do not use, for example camera=(), microphone=(), geolocation=()."` Change the paragraph to `"Start with these six. ScanMySaaS reports each one when it is missing."` (Code: `scanner.ts:440-503`.)
4. Section "Roll out CSP": append paragraph `"Report-Only only works as an HTTP header, not a meta tag, and browsers send reports only when the policy has a report-to directive (with a Reporting-Endpoints header) or the older report-uri; MDN suggests setting both. frame-ancestors also only works as a header and does not inherit from default-src."` and `"In Next.js 16, generate a fresh nonce per request in proxy.ts (the renamed middleware) and pass it through the Content-Security-Policy request header; nonced pages must be dynamically rendered. Next.js also has experimental hash-based CSP through Subresource Integrity if you need static pages."` (Sources: MDN pages; Next.js CSP guide https://nextjs.org/docs/app/guides/content-security-policy .)
5. Section "Do not enable HSTS by reflex": append `"Check what your host already sends. Vercel adds Strict-Transport-Security: max-age=63072000 to custom domains by default. Preload has fixed requirements: max-age of at least 31536000, includeSubDomains, the preload directive and an HTTP to HTTPS redirect on the same host. ScanMySaaS reports max-age below about six months as a low finding, which you can accept while you ramp up."` (Sources: Vercel encryption doc, hstspreload.org, `scanner.ts:493`.)
6. Add a new section before "A sensible release check", heading `"Copy-paste starting point"`, paragraphs with these snippets (all standard config syntax; keep the CSP out of the static block since it needs per-app sources):
   - Next.js `next.config.ts`: `async headers() { return [{ source: '/:path*', headers: [ { key: 'X-Content-Type-Options', value: 'nosniff' }, { key: 'X-Frame-Options', value: 'DENY' }, { key: 'Referrer-Policy', value: 'strict-origin-when-cross-origin' }, { key: 'Permissions-Policy', value: 'camera=(), microphone=(), geolocation=()' }, { key: 'Strict-Transport-Security', value: 'max-age=31536000' } ] }]; }`
   - Vercel `vercel.json`: `{ "headers": [{ "source": "/(.*)", "headers": [{ "key": "X-Content-Type-Options", "value": "nosniff" }] }] }`
   - Netlify `_headers` file: `/*` on one line, then indented `X-Content-Type-Options: nosniff`, `X-Frame-Options: DENY`, `Referrer-Policy: strict-origin-when-cross-origin`.
   - Test: `curl -sI https://your-domain | grep -iE 'strict-transport|content-security|x-frame|x-content-type|referrer-policy|permissions-policy'`
   - Note: since guide sections are plain strings, add a `code?: string` field to `GuideSection` and render it in `<pre>`, or put snippets in bullets.
7. Section "A sensible release check": replace `"Scan the production hostname after deployment"` with `"Run the free website scan against the production hostname after deployment"` and link /free-website-vulnerability-scanner.
8. Add sources: MDN HSTS, MDN CSP-Report-Only, MDN frame-ancestors, hstspreload.org, Next.js CSP guide, OWASP HTTP Headers Cheat Sheet (https://cheatsheetseries.owasp.org/cheatsheets/HTTP_Headers_Cheat_Sheet.html, verify URL resolves before adding).
9. Product follow-up (not a guide edit): `scanner.ts:490` remedy defaults to `includeSubDomains; preload`. Align it with the guide: recommend `max-age=31536000` first, `includeSubDomains` after checking subdomains, preload only after reading hstspreload.org.

---

## 6. github-actions-security-for-vibe-coded-apps (priority 6)

Target query: "github actions security best practices", "pull_request_target security". Results: GitHub docs, Aikido "checklist github actions", runs-on pull_request vs pull_request_target, OpenReplay audit.

### Fact check

| Claim (quote) | Verdict | Correct fact and source |
|---|---|---|
| "The pull_request_target event runs in the context of the base repository." | CORRECT, now more precise | Since 2025-12-08 it "always uses the default branch for workflow source and reference"; GITHUB_REF resolves to the default branch. https://github.blog/changelog/2025-11-07-actions-pull_request_target-and-environment-branch-protections-changes/ |
| "dangerous when the job checks out and executes code from a fork" | CORRECT | GitHub: "The vulnerability is completed by the next step that runs code checked out"; called a "pwn request". https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target |
| "split it into a separate workflow that consumes a small, verified artifact" | PARTIAL | GitHub: a workflow_run workflow should treat artifacts from other workflows as untrusted data, since a fork can supply them. "verified" suggests trust; say "treat as untrusted data and never execute". Same URL. |
| "Declare contents: read at workflow level... Avoid permissions: write-all." | CORRECT | Secure use: GITHUB_TOKEN "minimum required permissions", read-only contents default, raise per job. https://docs.github.com/en/actions/reference/security/secure-use |
| "GitHub documents a full-length commit SHA as the immutable way to reference an action." | CORRECT, update | Secure use: "Pin references to actions to a commit SHA"; a tag "can be moved or deleted". It now also says a lockfile "supersedes SHA pinning for repositories that adopt it." Workflow lockfiles (`.github/workflows/actions.lock`, `gh actions-lock` extension) are in public preview since 2026-10-14: https://github.blog/changelog/2026-10-14-github-actions-workflow-lockfiles-in-public-preview/ . Policy to enforce SHA pinning and block actions since Aug 2025: https://github.blog/changelog/2025-08-15-github-actions-policy-now-supports-blocking-and-sha-pinning-actions/ |
| "Limit which actions and reusable workflows the repository may run." | CORRECT | Same policy feature. |
| "GitHub masks known secret values in normal logs, but masking is not a security boundary." | CORRECT | Secure use: "automatic redaction is not guaranteed"; register transformed values; avoid structured secrets. |
| Product match | CORRECT | Scanner flags write-all (`github-scanner.ts:322`), missing permissions (`:325`), pull_request_target with PR-head checkout (`:327`), non-SHA `uses:` (`:331-336`), `echo/printf ${{ secrets.` (`:339`). Not detected: `persist-credentials`, `${{ github.event.* }}` script injection, workflow_run artifact use. |
| Dates / sources | Sources OK (both resolve), dates missing | |

### AI-writing tells
- "A GitHub Actions file is production code with credentials." (aphorism opener)
- "AI coding tools are good at producing a workflow that passes. They cannot decide how much authority..." (setup/punchline)
- "A test job does not need the same authority as a deployment job." (restated takeaway)

### SEO notes
- No seoTitle. Suggest `"GitHub Actions Security Checklist: Permissions, pull_request_target & SHA Pinning"`.
- Thin (414 words). Missing what competitors cover: script injection via `${{ github.event... }}` in `run:`, `persist-credentials: false`, OIDC instead of long-lived cloud keys, environments with required reviewers. Add only the first two with GitHub doc sources (both are in GitHub's secure-use reference; verify before adding).
- Links: /repo-scan, vibe checklist section 10. `related: ["github-secret-scanning-for-vibe-coded-apps", "vibe-coding-security-checklist"]`.

### Exact edit instructions
1. Add seoTitle as above; set updatedAt.
2. Section "Make token permissions explicit": add a snippet bullet: `"permissions:\n  contents: read"` at the top of the workflow, and in the release job only `"permissions:\n  contents: write"` (or packages: write, id-token: write as needed). Add `"Set persist-credentials: false on actions/checkout in jobs that do not push, so the token is not left in .git/config for later steps."` (Verify against actions/checkout README before publishing.)
3. Section "Treat pull request code as hostile input" paragraph 1: append `"Since December 8, 2025, pull_request_target always runs the workflow file from the default branch, so editing the workflow in a pull request no longer changes what runs. Checking out and running the pull request's code is still the risk."` Paragraph 2: replace `"consumes a small, verified artifact and never executes pull request code."` with `"reads a small artifact as untrusted data (GitHub warns that a fork can supply it) and never executes pull request code."`
4. Section "Pin the software inside the workflow": append `"Organization and repository admins can enforce SHA pinning and block specific actions in Actions policy settings. GitHub's newer workflow lockfiles (public preview since October 2026, .github/workflows/actions.lock, created with the gh actions-lock extension) record the commits a workflow uses; GitHub's secure-use guide says a lockfile supersedes SHA pinning for repositories that adopt it."` Add both changelog URLs to sources.
5. intro[1]: replace `"AI coding tools are good at producing a workflow that passes. They cannot decide how much authority that workflow should have without a clear security boundary from you."` with `"An AI-written workflow usually passes on the first try. How much access it gets is still your decision."`
6. Add a sentence to "Make token permissions explicit": `"ScanMySaaS flags write-all, workflows with no permissions block, unpinned actions, pull_request_target jobs that check out pull request code and shell commands that echo secrets."` Link /repo-scan. (Code: `github-scanner.ts:322-340`.)

---

## 7. github-secret-scanning-for-vibe-coded-apps (priority 6)

Target query: realistically "committed .env to github what to do" / "leaked api key github". Results: gist "If you accidentally push a .env", dev.to "Accidentally pushed a .env secret to a public GitHub repo? Here's what to do", freeCodeCamp "How to uncommit sensitive files from Git". All are step-by-step with commands. Title "GitHub secret scanning for vibe-coded apps" collides with GitHub's own feature name and docs.

### Fact check

| Claim (quote) | Verdict | Correct fact and source |
|---|---|---|
| "A later commit that removes .env only changes the current tree. The earlier blob remains in history until it is rewritten." | CORRECT | https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository |
| "Coordinate a history cleanup with collaborators because rewritten commits change hashes and require fresh clones" | CORRECT | Same doc; also removes signatures, needs force-push, breaks closed PR diffs. |
| "History cleanup is not a substitute for rotation." / "Revoke the credential first." | CORRECT | Same doc: "revoke and/or rotate that secret" first. |
| "Build logs, forks, caches, and local clones may keep another copy." | CORRECT | Same doc: data in forks stays accessible; GitHub Support can remove cached views and PR references. |
| "Turn on GitHub secret scanning and push protection where available." | PARTIAL / outdated phrasing | Secret scanning and push protection are "Available for public repositories by default"; "Push protection for users is on by default". Private repos on Team/Enterprise need GitHub Secret Protection. https://docs.github.com/en/code-security/getting-started/github-security-features |
| "A Supabase publishable key... is designed for client code when Row Level Security is correct. The service-role or secret key... bypasses those controls." | CORRECT | Supabase api-keys page. |
| "Keep privileged values out of public prefixes such as NEXT_PUBLIC_, VITE_, and REACT_APP_." | CORRECT | Matches scanner `github-scanner.ts:306`. |
| "A scanner should classify the key by role, not flag every long string as a breach." | CORRECT for ScanMySaaS | Scanner decodes JWT role and only flags service_role (`github-scanner.ts:303`, `secret-patterns.ts:19-27`). |
| Source "OWASP Developer Guide: Secure coding" (PDF) | Weak | Resolves (redirect to owasp.github.io) but is a whole book; does not specifically support the text. Replace with GitHub "Removing sensitive data" doc. |
| Dates | Missing | |

### AI-writing tells
- "A committed secret is an incident, even when..." / "The response order matters more than the cleanup command." (aphorisms)
- "Assume the value was copied" heading + "Do not wait for evidence" restatement.
- Uniform 4 sections, two lists of exactly 4.

### SEO notes
- Change seoTitle to target the incident query: `"Committed a .env or API Key to GitHub? What to Do (Rotate, Remove, Prevent)"`. Keep H1 but consider `"Committed a secret to GitHub: what to do in a vibe-coded app"`.
- Add commands (competitors all have them): `git rm --cached .env`, `git filter-repo --sensitive-data-removal --invert-paths --path .env` (GitHub doc), how to find it: `git log --all --oneline -- .env`.
- Links: /repo-scan, supabase guide (rotation of legacy keys), vibe checklist section 1. `related: ["github-actions-security-for-vibe-coded-apps", "supabase-security-for-vibe-coded-apps"]`.

### Exact edit instructions
1. Add seoTitle above; set updatedAt.
2. Section "Deleting the file does not delete Git history" paragraph 1: append `"Find every commit that touched the file with git log --all --oneline -- .env. GitHub recommends git-filter-repo (version 2.47 or later) with the --sensitive-data-removal flag, for example git filter-repo --sensitive-data-removal --invert-paths --path .env, then a force push. Copies in forks stay accessible, and GitHub Support can remove cached views and pull request references only after you have rotated the credential."` (Source: GitHub removing-sensitive-data doc.)
3. Section "Fix the path that produced the leak" paragraph: append `"If .env is already tracked, git rm --cached .env removes it from the index without deleting your local file."` Bullet 1: replace `"Turn on GitHub secret scanning and push protection where available."` with `"Keep push protection on. GitHub enables secret scanning and push protection by default for public repositories and push protection for user accounts; private repositories on Team or Enterprise plans need GitHub Secret Protection."`
4. intro[1]: replace `"The response order matters more than the cleanup command. Revoke the credential first."` with `"Revoke the credential first."`
5. Section "Know which keys are meant to be public": append `"ScanMySaaS decodes Supabase JWTs and only reports the service_role role, and reports sb_secret_ keys, so a committed publishable key is not a finding."` (Code: `github-scanner.ts:303`, `secret-patterns.ts:10`.)
6. Replace source `OWASP Developer Guide` with `{ label: "GitHub: Removing sensitive data from a repository", url: "https://docs.github.com/en/authentication/keeping-your-account-and-data-secure/removing-sensitive-data-from-a-repository" }`. Add Supabase api-keys page.

---

## 8. saas-launch-security-checklist (priority 5)

Target query: "saas security checklist before launch". Results: rocket.new, techsy.io "SaaS security checklist before launch (40 checks)" in many languages, acquaintsoft, connectwise, freshcodeit, Astra e-book. This guide is the most careful and best-sourced in the set.

### Fact check

| Claim (quote) | Verdict | Correct fact and source |
|---|---|---|
| "OWASP recommends checking authorization on every request." | CORRECT | Authorization Cheat Sheet "Validate the Permissions on Every Request". https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html |
| "review table grants and Row Level Security together" | CORRECT, now more important | Supabase changelog 45329: new tables not exposed without explicit GRANT (all existing projects from 2026-10-30). Worth one sentence. |
| "Exercise requests with the publishable or legacy anon key" | CORRECT | Supabase api-keys page. |
| "a policy must constrain the resulting row as well as the existing one" | CORRECT | RLS docs: "The with check clause decides what the resulting row is allowed to look like." |
| "Public buckets are intended for public content; a hard-to-guess filename is not a private-file access control." | CORRECT | Supabase storage access control. |
| "Stripe documents webhooks as necessary for reliable fulfillment." | CORRECT | "Webhooks are required for fulfillment". https://docs.stripe.com/checkout/fulfillment?ui=full-page |
| "Verify webhook signatures against the raw request body" / "The secret used by a local Stripe CLI listener can differ from the registered endpoint's secret." | CORRECT | https://docs.stripe.com/webhooks (raw body; `stripe listen` prints its own whsec; test and live secrets differ per endpoint). |
| "Retry the same sandbox event... including concurrent processing" | CORRECT | Stripe fulfillment: function "might be called multiple times, possibly concurrently". |
| "Test relevant delayed, failed, and out-of-order events" | CORRECT | Stripe: "doesn't guarantee the delivery of events in the order"; async_payment_succeeded/failed. |
| "ScanMySaaS can inspect observable signals such as headers, transport, cookies, and exposed files on reachable public pages." | CORRECT | `scanner.ts:1335-1511`. |
| "Its separate public GitHub scan reads a bounded set of files from the current tree... It does not execute the repository or search full Git history" | CORRECT | `github-scanner.ts:11-14, 495-500`; llms.txt. |
| "private repository support is not part of that public scan." | OUTDATED / misleading | Private repos are scanned on Starter and Pro via a read-only GitHub App (`github-scanner.ts:490`, llms.txt). Sentence implies no private support. |
| Source "Stripe: Checkout fulfillment" `?payment-ui=stripe-hosted` | OUTDATED URL | Resolves (200) but now shows only a variant index pointing to `?ui=full-page` / `?ui=checkout-form`. |
| Source "OWASP: Multi-tenant isolation and verification" | CORRECT | Resolves (200). |
| Dates 2026-09-06 | OK | |

### AI-writing tells
- "The useful outcome is a repeatable check and evidence of the fix, not a one-time score." (S1 restated takeaway, not-X-but-Y)
- "Missing evidence is not a pass." (fine once; repeated in vibe checklist as "an untested item is not a pass").
- Long, even, procedural sections; acceptable register for a checklist. Lowest AI-tell density of the set.

### SEO notes
- seoTitle "SaaS Security Checklist Before Launch (2026, Vibe-Coded Apps)" overlaps the vibe checklist. Recommend `"SaaS Security Checklist Before Launch (2026): Tenant, RLS & Stripe Tests"`.
- Competitors (techsy "40 checks") are count-based. This guide's differentiator is the test worksheet; keep it.
- Links: /free-website-vulnerability-scanner and /repo-scan in section 6; supabase guide in section 3; vibe checklist. `related: ["vibe-coding-security-checklist", "supabase-security-for-vibe-coded-apps"]`.

### Exact edit instructions
1. seoTitle: replace with `"SaaS Security Checklist Before Launch (2026): Tenant, RLS & Stripe Tests"`.
2. Section 6 paragraph 1: replace `"It does not execute the repository or search full Git history; private repository support is not part of that public scan."` with `"It does not execute the repository or search full Git history. Private repositories can be scanned on Starter and Pro through a read-only GitHub App."` (Code: `github-scanner.ts:490`; `public/llms.txt`.)
3. Section 3 paragraph 1: after `"review table grants and Row Level Security together."` insert `"Since October 30, 2026, new tables in Supabase's public schema get no Data API access until you grant it, so a missing grant shows up as a 42501 permission error rather than a leak; an over-broad grant plus a weak policy is still a leak."` (Source: Supabase changelog 45329; add to sources.)
4. Section "Decide whether this release is ready": replace `"The useful outcome is a repeatable check and evidence of the fix, not a one-time score."` with `"Keep the evidence; the next release will need the same checks."` or delete.
5. sources: change `https://docs.stripe.com/checkout/fulfillment?payment-ui=stripe-hosted` to `https://docs.stripe.com/checkout/fulfillment?ui=full-page`.
6. Add section links: section 3 to /guides/supabase-security-for-vibe-coded-apps, section 6 to /free-website-vulnerability-scanner and /repo-scan.

---

## 9. exposed-files-and-source-maps (priority 5)

Target query: "exposed .env file production", "source maps in production security". The scan result page links source-map, sensitive-file and info-disclosure findings here (`src/app/scan/[id]/page.tsx:63`), so it is the landing page for critical findings.

### Fact check

| Claim (quote) | Verdict | Correct fact / evidence |
|---|---|---|
| "If a public file contains credentials, removing the file is not enough. Rotate the exposed values" | CORRECT | Same principle as GitHub sensitive-data doc. |
| "Browser source maps can reveal readable source, file paths, comments, and internal names. That does not automatically create an exploit" | CORRECT | Balanced; matches scanner severity medium (`scanner.ts:1201`). |
| "If an error-monitoring service needs source maps, generate them in CI, upload them privately, and exclude them from the public artifact. Also remove sourceMappingURL references" | CORRECT | Standard practice. Next.js: `productionBrowserSourceMaps` is off unless enabled (Next docs mention it in memory-usage guide); scanner repo check flags `productionBrowserSourceMaps: true` / `sourcemap: true` (`github-scanner.ts:391-393`). |
| "A CDN may cache the old file even after it disappears from the origin. Purge the relevant paths" | CORRECT | General. |
| "Document the incident and any required user or regulator notification." | CORRECT, generic | |
| Implied coverage: "Environment files, repository metadata, database backups, logs" | PARTIAL vs product | Scanner probes `/.env`, `/.git/config`, `/.git/HEAD`, `/backup.sql`, `/database.sql`, `/debug.log`, `/error.log`, `/.svn/entries`, `/.DS_Store`, `/.htaccess`, Docker files, package/composer.json, phpinfo, etc. (`scanner.ts:797-816`) and confirms by content (`:769-790`). It does not request `/.env.local`, `/.env.production`, `/.git/index`, or `*.zip` backups. Source maps: only `<script src>.map` for the first 5 scripts on the first 3 pages (`scanner.ts:1172-1189`) plus sourceMappingURL in HTML (`:760-762`). |
| Dates / sources | Missing | |

### AI-writing tells
- "The first response is containment. The second is fixing the pipeline that allowed the file to ship." (staccato pair)
- "A deployment can work perfectly while publishing files that were never meant for a browser." (setup)
- Uniform 4 sections, two lists of 4.

### SEO notes
- No seoTitle. Suggest `"Exposed .env, .git and Source Maps in Production: How to Find and Fix"`.
- Add test commands and framework settings; competitors' versions have them.
- Links: /free-website-vulnerability-scanner, github-secret guide (rotation), vibe checklist section 8. `related: ["github-secret-scanning-for-vibe-coded-apps", "security-headers-for-saas"]`.

### Exact edit instructions
1. Add seoTitle above; set updatedAt.
2. intro[1]: replace `"The first response is containment. The second is fixing the pipeline that allowed the file to ship."` with `"Contain it first, then fix the build step that shipped it."`
3. Section "Verify the fix from outside": add bullets: `"curl -s -o /dev/null -w '%{http_code}\\n' https://your-domain/.env (repeat for /.env.local, /.env.production, /.git/config, /backup.sql). Expect 404 or 403, and check that a 200 is not your HTML app shell."` and `"Open DevTools, Sources tab, and confirm original .ts/.tsx files are not listed for the production site."`
4. Section "Handle source maps deliberately": append `"In Next.js, browser source maps are only published when productionBrowserSourceMaps is set to true. In Vite, build.sourcemap: 'hidden' generates maps for upload without adding the sourceMappingURL comment."` (Next.js docs in node_modules; Vite `build.sourcemap` docs, verify 'hidden' wording at https://vite.dev/config/build-options before publishing.)
5. Section "Publish a build artifact" bullet 3: replace `"Configure the server to deny dotfiles and backup extensions as a second layer."` with `"Deny dotfiles and backup extensions at the server as a second layer, for example in Nginx: location ~ /\\. { deny all; }"`.
6. Add a short paragraph: `"ScanMySaaS requests a fixed list of paths, including /.env, /.git/config, /.git/HEAD, SQL dumps, logs and Docker files, and only reports a file when its content matches the expected format. It checks .map files for the scripts on the first pages it reads. Test other environment file names yourself."` (Code: `scanner.ts:769-816, 1172-1189`.)
7. Add sources: GitHub removing-sensitive-data doc (rotation), OWASP WSTG "Review Webpage Content for Information Leakage" (verify URL before adding).

---

## 10. llms-txt-for-saas (priority 4)

Target query: "llms.txt for saas". Results: releasepad "llms.txt SaaS guide", discoveredlabs "llms.txt example B2B SaaS template", rankability "LLMS.txt best practices", dev.to posts. Competitors provide a full example file.

### Fact check

| Claim (quote) | Verdict | Correct fact and source |
|---|---|---|
| "An llms.txt file is a plain-text guide placed at the root of a website." | PARTIAL | llmstxt.org: the file "uses Markdown"; the H1 "is the only required section"; can sit "at the site root, or at any path within it". https://llmstxt.org/ |
| "Google has said its systems do not use llms.txt for AI Overviews or AI Mode." | CORRECT | Google guide (updated 2026-07-10) "Mythbusting": no need for "new machine readable files, AI text files..."; Google Search "ignores them"; lists "creating unnecessary AI text files (like llms.txt)" as ignorable. https://developers.google.com/search/docs/fundamentals/ai-optimization-guide . Quote it directly. |
| "A separate llms-full.txt can hold a longer product summary" | PARTIAL | llms-full.txt is not part of the llmstxt.org spec (it is a common convention); the spec instead proposes Markdown versions of pages at the same URL with .md appended. |
| "Open with the product name and one factual sentence." | CORRECT | Spec: H1 name, then blockquote summary. |
| "A scanner can verify that the file exists and that its important links are reachable" | PARTIAL vs product | ScanMySaaS readiness only checks that /llms.txt is readable and contains a heading or a URL (`scanner.ts:1108-1110`); it does not test links. |
| Dates / seoTitle | Missing | |

### AI-writing tells
- "useful file, realistic expectations" title formula; "It is not a switch for rankings or AI answers."
- "Write for retrieval, not promotion" heading (not X); "should summarize and route, not introduce a different story."
- "A clean sitemap, crawlable pages, descriptive titles, useful body content, canonical URLs, and accurate structured data remain the practical foundation." (list padding)

### SEO notes
- No seoTitle. Suggest `"llms.txt for SaaS: Format, Example File and What Google Says (2026)"`.
- Add an example file following the spec (H1, blockquote, H2 sections with Markdown links, "Optional" section). ScanMySaaS's own `public/llms.txt` is a real example to excerpt.
- Links: robots guide, /free-website-vulnerability-scanner (readiness snapshot). `related: ["robots-txt-and-sitemap-for-saas", "saas-launch-security-checklist"]`.
- Low commercial intent; fine at low priority.

### Exact edit instructions
1. Add seoTitle above; set updatedAt.
2. intro[0]: replace `"An llms.txt file is a plain-text guide placed at the root of a website."` with `"An llms.txt file is a short Markdown file, usually at /llms.txt, that names your product and links to the pages a language model should read."`
3. intro[1]: replace `"Google has said its systems do not use llms.txt for AI Overviews or AI Mode."` with `"Google's guide to generative AI features says Google Search ignores llms.txt and similar AI text files, and that you do not need them to appear in its AI features."`
4. Section "Write for retrieval": add paragraph `"The llmstxt.org format has one required element, an H1 with the product name. Then a blockquote summary, optional paragraphs, and H2 sections that list Markdown links with a short note each. A section titled Optional holds links an agent can skip."` Add an example as bullets: `"# ScanMySaaS"`, `"> One-sentence factual summary."`, `"## Docs"`, `"- [Pricing](https://example.com/pricing): plans and limits"`, `"## Optional"`.
5. Section "Keep the short file short": replace `"A separate llms-full.txt can hold a longer product summary"` with `"Some sites also publish an llms-full.txt with longer content; that name is a convention, not part of the llmstxt.org proposal, which instead suggests Markdown versions of pages at the same URL with .md added."`
6. Section "Maintain it like documentation": replace `"A scanner can verify that the file exists and that its important links are reachable, but usefulness still depends on careful editing."` with `"ScanMySaaS checks that /llms.txt is readable and has a heading or links. Check the links yourself after each release."` (Code: `scanner.ts:1108-1110`.)
7. Add source `{ label: "llmstxt.org: The /llms.txt file proposal", url: "https://llmstxt.org/" }`.

---

## Cross-guide AI-writing pattern summary
- Em dashes and en dashes: zero in guides.ts. Curly quotes: zero. Good. (The scanner remedies in `scanner.ts` do contain em dashes, outside this audit's scope.)
- Most repeated tell: tailing negation ", not X" (18 instances, list from `grep`): lines 131, 156, 191, 204, 222, 332, 379, 430, 497, 525, 552, 583, 588, 599, 600, 609, 631, 658 of guides.ts. Fix about half; keep the ones that carry a real contrast for a checklist (for example "on the server, not only in the UI").
- Structural uniformity (S6): the seven older guides all have 4 or 5 sections and bullet lists of exactly 3 or 4 items, with one-paragraph sections. Breaking this is the content additions above (snippets, test commands, new sections).
- Aphorism openers: "outsized job", "production code with credentials", "A committed secret is an incident", "A valid padlock is the beginning... not the end", "The first response is containment."
- Restated takeaways (S1): "The denied case is the test that matters.", "Every hop matters.", "A test job does not need the same authority as a deployment job.", "The useful outcome is a repeatable check..."
- Author: "ScanMySaaS Editorial Team" on every guide (template). A named author with a short bio would help E-E-A-T for security content; only do this if a real person reviews the guides.

## Cannibalization map
- "vibe coding security checklist" query family: vibe-coding-security-checklist (target), saas-launch seoTitle ("Vibe-Coded Apps"), /vibe-coding-security product page. Fix: saas-launch seoTitle change (guide 8 edit 1); vibe checklist links to /vibe-coding-security and vice versa.
- Supabase: supabase guide (canonical), saas-launch section 3, vibe checklist section 4. Fix: the latter two link to the Supabase guide.
- HSTS: security-headers (canonical rollout) and ssl-tls. Fix: ssl-tls links to headers for rollout detail.
- Secrets: github-secret guide (canonical incident response) and vibe checklist section 1.

## Recommended fix order
1. Supabase guide edits 3, 4, 7, 8, 11 (grant change, wrong anon test, legacy-key wording, getClaims). Time-sensitive: the Supabase change landed 2026-10-30 and readers following the current test bullet will misread a correct denial.
2. Template edit 1 (outdated private-repo CTA, shown on 4 repo guides) and saas-launch edit 2 (same claim).
3. Vibe checklist edits 1, 6, 7, 8 (product overclaims and the Stripe contradiction on a page published today), then 2 to 5 and links.
4. SSL/TLS: new certificate-lifetime section (edit 3) and the preload redirect correction (edit 5).
5. robots guide edits 1 and 3 (invented Search Console warning; priority field), then edit 4 to match the seoTitle.
6. Security headers: description/body mismatch (edit 3), copy-paste section (edit 6), HSTS note (edit 5); align `scanner.ts:490` remedy.
7. Template edits 2 to 6 (Sources heading, related, body links, read times, dates).
8. GitHub Actions edits 3 and 4; GitHub secret edits 2, 3, 6.
9. Exposed files edits 3 to 6; llms.txt edits 2 to 6.
10. Product follow-ups (not guide text): scale the 30-day certificate-expiry threshold for shorter certificate lifetimes (`scanner.ts:412`); consider checking Supabase GRANTs in migrations alongside RLS (`github-scanner.ts:407-423`); consider `/.env.local` and `/.env.production` probes (`scanner.ts:797`).
