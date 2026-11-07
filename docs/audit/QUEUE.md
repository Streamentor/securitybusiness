# Page fix queue

Created 2026-11-07. A scheduled task works through this list two items per run (every 2 days). Each run takes the first two unchecked items, fixes them, and ticks them here in the same PR with the date and PR number.

Already done on 2026-11-07 (PR #10): homepage, `/free-website-vulnerability-scanner`, and fact corrections on `/lovable-security-scanner` (items 1-11, 13-15 of its section in `landing-pages.md`).

Instructions for each item are in:
- `docs/audit/landing-pages.md` (landing pages, by section number)
- `docs/audit/guides.md` (guides; section `T` is the guide template)

Order (highest value first):

- [ ] 1. Guide template `src/app/guides/[slug]/page.tsx` + `src/lib/guides.ts` interface (guides.md §T). Do this first: it adds in-body links and fixes the outdated "public repository" CTA, which every later guide edit relies on.
- [ ] 2. `supabase-security-for-vibe-coded-apps` (guides.md §1). Supabase grant change of 2026-10-30, 42501 denial, getClaims, edge function keys, description wording.
- [ ] 3. `vibe-coding-security-checklist` (guides.md §3). Automated-vs-manual claims, Stripe success-page rule, CORS bullet, CSP first-page caveat.
- [ ] 4. `/repo-scan` (landing-pages.md §3). Meta "free ... private" claim, dependency coverage accuracy, limits.
- [ ] 5. `ssl-tls-checklist-for-saas` (guides.md §2). 2026 certificate lifetime limits, Let's Encrypt changes, HSTS preload redirect rule.
- [ ] 6. `robots-txt-and-sitemap-for-saas` (guides.md §4). Remove invented Search Console warning, priority/changefreq, cover "Blocked by robots.txt" or change the seoTitle.
- [ ] 7. `/pricing` (landing-pages.md §5). Pro feature list, "10 website scans", repo-credits FAQ, Offer schema. Do NOT change prices or plan limits; only make copy match `src/lib/stripe.ts`. Leave "Most popular" and "Existing subscriber prices stay unchanged" as they are unless Stefan confirmed them.
- [ ] 8. `security-headers-for-saas` (guides.md §5). Referrer-Policy and Permissions-Policy sections, HSTS advice vs scanner remedy, read time.
- [ ] 9. `/vibe-coding-security` (landing-pages.md §4). Archived OWASP link, research numbers, meta overpromise, dateModified, H1.
- [ ] 10. `/lovable-security-scanner` remaining items (landing-pages.md §7 items 12 and 16): H1 tail, Lovable Cloud FAQ. Item 16 only after a real test scan shows the repo RLS check fires on a Lovable Cloud repo; if it cannot be verified, skip 16 and note why.
- [ ] 11. `github-actions-security-for-vibe-coded-apps` (guides.md §6). pull_request_target change 2025-12-08, SHA-pinning policy, workflow lockfiles, workflow_run artifacts.
- [ ] 12. `github-secret-scanning-for-vibe-coded-apps` (guides.md §7).
- [ ] 13. `saas-launch-security-checklist` (guides.md §8). Private repo statement, seoTitle cannibalization with the vibe checklist.
- [ ] 14. `exposed-files-and-source-maps` (guides.md §9).
- [ ] 15. `llms-txt-for-saas` (guides.md §10). Markdown not plain text, llms-full.txt not in spec, what the scanner actually checks.
- [ ] 16. `/guides` index (landing-pages.md §6).

Product follow-ups (not page copy; do not do these in the page runs, list them for Stefan):
- Certificate "expires soon" threshold of 30 days (`src/lib/scanner.ts`) will flag healthy short-lived certificates.
- Repo RLS check ignores GRANTs (`src/lib/github-scanner.ts` scanSupabase).
- Only `/.env` is probed, not `/.env.local` or `/.env.production`.
