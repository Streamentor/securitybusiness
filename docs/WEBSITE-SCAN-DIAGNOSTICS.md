# Website scan failures and honest score scope

## Observed diagnosis, 8 November 2026

Vercel production runtime logs for the timestamps in the supplied list confirm two failure paths, rather than a proven single firewall issue:

- 22:52, 22:17 and 22:16 Europe/Belgrade: discovery read at least one HTML page, then the analysis phase's second request could not read any HTML. The old pipeline discarded its first successful response and failed the job.
- 22:30 (two entries), 22:29, 22:18 and 22:06: discovery returned no readable HTML. The helper swallowed transport errors/status context. These logs cannot establish whether the individual cause was DNS, a timeout, TLS, a firewall response or a non-HTML page.

No third-party customer website was re-scanned to investigate. Claims that all sites currently return 200, that specific hosts block Vercel, or that a particular domain is parked were not independently established by these logs.

## Changes

Discovery retains each bounded HTML/headers snapshot and analysis plus source-map discovery use that same evidence. It no longer needs a second successful page response. Cache lifetime is one scan, with at most 25 snapshots and a 2 MB response cap each. Redirect validation, socket DNS rebinding checks, HTTPS trust and private-address restrictions remain enabled.

A 25-second crawl budget, a 90-second request budget and bounded TXT lookups leave time for storage within the 120-second route limit. Initial discovery allows up to 12 seconds per response, bounded by the remaining crawl budget. Jobs with at least one readable page keep findings and report partial coverage when pages/requests fail or the request budget is reached. Block/challenge responses mark incomplete coverage. No HTML means no score. Partial reports are excluded from rescan comparisons and percentile claims. Email follow-ups disclose partial welcome coverage, suppress clean-outside claims, and do not claim resolved findings when either compared scan is partial. No claim is made that these budgets guarantee completion if a platform/storage process itself fails.

Main crawl redirects to a different hostname (apart from www normalization) stop with a request for the final authorized app URL, rather than scoring an unrelated destination. No bot-challenge bypass or user-agent impersonation was added.

Failure classification records a safe code and static message: timeout, DNS, TLS, blocked HTTP/challenge, HTTP error, non-HTML, empty HTML, body-size limit, redirect, network, internal. Cloudflare/Vercel labels are inferred only from response headers. Exception strings, bodies, secrets and redirected URLs are not persisted. `WebsiteScanDiagnostic` is an additive idempotent runtime table; no existing Scan columns are changed. Terminal failures now get a finish timestamp and retain existing credit refund handling. Diagnostic storage failures never discard a successful scan.

Report access checks run before diagnostic reads. Admin recent scans and user details show new failure reasons or explicitly say the older scan did not record a reason. Report pages show failure/partial state rather than presenting a failed job as a low or clean security score.

## Scoring

Weights and numeric scores are unchanged. The UI calls the number a public surface score, foregrounds the finding count, explains that repository code was not assessed by this website scan, and links to the repository workflow. It does not imply that URL/code constitute equal halves of a full security assessment. A separate repo scan might already exist; the coverage wording is deliberately scoped to this website report.

Critical/high findings override a green "Strong" presentation even if the existing number is high. No missing-repository score penalty was introduced.

Controlled examples evaluated against the existing formula (not customer scans):

| Findings | Existing score |
| --- | ---: |
| One critical sensitive-file finding | 91 |
| One medium headers finding | 95 |
| Eighteen medium headers findings | 89 |
| One critical SSL finding | 87 |

The category caps and diminishing returns explain why a high score can coexist with a serious finding. A future calibration should be risk-based and versioned, evaluated on representative reports, rather than silently lowering customer scores for conversion.

## Verification and rollback

The new fixture suite mocks all HTTP/DNS calls. It reproduces a successful first HTML response followed by blocked reads through the actual scanner pipeline, verifies retained findings/partial coverage and exhausted-budget behavior, classifies failures, checks direct/SSE persistence and refunds, and verifies storage-failure isolation. Existing transport/SSRF, report-sharing, anonymous gating, remediation, billing and email tests remain enabled.

Rollback the deployment to restore the previous pipeline if needed. The additive diagnostic table may remain; no destructive migration or backfill is needed. Older failures are not retroactively assigned speculative causes.
