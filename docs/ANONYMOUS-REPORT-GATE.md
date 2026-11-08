# Anonymous website report preview

Website scans start without signup. The completion screen opens the real report preview: score, visible severity counts, one complete finding (the stable free fix when available), and title/severity-only rows for the other findings. When no actionable fix exists, one real observation is still shown; an empty report never invents issues.

`serializeWebsiteFindings` is the shared server boundary for GET `/api/scan/[id]` and direct POST `/api/scan`. Locked rows are constructed with an allowlist and have no affected URL, description, remedy, or future evidence fields. Readiness metadata is excluded from anonymous previews. SSE completion contains counts only; anonymous HTML progress does not reveal page paths.

Registration unlocks evidence and locations, not all paid remedies. One free fix remains available and paid plans retain their existing entitlements. Valid owner-created sharing links bypass the registration gate and retain the existing plan-based remediation behavior. Creator cookie ownership, share revocation and compare-and-set claiming are unchanged.

## Login and welcome

The signup CTA passes a validated `scan` parameter and saves `pendingScanId`. OAuth receives `/scan/<id>` as its callback. Signup attribution also carries the scan ID in the existing referrer cookie, bound on the server to the HttpOnly creator proof. Password registration keeps the ID through the login return; it is removed only after a successful claim. Existing users who sign in can claim the report without being counted as a new account.

Welcome emails continue through the existing claim path and require the user's explicit optional email opt-in. Registration alone does not enroll somebody in the email sequence.

## Admin funnel

Admin > Overview > Anonymous scan conversion compares scans created in the 14 days before and after measurement initialization. The after cohort is labelled partial until its 14 days elapse. Conversions can mature later. These are scan counts, not unique people, and can contain bots/test scans.

The anonymous creator hash identifies scans that originally started without an account, even after claiming. Historical scans without a creator-proof row are excluded. Started/completed/claimed counts can be reconstructed; historical signup clicks, new-account attribution and paid attribution cannot, and display "Not recorded".

New events are idempotent per scan: signup CTA, actual new account (OAuth or password), successful claim, and a verified paid checkout after claim. An existing-account login does not record a signup. The CTA endpoint requires same-origin and browser creator proof. Admin metrics require the current database admin role and use private/no-store headers. Telemetry failures never fail registration, claims or billing.

`ScanFunnel` and singleton `ScanFunnelRollout` are created idempotently at runtime, following the repository's DDL pattern. No production migration command or backfill is required. The first anonymous report request or funnel event/admin view initializes measurement. Existing columns and billing behavior are unchanged. Rollback the deployment if necessary; the additive telemetry tables can remain.

## Validation

`verify-anonymous-report-gate.mjs` uses only auth, DB, scanner and fetch fixtures. It exercises anonymous GET and POST, SSE path privacy, shared links, authenticated free/paid behavior, metadata/future-field exclusion, stable sample selection, no-fix/empty reports, creator-bound CTA/signup, claim, paid telemetry, telemetry failure, OAuth return IDs and safe redirects. Existing sharing and remediation regressions remain enabled.

Browser QA uses clearly labelled synthetic data only; it does not create a real customer, send mail, charge a card or scan a third-party app. Desktop and narrow/mobile preview, registration navigation, opt-in default and admin funnel were checked. A fresh Google signup has not been performed as a live customer test.
