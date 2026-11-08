# Implementation notes

The UI and sequence examples are synthetic fixtures. No customer email was sent during implementation.

Verified with 17 offline fixture suites (including the new email suite), TypeScript, ESLint (zero errors, one pre-existing admin image warning), and a Next production webpack build. Turbopack in this restricted local environment could not bind its worker port; the equivalent webpack build succeeds. Vercel's actual deployment build remains a separate rollout gate.

The SQL was also executed twice in an isolated PGlite database. Live-key uniqueness, separate dry-run uniqueness and user-deletion cascades passed. No production database was used for fixture tests.

Browser QA uses the actual compiled components behind a local HTTP proxy with clearly synthetic admin/session/API responses. It does not bypass production authentication and never calls SES. Screenshots record the selected viewports and mock activity, not product traction or customer outcomes.

Infrastructure work and pending rollout gates are recorded separately in `ROLLOUT.md`. The two-day dry-run and real Gmail/Outlook/iCloud inbox/header checks cannot be replaced by fixtures or asserted ahead of time.

Final browser checks: 1440px desktop and 390px mobile (accounting for the browser's existing zoom), no page-level horizontal overflow, preview text visible, send-test disabled in off and unavailable modes, dashboard preference saved on/off, registration choice initially unchecked. A synthetic API failure shows a retryable message. Fixtures separately exercise authentication and same-origin API guards. Screenshots are under `qa/`.

- [Admin desktop](qa/admin-desktop.jpg), [mobile](qa/admin-mobile.jpg), [failure state](qa/admin-error-mobile.jpg)
- [Dashboard desktop](qa/dashboard-desktop.jpg), [mobile](qa/dashboard-mobile.jpg)
- [Registration desktop](qa/register-desktop.jpg), [mobile](qa/register-mobile.jpg)
