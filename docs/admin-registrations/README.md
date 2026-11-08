# Daily registrations

Admin Overview includes a 7/30/90-day chart and accessible daily table. The new private, no-store `/api/admin/registrations` endpoint verifies the stored admin role before querying. It only returns aggregate dates/counts.

Buckets are calendar dates in Europe/Belgrade, including today so far. The previous adjacent period contains full days; the UI explicitly calls out the incomplete current day. This differs from the existing rolling 7/30-day cards. All account roles are included to match Total Users; test accounts are not inferred. Zero days are filled by the database; query failures show an error rather than zero growth.

No schema, plan, billing or email-delivery changes.

Verification: all 16 offline fixture suites, TypeScript, ESLint (0 errors; existing admin image warning), and production build with dummy DB/auth settings. SQL also ran against synthetic in-memory Postgres fixtures for midnight boundaries, both DST transitions, session timezone independence, and future-record exclusion. UI tested at 1440/390 px for all ranges, keyboard selection, empty state, failed request/retry and overflow.

Screenshots below contain explicitly synthetic Local QA fixture data, not customer records:

- [Desktop](fixture-1440.webp)
- [Mobile](fixture-390.webp)
