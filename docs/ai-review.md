# Repository AI logic review

The background job reads one commit once. `onFilesLoaded` exposes contents only to
its server-side callback, disables public result caching for that call, and never
adds source to the result. The callback sorts by the scanner's existing risk score.
AI review runs after rule checks; final scoring follows AI validation. A compare-and-set
job claim prevents two workers from processing the same queued job.

## Provider and privacy

Responses API, `store: false`, strict JSON-schema output, no tools, no automatic
retries. Default model `gpt-5.6-luna`; `gpt-5.6-terra` is allowed only for Pro/admin
when explicitly configured. Preview deployments never call the AI provider, even
if a key is accidentally present. No production configuration other than the two
requested OpenAI variables is needed. No repository source is logged or stored;
reports contain only redacted evidence excerpts. Credential signatures are shared
with the rule scanner and run before transmission and on every returned text field.
Redaction is best-effort, not a guarantee that all sensitive content is detected.
`store: false` disables response storage; it is not a promise of zero provider retention.

The current DB plan/role controls eligibility, including for public repositories.
Free scans never incur AI usage; their teaser does not invent a finding count.
A previously paid user reading an existing AI report after a downgrade receives only
rule findings, their recalculated rule-only score and the actual AI count teaser.
Dashboard lists omit result JSON entirely. A per-account opt-out is available in
the dashboard and connected repository picker, and applies to future reviews.

## Limits and accounting

- `AI_REVIEW_INPUT_TOKENS`: 60,000 by default, configurable downward, hard max 60,000.
- `AI_REVIEW_OUTPUT_TOKENS`: 3,000 per request by default, bounded to 500–6,000.
- At most two concurrent requests, one 40-second deadline, and no retries.
- Each batch's entire serialized request, including instructions and schema, must
  fit half the total input budget. UTF-8 byte count conservatively bounds tokenizer
  usage rather than relying on an optimistic characters/token estimate. Oversized
  files and tests/examples/generated files are skipped, not silently truncated.
- At most 15 accepted findings per scan. A sent file, in-range integer line, allowed
  enums, valid schema, and a real nearby source excerpt are required.
- Near-line findings with similar titles are deduplicated against rules and AI results.
- `AI_REVIEW_STARTER_MONTHLY_TOKENS`: 600,000; `AI_REVIEW_PRO_MONTHLY_TOKENS`: 2,000,000.
  These are UTC-calendar-month aggregate input+output token budgets, not website credits.
- Postgres atomically debits the worst-case input+max-output budget before sending
  anything. Successful responses release unused capacity based on actual usage.
  Timeouts, unknown usage and crashed jobs retain the conservative debit so a retry
  or concurrent instance cannot overspend the cap. Failure to debit fails closed.
- The same month key is retained across reservation and settlement at month boundaries.
- AI is skipped when fewer than five seconds remain before the job's 110-second
  working deadline, leaving time for final persistence inside the 120-second route.
- `AI_REVIEW_ENABLED=false` disables AI. Absent key, disabled preference, missing
  configuration, budget exhaustion or provider errors still yield rule-based reports.

AI score penalty: high-confidence = 50% of the normal severity penalty, medium =
25%, low = 0%. Round the aggregate score once. Provisional AI severity is downgraded
one tier for the risk label; low confidence cannot affect it. Rule scoring is unchanged.

## Storage and rollout

`ensureRepoTables` adds four nullable `RepoScan` columns (`aiModel`, `aiInputTokens`,
`aiOutputTokens`, `aiFindingsCount`) with `ADD COLUMN IF NOT EXISTS` and creates the
additive preference/usage tables. No existing column/data is dropped or rewritten.
Metadata token counts are known provider usage; the monthly debit can be higher
when a response was lost. Database account must permit these additive DDL statements,
consistent with the existing repository-store pattern. Rollback can retain the
nullable columns/tables and use the previous deployment without destructive cleanup.

Only add `OPENAI_API_KEY` and `OPENAI_REVIEW_MODEL=gpt-5.6-luna` to Vercel Production.
Do not add keys to Preview. Do not change Stripe prices, products or website credits.

## Evidence and verification

Official pricing checked 2026-11-07:
https://developers.openai.com/api/docs/pricing
Standard Luna input/output $0.20/$1.20 per million tokens; Terra $2/$12.
Input cache writes are priced at 1.25x normal input. The estimates below conservatively
charge every input token as a cache write; they are estimates from actual token usage,
not a provider invoice. No model substitutions were made.

Final-prompt manual benchmark (2026-11-07, Luna, real API, selected source only):

| Owner-authorized repository | Files reviewed | Input | Output | AI seconds | Total seconds | Estimated upper USD | Accepted findings |
| --- | ---: | ---: | ---: | ---: | ---: | ---: | ---: |
| Streamentor/securitybusiness, 49afd1f | 26 | 16,106 | 1,738 | 21.285 | 25.522 | 0.0061121 | 1 |
| stefanautomateed/securitybusiness, 00137a4 | 21 | 14,976 | 1,910 | 20.334 | 24.792 | 0.0060360 | 2 |
| Owner's private application (name withheld), 246b0bb | 13 | 15,346 | 1,698 | 20.304 | 25.047 | 0.0058741 | 2 |

All five proposed findings passed the schema/reference/evidence checks in this final
run. Independent static triage: four findings have concrete code support (the same
invoice-idempotency gap appears in two versions, plus two private-app control gaps).
One public-report access finding requires a product decision about intentionally
shareable reports. No accepted false positive was established, but runtime
exploitability was not tested and the context-dependent item is not counted as
confirmed. No unrelated defect was fixed in this feature. This tiny sample,
including two versions of the same product, is not a precision or recall benchmark.
Zero findings is never proof of security. The chosen monthly limits leave room for
repeat scans at the measured token sizes; reservations still use the larger safe bound.
Local `benchmark-results/` contains private evidence and is gitignored.

All `scripts/verify-*.mjs` are offline fixtures; `verify-ai-review.mjs` mocks fetch,
Prisma, auth and accounting. `benchmark-ai-review.mjs` is a separate, explicitly
opt-in manual tool, never called by verification or CI. Run with `--allow-real-api`
and optional `--repo=OWNER/NAME` flags, only for the two authorized owner namespaces.
It logs aggregate measurements only; key values, source and provider bodies are not logged.
