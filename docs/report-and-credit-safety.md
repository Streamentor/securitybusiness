# Report sharing, AI scoring and renewal credit safety

## Behavior

Unverified AI findings retain the existing confidence weights (high 50%, medium
25%, low 0%), but their combined score penalty cannot exceed 20 points. Rule
penalties and finding visibility are unchanged. Report reads and dashboard rows
recalculate saved scores too; no destructive report backfill is needed. Severity
labels still communicate potential risks independently of the capped score.

Website report IDs are no longer public access credentials, including for existing
reports. The account owner retains access. A new anonymous scan is bound to a
random HttpOnly, Secure-on-HTTPS, SameSite=Lax browser cookie for 30 days; a hash is
stored per scan. Only that browser can view or claim the unowned report, and claim
uses compare-and-set. Existing anonymous scans without creator proof cannot be
claimed by guessing their IDs. Previously public bare-ID links intentionally stop
working. Repository reports remain account-private.

An authenticated website-report owner can create a 256-bit random sharing token,
replace it (invalidating the previous token), or revoke it. Only its SHA-256 hash
is stored. The token is in the link fragment, not the HTTP URL; the page sends it
to the API in an explicit header. Sharing endpoints require same-origin requests
and account ownership. Shared views omit owner IDs and private scan comparisons;
existing viewer-plan remediation rules still apply. API responses are no-store,
and report pages use no-referrer/noindex. Revocation blocks subsequent server
reads; it cannot erase a copy someone already saved. No raw tokens are logged.

Recurring invoice fulfillment uses the Stripe invoice ID as the unique key, so
separate Stripe Event IDs for the same invoice are also deduplicated. The ledger
insert and atomic balance increment/rollover cap commit in one DB transaction.
A failed update rolls back the ledger, permitting a retry. Existing plan prices,
credit amounts and 2x rollover cap are unchanged. Credit consumption is preserved
because SQL uses the current locked balance, rather than a pre-read balance.
The period end cannot move backwards. Initial checkout fulfillment is unchanged.
The ledger starts at rollout; historical grants cannot be reconstructed from the
old schema and are not retroactively corrected by this change.

## Additive schema and recovery

Existing project pattern: `CREATE TABLE IF NOT EXISTS`, on first use, for new
`WebsiteReportAccess` and `InvoiceCreditGrant` tables. The former has an FK to
Scan with cascade deletion; the latter stores invoice/subscription IDs, not card
or source data. No existing table alteration, full-table rewrite, data deletion,
price change, environment change or production webhook replay is performed.

Rollback to the previous Vercel deployment can retain both tables. That version
would restore the older scoring, bare-ID access and renewal behavior, so rollback
is for a production regression, not a substitute for a forward security fix.

## Verification

13 offline verify scripts, TypeScript, ESLint (zero errors; existing admin image
warning) and required Next build with fake DB/auth. New fixtures cover token
rotation/revocation, cross-account and cross-origin denial, proof-bound atomic
claims, both anonymous scan transports, score cap on older results, concurrent
invoice retries, two Event IDs/one invoice, rollback/retry and rollover.

An additional manual check executed the exact store SQL in disposable in-memory
PostgreSQL (PGlite, outside repository dependencies): additive DDL, twenty parallel
same-invoice deliveries, transaction rollback/retry, existing rollover cap and
monotonic period all passed. This is local SQL evidence, not a production payment
or multi-server load test. No Stripe payment, invoice replay or customer credit
change was made for verification.

Stripe duplicate-event guidance:
https://docs.stripe.com/webhooks#handle-duplicate-events
