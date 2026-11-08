# ScanMySaaS email setup and rollout

Status: sending defaults to **off**, including every Preview deployment. Never enable live as part of the initial merge. No existing users are enrolled automatically. Registration offers an optional, unchecked email-updates choice; a positive choice is saved with a timestamp. OAuth carries that choice through the existing short-lived signup cookie. The start-date gate still applies to accounts that opt in later.

## AWS and DNS checklist

Use the existing SES region, **eu-central-1 (Frankfurt)**. Do not change any other business's identities, credentials, configuration sets or DNS.

1. Create the domain identity `scanmysaas.com`, **Easy DKIM, RSA 2048**, signing enabled. Publish the three generated CNAME records in Hostinger. Wait for Verified and DKIM Successful.
2. Set custom MAIL FROM to `bounce.scanmysaas.com`. Publish MX priority 10 pointing to `feedback-smtp.eu-central-1.amazonses.com`, and TXT `v=spf1 include:amazonses.com ~all` on **bounce**, not the root. Reject on MX failure. Leave the root Hostinger SPF and root MX unchanged. DKIM aligns with the visible From domain; the MAIL FROM subdomain uses relaxed SPF alignment.
3. Keep the existing DMARC policy at `p=none`; add `rua=mailto:stefan@scanmysaas.com` only after confirming that mailbox receives mail. After 2-4 weeks of clean reports, Stefan decides whether to change to `p=quarantine`. Do not automatically tighten it.
4. Verify production access in this region. Sandbox accounts need an honest production-access request: registered users, scan-related onboarding, opt-in, one-click unsubscribe and bounce/complaint suppression. Do not describe purchased lists or bulk cold outreach.
5. Create configuration set **scanmysaas-onboarding**. Do not enable a redirect domain, Open/Click event publishing, engagement tracking, archiving, paid validation or dedicated IPs. Override VDM engagement tracking to **Disabled** even if the account default is enabled. Require TLS for delivery.
6. Create a **Standard** SNS topic `scanmysaas-ses-events` in the same region. Allow only `ses.amazonaws.com` to publish, constrained by the AWS account and this configuration set's SourceArn. Configure SES events **Bounce, Complaint, Reject, Delivery** only. Add an HTTPS subscription to `https://www.scanmysaas.com/api/email/ses-events` after the endpoint is deployed and the expected TopicArn is configured. The endpoint verifies signatures before auto-confirming. Do not turn on raw SNS delivery: it needs the signed envelope.
7. Enable or confirm account-level suppression for permanent bounces and complaints. Do not clear existing suppressed addresses. The app additionally suppresses Reject notifications.
8. Create a dedicated IAM principal with only `ses:SendEmail` and `ses:SendRawEmail` for this domain identity and configuration set. Restrict `ses:FromAddress` to `stefan@scanmysaas.com`. No console access, list permissions or broad SES admin policy. New credentials/permissions require the browser's action-time approval. Do not reuse another business's broad AWS keys. See `docs/email/iam-send-policy.json`.
9. Verify `stefan@scanmysaas.com` is a real monitored mailbox in Hostinger. Set it as From and Reply-To. Stefan confirmed the existing company postal address: **Content Petit LLC, 16192 Coastal Highway, Lewes, Delaware 19958, United States**. Do not fabricate an address if the company changes.
10. Verify `scanmysaas.com` in Google Postmaster Tools, using its actual DNS challenge. Watch spam rate. Gmail's published maximum is 0.3%; this rollout's operational pause threshold is **0.1%**. If exceeded, set mode off and investigate consent, targeting and content.

References: [SESv2 Message custom headers](https://docs.aws.amazon.com/ses/latest/APIReference-V2/API_Message.html), [SNS signature verification](https://docs.aws.amazon.com/sns/latest/dg/sns-verify-signature-of-message.html), [Gmail sender guidelines](https://support.google.com/mail/answer/81126?hl=en), [Vercel cron limits](https://vercel.com/docs/cron-jobs/usage-and-pricing).

## Vercel Production only

Configure these in the `securitybusiness-n767` project, **Production only**. Mark secrets sensitive. Never paste keys in chat, commit them, expose them to the client, log environment contents, or add them to Preview.

- `AWS_SES_REGION=eu-central-1`
- `AWS_SES_ACCESS_KEY_ID` and `AWS_SES_SECRET_ACCESS_KEY`: dedicated IAM sending credentials
- `AWS_SES_SNS_TOPIC_ARN`: exact topic ARN from AWS
- `EMAIL_FROM=Stefan from ScanMySaaS <stefan@scanmysaas.com>`
- `EMAIL_REPLY_TO=stefan@scanmysaas.com`
- `EMAIL_POSTAL_ADDRESS=Content Petit LLC, 16192 Coastal Highway, Lewes, Delaware 19958, United States`
- `EMAIL_SEQUENCE_MODE=off` initially; allowed values `off`, `dry-run`, `live`
- `EMAIL_SEQUENCE_START_AT`: a valid UTC ISO timestamp. Required even in dry-run. Reset to the actual activation time when switching live; do not backdate to enroll old accounts.
- `EMAIL_UNSUBSCRIBE_SECRET`: at least 32 random bytes, preferably 64 hex characters. Retain it: rotation invalidates existing unsubscribe links.
- `CRON_SECRET`: a separate random secret for Vercel's Bearer-authenticated cron calls. Preserve any existing cron secret rather than rotating it unnecessarily.

The code always passes `ConfigurationSetName=scanmysaas-onboarding`. SESv2 Simple supports custom headers, so it assembles multipart/alternative from Text and Html. Both unsubscribe headers and Reply-To are included. The HTML twin contains only paragraphs and direct links. UTMs are campaign labels, not a click tracking redirect.

## Timing and safety decisions

The original brief asks for hourly scheduling and a stable 0-40 minute delay within the user's signup hour. One hourly tick cannot deliver all those minute offsets. `vercel.json` therefore checks at minutes **0, 10, 20, 30, 40** of each hour (Pro plan verified). The deterministic jitter is rounded forward to the next tick, staying within 0-40 minutes. A database lock limits live reservations to **50 in any rolling hour**, not 50 per tick. Admin tests have their own 50/hour cap. Candidates rotate by their last check time, so a large cohort cannot permanently starve newer users. No paid infrastructure upgrade is needed.

The signup hour is **UTC**, not inferred local time. Hours 00-05 shift to 08 UTC. Delayed cron calls cannot send follow-ups outside that hour. Welcome has a 10-minute window after the first completed scan/claim, and bypasses the hour rule. The **44-hour minimum gap** and **six-message lifetime maximum** always win, including no-scan reminders and ambiguous sends. A day-1 note following welcome usually runs on day 2 at the signup hour. Copy says "latest scan", not "yesterday". Each slot has an expiry; missed slots are skipped instead of creating a backlog. Rescan reminders additionally require the actual unused verification window to be 1-3 days away.

The main anchor is the later of account creation and the first completed owned scan. This includes a claimed pre-signup scan. A first scan later than 14 days after signup does not start the main sequence. No-scan reminders stop after their second slot. No message claims that historical findings prove vulnerabilities are still present now. Comparison numbers refer to finding groups, matching the report comparison, rather than pretending to count resolved URL instances.

`EmailPreference`, `EmailSend`, `EmailTestSend`, `EmailEvent`, and `EmailConversion` use idempotent runtime DDL, with user foreign keys cascading on account deletion. No Prisma migration or destructive schema change is used. Runtime DDL is cached per process. Deployments with mode off do not run the cron's queries. Admin/preferences pages initialize the tables on first use.

A unique `(userId,emailKey)` record is committed **before** live sending. User-row locks serialize reservations, final eligibility checks, opt-outs, suppression, upgrades and deletion. The final send transaction holds that lock only for a bounded SES attempt (8 seconds; transaction 15 seconds). AWS retries are disabled. A timeout, process crash or uncertain acknowledgement retains a `sending`/`unknown` reservation and consumes the key and caps: **no automatic resend**. SNS may reconcile it using the opaque `send_id` tag. Investigate uncertain outcomes in SES before taking any manual action. Do not delete reservations to retry them.

Dry-run records are separate from live keys. Only a database-admin address receives them, prefixed `[dry-run → intended recipient]`. Previewing does not send. No email bodies, recipient lists, tokens or findings are logged to server logs. Test events suppress the **admin recipient**, not the user whose data was previewed. Delivery events never remove a complaint/bounce suppression.

GET on the signed unsubscribe URL opts out and shows a confirmation page. POST is the empty 200 one-click path. Resubscribe requires a signed-in, same-origin dashboard action; link scanners and GET requests cannot enable sending. The toggle cannot clear a suppression. Replies cannot be detected by SES sending alone, so reply-based exit is not claimed or automated.

## Rollout gates

1. Merge/build with mode **off**, verify Ready deployment, dashboard and admin Emails/registration chart. Confirm anonymous users cannot read email/admin data. Preview sends nothing.
2. Complete the DNS, mailbox, SNS, IAM and Production environment checks above. Confirm SNS subscription and account suppression.
3. Set mode **dry-run** and record activation UTC time. Spend **two actual days** reviewing admin-only emails. Use the admin preview for every key; a missing required variable must skip, never send broken copy.
4. Use "Send test to me" from the intended admin account. Check Gmail "Show original": SPF, DKIM and DMARC PASS, both List-Unsubscribe headers, readable plain text, no pixel and no rewritten links. Separately test owner-controlled Gmail, Outlook and iCloud mailboxes. The app's test endpoint intentionally cannot target arbitrary addresses; use an admin account with the desired owner-controlled address or an explicitly authorized SES test. Do not create customer accounts or mail third parties for testing.
5. Record where each test lands. Plain text does **not guarantee Inbox** or avoid Promotions. If a test lands elsewhere, investigate authentication/reputation/content before live. Never claim an inbox result that was not observed.
6. Only after the two-day review and mailbox checks, switch to **live** and set START_AT to that switch time. Redeploy Production for changed env variables. Do not retroactively send to the existing user base.
7. After two weeks, review per-key sends, delivery events, permanent bounces, complaints, unsubscribes and first paid checkouts within seven days. Checkout carries only a validated campaign/send ID in Stripe metadata, checked against an actual owned send. The webhook must report `payment_status=paid`. Each user can count once. This is **UTM-associated conversion**, not a claim that the email caused it. No opens/clicks are measured. Attribution failure must never break billing.

Pause: mode off + redeploy. This keeps reports, preferences and SNS handling available. Emergency code recovery: Vercel Instant Rollback to the previous Ready deployment. Additive email tables need not be dropped on rollback.

## Privacy copy for review

> If you opt in, we send short onboarding and product emails based on your own scan data, such as findings, saved reports and verification rescan availability. Amazon Simple Email Service (SES) processes the recipient address and email content for delivery. We do not use open-tracking pixels or click-tracking redirects. We keep send, delivery, bounce, complaint and unsubscribe records to operate the service and prevent unwanted messages. Unsubscribe using any email footer or change Email updates in your dashboard. Unsubscribing does not clear a bounce or complaint suppression.
