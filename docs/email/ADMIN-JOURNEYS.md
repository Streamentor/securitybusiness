# Email sequence operations

Open `/admin`, then **Emails**. All reads require the current session user to have an admin role in the database; responses are private and never cached.

- **User sequence progress** searches email, name or exact user ID, with 20 users per page. Filter enrollment candidates, users with customer-send history, unsubscribed, suppressed or paid accounts.
- **View timeline** shows actual customer send statuses, used send slots out of the six-message maximum, recorded delivery events, consent, unsubscribe, suppression, scheduler checks and any attributed paid upgrade. Selecting a user also fills the existing preview user ID.
- The next eligible check runs the sender's actual policy over future cron ticks. It is a forecast based on current scan data, not a queued guarantee. Upgrades, scans, opt-out, provider errors and global rate limits can change it.
- An unsent step marked **not applicable now** explains the current branch condition. It is not a stored historical skip decision. **Expired** means its send window passed; messages do not accumulate for catch-up.
- **Unknown** means the provider outcome was ambiguous. It is never displayed as delivered and that message is not retried automatically. Cancelled reservations retain their unique message key and are not forecast for retry.
- Admin tests and dry-run sends are listed separately and never advance customer progress. Delivered means receiver-server acceptance, not that someone opened or read a message. There are no open or click tracking pixels.
- **Scheduler health** records the most recent five cron outcomes, start/end, mode, examined accounts and accepted sends. The additive `EmailSequenceRun` table starts collecting at this release; no previous runs are invented. It stores no recipient, content, secret or exception detail. A health-log write failure never fails a scan or causes a send retry.

Enrollment remains free plan + explicit opt-in + account creation after `EMAIL_SEQUENCE_START_AT`. Existing accounts are not backfilled. A paid plan, opt-out, suppression or deletion stops future sending. Repo scan completion suppresses repeat repo invitations and first-scan reminders. Six-message lifetime, 44-hour spacing and 50-per-hour caps remain enforced.

## Owner-requested live rollout

On November 8, 2026 Stefan explicitly requested immediate live activation and waived the remaining 48-hour dry-run wait and Outlook/iCloud checks. Gmail verification had passed: Inbox / Updates, SPF/DKIM/DMARC PASS and signed one-click unsubscribe headers. This is not a guarantee of Inbox placement for other providers.

Production configuration is `EMAIL_SEQUENCE_MODE=live` with a fresh enrollment cutoff `2026-11-08T21:27:05.337Z`. The active production admin confirmed live mode after the configuration redeploy. No Preview sending or secret settings were changed. No deferred activation automation was created.
