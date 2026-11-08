# Rollout record - 2026-11-08

Completed and observed in the signed-in browser:

- Existing AWS SES region: Frankfurt, eu-central-1. Sending quota is 50,000/day; account status Healthy.
- Domain identity scanmysaas.com: Verified. Easy DKIM signing enabled, RSA 2048, configuration Successful.
- Custom MAIL FROM bounce.scanmysaas.com: Successful, reject on MX failure.
- Hostinger: three SES DKIM CNAMEs, bounce MX priority 10 and bounce SPF added. Existing root Hostinger MX/SPF and website records preserved.
- DMARC remains p=none, with reporting to stefan@scanmysaas.com.
- Hostinger mailbox stefan@scanmysaas.com exists and is Active. Stefan confirmed the existing company address and reply address.
- Configuration set scanmysaas-onboarding created. Engagement tracking Disabled, custom redirect domain absent, archiving Disabled, TLS Required.
- Standard SNS topic scanmysaas-ses-events created. SES destination contains only Rejects, Deliveries, Hard bounces and Complaints. No Opens/Clicks.
- AWS account suppression already Enabled for Bounce and complaints; no suppressed addresses removed.
- Production-only non-secret email settings saved, including EMAIL_SEQUENCE_MODE=off. Credentials, signing secrets and START_AT are still absent.
- Vercel team has Pro. Production was Ready at main 5064f50 before this release; previous deployment is recorded privately for rollback.

Still required before any real sending:

- Dedicated IAM sending principal, its narrow policy, and new credentials. Browser policy requires action-time confirmation before creating security-sensitive access.
- SNS topic access policy permitting this configuration set to publish; exact expected ARN in Production, then signed HTTPS subscription confirmation after deployment.
- Production-only environment configuration, initially off. No email keys were created or exposed during implementation.
- Google Postmaster Tools ownership verification.
- Real admin test delivery and SPF/DKIM/DMARC/one-click header inspection.
- Two actual days of admin-only dry-run, then owner-controlled Gmail/Outlook/iCloud inbox checks.
- Live activation only after these gates, with START_AT reset to activation time. Existing accounts remain excluded.

No customer messages have been sent. Fixture tests and previews do not establish deliverability, inbox placement or conversion results.
