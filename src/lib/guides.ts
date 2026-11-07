export interface GuideSection {
  heading: string;
  paragraphs: string[];
  bullets?: string[];
}

export interface Guide {
  slug: string;
  title: string;
  description: string;
  eyebrow: string;
  readTime: string;
  publishedAt?: string;
  updatedAt?: string;
  relatedChecks: string[];
  intro: string[];
  sections: GuideSection[];
  sources?: Array<{ label: string; url: string }>;
}

export const guides: Guide[] = [
  {
    slug: "saas-launch-security-checklist",
    title: "SaaS launch security checklist for vibe-coded apps",
    description: "Check tenant isolation, Supabase RLS, sessions, Stripe webhooks, and public exposure before your SaaS launch, with a find, fix, and retest worksheet.",
    eyebrow: "Before you launch",
    readTime: "9 min read",
    publishedAt: "2026-09-06",
    updatedAt: "2026-09-06",
    relatedChecks: ["Public security headers", "Exposed files", "Cookie settings", "Repository secret patterns"],
    intro: [
      "Before you send Product Hunt visitors or your first paying customers to a new SaaS, check what each person is allowed to do. A successful signup and checkout demonstrate the happy path. They do not show whether a different account can read a private document or unlock a paid feature without paying.",
      "Use this vibe coding security checklist on an app you own or are authorized to test. It combines manual checks behind login with a review of the deployed public surface. Keep evidence for each result, fix the failures, and repeat the same checks on the release you intend to launch.",
    ],
    sections: [
      {
        heading: "1. Prepare two test tenants and an anonymous session",
        paragraphs: [
          "Use a staging environment with production-like authorization settings and synthetic data. Create tenant A and tenant B, each with an account and a private test record. Add an ordinary member and an administrator when your app has roles. Keep a separate browser profile with no login. Use your own mailboxes and a Stripe sandbox; do not use customer records or real charges for these checks.",
          "Write the expected permissions before testing. For example: an A member may read A's document, cannot read B's document, and cannot invite an administrator. A visitor with no session cannot access either private document. If cross-tenant sharing is intentional, record exactly which operation is allowed.",
        ],
        bullets: [
          "Record the environment, deployment or commit, test account roles, and synthetic record IDs.",
          "Use separate browser profiles so switching accounts does not silently reuse the same session.",
          "Mark each result Pass, Fail, Not tested, or Not applicable. Missing evidence is not a pass.",
        ],
      },
      {
        heading: "2. Test permissions at the request boundary",
        paragraphs: [
          "In your own test environment, use browser developer tools to inspect a request for a private record. While signed in as A, repeat the request with B's known test record ID. Check both the response and stored data: hiding a button or returning an error message is insufficient if the server still performs the action. OWASP recommends checking authorization on every request.",
          "Repeat the check for reads, edits, deletes, exports, invitations, and role changes that your app supports. Test the ordinary member against administrator-only actions. Confirm the legitimate owner can still perform the intended operation; blocking everyone can make a broken feature look protected.",
        ],
        bullets: [
          "No session: private responses reveal no protected data and make no unauthorized changes.",
          "Tenant A requesting B's record: the request is denied or returns no unauthorized rows; B's data stays unchanged.",
          "Member requesting an admin action: the server checks current membership and role, independent of client-supplied IDs.",
          "Owner performing an allowed action: the expected data is returned or changed successfully.",
        ],
      },
      {
        heading: "3. Check Supabase RLS through the real client path",
        paragraphs: [
          "If you use Supabase, review table grants and Row Level Security together. Exercise requests with the publishable or legacy anon key and no user session, then with each test user's session. Do not use an administrative SQL connection or a privileged server key to judge what a browser user can access. Test the roles and connection path the application actually uses.",
          "Check SELECT, INSERT, UPDATE, and DELETE separately. For updates, test whether a user can change a row's owner or tenant; a policy must constrain the resulting row as well as the existing one. Verify policies against the deployed database rather than assuming a migration file reflects its current state.",
        ],
        bullets: [
          "Private tables: enable RLS and grant only the operations that the intended roles need.",
          "Public content: confirm only the intended rows are readable and visitors cannot write them.",
          "Privileged Supabase secret or service-role keys: keep them out of browser bundles and public environment prefixes.",
          "Server routes using privileged clients: perform their own user, tenant, and role checks before querying.",
        ],
      },
      {
        heading: "4. Include files, sessions, and account changes",
        paragraphs: [
          "Use a harmless test file to check storage permissions. As A, try to read, overwrite, and delete B's private file through the app's normal API path. Inspect bucket visibility and storage policies separately from table policies. Public buckets are intended for public content; a hard-to-guess filename is not a private-file access control.",
          "Exercise login, password reset, account switching, and logout with your test accounts. Confirm session cookies use appropriate Secure, HttpOnly, and SameSite settings where your authentication design uses cookies. Inspect actual network responses rather than relying on a dashboard screenshot.",
        ],
        bullets: [
          "After logout, confirm the client session is cleared and protected requests follow your documented token expiry and revocation behavior.",
          "After removing a test member, verify that they lose the access your membership policy says should end.",
          "Keep test tokens and reset links out of screenshots, shared reports, analytics, and coding-agent prompts.",
        ],
      },
      {
        heading: "5. Verify Stripe payments on the server",
        paragraphs: [
          "In a Stripe sandbox, complete one test purchase and confirm that the correct account receives the correct entitlement once. Opening a success URL or changing a browser-supplied plan must not independently grant paid access. Your server should verify the relevant Checkout Session and payment or subscription state; Stripe documents webhooks as necessary for reliable fulfillment.",
          "Verify webhook signatures against the raw request body with the signing secret for that endpoint. Test an invalid signature and confirm it causes no entitlement change. The secret used by a local Stripe CLI listener can differ from the registered endpoint's secret.",
        ],
        bullets: [
          "Retry the same sandbox event and confirm credits or access are not granted twice, including concurrent processing.",
          "Test relevant delayed, failed, and out-of-order events; an old event must not incorrectly restore or remove current access.",
          "Close the browser before the success redirect and confirm the webhook still completes eligible fulfillment.",
          "Keep test and live keys, webhook secrets, and customer records separate; inspect the configured live destination before launch.",
        ],
      },
      {
        heading: "6. Inspect the public deployment and record coverage gaps",
        paragraphs: [
          "Scan the final public hostname after deploying. ScanMySaaS can inspect observable signals such as headers, transport, cookies, and exposed files on reachable public pages. Its separate public GitHub scan reads a bounded set of files from the current tree for security-relevant patterns. It does not execute the repository or search full Git history; private repository support is not part of that public scan.",
          "These checks cannot prove the tenant, RLS, storage, session-revocation, or Stripe entitlement tests above have passed. A repository hint about a missing policy is not a live authorization test. A clean public report is not security certification. Record untested boundaries explicitly and use the relevant platform checks and manual review alongside the report.",
        ],
        bullets: [
          "Confirm the hostname and deployed version match the app people will actually use.",
          "For every finding, keep the affected location and redacted evidence; distinguish a verified exposure from a hardening recommendation.",
          "After header or hosting changes, recheck signup, login, checkout, and external integrations for regressions.",
        ],
      },
      {
        heading: "7. Copy this find, fix, and retest worksheet",
        paragraphs: [
          "Create one entry per failed check in your issue tracker. The format below works for a manual authorization failure or an automated public finding. Keep raw tokens and private customer data out of the entry.",
        ],
        bullets: [
          "Find: environment and release; test actor and role; affected route, file, or object; expected result; actual result; redacted evidence.",
          "Prioritize: what data or action is exposed; which users are affected; confirmed failure or unverified signal; owner and planned fix.",
          "Fix: smallest reviewed change; deployment reference; rollback plan; any connected flows that need checking.",
          "Retest: repeat the original failing request with the same test roles, then verify the legitimate user's allowed action still succeeds.",
          "Record: retest time and release; new evidence; remaining gaps; Pass, Fail, or Not tested. Close only the check the evidence actually resolves.",
        ],
      },
      {
        heading: "Decide whether this release is ready for visitors",
        paragraphs: [
          "Treat unauthorized access to another tenant's data, exposed privileged credentials, and incorrect paid entitlements as launch blockers until they are contained and fixed. Give other verified findings an owner and an explicit decision. Do not make every missing hardening header look like the same level of risk.",
          "Keep the worksheet with the release and rerun affected checks after changes to authentication, database policies, billing, hosting, or membership rules. The useful outcome is a repeatable check and evidence of the fix, not a one-time score.",
        ],
      },
    ],
    sources: [
      { label: "OWASP: Authorization checks and testing", url: "https://cheatsheetseries.owasp.org/cheatsheets/Authorization_Cheat_Sheet.html" },
      { label: "OWASP: Multi-tenant isolation and verification", url: "https://cheatsheetseries.owasp.org/cheatsheets/Multi_Tenant_Security_Cheat_Sheet.html" },
      { label: "OWASP: Session management", url: "https://cheatsheetseries.owasp.org/cheatsheets/Session_Management_Cheat_Sheet.html" },
      { label: "Supabase: Row Level Security", url: "https://supabase.com/docs/guides/database/postgres/row-level-security" },
      { label: "Supabase: Publishable and secret API keys", url: "https://supabase.com/docs/guides/getting-started/api-keys" },
      { label: "Supabase: Storage access control", url: "https://supabase.com/docs/guides/storage/security/access-control" },
      { label: "Stripe: Webhook signatures, retries, and duplicate events", url: "https://docs.stripe.com/webhooks" },
      { label: "Stripe: Checkout fulfillment", url: "https://docs.stripe.com/checkout/fulfillment?payment-ui=stripe-hosted" },
    ],
  },
  {
    slug: "security-headers-for-saas",
    title: "Security headers for SaaS: what to add first",
    description: "A practical guide to CSP, HSTS, clickjacking protection, MIME sniffing, referrer policy, and permissions policy for SaaS teams.",
    eyebrow: "Browser security",
    readTime: "8 min read",
    relatedChecks: ["Content Security Policy", "HSTS", "X-Frame-Options", "X-Content-Type-Options"],
    intro: [
      "Security headers are small response headers with an outsized job. They tell a browser which scripts may run, whether a page may be framed, and whether an insecure connection is acceptable. A SaaS can have solid application code and still leave these browser defenses unset.",
      "The hard part is not adding every possible header. It is choosing a safe order, measuring what breaks, and avoiding a copied policy that does not match your product.",
    ],
    sections: [
      {
        heading: "Start with the headers that close clear gaps",
        paragraphs: ["For most SaaS products, four headers deserve attention first. They cover transport, framing, content interpretation, and script execution."],
        bullets: [
          "Strict-Transport-Security tells supporting browsers to return over HTTPS after the first secure visit.",
          "Content-Security-Policy limits where scripts, styles, images, frames, and connections may come from.",
          "X-Content-Type-Options: nosniff stops a browser from guessing a different content type.",
          "frame-ancestors in CSP, or X-Frame-Options for older clients, limits clickjacking through hostile frames.",
        ],
      },
      {
        heading: "Roll out CSP without breaking production",
        paragraphs: [
          "A strict CSP copied from another app can block payments, analytics, support widgets, or your own inline code. Begin with Content-Security-Policy-Report-Only, collect violations, and map each required third party to the narrowest directive that allows it.",
          "Avoid treating unsafe-inline and a wildcard as the finished policy. They may make the report quiet while leaving much of the original risk in place. Nonces or hashes are a better long-term answer for inline scripts.",
        ],
        bullets: [
          "Inventory scripts, API connections, images, fonts, frames, and form destinations.",
          "Ship a report-only policy and watch real routes, including login, checkout, and password reset.",
          "Replace broad sources with exact hosts, nonces, or hashes.",
          "Move to an enforced policy and keep violation reporting during later releases.",
        ],
      },
      {
        heading: "Do not enable HSTS by reflex",
        paragraphs: [
          "HSTS is valuable only when every affected hostname is ready for HTTPS. Start with a shorter max-age on the primary host. Add includeSubDomains after checking forgotten subdomains, status pages, and customer-facing custom domains. Preload is a separate commitment and is difficult to undo quickly.",
          "Also keep the server-side HTTP to HTTPS redirect. HSTS improves repeat visits, but a new visitor can still arrive over HTTP before the browser has learned the policy.",
        ],
      },
      {
        heading: "A sensible release check",
        paragraphs: ["Test headers on the final public response, not only in application code. A CDN, reverse proxy, or hosting platform can add, remove, or duplicate them. Scan the production hostname after deployment, open important flows manually, and keep the change easy to roll back."],
      },
    ],
  },
  {
    slug: "ssl-tls-checklist-for-saas",
    title: "SSL and TLS checklist for a production SaaS",
    description: "Check certificate trust and expiry, HTTPS redirects, HSTS, mixed content, cookies, and redirect chains before they become incidents.",
    eyebrow: "Transport security",
    readTime: "7 min read",
    relatedChecks: ["Certificate expiry", "HTTPS redirect", "HSTS", "Mixed content"],
    intro: [
      "A valid padlock is the beginning of transport security, not the end. SaaS traffic can still pass through an HTTP redirect, load an insecure asset, or lose cookie protection because one layer of the stack sees the wrong protocol.",
      "Treat TLS as a path from the first request to the final application response. Every hop matters.",
    ],
    sections: [
      {
        heading: "Verify the certificate as a customer sees it",
        paragraphs: ["Check the production hostname with Server Name Indication, confirm the certificate chain is trusted, and record the expiry date. If your platform renews certificates automatically, alerting still matters. DNS changes, failed challenges, or an abandoned custom domain can interrupt renewal."],
        bullets: [
          "The certificate covers the exact hostname users visit.",
          "The full chain is trusted by common clients.",
          "Expiry monitoring leaves enough time to investigate a failed renewal.",
          "Old or customer-managed domains have a clear ownership and removal process.",
        ],
      },
      {
        heading: "Make the first redirect secure and direct",
        paragraphs: [
          "An HTTP request should move straight to the final HTTPS hostname. Avoid a chain that first adds www, then adds HTTPS, then changes a trailing slash. Each extra hop is slower and creates another configuration surface.",
          "Update internal links, canonical URLs, emails, and marketing redirects to point at the final HTTPS destination. Redirects are a fallback, not a substitute for correct links.",
        ],
      },
      {
        heading: "Check the layers behind the proxy",
        paragraphs: ["Many SaaS apps terminate TLS at a CDN or load balancer. The application must trust forwarded protocol headers only from known proxies. Otherwise it may create HTTP links, skip Secure cookies, or enter a redirect loop."],
        bullets: [
          "Set session cookies with Secure, HttpOnly, and an intentional SameSite policy.",
          "Search rendered HTML and CSS for http:// assets or form actions.",
          "Confirm webhooks and API callbacks use current TLS endpoints.",
          "Recheck transport behavior after CDN, proxy, or custom-domain changes.",
        ],
      },
      {
        heading: "Add HSTS after the route is clean",
        paragraphs: ["Once HTTPS works across the required hostnames, add HSTS in stages. A short first max-age makes mistakes recoverable. Increase it after normal product traffic, login, billing, and subdomains have been exercised."],
      },
    ],
  },
  {
    slug: "robots-txt-and-sitemap-for-saas",
    title: "robots.txt and XML sitemaps for SaaS websites",
    description: "Configure robots.txt and XML sitemaps without leaking private routes or accidentally blocking the public pages that should rank.",
    eyebrow: "Technical SEO",
    readTime: "7 min read",
    relatedChecks: ["robots.txt", "XML sitemap", "Indexability", "Canonical URL"],
    intro: [
      "robots.txt and an XML sitemap solve different problems. One gives crawlers instructions. The other gives search engines a clean list of canonical public URLs. Neither file protects a private page.",
      "For SaaS sites, the common failure is mixing the marketing site with the logged-in product. Public guides belong in the sitemap. Account, billing, internal API, and dashboard routes usually do not.",
    ],
    sections: [
      {
        heading: "Use robots.txt for crawl guidance, not access control",
        paragraphs: ["A disallowed path is still public. Anyone can read robots.txt, and a URL may still be indexed from links elsewhere. Protect sensitive routes with authentication and authorization. Use noindex on a public page when the goal is to keep that page out of search results."],
        bullets: [
          "Keep production robots.txt available at the root hostname.",
          "Do not block CSS or JavaScript needed to render public pages.",
          "Reference the canonical sitemap URL.",
          "Review broad rules such as Disallow: / before every launch.",
        ],
      },
      {
        heading: "Build a sitemap from pages worth indexing",
        paragraphs: [
          "Include canonical, indexable URLs that return a successful response. Exclude dashboard screens, search results, temporary campaign variants, redirected URLs, and routes that carry private identifiers.",
          "The sitemap should agree with the page. A URL marked noindex or canonicalized to another page should not be listed as if it were a primary result.",
        ],
      },
      {
        heading: "Separate product and marketing surfaces",
        paragraphs: ["If the app and marketing site share one host, make ownership explicit. The marketing build can generate the sitemap while product routes default to noindex where appropriate. If they use separate hosts, give each host its own crawl rules and only publish a sitemap for content that should be found."],
        bullets: [
          "Homepage, pricing, feature pages, comparisons, and useful guides are typical sitemap entries.",
          "Login may be crawlable but rarely needs high sitemap priority.",
          "Authenticated dashboards should not rely on robots.txt for privacy.",
          "Staging hosts should require access control and stay outside public sitemaps.",
        ],
      },
      {
        heading: "Test the files after deployment",
        paragraphs: ["Fetch both files from the public domain, follow a sample of sitemap URLs, and check their status, canonical, and robots directives. Then submit the sitemap through your search engine tooling and watch for excluded or redirected entries."],
      },
    ],
  },
  {
    slug: "llms-txt-for-saas",
    title: "llms.txt for SaaS: useful file, realistic expectations",
    description: "What an llms.txt file can communicate, what it cannot guarantee, and how to publish a concise version for a SaaS product.",
    eyebrow: "AI discovery",
    readTime: "6 min read",
    relatedChecks: ["llms.txt", "Canonical links", "Public documentation", "XML sitemap"],
    intro: [
      "An llms.txt file is a plain-text guide placed at the root of a website. Its purpose is to give compatible AI systems a compact description of the product and point them toward the most useful public pages.",
      "It is not a switch for rankings or AI answers. Google has said its systems do not use llms.txt for AI Overviews or AI Mode. The file can still be a tidy machine-readable map for tools that choose to read it.",
    ],
    sections: [
      {
        heading: "Write for retrieval, not promotion",
        paragraphs: ["Open with the product name and one factual sentence. Then list the pages that answer real questions: documentation, pricing, security, terms, contact, and the XML sitemap. Keep claims consistent with visible pages."],
        bullets: [
          "Use stable canonical HTTPS links.",
          "State important limitations next to capabilities.",
          "Keep plan details on the pricing page if they change often.",
          "Avoid keyword lists, testimonials without sources, or hidden claims.",
        ],
      },
      {
        heading: "Keep the short file short",
        paragraphs: ["The root file should help a system choose what to read next. A separate llms-full.txt can hold a longer product summary, but it should still link back to canonical web pages rather than becoming a shadow version of the whole site."],
      },
      {
        heading: "Pair it with foundations that search engines use",
        paragraphs: [
          "A clean sitemap, crawlable pages, descriptive titles, useful body content, canonical URLs, and accurate structured data remain the practical foundation. llms.txt does not replace any of them.",
          "If you want AI systems to understand a feature, explain that feature on a normal public page first. The machine-readable file should summarize and route, not introduce a different story.",
        ],
      },
      {
        heading: "Maintain it like documentation",
        paragraphs: ["Check the file during releases that change pricing, product names, public routes, or ownership. Broken links and stale plan claims make the file less trustworthy. A scanner can verify that the file exists and that its important links are reachable, but usefulness still depends on careful editing."],
      },
    ],
    sources: [
      { label: "Google Search Central: Optimizing for generative AI features", url: "https://developers.google.com/search/docs/fundamentals/ai-optimization-guide" },
    ],
  },
  {
    slug: "exposed-files-and-source-maps",
    title: "Exposed files and source maps in production",
    description: "Find and remove public environment files, Git metadata, backups, debug pages, and JavaScript source maps from a SaaS deployment.",
    eyebrow: "Application exposure",
    readTime: "8 min read",
    relatedChecks: [".env exposure", "Git metadata", "Backup files", "Source maps"],
    intro: [
      "A deployment can work perfectly while publishing files that were never meant for a browser. Environment files, repository metadata, database backups, logs, and source maps often appear because the build artifact is too broad or the web root points at the wrong directory.",
      "The first response is containment. The second is fixing the pipeline that allowed the file to ship.",
    ],
    sections: [
      {
        heading: "Treat confirmed secrets as compromised",
        paragraphs: ["If a public file contains credentials, removing the file is not enough. Rotate the exposed values, review access logs, and identify what each credential could reach. A secret may have been copied before your scan found it."],
        bullets: [
          "Remove public access or take the affected deployment offline.",
          "Rotate API keys, database passwords, signing secrets, and tokens found in the file.",
          "Review provider and application logs for unexpected use.",
          "Document the incident and any required user or regulator notification.",
        ],
      },
      {
        heading: "Publish a build artifact, not the repository",
        paragraphs: ["The safest deployment copies only the files needed at runtime. Do not sync the entire working directory to a web root. Keep .git, local environment files, test fixtures, SQL exports, and editor artifacts outside the published output."],
        bullets: [
          "Use a clean build directory created in CI.",
          "Inspect the artifact before upload and fail the build on forbidden patterns.",
          "Configure the server to deny dotfiles and backup extensions as a second layer.",
          "Keep backups in private object storage, never beside public application assets.",
        ],
      },
      {
        heading: "Handle source maps deliberately",
        paragraphs: [
          "Browser source maps can reveal readable source, file paths, comments, and internal names. That does not automatically create an exploit, but it gives an attacker a much clearer map of the client application.",
          "If an error-monitoring service needs source maps, generate them in CI, upload them privately, and exclude them from the public artifact. Also remove sourceMappingURL references when your build tool leaves them behind.",
        ],
      },
      {
        heading: "Verify the fix from outside",
        paragraphs: ["Test the exact production URLs after redeploying. A CDN may cache the old file even after it disappears from the origin. Purge the relevant paths, confirm they return a real 404 or access denial, and run a fresh scan against the public hostname."],
      },
    ],
  },
  {
    slug: "github-secret-scanning-for-vibe-coded-apps",
    title: "GitHub secret scanning for vibe-coded apps",
    description: "What to do when an AI-built app commits an .env file, API key, database URL, private key, or service credential to GitHub.",
    eyebrow: "Repository security",
    readTime: "8 min read",
    relatedChecks: ["Committed .env files", "Provider tokens", "Private keys", "Database URLs"],
    intro: [
      "A committed secret is an incident, even when the repository is private and the file was deleted five minutes later. Git keeps history. Build logs, forks, caches, and local clones may keep another copy.",
      "The response order matters more than the cleanup command. Revoke the credential first. Then remove the value from the repository and close the path that allowed it to be committed.",
    ],
    sections: [
      {
        heading: "Assume the value was copied",
        paragraphs: ["Do not wait for evidence that someone used the key. Rotate an exposed database password, API token, signing secret, or private key from the provider that issued it. Check audit logs and narrow the replacement credential to the permissions the app actually needs."],
        bullets: [
          "Revoke or rotate the credential at its source.",
          "Review provider logs from the first public commit onward.",
          "Replace broad account keys with service-specific credentials.",
          "Record which systems and customer data the old value could reach.",
        ],
      },
      {
        heading: "Deleting the file does not delete Git history",
        paragraphs: [
          "A later commit that removes .env only changes the current tree. The earlier blob remains in history until it is rewritten. Coordinate a history cleanup with collaborators because rewritten commits change hashes and require fresh clones or careful rebases.",
          "History cleanup is not a substitute for rotation. It reduces future discovery, but it cannot recall a value that was already copied.",
        ],
      },
      {
        heading: "Fix the path that produced the leak",
        paragraphs: ["Add .env* and local credential files to the root .gitignore. Keep a scrubbed .env.example with variable names and safe placeholders. Store production values in Vercel, GitHub Actions, a cloud secret manager, or another server-side store."],
        bullets: [
          "Turn on GitHub secret scanning and push protection where available.",
          "Add a local pre-commit secret check for fast feedback.",
          "Fail CI when a new high-confidence secret pattern appears.",
          "Keep privileged values out of public prefixes such as NEXT_PUBLIC_, VITE_, and REACT_APP_.",
        ],
      },
      {
        heading: "Know which keys are meant to be public",
        paragraphs: ["Some browser SDKs use publishable identifiers. A Supabase publishable key, for example, is designed for client code when Row Level Security is correct. The service-role or secret key is different because it bypasses those controls. A scanner should classify the key by role, not flag every long string as a breach."],
      },
    ],
    sources: [
      { label: "GitHub: Secret scanning and push protection", url: "https://docs.github.com/en/code-security/getting-started/github-security-features" },
      { label: "OWASP Developer Guide: Secure coding", url: "https://owasp.org/www-project-developer-guide/assets/exports/OWASP_Developer_Guide.pdf" },
    ],
  },
  {
    slug: "github-actions-security-for-vibe-coded-apps",
    title: "GitHub Actions security for vibe-coded apps",
    description: "Review workflow token permissions, pull_request_target, secret handling, third-party actions, and release jobs before an AI-generated workflow reaches production.",
    eyebrow: "CI and deployment",
    readTime: "9 min read",
    relatedChecks: ["GITHUB_TOKEN permissions", "pull_request_target", "Pinned actions", "Secret output"],
    intro: [
      "A GitHub Actions file is production code with credentials. It can publish a package, deploy an app, write to the repository, and read any secret explicitly provided to the job.",
      "AI coding tools are good at producing a workflow that passes. They cannot decide how much authority that workflow should have without a clear security boundary from you.",
    ],
    sections: [
      {
        heading: "Make token permissions explicit",
        paragraphs: ["Start read-only. Declare contents: read at workflow level, then grant a narrower write permission only to the release job that needs it. Avoid permissions: write-all. A test job does not need the same authority as a deployment job."],
      },
      {
        heading: "Treat pull request code as hostile input",
        paragraphs: [
          "The pull_request_target event runs in the context of the base repository. That makes it useful for trusted labeling or commenting, but dangerous when the job checks out and executes code from a fork. A contributor can change a build script, test command, or package hook and use the privileged job to reach secrets or a writable token.",
          "Use pull_request for untrusted builds. If you need a privileged follow-up action, split it into a separate workflow that consumes a small, verified artifact and never executes pull request code.",
        ],
      },
      {
        heading: "Pin the software inside the workflow",
        paragraphs: ["A tag such as v4 can move. GitHub documents a full-length commit SHA as the immutable way to reference an action. Review the SHA in the action's repository, pin it, and leave the friendly version in a comment so automated dependency updates remain understandable."],
        bullets: [
          "Pin third-party actions to reviewed full commit SHAs.",
          "Limit which actions and reusable workflows the repository may run.",
          "Keep Dependabot or Renovate updates reviewable instead of auto-merging workflow changes.",
        ],
      },
      {
        heading: "Secrets can leave without appearing in a log",
        paragraphs: ["GitHub masks known secret values in normal logs, but masking is not a security boundary. A compromised command can send a secret over the network or transform it before printing. Pass secrets only to the step that needs them, avoid shell tracing, and do not hand deployment credentials to ordinary test jobs."],
      },
    ],
    sources: [
      { label: "GitHub: Secure use reference for Actions", url: "https://docs.github.com/en/actions/reference/security/secure-use" },
      { label: "GitHub: Securely using pull_request_target", url: "https://docs.github.com/en/actions/reference/security/securely-using-pull_request_target" },
    ],
  },
  {
    slug: "supabase-security-for-vibe-coded-apps",
    title: "Supabase security for vibe-coded apps",
    description: "Protect a Supabase app with Row Level Security, correct key placement, tenant-aware policies, storage rules, and server-only administrative access.",
    eyebrow: "Database security",
    readTime: "10 min read",
    relatedChecks: ["Row Level Security", "Service-role keys", "Public environment variables", "SQL migrations"],
    intro: [
      "Supabase makes a browser-to-database product possible with very little code. The safety of that design depends on Row Level Security and the difference between a publishable key and a privileged server key.",
      "A working login screen proves authentication. It does not prove that one user cannot read or update another user's rows.",
    ],
    sections: [
      {
        heading: "Enable RLS on every exposed table",
        paragraphs: ["Supabase says Row Level Security must be enabled on tables in an exposed schema such as public. Tables created in the dashboard receive RLS by default, but raw SQL migrations need an explicit ALTER TABLE statement. Check migrations, not only the current dashboard state."],
        bullets: [
          "Enable RLS before production data is written.",
          "Create separate policies for select, insert, update, and delete when their rules differ.",
          "Test as anon, as a signed-in user, as another tenant, and with no session.",
          "Apply the same ownership model to storage objects and database functions.",
        ],
      },
      {
        heading: "A policy must match the tenant model",
        paragraphs: [
          "A check such as user_id = auth.uid() works for rows owned directly by one user. Team SaaS products usually need membership joins, organization IDs, role checks, and rules for invitations or suspended accounts. Copying a single-user policy into a multi-tenant app can either expose data or block legitimate work.",
          "Write tests that create two tenants and attempt every read and write across the boundary. The denied case is the test that matters.",
        ],
      },
      {
        heading: "Keep privileged keys on the server",
        paragraphs: ["Supabase publishable keys and legacy anon keys are intended for public clients when RLS is correct. Secret keys and legacy service-role keys bypass RLS and belong only in controlled backend code. Never give them a NEXT_PUBLIC_, VITE_, or REACT_APP_ prefix."],
      },
      {
        heading: "Review server routes too",
        paragraphs: ["A server route using a privileged Supabase client becomes its own authorization boundary. Verify the signed-in user, check the tenant and role, validate the input, then perform the administrative query. The service key will not repair a missing authorization check."],
      },
    ],
    sources: [
      { label: "Supabase: Row Level Security", url: "https://supabase.com/docs/guides/database/postgres/row-level-security" },
      { label: "Supabase: Securing your data and API keys", url: "https://supabase.com/docs/guides/database/secure-data" },
    ],
  },
];

export function getGuide(slug: string) {
  return guides.find((guide) => guide.slug === slug);
}
