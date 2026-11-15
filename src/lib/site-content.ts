export const homeFaqs = [
  {
    question: "What is a SaaS security scanner?",
    answer:
      "A SaaS security scanner checks a software-as-a-service product for security problems an attacker could find from the outside or in its code. ScanMySaaS scans the deployed website (headers, cookies, exposed files, TLS and more) and, separately, the GitHub repository behind it (committed secrets, risky GitHub Actions, missing database rules, vulnerable dependencies and, on paid plans, an AI review of authorization logic).",
  },
  {
    question: "What is the difference between the website scan and the GitHub repo scan?",
    answer:
      "The website scan only sees what is publicly reachable on your deployed app. The GitHub repo scanner reads your source code, public or private through a read-only GitHub App, and finds issues an outside scan cannot see, such as committed .env files, API keys in code and unsafe GitHub Actions, with the exact file and line. On Starter and Pro, an AI review also looks for missing ownership checks in server code. Use both: scan the code before launch and the live site after each release.",
  },
  {
    question: "How do I scan a SaaS application for security vulnerabilities?",
    answer:
      "Enter a public URL you own or are authorized to test. ScanMySaaS crawls up to 25 reachable pages, runs more than 60 automated website vulnerability checks, and returns a prioritized report with severity, affected URLs, and finding descriptions.",
  },
  {
    question: "What types of vulnerability does the scanner detect?",
    answer:
      "SSL and HTTPS problems, missing or weak security headers, risky cookie flags, exposed environment, Git and backup files, CORS that reflects untrusted origins with credentials, redirect problems (no HTTP to HTTPS redirect, HTTPS downgrades, long redirect chains), public source maps, old jQuery, AngularJS or Bootstrap builds, unsafe inline JavaScript, and missing SPF or DMARC records. It does not send attack payloads such as SQL injection or XSS tests.",
  },
  {
    question: "Is the SaaS security scanner free?",
    answer:
      "Yes. Your first scan is free, requires no credit card, and can inspect up to 25 reachable pages. The free report includes the security score, severity breakdown, affected URLs, finding descriptions, and one prioritized fix when an actionable finding is available. A free account keeps the report and gives you one free rescan of the same site within 7 days, with a list of what was fixed and what is new. Paid plans add a fix for every finding and monthly credits for more scans.",
  },
  {
    question: "How is ScanMySaaS different from Burp Suite or Nikto?",
    answer:
      "ScanMySaaS is designed as a quick, browser-based outside-in check for SaaS founders and product teams. It requires no installation or command line, but it is not a replacement for Burp Suite, Nikto, manual penetration testing, or a professional security review.",
  },
  {
    question: "Do I need penetration testing experience to use it?",
    answer:
      "No. Findings are ordered by severity and connected to the page where each issue was observed. One actionable finding includes free remediation steps when available. Paid reports unlock the remaining fixes. Verify each finding and proposed change before applying it to production.",
  },
] as const;

export const productFeatures = [
  {
    title: "Full-site vulnerability scan",
    copy: "Crawl up to 25 reachable pages so the assessment covers more than the homepage.",
  },
  {
    title: "Prioritized security findings",
    copy: "Separate critical and high-risk issues from medium, low, and informational signals.",
  },
  {
    title: "Affected URLs preserved",
    copy: "Keep every finding connected to the exact page where the scanner observed it.",
  },
  {
    title: "Step-by-step remediation",
    copy: "Try one actionable fix in the free report. Paid plans unlock the remaining remediation steps and configuration examples.",
  },
  {
    title: "Saved scan history",
    copy: "Return to earlier reports without losing the context behind previous findings.",
  },
  {
    title: "Rescans and score trends",
    copy: "Run a fresh scan after a release and track whether the security score improves over time. Free accounts get one verification rescan within 7 days; later rescans use credits.",
  },
] as const;

export const repoScanSteps = [
  { title: "Paste a repository or connect GitHub", copy: "Paste a public github.com URL, including a /tree/branch link, or connect the read-only ScanMySaaS GitHub App and pick a private repository." },
  { title: "We read one exact commit", copy: "The branch is resolved to a commit SHA and up to 60 security-relevant files are read from it in this order: environment and key files, GitHub workflows and agent configs, lockfiles and SQL migrations, build configs, then source files ranked by risk (middleware, API routes, auth and payment code)." },
  { title: "Get findings with file and line", copy: "Each finding names the file and line, explains why it was flagged and comes with a fix prompt for Cursor, Claude or Codex. Rescan after fixing to confirm." },
] as const;

export const repoFaqs = [
  {
    question: "What does the GitHub repo scanner check?",
    answer: "It looks for committed .env files and private keys, API keys and tokens in code, risky GitHub Actions (broad permissions, unpinned actions, pull_request_target), client-side secret exposure, unsafe code sinks, Supabase service-role exposure and tables without row level security, coding-agent and MCP configuration risks, and exact dependency versions with known vulnerabilities in the OSV database. On Starter and Pro an AI review also reads the riskiest files for authorization and business-logic gaps.",
  },
  {
    question: "How do I scan a GitHub repository for secrets and vulnerabilities?",
    answer: "Paste the repository URL into the repo scanner and confirm you own it or have permission. For a private repository, sign in, connect GitHub with the read-only ScanMySaaS GitHub App and choose the repository. The scan reads one pinned commit and returns findings with file paths and line numbers.",
  },
  {
    question: "Is the repo scanner free?",
    answer: "Public repository scans are free. Private repository scans and the AI logic review are included in the Starter and Pro plans.",
  },
  {
    question: "Do repository scans use scan credits?",
    answer: "No. Credits are only used for website scans. Public repository scans are free, and private repository scans are included in Starter and Pro.",
  },
  {
    question: "Can I scan a private GitHub repository?",
    answer: "Yes. Install the ScanMySaaS GitHub App on the repositories you choose. It can only read repository contents and metadata and cannot write to your code. Files are read in memory during the scan and discarded; only the report is saved, privately to your account. You can revoke access on GitHub at any time.",
  },
  {
    question: "Does the scanner clone my repository or run my code?",
    answer: "No. It does not clone the repository, install packages, run builds or execute code. It reads a bounded set of text files from one commit through the GitHub API, and secret values never appear in the report.",
  },
  {
    question: "How is this different from GitHub secret scanning or Dependabot?",
    answer: "GitHub's tools focus on known secret formats and dependency alerts. The ScanMySaaS repo scanner adds checks aimed at apps built with AI coding agents (Supabase RLS, client-exposed keys, risky workflows, agent and MCP configs, missing authorization logic) and pairs the code scan with a scan of your live website. Keep GitHub's protections enabled as well.",
  },
] as const;

export const pricingFaqs: ReadonlyArray<readonly [string, string]> = [
  ["How much does vulnerability scanning cost?", "ScanMySaaS starts free: one website scan with a prioritized report and one actionable fix, plus free public GitHub repository scans. Starter is $29 per month with 10 website scan credits, and Pro is $79 per month with 30 credits. Both include private repository scans, remediation for every finding and the AI logic review of repository code."],
  ["Is there a free vulnerability scanner?", "Yes. The first website vulnerability scan is free with no credit card, and public GitHub repositories can be scanned for free at any time."],
  ["What counts as a scan credit?", "One credit runs a new crawl and security report for one website. A scan can cover up to 25 reachable pages on that site."],
  ["Do unused credits roll over?", "Yes. Starter can hold up to 20 credits and Pro can hold up to 60. New monthly credits are added up to that cap."],
  ["Why pay if the first report is free?", "The free report shows the score, affected URLs, severity, and descriptions, plus one prioritized fix when an actionable finding is available. Paid plans unlock remediation for the remaining findings and give you credits to verify fixes over time."],
  ["How does private repository access work?", "You install the ScanMySaaS GitHub App on the repositories you choose. It can only read repository contents and metadata. Files are read in memory for the scan and discarded; only the report is saved, and it is visible only to your account. You can revoke access on GitHub at any time."],
  ["How does AI logic review handle my code?", "On Starter and Pro, selected source files are sent to OpenAI for analysis using store: false. AI findings need verification. You can opt out in your dashboard; rule-based scans still run. Input and monthly token budgets apply, with a higher monthly budget on Pro. If AI is unavailable or the budget is exhausted, your rule-based report still completes."],
  ["Can I change or cancel my plan?", "Yes. Subscribers can open the Stripe billing portal from the dashboard to manage or cancel billing."],
  ["Is the result a security certification?", "No. It is an automated outside-in assessment, not a certification or penetration test. Use it as a fast feedback layer in a broader security process."],
];
