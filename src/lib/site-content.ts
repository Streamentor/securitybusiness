export const homeFaqs = [
  {
    question: "How do I scan a SaaS application for security vulnerabilities?",
    answer:
      "Enter a public URL you own or are authorized to test. ScanMySaaS crawls up to 25 reachable pages, runs more than 60 automated website vulnerability checks, and returns a prioritized report with severity, affected URLs, and finding descriptions.",
  },
  {
    question: "How does a website vulnerability scanner work?",
    answer:
      "A website vulnerability scanner inspects the public surface of a web application for observable security issues and misconfigurations. ScanMySaaS checks transport security, response headers, cookies, forms, exposed files, client-side code, redirects, DNS and email-security signals, then groups the findings by severity.",
  },
  {
    question: "What types of vulnerability does the scanner detect?",
    answer:
      "The scanner looks for SSL and HTTPS problems, missing or unsafe security headers, risky cookie settings, exposed environment or backup files, CORS mistakes, open redirects, source maps, outdated client-side libraries, unsafe JavaScript patterns, and other publicly observable web application risks.",
  },
  {
    question: "Is ScanMySaaS a free website vulnerability scanner?",
    answer:
      "Yes. Your first scan is free, requires no credit card, and can inspect up to 25 reachable pages. The free report includes the security score, severity breakdown, affected URLs, finding descriptions, and one prioritized fix when an actionable finding is available. Paid plans add remediation for all findings, monthly credits, rescans, saved history, and score trends.",
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
    copy: "Run a fresh scan after a release and track whether the security score improves over time.",
  },
] as const;
