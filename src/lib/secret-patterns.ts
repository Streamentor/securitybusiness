/** Shared credential signatures. Never return matched values to clients or logs. */
export function repositorySecretPatterns() {
  return [
    { regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, title: "Private key committed to the repository", description: "A private key marker is present in source control." },
    { regex: /\bAKIA[0-9A-Z]{16}\b/g, title: "Potential AWS access key committed", description: "The file contains a value shaped like an AWS access key ID." },
    { regex: /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/g, title: "Potential GitHub token committed", description: "The file contains a value shaped like a GitHub access token." },
    { regex: /\bsk_live_[A-Za-z0-9]{16,}\b/g, title: "Potential live secret key committed", description: "The file contains a value shaped like a live provider secret key." },
    { regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, title: "Potential Google API key committed", description: "The file contains a value shaped like a Google API key." },
    { regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, title: "Potential Slack token committed", description: "The file contains a value shaped like a Slack token." },
    { regex: /\bsb_secret_[A-Za-z0-9_-]{20,}\b/g, title: "Supabase secret key committed", description: "The file contains a Supabase secret API key (sb_secret_). It bypasses Row Level Security and must only live in server-side secret storage." },
    { regex: /\bsk-(?:proj|svcacct|admin)-[A-Za-z0-9_-]{20,}\b/g, title: "Potential OpenAI API key committed", description: "The file contains a value shaped like an OpenAI project, service account or admin key." },
    { regex: /\bgithub_pat_[A-Za-z0-9_]{40,}\b/g, title: "Potential GitHub fine-grained token committed", description: "The file contains a value shaped like a GitHub fine-grained personal access token." },
    { regex: /\b(?:rk_live|whsec)_[A-Za-z0-9]{16,}\b/g, title: "Potential Stripe restricted key or webhook secret committed", description: "The file contains a value shaped like a Stripe restricted key or webhook signing secret." },
    { regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s@/]+@[^\s"'`]+/gi, title: "Database URL with embedded credentials", description: "A database connection string appears to contain a username and password." },
  ];
}

/** Returns the JWT `role` claim if the token decodes as a JWT, otherwise null. Never logs the token. */
export function jwtRole(token: string): string | null {
  const part = token.split(".")[1];
  if (!part) return null;
  try {
    const json = JSON.parse(Buffer.from(part.replace(/-/g, "+").replace(/_/g, "/"), "base64").toString("utf8"));
    return typeof json?.role === "string" ? json.role : null;
  } catch {
    return null;
  }
}

export function redactSecrets(value: string): string {
  let text = value.replace(/-----BEGIN [^-]*PRIVATE KEY-----[\s\S]*?-----END [^-]*PRIVATE KEY-----/g, (block) => block.split("\n").map(() => "[REDACTED]").join("\n"));
  for (const { regex } of repositorySecretPatterns()) text = text.replace(regex, "[REDACTED]");
  return text
    .replace(/\bsk-(?:proj-|svcacct-)?[A-Za-z0-9_-]{16,}/g, "[REDACTED]")
    .replace(/\bgithub_pat_[A-Za-z0-9_]{20,}/g, "[REDACTED]")
    .replace(/\beyJ[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+\.[A-Za-z0-9_-]+/g, "[REDACTED]")
    .replace(/((?:[A-Za-z0-9_]*(?:secret|password|api[_-]?key|access[_-]?token|service[_-]?role|token|credential|private[_-]?key)[A-Za-z0-9_]*)["']?\s*[:=]\s*["'])([^"'\n]{8,})(["'])/gi, "$1[REDACTED]$3")
    .replace(/(Bearer\s+)[A-Za-z0-9._~+/-]{12,}/gi, "$1[REDACTED]");
}
