import "server-only";

import { analyzeAgentSecurityFile, analyzeDependencyHygiene, extractDependencyInventory, isAgentSecurityFile } from "@/lib/repo-security-rules";
import type { RepoRuleCategory } from "@/lib/repo-security-rules";
import { queryKnownVulnerabilities } from "@/lib/osv";

const GITHUB_API = "https://api.github.com";
const GITHUB_RAW = "https://raw.githubusercontent.com";
const API_VERSION = "2022-11-28";
const MAX_FILES = 60;
const MAX_FILE_BYTES = 240_000;
const MAX_MANIFEST_BYTES = 1_500_000;
const MAX_TOTAL_BYTES = 6_000_000;
const CACHE_TTL_MS = 10 * 60 * 1000;

export type RepoSeverity = "critical" | "high" | "medium" | "low";
export type RepoCategory = RepoRuleCategory;

export interface RepoFinding {
  id: string;
  severity: RepoSeverity;
  category: RepoCategory;
  title: string;
  description: string;
  file: string;
  line: number | null;
  remedy: string;
  referenceUrl?: string;
}

export interface RepoScanResult {
  repository: {
    owner: string;
    name: string;
    fullName: string;
    url: string;
    defaultBranch: string;
    visibility: "public";
    latestPush: string | null;
  };
  score: number;
  risk: "low" | "moderate" | "high" | "critical";
  filesInRepository: number;
  filesScanned: number;
  bytesScanned: number;
  truncated: boolean;
  findings: RepoFinding[];
  coverage: {
    candidateFiles: number;
    filesSkipped: number;
    agentFilesScanned: number;
    dependencyManifests: number;
    dependenciesChecked: number;
    knownVulnerabilities: number;
    dependencyStatus: "checked" | "partial" | "unavailable" | "not-detected";
  };
  scannedAt: string;
}

interface GitHubRepository {
  name: string;
  full_name: string;
  html_url: string;
  private: boolean;
  default_branch: string;
  pushed_at: string | null;
}

interface GitTreeItem {
  path: string;
  type: "blob" | "tree";
  size?: number;
}

interface GitTreeResponse {
  tree: GitTreeItem[];
  truncated: boolean;
}

interface CachedScan {
  expiresAt: number;
  result: RepoScanResult;
}

const scanCache = new Map<string, CachedScan>();

export class GitHubScannerError extends Error {
  constructor(
    public code: "invalid_repository" | "not_found" | "private_repository" | "rate_limited" | "upstream_unavailable" | "repository_too_large",
    message: string,
    public retryAfter?: number,
  ) {
    super(message);
  }
}

export function parseGitHubRepository(input: string) {
  const trimmed = input.trim().replace(/\.git$/, "");
  let owner = "";
  let repo = "";

  if (/^https?:\/\//i.test(trimmed)) {
    let parsed: URL;
    try { parsed = new URL(trimmed); } catch { throw new GitHubScannerError("invalid_repository", "Enter a valid GitHub repository URL."); }
    if (parsed.hostname.toLowerCase() !== "github.com") throw new GitHubScannerError("invalid_repository", "Only github.com repository URLs are supported.");
    const parts = parsed.pathname.split("/").filter(Boolean);
    [owner, repo] = parts;
  } else {
    [owner, repo] = trimmed.split("/").filter(Boolean);
  }

  const validPart = /^[A-Za-z0-9_.-]{1,100}$/;
  if (!owner || !repo || !validPart.test(owner) || !validPart.test(repo)) {
    throw new GitHubScannerError("invalid_repository", "Use a GitHub URL such as https://github.com/owner/repository.");
  }
  return { owner, repo };
}

async function fetchWithTimeout(url: string, init: RequestInit = {}, timeoutMs = 10_000) {
  const controller = new AbortController();
  const timer = setTimeout(() => controller.abort(), timeoutMs);
  try {
    return await fetch(url, { ...init, signal: controller.signal, cache: "no-store" });
  } catch {
    throw new GitHubScannerError("upstream_unavailable", "GitHub could not be reached. Try again in a moment.");
  } finally {
    clearTimeout(timer);
  }
}

function githubHeaders() {
  const token = process.env.GITHUB_SCANNER_TOKEN;
  return {
    Accept: "application/vnd.github+json",
    "User-Agent": "ScanMySaaS-Repo-Scanner/1.0",
    "X-GitHub-Api-Version": API_VERSION,
    ...(token ? { Authorization: `Bearer ${token}` } : {}),
  };
}

async function githubJson<T>(path: string): Promise<T> {
  const response = await fetchWithTimeout(`${GITHUB_API}${path}`, { headers: githubHeaders() });
  if (response.status === 404) throw new GitHubScannerError("not_found", "The public repository could not be found. Private repositories are not supported yet.");
  if (response.status === 403 || response.status === 429) {
    const reset = Number(response.headers.get("x-ratelimit-reset") || 0);
    const retryAfter = Number(response.headers.get("retry-after") || 0) || (reset ? Math.max(1, reset - Math.floor(Date.now() / 1000)) : 60);
    throw new GitHubScannerError("rate_limited", "GitHub's public API limit has been reached. Try again later.", retryAfter);
  }
  if (!response.ok) throw new GitHubScannerError("upstream_unavailable", `GitHub returned ${response.status}. Try again in a moment.`);
  try { return await response.json() as T; }
  catch { throw new GitHubScannerError("upstream_unavailable", "GitHub returned an unexpected response."); }
}

function isCandidateFile(item: GitTreeItem, includeOversized = false) {
  if (item.type !== "blob" || !item.path || (!includeOversized && (item.size ?? 0) > fileByteLimit(item.path))) return false;
  const path = item.path.toLowerCase();
  if (/(^|\/)(node_modules|vendor|dist|build|\.next|coverage|\.cache|target|pods)(\/|$)/.test(path)) return false;
  if (isAgentSecurityFile(item.path)) return true;
  const basename = path.split("/").pop() || "";
  if (["package-lock.json", "npm-shrinkwrap.json", "cargo.lock", "go.mod"].includes(basename) || /^requirements(?:-[a-z0-9_.-]+)?\.txt$/i.test(basename)) return true;
  if (/\.(min\.js|map|png|jpe?g|gif|webp|svg|ico|woff2?|ttf|eot|pdf|zip|gz|mp4|mov|mp3|lock)$/i.test(path)) return false;
  if (/^\.env($|\.)/.test(basename) || [".gitignore", ".npmrc", ".pypirc", ".netrc", "dockerfile", "package.json", "vercel.json", "netlify.toml", "supabase.toml"].includes(basename)) return true;
  if (path.startsWith(".github/workflows/") && /\.ya?ml$/.test(path)) return true;
  return /\.(ts|tsx|js|jsx|mjs|cjs|py|rb|go|java|kt|php|cs|rs|sql|prisma|ya?ml|json|toml|ini|conf|config|properties|pem|key)$/i.test(path);
}

function fileByteLimit(path: string) {
  const basename = path.toLowerCase().split("/").pop() || "";
  return ["package-lock.json", "npm-shrinkwrap.json", "cargo.lock"].includes(basename) ? MAX_MANIFEST_BYTES : MAX_FILE_BYTES;
}

function candidatePriority(path: string) {
  const lower = path.toLowerCase();
  const basename = lower.split("/").pop() || "";
  if (/^\.env($|\.)/.test(basename) || /\.(pem|key)$/.test(lower) || [".npmrc", ".pypirc", ".netrc"].includes(basename)) return 0;
  if (lower.startsWith(".github/workflows/")) return 1;
  if (isAgentSecurityFile(path)) return 1;
  if (["package-lock.json", "npm-shrinkwrap.json", "cargo.lock", "go.mod"].includes(basename) || /^requirements(?:-[a-z0-9_.-]+)?\.txt$/i.test(basename)) return 2;
  if (lower.includes("supabase") || /(^|\/)migrations?\//.test(lower) || /\.sql$/.test(lower)) return 2;
  if ([".gitignore", "package.json", "next.config.js", "next.config.ts", "vite.config.js", "vite.config.ts"].includes(basename)) return 3;
  return 4;
}

function rawUrl(owner: string, repo: string, branch: string, path: string) {
  const encodedPath = path.split("/").map(encodeURIComponent).join("/");
  return `${GITHUB_RAW}/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/${encodeURIComponent(branch)}/${encodedPath}`;
}

async function fetchRepositoryFiles(owner: string, repo: string, branch: string, items: GitTreeItem[]) {
  const candidateCount = items.filter((item) => isCandidateFile(item, true)).length;
  const selected = items
    .filter((item) => isCandidateFile(item))
    .sort((a, b) => candidatePriority(a.path) - candidatePriority(b.path) || (a.size ?? 0) - (b.size ?? 0))
    .slice(0, MAX_FILES);
  const files: Array<{ path: string; content: string }> = [];
  let totalBytes = 0;

  for (let index = 0; index < selected.length; index += 8) {
    const batch = selected.slice(index, index + 8);
    const loaded = await Promise.all(batch.map(async (item) => {
      if (totalBytes >= MAX_TOTAL_BYTES) return null;
      try {
        const response = await fetchWithTimeout(rawUrl(owner, repo, branch, item.path), { headers: { "User-Agent": "ScanMySaaS-Repo-Scanner/1.0" } }, 7000);
        if (!response.ok) return null;
        const contentLength = Number(response.headers.get("content-length") || item.size || 0);
        const byteLimit = fileByteLimit(item.path);
        if (contentLength > byteLimit) return null;
        const content = await response.text();
        const bytes = Buffer.byteLength(content, "utf8");
        if (bytes > byteLimit) return null;
        return { path: item.path, content, bytes };
      } catch { return null; }
    }));
    for (const file of loaded) {
      if (!file || totalBytes + file.bytes > MAX_TOTAL_BYTES) continue;
      totalBytes += file.bytes;
      files.push({ path: file.path, content: file.content });
    }
    if (totalBytes >= MAX_TOTAL_BYTES) break;
  }

  return { files, totalBytes, candidateCount };
}

function lineOf(content: string, index: number) {
  return content.slice(0, index).split("\n").length;
}

function findingId(category: RepoCategory, file: string, line: number | null, title: string) {
  return `${category}:${file}:${line ?? 0}:${title}`.toLowerCase().replace(/[^a-z0-9:._/-]+/g, "-");
}

function addFinding(findings: RepoFinding[], finding: Omit<RepoFinding, "id">) {
  const id = findingId(finding.category, finding.file, finding.line, finding.title);
  if (!findings.some((item) => item.id === id)) findings.push({ id, ...finding });
}

function scanSecretPatterns(path: string, content: string, findings: RepoFinding[]) {
  const patterns: Array<{ regex: RegExp; title: string; description: string }> = [
    { regex: /-----BEGIN (?:RSA |EC |OPENSSH |DSA )?PRIVATE KEY-----/g, title: "Private key committed to the repository", description: "A private key marker is present in source control." },
    { regex: /\bAKIA[0-9A-Z]{16}\b/g, title: "Potential AWS access key committed", description: "The file contains a value shaped like an AWS access key ID." },
    { regex: /\bgh[pousr]_[A-Za-z0-9_]{36,255}\b/g, title: "Potential GitHub token committed", description: "The file contains a value shaped like a GitHub access token." },
    { regex: /\bsk_live_[A-Za-z0-9]{16,}\b/g, title: "Potential live secret key committed", description: "The file contains a value shaped like a live provider secret key." },
    { regex: /\bAIza[0-9A-Za-z_-]{35}\b/g, title: "Potential Google API key committed", description: "The file contains a value shaped like a Google API key." },
    { regex: /\bxox[baprs]-[0-9A-Za-z-]{10,}\b/g, title: "Potential Slack token committed", description: "The file contains a value shaped like a Slack token." },
    { regex: /(?:postgres(?:ql)?|mysql|mongodb(?:\+srv)?):\/\/[^\s:@/]+:[^\s@/]+@[^\s"'`]+/gi, title: "Database URL with embedded credentials", description: "A database connection string appears to contain a username and password." },
  ];

  for (const pattern of patterns) {
    pattern.regex.lastIndex = 0;
    for (let match = pattern.regex.exec(content); match; match = pattern.regex.exec(content)) {
      addFinding(findings, { severity: "critical", category: "secrets", title: pattern.title, description: pattern.description, file: path, line: lineOf(content, match.index), remedy: "Revoke or rotate the credential first. Removing it from the latest file is not enough because Git history may still contain it. Purge the value from history, move it to the deployment platform's secret store, and enable GitHub push protection." });
      if (pattern.regex.lastIndex === match.index) pattern.regex.lastIndex += 1;
    }
  }

  const publicSecret = /\b(?:NEXT_PUBLIC|VITE|REACT_APP)_[A-Z0-9_]*(?:SECRET|PRIVATE|SERVICE_ROLE|PASSWORD|TOKEN)[A-Z0-9_]*\s*=\s*["']?([^\s"']{8,})/g;
  for (let match = publicSecret.exec(content); match; match = publicSecret.exec(content)) {
    addFinding(findings, { severity: "critical", category: "client-code", title: "Secret-like value exposed through a public environment variable", description: "A client-bundled environment variable name contains a secret, private, service-role, password, or token marker.", file: path, line: lineOf(content, match.index), remedy: "Remove the value from the public environment namespace and rotate it. Public prefixes such as NEXT_PUBLIC_, VITE_, and REACT_APP_ intentionally place values in browser code. Call the privileged service from a server route instead." });
  }

  const genericAssignment = /\b([A-Z][A-Z0-9_]{2,}(?:SECRET|API_KEY|ACCESS_TOKEN|PASSWORD|PRIVATE_KEY)[A-Z0-9_]*)\s*[:=]\s*["']([^"'\n]{16,})["']/g;
  for (let match = genericAssignment.exec(content); match; match = genericAssignment.exec(content)) {
    const value = match[2];
    if (/example|placeholder|changeme|your[_-]|process\.env|import\.meta|\$\{|test[_-]?key/i.test(value)) continue;
    addFinding(findings, { severity: "high", category: "secrets", title: "Potential hardcoded secret", description: `A secret-like variable named ${match[1]} has a literal value in source code. The value is never included in this report.`, file: path, line: lineOf(content, match.index), remedy: "Confirm whether the value is real. If it is, rotate it, remove it from Git history, and load it from a server-side secret store. Add a pre-commit secret check and GitHub push protection before the next release." });
  }
}

function scanWorkflow(path: string, content: string, findings: RepoFinding[]) {
  if (!path.toLowerCase().startsWith(".github/workflows/")) return;
  const writeAll = /^\s*permissions:\s*write-all\s*$/im.exec(content);
  if (writeAll) addFinding(findings, { severity: "high", category: "github-actions", title: "GitHub Actions token has write-all permissions", description: "The workflow grants broad write access to its GITHUB_TOKEN.", file: path, line: lineOf(content, writeAll.index), remedy: "Replace write-all with the smallest job-level permissions required. Start with contents: read and add a write permission only to the job that needs it." });

  if (!/^\s*permissions\s*:/im.test(content)) addFinding(findings, { severity: "low", category: "github-actions", title: "Workflow does not declare token permissions", description: "The workflow relies on the repository's default GITHUB_TOKEN permissions.", file: path, line: 1, remedy: "Declare permissions explicitly. A safe baseline for a read-only build is permissions: { contents: read }. Add narrower permissions at job level when a release step needs them." });

  if (/pull_request_target\s*:/i.test(content) && /actions\/checkout@/i.test(content) && /(github\.event\.pull_request\.head|refs\/pull\/|head\.sha)/i.test(content)) {
    addFinding(findings, { severity: "critical", category: "github-actions", title: "Untrusted pull request code may run with privileged workflow access", description: "A pull_request_target workflow appears to check out pull request code. This can expose repository secrets or a writable token.", file: path, line: lineOf(content, content.search(/pull_request_target\s*:/i)), remedy: "Do not execute pull request code in pull_request_target. Use pull_request for untrusted builds, keep permissions read-only, and split any trusted labeling or commenting job from the job that checks out and executes code." });
  }

  const actionUse = /^\s*-?\s*uses:\s*([^\s#]+)@([^\s#]+).*$/gim;
  for (let match = actionUse.exec(content); match; match = actionUse.exec(content)) {
    const action = match[1];
    const ref = match[2];
    if (action.startsWith("./") || action.startsWith("docker://") || /^[a-f0-9]{40}$/i.test(ref)) continue;
    addFinding(findings, { severity: "medium", category: "github-actions", title: "GitHub Action is not pinned to a full commit SHA", description: `${action} uses a mutable tag or branch (${ref}).`, file: path, line: lineOf(content, match.index), remedy: "Pin the action to a reviewed full-length commit SHA. Keep the version tag in a comment so dependency tools can still propose updates." });
  }

  const secretEcho = /(?:echo|printf)[^\n]*\$\{\{\s*secrets\./gi.exec(content);
  if (secretEcho) addFinding(findings, { severity: "high", category: "github-actions", title: "Workflow may print a secret", description: "A shell command references a GitHub secret while writing output.", file: path, line: lineOf(content, secretEcho.index), remedy: "Do not print secrets. Pass the secret directly to the command through an environment variable, keep shell tracing disabled, and verify that third-party tools do not echo arguments." });
}

function sourceLineAt(content: string, index: number) {
  const start = content.lastIndexOf("\n", index - 1) + 1;
  const nextBreak = content.indexOf("\n", index);
  return { line: content.slice(start, nextBreak === -1 ? content.length : nextBreak), column: index - start };
}

function isInsideQuotedLiteral(line: string, column: number) {
  let quote: '"' | "'" | "`" | null = null;
  let escaped = false;
  for (let index = 0; index < column; index += 1) {
    const character = line[index];
    if (escaped) { escaped = false; continue; }
    if (character === "\\") { escaped = true; continue; }
    if (quote) {
      if (character === quote) quote = null;
      continue;
    }
    if (character === '"' || character === "'" || character === "`") quote = character;
  }
  return quote !== null;
}

function isDetectorDefinition(line: string) {
  return /\b(?:const|let|var)\s+[A-Za-z_$][\w$]*\s*=\s*\//.test(line);
}

function scanCodePatterns(path: string, content: string, findings: RepoFinding[]) {
  const unsafeEvalPattern = /\b(?:eval\s*\(|new\s+Function\s*\()/g;
  for (let unsafeEval = unsafeEvalPattern.exec(content); unsafeEval; unsafeEval = unsafeEvalPattern.exec(content)) {
    const source = sourceLineAt(content, unsafeEval.index);
    if (isInsideQuotedLiteral(source.line, source.column) || isDetectorDefinition(source.line)) continue;
    addFinding(findings, { severity: "medium", category: "client-code", title: "Dynamic code execution needs review", description: "The file uses eval() or the Function constructor. User-controlled input can turn this into code execution or XSS.", file: path, line: lineOf(content, unsafeEval.index), remedy: "Replace dynamic code execution with explicit parsing or a narrow allowlist. If it cannot be removed, prove that the input is fully controlled and add a regression test for hostile input." });
    break;
  }

  const dangerousHtmlPattern = /dangerouslySetInnerHTML\s*=|\.innerHTML\s*=/g;
  for (let dangerousHtml = dangerousHtmlPattern.exec(content); dangerousHtml; dangerousHtml = dangerousHtmlPattern.exec(content)) {
    const source = sourceLineAt(content, dangerousHtml.index);
    const nearby = content.slice(Math.max(0, dangerousHtml.index - 500), dangerousHtml.index + 500);
    const structuredData = /application\/ld\+json/i.test(nearby) && /JSON\.stringify/.test(nearby);
    if (isInsideQuotedLiteral(source.line, source.column) || isDetectorDefinition(source.line) || structuredData) continue;
    addFinding(findings, { severity: "medium", category: "client-code", title: "Raw HTML rendering needs sanitization", description: "The file writes raw HTML into the page. Untrusted content can become cross-site scripting.", file: path, line: lineOf(content, dangerousHtml.index), remedy: "Prefer normal framework rendering. If raw HTML is required, sanitize it with a maintained allowlist-based library on the server and test script, event-handler, SVG, and URL payloads." });
    break;
  }

  const wildcardCors = /(?:origin\s*:\s*["']\*["']|Access-Control-Allow-Origin["']?\s*[:,]\s*["']\*["'])/gi.exec(content);
  if (wildcardCors) addFinding(findings, { severity: "low", category: "client-code", title: "Wildcard CORS configuration needs scope review", description: "The application appears to allow browser reads from every origin. This can be intentional for a public API or asset, so verify the affected route and response data before changing it.", file: path, line: lineOf(content, wildcardCors.index), remedy: "Confirm which routes inherit this configuration. Keep the wildcard only for responses that are intentionally public and never credentialed. For user or tenant data, use an exact origin allowlist and test that an unrelated Origin receives no Access-Control-Allow-Origin or Access-Control-Allow-Credentials headers." });

  const isBuildConfig = /(?:^|\/)(?:next|vite|webpack|rollup|svelte|nuxt)\.config\.[cm]?[jt]s$/i.test(path);
  const publicMaps = isBuildConfig ? /(?:productionBrowserSourceMaps\s*:\s*true|sourcemap\s*:\s*true)/g.exec(content) : null;
  if (publicMaps) addFinding(findings, { severity: "medium", category: "client-code", title: "Production source maps may be public", description: "The build configuration appears to publish browser source maps.", file: path, line: lineOf(content, publicMaps.index), remedy: "Disable public source maps. If an error-monitoring service needs them, upload them privately during CI and exclude .map files from the deployed artifact." });
}

function scanEnvironmentFiles(path: string, content: string, findings: RepoFinding[]) {
  const basename = path.toLowerCase().split("/").pop() || "";
  if (/^\.env($|\.)/.test(basename) && !/(example|sample|template|defaults|schema)/.test(basename)) {
    addFinding(findings, { severity: "critical", category: "environment", title: "Environment file committed to Git", description: "A real environment file is present in the repository. It may contain credentials even if the current values look harmless.", file: path, line: 1, remedy: "Remove the file from Git history, rotate every credential it contained, and add .env* to .gitignore while explicitly allowing a scrubbed .env.example file." });
  }

  if ([".npmrc", ".pypirc", ".netrc"].includes(basename) && /(?:_authToken|password|token)\s*[=:]\s*[^\s$<{]+/i.test(content)) {
    addFinding(findings, { severity: "critical", category: "environment", title: "Package or network credential committed", description: `${basename} appears to contain a literal credential.`, file: path, line: lineOf(content, content.search(/(?:_authToken|password|token)\s*[=:]/i)), remedy: "Revoke the credential, remove it from Git history, and inject it only in CI through a protected secret. Keep the local credential file ignored." });
  }
}

function scanSupabase(files: Array<{ path: string; content: string }>, findings: RepoFinding[]) {
  const usesSupabase = files.some((file) => /@supabase\/supabase-js|supabase\/migrations|supabase\.co/i.test(`${file.path}\n${file.content}`));
  if (!usesSupabase) return;
  const sqlFiles = files.filter((item) => /\.sql$/i.test(item.path));
  const allSql = sqlFiles.map((file) => file.content).join("\n");
  for (const file of sqlFiles) {
    const createTable = /create\s+table\s+(?:if\s+not\s+exists\s+)?((?:"?[a-z_][\w$]*"?\.)?"?[a-z_][\w$]*"?)/gi;
    for (let match = createTable.exec(file.content); match; match = createTable.exec(file.content)) {
      const qualifiedTable = match[1].replace(/"/g, "");
      const table = qualifiedTable.split(".").pop() || qualifiedTable;
      const escapedTable = table.replace(/[.*+?^${}()|[\]\\]/g, "\\$&");
      const rlsPattern = new RegExp(`alter\\s+table\\s+(?:if\\s+exists\\s+)?(?:(?:\"?[a-z_][\\w$]*\"?)\\.)?\"?${escapedTable}\"?\\s+enable\\s+row\\s+level\\s+security`, "i");
      if (rlsPattern.test(allSql)) continue;
      addFinding(findings, { severity: "high", category: "database", title: `Supabase table ${table} has no visible RLS enablement`, description: `The scanned SQL migrations create ${qualifiedTable}, but no scanned migration enables row level security for that table.`, file: file.path, line: lineOf(file.content, match.index), remedy: `Verify whether ${qualifiedTable} is exposed through the Supabase Data API. If it is, enable row level security and add policies for the exact user and tenant model before production data is written. Test anonymous access, the owning user, a user from another tenant, and service-role server access separately.` });
    }
  }
}

function scanGitignore(files: Array<{ path: string; content: string }>, findings: RepoFinding[], repositoryPaths: string[], treeComplete: boolean) {
  const gitignore = files.find((file) => file.path === ".gitignore");
  if (!gitignore) {
    if (!treeComplete || repositoryPaths.includes(".gitignore")) return;
    addFinding(findings, { severity: "medium", category: "environment", title: "No root .gitignore was found", description: "The repository has no root ignore file to keep local secrets and build artifacts out of Git.", file: ".gitignore", line: null, remedy: "Add a root .gitignore for your stack. At minimum ignore .env files, local credential files, dependency directories, build output, logs, and editor artifacts. Keep a scrubbed .env.example file." });
    return;
  }
  if (!/(^|\n)\.env(?:\*|\b|\.)/m.test(gitignore.content)) {
    addFinding(findings, { severity: "medium", category: "environment", title: ".gitignore does not cover environment files", description: "The root .gitignore does not appear to ignore .env files.", file: ".gitignore", line: 1, remedy: "Add .env* and then allow only a scrubbed template with !.env.example. If an environment file was already committed, ignoring it will not remove it from history." });
  }
}

function scoreFindings(findings: RepoFinding[]) {
  const penalty = { critical: 24, high: 13, medium: 6, low: 2 } satisfies Record<RepoSeverity, number>;
  const score = Math.max(0, 100 - findings.reduce((sum, finding) => sum + penalty[finding.severity], 0));
  const risk = findings.some((finding) => finding.severity === "critical") ? "critical" : findings.some((finding) => finding.severity === "high") ? "high" : findings.some((finding) => finding.severity === "medium") ? "moderate" : "low";
  return { score, risk } as const;
}

function pruneCache() {
  const now = Date.now();
  for (const [key, value] of scanCache) if (value.expiresAt <= now) scanCache.delete(key);
  while (scanCache.size > 100) scanCache.delete(scanCache.keys().next().value!);
}

export async function scanPublicGitHubRepository(input: string): Promise<RepoScanResult> {
  const { owner, repo } = parseGitHubRepository(input);
  const cacheKey = `${owner.toLowerCase()}/${repo.toLowerCase()}`;
  pruneCache();
  const cached = scanCache.get(cacheKey);

  const repository = await githubJson<GitHubRepository>(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}`);
  if (repository.private) throw new GitHubScannerError("private_repository", "Private repository scanning requires the upcoming GitHub App connection.");
  if (cached && cached.expiresAt > Date.now() && cached.result.repository.latestPush === repository.pushed_at && cached.result.repository.defaultBranch === repository.default_branch) return cached.result;
  const tree = await githubJson<GitTreeResponse>(`/repos/${encodeURIComponent(owner)}/${encodeURIComponent(repo)}/git/trees/${encodeURIComponent(repository.default_branch)}?recursive=1`);
  if (!Array.isArray(tree.tree)) throw new GitHubScannerError("upstream_unavailable", "GitHub returned an invalid repository tree.");
  if (tree.tree.length > 100_000) throw new GitHubScannerError("repository_too_large", "This repository is too large for the public scanner.");

  const loaded = await fetchRepositoryFiles(owner, repo, repository.default_branch, tree.tree);
  if (!loaded.files.length) {
    throw new GitHubScannerError("upstream_unavailable", "No supported repository files could be read. The repository may be empty, use unsupported file types, or be temporarily unavailable. Try again with a repository containing source or configuration files.");
  }
  const repositoryPaths = tree.tree.filter((item) => item.type === "blob").map((item) => item.path);
  const findings: RepoFinding[] = [];
  for (const file of loaded.files) {
    scanEnvironmentFiles(file.path, file.content, findings);
    scanSecretPatterns(file.path, file.content, findings);
    scanWorkflow(file.path, file.content, findings);
    scanCodePatterns(file.path, file.content, findings);
    for (const finding of analyzeAgentSecurityFile(file)) addFinding(findings, finding);
  }
  scanGitignore(loaded.files, findings, repositoryPaths, !tree.truncated);
  scanSupabase(loaded.files, findings);
  for (const finding of analyzeDependencyHygiene(loaded.files, repositoryPaths, !tree.truncated)) addFinding(findings, finding);

  const dependencyInventory = extractDependencyInventory(loaded.files);
  const dependencyScan = await queryKnownVulnerabilities(dependencyInventory.dependencies, dependencyInventory.truncated);
  for (const match of dependencyScan.matches) {
    const ids = match.ids.slice(0, 6);
    addFinding(findings, {
      severity: "medium",
      category: "dependencies",
      title: `Known vulnerability reported for ${match.dependency.name}@${match.dependency.version}`,
      description: `OSV matched ${ids.join(", ")}${match.ids.length > ids.length ? ` and ${match.ids.length - ids.length} more` : ""} to this exact dependency version. Reachability and advisory severity still need verification.`,
      file: match.dependency.file,
      line: match.dependency.line,
      remedy: "Open the advisory, identify the nearest fixed version, and upgrade through the existing package manager. Review breaking changes, regenerate the lockfile, run the relevant tests and build, and confirm whether the vulnerable code path is reachable in production.",
      referenceUrl: `https://osv.dev/vulnerability/${encodeURIComponent(match.ids[0])}`,
    });
  }

  const severityOrder: Record<RepoSeverity, number> = { critical: 0, high: 1, medium: 2, low: 3 };
  findings.sort((a, b) => severityOrder[a.severity] - severityOrder[b.severity] || a.file.localeCompare(b.file) || (a.line ?? 0) - (b.line ?? 0));
  const { score, risk } = scoreFindings(findings);
  const result: RepoScanResult = {
    repository: { owner, name: repository.name, fullName: repository.full_name, url: repository.html_url, defaultBranch: repository.default_branch, visibility: "public", latestPush: repository.pushed_at },
    score,
    risk,
    filesInRepository: tree.tree.filter((item) => item.type === "blob").length,
    filesScanned: loaded.files.length,
    bytesScanned: loaded.totalBytes,
    truncated: tree.truncated || loaded.candidateCount > loaded.files.length,
    findings,
    coverage: {
      candidateFiles: loaded.candidateCount,
      filesSkipped: loaded.candidateCount - loaded.files.length,
      agentFilesScanned: loaded.files.filter((file) => isAgentSecurityFile(file.path)).length,
      dependencyManifests: dependencyInventory.manifests,
      dependenciesChecked: dependencyScan.dependenciesChecked,
      knownVulnerabilities: dependencyScan.matches.reduce((total, match) => total + match.ids.length, 0),
      dependencyStatus: dependencyScan.status,
    },
    scannedAt: new Date().toISOString(),
  };
  scanCache.set(cacheKey, { expiresAt: Date.now() + CACHE_TTL_MS, result });
  return result;
}
