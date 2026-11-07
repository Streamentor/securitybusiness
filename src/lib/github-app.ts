import { createHmac, createSign, randomBytes, timingSafeEqual } from "node:crypto";

/**
 * Read-only GitHub App integration.
 *
 * Required environment (feature stays hidden until all are set):
 *   GITHUB_APP_ID, GITHUB_APP_SLUG, GITHUB_APP_PRIVATE_KEY,
 *   GITHUB_APP_CLIENT_ID, GITHUB_APP_CLIENT_SECRET
 * The app needs only "Contents: read" and "Metadata: read", and must have
 * "Request user authorization (OAuth) during installation" enabled so the
 * callback can prove the signed-in person can access each installation.
 */

const GITHUB_API = "https://api.github.com";
const API_VERSION = "2022-11-28";
const STATE_TTL_MS = 15 * 60 * 1000;

export class GitHubAppError extends Error {
  constructor(public code: "not_configured" | "invalid_state" | "oauth_failed" | "upstream" | "no_access", message: string) {
    super(message);
  }
}

export interface GitHubAppConfig {
  appId: string;
  slug: string;
  privateKey: string;
  clientId: string;
  clientSecret: string;
}

export function normalizePrivateKey(raw: string): string {
  let key = raw.replace(/\\n/g, "\n").trim();
  if (!key.startsWith("-----BEGIN")) {
    try { key = Buffer.from(key, "base64").toString("utf8").replace(/\\n/g, "\n").trim(); } catch { /* keep original */ }
  }
  return key;
}

export function getGitHubAppConfig(env: Record<string, string | undefined> = process.env): GitHubAppConfig | null {
  const appId = env.GITHUB_APP_ID?.trim();
  const slug = env.GITHUB_APP_SLUG?.trim();
  const rawKey = env.GITHUB_APP_PRIVATE_KEY;
  const clientId = env.GITHUB_APP_CLIENT_ID?.trim();
  const clientSecret = env.GITHUB_APP_CLIENT_SECRET?.trim();
  if (!appId || !slug || !rawKey || !clientId || !clientSecret) return null;
  return { appId, slug, privateKey: normalizePrivateKey(rawKey), clientId, clientSecret };
}

function requireConfig(): GitHubAppConfig {
  const config = getGitHubAppConfig();
  if (!config) throw new GitHubAppError("not_configured", "Private repository connections are not available yet.");
  return config;
}

const base64url = (input: Buffer | string) => Buffer.from(input).toString("base64url");

/** RS256 JWT that authenticates as the app for 9 minutes (GitHub allows at most 10). */
export function createAppJwt(config: Pick<GitHubAppConfig, "appId" | "privateKey">, now = Date.now()): string {
  const header = base64url(JSON.stringify({ alg: "RS256", typ: "JWT" }));
  const seconds = Math.floor(now / 1000);
  const payload = base64url(JSON.stringify({ iat: seconds - 60, exp: seconds + 540, iss: config.appId }));
  const signer = createSign("RSA-SHA256");
  signer.update(`${header}.${payload}`);
  return `${header}.${payload}.${base64url(signer.sign(config.privateKey))}`;
}

// ── Signed state that binds the install/authorize round-trip to one signed-in user ──

function stateSecret(): string {
  const secret = process.env.AUTH_SECRET || process.env.NEXTAUTH_SECRET;
  if (!secret) throw new GitHubAppError("not_configured", "Server secret is missing.");
  return secret;
}

export function createConnectState(userId: string, secret = stateSecret(), now = Date.now()) {
  const nonce = randomBytes(16).toString("base64url");
  const body = base64url(JSON.stringify({ u: userId, n: nonce, e: now + STATE_TTL_MS }));
  const signature = createHmac("sha256", secret).update(`gh-connect.${body}`).digest("base64url");
  return { state: `${body}.${signature}`, nonce };
}

export function verifyConnectState(state: string, expected: { userId: string; nonce: string }, secret = stateSecret(), now = Date.now()) {
  const [body, signature] = state.split(".");
  if (!body || !signature) throw new GitHubAppError("invalid_state", "The GitHub connection request is invalid. Please try again.");
  // Compare the canonical encoded text so non-canonical base64 variants are rejected too.
  const wanted = Buffer.from(createHmac("sha256", secret).update(`gh-connect.${body}`).digest("base64url"));
  const given = Buffer.from(signature);
  if (given.length !== wanted.length || !timingSafeEqual(given, wanted)) throw new GitHubAppError("invalid_state", "The GitHub connection request could not be verified. Please try again.");
  let parsed: { u?: string; n?: string; e?: number };
  try { parsed = JSON.parse(Buffer.from(body, "base64url").toString("utf8")); } catch { throw new GitHubAppError("invalid_state", "The GitHub connection request is invalid."); }
  if (!parsed.e || parsed.e < now) throw new GitHubAppError("invalid_state", "The GitHub connection request expired. Please try again.");
  if (parsed.u !== expected.userId || parsed.n !== expected.nonce) throw new GitHubAppError("invalid_state", "This GitHub connection was started from another session. Please try again.");
}

// ── GitHub HTTP helpers ──

type FetchLike = typeof fetch;

async function githubRequest<T>(path: string, init: RequestInit & { token: string; scheme?: "Bearer" | "token" }, fetchImpl: FetchLike = fetch): Promise<T> {
  const { token, scheme = "Bearer", ...rest } = init;
  const response = await fetchImpl(`${GITHUB_API}${path}`, {
    ...rest,
    cache: "no-store",
    headers: {
      Accept: "application/vnd.github+json",
      "X-GitHub-Api-Version": API_VERSION,
      "User-Agent": "ScanMySaaS-GitHub-App/1.0",
      Authorization: `${scheme} ${token}`,
      ...(rest.headers || {}),
    },
  });
  if (response.status === 404 || response.status === 403) throw new GitHubAppError("no_access", "GitHub denied access to this resource.");
  if (!response.ok) throw new GitHubAppError("upstream", `GitHub returned ${response.status}.`);
  return await response.json() as T;
}

/** Exchange the OAuth code GitHub returns after install/authorize for a user-to-server token. */
export async function exchangeOAuthCode(code: string, fetchImpl: FetchLike = fetch): Promise<string> {
  const config = requireConfig();
  const response = await fetchImpl("https://github.com/login/oauth/access_token", {
    method: "POST",
    cache: "no-store",
    headers: { Accept: "application/json", "Content-Type": "application/json", "User-Agent": "ScanMySaaS-GitHub-App/1.0" },
    body: JSON.stringify({ client_id: config.clientId, client_secret: config.clientSecret, code }),
  });
  const data = await response.json().catch(() => ({})) as { access_token?: string; error?: string };
  if (!response.ok || !data.access_token) throw new GitHubAppError("oauth_failed", "GitHub did not confirm the authorization. Please try connecting again.");
  return data.access_token;
}

export interface UserInstallation { installationId: number; accountLogin: string; accountType: string }

/** Installations of THIS app that the GitHub user behind the token can access. */
export async function listUserInstallations(userToken: string, fetchImpl: FetchLike = fetch): Promise<UserInstallation[]> {
  const data = await githubRequest<{ installations?: Array<{ id: number; app_id?: number; account?: { login?: string; type?: string } }> }>("/user/installations?per_page=100", { token: userToken }, fetchImpl);
  const appId = getGitHubAppConfig()?.appId;
  return (data.installations || [])
    .filter((installation) => !appId || installation.app_id === undefined || String(installation.app_id) === appId)
    .map((installation) => ({ installationId: installation.id, accountLogin: installation.account?.login || "unknown", accountType: installation.account?.type || "User" }));
}

// Installation tokens live for one hour; cache them per instance for 50 minutes.
const tokenCache = new Map<number, { token: string; expiresAt: number }>();

export async function getInstallationToken(installationId: number, fetchImpl: FetchLike = fetch): Promise<string> {
  const cached = tokenCache.get(installationId);
  if (cached && cached.expiresAt > Date.now()) return cached.token;
  const config = requireConfig();
  const data = await githubRequest<{ token: string }>(`/app/installations/${installationId}/access_tokens`, {
    method: "POST",
    token: createAppJwt(config),
    // Narrow the token to what the scanner needs, whatever the app was granted.
    body: JSON.stringify({ permissions: { contents: "read", metadata: "read" } }),
    headers: { "Content-Type": "application/json" },
  }, fetchImpl);
  tokenCache.set(installationId, { token: data.token, expiresAt: Date.now() + 50 * 60 * 1000 });
  return data.token;
}

export interface InstallationRepository {
  fullName: string;
  private: boolean;
  defaultBranch: string;
  pushedAt: string | null;
  installationId: number;
}

export async function listInstallationRepositories(installationId: number, fetchImpl: FetchLike = fetch): Promise<InstallationRepository[]> {
  const token = await getInstallationToken(installationId, fetchImpl);
  const repositories: InstallationRepository[] = [];
  for (let page = 1; page <= 5; page++) {
    const data = await githubRequest<{ repositories?: Array<{ full_name: string; private: boolean; default_branch: string; pushed_at: string | null }>; total_count?: number }>(`/installation/repositories?per_page=100&page=${page}`, { token }, fetchImpl);
    for (const repo of data.repositories || []) repositories.push({ fullName: repo.full_name, private: repo.private, defaultBranch: repo.default_branch, pushedAt: repo.pushed_at, installationId });
    if (!data.repositories || data.repositories.length < 100) break;
  }
  return repositories;
}

export function installUrl(state: string): string {
  const config = requireConfig();
  return `https://github.com/apps/${encodeURIComponent(config.slug)}/installations/new?state=${encodeURIComponent(state)}`;
}

/** For accounts that already installed the app: authorize only, then link existing installations. */
export function authorizeUrl(state: string, redirectUri: string): string {
  const config = requireConfig();
  return `https://github.com/login/oauth/authorize?client_id=${encodeURIComponent(config.clientId)}&state=${encodeURIComponent(state)}&redirect_uri=${encodeURIComponent(redirectUri)}`;
}
