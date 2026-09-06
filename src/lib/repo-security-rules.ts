export type RepoRuleSeverity = "critical" | "high" | "medium" | "low";
export type RepoRuleCategory = "secrets" | "environment" | "github-actions" | "database" | "client-code" | "dependencies" | "agent-security";

export interface RepositoryFile {
  path: string;
  content: string;
}

export interface RepoRuleFinding {
  severity: RepoRuleSeverity;
  category: RepoRuleCategory;
  title: string;
  description: string;
  file: string;
  line: number | null;
  remedy: string;
  referenceUrl?: string;
}

export interface DependencyCoordinate {
  ecosystem: "npm" | "PyPI" | "Go" | "crates.io";
  name: string;
  version: string;
  file: string;
  line: number | null;
}

const MAX_DEPENDENCIES = 180;

function lineOf(content: string, index: number) {
  return content.slice(0, Math.max(0, index)).split("\n").length;
}

function lineFor(content: string, needle: string) {
  const index = content.indexOf(needle);
  return index === -1 ? null : lineOf(content, index);
}

function looksLikePlaceholder(value: string) {
  return /^(?:\$\{|process\.env|env\.|<|your[_-]|example|placeholder|changeme|replace[_-]?me)/i.test(value.trim());
}

function packageNameFromLockPath(path: string) {
  const marker = "node_modules/";
  const index = path.lastIndexOf(marker);
  return index === -1 ? "" : path.slice(index + marker.length);
}

function addDependency(target: Map<string, DependencyCoordinate>, dependency: DependencyCoordinate) {
  if (!dependency.name || !dependency.version || dependency.version.length > 100) return;
  if (/^(?:file:|link:|workspace:|https?:|git\+|github:)/i.test(dependency.version)) return;
  const key = `${dependency.ecosystem}:${dependency.name.toLowerCase()}:${dependency.version}`;
  if (!target.has(key)) target.set(key, dependency);
}

export function isAgentSecurityFile(path: string) {
  const lower = path.toLowerCase();
  const basename = lower.split("/").pop() || "";
  if (["agents.md", "claude.md", ".mcp.json", "mcp.json", "claude_desktop_config.json"].includes(basename)) return true;
  if (/(^|\/)\.claude\/(?:settings(?:\.local)?\.json|commands\/.*\.md|agents\/.*\.md)$/.test(lower)) return true;
  if (/(^|\/)\.cursor\/(?:mcp\.json|rules\/.*(?:\.md|\.mdc))$/.test(lower)) return true;
  if (/(^|\/)\.codex\/(?:config\.toml|skills\/.*\/skill\.md)$/.test(lower)) return true;
  if (/(^|\/)\.agents\/skills\/.*\/skill\.md$/.test(lower)) return true;
  return false;
}

export function analyzeAgentSecurityFile(file: RepositoryFile): RepoRuleFinding[] {
  if (!isAgentSecurityFile(file.path)) return [];
  const findings: RepoRuleFinding[] = [];
  const add = (finding: Omit<RepoRuleFinding, "file">) => findings.push({ ...finding, file: file.path });
  const content = file.content;

  const destructive = /\b(?:sudo\s+)?rm\s+-rf\s+(?:\/(?:\s|$)|~(?:\/|\s|$)|\$\{?HOME\}?\b)/im.exec(content);
  if (destructive) add({ severity: "high", category: "agent-security", title: "Agent instructions include a destructive filesystem command", description: "An AI coding instruction or hook contains an unbounded recursive delete targeting a system or home path.", line: lineOf(content, destructive.index), remedy: "Remove the command or constrain it to an explicit, validated temporary directory. Require a human confirmation step before destructive operations and add a negative test proving broad paths are rejected." });

  const pipeToShell = /(?:curl|wget)\b[^\n|]{0,300}\|\s*(?:sudo\s+)?(?:ba|z|fi)?sh\b/im.exec(content);
  if (pipeToShell) add({ severity: "high", category: "agent-security", title: "Agent instructions pipe a remote download into a shell", description: "The agent configuration can execute network-delivered code without a reviewable local artifact or integrity check.", line: lineOf(content, pipeToShell.index), remedy: "Download a versioned artifact first, verify its checksum or signature, inspect it, and execute only the verified local file. Pin the source and avoid automatic privilege elevation." });

  const secretTransfer = /(?:(?:curl|wget|fetch|upload|webhook|http\s+post)[^\n]{0,220}(?:\.env\b|process\.env)|(?:\.env\b|process\.env)[^\n]{0,220}(?:curl|wget|fetch|upload|webhook|http\s+post))/im.exec(content);
  if (secretTransfer) add({ severity: "critical", category: "agent-security", title: "Agent instruction may transmit environment secrets", description: "A network or upload instruction appears on the same command path as environment-file or process environment access.", line: lineOf(content, secretTransfer.index), remedy: "Disable this instruction or hook until its destination and data flow are verified. Never send an environment file or the full process environment. Pass only an explicit allowlist of non-secret fields and add an egress test with fake canary values." });

  const overridePhrase = /ignore\s+(?:all\s+|any\s+|the\s+)?(?:previous|prior|system)\s+instructions?/i.exec(content);
  if (overridePhrase && /(?:skill\.md|commands\/|agents\/)/i.test(file.path)) add({ severity: "medium", category: "agent-security", title: "Agent skill contains an instruction-override phrase", description: "A reusable agent skill tries to override earlier instructions. In a third-party skill this can be a prompt-injection signal, though legitimate security examples can also match.", line: lineOf(content, overridePhrase.index), remedy: "Review the skill source and publisher. Remove instruction-override language, constrain allowed tools and paths, and test the skill against requests involving secrets, network access, and destructive commands before enabling it." });

  if (/\.json$/i.test(file.path)) {
    try {
      const parsed = JSON.parse(content) as Record<string, unknown>;
      const permissions = parsed.permissions && typeof parsed.permissions === "object" ? parsed.permissions as Record<string, unknown> : null;
      const allowed = permissions && Array.isArray(permissions.allow) ? permissions.allow.map(String) : [];
      const broadPermission = allowed.find((value) => /^(?:\*|Bash\s*\(\s*\*\s*\)|Bash:\*)$/i.test(value.trim()));
      if (broadPermission) add({ severity: "high", category: "agent-security", title: "AI agent has unrestricted shell permission", description: `The agent permission allowlist includes ${broadPermission}, which can let generated instructions run arbitrary shell commands without a per-command review.`, line: lineFor(content, broadPermission), remedy: "Replace the wildcard with the smallest command and path allowlist needed for this repository. Keep network, credential, Git push, deployment, and destructive commands behind explicit approval." });

      const servers = parsed.mcpServers && typeof parsed.mcpServers === "object" ? parsed.mcpServers as Record<string, unknown> : {};
      for (const [serverName, rawServer] of Object.entries(servers)) {
        if (!rawServer || typeof rawServer !== "object") continue;
        const server = rawServer as Record<string, unknown>;
        const url = typeof server.url === "string" ? server.url : "";
        if (/^http:\/\//i.test(url) && !/^http:\/\/(?:localhost|127\.0\.0\.1|\[::1\])(?::|\/|$)/i.test(url)) {
          let endpoint = "the configured remote endpoint";
          try { endpoint = new URL(url).origin; } catch { /* Never copy a malformed URL that might contain a credential. */ }
          add({ severity: "high", category: "agent-security", title: "Remote MCP server uses unencrypted HTTP", description: `The ${serverName} MCP server sends agent traffic to ${endpoint} without TLS. Prompts, tool inputs, or credentials can be observed or modified in transit.`, line: lineFor(content, url), remedy: "Use a verified HTTPS endpoint with certificate validation. Rotate any credential previously sent to the HTTP endpoint and restrict the MCP server to the minimum tools and data it needs." });
        }

        const command = typeof server.command === "string" ? server.command : "";
        const args = Array.isArray(server.args) ? server.args.map(String) : [];
        if (/^(?:npx|bunx)$/i.test(command)) {
          const packageArg = args.find((value) => !value.startsWith("-") && value !== "npx" && value !== "bunx");
          const pinned = packageArg ? (/^@[^/]+\/[^@]+@\d/.test(packageArg) || /^[^@]+@\d/.test(packageArg)) : false;
          if (packageArg && !pinned) add({ severity: "medium", category: "agent-security", title: "MCP package is executed without a pinned version", description: `The ${serverName} MCP server runs ${packageArg} through ${command} without an exact version. A future registry release can change the code your agent executes.`, line: lineFor(content, packageArg), remedy: "Pin the MCP package to an reviewed exact version and update it deliberately. Prefer a lockfile or a locally installed binary, and verify the package publisher and integrity before granting tools or secrets." });
        }

        if (/^uvx$/i.test(command)) {
          const packageArg = args.find((value) => !value.startsWith("-"));
          if (packageArg && !/==\d/.test(packageArg)) add({ severity: "medium", category: "agent-security", title: "Python MCP package is executed without a pinned version", description: `The ${serverName} MCP server runs ${packageArg} through uvx without an exact version.`, line: lineFor(content, packageArg), remedy: "Pin the package with an exact version, verify its publisher and hash, and update it through a reviewed change." });
        }

        const env = server.env && typeof server.env === "object" ? server.env as Record<string, unknown> : {};
        for (const [key, rawValue] of Object.entries(env)) {
          const value = typeof rawValue === "string" ? rawValue : "";
          if (!/(?:SECRET|TOKEN|PASSWORD|PRIVATE|API[_-]?KEY|SERVICE[_-]?ROLE)/i.test(key) || !value || looksLikePlaceholder(value)) continue;
          add({ severity: "critical", category: "agent-security", title: "Literal credential stored in MCP configuration", description: `The MCP server ${serverName} has a literal value for the secret-like ${key} field. The value is not included in this report.`, line: lineFor(content, key), remedy: "Rotate the credential, remove it from Git history, and inject it from the local or deployment secret store. Limit the MCP server's access and confirm that logs never record the value." });
        }
      }
    } catch {
      // Invalid JSON is handled by the tool that consumes it; raw-pattern checks above still run.
    }
  }

  return findings;
}

export function analyzeDependencyHygiene(files: RepositoryFile[], repositoryPaths = files.map((file) => file.path), treeComplete = true): RepoRuleFinding[] {
  const findings: RepoRuleFinding[] = [];
  const packageFiles = files.filter((file) => /(^|\/)package\.json$/i.test(file.path));
  const hasNpmLock = repositoryPaths.some((path) => /(^|\/)(?:package-lock\.json|npm-shrinkwrap\.json|pnpm-lock\.yaml|yarn\.lock|bun\.lockb?)$/i.test(path));

  if (packageFiles.length && !hasNpmLock && treeComplete) findings.push({ severity: "medium", category: "dependencies", title: "JavaScript dependencies have no scanned lockfile", description: "A package.json was found, but no npm, pnpm, Yarn, or Bun lockfile was listed in the repository tree. Builds can resolve different transitive versions over time.", file: packageFiles[0].path, line: 1, remedy: "Generate and commit the lockfile for the package manager used in CI. Install with the frozen or clean-install command and review automated dependency updates before merging." });

  for (const file of packageFiles) {
    try {
      const parsed = JSON.parse(file.content) as Record<string, unknown>;
      for (const group of ["dependencies", "devDependencies", "optionalDependencies"]) {
        const dependencies = parsed[group] && typeof parsed[group] === "object" ? parsed[group] as Record<string, unknown> : {};
        for (const [name, rawVersion] of Object.entries(dependencies)) {
          const version = String(rawVersion);
          if (/^(?:\*|latest|next)$/i.test(version)) findings.push({ severity: "medium", category: "dependencies", title: "Dependency uses a floating version", description: `${name} is declared as ${version}, so a future install can silently select different code.`, file: file.path, line: lineFor(file.content, `"${name}"`), remedy: "Choose a reviewed release, pin it through the lockfile, and let an automated update tool propose later versions in separate pull requests." });
          else if (/^(?:https?:|git\+|github:)/i.test(version) && !/#[a-f0-9]{40}$/i.test(version)) findings.push({ severity: "medium", category: "dependencies", title: "Source dependency is not pinned to an immutable commit", description: `${name} is installed from a URL or Git reference that is not pinned to a full commit SHA.`, file: file.path, line: lineFor(file.content, `"${name}"`), remedy: "Pin the source dependency to a reviewed full commit SHA or a published registry version with lockfile integrity metadata." });
        }
      }

      const scripts = parsed.scripts && typeof parsed.scripts === "object" ? parsed.scripts as Record<string, unknown> : {};
      for (const hook of ["preinstall", "install", "postinstall"]) {
        const command = typeof scripts[hook] === "string" ? scripts[hook] as string : "";
        if (/(?:curl|wget)\b[^|\n]*\|\s*(?:ba|z|fi)?sh\b/i.test(command)) findings.push({ severity: "high", category: "dependencies", title: "Package install hook executes network-delivered shell code", description: `The ${hook} script downloads code and pipes it directly into a shell during dependency installation.`, file: file.path, line: lineFor(file.content, `"${hook}"`), remedy: "Remove the network pipe from the install lifecycle. Vendor or download a versioned artifact separately, verify its checksum or signature, and execute only the reviewed local file." });
      }
    } catch {
      // The package manager will report malformed JSON; avoid duplicating that as a security finding.
    }
  }
  return findings;
}

export function extractDependencyInventory(files: RepositoryFile[]) {
  const dependencies = new Map<string, DependencyCoordinate>();
  let manifests = 0;

  for (const file of files) {
    const basename = file.path.toLowerCase().split("/").pop() || "";
    if (["package-lock.json", "npm-shrinkwrap.json"].includes(basename)) {
      manifests += 1;
      try {
        const parsed = JSON.parse(file.content) as { packages?: Record<string, { name?: string; version?: string }> };
        for (const [lockPath, record] of Object.entries(parsed.packages || {})) {
          if (!lockPath.includes("node_modules/") || !record?.version) continue;
          const name = record.name || packageNameFromLockPath(lockPath);
          addDependency(dependencies, { ecosystem: "npm", name, version: record.version, file: file.path, line: lineFor(file.content, `"${lockPath}"`) });
        }
      } catch { /* Ignore malformed lockfiles. */ }
      continue;
    }

    if (/^requirements(?:-[a-z0-9_.-]+)?\.txt$/i.test(basename)) {
      manifests += 1;
      for (const line of file.content.split("\n")) {
        const match = /^\s*([A-Za-z0-9_.-]+)==([A-Za-z0-9_.+!-]+)\s*(?:#.*)?$/.exec(line);
        if (match) addDependency(dependencies, { ecosystem: "PyPI", name: match[1], version: match[2], file: file.path, line: lineFor(file.content, line) });
      }
      continue;
    }

    if (basename === "go.mod") {
      manifests += 1;
      const requirement = /^\s*([A-Za-z0-9_.~/-]+)\s+(v[0-9][^\s]*)/gm;
      for (let match = requirement.exec(file.content); match; match = requirement.exec(file.content)) addDependency(dependencies, { ecosystem: "Go", name: match[1], version: match[2], file: file.path, line: lineOf(file.content, match.index) });
      continue;
    }

    if (basename === "cargo.lock") {
      manifests += 1;
      const block = /\[\[package\]\]\s+name\s*=\s*"([^"]+)"\s+version\s*=\s*"([^"]+)"/g;
      for (let match = block.exec(file.content); match; match = block.exec(file.content)) addDependency(dependencies, { ecosystem: "crates.io", name: match[1], version: match[2], file: file.path, line: lineOf(file.content, match.index) });
    }
  }

  const all = [...dependencies.values()];
  return { dependencies: all.slice(0, MAX_DEPENDENCIES), total: all.length, manifests, truncated: all.length > MAX_DEPENDENCIES };
}

export function buildOsvQueryBatch(dependencies: DependencyCoordinate[]) {
  return { queries: dependencies.map((dependency) => ({ package: { ecosystem: dependency.ecosystem, name: dependency.name }, version: dependency.version })) };
}

export function normalizeOsvBatchResponse(value: unknown, dependencies: DependencyCoordinate[]) {
  if (!value || typeof value !== "object" || !("results" in value) || !Array.isArray((value as { results: unknown }).results)) return null;
  const results = (value as { results: unknown[] }).results;
  if (results.length !== dependencies.length) return null;
  if (results.some((result) => {
    if (!result || typeof result !== "object" || Array.isArray(result)) return true;
    const record = result as { vulns?: unknown; next_page_token?: unknown };
    if (record.next_page_token !== undefined && typeof record.next_page_token !== "string") return true;
    if (record.vulns === undefined) return false;
    return !Array.isArray(record.vulns) || record.vulns.some((vulnerability) => !vulnerability || typeof vulnerability !== "object" || !("id" in vulnerability) || typeof vulnerability.id !== "string" || !vulnerability.id.trim());
  })) return null;
  return results.map((result, index) => {
    const record = result && typeof result === "object" ? result as { vulns?: unknown; next_page_token?: unknown } : {};
    const ids = Array.isArray(record.vulns) ? record.vulns.map((vulnerability) => vulnerability && typeof vulnerability === "object" && "id" in vulnerability ? String((vulnerability as { id: unknown }).id) : "").filter(Boolean) : [];
    const uniqueIds = [...new Set(ids)];
    return { dependency: dependencies[index], ids: uniqueIds.slice(0, 20), paginated: uniqueIds.length > 20 || (typeof record.next_page_token === "string" && Boolean(record.next_page_token)) };
  });
}
