import { posix } from "node:path";
import ts from "typescript";
import type { RepoFinding } from "./github-scanner";

type Source = { path: string; content: string };
export type RouteStatus = "public-by-design" | "auth-checked" | "no-auth-seen";
export interface RepoRoute {
  file: string;
  line: number;
  path: string;
  method: string;
  status: RouteStatus;
  evidence: string;
  priority: number;
}

const MUTATING = /^(POST|PUT|PATCH|DELETE|ACTION)$/;
const HTTP_METHOD = /^(GET|HEAD|POST|PUT|PATCH|DELETE|OPTIONS|ALL)$/;
const RISKY = /(?:admin|debug|purge|internal|stats|inbox|export|preview)/i;
const PAYMENT = /(?:stripe|paypal|checkout|billing|upsell|license|payment)/i;
const AUTH_FILE = /(?:auth|session|middleware|proxy|permission)/i;
const SOURCE = /\.[cm]?[jt]sx?$/;

function parse(file: Source) {
  return ts.createSourceFile(file.path, file.content, ts.ScriptTarget.Latest, true);
}

function walk(node: ts.Node, visit: (n: ts.Node) => void) {
  visit(node);
  node.forEachChild((child) => walk(child, visit));
}

function calls(node: ts.Node) {
  const result = new Set<string>();
  walk(node, (part) => {
    if (ts.isCallExpression(part)) result.add(part.expression.getText());
  });
  return result;
}

function authCall(name: string) {
  return /^(?:auth|getServerSession|currentUser)$/.test(name) || /(?:^|\.)auth\.(?:getUser|getClaims)$/.test(name);
}

function resolves(from: string, target: string, sources: ReadonlyMap<string, Source>) {
  const base = target.startsWith(".") ? posix.normalize(posix.join(posix.dirname(from), target))
    : target.startsWith("@/") || target.startsWith("~/") ? target.slice(2) : null;
  if (!base) return undefined;
  for (const path of [base, "src/" + base, "app/" + base]) {
    for (const name of [path, path.replace(/\.js$/, ""), path + "/index"]) {
      const file = ["", ".ts", ".tsx", ".js", ".jsx", ".mjs", ".cjs"].map((ext) => sources.get(name + ext)).find(Boolean);
      if (file) return file;
    }
  }
}

function imports(file: ts.SourceFile) {
  return file.statements.filter(ts.isImportDeclaration).filter((node): node is ts.ImportDeclaration & { moduleSpecifier: ts.StringLiteral } => ts.isStringLiteral(node.moduleSpecifier));
}

function localGuardNames(file: ts.SourceFile, sources: ReadonlyMap<string, Source>) {
  const result = new Set<string>();
  for (const node of imports(file)) {
    const bindings = node.importClause?.namedBindings;
    if (!bindings || !ts.isNamedImports(bindings)) continue;
    const target = resolves(file.fileName, node.moduleSpecifier.text, sources);
    const candidates = bindings.elements.filter((part) => /auth|user|session|admin|access|permission|role/i.test(part.name.text));
    if (!target || !candidates.length) continue;
    for (const statement of parse(target).statements) {
      if (!ts.isFunctionDeclaration(statement) || !statement.name || !statement.body) continue;
      const binding = candidates.find((part) => (part.propertyName?.text ?? part.name.text) === statement.name?.text);
      if (binding && [...calls(statement.body)].some(authCall)) result.add(binding.name.text);
    }
  }
  return result;
}

function signatureCheck(node: ts.Node, callSet: Set<string>, path: string) {
  const text = node.getText();
  const matches = (pattern: RegExp) => [...callSet].some((call) => pattern.test(call));
  if (/stripe/i.test(path)) return matches(/(?:^|\.)constructEvent(?:Async)?$/);
  if (/twilio/i.test(path)) return matches(/(?:^|\.)validateRequest(?:WithBody)?$/);
  if (/resend/i.test(path)) return matches(/webhooks\.verify$|verifyWebhookSignature$/);
  if (/paypal/i.test(path)) return matches(/verify(?:PayPal)?WebhookSignature$/);
  if (/github/i.test(path)) return matches(/(?:^|\.)verifyWebhookSignature$/) || /x-hub-signature-256/i.test(text) && matches(/(?:^|\.)timingSafeEqual$/);
  if (/ses|sns/i.test(path)) return matches(/verify(?:Sns|Ses)?(?:Message|Signature)$/);
  return matches(/verifyWebhookSignature$|\.webhooks\.verify$/);
}

function matcherCovers(path: string, matcher: string) {
  if (matcher === path) return true;
  const prefix = /^(\/[-\w/]+?)(?:\/:[\w]+\*|\/\*)$/.exec(matcher)?.[1];
  return Boolean(prefix && (path === prefix || path.startsWith(prefix + "/")));
}

function appPath(path: string) {
  return "/" + path.split("/").filter((part) => !/^\([^)]*\)$|^@/.test(part)).join("/");
}

export function inventoryRepoRoutes(files: readonly Source[]) {
  const sources = new Map(files.map((file) => [file.path, file]));
  const routes: RepoRoute[] = [];
  const findings: Array<Omit<RepoFinding, "id">> = [];
  const matchers: string[] = [];
  const proxies = files.filter((file) => /^(?:(?:src)\/)?(?:middleware|proxy)\.[cm]?[jt]s$/.test(file.path));
  for (const proxy of proxies) {
    const parsed = parse(proxy);
    const guarded = [...calls(parsed)].some((call) => authCall(call) || /^(?:withAuth|clerkMiddleware)$/.test(call));
    if (!guarded) continue;
    // Only literal, non-conditional matchers can support a coverage claim.
    walk(parsed, (node) => {
      if (!ts.isPropertyAssignment(node) || node.name.getText().replace(/['"]/g, "") !== "matcher") return;
      for (const value of ts.isArrayLiteralExpression(node.initializer) ? node.initializer.elements : [node.initializer]) {
        if (ts.isStringLiteral(value)) matchers.push(value.text);
      }
    });
  }

  for (const file of files) {
    if (!SOURCE.test(file.path) || /(?:^|\/)(?:tests?|__tests__|fixtures|examples)(?:\/|$)|\.(?:spec|test)\./i.test(file.path)) continue;
    const appRoute = /(?:^|\/)app(?:\/(.*))?\/route\.[cm]?[jt]s$/.exec(file.path);
    const pagesRoute = /(?:^|\/)pages\/api\/(.*?)\.[cm]?[jt]sx?$/.exec(file.path);
    const proxy = proxies.includes(file);
    const possibleAction = /^\s*(?:\/\*[\s\S]*?\*\/\s*|\/\/[^\n]*\n\s*)*["']use server["']/.test(file.content);
    const possibleRouter = /["'](?:express|hono|fastify)["']/.test(file.content);
    if (!appRoute && !pagesRoute && !proxy && !possibleAction && !possibleRouter) continue;

    const parsed = parse(file);
    const localGuards = localGuardNames(parsed, sources);
    const add = (node: ts.Node, path: string, method: string, body: ts.Node = node) => {
      const line = parsed.getLineAndCharacterOfPosition(node.getStart(parsed)).line + 1;
      const callSet = calls(body);
      const webhook = /webhook|(?:twilio|stripe|paypal|resend|github|ses|sns)\/callback/i.test(path + "/" + file.path);
      const signed = webhook && signatureCheck(body, callSet, path + "/" + file.path);
      const guarded = [...callSet].some((call) => authCall(call) || localGuards.has(call));
      const middleware = method !== "ACTION" && method !== "MIDDLEWARE" && matchers.some((matcher) => matcherCovers(path, matcher));
      const publicRead = /^(GET|HEAD)$/.test(method) && /\/(?:healthz?|og|opengraph-image|sitemap(?:\.xml)?|feed(?:\.xml)?|rss(?:\.xml)?)\/?$/i.test(path);
      const status = signed || publicRead ? "public-by-design" : guarded || middleware ? "auth-checked" : "no-auth-seen";
      const evidence = signed ? "Signature verification call seen" : publicRead ? "Conventional public read endpoint" : guarded ? "Authentication call seen" : middleware ? "Matches a middleware with an authentication call" : "No recognized authentication call";
      const high = webhook && !signed || status === "no-auth-seen" && (MUTATING.test(method) || method === "ALL" || RISKY.test(path));
      const priority = high && (webhook || MUTATING.test(method) || method === "ALL") ? 5 : PAYMENT.test(path) ? 4 : RISKY.test(path) ? 3 : proxy || AUTH_FILE.test(path) ? 2 : high ? 3 : 1;
      routes.push({ file: file.path, line, path, method, status, evidence, priority });
      if (method === "MIDDLEWARE" || publicRead || !webhook && status !== "no-auth-seen" || webhook && signed) return;
      findings.push({
        category: webhook ? "webhooks" : "authorization",
        severity: high ? "high" : "medium",
        title: webhook ? "Webhook signature verification not seen" : "Route authentication not seen",
        description: method + " " + path + " " + (webhook ? "has no recognized provider verification call in the handler." : "has no recognized authentication call in the handler or matching authentication middleware.") + " Verify guards and caller context in the application.",
        file: file.path, line,
        remedy: webhook ? "Verify the provider signature and reject invalid requests before running business logic. Add a test for invalid signatures and protect against duplicate deliveries."
          : "Verify whether the operation is intentionally public. For private operations, authenticate on the server and enforce the required role, tenant and resource ownership before returning data or making changes.",
      });
    };

    if (proxy) add(parsed, "/" + file.path, "MIDDLEWARE");
    const exported = (node: ts.Node) => ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.ExportKeyword);
    for (const statement of parsed.statements) {
      if (!exported(statement)) continue;
      const declarations = ts.isVariableStatement(statement) ? statement.declarationList.declarations
        : ts.isFunctionDeclaration(statement) ? [statement] : [];
      for (const declaration of declarations) {
        const name = declaration.name?.getText(parsed);
        if (appRoute && name && HTTP_METHOD.test(name)) add(declaration, appPath(appRoute[1] ?? ""), name);
        else if (possibleAction && name && (ts.isFunctionDeclaration(declaration) || ts.isVariableDeclaration(declaration) && declaration.initializer && (ts.isArrowFunction(declaration.initializer) || ts.isFunctionExpression(declaration.initializer)))) add(declaration, file.path + "#" + name, "ACTION");
      }
      if (appRoute && ts.isExportDeclaration(statement) && statement.exportClause && ts.isNamedExports(statement.exportClause)) {
        for (const entry of statement.exportClause.elements) {
          if (HTTP_METHOD.test(entry.name.text)) add(entry, appPath(appRoute[1] ?? ""), entry.name.text);
        }
      }
    }
    if (pagesRoute) {
      const handler = parsed.statements.find((node) => ts.isExportAssignment(node) || ts.canHaveModifiers(node) && ts.getModifiers(node)?.some((modifier) => modifier.kind === ts.SyntaxKind.DefaultKeyword));
      if (handler) add(handler, "/api/" + pagesRoute[1].replace(/(?:^|\/)index$/, ""), "ALL");
    }
    if (possibleRouter) {
      walk(parsed, (node) => {
        if (!ts.isCallExpression(node) || !ts.isPropertyAccessExpression(node.expression)) return;
        const method = node.expression.name.text.toUpperCase();
        const [path] = node.arguments;
        if (HTTP_METHOD.test(method) && path && ts.isStringLiteral(path) && path.text.startsWith("/")) add(node, path.text, method);
        if (method === "ROUTE" && path && ts.isObjectLiteralExpression(path)) {
          const fields = new Map(path.properties.filter(ts.isPropertyAssignment).map((prop) => [prop.name.getText(parsed).replace(/['"]/g, ""), prop.initializer]));
          const url = fields.get("url"), verb = fields.get("method"), handler = fields.get("handler");
          if (url && verb && handler && ts.isStringLiteral(url) && ts.isStringLiteral(verb) && HTTP_METHOD.test(verb.text.toUpperCase())) add(node, url.text, verb.text.toUpperCase(), handler);
        }
      });
    }
  }
  return { routes, findings };
}

export function prioritizeRepoReview(files: readonly Source[], routes: readonly RepoRoute[], riskScore: (path: string) => number, eligible: (path: string) => boolean, previouslyReviewed: ReadonlySet<string> = new Set()) {
  const sources = new Map(files.map((file) => [file.path, file]));
  const priorities = new Map<string, number>();
  for (const route of routes) priorities.set(route.file, Math.max(priorities.get(route.file) ?? 0, route.priority));
  const ranked = files.filter((file) => eligible(file.path) && !previouslyReviewed.has(file.path)).sort((a, b) =>
    (priorities.get(b.path) ?? 0) - (priorities.get(a.path) ?? 0) || riskScore(b.path) - riskScore(a.path) || a.path.localeCompare(b.path));
  return ranked.map((file) => {
    if (!SOURCE.test(file.path) || !priorities.has(file.path)) return file;
    const context = imports(parse(file)).map((node) => resolves(file.path, node.moduleSpecifier.text, sources))
      .filter((item): item is Source => Boolean(item && eligible(item.path) && item.path !== file.path));
    return context.length ? { ...file, context } : file;
  });
}
