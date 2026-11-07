import assert from "node:assert/strict";

// Synthetic fixtures only; nothing here contacts a website.
const scanner = await import("../src/lib/scanner.ts");
const url = "https://fixture.invalid/";
const inline = (policy) => scanner.analyzeCSP(url, policy).some((finding) => finding.title === "CSP Allows Unsafe Inline Scripts");
const evalAllowed = (policy) => scanner.analyzeCSP(url, policy).some((finding) => finding.title === "CSP Allows Unsafe Eval");

// CSP semantics (W3C CSP3)
assert.equal(inline("script-src 'nonce-abc' 'strict-dynamic' 'unsafe-inline' https:; object-src 'none'; base-uri 'none'"), false, "'unsafe-inline' is ignored next to a nonce");
assert.equal(inline("script-src 'sha256-AAAA' 'unsafe-inline'"), false, "'unsafe-inline' is ignored next to a hash");
assert.equal(inline("script-src 'none'; script-src-elem 'unsafe-inline'"), true, "script-src-elem overrides script-src for script elements");
assert.equal(inline("script-src 'self'; script-src-attr 'unsafe-inline'"), true, "inline event handlers via script-src-attr are detected");
assert.equal(inline("script-src 'self'; script-src 'unsafe-inline'"), false, "the first duplicate directive wins");
assert.equal(inline("script-src 'unsafe-inline'; script-src 'self'"), true, "the first duplicate directive wins");
assert.equal(inline("default-src 'self' 'unsafe-inline'"), true, "default-src fallback still applies");
assert.equal(inline("script-src 'unsafe-inline', script-src 'self'"), false, "every enforced policy must allow inline execution");
assert.equal(inline("img-src 'self'"), false, "a policy without script restrictions is not reported as 'unsafe-inline'");
assert.equal(evalAllowed("script-src 'self' 'unsafe-eval'"), true);
assert.equal(evalAllowed("script-src 'self' 'unsafe-eval', script-src 'self'"), false);
assert.equal(scanner.analyzeCSP(url, "default-src 'self'; object-src 'none', default-src *").some((f) => f.title === "CSP Does Not Restrict Object Sources"), false, "one restricting policy is enough for object-src");

// CSRF per form
const csrf = (html) => scanner.checkHTMLSecurity(url, html).filter((finding) => finding.type === "csrf");
const mixed = csrf('<form method="post"><input name="csrf_token"></form><form method="post" action="/delete"></form>');
assert.equal(mixed.length, 1, "a form without a token must still be reported when another form has one");
assert.match(mixed[0].description, /^1 state-changing form/);
assert.equal(mixed[0].severity, "low", "a missing visible token is a review signal");
assert.equal(csrf('<form method="post"><input name="tokenizer_mode"></form>').length, 1, "token-like substrings are not tokens");
assert.equal(csrf('<form method="POST"><input type="hidden" name="authenticity_token"></form>').length, 0);
assert.equal(csrf('<form method="post"><input type="hidden" name="$ACTION_ID_abc"></form>').length, 0, "Next.js server actions are Origin-checked");
assert.equal(csrf('<form><input name="q"></form>').length, 0, "forms without a method are GET");

// XSS sinks vs text
const xss = (html) => scanner.checkHTMLSecurity(url, html).filter((finding) => finding.type === "xss");
assert.equal(xss('<script>const documentation = "element.innerHTML = value";</script>').length, 0, "sinks inside strings are text");
assert.equal(xss("<script>// never use el.innerHTML = x\n/* eval(x) */</script>").length, 0, "sinks inside comments are text");
assert.equal(xss("<script>const t = `document.write(x)`;</script>").length, 0, "sinks inside template literals are text");
assert.equal(xss("<script>if (el.innerHTML == '') {}</script>").length, 0, "comparison is not assignment");
const sink = xss("<script>el.innerHTML = location.hash</script>");
assert.equal(sink.length, 1);
assert.equal(sink[0].severity, "medium");
assert.equal(scanner.stripJsLiteralsAndComments('a = "x\\"y"; b'), 'a = ""; b');

// Cookies are checked one by one
const headers = new Headers();
headers.append("set-cookie", "session=abc; Path=/");
headers.append("set-cookie", "prefs=1; HttpOnly; Secure; SameSite=Lax");
const cookies = scanner.checkCookies(url, headers);
const httpOnly = cookies.find((finding) => finding.title === "Cookies Without HttpOnly");
assert.ok(httpOnly, "a session cookie without HttpOnly must be reported even if another cookie has the flag");
assert.equal(httpOnly.severity, "medium");
assert.match(httpOnly.description, /session/);
assert.ok(cookies.some((finding) => finding.title === "Cookies Without Secure Flag"));
const secureNamed = new Headers({ "set-cookie": "__Secure-x=1; Path=/; HttpOnly; SameSite=Lax" });
assert.ok(scanner.checkCookies(url, secureNamed).some((finding) => finding.title === "Cookies Without Secure Flag"), "a cookie name containing 'Secure' is not the Secure attribute");
const theme = new Headers({ "set-cookie": "theme=dark; Path=/; Secure; SameSite=Lax" });
assert.equal(scanner.checkCookies(url, theme).find((finding) => finding.title === "Cookies Without HttpOnly")?.severity, "low", "non-session cookies readable by JS are low severity");
assert.equal(scanner.checkCookies("http://fixture.invalid/", new Headers({ "set-cookie": "a=1; HttpOnly; SameSite=Lax" })).some((finding) => finding.title === "Cookies Without Secure Flag"), false, "Secure is not required on plain HTTP origins");

// Removed checks no longer produce hidden findings that lower the score
const legacy = scanner.checkHTMLSecurity(url, '<iframe src="https://other.example"></iframe><input type="password" autocomplete="on"><a href="/login?next=https://evil.example">x</a><a href="https://x.example" target="_blank" rel="opener">x</a>').map((finding) => finding.title);
for (const title of ["External Iframes Without Sandbox", "Password Fields Allow Autocomplete", "Potential Open Redirect Parameters", 'target="_blank" Missing rel="noopener"']) {
  assert.equal(legacy.includes(title), false, `${title} is hidden in reports and must not be produced`);
}

console.log("Scanner accuracy checks passed.");
