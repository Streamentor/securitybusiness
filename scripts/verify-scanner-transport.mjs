import assert from "node:assert/strict";
import { MAX_SCAN_RESPONSE_BYTES, safeFetch } from "../src/lib/scanner.ts";

const originalFetch = globalThis.fetch;
const target = "https://203.0.113.1";
const flushCancellation = () => new Promise((resolve) => setImmediate(resolve));

// All requests and body streams below are local fixtures; no target is contacted.
try {
  const headers = new Headers({ "content-type": "application/json" });
  headers.append("set-cookie", "one=1; HttpOnly");
  headers.append("set-cookie", "two=2; Secure");
  const originalResponse = new Response('{"ok":true}', { status: 201, headers });
  globalThis.fetch = async () => originalResponse;
  const bounded = await safeFetch(target, { timeout: 1000 });
  assert.equal(bounded, originalResponse, "the native Response and its metadata must be preserved");
  assert.equal(bounded.bodyUsed, false, "the response body must remain available to the caller");
  assert.equal(bounded.status, 201);
  assert.deepEqual(bounded.headers.getSetCookie(), ["one=1; HttpOnly", "two=2; Secure"], "multiple Set-Cookie values must remain separate");
  assert.equal(await bounded.clone().text(), '{"ok":true}', "clone/text semantics must still work after bounded buffering");
  assert.deepEqual(await bounded.json(), { ok: true });

  let stalledCanceled = false;
  let stalledSignal;
  globalThis.fetch = async (_url, options) => {
    stalledSignal = options.signal;
    return new Response(new ReadableStream({
      start(controller) { controller.enqueue(new TextEncoder().encode("first chunk")); },
      cancel() { stalledCanceled = true; return new Promise(() => {}); },
    }));
  };
  const started = performance.now();
  assert.equal(await safeFetch(target, { timeout: 50 }), null, "a stalled body must not outlive the response deadline");
  assert.ok(performance.now() - started < 1000, "the stalled-body test must finish promptly without waiting for EOF");
  await flushCancellation();
  assert.equal(stalledSignal.aborted, true, "the network request must be aborted at its deadline");
  assert.equal(stalledCanceled, true, "both tee branches must be canceled so the upstream body is released");

  let oversizedCanceled = false;
  globalThis.fetch = async () => new Response(new ReadableStream({
    pull(controller) { controller.enqueue(new Uint8Array(MAX_SCAN_RESPONSE_BYTES / 2 + 1)); },
    cancel() { oversizedCanceled = true; },
  }), { headers: { "content-length": "1" } });
  assert.equal(await safeFetch(target, { timeout: 1000 }), null, "actual decoded bytes must be bounded even when Content-Length lies");
  await flushCancellation();
  assert.equal(oversizedCanceled, true, "an oversized stream must be canceled rather than returned partially");

  let advertisedCanceled = false;
  globalThis.fetch = async () => new Response(new ReadableStream({ cancel() { advertisedCanceled = true; } }), { headers: { "content-length": String(MAX_SCAN_RESPONSE_BYTES + 1) } });
  assert.equal(await safeFetch(target, { timeout: 1000 }), null, "an advertised oversized body must be rejected before reading it");
  assert.equal(advertisedCanceled, true);

  for (const location of ["/ready", "http://127.0.0.1/private"]) {
    let redirectCanceled = false;
    let requests = 0;
    globalThis.fetch = async () => {
      requests += 1;
      if (requests === 1) return new Response(new ReadableStream({ cancel() { redirectCanceled = true; } }), { status: 302, headers: { location } });
      assert.equal(redirectCanceled, true, "an intermediate redirect body must be canceled before the next request");
      return new Response("ready");
    };
    const response = await safeFetch(target, { timeout: 1000 });
    assert.equal(redirectCanceled, true, "a redirect body must also be canceled when its next target is rejected");
    if (location.startsWith("/")) {
      assert.equal(requests, 2);
      assert.equal(await response.text(), "ready");
    } else {
      assert.equal(requests, 1, "private redirect targets must still be blocked before fetch");
      assert.equal(response, null);
    }
  }

  globalThis.fetch = async () => new Response("Moved", { status: 302, headers: { location: "/next" } });
  const manual = await safeFetch(target, { redirect: "manual", timeout: 1000 });
  assert.equal(manual.status, 302, "manual redirect inspection must retain response status and headers");
  assert.equal(manual.headers.get("location"), "/next");
  assert.equal(await manual.text(), "Moved");

  globalThis.fetch = async () => new Response(null, { status: 204, headers: { "content-length": String(MAX_SCAN_RESPONSE_BYTES + 1) } });
  const empty = await safeFetch(target, { timeout: 1000 });
  assert.equal(empty.status, 204, "bodyless HTTP responses must retain native semantics");
  assert.equal(empty.body, null);
} finally {
  globalThis.fetch = originalFetch;
}

console.log("Scanner transport regression checks passed.");
