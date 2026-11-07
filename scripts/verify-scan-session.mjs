import assert from "node:assert/strict";
import { beginScanSessionVerification } from "../src/lib/scan-session-verification.ts";

const originalFetch = globalThis.fetch;
const flush = () => new Promise((resolve) => setImmediate(resolve));
const deferred = () => {
  let resolve;
  let reject;
  const promise = new Promise((yes, no) => { resolve = yes; reject = no; });
  return { promise, resolve, reject };
};

try {
  const requests = [];
  globalThis.fetch = (_url, options) => {
    const request = deferred();
    requests.push({ ...request, signal: options.signal, cache: options.cache });
    return request.promise;
  };
  const observed = [];

  // Open a modal, receive headers, then close before its plan body is parsed.
  const firstBody = deferred();
  const closeFirst = beginScanSessionVerification((verified) => observed.push({ run: 1, verified }));
  requests[0].resolve({ ok: true, json: () => firstBody.promise });
  await flush();
  closeFirst();
  assert.equal(requests[0].signal.aborted, true, "closing a modal must cancel its in-flight verification");

  // A second opening must reverify independently, even with unchanged auth status.
  const closeSecond = beginScanSessionVerification((verified) => observed.push({ run: 2, verified }));
  assert.equal(requests.length, 2, "a reopened modal must start another verification");
  assert.equal(requests[1].cache, "no-store", "a new run must not rely on an old browser-cached plan response");
  requests[1].resolve(Response.json({ plan: "free" }));
  await flush();
  assert.deepEqual(observed, [{ run: 2, verified: true }], "a valid account on the second run must retain full-report navigation");

  firstBody.resolve({ plan: "anonymous" });
  await flush();
  assert.deepEqual(observed, [{ run: 2, verified: true }], "a late body from the closed run must not replace the current verification");
  closeSecond();

  const closeThird = beginScanSessionVerification((verified) => observed.push({ run: 3, verified }));
  closeThird();
  requests[2].reject(new Error("late failure after close"));
  await flush();
  assert.deepEqual(observed, [{ run: 2, verified: true }], "a canceled run's rejection must not reset the current UI");

  for (const [response, expected] of [
    [Response.json({ plan: "free" }), true],
    [Response.json({ plan: "starter" }), true],
    [Response.json({ plan: "pro" }), true],
    [Response.json({ plan: "anonymous" }), false],
    [Response.json({ error: "session unavailable" }), false],
    [Response.json({ plan: "free" }, { status: 500 }), false],
  ]) {
    globalThis.fetch = async () => response;
    const updates = [];
    const cleanup = beginScanSessionVerification((verified) => updates.push(verified));
    await flush();
    assert.deepEqual(updates, [expected], "only a successful supported DB plan may verify the account");
    cleanup();
  }

  globalThis.fetch = async () => { throw new Error("network unavailable"); };
  const updates = [];
  const cleanup = beginScanSessionVerification((verified) => updates.push(verified));
  await flush();
  assert.deepEqual(updates, [false], "a current request failure must fail closed");
  cleanup();
} finally {
  globalThis.fetch = originalFetch;
}

console.log("Scan-modal session lifecycle regression checks passed.");
