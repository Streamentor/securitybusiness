/** One verification per open modal; cleanup rejects updates from an older run. */
export function beginScanSessionVerification(onVerified: (verified: boolean) => void) {
  const controller = new AbortController();
  let active = true;

  fetch("/api/user/plan", { signal: controller.signal, cache: "no-store" })
    .then(async (response) => response.ok ? await response.json() : null)
    .then((data: unknown) => {
      if (!active) return;
      const plan = data && typeof data === "object" && "plan" in data ? data.plan : null;
      onVerified(plan === "free" || plan === "starter" || plan === "pro");
    })
    .catch(() => {
      if (active) onVerified(false);
    });

  return () => {
    active = false;
    controller.abort();
  };
}
