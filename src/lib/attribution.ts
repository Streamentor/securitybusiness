type AttributionStorage = Pick<Storage, "getItem" | "setItem">;

/** Capture the first landing on any page without storing referring URL queries. */
export function captureAttribution(href: string, referrer: string, storage: AttributionStorage) {
  if (storage.getItem("attribution_captured")) return;
  const landing = new URL(href);
  if (referrer && !storage.getItem("referrer_url")) {
    try {
      const source = new URL(referrer);
      if (["http:", "https:"].includes(source.protocol) && source.hostname.replace(/^www\./, "") !== landing.hostname.replace(/^www\./, "")) {
        storage.setItem("referrer_url", source.origin);
      }
    } catch {
      // Ignore malformed referrers.
    }
  }
  for (const key of ["utm_source", "utm_medium", "utm_campaign"]) {
    const value = landing.searchParams.get(key);
    if (value && !storage.getItem(key)) storage.setItem(key, value.slice(0, 200));
  }
  storage.setItem("attribution_captured", "1");
}
