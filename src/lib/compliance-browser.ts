import type { Browser, BrowserContext, Frame, Page } from "playwright-core";
import type { VulnerabilityResult } from "./scanner";
import { TRACKERS, detectTrackers, type TrackerSignature } from "@/lib/compliance";

/**
 * Loads the site in a real browser to see what happens before and after consent.
 * Evidence is cookies, not network requests: Google consent mode sends cookieless
 * pings while consent is denied, and those must not be reported as tracking.
 */

export interface BrowserConsentResult {
  status: "ran" | "unavailable";
  findings: VulnerabilityResult[];
  trackers: TrackerSignature[];
  bannerFound: boolean;
}

interface BrowserOptions {
  timeoutMs: number;
  /** Rejects hosts that are not public. Called for every request the page makes. */
  assertPublicHost: (hostname: string) => Promise<void>;
}

const ACCEPT = /^(?:accept|accept all|accept all cookies|accept cookies|allow all|allow all cookies|allow cookies|i agree|agree|agree and close|i accept|yes,? i agree|got it|ok|okay|alle akzeptieren|akzeptieren|alle zulassen|tout accepter|accepter|j'accepte|aceptar|aceptar todo|aceptar todas|accetta|accetta tutti|aceitar|aceitar todos|prihvati|prihvatam|prihvati sve|slažem se)$/i;
const REJECT = /^(?:reject|reject all|reject all cookies|reject cookies|decline|decline all|deny|deny all|refuse|refuse all|disagree|necessary only|only necessary|only necessary cookies|use necessary cookies only|essential only|only essential|essential cookies only|continue without accepting|ablehnen|alle ablehnen|nur notwendige|nur notwendige cookies|tout refuser|refuser|continuer sans accepter|rechazar|rechazar todo|rechazar todas|rifiuta|rifiuta tutti|rejeitar|odbij|odbij sve|samo neophodni)$/i;
const BANNER_CONTEXT = /cookie|consent|privacy|datenschutz|tracking|kolačić|kolacic|personal data|gdpr/i;

function trackerForCookie(name: string) {
  return TRACKERS.find((tracker) => tracker.cookies.some((pattern) => pattern.test(name)));
}

function trackerCookies(cookies: Array<{ name: string; domain: string }>) {
  return cookies.flatMap((cookie) => {
    const tracker = trackerForCookie(cookie.name);
    return tracker ? [{ ...cookie, tracker }] : [];
  });
}

async function launch(): Promise<Browser> {
  const { chromium } = await import("playwright-core");
  if (process.env.VERCEL || process.env.AWS_LAMBDA_FUNCTION_NAME) {
    const serverless = (await import("@sparticuz/chromium")).default;
    return chromium.launch({ executablePath: await serverless.executablePath(), args: serverless.args, headless: true });
  }
  return chromium.launch({ headless: true });
}

async function guardedContext(browser: Browser, options: BrowserOptions, extra: Parameters<Browser["newContext"]>[0] = {}) {
  const context = await browser.newContext({ acceptDownloads: false, locale: "en-US", viewport: { width: 1280, height: 860 }, serviceWorkers: "block", ...extra });
  const checked = new Map<string, Promise<boolean>>();
  await context.route("**/*", async (route) => {
    const request = route.request();
    let url: URL;
    try { url = new URL(request.url()); } catch { return route.abort(); }
    if (url.protocol === "data:" || url.protocol === "blob:") return route.continue();
    if (url.protocol !== "http:" && url.protocol !== "https:") return route.abort();
    if (["media", "font"].includes(request.resourceType())) return route.abort();
    let allowed = checked.get(url.hostname);
    if (!allowed) {
      allowed = options.assertPublicHost(url.hostname).then(() => true, () => false);
      checked.set(url.hostname, allowed);
    }
    return (await allowed) ? route.continue() : route.abort();
  });
  return context;
}

interface BannerButtons { accept: boolean; reject: boolean }

/** Marks the first visible reject button with a data attribute so it can be clicked. */
async function findBannerButtons(frame: Frame): Promise<BannerButtons> {
  return frame.evaluate(({ accept, reject, context }) => {
    const acceptRe = new RegExp(accept, "i"), rejectRe = new RegExp(reject, "i"), contextRe = new RegExp(context, "i");
    const visible = (el: Element) => {
      const rect = el.getBoundingClientRect();
      const style = getComputedStyle(el);
      return rect.width > 0 && rect.height > 0 && style.visibility !== "hidden" && style.display !== "none" && Number(style.opacity) > 0.05;
    };
    const inBanner = (el: Element) => {
      let node: Element | null = el;
      for (let depth = 0; node && depth < 7; depth += 1, node = node.parentElement) {
        if (contextRe.test((node.textContent || "").slice(0, 3000))) return true;
      }
      return false;
    };
    const result = { accept: false, reject: false };
    for (const el of Array.from(document.querySelectorAll("button, a, [role=button], input[type=button], input[type=submit]"))) {
      const label = ((el as HTMLInputElement).value || el.textContent || el.getAttribute("aria-label") || "").replace(/\s+/g, " ").trim();
      if (!label || label.length > 45 || !visible(el) || !inBanner(el)) continue;
      if (rejectRe.test(label) && !result.reject) { result.reject = true; el.setAttribute("data-smr-reject", "1"); }
      if (acceptRe.test(label)) result.accept = true;
    }
    return result;
  }, { accept: ACCEPT.source, reject: REJECT.source, context: BANNER_CONTEXT.source }).catch(() => ({ accept: false, reject: false }));
}

async function findBanner(page: Page) {
  const found = { accept: false, reject: false, rejectFrame: null as Frame | null };
  for (const frame of page.frames()) {
    const buttons = await findBannerButtons(frame);
    found.accept ||= buttons.accept;
    if (buttons.reject && !found.reject) { found.reject = true; found.rejectFrame = frame; }
  }
  return found;
}

async function open(context: BrowserContext, url: string) {
  const page = await context.newPage();
  await page.goto(url, { waitUntil: "domcontentloaded", timeout: 15_000 });
  await page.waitForLoadState("load", { timeout: 6_000 }).catch(() => undefined);
  await page.waitForTimeout(3_500);
  return page;
}

/** Text-contrast sample on the first screen: only clear failures below 3:1 are counted. */
async function lowContrastSamples(page: Page): Promise<string[]> {
  return page.evaluate(() => {
    const parse = (value: string) => {
      const match = value.match(/rgba?\(([^)]+)\)/);
      if (!match) return null;
      const [r, g, b, a = "1"] = match[1].split(/[\s,/]+/).filter(Boolean);
      return { r: Number(r), g: Number(g), b: Number(b), a: Number(a) };
    };
    const luminance = ({ r, g, b }: { r: number; g: number; b: number }) => {
      const channel = (v: number) => { const c = v / 255; return c <= 0.03928 ? c / 12.92 : ((c + 0.055) / 1.055) ** 2.4; };
      return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
    };
    const background = (el: Element | null): { r: number; g: number; b: number } | null => {
      for (let node = el; node; node = node.parentElement) {
        const style = getComputedStyle(node);
        if (style.backgroundImage !== "none") return null;
        const color = parse(style.backgroundColor);
        if (color && color.a >= 0.95) return color;
        if (color && color.a > 0.05) return null;
      }
      return { r: 255, g: 255, b: 255 };
    };
    const samples: string[] = [];
    const walker = document.createTreeWalker(document.body, NodeFilter.SHOW_TEXT);
    let checked = 0;
    while (walker.nextNode() && checked < 400 && samples.length < 5) {
      const text = (walker.currentNode.textContent || "").replace(/\s+/g, " ").trim();
      const el = walker.currentNode.parentElement;
      if (text.length < 3 || !el) continue;
      const rect = el.getBoundingClientRect();
      if (rect.width === 0 || rect.height === 0 || rect.top > window.innerHeight * 2) continue;
      checked += 1;
      const style = getComputedStyle(el);
      const fg = parse(style.color);
      const bg = background(el);
      if (!fg || !bg || fg.a < 0.95 || style.visibility === "hidden") continue;
      const [l1, l2] = [luminance(fg), luminance(bg)].sort((a, b) => b - a);
      const ratio = (l1 + 0.05) / (l2 + 0.05);
      if (ratio < 3) samples.push(`"${text.slice(0, 40)}" ${ratio.toFixed(1)}:1`);
    }
    return samples;
  }).catch(() => []);
}

const LAWYER = "This is an automated signal, not legal advice; check with a privacy lawyer.";
const LOCATION = "The test browser runs from a US data center; sites that show a consent banner only to EU or UK visitors can behave differently there, so confirm from an EU connection.";

export async function runBrowserConsentCheck(url: string, options: BrowserOptions): Promise<BrowserConsentResult> {
  const unavailable: BrowserConsentResult = { status: "unavailable", findings: [], trackers: [], bannerFound: false };
  let browser: Browser | null = null;
  let timer: ReturnType<typeof setTimeout> | undefined;
  let cancelled = false;
  const work = (async (): Promise<BrowserConsentResult> => {
    browser = await launch();
    if (cancelled) { await browser.close().catch(() => undefined); throw new Error("Browser check cancelled."); }
    const findings: VulnerabilityResult[] = [];

    // 1. First visit, no interaction.
    const first = await guardedContext(browser, options);
    const page = await open(first, url);
    const before = trackerCookies(await first.cookies());
    const trackers = detectTrackers(await page.content().catch(() => ""));
    for (const cookie of before) if (!trackers.includes(cookie.tracker)) trackers.push(cookie.tracker);
    const banner = await findBanner(page);
    const contrast = await lowContrastSamples(page);
    await first.close();

    const bannerFound = banner.accept || banner.reject;
    if (before.length) {
      const names = [...new Set(before.map((cookie) => cookie.name))].slice(0, 8);
      const vendors = [...new Set(before.map((cookie) => cookie.tracker.name))];
      // With a banner on screen the site is clearly asking for consent it has not waited for. Without one, the banner may be geo-targeted.
      findings.push({ type: "cookies-consent", severity: bannerFound ? "high" : "medium", title: "Tracking cookies are set before consent", url,
        description: `On a first visit with no clicks, a real browser received these tracking cookies: ${names.join(", ")} (${vendors.join(", ")}).${bannerFound ? " A cookie banner was shown, but the cookies were already set." : ` No cookie banner was found. ${LOCATION}`} In the EU and UK, non-essential analytics and advertising cookies generally need consent before they are set. ${LAWYER}`,
        remedy: "Load these tags only after the visitor accepts. With Google tags, set consent mode to denied by default before gtag/GTM loads, and update it on accept. With other tools, let your consent tool inject the script, or block it with type=\"text/plain\" plus your consent tool's category attribute." });
    }
    if (banner.accept && !banner.reject) {
      findings.push({ type: "cookies-consent", severity: "medium", title: "Cookie banner has no reject button on the first screen", url,
        description: `The cookie banner offers an accept button but no visible "Reject" or "Necessary only" option on its first layer. EU regulators, such as the French CNIL, expect refusing to be as easy as accepting. ${LOCATION} ${LAWYER}`,
        remedy: "Add a \"Reject all\" (or \"Necessary only\") button next to \"Accept all\", with the same size and visual weight." });
    }

    // 2. Reject, then reload: tracking cookies must not come back. 3. Global Privacy Control.
    const rejectCheck = (async () => {
      if (!banner.reject) return;
      const context = await guardedContext(browser!, options);
      try {
        const rejectPage = await open(context, url);
        const again = await findBanner(rejectPage);
        if (!again.rejectFrame) return;
        await again.rejectFrame.locator("[data-smr-reject='1']").first().click({ timeout: 4_000 });
        await rejectPage.waitForTimeout(1_500);
        for (const tracker of TRACKERS) for (const pattern of tracker.cookies) await context.clearCookies({ name: pattern });
        await rejectPage.reload({ waitUntil: "domcontentloaded", timeout: 15_000 });
        await rejectPage.waitForTimeout(3_500);
        const after = trackerCookies(await context.cookies());
        if (after.length) {
          const names = [...new Set(after.map((cookie) => cookie.name))].slice(0, 8);
          findings.push({ type: "cookies-consent", severity: "high", title: "Tracking cookies are set after Reject", url,
            description: `After clicking the banner's reject button and reloading, the browser received tracking cookies again: ${names.join(", ")} (${[...new Set(after.map((c) => c.tracker.name))].join(", ")}). A refusal that does not stop tracking is not a valid choice under GDPR and ePrivacy rules. ${LAWYER}`,
            remedy: "Make sure every tag reads the stored consent state on each page load before it runs. Test by rejecting, reloading and checking DevTools > Application > Cookies." });
        }
      } finally { await context.close().catch(() => undefined); }
    })().catch(() => undefined);

    const gpcCheck = (async () => {
      if (!trackers.some((tracker) => tracker.kind === "advertising")) return;
      const context = await guardedContext(browser!, options, { extraHTTPHeaders: { "Sec-GPC": "1" } });
      try {
        await context.addInitScript(() => { Object.defineProperty(Navigator.prototype, "globalPrivacyControl", { get: () => true }); });
        await open(context, url);
        const ads = trackerCookies(await context.cookies()).filter((cookie) => cookie.tracker.kind === "advertising");
        if (ads.length) {
          findings.push({ type: "privacy", severity: "low", title: "Global Privacy Control signal is not honored", url,
            description: `With the Global Privacy Control signal on (Sec-GPC: 1), advertising cookies were still set on the first visit: ${[...new Set(ads.map((c) => c.name))].slice(0, 6).join(", ")}. California's CCPA regulations treat GPC as a valid opt-out of sale or sharing for businesses the law covers. ${LAWYER}`,
            remedy: "If the CCPA applies to you, read navigator.globalPrivacyControl (or the Sec-GPC header) and treat it as an opt-out: do not load advertising tags for that visitor." });
        }
      } finally { await context.close().catch(() => undefined); }
    })().catch(() => undefined);

    await Promise.all([rejectCheck, gpcCheck]);

    if (contrast.length) {
      findings.push({ type: "accessibility", severity: "low", title: "Text with very low contrast", url,
        description: `Text on the first screens has a contrast ratio below 3:1 against its background, under the WCAG 1.4.3 minimum of 4.5:1 for normal text. Examples: ${contrast.join("; ")}. Only solid backgrounds were measured.`,
        remedy: "Darken the text or lighten the background until normal text reaches at least 4.5:1 and large text 3:1. Check with your browser DevTools color picker." });
    }
    return { status: "ran", findings, trackers, bannerFound };
  })();
  try {
    return await Promise.race([work, new Promise<BrowserConsentResult>((resolve) => { timer = setTimeout(() => resolve(unavailable), options.timeoutMs); })]);
  } catch {
    return unavailable;
  } finally {
    cancelled = true;
    if (timer) clearTimeout(timer);
    await (browser as Browser | null)?.close().catch(() => undefined);
    work.catch(() => undefined);
  }
}
