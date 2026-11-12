import * as cheerio from "cheerio";
import type { VulnerabilityResult } from "./scanner";

/**
 * Privacy, consent and accessibility checks over HTML the scanner already read.
 * Every finding carries evidence and says "check with a lawyer", never "you violate".
 */

export type TrackerKind = "analytics" | "advertising" | "session-replay";
export interface TrackerSignature {
  id: string;
  name: string;
  kind: TrackerKind;
  /** Matched against the raw HTML, including inline scripts and framework payloads. */
  patterns: RegExp[];
  /** Cookie names this tracker sets in the browser. */
  cookies: RegExp[];
  /** How a privacy policy would usually name the vendor. */
  mention: RegExp;
}

export const TRACKERS: TrackerSignature[] = [
  { id: "google-analytics", name: "Google Analytics / Google tag", kind: "analytics", patterns: [/googletagmanager\.com\/(?:gtag\/js|gtm\.js)/i, /google-analytics\.com\/(?:analytics|ga)\.js/i, /gtag\(\s*['"]config['"]\s*,\s*['"](?:G|UA)-/i], cookies: [/^_ga(?:$|_)/, /^_gid$/, /^_gat/], mention: /google/i },
  { id: "google-ads", name: "Google Ads conversion tracking", kind: "advertising", patterns: [/googleadservices\.com\/pagead\/conversion/i, /googleads\.g\.doubleclick\.net/i, /gtag\(\s*['"]config['"]\s*,\s*['"]AW-/i], cookies: [/^_gcl_(?:au|aw|dc|gb)$/], mention: /google/i },
  { id: "meta-pixel", name: "Meta Pixel", kind: "advertising", patterns: [/connect\.facebook\.net\/[^"'\s]*\/fbevents\.js/i, /fbq\(\s*['"]init['"]/i], cookies: [/^_fbp$/, /^_fbc$/], mention: /facebook|\bmeta\b/i },
  { id: "hotjar", name: "Hotjar", kind: "session-replay", patterns: [/static\.hotjar\.com/i, /_hjSettings/], cookies: [/^_hj/], mention: /hotjar/i },
  { id: "clarity", name: "Microsoft Clarity", kind: "session-replay", patterns: [/clarity\.ms\/tag/i], cookies: [/^_clck$/, /^_clsk$/], mention: /clarity|microsoft/i },
  { id: "tiktok", name: "TikTok Pixel", kind: "advertising", patterns: [/analytics\.tiktok\.com/i, /ttq\.load\(/], cookies: [/^_ttp$/, /^_tt_enable_cookie$/], mention: /tiktok/i },
  { id: "linkedin", name: "LinkedIn Insight Tag", kind: "advertising", patterns: [/snap\.licdn\.com\/li\.lms-analytics/i, /_linkedin_partner_id/], cookies: [/^li_(?:fat_id|sugr|gc)$/, /^bcookie$/, /^lidc$/, /^AnalyticsSyncHistory$/, /^UserMatchHistory$/], mention: /linkedin/i },
  { id: "x-ads", name: "X (Twitter) Pixel", kind: "advertising", patterns: [/static\.ads-twitter\.com/i, /twq\(\s*['"](?:init|config)['"]/i], cookies: [/^muc_ads$/, /^personalization_id$/], mention: /twitter|\bx corp|\bx\.com/i },
  { id: "bing-ads", name: "Microsoft Advertising UET", kind: "advertising", patterns: [/bat\.bing\.com\/bat\.js/i], cookies: [/^_uet(?:sid|vid)$/], mention: /bing|microsoft/i },
  { id: "reddit", name: "Reddit Pixel", kind: "advertising", patterns: [/redditstatic\.com\/ads\/pixel\.js/i, /rdt\(\s*['"]init['"]/i], cookies: [/^_rdt_uuid$/], mention: /reddit/i },
  { id: "pinterest", name: "Pinterest Tag", kind: "advertising", patterns: [/s\.pinimg\.com\/ct\/core\.js/i, /pintrk\(\s*['"]load['"]/i], cookies: [/^_pin_unauth$/, /^_pinterest_ct/], mention: /pinterest/i },
  { id: "segment", name: "Segment", kind: "analytics", patterns: [/cdn\.segment\.com\/analytics\.js/i], cookies: [/^ajs_(?:anonymous_id|user_id)$/], mention: /segment|twilio/i },
  { id: "mixpanel", name: "Mixpanel", kind: "analytics", patterns: [/cdn\.mxpnl\.com/i, /mixpanel\.init\(/], cookies: [/^mp_.*_mixpanel$/], mention: /mixpanel/i },
  { id: "posthog", name: "PostHog", kind: "analytics", patterns: [/posthog\.init\(/, /(?:us|eu)(?:-assets)?\.i\.posthog\.com/i], cookies: [/^ph_.*_posthog$/], mention: /posthog/i },
  { id: "amplitude", name: "Amplitude", kind: "analytics", patterns: [/cdn\.amplitude\.com/i, /amplitude\.(?:init|getInstance)\(/], cookies: [/^AMP_/], mention: /amplitude/i },
  { id: "heap", name: "Heap", kind: "analytics", patterns: [/cdn\.heapanalytics\.com/i], cookies: [/^_hp2_/], mention: /heap/i },
  { id: "fullstory", name: "FullStory", kind: "session-replay", patterns: [/edge\.fullstory\.com|fullstory\.com\/s\/fs\.js/i], cookies: [/^fs_uid$/], mention: /fullstory/i },
];

const CONSENT_TOOLS: Array<{ name: string; pattern: RegExp }> = [
  { name: "Cookiebot", pattern: /consent\.cookiebot\.com|cookiebot/i },
  { name: "OneTrust", pattern: /cdn\.cookielaw\.org|onetrust|optanon/i },
  { name: "Usercentrics", pattern: /usercentrics/i },
  { name: "iubenda", pattern: /cdn\.iubenda\.com|_iub\s*=|iubenda_cs/i },
  { name: "CookieYes", pattern: /cookieyes/i },
  { name: "Termly", pattern: /app\.termly\.io|termly/i },
  { name: "Osano", pattern: /cmp\.osano\.com|osano/i },
  { name: "Didomi", pattern: /didomi/i },
  { name: "Klaro", pattern: /klaro/i },
  { name: "Quantcast Choice", pattern: /quantcast\.mgr\.consensu\.org|cmp\.quantcast\.com/i },
  { name: "consentmanager", pattern: /consentmanager\.net/i },
  { name: "Complianz", pattern: /complianz/i },
  { name: "CookieHub", pattern: /cookiehub/i },
  { name: "Axeptio", pattern: /axeptio/i },
  { name: "TrustArc", pattern: /trustarc/i },
  { name: "Sourcepoint", pattern: /sourcepoint|sp-prod\.net/i },
  { name: "Borlabs Cookie", pattern: /borlabs/i },
  { name: "Civic Cookie Control", pattern: /civiccomputing|cookiecontrol/i },
  { name: "CookieConsent", pattern: /cookieconsent|cookie-consent|vanilla-cookieconsent/i },
  { name: "Google consent mode default", pattern: /gtag\(\s*['"]consent['"]\s*,\s*['"]default['"]/i },
  { name: "Cookie banner markup", pattern: /(?:id|class)=["'][^"']*(?:cookie[-_ ]?(?:banner|consent|notice|bar|popup|modal)|gdpr[-_ ]?(?:banner|consent))/i },
];

const PRIVACY_LINK = /privacy|privacidad|privacidade|privatnost|privatezza|datenschutz|confidentialit|donn[ée]es[ -]personnelles|politika[- ]privatnosti|gdpr/i;
/** A link is a policy link when its path says so, or its short label does ("Privacy", "Privacy Policy"), not a blog post about privacy. */
const PRIVACY_PATH = /^\/(?:[a-z]{2}(?:-[a-z]{2})?\/)?(?:legal\/)?(?:privacy|privacy[-_]policy|privacy[-_]notice|privacy[-_]statement|datenschutz(?:erklaerung|erklärung)?|politica[-_]de[-_]privacidad|privacidad|confidentialite|politique[-_]de[-_]confidentialite|politika[-_]privatnosti|privatnost)(?:\.html?)?\/?$/i;
const PRIVACY_LABEL = /^(?:privacy|privacy policy|privacy notice|privacy statement|privacy & cookies|privacy and cookies|datenschutz|datenschutzerkl[äa]rung|pol[ií]tica de privacidad|confidentialit[ée]|politique de confidentialit[ée]|politika privatnosti|privatnost|informativa (?:sulla )?privacy)$/i;
const TERMS_PATH = /^\/(?:[a-z]{2}(?:-[a-z]{2})?\/)?(?:legal\/)?(?:terms|tos|terms[-_]of[-_](?:service|use)|terms[-_]and[-_]conditions|conditions|agb|nutzungsbedingungen|condiciones|uslovi|cgu|cgv|termini)(?:\.html?)?\/?$/i;
const TERMS_LABEL = /^(?:terms|terms of service|terms of use|terms & conditions|terms and conditions|legal terms|agb|nutzungsbedingungen|t[ée]rminos(?: y condiciones)?|conditions g[ée]n[ée]rales.*|uslovi(?: kori[sš][cć]enja)?|termini(?: e condizioni)?)$/i;
const TERMS_LINK = /terms|\btos\b|conditions|\bagb\b|nutzungsbedingungen|condiciones|uslovi|cgu|cgv|termini|condi[cç][õo]es/i;
const IMPRESSUM_LINK = /impressum|imprint|legal[- ]notice|mentions[- ]l[ée]gales|aviso[- ]legal/i;
const SALE_OPT_OUT_LINK = /do not sell|do not share|your privacy choices|opt[- ]out of (?:sale|sharing)/i;
const AUTH_OR_SIGNUP = /sign ?up|register|log ?in|sign ?in|get started|start (?:free|trial)|create (?:an )?account|registr|anmelden|prijav/i;
const MARKETING_LABEL = /newsletter|marketing|offers|promotion|promo|special deals|news and updates|product updates|angebote|werbung|novosti|ponude|offres/i;
const COOKIE_WORD = /cookie|kola[čc]i[ćc]/i;

export interface CompliancePage { url: string; html: string }
export interface LegalLink { href: string; text: string; page: string; inFooter: boolean }
export interface ComplianceDeps {
  /** Bounded, SSRF-safe HTML fetch. Returns null when the URL is unreachable or not HTML. */
  fetchHtml: (url: string) => Promise<CompliancePage | null>;
}
export interface StaticComplianceResult {
  findings: VulnerabilityResult[];
  trackers: TrackerSignature[];
  consentTools: string[];
  policy: { url: string; text: string } | null;
  /** The finding that a browser test should replace when it runs. */
  noConsentToolFinding?: VulnerabilityResult;
}

export function detectTrackers(html: string): TrackerSignature[] {
  return TRACKERS.filter((tracker) => tracker.patterns.some((pattern) => pattern.test(html)));
}

export function detectConsentTools(html: string): string[] {
  return CONSENT_TOOLS.filter((tool) => tool.pattern.test(html)).map((tool) => tool.name);
}

function normalizedText(value: string) {
  return value.replace(/\s+/g, " ").trim();
}

export function collectLinks(page: CompliancePage): LegalLink[] {
  const $ = cheerio.load(page.html);
  const links: LegalLink[] = [];
  $("a[href]").each((_, element) => {
    const raw = $(element).attr("href") || "";
    if (/^(?:#|mailto:|tel:|javascript:)/i.test(raw)) return;
    let href: string;
    try { href = new URL(raw, page.url).toString(); } catch { return; }
    const text = normalizedText($(element).text() || $(element).attr("aria-label") || $(element).attr("title") || "").slice(0, 120);
    links.push({ href, text, page: page.url, inFooter: $(element).closest("footer, [role=contentinfo]").length > 0 });
  });
  return links;
}

function linkPath(link: LegalLink) {
  try { return decodeURIComponent(new URL(link.href).pathname); } catch { return link.href; }
}

function matchesLink(link: LegalLink, pattern: RegExp) {
  return pattern.test(link.text) || pattern.test(linkPath(link));
}

function isPolicyLink(link: LegalLink, path: RegExp, label: RegExp) {
  return path.test(linkPath(link)) || label.test(link.text.trim());
}

export function findLegalPages(pages: CompliancePage[]) {
  const links = pages.flatMap(collectLinks);
  const pick = (pattern: RegExp) => links.find((link) => matchesLink(link, pattern) && !/cookie/i.test(link.text)) ?? links.find((link) => matchesLink(link, pattern));
  // Footer links first: that is where policies live, and nav or blog links can mention privacy.
  const policy = (path: RegExp, label: RegExp) => links.find((link) => link.inFooter && isPolicyLink(link, path, label)) ?? links.find((link) => isPolicyLink(link, path, label));
  const crawled = (pattern: RegExp) => pages.find((page) => { try { return pattern.test(decodeURIComponent(new URL(page.url).pathname)); } catch { return false; } });
  const privacy = policy(PRIVACY_PATH, PRIVACY_LABEL);
  const terms = policy(TERMS_PATH, TERMS_LABEL);
  return {
    links,
    privacyUrl: privacy?.href ?? crawled(PRIVACY_PATH)?.url,
    termsUrl: terms?.href ?? crawled(TERMS_PATH)?.url,
    impressumUrl: pick(IMPRESSUM_LINK)?.href,
    saleOptOut: links.find((link) => SALE_OPT_OUT_LINK.test(link.text)),
    cookiePolicyUrl: links.find((link) => /cookie/i.test(link.text) && /polic|richtlinie|politi|notice/i.test(link.text))?.href,
  };
}

function hasAccessibleName($: cheerio.CheerioAPI, element: Parameters<cheerio.CheerioAPI>[0]) {
  const el = $(element);
  if (normalizedText(el.attr("aria-label") || "") || el.attr("aria-labelledby") || normalizedText(el.attr("title") || "")) return true;
  if (normalizedText(el.text())) return true;
  if (el.find("img[alt]").toArray().some((img) => normalizedText($(img).attr("alt") || ""))) return true;
  if (el.find("svg title").length || el.find("[aria-label]").length) return true;
  return el.is("input") && Boolean(normalizedText(el.attr("value") || ""));
}

interface FormSignal { page: string; emailForms: number; formsWithoutPolicyLink: number; preChecked: string[] }

export function inspectForms(page: CompliancePage): FormSignal {
  const $ = cheerio.load(page.html);
  const signal: FormSignal = { page: page.url, emailForms: 0, formsWithoutPolicyLink: 0, preChecked: [] };
  $("form").each((_, form) => {
    const $form = $(form);
    const email = $form.find("input[type=email], input[name*=email i], input[id*=email i], input[autocomplete=email]").length > 0;
    const password = $form.find("input[type=password]").length > 0;
    const submitText = normalizedText($form.find("button, input[type=submit]").text() + " " + ($form.find("input[type=submit]").attr("value") || ""));
    const isLogin = password && /log ?in|sign ?in|anmelden|prijav/i.test(submitText) && !/sign ?up|register|create/i.test(submitText);
    $form.find("input[type=checkbox][checked]").each((__, box) => {
      const id = $(box).attr("id");
      const label = normalizedText((id ? $(`label[for="${id.replace(/"/g, "")}"]`).text() : "") || $(box).closest("label").text() || $(box).parent().text());
      if (MARKETING_LABEL.test(label)) signal.preChecked.push(label.slice(0, 100));
    });
    if (!email || isLogin) return;
    signal.emailForms += 1;
    // The form and its close wrappers, not the whole page: a site-wide footer link is checked separately.
    let nearby = $form;
    for (let wrapper = $form.parent(), depth = 0; depth < 2 && wrapper.length && !wrapper.is("body, html, main, footer"); wrapper = wrapper.parent(), depth += 1) nearby = nearby.add(wrapper);
    const policyLink = nearby.find("a[href]").toArray().some((anchor) => PRIVACY_LINK.test(`${$(anchor).text()} ${$(anchor).attr("href")}`));
    if (!policyLink) signal.formsWithoutPolicyLink += 1;
  });
  return signal;
}

export interface AccessibilityIssues { missingLang: boolean; imagesWithoutAlt: number; unlabeledInputs: number; unnamedControls: number; zoomDisabled: boolean; examples: string[] }

export function inspectAccessibility(page: CompliancePage): AccessibilityIssues {
  const $ = cheerio.load(page.html);
  const examples: string[] = [];
  const lang = normalizedText($("html").attr("lang") || "");
  const imagesWithoutAlt = $("img:not([alt])").filter((_, img) => $(img).attr("aria-hidden") !== "true" && $(img).attr("role") !== "presentation").length;
  if (imagesWithoutAlt) examples.push(`img without alt: ${($("img:not([alt])").first().attr("src") || "").slice(0, 80)}`);
  let unlabeledInputs = 0;
  $("input, select, textarea").each((_, element) => {
    const el = $(element);
    const type = (el.attr("type") || "text").toLowerCase();
    if (["hidden", "submit", "button", "image", "reset"].includes(type) || el.attr("aria-hidden") === "true") return;
    const id = el.attr("id");
    const labelled = Boolean(normalizedText(el.attr("aria-label") || "")) || Boolean(el.attr("aria-labelledby")) || Boolean(normalizedText(el.attr("title") || ""))
      || el.closest("label").length > 0 || Boolean(id && $(`label[for="${id.replace(/"/g, "")}"]`).length);
    if (!labelled) {
      unlabeledInputs += 1;
      if (unlabeledInputs === 1) examples.push(`unlabeled ${element.tagName}${el.attr("name") ? ` name="${el.attr("name")?.slice(0, 40)}"` : ""}`);
    }
  });
  let unnamedControls = 0;
  $("button, a[href], [role=button]").each((_, element) => {
    if ($(element).attr("aria-hidden") === "true") return;
    if (!hasAccessibleName($, element)) {
      unnamedControls += 1;
      if (unnamedControls === 1) examples.push(`${element.tagName} without an accessible name${$(element).attr("href") ? ` (${$(element).attr("href")?.slice(0, 60)})` : ""}`);
    }
  });
  const viewport = $("meta[name=viewport]").attr("content") || "";
  const zoomDisabled = /user-scalable\s*=\s*(?:no|0)/i.test(viewport) || /maximum-scale\s*=\s*1(?:\.0)?(?:\s|,|$)/i.test(viewport);
  return { missingLang: !lang, imagesWithoutAlt, unlabeledInputs, unnamedControls, zoomDisabled, examples };
}

export function policyText(html: string) {
  const $ = cheerio.load(html);
  $("script, style, noscript, svg, nav, header").remove();
  const main = $("main").length ? $("main").text() : $("body").text();
  return normalizedText(main);
}

export function vendorsMissingFromPolicy(text: string, trackers: TrackerSignature[]) {
  const seen = new Set<string>();
  return trackers.filter((tracker) => {
    if (tracker.mention.test(text)) return false;
    const key = tracker.mention.source;
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

const LAWYER = "This is an automated signal, not legal advice. Whether it applies depends on where you and your users are; check with a privacy lawyer.";

function list(items: string[]) {
  return items.length <= 1 ? items.join("") : `${items.slice(0, -1).join(", ")} and ${items[items.length - 1]}`;
}

export async function checkCompliance(baseUrl: string, pages: CompliancePage[], deps: ComplianceDeps): Promise<StaticComplianceResult> {
  const findings: VulnerabilityResult[] = [];
  const origin = new URL(baseUrl).origin;
  const home = pages[0];
  const allHtml = pages.map((page) => page.html).join("\n");
  const trackers = detectTrackers(allHtml);
  const consentTools = detectConsentTools(allHtml);
  const legal = findLegalPages(pages);
  const forms = pages.map(inspectForms);
  const emailForms = forms.reduce((sum, form) => sum + form.emailForms, 0);
  const hasAccounts = legal.links.some((link) => AUTH_OR_SIGNUP.test(link.text) || /\/(?:sign-?up|register|login|signin)\b/i.test(link.href));
  const collectsData = trackers.length > 0 || emailForms > 0 || hasAccounts;

  // Probe common paths only when no link was found, so a missing link does not become a false "no policy".
  let privacyUrl = legal.privacyUrl;
  if (!privacyUrl) {
    for (const path of ["/privacy", "/privacy-policy"]) {
      const page = await deps.fetchHtml(origin + path);
      if (page && PRIVACY_LINK.test(policyText(page.html).slice(0, 4000))) { privacyUrl = page.url; break; }
    }
  }
  let termsUrl = legal.termsUrl;
  if (!termsUrl && hasAccounts) {
    const page = await deps.fetchHtml(origin + "/terms");
    if (page && TERMS_LINK.test(policyText(page.html).slice(0, 4000))) termsUrl = page.url;
  }

  if (!privacyUrl && collectsData) {
    const reasons = [trackers.length ? `loads ${list(trackers.map((t) => t.name))}` : "", emailForms ? `has ${emailForms} form${emailForms === 1 ? "" : "s"} that collect email addresses` : "", hasAccounts ? "offers sign-up or login" : ""].filter(Boolean);
    findings.push({ type: "privacy", severity: "high", title: "No Privacy Policy found", url: origin + "/",
      description: `No link to a privacy policy was found on ${pages.length} scanned page${pages.length === 1 ? "" : "s"}, and /privacy and /privacy-policy did not return one. The site ${list(reasons)}, so it processes personal data. GDPR (Articles 13 and 14) and US state privacy laws such as the CCPA usually require a privacy notice in that case. ${LAWYER}`,
      remedy: "1. Publish a privacy policy at a stable URL such as /privacy.\n2. Say who runs the service and how to contact you, what personal data you collect, why, which third parties receive it (analytics, payments, email, hosting), how long you keep it, and how users can access or delete it.\n3. Link it from the footer of every page and next to every form that collects personal data.\n4. Have a lawyer review it if you have users in the EU, UK or California." });
  } else if (privacyUrl && home && !collectLinks(home).some((link) => link.href.split("#")[0] === privacyUrl!.split("#")[0] || isPolicyLink(link, PRIVACY_PATH, PRIVACY_LABEL))) {
    findings.push({ type: "privacy", severity: "low", title: "Privacy Policy is not linked from the homepage", url: home.url,
      description: `A privacy policy exists at ${privacyUrl}, but the homepage does not link to it. Privacy notices are expected to be easy to find, which in practice means a link in the footer of every page. ${LAWYER}`,
      remedy: "Add a \"Privacy Policy\" link to the shared site footer so it appears on every page, including the homepage." });
  }

  if (!termsUrl && hasAccounts) {
    findings.push({ type: "privacy", severity: "medium", title: "No Terms of Service found", url: origin + "/",
      description: `The site offers sign-up or login, but no link to terms of service was found on the scanned pages and /terms did not return them. Terms are not always a legal requirement, but a SaaS without them has no agreed rules on acceptable use, payment, refunds, liability or account termination. ${LAWYER}`,
      remedy: "Publish terms of service at /terms covering acceptable use, accounts, payment and refunds, termination, liability limits and governing law. Link them in the footer and on the sign-up form." });
  }

  const tracking = trackers;
  let noConsentToolFinding: VulnerabilityResult | undefined;
  if (tracking.length && !consentTools.length) {
    noConsentToolFinding = { type: "cookies-consent", severity: "medium", title: "Trackers found with no cookie consent tool", url: home?.url ?? origin + "/",
      description: `The page HTML loads ${list(tracking.map((t) => t.name))}, and no consent management tool, Google consent mode default or cookie banner markup was found in it. In the EU and UK, the ePrivacy rules and GDPR generally require consent before non-essential analytics or advertising cookies are set. A banner rendered only by JavaScript may not be visible to this check. ${LAWYER}`,
      remedy: "1. Add a consent tool (for example Cookiebot, Usercentrics, CookieYes, Klaro or a self-built banner).\n2. Load analytics and ad tags only after the visitor accepts, or set Google consent mode to denied by default:\n\n   gtag('consent', 'default', { analytics_storage: 'denied', ad_storage: 'denied', ad_user_data: 'denied', ad_personalization: 'denied' });\n\n3. Give \"Reject\" the same prominence as \"Accept\".\n4. List these services in your privacy or cookie policy." };
    findings.push(noConsentToolFinding);
  }
  if (trackers.length) {
    findings.push({ type: "cookies-consent", severity: "info", title: "Tracking and analytics services detected", url: home?.url ?? origin + "/",
      description: `Detected in the page HTML: ${trackers.map((t) => `${t.name} (${t.kind})`).join(", ")}.${consentTools.length ? ` Consent tooling detected: ${list(consentTools)}.` : ""} Each of these receives visitor data and usually needs to be named in your privacy policy.`,
      remedy: "Keep this list in sync with your privacy and cookie policy, and remove tags you no longer use." });
  }

  const advertising = trackers.filter((tracker) => tracker.kind === "advertising");
  if (advertising.length && !legal.saleOptOut) {
    findings.push({ type: "privacy", severity: "low", title: "No \"Do Not Sell or Share\" link with advertising trackers", url: home?.url ?? origin + "/",
      description: `The site loads ${list(advertising.map((t) => t.name))}. Sharing visitor data with ad platforms can count as "selling" or "sharing" under California's CCPA/CPRA, which then requires a "Do Not Sell or Share My Personal Information" or "Your Privacy Choices" link. The law applies only to businesses above its size or data thresholds. ${LAWYER}`,
      remedy: "If the CCPA applies to you, add a \"Do Not Sell or Share My Personal Information\" (or \"Your Privacy Choices\") link to the footer, honor Global Privacy Control signals, and describe the opt-out in your privacy policy." });
  }

  const formPages = forms.filter((form) => form.formsWithoutPolicyLink > 0).slice(0, 3);
  for (const form of formPages) {
    findings.push({ type: "privacy", severity: "low", title: "Email form without a privacy notice link", url: form.page,
      description: `${form.formsWithoutPolicyLink} form${form.formsWithoutPolicyLink === 1 ? "" : "s"} on this page collect${form.formsWithoutPolicyLink === 1 ? "s" : ""} an email address with no link to the privacy policy inside or next to the form. GDPR expects people to be told how their data is used at the moment it is collected. A footer link may be enough for some regulators. ${LAWYER}`,
      remedy: "Add a short line under the form, for example: \"We use your email to send you X. See our Privacy Policy.\" with a link to the policy." });
  }
  const preChecked = forms.filter((form) => form.preChecked.length).slice(0, 3);
  for (const form of preChecked) {
    findings.push({ type: "privacy", severity: "medium", title: "Marketing checkbox is pre-checked", url: form.page,
      description: `A checkbox for marketing messages is checked by default: "${form.preChecked[0]}". Under GDPR, consent must be an active opt-in; the CJEU ruled in Planet49 (C-673/17) that pre-ticked boxes are not valid consent. ${LAWYER}`,
      remedy: "Remove the checked attribute so the visitor has to tick the box themselves, and store when and how consent was given." });
  }

  const tld = new URL(origin).hostname.split(".").pop() || "";
  const germanSite = ["de", "at"].includes(tld) || /^de\b/i.test(cheerio.load(home?.html ?? "")("html").attr("lang") || "");
  if (germanSite && !legal.impressumUrl) {
    findings.push({ type: "privacy", severity: "info", title: "No Impressum link found", url: home?.url ?? origin + "/",
      description: `This looks like a German-language or .${tld} site, and no Impressum or legal notice link was found. Commercial websites run from Germany or Austria usually need an Impressum with the provider's name, address and contact details. ${LAWYER}`,
      remedy: "If your business is established in Germany or Austria, publish an Impressum and link it from every page footer." });
  }

  // Accessibility: aggregate across pages, report each kind once with the affected pages.
  const a11y = pages.map((page) => ({ page: page.url, issues: inspectAccessibility(page) }));
  const eaa = "The European Accessibility Act has applied to many consumer-facing online services in the EU since June 28, 2025 (microenterprises providing services are exempt), and WCAG 2.1 AA is the usual reference.";
  const affected = (pick: (issues: AccessibilityIssues) => number | boolean) => a11y.filter((entry) => pick(entry.issues));
  const imgPages = affected((issues) => issues.imagesWithoutAlt);
  if (imgPages.length) {
    const total = imgPages.reduce((sum, entry) => sum + entry.issues.imagesWithoutAlt, 0);
    findings.push({ type: "accessibility", severity: "low", title: "Images without alt text", url: imgPages[0].page,
      description: `${total} image${total === 1 ? "" : "s"} on ${imgPages.length} page${imgPages.length === 1 ? "" : "s"} ${total === 1 ? "has" : "have"} no alt attribute, so screen readers cannot describe them (WCAG 1.1.1). Example: ${imgPages[0].issues.examples.find((e) => e.startsWith("img")) ?? "see page"}. ${eaa}`,
      remedy: "Add alt text that describes informative images. For purely decorative images use alt=\"\" so screen readers skip them. In Next.js, next/image requires an alt prop." });
  }
  const inputPages = affected((issues) => issues.unlabeledInputs);
  if (inputPages.length) {
    const total = inputPages.reduce((sum, entry) => sum + entry.issues.unlabeledInputs, 0);
    findings.push({ type: "accessibility", severity: "low", title: "Form fields without labels", url: inputPages[0].page,
      description: `${total} form field${total === 1 ? "" : "s"} on ${inputPages.length} page${inputPages.length === 1 ? "" : "s"} ${total === 1 ? "has" : "have"} no label, aria-label or aria-labelledby (WCAG 1.3.1 and 4.1.2). A placeholder is not a label. Example: ${inputPages[0].issues.examples.find((e) => e.startsWith("unlabeled")) ?? "see page"}. ${eaa}`,
      remedy: "Give every field a visible <label for=\"field-id\">. Where a visible label is impossible (a search box with an icon), add aria-label." });
  }
  const controlPages = affected((issues) => issues.unnamedControls);
  if (controlPages.length) {
    const total = controlPages.reduce((sum, entry) => sum + entry.issues.unnamedControls, 0);
    findings.push({ type: "accessibility", severity: "low", title: "Buttons or links without an accessible name", url: controlPages[0].page,
      description: `${total} button${total === 1 ? "" : "s"} or link${total === 1 ? "" : "s"} ${total === 1 ? "has" : "have"} no text, aria-label or labelled image, so screen readers announce them only as "button" or "link" (WCAG 4.1.2). Icon-only buttons are the usual cause. Example: ${controlPages[0].issues.examples.find((e) => e.includes("accessible name")) ?? "see page"}. ${eaa}`,
      remedy: "Add aria-label to icon-only buttons and links, for example <button aria-label=\"Open menu\">, or include visually hidden text." });
  }
  if (home && a11y[0]?.issues.missingLang) {
    findings.push({ type: "accessibility", severity: "low", title: "Page language is not declared", url: home.url,
      description: `The <html> element has no lang attribute, so screen readers may pronounce the content in the wrong language (WCAG 3.1.1). ${eaa}`,
      remedy: "Set the page language, for example <html lang=\"en\">. In the Next.js App Router this is the lang prop on <html> in app/layout.tsx." });
  }
  const zoomPages = affected((issues) => issues.zoomDisabled);
  if (zoomPages.length) {
    findings.push({ type: "accessibility", severity: "low", title: "Pinch zoom is disabled", url: zoomPages[0].page,
      description: `The viewport meta tag sets user-scalable=no or maximum-scale=1, which stops people with low vision from zooming on mobile (WCAG 1.4.4). ${eaa}`,
      remedy: "Use <meta name=\"viewport\" content=\"width=device-width, initial-scale=1\"> without user-scalable or maximum-scale." });
  }

  // Read the policy itself so it can be compared with what the site actually loads.
  let policy: StaticComplianceResult["policy"] = null;
  const readPolicy = async (url: string) => {
    const crawled = pages.find((page) => page.url.split("#")[0] === url.split("#")[0]);
    const page = crawled ?? await deps.fetchHtml(url);
    return page ? policyText(page.html) : "";
  };
  if (privacyUrl) {
    const text = await readPolicy(privacyUrl);
    // A separate cookie policy often lists the vendors, so it counts as part of the notice.
    const cookieText = legal.cookiePolicyUrl && legal.cookiePolicyUrl !== privacyUrl ? await readPolicy(legal.cookiePolicyUrl) : "";
    if (text.length >= 400) policy = { url: privacyUrl, text: cookieText ? `${text}\n${cookieText}` : text };
  }
  return { findings, trackers, consentTools, policy, noConsentToolFinding };
}

/** Compares a privacy policy with the trackers seen on the site (static and browser). */
export function checkPolicyAgainstTrackers(policy: { url: string; text: string }, trackers: TrackerSignature[]): VulnerabilityResult[] {
  const findings: VulnerabilityResult[] = [];
  const missing = vendorsMissingFromPolicy(policy.text, trackers);
  if (missing.length) {
    findings.push({ type: "privacy", severity: "medium", title: "Privacy Policy does not name services the site uses", url: policy.url,
      description: `The site loads ${list(missing.map((t) => t.name))}, but the privacy policy text does not mention ${missing.length === 1 ? "it" : "them"}. A cookie declaration loaded by JavaScript is not visible to this check. Privacy notices are expected to name the recipients or categories of recipients of personal data (GDPR Article 13(1)(e)). ${LAWYER}`,
      remedy: `Add a section on third-party services that lists ${list(missing.map((t) => t.name))}, what data each receives, why, and a link to each provider's privacy policy. If a service is no longer used, remove its tag from the site instead.` });
  }
  if (trackers.length && !COOKIE_WORD.test(policy.text)) {
    findings.push({ type: "privacy", severity: "medium", title: "Privacy Policy does not mention cookies", url: policy.url,
      description: `The site uses ${list(trackers.map((t) => t.name))}, which set cookies or similar identifiers, but the privacy policy never mentions cookies. ${LAWYER}`,
      remedy: "Add a cookies section (or a separate cookie policy) listing each cookie or tracker, its purpose, its lifetime and how to withdraw consent." });
  }
  return findings;
}
