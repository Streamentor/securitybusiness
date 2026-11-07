# Product visuals

This branch adds real product captures, twelve code-native security diagrams, ten guide covers, one decorative hero illustration, and page-specific Open Graph images. It is based on production main `7ac8372` (PR #11), preserving the concurrent SEO work and floating mobile CTA.

## Capture provenance and privacy

Stefan explicitly approved the existing reports on 2026-11-07 with redaction. All screenshots are real rendered product pages; scores and finding counts are unchanged. No generated art is used for product UI.

| Capture | Source and treatment |
|---|---|
| Website summary and finding | Approved scan of Stefan's `stefbuilds.com`; header, account controls and sharing controls outside the crop. Desktop summary includes the first finding; the mobile crop emphasizes the summary. |
| Repository summary | Approved owned private repository report; crop starts below the repository identity. Findings stay collapsed so private GitHub URLs are outside the captured content. This report has zero critical findings; none were invented. |
| AI finding | Approved report, cropped before the GitHub link row; retains Needs verification, file/line, explanation and evidence. Mobile is an excerpt, not the entire remediation panel. |
| Background loader | Actual scans of owned public `Streamentor/securitybusiness`, captured while AI review was active. The live pipeline has seven stages, including AI review. |
| Repository picker | Actual connected picker, filtered to owned public `securitybusiness`; other repository names are excluded. No permissions or GitHub App settings changed. |
| Rescan comparison | Actual second scan of owned `stefbuilds.com`; 0 resolved, 0 new, 4 still-open finding groups. No change was fabricated to suggest successful fixes. |

Website and repository captures were taken at 1440×900/DPR 2 and 390×844/DPR 3. WebP exports retain at least 2× density for the mobile display width. The Vercel toolbar was hidden through its UI during capture. No secret values, email addresses or private repository names are visible in the committed crops. The optional RLS demo capture S8 was unavailable, so the Lovable page uses the approved repository report fallback.

The picker and AI review captions name Starter and Pro based on the existing plan gates. Prices, credits, auth and scan logic are unchanged.

## Diagrams and illustrations

Components live in `src/components/visuals/`; page edits only insert components or adjust the free scanner hero columns. Diagrams have accessible descriptions, normal document flow and intrinsic SVG dimensions. Mobile flows stack; no new animations are added. Page/check limits are props passed from the current page claims (25 and 60+).

Examples are explicitly labeled. RLS diagrams qualify grants, policies and caller identity. `frame-ancestors` is shown inside CSP, not as an invented HTTP header. Crawl discovery precedes the robots decision. Certificate dates and durations are not invented. AI results remain hypotheses requiring verification.

Illustrations used the built-in image generator, not Google Imagen. Four alternatives per subject were visually reviewed on contact sheets; the selected composition was rendered again as a full-frame asset. All eleven finals were inspected for text-like artifacts and logos. Covers are decorative (`alt=""`, `aria-hidden`); product captures have descriptive alt text. Prompt subjects and selections are in [PROMPTS.json](PROMPTS.json).

Final art is 44–79 KB per guide cover; the square hero is 52 KB. Every product crop is below 120 KB. `scripts/verify-visual-assets.mjs` checks actual files, intrinsic dimensions, references and byte budgets offline. Missing optional cover metadata renders no image.

Original PNGs, contact sheets, QA captures and final media are archived under iCloud `Codex-Media/scanmysaas-visuals/`. Dependencies and build caches remain local.

## Verification

- All 15 offline `scripts/verify-*.mjs` suites pass, with mocked external services.
- TypeScript passes; ESLint has 0 errors and one pre-existing admin `<img>` warning.
- Production build passes with dummy DATABASE_URL and AUTH_SECRET.
- 17 pages checked at 1440 and 390 px: no horizontal overflow, broken images, SVG text overflow or console/page errors. [All 34 screenshots](SCREENSHOTS.md).
- Metadata, H1s, page JSON-LD and copy arrays compared to `origin/main`: unchanged. Guide prose is unchanged; only cover/figure fields and Article `image` were added.
- Mobile H1 → form → visual order checked on both scanner pages. Floating CTA returns focus to the input and hides while the form is visible; figures reserve 110 px below their mobile content.
- All 19 OG routes return 1200×630 PNGs; long titles were visually inspected after fixing wrapping.
- The homepage retains `public/og-image.png`; other marketing pages and guides have 1200×630 `ImageResponse` images.

Local mobile Lighthouse, same machine, production server and settings before/after, baseline from `7ac8372`:

| Page | LCP before | LCP after | CLS before / after |
|---|---:|---:|---:|
| Free website scanner | 0.908 s | 0.903 s | 0 / 0 |
| Repo scanner | 0.903 s | 0.902 s | 0 / 0 |

These are local lab measurements, not production field performance. The millisecond differences are within ordinary run variance. No production deployment or merge is part of this visual PR.
