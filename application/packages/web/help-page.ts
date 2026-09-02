import { transformWithOxc, type Plugin } from 'vite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { THEME_SCRIPT_TAG, THEME_TOGGLE_CSS, themeVarsCss } from './static-page-theme.ts';
import { BRAND_CSS, brandMark, CHROME_CSS, LINK_ICON, OG_IMAGE_TAGS, ogLocaleTag, siteFooterFor, siteNav, type NavLabels } from './static-page-chrome.ts';
import { LOCALE_TO_SLUG, RTL_LOCALES, helpPath } from './src/localeRoutes.ts';
import { FAQ_SOURCES, SOURCE_FILES, sourceUrl } from './src/faqSources.ts';
import { VERSION } from './src/version.ts';
import { LANDING_PAGES_PUBLIC } from './landing-pages.ts';
import { Flag, LANGUAGE_META, sortByNative } from './src/languageData.tsx';

// Pre-renders the static Help center (formerly /faq; worker.ts 301s the
// old URLs), once per locale, as a three-layer hybrid:
//
//  1. The HUB (/help, /de/help, ...): every FAQ entry on one page with
//     live search, the topic rail, native <details>, and a strip linking
//     the import guides. The page users browse.
//  2. One FAQ LEAF per entry (/help/<id>/, /de/help/<id>/, ...): a
//     focused landing page whose <title>, H1, and meta description are
//     the question itself. The pages search engines rank for long-tail
//     queries; "copy link" on the hub hands out leaf URLs.
//  3. IMPORT GUIDES (/help/import/<app>/): step-by-step export+import
//     tutorials per source app. English-only for now: a guide page is
//     only emitted when the guides catalog contains it, so a missing
//     translation can never publish a wrong-language page.
//
// Duplicate-content stance: hub, leaves, and guides are all
// SELF-canonical. A leaf->hub canonical would tell Google to drop the
// leaves (pointless); the hub is a structurally different document (a
// collection with its own title/description) rather than a copy of any
// one leaf. Distinct titles + H1s + descriptions per URL, crawl paths
// via the hub's per-entry permalink anchors, the guide strip, and each
// leaf's related-questions list, plus sitemap-help.xml. Every page
// carries the full hreflang cluster for its own URL shape; English is
// always the x-default.
//
// FAQ strings live in src/locales/<lng>/faq.json (namespace `faq`, also
// read by the in-app FAQ tab), guide strings in
// src/locales/<lng>/guides.json (namespace `guides`); structure comes
// from src/faq.ts and src/guides.ts. FAQ entries missing from a target
// locale fall back to English per entry. The language switcher reuses
// the homepage's pieces: names + flags from src/languageData.tsx
// (rendered via react-dom/server) and the langSuggest.* strings from
// src/locales/<lng>/settings.json for the "View in <language>" banner.
//
// CSP: no inline scripts (script-src 'self'). Interactivity ships in
// /static-pages.js; every page renders complete without it. The JSON-LD
// blocks are inert data and unaffected by the CSP.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const FAQ_SRC = path.resolve(__dirname, 'src/faq.ts');
const GUIDES_SRC = path.resolve(__dirname, 'src/guides.ts');
const HOTKEYS_SRC = path.resolve(__dirname, 'src/hotkeysData.ts');
const LOCALES_DIR = path.resolve(__dirname, 'src/locales');
const ORIGIN = 'https://privacynotes.app';

/** Locales with static Help pages. English first: it is the fallback. */
const HELP_LOCALES = ['en', 'de', 'fr', 'it', 'es', 'nl', 'pl', 'pt-PT', 'pt-BR', 'ja', 'ko', 'zh-TW', 'ca', 'cs', 'tr', 'sv', 'ar'] as const;
type HelpLocale = (typeof HELP_LOCALES)[number];

/** `dir="rtl"` for RTL locales, empty string otherwise - splice straight into `<html lang="${locale}"${htmlDir(locale)}>`. */
const htmlDir = (locale: string): string =>
  (RTL_LOCALES as readonly string[]).includes(locale) ? ' dir="rtl"' : '';

/** URL prefix per locale: '' for English (apex /help), '/de' etc. otherwise. */
function localePrefix(locale: HelpLocale): string {
  return locale === 'en' ? '' : LOCALE_TO_SLUG[locale];
}

/** FAQ leaf path, e.g. /de/help/lost-phrase (no trailing slash: canonical form). */
function leafPath(locale: HelpLocale, id: string): string {
  return `${helpPath(locale)}/${id}`;
}

/**
 * Nav labels for this locale (English via the catalog fallback). Only the
 * three keys the catalogs already carry are translated; the other section
 * names (Help, Roadmap, Brand) render English everywhere, because those
 * pages are English-only by the i18n tier policy and a translated label
 * pointing at an English page helps nobody.
 */
function navLabels(p: Record<string, string>): NavLabels {
  return { home: esc(p.homeLabel), app: esc(p.appLabel), changelog: esc(p.changelogLabel) };
}

/** Import-guide path, e.g. /de/help/import/google-keep (no trailing slash). */
function guidePath(locale: HelpLocale, id: string): string {
  return `${helpPath(locale)}/import/${id}`;
}

/**
 * The printable hotkey cheat sheet, nested under the keyboard-shortcuts
 * FAQ leaf. ENGLISH-ONLY by design (i18n tier policy, like /roadmap and
 * /brand): one URL, one fixed A4 layout that translated label lengths can
 * never break - decided 2026-08-21. Canonicalizes AT the English leaf:
 * the sheet is a print-formatted view of the same list, so it stays out
 * of the sitemaps and the leaf keeps the search ranking (check-sitemap.mjs
 * accepts an emitted page whose canonical points elsewhere). Measured
 * 2026-08-26 and the stance held: the sheet carries 86 key caps and 272
 * words, the leaf carries 87 and 798, so indexing the sheet would field a
 * thinner near-duplicate against the richer page.
 *
 * It gets no hreflang FOR THE SAME REASON. hreflang is only read on a
 * self-canonical page, so a cluster here would be inert and would come back
 * from Search Console as "alternate page with proper canonical tag". Its
 * Open Graph tags are a separate question and it does have those: the sheet
 * is linked from the footer and the About modal, so it gets shared.
 */
function cheatSheetPath(): string {
  return `${leafPath('en', 'keyboard-shortcuts')}/cheat-sheet`;
}

type FaqGroupKey = string;
type FaqStructureRow = { id: string; group: FaqGroupKey };
type FaqCatalog = {
  page: Record<string, string>;
  groups: Record<FaqGroupKey, string>;
  entries: Record<string, { q: string; a: string[] }>;
};
type GuideImg = { src: string; alt: string; width: number; height: number };
type GuideSection = { h?: string; p?: string[]; steps?: string[]; img?: GuideImg };
type Guide = { app: string; title: string; metaTitle: string; lead: string; sections: GuideSection[] };
type GuidesCatalog = {
  page: { importTitle: string; importSteps: string[]; otherGuides: string };
  guides: Record<string, Guide>;
};
/** Mirrors HotkeyGroup in src/hotkeysData.ts (evaluated standalone). */
type HotkeyGroupData = {
  title: string;
  i18nKey: string;
  rows: { keys: string; label: string; i18nKey: string }[];
};

// Transpile a self-contained TS module (no imports) with Oxc and
// import it as a data-URL ES module to pull out its exports.
async function evalModule(file: string): Promise<Record<string, unknown>> {
  const src = fs.readFileSync(file, 'utf8');
  const { code } = await transformWithOxc(src, file, { lang: 'ts' });
  return (await import(
    'data:text/javascript;base64,' + Buffer.from(code).toString('base64')
  )) as Record<string, unknown>;
}

async function loadStructure(): Promise<{
  order: FaqGroupKey[];
  rows: FaqStructureRow[];
  guideOrder: string[];
  hotkeyGroups: HotkeyGroupData[];
}> {
  const faq = await evalModule(FAQ_SRC);
  const guides = await evalModule(GUIDES_SRC);
  const hotkeys = await evalModule(HOTKEYS_SRC);
  return {
    order: faq.FAQ_GROUP_ORDER as FaqGroupKey[],
    rows: faq.FAQ_STRUCTURE as FaqStructureRow[],
    guideOrder: guides.GUIDE_ORDER as string[],
    hotkeyGroups: hotkeys.HOTKEY_GROUPS as HotkeyGroupData[],
  };
}

function readCatalog(locale: HelpLocale): FaqCatalog | null {
  const file = path.join(LOCALES_DIR, locale, 'faq.json');
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8')) as FaqCatalog;
}

function readGuides(locale: HelpLocale): GuidesCatalog | null {
  const file = path.join(LOCALES_DIR, locale, 'guides.json');
  if (!fs.existsSync(file)) return null;
  return JSON.parse(fs.readFileSync(file, 'utf8')) as GuidesCatalog;
}

/**
 * Guides catalog with the same fallback discipline as the FAQ: page
 * strings per key, whole guides atomically.
 */
function loadGuides(locale: HelpLocale, en: GuidesCatalog | null): GuidesCatalog | null {
  if (!en) return null;
  if (locale === 'en') return en;
  const loc = readGuides(locale);
  if (!loc) return en;
  const guides: GuidesCatalog['guides'] = {};
  for (const [id, enGuide] of Object.entries(en.guides)) {
    const cand = loc.guides?.[id];
    guides[id] =
      cand && cand.app && cand.title && cand.lead && Array.isArray(cand.sections) && cand.sections.length > 0
        ? cand
        : enGuide;
  }
  return { page: { ...en.page, ...(loc.page ?? {}) }, guides };
}

/**
 * Locale catalog with English fallback. Page/group strings fall back per
 * key; entries fall back atomically (never an English answer under a
 * translated question, or vice versa).
 */
function loadCatalog(locale: HelpLocale, en: FaqCatalog): FaqCatalog {
  if (locale === 'en') return en;
  const loc = readCatalog(locale);
  if (!loc) return en;
  const entries: FaqCatalog['entries'] = {};
  for (const [id, enEntry] of Object.entries(en.entries)) {
    const cand = loc.entries?.[id];
    entries[id] =
      cand && cand.q && Array.isArray(cand.a) && cand.a.length > 0 ? cand : enEntry;
  }
  return {
    page: { ...en.page, ...(loc.page ?? {}) },
    groups: { ...en.groups, ...(loc.groups ?? {}) },
    entries,
  };
}

/**
 * "View in <language>" strings for the suggestion banner, reusing the
 * app's own langSuggest.* keys from settings.json (LanguageSuggest.tsx),
 * pre-interpolated with each language's endonym. Baked into a data
 * attribute so static-pages.js can label the banner in the SUGGESTED
 * language, exactly like the homepage banner.
 */
function suggestStrings(): Record<string, { action: string; dismiss: string }> {
  const out: Record<string, { action: string; dismiss: string }> = {};
  for (const locale of HELP_LOCALES) {
    let action = 'View in {{lang}}';
    let dismiss = 'Dismiss';
    try {
      const s = JSON.parse(
        fs.readFileSync(path.join(LOCALES_DIR, locale, 'settings.json'), 'utf8')
      ) as { langSuggest?: { action?: string; dismiss?: string } };
      action = s.langSuggest?.action ?? action;
      dismiss = s.langSuggest?.dismiss ?? dismiss;
    } catch {
      /* fall back to English wording */
    }
    out[locale] = {
      action: action.replace('{{lang}}', LANGUAGE_META[locale]?.native ?? locale),
      dismiss,
    };
  }
  return out;
}

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Converts the two markups the catalogs support into HTML: [text](url)
// links and **bold**. External links open a new tab; same-site paths
// navigate in place. Bold exists for one job - naming a real UI label
// inside an answer ("**Save to my notes**") - so keep it to that.
// The .md twins carry both markups through unchanged, which is why the
// syntax is markdown rather than anything of our own.
function renderInline(s: string): string {
  return esc(s)
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, (_, text, url) =>
      url.startsWith('/')
        ? `<a href="${url}">${text}</a>`
        : `<a href="${url}" target="_blank" rel="noopener noreferrer">${text}</a>`
    )
    .replace(/\*\*([^*]+)\*\*/g, '<strong>$1</strong>')
    .replace(/`([^`]+)`/g, '<code>$1</code>');
}

/**
 * A whole paragraph wrapped in backticks is a value the reader has to move
 * somewhere else by hand - an Obtainium source URL, and nothing else so far.
 * It renders as a bordered monospace row with a Copy button rather than as
 * prose, because a URL buried mid-sentence on a phone is selected wrong far
 * more often than it is selected right.
 *
 * Deliberately paragraph-level, not an inline `code` span: the markup marks
 * a value to be TAKEN, so it must own its line to be worth a button. The .md
 * twins and the llms text layer carry the backticks through untouched, where
 * they already mean exactly this.
 */
const CODE_PARA = /^`([^`]+)`$/;

/**
 * A paragraph whose every line starts with "- " is a list: one row per line,
 * rendered as a borderless definition table rather than as prose. It exists
 * for a set the reader scans to find their own row - the per-platform storage
 * paths - where a sentence makes every reader read four answers that are not
 * theirs. Single backticks inside a row mark a literal path or value.
 *
 * The .md twins and the llms text layer carry the dashes through untouched,
 * where they already mean a list, and stripMd drops the markers for the text
 * surfaces (JSON-LD, meta descriptions, the search haystack).
 * // Spec: ops/docs/help-center.md (the template)
 */

/**
 * A whole paragraph that is one linked image is a badge: today the Obtainium
 * one, which adds PrivacyNotes to a reader's phone in a tap. It renders as a
 * plain tappable image rather than as prose, because a store badge already IS
 * the button, and a reader looking for the install route finds a shape they
 * know faster than they find a sentence.
 *
 * Standard markdown on purpose, exactly like the two inline markups: the .md
 * twins and llms-full.txt carry `[![alt](src)](href)` through `absoluteLinks`
 * untouched, where an image inside a link means precisely this, and where the
 * relative src comes out absolute for free.
 */
const BADGE_PARA = /^\[!\[([^\]]*)\]\(([^)]+)\)\]\(([^)]+)\)$/;

/**
 * Intrinsic size for that badge, as a constant rather than as syntax in the
 * catalogs: every badge we ship is the Obtainium one at its own 3.36:1 shape,
 * and a reader on a slow connection still gets the box reserved before the
 * image lands. A second badge of another shape is the moment to widen the
 * markup, not the moment to guess.
 * // Spec: ops/packaging/obtainium/README.md (the badge)
 */
const BADGE_W = 161;
const BADGE_H = 48;

/**
 * One answer paragraph: prose, the badge above, or the copy row above.
 * `askCopyShort` and `askCopied` are reused rather than adding a label of its
 * own, so a new copy row never costs a 17-locale batch.
 */
function renderParagraph(par: string, p: Record<string, string>): string {
  const badge = BADGE_PARA.exec(par.trim());
  if (badge) {
    const [, alt, src, href] = badge;
    return `<a class="bdg" href="${esc(href)}" target="_blank" rel="noopener noreferrer"><img src="${esc(src)}" alt="${esc(alt)}" width="${BADGE_W}" height="${BADGE_H}" loading="lazy"></a>`;
  }
  const lines = par.trim().split('\n');
  if (lines.length > 1 && lines.every((l) => l.startsWith('- '))) {
    const items = lines.map((l) => `<li>${renderInline(l.slice(2))}</li>`).join('');
    return `<ul class="lst">${items}</ul>`;
  }
  const code = CODE_PARA.exec(par.trim());
  if (!code) return `<p>${renderInline(par)}</p>`;
  return `<div class="cbx"><code>${esc(code[1])}</code><button class="btn-ok js-cbx-copy" type="button" data-copied="${esc(p.askCopied)}" hidden><span class="ic ic-copy">${icon(COPY_PATH, 13)}</span><span class="ic ic-done">${icon(CHECK_PATH, 13)}</span><span class="lbl">${esc(p.askCopyShort)}</span></button></div>`;
}

/** Links, bold and code to plain text, for JSON-LD, descriptions, haystacks. */
function stripMd(s: string): string {
  return s
    .replace(/\[!\[([^\]]*)\]\([^)]+\)\]\([^)]+\)/g, '$1')
    .replace(/\[([^\]]+)\]\(([^)]+)\)/g, '$1')
    .replace(/\*\*([^*]+)\*\*/g, '$1')
    .replace(/`([^`]+)`/g, '$1')
    .replace(/^- /gm, '');
}

/**
 * Same-site links in the catalogs are relative (`/help/remove-device/`),
 * which is right inside a page and ambiguous inside a standalone .md file
 * an agent fetched on its own. Absolutize them so every link resolves
 * without the reader knowing where the file came from.
 */
function absoluteLinks(s: string): string {
  return s.replace(/\]\((\/[^)]*)\)/g, `](${ORIGIN}$1)`);
}

/** Lowercased, diacritics-stripped haystack for the client-side search. */
function normalize(s: string): string {
  return stripMd(s)
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase();
}

/** Excerpt for a meta description (~155 chars, word boundary). */
function excerpt(text: string): string {
  const plain = stripMd(text);
  if (plain.length <= 155) return plain;
  const cut = plain.slice(0, 155);
  // Trim to a word boundary, but only when there IS one near the end. Japanese
  // and Chinese write no spaces, so the last space in a CJK excerpt sits after
  // whatever Latin fragment happens to appear first, and the trim collapsed the
  // whole description: the ja burn-notes page shipped a 7-character "burn...".
  // Below the threshold the hard cut wins, which is what a CJK reader expects
  // anyway. English is unaffected: its last space is almost always past 140.
  const space = cut.lastIndexOf(' ');
  return `${space > 120 ? cut.slice(0, space) : cut}...`;
}

function fill(template: string, vars: Record<string, string | number>): string {
  return template.replace(/\{\{(\w+)\}\}/g, (_, k) => String(vars[k] ?? ''));
}

type Section = { key: FaqGroupKey; label: string; entries: { id: string; q: string; a: string[] }[] };

function buildSections(order: FaqGroupKey[], rows: FaqStructureRow[], cat: FaqCatalog): Section[] {
  return order
    .map((key) => ({
      key,
      label: cat.groups[key] ?? key,
      entries: rows
        .filter((r) => r.group === key)
        .map((r) => ({ id: r.id, ...cat.entries[r.id] }))
        .filter((e) => e.q && e.a?.length),
    }))
    .filter((s) => s.entries.length > 0);
}

type RailItem = { href: string; label: string; count?: number; on?: boolean; search?: string; icon?: string };

function railRows(items: RailItem[], cls: string): string {
  return items
    .map(
      (it) =>
        `<a class="ritem ${cls}${it.on ? ' on' : ''}" href="${it.href}"${it.search ? ` data-s="${esc(it.search)}"` : ''}>${it.icon ?? ''}<span class="rlbl">${esc(it.label)}</span>${it.count != null ? `<span class="rct">${it.count}</span>` : ''}</a>`
    )
    .join('\n');
}

/**
 * The unified sidebar shown on EVERY Help view (hub, FAQ leaves, guides):
 * the FAQ topics on top, the import guides beneath. Topic rows carry the
 * `rt` class so static-pages.js can scope search-filtering and the
 * scroll-spy to them without touching the guide rows.
 */
function renderSidebar(opts: {
  topicsLabel: string;
  topics: RailItem[];
  guidesLabel: string;
  guideItems: RailItem[];
  homeHref: string;
  homeLabel: string;
  id?: string;
}): string {
  const guidesNav = opts.guideItems.length
    ? `<nav class="rail rail-guides" aria-label="${esc(opts.guidesLabel)}">
<p class="eyebrow rail-sep">// ${esc(opts.guidesLabel)}</p>
${railRows(opts.guideItems, 'rg')}
</nav>`
    : '';
  // Two navs inside one column so mobile can split them: topics up under
  // the breadcrumb, import guides down below the article.
  // The home row is the one rail entry that is never a filter target: on a
  // leaf it walks back to the hub, on the hub it drops an active query.
  const homeRow = `<a class="ritem rhome" href="${opts.homeHref}">${RAIL_HOME_ICON}<span class="rlbl">${esc(opts.homeLabel)}</span></a>`;
  return `<div class="rail-col"${opts.id ? ` id="${opts.id}"` : ''}>
<nav class="rail rail-topics" aria-label="${esc(opts.topicsLabel)}">
<p class="eyebrow">// ${esc(opts.topicsLabel)}</p>
${homeRow}
${railRows(opts.topics, 'rt')}
</nav>
${guidesNav}
</div>`;
}

function topicRailItems(sections: Section[], hrefOf: (key: FaqGroupKey) => string, activeKey?: FaqGroupKey): RailItem[] {
  return sections.map((s) => ({
    href: hrefOf(s.key),
    label: s.label,
    count: s.entries.length,
    on: s.key === activeKey,
    icon: topicIcon(s.key),
  }));
}

function guideRailItems(locale: HelpLocale, guideOrder: string[], guides: GuidesCatalog | null, activeId?: string): RailItem[] {
  if (!guides) return [];
  return guideOrder
    .filter((id) => guides.guides[id]?.app)
    .map((id) => {
      const g = guides.guides[id];
      const icon = guideIconHref(id);
      return {
        href: guidePath(locale, id),
        label: g.app,
        on: id === activeId,
        // Lets the hub search keep matching guides visible (e.g. a query
        // like "takeout" that only appears in the Google Keep guide).
        search: normalize(`${g.app} ${g.title} ${g.lead}`),
        // Neutral chip behind the colorful app logo so light and dark
        // logos both sit comfortably on either theme.
        icon: icon
          ? `<span class="ichip"><img src="${icon}" width="18" height="18" alt="" loading="lazy"></span>`
          : guideGlyph(id, 18)
            ? `<span class="ichip">${guideGlyph(id, 18)}</span>`
            : undefined,
      };
    });
}

function renderSections(
  sections: Section[],
  locale: HelpLocale,
  cat: FaqCatalog,
  hotkeyGroups: HotkeyGroupData[]
): string {
  const permaLabel = cat.page.copyLink;
  return sections
    .map((s) => {
      const entries = s.entries
        .map((e) => {
          // Same special-casing as the leaves: the showcase entries render
          // their demo section inside the answer, and the shortcuts entry
          // drops its combo paragraph in favor of the grid. The haystack
          // keeps the FULL text so combo searches still match.
          const bodyA = e.id === 'keyboard-shortcuts' ? e.a.slice(0, 1) : e.a;
          const paragraphs = bodyA.map((par) => renderParagraph(par, cat.page)).join('');
          const extra = entryShowcase(e.id, locale, cat.page, hotkeyGroups);
          const hay = normalize(`${e.q} ${e.a.join(' ')}`);
          const leaf = leafPath(locale, e.id);
          return `<details class="entry" id="${esc(e.id)}" data-s="${esc(hay)}" data-leaf="${leaf}">
<summary><span class="q">${esc(e.q)}</span><a class="perma" href="${leaf}" aria-label="${esc(permaLabel)}: ${esc(e.q)}">${LINK_ICON}</a><span class="chev" aria-hidden="true"></span></summary>
<div class="a">${paragraphs}${extra}</div>
</details>`;
        })
        .join('\n');
      return `<section class="fgroup" id="g-${esc(s.key)}">
<h2 class="eyebrow">// ${esc(s.label)}</h2>
${entries}
</section>`;
    })
    .join('\n');
}

/** Phosphor bold paths, inlined like TOPIC_ICON above. Sparkle, ShieldCheck, Copy, Check. */
const SPARKLE_PATH =
  'M199,125.31l-49.88-18.39L130.69,57a19.92,19.92,0,0,0-37.38,0L74.92,106.92,25,125.31a19.92,19.92,0,0,0,0,37.38l49.88,18.39L93.31,231a19.92,19.92,0,0,0,37.38,0l18.39-49.88L199,162.69a19.92,19.92,0,0,0,0-37.38Zm-63.38,35.16a12,12,0,0,0-7.11,7.11L112,212.28l-16.47-44.7a12,12,0,0,0-7.11-7.11L43.72,144l44.7-16.47a12,12,0,0,0,7.11-7.11L112,75.72l16.47,44.7a12,12,0,0,0,7.11,7.11L180.28,144ZM140,40a12,12,0,0,1,12-12h12V16a12,12,0,0,1,24,0V28h12a12,12,0,0,1,0,24H188V64a12,12,0,0,1-24,0V52H152A12,12,0,0,1,140,40ZM252,88a12,12,0,0,1-12,12h-4v4a12,12,0,0,1-24,0v-4h-4a12,12,0,0,1,0-24h4V72a12,12,0,0,1,24,0v4h4A12,12,0,0,1,252,88Z';
const SHIELD_PATH =
  'M208,36H48A20,20,0,0,0,28,56v56c0,54.29,26.32,87.22,48.4,105.29,23.71,19.39,47.44,26,48.44,26.29a12.1,12.1,0,0,0,6.32,0c1-.28,24.73-6.9,48.44-26.29,22.08-18.07,48.4-51,48.4-105.29V56A20,20,0,0,0,208,36Zm-4,76c0,35.71-13.09,64.69-38.91,86.15A126.28,126.28,0,0,1,128,219.38a126.14,126.14,0,0,1-37.09-21.23C65.09,176.69,52,147.71,52,112V60H204ZM79.51,144.49a12,12,0,1,1,17-17L112,143l47.51-47.52a12,12,0,0,1,17,17l-56,56a12,12,0,0,1-17,0Z';

const COPY_PATH =
  'M216,28H88A12,12,0,0,0,76,40V76H40A12,12,0,0,0,28,88V216a12,12,0,0,0,12,12H168a12,12,0,0,0,12-12V180h36a12,12,0,0,0,12-12V40A12,12,0,0,0,216,28ZM156,204H52V100H156Zm48-48H180V88a12,12,0,0,0-12-12H100V52H204Z';
const CHECK_PATH =
  'M232.49,80.49l-128,128a12,12,0,0,1-17,0l-56-56a12,12,0,1,1,17-17L96,183,215.51,63.51a12,12,0,0,1,17,17Z';

/** One inline glyph, same shape as topicIcon. */
function icon(d: string, size: number): string {
  return `<svg width="${size}" height="${size}" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="${d}"/></svg>`;
}

/**
 * The prompt the "Ask an AI" box copies. English, and deliberately not in
 * the locale catalogs: it is an instruction to a model, not UI copy, and
 * models follow English instructions more reliably than a translation of
 * them. The last rule makes the model answer in the reader's language, so
 * a German reader pastes this and gets German back.
 *
 * The help URL carries the reader's locale slug: the model shows
 * that link to a person who then clicks it. /llms-full.txt stays bare -
 * it is one English file, not a marketing page with locale variants.
 *
 * SHORT ON PURPOSE, and it must stay short. Four rounds of tuning taught the
 * lesson the hard way: every failure tempted us to add a rule, each rule
 * added surface to misread, and one of them caused the next failure - naming
 * an internal marker got "Cite as:" echoed verbatim in front of readers. The
 * behaviour that actually stuck came from the FILES, not from prose: a
 * "Source:" line beside every answer fixed citations after three prompt
 * rewrites could not. So when an assistant gets something wrong here, change
 * what the files say and leave this alone. One rule per job, no more.
 *
 * The one exception is SCOPE, and /changelog.md is why the rule now names it.
 * A behaviour fix belongs in the data; a permission does not. The first line
 * and rule 1 together tell the model what it is allowed to read, so a pointer
 * living only inside llms-index.txt asks the DATA to widen a boundary the
 * READER set, which is the shape a careful model is right to refuse. Granting
 * it cost one word in the first line and one addressed line below, and no new
 * rule: everything the address block names is already covered by "Use only
 * those pages".
 *
 * Three fallbacks, narrowing: index, then the one-file bundle, then the
 * HTML pages. The last exists because at least one major assistant reports
 * "an automated web-fetching error" on a .txt URL while happily reading a
 * page; our own hosting is not the problem (every user agent gets a 200,
 * no challenge, no bot rule), so the prompt degrades instead of arguing.
 * The ladder names both file types because the same assistant refused a .md
 * URL on 2026-08-23, and refused the plain HTML changelog page in the same
 * breath, which no wording here can fix: production answered all three with
 * a 200 to every user agent tried, including the AI-crawler ones. Suspect
 * an edge-level AI-bot block before suspecting these files.
 *
 * The changelog line sits outside that ladder, after a blank line, because it
 * is not a fallback. Inside the ladder it would read as "only if you cannot
 * fetch a .txt file", which is the opposite of when it applies.
 *
 * The line before the sign-off is a usability catch, not a rule, which is
 * why it sits outside the list. Someone who has never done this pastes the
 * block and presses enter with nothing typed; without that line the
 * assistant answers a prompt with no question in it, and the reader is
 * confused at the exact moment they were about to be helped. With it, the
 * assistant asks what they want to know, which is the recovery a person
 * needs after the box is off their screen.
 *
 * The refusal rule is the load-bearing one. Sending readers to a third
 * party creates exactly one new way to lose a vault, which is a reader
 * pasting twelve words into someone else's chat box. The box says it too.
 */
function askPrompt(locale: HelpLocale): string {
  return `Answer my questions about PrivacyNotes using only its help center and its changelog.

Start here: ${ORIGIN}/llms-index.txt
It lists every question with the page that answers it. Fetch the one or two that match mine.
If you can only make one request, fetch ${ORIGIN}/llms-full.txt instead.
If you cannot fetch a .txt or .md file, read ${ORIGIN}${helpPath(locale)} and ${ORIGIN}/changelog instead.

For what changed, or where something moved, fetch ${ORIGIN}/changelog.md.

Rules:
- Use only those pages. If they do not answer something, say so instead of guessing.
- Never invent a feature, a menu path, a price, or a limit.
- End your reply with the "Source:" URL from the page you used, exactly as written.
- Reply in my language.
- Never ask me for my recovery phrase, my PIN, or the contents of a note.

If no question follows, ask me what I would like to know.

My first question:`;
}

/**
 * One copy control, rendered twice: compact beside the disclosure toggle and
 * full-label under the prompt text. Same function, same class, same CSS, so
 * the two can never drift apart visually.
 *
 * The compact one lives INSIDE the <summary> so it can share that row
 * without a wrapper element: the summary is a flex container here and the
 * button is just another item in it. static-pages.js stops the click
 * bubbling, or copying would toggle the disclosure at the same time. Both
 * ship `hidden` and are revealed by that script, so a reader without JS sees
 * neither and still gets the prompt text from the open <details>.
 */
function copyButton(p: Record<string, string>, id: string, label: string): string {
  return `<button class="btn-ok js-ask-copy" id="${id}" type="button" data-copied="${esc(p.askCopied)}" hidden><span class="ic ic-copy">${icon(COPY_PATH, 13)}</span><span class="ic ic-done">${icon(CHECK_PATH, 13)}</span><span class="lbl">${esc(label)}</span></button>`;
}

/**
 * "Ask an AI" - the support-deflection box, directly above the block that
 * hands out our contact links. That order is the whole point: it meets a
 * reader at the moment they have decided we did not answer them, and gives
 * them something that answers in seconds instead of a day.
 *
 * Numbered steps rather than a paragraph, because the reader who reaches
 * this box has already failed to find an answer and is deciding whether to
 * write to us: copy, paste, ask has to be readable at a glance. The fourth
 * step exists because the prompt only has to be pasted once - a reader who
 * keeps the chat can ask the next question straight away, which is the
 * difference between a one-off and a habit.
 *
 * The copy button ships `hidden` and static-pages.js reveals it, so a
 * no-JS reader still gets the prompt from the <details> underneath. Same
 * progressive-enhancement contract as the /brand copy cards.
 */
function askAiBlock(p: Record<string, string>, locale: HelpLocale, sections: Section[]): string {
  const total = sections.reduce((n, sec) => n + sec.entries.length, 0);
  const steps = [p.askStep1, p.askStep2, p.askStep3, p.askStep4]
    .filter(Boolean)
    .map((st) => `<li>${esc(st)}</li>`)
    .join('\n');
  return `<div class="ask" id="ask">
<div class="ask-head">
<span class="ask-ico">${icon(SPARKLE_PATH, 18)}</span>
<div>
<h2>${esc(p.askTitle)}</h2>
<p>${esc(fill(p.askBody, { total }))}</p>
</div>
</div>
<ol class="ask-steps">
${steps}
</ol>
<details class="ask-more">
<summary><span class="sum-lbl">${esc(p.askShow)}</span>${copyButton(p, 'ask-copy', p.askCopyShort)}</summary>
<pre id="ask-prompt">${esc(askPrompt(locale))}</pre>
<div class="ask-act">${copyButton(p, 'ask-copy-full', p.askCopy)}</div>
</details>
<p class="askwarn">${icon(SHIELD_PATH, 15)}<span>${esc(p.askWarn)}</span></p>
</div>
`;
}

/**
 * The one-line twin of the box above, rendered in the page header and
 * anchored at it. Someone who lands on a leaf from a search engine meets
 * the full box only after the answer, the hub section and the related
 * list; this gives them the same door at the top without repeating the
 * pitch, which is why it is a label and an arrow rather than a panel.
 */
function askMiniBar(p: Record<string, string>): string {
  return `<a class="askmini" href="#ask">${icon(SPARKLE_PATH, 13)}<span>${esc(p.askMini)}</span><span class="askmini-arr" aria-hidden="true"></span></a>`;
}

/** @phosphor-icons "github-logo" (fill), the shape the feedback row uses. */
const GITHUB_MARK =
  '<svg width="16" height="16" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M216,104v8a56.06,56.06,0,0,1-48.44,55.47A39.8,39.8,0,0,1,176,192v40a8,8,0,0,1-8,8H104a8,8,0,0,1-8-8V216H72a40,40,0,0,1-40-40A24,24,0,0,0,8,152a8,8,0,0,1,0-16,40,40,0,0,1,40,40,24,24,0,0,0,24,24H96v-8a39.8,39.8,0,0,1,8.44-24.53A56.06,56.06,0,0,1,56,112v-8a58.14,58.14,0,0,1,7.69-28.32A59.78,59.78,0,0,1,69.07,28,8,8,0,0,1,76,24a59.75,59.75,0,0,1,48,24h24a59.75,59.75,0,0,1,48-24,8,8,0,0,1,6.93,4,59.74,59.74,0,0,1,5.37,47.68A58,58,0,0,1,216,104Z"/></svg>';

/**
 * The published source that backs one answer, as a row per document.
 *
 * A row carries the file name and the exact heading it jumps to, both
 * quoted from the document, so the block needs no translated prose: the
 * only strings around it are its title and the line saying the documents
 * are in English. `FAQ_SOURCES` decides which entries get one.
 *
 * No trailing arrow on a row. The GitHub mark and the monospace file
 * name already read as a link off this site, and a second glyph is the
 * chrome the help chip lost for the same reason.
 */
function sourcesBlock(p: Record<string, string>, id: string): string {
  const rows = FAQ_SOURCES[id];
  if (!rows?.length) return '';
  const items = rows
    .map(
      (s) =>
        `<a class="src-row" href="${sourceUrl(s)}" target="_blank" rel="noopener noreferrer">${GITHUB_MARK}<span class="src-lbl"><span class="src-file">${esc(SOURCE_FILES[s.doc])}</span>${s.heading ? `<span class="src-head">${esc(s.heading)}</span>` : ''}</span></a>`
    )
    .join('\n');
  return `<div class="srcs">
<p class="eyebrow">// ${esc(p.sourcesTitle)}</p>
${items}
<p class="src-note">${esc(p.sourcesNote)}</p>
</div>`;
}

/** The same rows as markdown, for the .md twin and the text bundle. */
function sourcesMd(id: string): string {
  const rows = FAQ_SOURCES[id];
  if (!rows?.length) return '';
  const items = rows
    .map((s) => `- [${SOURCE_FILES[s.doc]}${s.heading ? `: ${s.heading}` : ''}](${sourceUrl(s)})`)
    .join('\n');
  return `\n## Read the source\n\n${items}\n`;
}

// "Question not answered" prompt with the same platforms as the site
// footer (footerData.ts). Icon paths: @phosphor-icons fill variants
// (viewBox 0 0 256 256), same shapes static-page-chrome.ts uses.
function feedbackBlock(prompt: string): string {
  return `<div class="feedback">
<p>${esc(prompt)}</p>
<div class="fb-links">
<a class="btn btn-ghost" href="https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues" target="_blank" rel="noopener noreferrer"><svg width="14" height="14" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M216,104v8a56.06,56.06,0,0,1-48.44,55.47A39.8,39.8,0,0,1,176,192v40a8,8,0,0,1-8,8H104a8,8,0,0,1-8-8V216H72a40,40,0,0,1-40-40A24,24,0,0,0,8,152a8,8,0,0,1,0-16,40,40,0,0,1,40,40,24,24,0,0,0,24,24H96v-8a39.8,39.8,0,0,1,8.44-24.53A56.06,56.06,0,0,1,56,112v-8a58.14,58.14,0,0,1,7.69-28.32A59.78,59.78,0,0,1,69.07,28,8,8,0,0,1,76,24a59.75,59.75,0,0,1,48,24h24a59.75,59.75,0,0,1,48-24,8,8,0,0,1,6.93,4,59.74,59.74,0,0,1,5.37,47.68A58,58,0,0,1,216,104Z"/></svg>GitHub</a>
<a class="btn btn-ghost" href="https://www.reddit.com/r/PrivacyNotes/" target="_blank" rel="noopener noreferrer"><svg width="14" height="14" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M248,104a32,32,0,0,0-52.94-24.19c-16.75-8.9-36.76-14.28-57.66-15.53l5.19-31.17,17.72,2.72a24,24,0,1,0,2.87-15.74l-26-4a8,8,0,0,0-9.11,6.59L121.2,64.16c-21.84.94-42.82,6.38-60.26,15.65a32,32,0,0,0-42.59,47.74A59,59,0,0,0,16,144c0,21.93,12,42.35,33.91,57.49C70.88,216,98.61,224,128,224s57.12-8,78.09-22.51C228,186.35,240,165.93,240,144a59,59,0,0,0-2.35-16.45A32.16,32.16,0,0,0,248,104ZM72,128a16,16,0,1,1,16,16A16,16,0,0,1,72,128Zm91.75,55.07a76.18,76.18,0,0,1-71.5,0,8,8,0,1,1,7.5-14.14,60.18,60.18,0,0,0,56.5,0,8,8,0,1,1,7.5,14.14ZM168,144a16,16,0,1,1,16-16A16,16,0,0,1,168,144Z"/></svg>Reddit</a>
<a class="btn btn-ghost" href="https://x.com/PrivacyNotesApp" target="_blank" rel="noopener noreferrer"><svg width="14" height="14" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M215,219.85a8,8,0,0,1-7,4.15H160a8,8,0,0,1-6.75-3.71l-40.49-63.63L53.92,221.38a8,8,0,0,1-11.84-10.76l61.77-68L41.25,44.3A8,8,0,0,1,48,32H96a8,8,0,0,1,6.75,3.71l40.49,63.63,58.84-64.72a8,8,0,0,1,11.84,10.76l-61.77,67.95,62.6,98.38A8,8,0,0,1,215,219.85Z"/></svg>X.com</a>
<a class="btn btn-ghost" href="https://mastodon.social/@privacynotes" target="_blank" rel="noopener noreferrer"><svg width="14" height="14" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M184,32H72A40,40,0,0,0,32,72V192a40,40,0,0,0,40,40h88a8,8,0,0,0,0-16H72a24,24,0,0,1-24-24v-8H184a40,40,0,0,0,40-40V72A40,40,0,0,0,184,32Zm0,104a8,8,0,0,1-16,0V104a16,16,0,0,0-32,0v32a8,8,0,0,1-16,0V104a16,16,0,0,0-32,0v32a8,8,0,0,1-16,0V104a32,32,0,0,1,56-21.13A32,32,0,0,1,184,104Z"/></svg>Mastodon</a>
</div>
</div>`;
}

/**
 * Help-center freshness, as ISO days, emitted as `dateModified` on the hub,
 * on every FAQ leaf and on every guide. Nothing here carried a date before
 * 2026-08-26, so neither search nor an AI reader could tell a page written
 * last week from one written last year.
 *
 * CONTENT_BASELINE is the day the whole centre was last reviewed end to end.
 * CONTENT_UPDATED overrides it per page, and that is how the tracking works
 * from here on: a turn that rewrites one answer or one guide adds that id
 * with the day it changed, and only that page's date moves. Review the whole
 * centre again and the baseline moves instead, and the overrides empty out.
 *
 * Keys are FAQ entry ids and guide ids. They share one map because no id
 * appears in both catalogs. Never write a future date and never bump one for
 * a typo: the whole value of the signal is that it is true.
 * // Spec: ops/docs/help-center.md (freshness dates)
 */
const CONTENT_BASELINE = '2026-08-26';
const CONTENT_UPDATED: Record<string, string> = {
  'data-location': '2026-08-28',
  'data-on-disk': '2026-09-02',
  'open-source': '2026-08-30',
  'report-vulnerability': '2026-08-31',
  'bip39-wordlist': '2026-08-30',
  'leaving': '2026-08-30',
  'android-backup': '2026-08-31',
  'try-before-signup': '2026-08-31',
  'threat-model-levels': '2026-08-31',
  'twelve-word-phrase': '2026-08-31',
  'why-no-2fa': '2026-08-31',
  'remove-device': '2026-08-31',
  'note-size-limit': '2026-08-31',
  'feature-requests': '2026-08-31',
  'android-updates': '2026-08-31',
  'translation-quality': '2026-08-31',
  'bookmarks': '2026-08-31',
  'ask-an-ai': '2026-08-31',
  'locked-vs-protected': '2026-08-31',
  'phrase-compromised': '2026-08-31',
  'lost-device': '2026-08-31',
  'device-limit': '2026-08-31',
  'backup-strategy': '2026-08-31',
  'restore-backup': '2026-08-31',
  'upload-failed': '2026-08-31',
  'manage-storage-addon': '2026-08-31',
  'play-vs-apk': '2026-08-31',
  'markdown-folder': '2026-08-31',
  'note-links': '2026-08-31',
  'share-with-someone': '2026-08-31',
  'wifi-only': '2026-08-31',
  'note-history': '2026-08-31',
  'vault-totp': '2026-08-31',
  'verify-download': '2026-08-31',
  'family-sharing': '2026-08-31',
  'business-use': '2026-08-31',
  'samsung-notes': '2026-08-31',
  'bitwarden': '2026-08-31',
  'upnote': '2026-08-31',
  'browser-passwords': '2026-08-31',
  'nextcloud-notes': '2026-08-31',
};

/** The day one page last changed, or the baseline when it has not since. */
function contentDate(id?: string): string {
  return (id && CONTENT_UPDATED[id]) || CONTENT_BASELINE;
}

/** The newest date anywhere. The hub aggregates every answer, so it reports this. */
function newestContentDate(): string {
  return Object.values(CONTENT_UPDATED).reduce((a, b) => (b > a ? b : a), CONTENT_BASELINE);
}

/** CSP-inert structured data. `entries` = all for the hub, one for a leaf. */
function faqJsonLd(entries: { q: string; a: string[] }[], dateModified: string): string {
  const data = {
    '@context': 'https://schema.org',
    '@type': 'FAQPage',
    dateModified,
    mainEntity: entries.map((e) => ({
      '@type': 'Question',
      name: stripMd(e.q),
      acceptedAnswer: { '@type': 'Answer', text: e.a.map(stripMd).join('\n\n') },
    })),
  };
  return `<script type="application/ld+json">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>`;
}

/**
 * A guide is an article about somebody else's export, so it says so. Google
 * shows no rich result for TechArticle and that is not what this is for: it
 * names the thing the page is ABOUT, the language it is written in and the
 * day it last changed, which is what an engine or an assistant needs to
 * decide the page answers "how do I export from <app>" and is still current.
 *
 * `about` is a plain Thing on purpose. Two guides cover a category rather
 * than one app - browser bookmarks, browser passwords - and calling those a
 * SoftwareApplication would be false. `datePublished` is deliberately absent:
 * we do not know it, and inventing one to fill a recommended field is the
 * kind of structured data that is worse than none.
 */
function guideJsonLd(
  g: { app: string; title: string; lead: string },
  url: string,
  locale: HelpLocale,
  dateModified: string
): string {
  const data = {
    '@context': 'https://schema.org',
    '@type': 'TechArticle',
    headline: stripMd(g.title),
    description: excerpt(g.lead),
    inLanguage: locale,
    dateModified,
    about: { '@type': 'Thing', name: g.app },
    mainEntityOfPage: url,
    isPartOf: { '@type': 'WebSite', name: 'PrivacyNotes', url: ORIGIN },
    publisher: { '@type': 'Organization', name: 'PrivacyNotes', url: ORIGIN },
  };
  return `<script type="application/ld+json">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>`;
}

function breadcrumbJsonLd(hubLabel: string, hubUrl: string, name: string, url: string): string {
  const data = {
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: hubLabel, item: hubUrl },
      { '@type': 'ListItem', position: 2, name: stripMd(name), item: url },
    ],
  };
  return `<script type="application/ld+json">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>`;
}

/**
 * Points a machine reader at this page's plain-text twin (see the
 * plain-text layer below). English only, because only English has one.
 * Declared as text/markdown, which is the format; it is SERVED as
 * text/plain so that a person following the link reads it in the browser
 * instead of downloading it (see public/_headers).
 */
function textAlternate(locale: HelpLocale, href: string): string {
  return locale === 'en' ? `\n<link rel="alternate" type="text/markdown" href="${ORIGIN}${href}">` : '';
}

/** hreflang cluster for the hub, or for one FAQ leaf when `id` is given. */
function hreflangCluster(id?: string): string {
  const href = (l: HelpLocale) => (id ? `${ORIGIN}${leafPath(l, id)}` : `${ORIGIN}${helpPath(l)}`);
  const links = HELP_LOCALES.map((l) => `<link rel="alternate" hreflang="${l}" href="${href(l)}">`);
  links.push(`<link rel="alternate" hreflang="x-default" href="${href('en')}">`);
  return links.join('\n');
}

/** Full hreflang cluster for one guide across every locale. */
function guideHreflang(id: string): string {
  const links = HELP_LOCALES.map(
    (l) => `<link rel="alternate" hreflang="${l}" href="${ORIGIN}${guidePath(l, id)}">`
  );
  links.push(`<link rel="alternate" hreflang="x-default" href="${ORIGIN}${guidePath('en', id)}">`);
  return links.join('\n');
}

// Phosphor "bold" path data (viewBox 0 0 256 256), extracted from the
// installed @phosphor-icons/react package so the sidebar matches the icon
// set the rest of the site uses. One icon per FAQ topic group.
/** Phosphor Key, bold. Shared: the Account & recovery topic wears it, and
 *  so does the Browser passwords guide, which has no app logo. */
const KEY_BOLD =
  'M196,76a16,16,0,1,1-16-16A16,16,0,0,1,196,76Zm48,22.74A84.3,84.3,0,0,1,160.11,180H160a83.52,83.52,0,0,1-23.65-3.38l-7.86,7.87A12,12,0,0,1,120,188H108v12a12,12,0,0,1-12,12H84v12a12,12,0,0,1-12,12H40a20,20,0,0,1-20-20V187.31a19.86,19.86,0,0,1,5.86-14.14l53.52-53.52A84,84,0,1,1,244,98.74ZM202.43,53.57A59.48,59.48,0,0,0,158,36c-32,1-58,27.89-58,59.89a59.69,59.69,0,0,0,4.2,22.19,12,12,0,0,1-2.55,13.21L44,189v23H60V200a12,12,0,0,1,12-12H84V176a12,12,0,0,1,12-12h19l9.65-9.65a12,12,0,0,1,13.22-2.55A59.58,59.58,0,0,0,160,156h.08c32,0,58.87-26.07,59.89-58A59.55,59.55,0,0,0,202.43,53.57Z';

const TOPIC_ICON: Record<string, string> = {
  gettingStarted:
    'M40.14,46.88A12,12,0,0,0,36,56V224a12,12,0,0,0,24,0V181.72c22.84-17.12,42.1-9.12,70.68,5,16.23,8,34.74,17.2,54.8,17.2,14.72,0,30.28-4.94,46.38-18.88A12,12,0,0,0,236,176V56a12,12,0,0,0-19.86-9.07c-24.71,21.41-44.53,13.31-74.82-1.68C113.19,31.27,78.17,13.94,40.14,46.88ZM212,170.26c-22.84,17.13-42.1,9.11-70.68-5C118.16,153.76,90.33,140,60,153.87V61.69c22.84-17.12,42.1-9.12,70.68,5,16.23,8,34.74,17.2,54.8,17.2A63,63,0,0,0,212,78.08Z',
  securityPrivacy:
    'M208,36H48A20,20,0,0,0,28,56v56c0,54.29,26.32,87.22,48.4,105.29,23.71,19.39,47.44,26,48.44,26.29a12.1,12.1,0,0,0,6.32,0c1-.28,24.73-6.9,48.44-26.29,22.08-18.07,48.4-51,48.4-105.29V56A20,20,0,0,0,208,36Zm-4,76c0,35.71-13.09,64.69-38.91,86.15A126.28,126.28,0,0,1,128,219.38a126.14,126.14,0,0,1-37.09-21.23C65.09,176.69,52,147.71,52,112V60H204ZM79.51,144.49a12,12,0,1,1,17-17L112,143l47.51-47.52a12,12,0,0,1,17,17l-56,56a12,12,0,0,1-17,0Z',
  accountRecovery: KEY_BOLD,
  syncDevices:
    'M228,48V96a12,12,0,0,1-12,12H168a12,12,0,0,1,0-24h19l-7.8-7.8a75.55,75.55,0,0,0-53.32-22.26h-.43A75.49,75.49,0,0,0,72.39,75.57,12,12,0,1,1,55.61,58.41a99.38,99.38,0,0,1,69.87-28.47H126A99.42,99.42,0,0,1,196.2,59.23L204,67V48a12,12,0,0,1,24,0ZM183.61,180.43a75.49,75.49,0,0,1-53.09,21.63h-.43A75.55,75.55,0,0,1,76.77,179.8L69,172H88a12,12,0,0,0,0-24H40a12,12,0,0,0-12,12v48a12,12,0,0,0,24,0V189l7.8,7.8A99.42,99.42,0,0,0,130,226.06h.56a99.38,99.38,0,0,0,69.87-28.47,12,12,0,0,0-16.78-17.16Z',
  yourData:
    'M196,35.52C177.62,25.51,153.48,20,128,20S78.38,25.51,60,35.52C39.37,46.79,28,62.58,28,80v96c0,17.42,11.37,33.21,32,44.48,18.35,10,42.49,15.52,68,15.52s49.62-5.51,68-15.52c20.66-11.27,32-27.06,32-44.48V80C228,62.58,216.63,46.79,196,35.52ZM204,128c0,17-31.21,36-76,36s-76-19-76-36v-8.46a88.9,88.9,0,0,0,8,4.94c18.35,10,42.49,15.52,68,15.52s49.62-5.51,68-15.52a88.9,88.9,0,0,0,8-4.94ZM128,44c44.79,0,76,19,76,36s-31.21,36-76,36S52,97,52,80,83.21,44,128,44Zm0,168c-44.79,0-76-19-76-36v-8.46a88.9,88.9,0,0,0,8,4.94c18.35,10,42.49,15.52,68,15.52s49.62-5.51,68-15.52a88.9,88.9,0,0,0,8-4.94V176C204,193,172.79,212,128,212Z',
  pricingPro:
    'M227.85,46.89a20,20,0,0,0-18.74-18.74c-13.13-.77-46.65.42-74.48,28.24L131,60H74.36a19.83,19.83,0,0,0-14.14,5.86L25.87,100.19a20,20,0,0,0,11.35,33.95l37.14,5.18,42.32,42.32,5.19,37.18A19.88,19.88,0,0,0,135.34,235a20.13,20.13,0,0,0,6.37,1,19.9,19.9,0,0,0,14.1-5.87l34.34-34.35A19.85,19.85,0,0,0,196,181.64V125l3.6-3.59C227.43,93.54,228.62,60,227.85,46.89ZM76,84h31L75.75,115.28l-27.23-3.8ZM151.6,73.37A72.27,72.27,0,0,1,204,52a72.17,72.17,0,0,1-21.38,52.41L128,159,97,128ZM172,180l-27.49,27.49-3.8-27.23L172,149Zm-72,22c-8.71,11.85-26.19,26-60,26a12,12,0,0,1-12-12c0-33.84,14.12-51.32,26-60A12,12,0,1,1,68.18,175.3C62.3,179.63,55.51,187.8,53,203c15.21-2.51,23.37-9.3,27.7-15.18A12,12,0,1,1,100,202Z',
  appsPlatforms:
    'M100,36H56A20,20,0,0,0,36,56v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V56A20,20,0,0,0,100,36ZM96,96H60V60H96ZM200,36H156a20,20,0,0,0-20,20v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V56A20,20,0,0,0,200,36Zm-4,60H160V60h36Zm-96,40H56a20,20,0,0,0-20,20v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V156A20,20,0,0,0,100,136Zm-4,60H60V160H96Zm104-60H156a20,20,0,0,0-20,20v44a20,20,0,0,0,20,20h44a20,20,0,0,0,20-20V156A20,20,0,0,0,200,136Zm-4,60H160V160h36Z',
};

function topicIcon(key: FaqGroupKey, size = 15): string {
  const d = TOPIC_ICON[key];
  if (!d) return '';
  return `<svg width="${size}" height="${size}" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="${d}"/></svg>`;
}

/**
 * Guides drawn with a phosphor glyph instead of an app logo, keyed by guide
 * id. A guide about one app gets that app's icon from public/help/icons/;
 * a guide about a whole category has no logo that would be honest, so it
 * borrows the glyph the app itself uses. `GUIDE_META` marks these by
 * omitting `icon` - keep the two in step.
 */
const GUIDE_GLYPH: Record<string, string> = {
  'browser-passwords': KEY_BOLD,
};

/** Inline glyph for a guide with no logo asset, or '' when it has one. */
function guideGlyph(id: string, size: number): string {
  const d = GUIDE_GLYPH[id];
  if (!d) return '';
  return `<svg width="${size}" height="${size}" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="${d}"/></svg>`;
}

const ICONS_DIR = path.resolve(__dirname, 'public/help/icons');

/**
 * App icon for a guide, if an asset exists in public/help/icons/ (SVG
 * preferred, .webp fallback for the raster ones). Returns the public URL.
 */
function guideIconHref(id: string): string | null {
  for (const ext of ['svg', 'webp', 'png']) {
    if (fs.existsSync(path.join(ICONS_DIR, `${id}.${ext}`))) return `/help/icons/${id}.${ext}`;
  }
  return null;
}

const CARET_ICON =
  '<svg class="lm-caret" width="12" height="12" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
const CHECK_ICON =
  '<svg width="13" height="13" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';
const SYSTEM_ICON =
  '<svg width="26" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true" style="padding:2px 6px"><path d="m5 8 6 6"/><path d="m4 14 6-6 2-3"/><path d="M2 5h12"/><path d="M7 2h1"/><path d="m22 22-5-10-5 10"/><path d="M14 18h6"/></svg>';

function flagSvg(code: string): string {
  return renderToStaticMarkup(createElement(Flag, { code }));
}

/**
 * Language switcher mirroring the homepage LanguageMenu (flag + endonym +
 * caret pill, dropdown with a System row, flags, and a check on the
 * current choice). Same data sources (languageData.tsx, localeRoutes.ts)
 * rendered to static HTML; static-pages.js adds outside-click close,
 * persists choices under the app's own language keys, and swaps to the
 * matching page in the picked language.
 *
 * Rendered twice per page - header rail and footer (helpFooter below) -
 * the way the homepage carries LanguageMenu in the nav and again at the
 * end of SiteFooter. `id` distinguishes the two instances; static-pages.js
 * wires every `.langmenu` on the page, so both persist and navigate
 * identically. Placement styling is CHROME_CSS's job, not this function's.
 */
function languageMenu(
  current: HelpLocale,
  label: string,
  pathOf: (l: HelpLocale) => string,
  id = 'lang-menu'
): string {
  const rows = (sortByNative(HELP_LOCALES) as HelpLocale[]).map((l) => {
    const on = l === current;
    return `<a${on ? ' class="on"' : ''} href="${pathOf(l)}" hreflang="${l}" data-lang="${l}">${flagSvg(l)}<span>${esc(LANGUAGE_META[l].native)}</span>${on ? CHECK_ICON : ''}</a>`;
  }).join('\n');
  const locales: Record<string, string> = {};
  for (const l of HELP_LOCALES) locales[l] = localePrefix(l);
  return `<details class="langmenu" id="${id}" data-locales="${esc(JSON.stringify(locales))}">
<summary aria-label="${esc(label)}">${flagSvg(current)}<span class="lm-name">${esc(LANGUAGE_META[current].native)}</span>${CARET_ICON}</summary>
<div class="langlist">
<a href="/help" data-lang="system">${SYSTEM_ICON}<span>System</span></a>
${rows}
</div>
</details>`;
}

/**
 * The footer every Help page ends on: the shared chrome footer plus the
 * SAME language menu the top bar renders, in the slot the homepage footer
 * puts it. `pathOf` is the caller's own page-shape mapper (hub, leaf, or
 * guide), so picking a language from the footer lands on the translated
 * version of the page you were reading, not the hub.
 */
function helpFooter(
  locale: HelpLocale,
  label: string,
  pathOf: (l: HelpLocale) => string
): string {
  return siteFooterFor(
    helpPath(locale),
    LOCALE_TO_SLUG[locale],
    languageMenu(locale, label, pathOf, 'lang-menu-footer')
  );
}

const SEARCH_ICON =
  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="8"/><path d="m21 21-4.3-4.3"/></svg>';

const CLEAR_ICON =
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><path d="M18 6 6 18M6 6l12 12"/></svg>';

const RAIL_HOME_ICON =
  '<svg width="15" height="15" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M224,128a8,8,0,0,1-8,8H40a8,8,0,0,1,0-16H216A8,8,0,0,1,224,128ZM40,72H216a8,8,0,0,0,0-16H40a8,8,0,0,0,0,16ZM216,184H40a8,8,0,0,0,0,16H216a8,8,0,0,0,0-16Z"/></svg>';

/** Shared <head> boilerplate for every Help page. */
function headCommon(
  title: string,
  description: string,
  canonical: string,
  alternates: string,
  locale: HelpLocale
): string {
  return `<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)}</title>
<meta name="description" content="${esc(description)}">
<link rel="canonical" href="${canonical}">
${alternates}
<meta property="og:title" content="${esc(title)}">
<meta property="og:description" content="${esc(description)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${canonical}">
<meta property="og:site_name" content="PrivacyNotes">
${ogLocaleTag(locale)}
${OG_IMAGE_TAGS}
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
${THEME_SCRIPT_TAG}
<script src="/static-pages.js" defer></script>`;
}

const PAGE_VARS = themeVarsCss(
  '--bg:#fff;--fg:#15171a;--muted:#5b6168;--faint:#8a9099;--line:#e7e9ec;--accent:#1E40AF;--imp-bg:#eff6ff;--mark-fg:#1E40AF;--chip:#eceef1;--rail:#f2f3f5;--on-accent:#fff;--ok:#3b6d11;--ok-bg:#f1f7e8;--ok-line:#d3e3bc',
  '--bg:#0e1014;--fg:#e7e9ec;--muted:#9aa1aa;--faint:#6b7178;--line:#23262c;--accent:#4A90D9;--imp-bg:#11233a;--mark-fg:#7FB0E4;--chip:#3a4149;--rail:#191d23;--on-accent:#03203E;--ok:#a7cf6f;--ok-bg:#161d0e;--ok-line:#2e3d1d'
);

/** Styles shared by hub, leaves, and guides. */
const HELP_SHARED_CSS = `
.entry{border-top:1px solid var(--line)}
.eyebrow + .entry{border-top:0}
.entry[hidden]{display:none}
summary{display:flex;align-items:center;gap:12px;padding:18px 0;cursor:pointer;list-style:none}
summary::-webkit-details-marker{display:none}
summary .q{flex:1;font-size:16px;font-weight:600;letter-spacing:-.01em}
summary:hover .q{color:var(--accent)}
.perma{flex:0 0 auto;display:inline-flex;align-items:center;color:var(--faint);text-decoration:none;opacity:0;transition:opacity .12s ease;padding:0 2px}
.perma:focus-visible{opacity:1}
summary:hover .perma{opacity:1}
.perma:hover{color:var(--accent);text-decoration:none}
.chev{flex:0 0 auto;width:10px;height:10px;border-right:2px solid var(--faint);border-bottom:2px solid var(--faint);transform:rotate(45deg);transition:transform .15s ease;margin-top:-4px}
details[open] .chev{transform:rotate(-135deg);margin-top:4px}
.a{padding:0 0 22px}
.a p{margin:0 0 12px;font-size:15px;color:var(--muted)}\n.cbx{display:flex;flex-wrap:wrap;align-items:center;gap:9px 10px;margin:0 0 12px;padding:9px 10px 9px 13px;border:1px solid var(--line);border-radius:9px;background:var(--rail)}\n.cbx code{flex:1 1 210px;min-width:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.5;color:var(--fg);word-break:break-all}\n.cbx .btn-ok{flex:none;margin-inline-start:auto}\n.lst{margin:0 0 14px;padding-inline-start:19px;list-style:disc}\n.lst li{margin:0 0 7px;font-size:15px;color:var(--muted);line-height:1.65}\n.lst strong{color:var(--fg)}\n.lst code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--fg);word-break:break-all;direction:ltr;unicode-bidi:isolate}\n.bdg{display:block;width:max-content;max-width:100%;margin:0 0 14px;transition:opacity .15s ease}\n.bdg:hover{opacity:.82}\n.bdg img{display:block;height:48px;width:auto}
.a p:last-child{margin-bottom:0}
.copybtn{display:inline-flex;align-items:center;gap:6px;font-size:12px;color:var(--faint);background:none;border:0;cursor:pointer;padding:0;margin-top:2px;font-family:inherit}
.copybtn:hover{color:var(--accent)}
.copybtn svg{flex:0 0 auto}
/* .langmenu / .langlist moved to CHROME_CSS (static-page-chrome.ts): the
   footer renders one too, and the footer is that module's. Only the
   suggest banner below is Help-specific. */
.lang-banner{display:flex;align-items:center;gap:6px;width:max-content;max-width:100%;margin:0 0 14px;padding:5px 6px 5px 12px;border:1px solid var(--line);border-radius:99px;background:var(--imp-bg)}
.lang-banner a{display:inline-flex;align-items:center;gap:8px;font-size:13.5px;font-weight:600;color:var(--accent);text-decoration:none}
.lang-banner a svg{width:20px;height:14px;border-radius:2px}
.lang-banner button{border:0;background:none;cursor:pointer;color:var(--faint);font-size:14px;line-height:1;padding:5px 7px;border-radius:99px}
.lang-banner button:hover{color:var(--fg)}
/* flow-root + a FLOATED tile, not a flex row: as a flex item the tile reserved
   its column for the whole head, so on a phone every line of the lead wrapped
   short against an icon that had ended several lines earlier. Floated, the
   text runs full width the moment it clears the tile. flow-root contains the
   float, so a tile taller than its text still cannot ride over the pill below.
   The tile is emitted BEFORE .head-txt in the markup because a float only
   wraps the content that follows it. */
.head-row{display:flow-root}
.head-txt{min-width:0}
/* float:right plus a dir=rtl mirror, rather than the logical float:inline-end:
   that value is recent enough that a browser which ignores it drops the float
   altogether, and the pair below costs one line.
   Spec: ops/docs/ui-patterns.md (section 67, icon mirroring) */
.app-tile{float:right;margin-inline-start:24px;margin-block-end:12px;width:96px;height:96px;background:var(--chip);border-radius:22px;display:flex;align-items:center;justify-content:center}
[dir=rtl] .app-tile{float:left}
.app-tile img{width:72px;height:72px;object-fit:contain}
.feedback{margin:22px 0 0}
.feedback p{margin:0 0 10px;color:var(--muted);font-size:14px}
.ask{margin:30px 0 0;padding:18px 20px;border:1px solid var(--ok-line);background:var(--ok-bg);border-radius:12px}
.ask-head{display:flex;gap:13px;align-items:flex-start}
.ask-ico{flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;width:32px;height:32px;border-radius:9px;background:var(--ok);color:var(--ok-bg)}
.ask h2{margin:0 0 4px;font-size:15.5px;font-weight:700;color:var(--ok);letter-spacing:-.01em}
.ask-head p{margin:0;color:var(--muted);font-size:14px;line-height:1.6}
.ask-steps{margin:15px 0 0;padding:0;list-style:none;counter-reset:askstep}
.ask-steps li{counter-increment:askstep;position:relative;padding-inline-start:31px;margin:0 0 8px;font-size:14px;line-height:1.5;color:var(--fg)}
.ask-steps li:last-child{margin-bottom:0}
.ask-steps li::before{content:counter(askstep);position:absolute;inset-inline-start:0;top:0;width:20px;height:20px;border-radius:99px;background:var(--ok);color:var(--ok-bg);font-size:11.5px;font-weight:700;display:flex;align-items:center;justify-content:center}
.ask-more{margin:16px 0 0}
.ask-more summary{display:inline-flex;align-items:center;gap:10px;cursor:pointer;list-style:none}
.ask-more summary::-webkit-details-marker{display:none}
.sum-lbl{display:inline-flex;align-items:center;gap:8px;padding:0 14px;height:32px;border:1px solid var(--ok);border-radius:8px;font-size:13px;font-weight:600;color:var(--ok)}
.sum-lbl:hover{background:var(--bg)}
.sum-lbl::after{content:'';width:6px;height:6px;border-right:2px solid currentColor;border-bottom:2px solid currentColor;transform:rotate(45deg);margin-block-start:-4px}
/* The chevrons here use PHYSICAL borders while every other rule in this block is logical, on purpose: a down-pointing arrow means the same thing in both directions, and border-inline-end turns it sideways under dir=rtl. Spec: ops/docs/ui-patterns.md (section 67, icon mirroring) */
.ask-more[open] .sum-lbl::after{transform:rotate(-135deg);margin-block-start:2px}
.ask-act{margin:13px 0 0}
/* One rule for both copy buttons, the compact one on the summary row and the
   long one under the prompt. Matching the 32px height to .sum-lbl is what
   makes the pair read as one control rather than two stacked things. */
.btn-ok{display:inline-flex;align-items:center;gap:7px;height:32px;padding:0 14px;border:0;border-radius:8px;background:var(--ok);color:var(--ok-bg);font-family:inherit;font-size:13px;font-weight:600;line-height:1;white-space:nowrap;cursor:pointer;transition:filter .13s ease,transform .13s ease}
.btn-ok:hover{filter:brightness(1.09)}
.btn-ok:active{transform:scale(.95)}
.btn-ok .ic{display:inline-flex}
.btn-ok .ic-done{display:none}
.btn-ok.on{animation:ask-pop .34s ease}
.btn-ok.on .ic-copy{display:none}
.btn-ok.on .ic-done{display:inline-flex}
@keyframes ask-pop{0%{transform:scale(1)}35%{transform:scale(1.09)}70%{transform:scale(.98)}100%{transform:scale(1)}}
@media (prefers-reduced-motion:reduce){.btn-ok{transition:none}.btn-ok.on{animation:none}.btn-ok:active{transform:none}}
.ask pre{margin:13px 0 0;padding:13px 15px;max-height:480px;overflow-y:auto;border:1px solid var(--ok-line);border-radius:9px;background:var(--bg);color:var(--fg);font-size:12.5px;line-height:1.55;white-space:pre-wrap;overflow-x:auto}
/* display:flex + width:fit-content, NOT inline-flex: an inline-level box has its vertical margins ignored for line-box height, so margin-block-end here did nothing and the gap below the pill was whatever the grid happened to give - which differs between the wide layout and the reordered narrow one. Block-level shrink-wrap keeps the pill hugging its text and makes both margins real. */
.askmini{display:flex;width:fit-content;align-items:center;gap:8px;margin:18px 0 22px;padding:7px 14px;border:1px solid var(--ok-line);background:var(--ok-bg);border-radius:99px;font-size:13px;font-weight:600;color:var(--ok);text-decoration:none}
.askmini:hover{text-decoration:none;border-color:var(--ok)}
.askmini-arr{width:6px;height:6px;border-right:2px solid currentColor;border-bottom:2px solid currentColor;transform:rotate(45deg);margin-block-start:-4px}
.ask .askwarn{display:flex;gap:9px;align-items:flex-start;margin:17px 0 0;padding-block-start:14px;border-block-start:1px solid var(--ok-line);font-size:13px;font-weight:600;line-height:1.5;color:var(--fg)}
.ask .askwarn svg{flex:0 0 auto;color:var(--ok);margin-block-start:1px}
.fb-links{display:flex;gap:8px;flex-wrap:wrap}
/* The page shell (.wrap width, .pcols grid, .rail-col, .ritem, .search,
   .count, mark) lives in CHROME_CSS - every static page uses it now, not
   just Help. Only the Help-specific pieces are below. */
.crumb{grid-area:crumb;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;font-weight:600;letter-spacing:.14em;text-transform:uppercase;color:var(--faint);margin:4px 0 14px}
.crumb a{color:var(--accent);text-decoration:none}
.crumb a:hover{text-decoration:underline}
.crumb .sep{margin:0 7px;color:var(--faint)}
.sresults{display:flex;flex-direction:column;gap:2px;margin:10px 0 0}
.sresults[hidden]{display:none}
.sr-item{padding:9px 12px;border-radius:9px;font-size:14.5px;line-height:1.4;color:var(--muted);text-decoration:none}
.sr-item:hover,.sr-item.on{background:var(--imp-bg);color:var(--accent);text-decoration:none}
.sr-all{color:var(--accent);font-weight:600}
.leaf-hub{margin-top:38px;padding-top:26px;border-top:1px solid var(--line)}
.lh-title{margin:0 0 6px;font-size:20px;font-weight:800;letter-spacing:-.02em;color:var(--fg)}
.leaf-hub .sub{margin:0;font-size:14px;color:var(--muted)}
.leaf-hub .search{margin-top:14px}
/* The generic single-column collapse (and the rail-row-to-pill switch) is
   in CHROME_CSS; these are the per-view area maps only. */
@media(max-width:860px){
/* Hub: topics + guides stay one block between the head and the FAQ list.
   The un-sticking and the separator are in CHROME_CSS now - every page's
   rail needs them, not just this one. */
body[data-static-page="help"] .rail-guides{margin-top:12px}
/* Leaf & guide: topics under the breadcrumb, guides below the article. */
body[data-static-page="help-leaf"] .pcols,
body[data-static-page="help-guide"] .pcols{grid-template-areas:'crumb' 'topics' 'head' 'body' 'guides'}
body[data-static-page="help-leaf"] .rail-col,
body[data-static-page="help-guide"] .rail-col{display:contents}
.rail-topics{grid-area:topics}
.rail-guides{grid-area:guides}
body[data-static-page="help-leaf"] .rail-topics,
body[data-static-page="help-guide"] .rail-topics{margin:0;padding-bottom:18px;border-bottom:1px solid var(--line)}
body[data-static-page="help-leaf"] .col-head,
body[data-static-page="help-guide"] .col-head{margin:26px 0 20px}
body[data-static-page="help-leaf"] .rail-guides,
body[data-static-page="help-guide"] .rail-guides{margin-top:28px;padding-top:20px;border-top:1px solid var(--line)}
.app-tile{width:72px;height:72px;border-radius:18px}
.app-tile img{width:54px;height:54px}
}`;

// ---------------------------------------------------------------------------
// Leaf showcases. Two FAQ leaves get a rendered demo section beneath their
// answer: /help/markdown-syntax (live "markdown in, formatting out" cards)
// and /help/keyboard-shortcuts (the hotkey list as keycaps, sourced from
// src/hotkeysData.ts so the page can never drift from the in-app modal).
// Pure static HTML/CSS - no scripts, themed via the shared CSS variables.
// ---------------------------------------------------------------------------

const MD_SHOWCASE_CSS = `
.md-sec{margin-top:30px}
.md-sec>.eyebrow{margin:0 0 10px}
.md-cap{margin:16px 0 6px;font-size:11.5px;font-weight:600;letter-spacing:.06em;text-transform:uppercase;color:var(--faint)}
.md-sec>.eyebrow+.md-cap{margin-top:0}
.md-demo{display:grid;grid-template-columns:minmax(0,5fr) minmax(0,6fr);border:1px solid var(--line);border-radius:12px;overflow:hidden;margin:0 0 12px}
.md-src{background:var(--chip);padding:14px 16px;display:flex;align-items:center}
.md-src pre{margin:0;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.8;color:var(--muted);white-space:pre-wrap;word-break:break-word}
.md-out{padding:14px 18px;min-width:0;border-left:1px solid var(--line)}
.md-out>:first-child{margin-top:0}.md-out>:last-child{margin-bottom:0}
.d-h1{font-size:21px;font-weight:800;letter-spacing:-.02em;color:var(--fg);margin:0 0 4px}
.d-h2{font-size:17px;font-weight:700;letter-spacing:-.01em;color:var(--fg);margin:0 0 4px}
.d-h3{font-size:14.5px;font-weight:700;color:var(--fg);margin:0}
.d-p{margin:0 0 6px;font-size:14.5px;color:var(--fg);line-height:1.7}
.d-list{margin:0;padding-left:20px;font-size:14.5px;color:var(--fg);line-height:1.8}
.d-list ul{margin:0;padding-left:18px;list-style:disc}
.d-hr{border:0;border-top:1px solid var(--line);margin:10px 0}
.d-code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;background:var(--chip);border-radius:5px;padding:1px 5px}
.d-mark{background:var(--imp-bg);color:var(--mark-fg);border-radius:3px;padding:0 2px}
.d-task{display:flex;align-items:center;gap:9px;margin:4px 0;font-size:14.5px;color:var(--fg)}
.d-box{flex:0 0 auto;width:16px;height:16px;border:1.5px solid var(--faint);border-radius:4px;display:inline-flex;align-items:center;justify-content:center}
.d-box.on{background:var(--accent);border-color:var(--accent);color:#fff}
.d-quote{border-left:3px solid var(--accent);padding:2px 0 2px 12px;margin:0;font-size:14.5px;font-style:italic;color:var(--muted)}
.d-call{display:flex;gap:10px;padding:11px 13px;border-radius:10px;border:1px solid;font-size:13.5px;margin:0 0 8px}
.d-call:last-child{margin-bottom:0}
.d-call svg{flex:0 0 auto;margin-top:1px}
.d-call strong{display:block;font-size:13.5px;margin:0 0 2px;color:var(--fg)}
.d-call p{margin:0;color:var(--muted)}
.d-info{background:rgba(59,130,246,.09);border-color:rgba(59,130,246,.35)}
.d-info svg,.d-info strong{color:#3b82f6}
.d-warn{background:rgba(217,119,6,.09);border-color:rgba(217,119,6,.35)}
.d-warn svg,.d-warn strong{color:#d97706}
.d-table{border-collapse:collapse;width:100%;font-size:13.5px;color:var(--fg)}
.d-table th,.d-table td{border:1px solid var(--line);padding:7px 10px;text-align:left}
.d-table th{background:var(--chip);font-weight:600}
.d-cb{background:#0e1014;border:1px solid var(--line);border-radius:10px;padding:12px 14px;margin:0}
.d-cb code{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:1.7;color:#e7e9ec;white-space:pre-wrap}
.t-k{color:#c678dd}.t-f{color:#61afef}.t-c{color:#7f848e}
.d-math{margin:0;font-family:Georgia,'Times New Roman',serif;font-style:italic;font-size:16.5px;color:var(--fg)}
.d-nl{color:var(--accent);font-weight:600;border-bottom:1px dashed var(--accent);cursor:pointer}
@media(max-width:700px){.md-demo{grid-template-columns:minmax(0,1fr)}.md-out{border-left:0;border-top:1px solid var(--line)}}`;

const HK_SHOWCASE_CSS = `
.hk-sec{margin-top:26px}
.hk-sec>.eyebrow{margin:0 0 2px}
.hk-groups{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:2px 36px}
.hk-g .eyebrow{margin:18px 0 2px}
.hk-row{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:9px 0;border-top:1px solid var(--line);font-size:14px;color:var(--muted)}
.hk-g .eyebrow+.hk-row{border-top:0}
/* direction:ltr - key sequences are forced-LTR islands under RTL (same fix
   as .s-keys on the cheat sheet; "1 – ⌥⌘6" used to reorder on /ar). */
.hk-keys{display:inline-flex;align-items:center;gap:4px;flex:0 0 auto;direction:ltr}
.hk-or{color:var(--faint);font-size:12px;padding:0 1px}
kbd.cap{display:inline-flex;min-width:26px;height:26px;padding:0 7px;align-items:center;justify-content:center;border:1px solid var(--line);border-bottom-width:2.5px;border-radius:7px;background:var(--chip);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;font-weight:600;color:var(--fg)}
.hk-note{margin:18px 0 0;font-size:13px;color:var(--faint)}
.hk-note+.hk-note{margin-top:6px}
.hk-print{display:flex;width:fit-content;align-items:center;gap:8px;margin:18px 0 0;padding:7px 14px;border:1px solid var(--line);border-radius:99px;font-size:13px;font-weight:600;color:var(--accent);text-decoration:none}
.hk-print:hover{border-color:var(--accent);text-decoration:none}
.hk-print svg{flex:0 0 auto}
@media(max-width:700px){.hk-groups{grid-template-columns:minmax(0,1fr)}.hk-g .eyebrow{margin-top:14px}}`;

// Phosphor "printer" (bold), inlined like the sidebar's topic icons.
const PRINTER_ICON =
  '<svg width="15" height="15" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M214.67,68H204V40a12,12,0,0,0-12-12H64A12,12,0,0,0,52,40V68H41.33C25.16,68,12,80.56,12,96v80a12,12,0,0,0,12,12H52v28a12,12,0,0,0,12,12H192a12,12,0,0,0,12-12V188h28a12,12,0,0,0,12-12V96C244,80.56,230.84,68,214.67,68ZM76,52H180V68H76ZM180,204H76V172H180Zm40-40H204v-4a12,12,0,0,0-12-12H64a12,12,0,0,0-12,12v4H36V96c0-2.17,2.44-4,5.33-4H214.67c2.89,0,5.33,1.83,5.33,4Zm-16-44a16,16,0,1,1-16-16A16,16,0,0,1,204,120Z"/></svg>';

const CALL_INFO_ICON =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" aria-hidden="true"><circle cx="12" cy="12" r="9"/><path d="M12 11v5"/><path d="M12 8h.01"/></svg>';
const CALL_WARN_ICON =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m21.7 18-8-14a2 2 0 0 0-3.5 0l-8 14A2 2 0 0 0 4 21h16a2 2 0 0 0 1.7-3"/><path d="M12 9v4"/><path d="M12 17h.01"/></svg>';
const TASK_CHECK_ICON =
  '<svg width="10" height="10" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="3.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M20 6 9 17l-5-5"/></svg>';

/** One captioned "markdown in, result out" card. `src` arrives pre-escaped. */
function mdDemo(cap: string, src: string, out: string): string {
  return `<p class="md-cap">${esc(cap)}</p>
<div class="md-demo"><div class="md-src"><pre>${src}</pre></div><div class="md-out">${out}</div></div>`;
}

function renderMarkdownShowcase(label: string, p: Record<string, string>): string {
  const demos = [
    mdDemo(
      p.mdDemoHeadings ?? 'Headings',
      '# Planning\n## This week\n### Monday',
      '<p class="d-h1">Planning</p><p class="d-h2">This week</p><p class="d-h3">Monday</p>'
    ),
    mdDemo(
      p.mdDemoInline ?? 'Inline formatting',
      '**bold**, *italic*, ~~done~~,\n==marked== and \`inline code\`',
      '<p class="d-p"><strong>bold</strong>, <em>italic</em>, <s>done</s>, <span class="d-mark">marked</span> and <code class="d-code">inline code</code></p>'
    ),
    mdDemo(
      p.mdDemoTasks ?? 'Task list',
      '- [x] Derive keys on the device\n- [ ] Trust a server',
      `<div class="d-task"><span class="d-box on">${TASK_CHECK_ICON}</span>Derive keys on the device</div><div class="d-task"><span class="d-box"></span>Trust a server</div>`
    ),
    mdDemo(
      p.mdDemoLists ?? 'Nested lists',
      '1. Write your phrase down\n2. Store it offline\n   - paper beats cloud\n   - two copies, two places',
      '<ol class="d-list"><li>Write your phrase down</li><li>Store it offline<ul><li>paper beats cloud</li><li>two copies, two places</li></ul></li></ol>'
    ),
    mdDemo(
      p.mdDemoCallouts ?? 'Callouts',
      '&gt; [!info] Zero-knowledge\n&gt; The server stores only ciphertext.\n\n&gt; [!warning] No resets\n&gt; A lost phrase cannot be recovered.',
      `<div class="d-call d-info">${CALL_INFO_ICON}<div><strong>Zero-knowledge</strong><p>The server stores only ciphertext.</p></div></div><div class="d-call d-warn">${CALL_WARN_ICON}<div><strong>No resets</strong><p>A lost phrase cannot be recovered.</p></div></div>`
    ),
    mdDemo(
      p.mdDemoTable ?? 'Table',
      '| App | Can read your notes |\n| --- | --- |\n| PrivacyNotes | No |\n| Typical cloud notes | Yes |',
      '<table class="d-table"><thead><tr><th>App</th><th>Can read your notes</th></tr></thead><tbody><tr><td>PrivacyNotes</td><td>No</td></tr><tr><td>Typical cloud notes</td><td>Yes</td></tr></tbody></table>'
    ),
    mdDemo(
      p.mdDemoCode ?? 'Code block',
      '\`\`\`js\n// encrypted before it leaves\nconst keys = deriveKeys(phrase);\n\`\`\`',
      '<pre class="d-cb"><code><span class="t-c">// encrypted before it leaves</span>\n<span class="t-k">const</span> keys = <span class="t-f">deriveKeys</span>(phrase);</code></pre>'
    ),
    mdDemo(
      p.mdDemoScripts ?? 'Superscript, subscript, underline',
      'H&lt;sub&gt;2&lt;/sub&gt;O and E = mc&lt;sup&gt;2&lt;/sup&gt;,\n&lt;u&gt;underline&lt;/u&gt; included',
      '<p class="d-p">H<sub>2</sub>O and E = mc<sup>2</sup>, <u>underline</u> included</p>'
    ),
    mdDemo(
      p.mdDemoMath ?? 'Math (KaTeX)',
      '$e^{i\\pi} + 1 = 0$',
      '<p class="d-math">e<sup>i&pi;</sup> + 1 = 0</p>'
    ),
    mdDemo(
      p.mdDemoQuote ?? 'Quote and note-link',
      '&gt; Privacy is a feature, not a setting.\n\nIdeas live in [[Second brain]]',
      '<blockquote class="d-quote">Privacy is a feature, not a setting.</blockquote><p class="d-p" style="margin-top:8px">Ideas live in <span class="d-nl">Second brain</span></p>'
    ),
    mdDemo(
      p.mdDemoDivider ?? 'Divider',
      'Quick capture\n\n---\n\nPolished later',
      '<p class="d-p">Quick capture</p><hr class="d-hr"><p class="d-p">Polished later</p>'
    ),
  ];
  return `<section class="md-sec">
<h2 class="eyebrow">// ${esc(label)}</h2>
${demos.join('\n')}
</section>`;
}

/** '⌘K' -> ['⌘','K']; 'J / K' -> ['J','/','K']; 'Esc' stays whole.
 *  ' – ' splits a range ('⌥⌘1 – ⌥⌘6') into two full cap sequences, so the
 *  second one never lumps into one unreadable cap. */
function keyCaps(keys: string): string[] {
  if (keys.includes(' / '))
    return keys.split(' / ').flatMap((part, i) => (i ? ['/', ...keyCaps(part)] : keyCaps(part)));
  if (keys.includes(' – '))
    return keys.split(' – ').flatMap((part, i) => (i ? ['–', ...keyCaps(part)] : keyCaps(part)));
  const caps: string[] = [];
  let rest = keys;
  while (rest.length > 0) {
    const c = rest[0]!;
    if ('⌘⌥⇧⌫'.includes(c)) {
      caps.push(c);
      rest = rest.slice(1);
    } else {
      caps.push(rest);
      break;
    }
  }
  return caps;
}

/** hotkeys.* strings from common.json, per-key English fallback. */
function readHotkeyStrings(locale: HelpLocale): {
  groups: Record<string, string>;
  actions: Record<string, string>;
  typingNote: string;
  cheatSheet: string;
} {
  type HotkeyStrings = {
    groups?: Record<string, string>;
    actions?: Record<string, string>;
    typingNote?: string;
    cheatSheet?: string;
  };
  const read = (l: string): HotkeyStrings => {
    try {
      return (
        (JSON.parse(fs.readFileSync(path.join(LOCALES_DIR, l, 'common.json'), 'utf8')) as {
          hotkeys?: HotkeyStrings;
        }).hotkeys ?? {}
      );
    } catch {
      return {};
    }
  };
  const en = read('en');
  const loc = locale === 'en' ? en : read(locale);
  return {
    groups: { ...(en.groups ?? {}), ...(loc.groups ?? {}) },
    actions: { ...(en.actions ?? {}), ...(loc.actions ?? {}) },
    typingNote: loc.typingNote ?? en.typingNote ?? '',
    cheatSheet: loc.cheatSheet ?? en.cheatSheet ?? 'Printable cheat sheet',
  };
}

function renderHotkeysShowcase(
  locale: HelpLocale,
  hotkeyGroups: HotkeyGroupData[],
  label: string,
  legend: string
): string {
  const s = readHotkeyStrings(locale);
  const groups = hotkeyGroups
    .map((g) => {
      const rows = g.rows
        .map((r) => {
          const caps = keyCaps(r.keys)
            .map((c) => (c === '/' || c === '–' ? `<span class="hk-or">${c}</span>` : `<kbd class="cap">${esc(c)}</kbd>`))
            .join('');
          return `<div class="hk-row"><span>${esc(s.actions[r.i18nKey] ?? r.label)}</span><span class="hk-keys">${caps}</span></div>`;
        })
        .join('\n');
      return `<div class="hk-g">
<p class="eyebrow">// ${esc(s.groups[g.i18nKey] ?? g.title)}</p>
${rows}
</div>`;
    })
    .join('\n');
  return `<section class="hk-sec">
<h2 class="eyebrow">// ${esc(label)}</h2>
<div class="hk-groups">
${groups}
</div>
<p class="hk-note">${esc(legend)}</p>
${s.typingNote ? `<p class="hk-note">${esc(s.typingNote)}</p>` : ''}
<a class="hk-print" href="${cheatSheetPath()}">${PRINTER_ICON}${esc(s.cheatSheet)}</a>
</section>`;
}

/**
 * The printable cheat sheet page (see cheatSheetPath). A standalone page,
 * NOT on the docs shell: on screen it shows the sheet as a paper card under
 * a slim toolbar with a Print button (static-pages.js, initCheatSheet); in
 * print it is the sheet alone, one A4 page, two columns. The sheet itself
 * is always paper-white in both themes, so what you see is what prints.
 * Sourced from src/hotkeysData.ts like the modal and the FAQ leaf, so the
 * three can never drift. Links come here from the About modal's Hotkeys
 * tab, the site footer, and the keyboard-shortcuts leaf's showcase.
 */
function renderCheatSheetHtml(hotkeyGroups: HotkeyGroupData[]): string {
  // English-only page: its chrome strings live here, not in the catalogs
  // (the roadmap/brand pattern - a string in en/faq.json would oblige 16
  // translations of a page that only exists in English).
  const title = 'Keyboard shortcuts cheat sheet';
  const desc = 'Every PrivacyNotes keyboard shortcut on one printable A4 page.';
  const printLabel = 'Print';
  const hint = 'Prints on one A4 page - or choose PDF in the print dialog to save it as a file.';
  const legend = 'On Windows and Linux, ⌘ is Ctrl and ⌥ is Alt.';
  const legendPc = 'On a Mac, Ctrl is ⌘ and Alt is ⌥.';
  // Groups and rows render the English source labels straight from
  // hotkeysData; only the typing note is shared with the app's catalog.
  const typingNote = readHotkeyStrings('en').typingNote;
  const renderGroup = (g: HotkeyGroupData) => {
    const rows = g.rows
      .map((r) => {
        const caps = keyCaps(r.keys)
          .map((c) => (c === '/' || c === '–' ? `<span class="s-or">${c}</span>` : `<kbd class="s-cap">${esc(c)}</kbd>`))
          .join('');
        // "Toggle this help" is the MODAL's self-reference; on paper there
        // is no "this help", so the sheet points back at the app instead.
        const label = r.i18nKey === 'toggleHelp' ? 'Show this list in the app' : r.label;
        return `<div class="s-row"><span class="s-lbl">${esc(label)}</span><span class="s-dots"></span><span class="s-keys">${caps}</span></div>`;
      })
      .join('\n');
    return `<section class="s-g">
<h2>// ${esc(g.title)}</h2>
${rows}
</section>`;
  };
  // Two explicit columns, balanced by row count (a group header weighs about
  // one row). CSS `columns` balanced by height alone and Formatting alone
  // outweighs the other five groups, so the first column came up far
  // shorter. Brute force over the assignments (2^n, n=6): the smallest
  // height difference wins, the first data group stays in the first column
  // (mask step 2 keeps bit 0 set), ties prefer the fuller first column, and
  // data order is kept inside each column.
  const weight = (g: HotkeyGroupData) => g.rows.length + 1;
  let bestMask = 1;
  let bestDiff = Infinity;
  let bestLeft = 0;
  for (let mask = 1; mask < 1 << hotkeyGroups.length; mask += 2) {
    let l = 0;
    let r = 0;
    hotkeyGroups.forEach((g, i) => (mask & (1 << i) ? (l += weight(g)) : (r += weight(g))));
    const diff = Math.abs(l - r);
    if (diff < bestDiff || (diff === bestDiff && l > bestLeft)) {
      bestDiff = diff;
      bestLeft = l;
      bestMask = mask;
    }
  }
  const col = (keep: boolean) =>
    hotkeyGroups
      .filter((_, i) => Boolean(bestMask & (1 << i)) === keep)
      .map(renderGroup)
      .join('\n');
  return `<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(title)} - PrivacyNotes</title>
<meta name="description" content="${esc(desc)}">
<link rel="canonical" href="${ORIGIN}${leafPath('en', 'keyboard-shortcuts')}">
<meta property="og:title" content="${esc(title)} - PrivacyNotes">
<meta property="og:description" content="${esc(desc)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${ORIGIN}${cheatSheetPath()}">
<meta property="og:site_name" content="PrivacyNotes">
${ogLocaleTag('en')}
${OG_IMAGE_TAGS}
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
${THEME_SCRIPT_TAG}
<script src="/static-pages.js" defer></script>
<style>
${themeVarsCss(
  '--bg:#f2f3f5;--fg:#15171a;--muted:#5b6168;--line:#e7e9ec;--accent:#1E40AF;--on-accent:#fff',
  '--bg:#0e1014;--fg:#e7e9ec;--muted:#9aa1aa;--line:#23262c;--accent:#4A90D9;--on-accent:#03203E'
)}
${BRAND_CSS}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.5}
.bar{position:sticky;top:0;z-index:2;display:flex;align-items:center;justify-content:space-between;gap:12px;padding:12px 20px;background:var(--bg);border-bottom:1px solid var(--line)}
.bar-brand{display:inline-flex;align-items:center;gap:9px;font-size:15px;color:var(--fg);text-decoration:none}
.bar-brand img{width:26px;height:26px}
.btn-print{display:inline-flex;align-items:center;gap:8px;height:36px;padding:0 16px;border:0;border-radius:9px;background:var(--accent);color:var(--on-accent);font-family:inherit;font-size:13.5px;font-weight:600;line-height:1;white-space:nowrap;cursor:pointer}
.btn-print:hover{filter:brightness(1.08)}
.btn-print svg{flex:0 0 auto}
.hint{max-width:210mm;margin:18px auto 0;padding:0 20px;font-size:13px;color:var(--muted);text-align:center}
/* The sheet is paper: fixed light colors in both themes, so the preview on
   screen is exactly what comes out of the printer. */
.sheet{width:210mm;max-width:100%;margin:18px auto 48px;background:#fff;color:#15171a;border:1px solid var(--line);border-radius:4px;box-shadow:0 12px 40px rgba(0,0,0,.14);padding:13mm 12mm}
.s-head{display:flex;align-items:center;justify-content:space-between;gap:16px;flex-wrap:wrap;border-bottom:2px solid #15171a;padding-bottom:13px}
.s-brand{display:inline-flex;align-items:center;gap:8px;font-size:16px;letter-spacing:-.01em}
.s-brand img{width:22px;height:22px}
.s-head h1{margin:0;font-size:15px;font-weight:700;color:#3d434a;letter-spacing:-.01em}
.s-meta{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10.5px;color:#8a9099}
/* minmax(0,1fr), never bare 1fr: the dot leaders are one long nowrap glyph
   run, and a bare 1fr track's auto minimum honors that intrinsic width,
   pushing the second column off the sheet. */
.s-cols{display:grid;grid-template-columns:minmax(0,1fr) minmax(0,1fr);column-gap:10mm;align-items:start;margin-top:26px}
.s-col{min-width:0}
.s-g{margin:0 0 26px}
.s-g h2{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10.5px;font-weight:700;letter-spacing:.14em;text-transform:uppercase;color:#1E40AF;margin:0 0 6px}
.s-row{display:flex;align-items:center;gap:9px;padding:6.5px 0;border-top:1px solid #e7e9ec;font-size:12px;color:#3d434a}
.s-g h2+.s-row{border-top:0}
.s-lbl{flex:0 1 auto}
/* Dot leader between label and keys: REAL TEXT (a clipped run of middots),
   not a gradient background. A gradient rasterizes in the macOS save-as-PDF
   path and came out as broken dashes; glyphs are vectors in every print
   engine. The row's align-items centers it. */
.s-dots{flex:1 1 0;min-width:14px;overflow:hidden;white-space:nowrap;color:#c9ced4;font-size:11px;line-height:1;letter-spacing:5px;text-align:center}
.s-dots::before{content:"································································································"}
/* direction:ltr - a key sequence is a forced-LTR island under RTL, so a
   combined cap like "1 – ⌥⌘6" cannot reorder. Spec: ops/docs/ui-patterns.md
   (section 67, forced-LTR islands) */
.s-keys{display:inline-flex;align-items:center;gap:3px;flex:0 0 auto;direction:ltr}
.s-or{color:#8a9099;font-size:10px;padding:0 1px}
kbd.s-cap{display:inline-flex;min-width:20px;height:20px;padding:0 5px;align-items:center;justify-content:center;border:1px solid #d5d9de;border-bottom-width:2px;border-radius:5px;background:#f5f6f8;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10.5px;font-weight:600;color:#15171a}
.s-foot{margin-top:6px;padding-top:14px;border-top:1px solid #e7e9ec}
.s-foot p{margin:0 0 6px;font-size:10.5px;color:#5b6168}
.s-foot p:last-child{margin-bottom:0}
/* Zero page margin on purpose: the browser prints its own header/footer
   (title, URL, date, page count) INSIDE the page margin, so a 0mm margin
   leaves them no room and Chrome/Safari drop them. The sheet keeps the
   optical margin as its own padding, well clear of printer hardware
   margins. */
@page{size:A4;margin:0}
@media print{
body{background:#fff}
.bar,.hint{display:none}
.sheet{width:auto;max-width:none;margin:0;border:0;border-radius:0;box-shadow:none;padding:12mm 13mm}
kbd.s-cap,.s-g h2,.sheet .pn-mark-a{-webkit-print-color-adjust:exact;print-color-adjust:exact}
}
/* SCREEN-scoped on purpose: the macOS/WebKit print path measures the page
   in points (A4 = 595), which is under this breakpoint, so an unscoped
   query printed the PHONE layout - one stacked column across two pages.
   Print must always keep the two-column sheet. */
@media screen and (max-width:700px){
.s-cols{grid-template-columns:1fr}
.sheet{margin:16px auto 32px;padding:24px 20px}
.hint{margin-top:14px}
}
</style>
</head>
<body data-static-page="cheatsheet">
<div class="bar">
<a class="bar-brand" href="${helpPath('en')}"><img src="/privacy-notes.webp" width="26" height="26" alt="" aria-hidden="true" draggable="false">${brandMark()}</a>
<button class="btn-print" id="cs-print" type="button">${PRINTER_ICON}${esc(printLabel)}</button>
</div>
<p class="hint">${esc(hint)}</p>
<main class="sheet">
<header class="s-head">
<div class="s-brand"><img src="/privacy-notes.webp" width="22" height="22" alt="" aria-hidden="true" draggable="false">${brandMark()}</div>
<h1>${esc(title)}</h1>
<span class="s-meta">${brandMark('.app')} · v${VERSION}</span>
</header>
<div class="s-cols">
<div class="s-col">
${col(true)}
</div>
<div class="s-col">
${col(false)}
</div>
</div>
<footer class="s-foot">
<p id="cs-legend-mac">${esc(legend)}</p>
<p id="cs-legend-pc" hidden>${esc(legendPc)}</p>
${typingNote ? `<p>${esc(typingNote)}</p>` : ''}
</footer>
</main>
</body>
</html>`;
}

/** The rendered demo section for the two showcase entries; '' otherwise. */
function entryShowcase(
  id: string,
  locale: HelpLocale,
  p: Record<string, string>,
  hotkeyGroups: HotkeyGroupData[]
): string {
  if (id === 'markdown-syntax') return renderMarkdownShowcase(p.mdShowcase ?? 'See it in action', p);
  if (id === 'keyboard-shortcuts')
    return renderHotkeysShowcase(locale, hotkeyGroups, p.hkShowcase ?? 'The full list', p.hkLegend ?? '');
  return '';
}

/**
 * The Help search box - ONE source of truth for hub and leaves. The hub
 * variant is the JS-enhanced live filter over the answers on the page
 * (ships hidden; static-pages.js reveals it). The leaf variant stays a
 * real GET form to the hub, so it works with no JS at all and
 * static-pages.js reads ?q= on the hub to prefill + filter; with JS it is
 * upgraded in place into a live title typeahead over `index`, whose last
 * row always hands the query to the hub for the full-text search.
 */
function searchBox(
  p: Record<string, string>,
  mode: 'hub' | 'leaf',
  locale: HelpLocale,
  total = 0,
  index = ''
): string {
  const input = (extra: string) =>
    `<input ${extra} type="search" placeholder="${esc(p.searchPlaceholder)}" aria-label="${esc(p.searchLabel)}" autocomplete="off" spellcheck="false">`;
  const clear = (id: string) =>
    `<button type="button" class="sclear" id="${id}" aria-label="${esc(p.clearSearch)}" title="${esc(p.clearSearch)}">${CLEAR_ICON}</button>`;
  if (mode === 'hub')
    return `<div class="search" id="faq-search" hidden data-count-match="${esc(p.countMatch)}" data-no-matches="${esc(p.noMatches)}" data-copy="${esc(p.copyLink)}" data-copied="${esc(p.copied)}" data-total="${total}">
${SEARCH_ICON}
${input('id="faq-q"')}
${clear('faq-clear')}
<kbd>/</kbd>
</div>`;
  return `<form class="search" action="${helpPath(locale)}" method="get" role="search" id="faq-lform" data-index="${esc(index)}" data-search-all="${esc(p.searchAll)}">
${SEARCH_ICON}
${input('name="q" id="faq-lq"')}
${clear('faq-lclear')}
<kbd>/</kbd>
</form>
<div class="sresults" id="faq-sr" hidden></div>`;
}

/**
 * Question titles + their leaf URLs, baked into the leaf search box so it
 * can answer as you type instead of making you submit and land on the hub.
 * Titles only, which keeps the payload small: the full-text haystack lives
 * on the hub, and the results list always offers to take the query there.
 */
function leafSearchIndex(sections: Section[], locale: HelpLocale): string {
  return JSON.stringify(
    sections.flatMap((s) => s.entries.map((e) => [stripMd(e.q), leafPath(locale, e.id)]))
  );
}

export function renderHubHtml(
  locale: HelpLocale,
  order: FaqGroupKey[],
  rows: FaqStructureRow[],
  cat: FaqCatalog,
  guideOrder: string[],
  guides: GuidesCatalog | null,
  suggest: string,
  hotkeyGroups: HotkeyGroupData[] = []
): string {
  const sections = buildSections(order, rows, cat);
  const total = sections.reduce((n, s) => n + s.entries.length, 0);
  const p = cat.page;
  return `<!DOCTYPE html>
<html lang="${locale}"${htmlDir(locale)}>
<head>
${headCommon(p.metaTitle, p.metaDescription, `${ORIGIN}${helpPath(locale)}`, hreflangCluster() + textAlternate(locale, '/llms-full.txt'), locale)}
${faqJsonLd(sections.flatMap((s) => s.entries), newestContentDate())}
<style>
${PAGE_VARS}
${THEME_TOGGLE_CSS}
${CHROME_CSS}
${HELP_SHARED_CSS}
${MD_SHOWCASE_CSS}
${HK_SHOWCASE_CSS}
.gstrip{margin:8px 0 26px;padding:16px 18px;border:1px solid var(--line);border-radius:14px}
.gstrip .eyebrow{margin:0 0 4px}
.glead{margin:0 0 12px;font-size:14px;color:var(--muted)}
.fgroup .eyebrow{margin:34px 0 6px}
.fgroup:first-of-type .eyebrow{margin-top:8px}
.fgroup[hidden]{display:none}
</style>
</head>
<body data-static-page="help" data-locale="${locale}" data-suggest="${esc(suggest)}">
<div class="wrap">
${siteNav({ active: 'faq', helpLocale: locale, extra: languageMenu(locale, p.languageLabel, (l) => helpPath(l)), home: LOCALE_TO_SLUG[locale], labels: navLabels(p) })}
<div class="pcols">
${renderSidebar({
  topicsLabel: p.topics,
  topics: topicRailItems(sections, (k) => `#g-${k}`),
  guidesLabel: p.guides,
  guideItems: guideRailItems(locale, guideOrder, guides),
  homeHref: helpPath(locale),
  homeLabel: p.browseAll,
  id: 'faq-rail',
})}
<div class="col-head">
<h1>${esc(p.title)}</h1>
<p class="sub">${esc(p.sub)}</p>
${searchBox(p, 'hub', locale, total)}
<p class="count" id="faq-count"></p>
${askMiniBar(p)}
</div>
<div class="col-body" id="faq-list">
${renderSections(sections, locale, cat, hotkeyGroups)}
<div class="noresults" id="faq-empty" hidden>
<p id="faq-empty-lead"></p>
<button type="button" class="btn btn-ghost" id="faq-empty-clear">${CLEAR_ICON}${esc(p.clearSearch)}</button>
</div>
${askAiBlock(p, locale, sections)}${feedbackBlock(p.feedbackPrompt)}
</div>
</div>
</div>
${helpFooter(locale, p.languageLabel, (l) => helpPath(l))}
</body>
</html>`;
}

export function renderLeafHtml(
  locale: HelpLocale,
  order: FaqGroupKey[],
  rows: FaqStructureRow[],
  cat: FaqCatalog,
  guideOrder: string[],
  guides: GuidesCatalog | null,
  id: string,
  suggest: string,
  hotkeyGroups: HotkeyGroupData[] = []
): string {
  const p = cat.page;
  const row = rows.find((r) => r.id === id)!;
  const entry = cat.entries[id];
  const groupLabel = cat.groups[row.group] ?? row.group;
  const sections = buildSections(order, rows, cat);
  const related = rows
    .filter((r) => r.group === row.group && r.id !== id && cat.entries[r.id]?.q)
    .slice(0, 5);
  // The shortcuts leaf swaps its combo-enumeration paragraph for the keycap
  // grid below (the full text still feeds the hub, the in-app FAQ tab, the
  // search haystack, and this page's JSON-LD). Every other leaf renders all
  // of its paragraphs.
  const bodyParas = id === 'keyboard-shortcuts' ? entry.a.slice(0, 1) : entry.a;
  const showcase = entryShowcase(id, locale, p, hotkeyGroups);
  const showcaseCss =
    id === 'markdown-syntax' ? MD_SHOWCASE_CSS : id === 'keyboard-shortcuts' ? HK_SHOWCASE_CSS : '';
  const paragraphs = bodyParas.map((par) => renderParagraph(par, p)).join('\n');
  const relatedHtml = related.length
    ? `<div class="related">
<h2 class="eyebrow">// ${esc(p.related)}</h2>
${related.map((r) => `<a class="rel-q" href="${leafPath(locale, r.id)}">${esc(cat.entries[r.id].q)}<span class="chev" aria-hidden="true"></span></a>`).join('\n')}
</div>`
    : '';
  return `<!DOCTYPE html>
<html lang="${locale}"${htmlDir(locale)}>
<head>
${headCommon(`${stripMd(entry.q)} - PrivacyNotes`, excerpt(entry.a[0]), `${ORIGIN}${leafPath(locale, id)}`, hreflangCluster(id) + textAlternate(locale, `${leafPath('en', id)}.md`), locale)}
${faqJsonLd([entry], contentDate(id))}
${breadcrumbJsonLd(p.title, `${ORIGIN}${helpPath(locale)}`, entry.q, `${ORIGIN}${leafPath(locale, id)}`)}
<style>
${PAGE_VARS}
${THEME_TOGGLE_CSS}
${CHROME_CSS}
${HELP_SHARED_CSS}
h1{font-size:26px}
.leaf-body p{margin:0 0 14px;font-size:15.5px;color:var(--muted);line-height:1.65}
.leaf-body p:first-child{margin-top:2px}
.related{margin-top:34px}
.related .eyebrow{margin:0 0 4px}
.rel-q{display:flex;align-items:center;justify-content:space-between;gap:14px;padding:13px 2px;border-top:1px solid var(--line);font-size:14.5px;font-weight:600;color:var(--fg);text-decoration:none;letter-spacing:-.01em}
.related .eyebrow + .rel-q{border-top:0}
.rel-q:hover{color:var(--accent);text-decoration:none}
.rel-q .chev{transform:rotate(-45deg);margin-top:0}
.srcs{margin:26px 0 0;padding-top:18px;border-top:1px solid var(--line)}
.srcs .eyebrow{margin:0 0 6px}
.src-row{display:flex;align-items:center;gap:10px;padding:9px 2px;border-top:1px solid var(--line);color:var(--faint);text-decoration:none}
.srcs .eyebrow + .src-row{border-top:0}
.src-row:hover{text-decoration:none}
.src-row:hover .src-file{color:var(--accent)}
.src-lbl{flex:1;min-width:0;display:flex;flex-wrap:wrap;align-items:baseline;gap:1px 9px}
.src-file{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;font-weight:600;color:var(--fg)}
.src-head{font-size:13.5px;color:var(--muted)}
.src-note{margin:10px 0 0;font-size:12.5px;color:var(--faint)}
${showcaseCss}
</style>
</head>
<body data-static-page="help-leaf" data-locale="${locale}" data-suggest="${esc(suggest)}">
<div class="wrap">
${siteNav({ active: 'faq', helpLocale: locale, extra: languageMenu(locale, p.languageLabel, (l) => leafPath(l, id)), home: LOCALE_TO_SLUG[locale], labels: navLabels(p) })}
<div class="pcols">
${renderSidebar({
  topicsLabel: p.topics,
  topics: topicRailItems(sections, (k) => `${helpPath(locale)}#g-${k}`, row.group),
  guidesLabel: p.guides,
  guideItems: guideRailItems(locale, guideOrder, guides),
  homeHref: helpPath(locale),
  homeLabel: p.browseAll,
})}
<p class="crumb"><a href="${helpPath(locale)}">${esc(p.title)}</a><span class="sep">/</span><a href="${helpPath(locale)}#g-${esc(row.group)}">${esc(groupLabel)}</a></p>
<div class="col-head">
<h1>${esc(stripMd(entry.q))}</h1>
${askMiniBar(p)}
</div>
<div class="col-body">
<div class="leaf-body">
${paragraphs}
</div>
${showcase}
${sourcesBlock(p, id)}
<div class="leaf-hub">
<p class="lh-title">${esc(p.title)}</p>
<p class="sub">${esc(p.sub)}</p>
${searchBox(p, 'leaf', locale, 0, leafSearchIndex(sections, locale))}
</div>
${relatedHtml}
${askAiBlock(p, locale, sections)}${feedbackBlock(p.feedbackPrompt)}
</div>
</div>
</div>
${helpFooter(locale, p.languageLabel, (l) => leafPath(l, id))}
</body>
</html>`;
}

export function renderGuideHtml(
  locale: HelpLocale,
  order: FaqGroupKey[],
  rows: FaqStructureRow[],
  guideOrder: string[],
  guides: GuidesCatalog,
  cat: FaqCatalog,
  id: string,
  suggest: string
): string {
  const g = guides.guides[id];
  const gp = guides.page;
  const p = cat.page;
  const faqSections = buildSections(order, rows, cat);
  const iconHref = guideIconHref(id);
  const glyph = guideGlyph(id, 72);
  const tile = iconHref
    ? `<div class="app-tile"><img src="${iconHref}" width="72" height="72" alt="" loading="eager"></div>`
    : glyph
      ? `<div class="app-tile">${glyph}</div>`
      : '';
  const sections = g.sections
    .map((s) => {
      // The shot leads its section: a section with only an img renders
      // between the lead and the first heading. Intrinsic width/height
      // are always emitted so the reserved box kills the layout shift.
      const shot = s.img?.src
        ? `<figure class="guide-shot"><img src="${esc(s.img.src)}" alt="${esc(s.img.alt)}" width="${s.img.width}" height="${s.img.height}" loading="lazy" decoding="async"></figure>`
        : '';
      const head = s.h ? `<h2>${esc(s.h)}</h2>` : '';
      const paras = (s.p ?? []).map((par) => `<p>${renderInline(par)}</p>`).join('\n');
      const steps = s.steps?.length
        ? `<ol>${s.steps.map((st) => `<li>${renderInline(st)}</li>`).join('\n')}</ol>`
        : '';
      return `${shot}\n${head}\n${paras}\n${steps}`;
    })
    .join('\n');
  const importSteps = gp.importSteps
    .map((st) => `<li>${renderInline(fill(st, { app: g.app }))}</li>`)
    .join('\n');
  return `<!DOCTYPE html>
<html lang="${locale}"${htmlDir(locale)}>
<head>
${headCommon(g.metaTitle, excerpt(g.lead), `${ORIGIN}${guidePath(locale, id)}`, guideHreflang(id) + textAlternate(locale, `${guidePath('en', id)}.md`), locale)}
${breadcrumbJsonLd(p.title, `${ORIGIN}${helpPath(locale)}`, g.title, `${ORIGIN}${guidePath(locale, id)}`)}
${guideJsonLd(g, `${ORIGIN}${guidePath(locale, id)}`, locale, contentDate(id))}
<style>
${PAGE_VARS}
${THEME_TOGGLE_CSS}
${CHROME_CSS}
${HELP_SHARED_CSS}
h1{font-size:26px}
.lead{font-size:15.5px;color:var(--muted);line-height:1.6;margin:0 0 4px}
.guide-body h2{font-size:18px;font-weight:700;letter-spacing:-.01em;margin:26px 0 8px}
.guide-body>h2:first-child{margin-top:14px}
.guide-body>p:first-child{margin-top:14px}
.guide-body>figure.guide-shot:first-child{margin-top:14px}
.guide-shot{margin:0 0 18px}
.guide-shot img{display:block;width:100%;height:auto;border:1px solid var(--line);border-radius:10px}
.guide-body p{margin:0 0 13px;font-size:15.5px;color:var(--muted);line-height:1.65}
.guide-body ol{margin:0 0 16px;padding-left:22px}
.guide-body ol li{margin:0 0 9px;font-size:15.5px;color:var(--muted);line-height:1.6}
.guide-body ol li::marker{color:var(--accent);font-weight:600}
</style>
</head>
<body data-static-page="help-guide" data-locale="${locale}" data-suggest="${esc(suggest)}">
<div class="wrap">
${siteNav({ active: 'faq', helpLocale: locale, extra: languageMenu(locale, p.languageLabel, (l) => guidePath(l, id)), home: LOCALE_TO_SLUG[locale], labels: navLabels(p) })}
<div class="pcols">
${renderSidebar({
  topicsLabel: p.topics,
  topics: topicRailItems(faqSections, (k) => `${helpPath(locale)}#g-${k}`),
  guidesLabel: p.guides,
  guideItems: guideRailItems(locale, guideOrder, guides, id),
  homeHref: helpPath(locale),
  homeLabel: p.browseAll,
})}
<p class="crumb"><a href="${helpPath(locale)}">${esc(p.title)}</a><span class="sep">/</span>${esc(p.guides)}</p>
<div class="col-head">
<div class="head-row">
${tile}
<div class="head-txt">
<h1>${esc(g.title)}</h1>
<p class="lead">${esc(g.lead)}</p>
</div>
</div>
${askMiniBar(p)}
</div>
<div class="col-body">
<div class="guide-body">
${sections}
<h2>${esc(gp.importTitle)}</h2>
<ol>
${importSteps}
</ol>
</div>
${askAiBlock(p, locale, faqSections)}${feedbackBlock(p.feedbackPrompt)}
</div>
</div>
</div>
${helpFooter(locale, p.languageLabel, (l) => guidePath(l, id))}
</body>
</html>`;
}

function urlset(urls: string[]): string {
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls.map((u) => `<url><loc>${u}</loc></url>`).join('\n')}
</urlset>`;
}

/** sitemap-help.xml: hubs, FAQ leaves, and guides across every locale. */
function renderSitemap(rows: FaqStructureRow[], guideIds: string[]): string {
  const urls: string[] = [];
  for (const locale of HELP_LOCALES) {
    urls.push(`${ORIGIN}${helpPath(locale)}`);
    for (const r of rows) urls.push(`${ORIGIN}${leafPath(locale, r.id)}`);
    for (const id of guideIds) urls.push(`${ORIGIN}${guidePath(locale, id)}`);
  }
  return urlset(urls);
}

/**
 * sitemap-marketing.xml: the homepage, its per-locale slugs, and the two
 * other pre-rendered standalone pages.
 *
 * These were in no sitemap at all - robots.txt advertised only the Help
 * sitemap, so the homepage and every localized homepage were left to be
 * found by crawling. "/en" is deliberately absent: it canonicalizes to the
 * apex (see marketingPath() in src/seo.ts), and listing a URL that points
 * its canonical elsewhere is a contradiction Google reports back as
 * "Alternate page with proper canonical tag".
 */
function renderMarketingSitemap(): string {
  const urls = [`${ORIGIN}/`];
  for (const [locale, slug] of Object.entries(LOCALE_TO_SLUG)) {
    if (locale === 'en') continue;
    urls.push(`${ORIGIN}${slug}`);
  }
  urls.push(`${ORIGIN}/changelog`, `${ORIGIN}/roadmap`, `${ORIGIN}/brand`);
  return urlset(urls);
}

/**
 * sitemap.xml: the index robots.txt points at. Adding a sitemap means
 * adding a line here rather than editing robots.txt and resubmitting in
 * Search Console.
 */
function renderSitemapIndex(): string {
  const maps = [
    `${ORIGIN}/sitemap-marketing.xml`,
    `${ORIGIN}/sitemap-help.xml`,
    // The landing sitemap only exists while the landing pages are published;
    // listing it while landing-pages.ts emits nothing would advertise a 404.
    ...(LANDING_PAGES_PUBLIC ? [`${ORIGIN}/sitemap-landing.xml`] : []),
  ];
  return `<?xml version="1.0" encoding="UTF-8"?>
<sitemapindex xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${maps.map((m) => `<sitemap><loc>${m}</loc></sitemap>`).join('\n')}
</sitemapindex>`;
}

// ── Plain-text layer, for AI agents ──────────────────────────
//
// The help center is already crawlable: static HTML, FAQPage JSON-LD,
// a sitemap, and no bot blocked in robots.txt. What it was not is
// CHEAP TO READ. The hub is 266 KB of markup and one FAQ leaf is 85 KB,
// so an assistant answering "how much is Pro" paid for a stylesheet, a
// sidebar and 59 collapsed <details> to reach two sentences. The whole
// English help center as text is 72 KB - less than one leaf page.
//
// So every FAQ leaf and every guide also emits a .md twin at the page
// URL plus `.md`, and the lot is concatenated into /llms-full.txt, the
// companion the llms.txt convention names. Both come from the same
// catalogs the pages come from, so neither can disagree with the page
// it mirrors.
//
// Everything here says how the app WORKS. What CHANGED lives in the
// fourth file of this layer, /changelog.md, which changelog-page.ts emits
// from the same array the changelog page reads; both bundles point at it,
// because an assistant asked "where did this move" finds nothing in a
// catalog that only describes the app as it stands today.
//
// English only, on purpose: llms.txt is an English convention, and .md
// twins for every locale would add well over a thousand files to serve
// readers that do not exist yet. The .md files stay OUT of the sitemaps - a sitemap
// lists pages to index, and listing a twin of an indexed page is the
// duplicate-content shape the self-canonical stance exists to avoid.

/**
 * The hub URL for one FAQ group, spelled out under its heading in both
 * text bundles.
 *
 * Why: a `## Security & privacy` heading with no URL under it looks to a
 * model exactly like a markdown document heading, so an assistant asked to
 * cite the section builds `/help#security--privacy` - the GitHub anchor
 * slug for that text - and links a fragment this site has never had. Seen
 * in the wild. The real id is `g-<groupKey>`, written by the hub, and the
 * fix is to leave nothing to invent: every heading in those files now names
 * its own URL, exactly like every entry already did.
 *
 * Keep in step with the `id="g-..."` the hub emits; check:llms proves the
 * two agree against the built page.
 */
function groupUrl(key: FaqGroupKey): string {
  return `${ORIGIN}${helpPath('en')}#g-${key}`;
}

/**
 * Footer every .md twin carries. It is an instruction, not a description:
 * "The page this came from" told a model where the text originated and left
 * it free to cite whatever else looked safe, which is how one assistant
 * ended up linking only the help center home. Naming the citation is the
 * job of this line; the bundle link moved out because a second URL here
 * competed with the one that matters.
 *
 * The label is "Source:" rather than "Cite as:" because models echo it
 * verbatim into their reply. An instruction phrasing therefore surfaces as
 * "Cite as: https://..." in front of a reader, while "Source:" is what a
 * citation looks like anyway. Assume the label is user-facing.
 */
const MD_FOOTER = `\n---\nSource: `;

/** One FAQ answer as markdown: the question, its URL, the answer. */
function faqMd(id: string, entry: { q: string; a: string[] }): string {
  const url = `${ORIGIN}${leafPath('en', id)}`;
  return `# ${absoluteLinks(entry.q)}\n\n${entry.a.map(absoluteLinks).join('\n\n')}\n${sourcesMd(id)}${MD_FOOTER}${url}\n`;
}

/** One import guide as markdown, including the shared import steps. */
function guideMd(id: string, guides: GuidesCatalog): string {
  const g = guides.guides[id];
  const url = `${ORIGIN}${guidePath('en', id)}`;
  const body = g.sections
    .map((sec) => {
      const parts: string[] = [];
      if (sec.h) parts.push(`## ${sec.h}`);
      for (const par of sec.p ?? []) parts.push(absoluteLinks(par));
      if (sec.steps?.length) {
        parts.push(sec.steps.map((st, i) => `${i + 1}. ${absoluteLinks(st)}`).join('\n'));
      }
      return parts.join('\n\n');
    })
    .filter(Boolean)
    .join('\n\n');
  const steps = guides.page.importSteps
    .map((st, i) => `${i + 1}. ${absoluteLinks(fill(st, { app: g.app }))}`)
    .join('\n');
  return `# ${g.title}\n\n${absoluteLinks(g.lead)}\n\n${body}\n\n## ${guides.page.importTitle}\n\n${steps}\n${MD_FOOTER}${url}\n`;
}

/**
 * /llms-index.txt - the token-light tier.
 *
 * llms-full.txt is one fetch and about 17,700 tokens. That is free and
 * invisible on a chat subscription, and it is real money on a metered API
 * key and simply too large for a local model with an 8k window. So the
 * index lists every question against the URL that answers it, and points
 * at the .md twins rather than the pages: an answer costs about 230
 * tokens that way instead of the 21,000 its HTML page costs.
 *
 * Read index, fetch one page: roughly 2,000 tokens instead of 17,700.
 *
 * The index links llms-full.txt back, and the copied prompt names it as
 * the fallback, because an assistant that cannot chain two fetches has to
 * land somewhere that still answers the question.
 */
function renderLlmsIndex(
  order: FaqGroupKey[],
  rows: FaqStructureRow[],
  cat: FaqCatalog,
  guideOrder: string[],
  guides: GuidesCatalog | null
): string {
  const sections = buildSections(order, rows, cat);
  const entryCount = sections.reduce((n, sec) => n + sec.entries.length, 0);
  const guideIds = guides ? guideOrder.filter((id) => guides.guides[id]?.app) : [];
  const faq = sections
    .map(
      (sec) =>
        `## ${sec.label}\n${groupUrl(sec.key)}\n${sec.entries
          .map((e) => `- ${stripMd(e.q)} -> ${ORIGIN}${leafPath('en', e.id)}.md (source: ${ORIGIN}${leafPath('en', e.id)})`)
          .join('\n')}`
    )
    .join('\n\n');
  const guideList = guides
    ? `\n\n## Export and import guides\n${ORIGIN}${helpPath('en')}\n${guideIds
        .map((id) => `- ${guides.guides[id].title} -> ${ORIGIN}${guidePath('en', id)}.md (source: ${ORIGIN}${guidePath('en', id)})`)
        .join('\n')}`
    : '';
  return `# PrivacyNotes Help Center - index

> Every question in the PrivacyNotes help center, against the URL that answers it. ${entryCount} answers and ${guideIds.length} export and import guides. PrivacyNotes is an end-to-end encrypted notes, tasks, journal and vault app.

Read this first, then fetch ONLY the one or two pages that match the question.
Fetch the .md URL; end your reply with the "source" URL beside it. They
differ by the extension on purpose: the .md is the cheap copy, the other is
the page a reader can open.
Every URL below is plain text and small: an answer averages 900 bytes, a guide
about 2 KB. Drop the .md from any of them for the human-readable page.

If you cannot make a second request, fetch ${ORIGIN}/llms-full.txt
instead. It is the same content in one file, and costs about 17,700 tokens.

Everything here describes how the app works today. If the question is about
what CHANGED - a new feature, a version number, or where a menu path, a
shortcut or a setting moved - fetch ${ORIGIN}/changelog.md instead.
It is every release as plain text, newest first, and it cites its own page.

The same answers exist in ${HELP_LOCALES.length} languages under ${ORIGIN}/<language-slug>/help/,
as pages rather than as plain text. Answer in the reader's language from these.

${faq}${guideList}
`;
}

/**
 * /llms-full.txt - the whole English help center in one fetch.
 *
 * Structure matches the site: one `##` per FAQ group in render order,
 * one `###` per entry, then the import guides. Every entry names its own
 * page URL, because an assistant that cites this file cites a file
 * nobody can open, while a leaf URL is a page the reader can read.
 */
function renderLlmsFull(
  order: FaqGroupKey[],
  rows: FaqStructureRow[],
  cat: FaqCatalog,
  guideOrder: string[],
  guides: GuidesCatalog | null
): string {
  const sections = buildSections(order, rows, cat);
  const entryCount = sections.reduce((n, sec) => n + sec.entries.length, 0);
  const guideIds = guides ? guideOrder.filter((id) => guides.guides[id]?.app) : [];
  const localeCount = HELP_LOCALES.length;
  const faq = sections
    .map((sec) => {
      const entries = sec.entries
        .map(
          (e) =>
            `### ${absoluteLinks(e.q)}\nSource: ${ORIGIN}${leafPath('en', e.id)}\n\n${e.a.map(absoluteLinks).join('\n\n')}`
        )
        .join('\n\n');
      return `## ${sec.label}\n${groupUrl(sec.key)}\n\n${entries}`;
    })
    .join('\n\n');
  const guideBlocks = guides
    ? guideIds
        .map((id) => {
          const g = guides.guides[id];
          const body = g.sections
            .map((sec) => {
              const parts: string[] = [];
              if (sec.h) parts.push(`**${sec.h}**`);
              for (const par of sec.p ?? []) parts.push(absoluteLinks(par));
              if (sec.steps?.length) {
                parts.push(sec.steps.map((st, i) => `${i + 1}. ${absoluteLinks(st)}`).join('\n'));
              }
              return parts.join('\n\n');
            })
            .filter(Boolean)
            .join('\n\n');
          return `### ${g.title}\nSource: ${ORIGIN}${guidePath('en', id)}\n\n${absoluteLinks(g.lead)}\n\n${body}`;
        })
        .join('\n\n')
    : '';
  const importSteps = guides
    ? `\nEvery guide ends with the same four steps inside PrivacyNotes:\n\n${guides.page.importSteps
        .map((st, i) => `${i + 1}. ${absoluteLinks(fill(st, { app: 'the source app' }))}`)
        .join('\n')}\n`
    : '';
  return `# PrivacyNotes Help Center

> Every answer in the PrivacyNotes help center: ${entryCount} questions and ${guideIds.length} export and import guides, in full. PrivacyNotes is an end-to-end encrypted notes, tasks, journal and vault app. Everything is encrypted on the reader's own device before it is stored or synced.

This file exists so an assistant can answer a question about PrivacyNotes from
one fetch instead of crawling ${entryCount + guideIds.length} pages. It is generated from the same
catalogs the pages are generated from, so it cannot disagree with them.
Read ${ORIGIN}/llms.txt first for the rest of the site.
This file says how the app WORKS. For what CHANGED and when, and for where a
menu path or a shortcut moved, fetch ${ORIGIN}/changelog.md
instead: every release as plain text, newest first.

Every answer below carries a "Source:" line naming its own page. End your
reply with that URL, never this file and never the help center home.
The same pages exist in ${localeCount} languages at ${ORIGIN}/<language-slug>/help/.
Single answers are also served as plain text at ${ORIGIN}/help/<slug>.md.

${faq}

## Export and import guides
${ORIGIN}${helpPath('en')}

How to export from another app, and what arrives here. Imports run entirely on the reader's own
device, so nothing readable is uploaded.
${importSteps}
${guideBlocks}
`;
}

type Rendered = { fileName: string; source: string };

async function renderAll(): Promise<Rendered[]> {
  const { order, rows, guideOrder, hotkeyGroups } = await loadStructure();
  const en = readCatalog('en');
  if (!en) throw new Error('help-page: src/locales/en/faq.json is missing');
  const guidesEn = readGuides('en');
  const suggest = JSON.stringify(suggestStrings());
  const guideIds = guidesEn ? guideOrder.filter((id) => guidesEn.guides[id]?.app) : [];
  const out: Rendered[] = [];
  for (const locale of HELP_LOCALES) {
    const cat = loadCatalog(locale, en);
    const guidesCat = loadGuides(locale, guidesEn);
    const prefix = localePrefix(locale);
    const base = prefix ? `${prefix.slice(1)}/help` : 'help';
    out.push({
      fileName: `${base}/index.html`,
      source: renderHubHtml(locale, order, rows, cat, guideOrder, guidesCat, suggest, hotkeyGroups),
    });
    for (const r of rows) {
      if (!cat.entries[r.id]?.q) continue;
      out.push({
        fileName: `${base}/${r.id}/index.html`,
        source: renderLeafHtml(locale, order, rows, cat, guideOrder, guidesCat, r.id, suggest, hotkeyGroups),
      });
    }
    // The printable cheat sheet: ENGLISH ONLY (see cheatSheetPath), so it
    // is emitted for the apex /help tree alone. Canonicalizes at the
    // English leaf, so it stays out of sitemap-help.xml.
    if (locale === 'en') {
      out.push({
        fileName: `${base}/keyboard-shortcuts/cheat-sheet/index.html`,
        source: renderCheatSheetHtml(hotkeyGroups),
      });
    }
    if (guidesCat) {
      for (const id of guideIds) {
        out.push({
          fileName: `${base}/import/${id}/index.html`,
          source: renderGuideHtml(locale, order, rows, guideOrder, guidesCat, cat, id, suggest),
        });
      }
    }
  }
  // The plain-text layer: one .md per English FAQ leaf and guide, plus
  // the whole thing concatenated. Deliberately absent from the sitemaps.
  for (const r of rows) {
    if (!en.entries[r.id]?.q) continue;
    out.push({ fileName: `help/${r.id}.md`, source: faqMd(r.id, en.entries[r.id]) });
  }
  if (guidesEn) {
    for (const id of guideIds) {
      out.push({ fileName: `help/import/${id}.md`, source: guideMd(id, guidesEn) });
    }
  }
  out.push({
    fileName: 'llms-full.txt',
    source: renderLlmsFull(order, rows, en, guideOrder, guidesEn),
  });
  out.push({
    fileName: 'llms-index.txt',
    source: renderLlmsIndex(order, rows, en, guideOrder, guidesEn),
  });
  out.push({ fileName: 'sitemap-help.xml', source: renderSitemap(rows, guideIds) });
  out.push({ fileName: 'sitemap-marketing.xml', source: renderMarketingSitemap() });
  out.push({ fileName: 'sitemap.xml', source: renderSitemapIndex() });
  return out;
}

export function helpPagePlugin(): Plugin {
  return {
    name: 'emit-help-page',
    async generateBundle() {
      for (const page of await renderAll()) {
        this.emitFile({ type: 'asset', fileName: page.fileName, source: page.source });
      }
    },
    configureServer(server) {
      // Serve every locale's hub, the FAQ leaves, the guides, and the
      // sitemap in dev so the whole tree can be verified locally without
      // a production build.
      const xml = (
        res: { setHeader: (k: string, v: string) => void; end: (b: string) => void },
        body: string
      ) => {
        res.setHeader('Content-Type', 'application/xml; charset=utf-8');
        res.end(body);
      };
      server.middlewares.use('/sitemap-help.xml', async (_req, res, next) => {
        try {
          const { rows, guideOrder } = await loadStructure();
          const guidesEn = readGuides('en');
          const guideIds = guidesEn ? guideOrder.filter((id) => guidesEn.guides[id]?.app) : [];
          xml(res, renderSitemap(rows, guideIds));
        } catch (err) {
          next(err);
        }
      });
      server.middlewares.use('/sitemap-marketing.xml', (_req, res) => xml(res, renderMarketingSitemap()));
      for (const [route, render] of [
        ['/llms-full.txt', renderLlmsFull],
        ['/llms-index.txt', renderLlmsIndex],
      ] as const) {
        server.middlewares.use(route, async (_req, res, next) => {
          try {
            const { order, rows, guideOrder } = await loadStructure();
            const en = readCatalog('en');
            if (!en) throw new Error('help-page: src/locales/en/faq.json is missing');
            res.setHeader('Content-Type', 'text/plain; charset=utf-8');
            res.end(render(order, rows, en, guideOrder, readGuides('en')));
          } catch (err) {
            next(err);
          }
        });
      }
      server.middlewares.use('/sitemap.xml', (_req, res) => xml(res, renderSitemapIndex()));
      for (const locale of HELP_LOCALES) {
        const route = `${localePrefix(locale)}/help`;
        server.middlewares.use(route, async (req, res, next) => {
          try {
            const { order, rows, guideOrder, hotkeyGroups } = await loadStructure();
            const en = readCatalog('en');
            if (!en) throw new Error('help-page: src/locales/en/faq.json is missing');
            const cat = loadCatalog(locale, en);
            const guidesCat = loadGuides(locale, readGuides('en'));
            const suggest = JSON.stringify(suggestStrings());
            const seg = (req.url ?? '/').split('?')[0].replace(/^\/+|\/+$/g, '');
            // Only set the HTML content type on responses this middleware
            // actually renders: /help/icons/*.svg also flows through this
            // mount, and a leaked text/html header makes browsers refuse
            // to render the SVGs (raster formats survive by byte-sniffing).
            const html = (body: string) => {
              res.setHeader('Content-Type', 'text/html; charset=utf-8');
              res.end(body);
            };
            // The .md twins sit at the page URL plus `.md`, English only.
            // text/plain so a browser shows them; see public/_headers.
            if (locale === 'en' && seg.endsWith('.md')) {
              const base = seg.slice(0, -'.md'.length);
              let body: string | null = null;
              if (base.startsWith('import/')) {
                const gid = base.slice('import/'.length);
                if (guidesCat?.guides[gid]?.app) body = guideMd(gid, guidesCat);
              } else if (cat.entries[base]?.q) {
                body = faqMd(base, cat.entries[base]);
              }
              if (body === null) {
                next();
                return;
              }
              res.setHeader('Content-Type', 'text/plain; charset=utf-8');
              res.end(body);
            } else if (!seg) {
              html(renderHubHtml(locale, order, rows, cat, guideOrder, guidesCat, suggest, hotkeyGroups));
            } else if (locale === 'en' && seg === 'keyboard-shortcuts/cheat-sheet') {
              html(renderCheatSheetHtml(hotkeyGroups));
            } else if (seg.startsWith('import/')) {
              const id = seg.slice('import/'.length);
              if (guidesCat?.guides[id]?.app) {
                html(renderGuideHtml(locale, order, rows, guideOrder, guidesCat, cat, id, suggest));
              } else {
                next();
              }
            } else if (rows.some((r) => r.id === seg) && cat.entries[seg]?.q) {
              html(renderLeafHtml(locale, order, rows, cat, guideOrder, guidesCat, seg, suggest, hotkeyGroups));
            } else {
              next();
            }
          } catch (err) {
            next(err);
          }
        });
      }
    },
  };
}
