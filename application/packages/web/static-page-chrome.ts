// Shared chrome (brand header + editorial footer) for the static
// pre-rendered pages (/faq, /changelog, and any future help/migration
// page). Single source of truth so the two static pages - and whatever
// comes next - stay identical and on-brand without duplication.
//
// Note on "one source of truth" with the homepage: the homepage footer
// (LandingPage.tsx) is JSX + Tailwind and cannot be shared with these
// pages, which ship as raw HTML+CSS under a CSP that blocks inline
// scripts and never loads Tailwind. This module mirrors the homepage
// footer's structure and content in plain HTML+CSS, and is the single
// source feeding every static page.
//
// The footer is a dark slab in both themes, in the homepage footer's warm
// ink (`--footer` from static-page-theme.ts, `--wl-footer` on the homepage).

import fs from 'node:fs';
import { createElement } from 'react';
import { renderToStaticMarkup } from 'react-dom/server';
import { ArrowUpRight, SignIn } from '@phosphor-icons/react';
import { VERSION } from './src/version.ts';
import { THEME_TOGGLE_BUTTON } from './static-page-theme.ts';
import { DEMO_HREF, FOOTER_COLUMNS, NAV_SECTIONS, type FooterIcon } from './src/footerData.ts';
import { APP_ORIGIN, APEX_ORIGIN } from './src/hosts.ts';
import { LOCALE_TO_SLUG, helpPath } from './src/localeRoutes.ts';
import { ogLocale } from './src/marketingMeta.ts';
import { FOOTER_LINES_CSS, FOOTER_LINES_SCRIPT_TAG, footerLinesHtml, type FooterLinesText } from './src/footerLines.ts';
import { Flag, LANGUAGE_META, sortByNative } from './src/languageData.tsx';

// Phosphor icon paths (viewBox 0 0 256 256). Weights chosen to match the
// homepage footer: brand/social use "fill", utility icons use "bold".
const P = {
  github: 'M216,104v8a56.06,56.06,0,0,1-48.44,55.47A39.8,39.8,0,0,1,176,192v40a8,8,0,0,1-8,8H104a8,8,0,0,1-8-8V216H72a40,40,0,0,1-40-40A24,24,0,0,0,8,152a8,8,0,0,1,0-16,40,40,0,0,1,40,40,24,24,0,0,0,24,24H96v-8a39.8,39.8,0,0,1,8.44-24.53A56.06,56.06,0,0,1,56,112v-8a58.14,58.14,0,0,1,7.69-28.32A59.78,59.78,0,0,1,69.07,28,8,8,0,0,1,76,24a59.75,59.75,0,0,1,48,24h24a59.75,59.75,0,0,1,48-24,8,8,0,0,1,6.93,4,59.74,59.74,0,0,1,5.37,47.68A58,58,0,0,1,216,104Z',
  reddit: 'M248,104a32,32,0,0,0-52.94-24.19c-16.75-8.9-36.76-14.28-57.66-15.53l5.19-31.17,17.72,2.72a24,24,0,1,0,2.87-15.74l-26-4a8,8,0,0,0-9.11,6.59L121.2,64.16c-21.84.94-42.82,6.38-60.26,15.65a32,32,0,0,0-42.59,47.74A59,59,0,0,0,16,144c0,21.93,12,42.35,33.91,57.49C70.88,216,98.61,224,128,224s57.12-8,78.09-22.51C228,186.35,240,165.93,240,144a59,59,0,0,0-2.35-16.45A32.16,32.16,0,0,0,248,104ZM72,128a16,16,0,1,1,16,16A16,16,0,0,1,72,128Zm91.75,55.07a76.18,76.18,0,0,1-71.5,0,8,8,0,1,1,7.5-14.14,60.18,60.18,0,0,0,56.5,0,8,8,0,1,1,7.5,14.14ZM168,144a16,16,0,1,1,16-16A16,16,0,0,1,168,144Z',
  x: 'M215,219.85a8,8,0,0,1-7,4.15H160a8,8,0,0,1-6.75-3.71l-40.49-63.63L53.92,221.38a8,8,0,0,1-11.84-10.76l61.77-68L41.25,44.3A8,8,0,0,1,48,32H96a8,8,0,0,1,6.75,3.71l40.49,63.63,58.84-64.72a8,8,0,0,1,11.84,10.76l-61.77,67.95,62.6,98.38A8,8,0,0,1,215,219.85Z',
  mastodon: 'M184,32H72A40,40,0,0,0,32,72V192a40,40,0,0,0,40,40h88a8,8,0,0,0,0-16H72a24,24,0,0,1-24-24v-8H184a40,40,0,0,0,40-40V72A40,40,0,0,0,184,32Zm0,104a8,8,0,0,1-16,0V104a16,16,0,0,0-32,0v32a8,8,0,0,1-16,0V104a16,16,0,0,0-32,0v32a8,8,0,0,1-16,0V104a32,32,0,0,1,56-21.13A32,32,0,0,1,184,104Z',
  youtube: 'M234.33,69.52a24,24,0,0,0-14.49-16.4C185.56,39.88,131,40,128,40s-57.56-.12-91.84,13.12a24,24,0,0,0-14.49,16.4C19.08,79.5,16,97.74,16,128s3.08,48.5,5.67,58.48a24,24,0,0,0,14.49,16.41C69,215.56,120.4,216,127.34,216h1.32c6.94,0,58.37-.44,91.18-13.11a24,24,0,0,0,14.49-16.41c2.59-10,5.67-28.22,5.67-58.48S236.92,79.5,234.33,69.52Zm-73.74,65-40,28A8,8,0,0,1,108,156V100a8,8,0,0,1,12.59-6.55l40,28a8,8,0,0,1,0,13.1Z',
  facebook: 'M232,128a104.16,104.16,0,0,1-91.55,103.26,4,4,0,0,1-4.45-4V152h24a8,8,0,0,0,8-8.53,8.17,8.17,0,0,0-8.25-7.47H136V112a16,16,0,0,1,16-16h16a8,8,0,0,0,8-8.53A8.17,8.17,0,0,0,167.73,80H152a32,32,0,0,0-32,32v24H96a8,8,0,0,0-8,8.53A8.17,8.17,0,0,0,96.27,152H120v75.28a4,4,0,0,1-4.44,4A104.15,104.15,0,0,1,24.07,124.09c2-54,45.74-97.9,99.78-100A104.12,104.12,0,0,1,232,128Z',
  question: 'M144,180a16,16,0,1,1-16-16A16,16,0,0,1,144,180Zm92-52A108,108,0,1,1,128,20,108.12,108.12,0,0,1,236,128Zm-24,0a84,84,0,1,0-84,84A84.09,84.09,0,0,0,212,128ZM128,64c-24.26,0-44,17.94-44,40v4a12,12,0,0,0,24,0v-4c0-8.82,9-16,20-16s20,7.18,20,16-9,16-20,16a12,12,0,0,0-12,12v8a12,12,0,0,0,23.73,2.56C158.31,137.88,172,122.37,172,104,172,81.94,152.26,64,128,64Z',
  list: 'M76,64A12,12,0,0,1,88,52H216a12,12,0,0,1,0,24H88A12,12,0,0,1,76,64Zm140,52H88a12,12,0,0,0,0,24H216a12,12,0,0,0,0-24Zm0,64H88a12,12,0,0,0,0,24H216a12,12,0,0,0,0-24ZM44,112a16,16,0,1,0,16,16A16,16,0,0,0,44,112Zm0-64A16,16,0,1,0,60,64,16,16,0,0,0,44,48Zm0,128a16,16,0,1,0,16,16A16,16,0,0,0,44,176Z',
  lock: 'M208,76H180V56A52,52,0,0,0,76,56V76H48A20,20,0,0,0,28,96V208a20,20,0,0,0,20,20H208a20,20,0,0,0,20-20V96A20,20,0,0,0,208,76ZM100,56a28,28,0,0,1,56,0V76H100ZM204,204H52V100H204Zm-60-52a16,16,0,1,1-16-16A16,16,0,0,1,144,152Z',
  file: 'M216.49,79.52l-56-56A12,12,0,0,0,152,20H56A20,20,0,0,0,36,40V216a20,20,0,0,0,20,20H200a20,20,0,0,0,20-20V88A12,12,0,0,0,216.49,79.52ZM160,57l23,23H160ZM60,212V44h76V92a12,12,0,0,0,12,12h48V212Zm112-80a12,12,0,0,1-12,12H96a12,12,0,0,1,0-24h64A12,12,0,0,1,172,132Zm0,40a12,12,0,0,1-12,12H96a12,12,0,0,1,0-24h64A12,12,0,0,1,172,172Z',
  refund: 'M228,128a100,100,0,0,1-98.66,100H128a99.39,99.39,0,0,1-68.62-27.29,12,12,0,0,1,16.48-17.45,76,76,0,1,0-1.57-109c-.13.13-.25.25-.39.37L54.89,92H72a12,12,0,0,1,0,24H24a12,12,0,0,1-12-12V56a12,12,0,0,1,24,0V76.72L57.48,57.06A100,100,0,0,1,228,128Z',
  scales: 'M243.14,131.54l-32-80h0a12,12,0,0,0-13.73-7.25L140,57V40a12,12,0,0,0-24,0V62.37L53.4,76.29a12,12,0,0,0-8.54,7.25h0l0,0v0l-32,79.92A12,12,0,0,0,12,168c0,12.13,6.2,22.43,17.45,29A55,55,0,0,0,56,204a55,55,0,0,0,26.55-7C93.8,190.43,100,180.13,100,168a12,12,0,0,0-.86-4.46L72.38,96.65,116,87V204H104a12,12,0,0,0,0,24h48a12,12,0,0,0,0-24H140V81.63l40.42-9-23.56,58.9A12,12,0,0,0,156,136c0,12.13,6.2,22.43,17.45,29a53.78,53.78,0,0,0,53.1,0C237.8,158.43,244,148.13,244,136A12,12,0,0,0,243.14,131.54ZM56,180c-3.71,0-18-1.87-19.81-10.18L56,120.31l19.81,49.51C74,178.13,59.71,180,56,180Zm144-32c-3.71,0-18-1.87-19.81-10.18L200,88.31l19.81,49.51C218,146.13,203.71,148,200,148Z',
  download: 'M228,144v64a12,12,0,0,1-12,12H40a12,12,0,0,1-12-12V144a12,12,0,0,1,24,0v52H204V144a12,12,0,0,1,24,0Zm-108.49,8.49a12,12,0,0,0,17,0l40-40a12,12,0,0,0-17-17L140,115V32a12,12,0,0,0-24,0v83L96.49,95.51a12,12,0,0,0-17,17Z',
  palette: 'M203.57,51A107.9,107.9,0,0,0,20,128c0,44.72,27.6,82.25,72,97.94A36,36,0,0,0,140,192a12,12,0,0,1,12-12h46.21a35.79,35.79,0,0,0,35.1-28A108.6,108.6,0,0,0,236,127.09,107.23,107.23,0,0,0,203.57,51Zm6.34,95.67a11.91,11.91,0,0,1-11.7,9.3H152a36,36,0,0,0-36,36,12,12,0,0,1-16,11.3c-16.65-5.88-30.65-15.76-40.48-28.56A76,76,0,0,1,44,128a84,84,0,0,1,83.13-84H128a84.35,84.35,0,0,1,84,83.29A84.72,84.72,0,0,1,209.91,146.71ZM144,76a16,16,0,1,1-16-16A16,16,0,0,1,144,76Zm-44,24A16,16,0,1,1,84,84,16,16,0,0,1,100,100Zm0,56a16,16,0,1,1-16-16A16,16,0,0,1,100,156Zm88-56a16,16,0,1,1-16-16A16,16,0,0,1,188,100Z',
  shapes: 'M71.49,60.55a12,12,0,0,0-23,0l-36,120A12,12,0,0,0,24,196H96a12,12,0,0,0,11.49-15.45ZM40.13,172,60,105.76,79.87,172ZM212,74a54,54,0,1,0-54,54A54.06,54.06,0,0,0,212,74Zm-84,0a30,30,0,1,1,30,30A30,30,0,0,1,128,74Zm96,70H136a12,12,0,0,0-12,12v52a12,12,0,0,0,12,12h88a12,12,0,0,0,12-12V156A12,12,0,0,0,224,144Zm-12,52H148V168h64Z',
  printer: 'M214.67,68H204V40a12,12,0,0,0-12-12H64A12,12,0,0,0,52,40V68H41.33C25.16,68,12,80.56,12,96v80a12,12,0,0,0,12,12H52v28a12,12,0,0,0,12,12H192a12,12,0,0,0,12-12V188h28a12,12,0,0,0,12-12V96C244,80.56,230.84,68,214.67,68ZM76,52H180V68H76ZM180,204H76V172H180Zm40-40H204v-4a12,12,0,0,0-12-12H64a12,12,0,0,0-12,12v4H36V96c0-2.17,2.44-4,5.33-4H214.67c2.89,0,5.33,1.83,5.33,4Zm-16-44a16,16,0,1,1-16-16A16,16,0,0,1,204,120Z',
  shieldCheck: 'M208,36H48A20,20,0,0,0,28,56v56c0,54.29,26.32,87.22,48.4,105.29,23.71,19.39,47.44,26,48.44,26.29a12.1,12.1,0,0,0,6.32,0c1-.28,24.73-6.9,48.44-26.29,22.08-18.07,48.4-51,48.4-105.29V56A20,20,0,0,0,208,36Zm-4,76c0,35.71-13.09,64.69-38.91,86.15A126.28,126.28,0,0,1,128,219.38a126.14,126.14,0,0,1-37.09-21.23C65.09,176.69,52,147.71,52,112V60H204ZM79.51,144.49a12,12,0,1,1,17-17L112,143l47.51-47.52a12,12,0,0,1,17,17l-56,56a12,12,0,0,1-17,0Z',
};

/** Attribute-safe text. The nav's slug payload is JSON inside an attribute. */
function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/'/g, '&#39;');
}

function ph(path: string, size = 18): string {
  return `<svg width="${size}" height="${size}" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="${path}"/></svg>`;
}

// Switzerland flag uses its own viewBox.
const CH_FLAG =
  '<svg width="13" height="13" viewBox="0 0 32 32" aria-hidden="true" style="vertical-align:-1.5px;border-radius:2px"><rect width="32" height="32" fill="#da291c"/><rect x="13" y="6" width="6" height="20" fill="#fff"/><rect x="6" y="13" width="20" height="6" fill="#fff"/></svg>';

// Every brand mark (header logo, footer wordmark) points at the marketing
// homepage in the page's own language, and has to name the locale slug to do
// it: the apex '/' is the smart entry, so it drops a signed-in reader into
// their account instead of the homepage. Opening the app is the App button's
// job, and it names the app host.
// Spec: ops/docs/domain-split.md
const HOME_EN = '/en';

// The 24-box stroke family of the rail rows below.
const ICON =
  '<svg width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';

// The homepage rail's own Phosphor glyphs (bold, the app-wide weight), so the
// demo pill and the App button draw the same marks on both headers.
const phosphor = (icon: typeof SignIn, size: number) =>
  renderToStaticMarkup(createElement(icon, { size, weight: 'bold', 'aria-hidden': true }));
const APP_ICON = phosphor(SignIn, 15);
const DEMO_ICON = phosphor(ArrowUpRight, 13);

/**
 * Bug glyph for the /changelog rail's report row, drawn in the same 24-box
 * stroke family as the home/app pair rather than the Phosphor fill set, so
 * the one icon that lives in a rail row matches the rail's other strokes.
 * Plain geometry: a rounded body, a head cap, and six legs.
 */
export const BUG_ICON = `${ICON}<path d="M8 9a4 4 0 0 1 8 0"/><rect x="7" y="9" width="10" height="10" rx="5"/><line x1="3" y1="13" x2="7" y2="13"/><line x1="17" y1="13" x2="21" y2="13"/><line x1="4.5" y1="8" x2="7.5" y2="10"/><line x1="19.5" y1="8" x2="16.5" y2="10"/><line x1="4.5" y1="18.5" x2="7.5" y2="16.5"/><line x1="19.5" y1="18.5" x2="16.5" y2="16.5"/></svg>`;

/**
 * Chain link, for "copy a link to this". Shared so the Help entries' permalink
 * and the changelog's per-release permalink are ONE glyph: they are the same
 * affordance, and the Help side used to draw a pilcrow for it, which names a
 * paragraph rather than a link.
 */
export const LINK_ICON = `<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M10 13a5 5 0 0 0 7.54.54l3-3a5 5 0 0 0-7.07-7.07l-1.72 1.71"/><path d="M14 11a5 5 0 0 0-7.54-.54l-3 3a5 5 0 0 0 7.07 7.07l1.71-1.71"/></svg>`;

/**
 * GitHub mark for the /changelog rail's closed-issues row. The Phosphor fill
 * shape the footer and the Help feedback row use, at rail size: a brand mark
 * reads as "this leaves for GitHub" in a way a stroke glyph cannot.
 */
export const GITHUB_ICON = ph(P.github, 15);

/** RSS glyph for the /changelog rail's feed row. Same stroke family. */
export const RSS_ICON = `${ICON}<path d="M4 11a9 9 0 0 1 9 9"/><path d="M4 4a16 16 0 0 1 16 16"/><circle cx="5" cy="19" r="1.5"/></svg>`;

/**
 * Document-with-lines glyph, for the /changelog rail's plain-text row. Same
 * stroke family as the two rows above it; the lines say "text", which is the
 * whole difference between that row and the page it sits on.
 */
export const TEXT_ICON = `${ICON}<path d="M14 3H7a2 2 0 0 0-2 2v14a2 2 0 0 0 2 2h10a2 2 0 0 0 2-2V8z"/><polyline points="14 3 14 8 19 8"/><line x1="9" y1="13" x2="15" y2="13"/><line x1="9" y1="17" x2="13" y2="17"/></svg>`;

/**
 * The header's words come from the homepage's own catalog (`landing.json`,
 * `header.*` and `hero.tryDemo`), so a Help page in any language reads exactly
 * like the homepage rail in that language. A missing key falls back to
 * English, like i18next does on the homepage.
 */
type HeaderText = Record<'downloads' | 'help' | 'changelog' | 'themes' | 'roadmap' | 'sections' | 'tryDemo', string>;
const headerTextCache = new Map<string, HeaderText>();
function headerText(locale: string): HeaderText {
  const hit = headerTextCache.get(locale);
  if (hit) return hit;
  const read = (l: string) => {
    try {
      return JSON.parse(fs.readFileSync(new URL(`./src/locales/${l}/landing.json`, import.meta.url), 'utf8'));
    } catch {
      return {};
    }
  };
  const en = read('en');
  const own = locale === 'en' ? en : read(locale);
  const pick = (group: string, key: string): string => esc(own[group]?.[key] ?? en[group]?.[key] ?? key);
  const text: HeaderText = {
    downloads: pick('header', 'downloads'),
    help: pick('header', 'help'),
    changelog: pick('header', 'changelog'),
    themes: pick('header', 'themes'),
    roadmap: pick('header', 'roadmap'),
    sections: pick('header', 'sections'),
    tryDemo: pick('hero', 'tryDemo'),
  };
  headerTextCache.set(locale, text);
  return text;
}

const CARET_ICON =
  '<svg class="lm-caret" width="11" height="11" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.5" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="m6 9 6 6 6-6"/></svg>';
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
 * persists choices under the app's own language keys, and follows the link.
 *
 * Rendered twice per Help page - header rail and footer - the way the
 * homepage carries LanguageMenu in the nav and again at the end of
 * SiteFooter. `id` tells the two apart. `pathOf` maps a locale to the page
 * a pick lands on. `systemHref` is where System goes; without one the
 * menu routes System to the reader's own homepage, as the homepage does
 * (static-pages.js, `data-system-home`). Placement styling lives in CHROME_CSS.
 */
export function languageMenu(opts: {
  current: string;
  label: string;
  pathOf: (l: string) => string;
  locales?: readonly string[];
  id?: string;
  systemHref?: string;
}): string {
  const { current, label, pathOf, locales = Object.keys(LOCALE_TO_SLUG), id = 'lang-menu', systemHref } = opts;
  const rows = sortByNative([...locales]).map((l) => {
    const on = l === current;
    return `<a${on ? ' class="on"' : ''} href="${pathOf(l)}" hreflang="${l}" data-lang="${l}">${flagSvg(l)}<span>${esc(LANGUAGE_META[l].native)}</span>${on ? CHECK_ICON : ''}</a>`;
  }).join('\n');
  const prefixes: Record<string, string> = {};
  for (const l of locales) prefixes[l] = l === 'en' ? '' : LOCALE_TO_SLUG[l];
  const system = systemHref
    ? `<a href="${systemHref}" data-lang="system">`
    : `<a href="${HOME_EN}" data-lang="system" data-system-home>`;
  return `<details class="langmenu" id="${id}" data-locales="${esc(JSON.stringify(prefixes))}">
<summary aria-label="${esc(label)}">${flagSvg(current)}<span class="lm-name">${esc(LANGUAGE_META[current].native)}</span>${CARET_ICON}</summary>
<div class="langlist">
${system}${SYSTEM_ICON}<span>System</span></a>
${rows}
</div>
</details>`;
}

/** Which section owns the page, so its nav row can render active. */
export type NavSection = 'faq' | 'changelog' | 'themes' | 'roadmap';

/**
 * Social-card tags for the static pages. Each generator emits its own <head>
 * and inherits nothing from index.html, so without these a shared /help,
 * /changelog or /roadmap link previews as a bare line of text. Same 1200x630
 * card the SPA uses; twitter:card is what upgrades X from a thumbnail to the
 * large image. Bare apex on purpose: this identifies the site, it is not a link.
 */
export const OG_IMAGE_TAGS = `<meta property="og:image" content="${APEX_ORIGIN}/og-image.png">
<meta property="og:image:width" content="1200">
<meta property="og:image:height" content="630">
<meta name="twitter:card" content="summary_large_image">
<meta name="twitter:site" content="@PrivacyNotesApp">
<meta name="twitter:image" content="${APEX_ORIGIN}/og-image.png">`;

/**
 * og:locale for a static page. The Help pages ship in every locale and told
 * every scraper nothing about which one it was looking at, so a shared German
 * help link previewed with no language signal at all. English-only pages
 * (/changelog, /roadmap, /brand) pass no argument.
 */
export function ogLocaleTag(locale = 'en'): string {
  return `<meta property="og:locale" content="${ogLocale(locale)}">`;
}

/**
 * The one header for every static page, and the static twin of the homepage
 * header (LandingPage.tsx + HeaderRail in src/LandingNav.tsx): the same brand,
 * the same rail of Downloads plus NAV_SECTIONS, the same words from the
 * homepage catalog, then the language flag, theme toggle, Try the demo and
 * App. The page title sits in the page's own content column, never in this row.
 *
 * `active` marks the page's own section, the one thing the homepage rail has
 * no use for. `language` is the rail's language menu; pages that pass none get
 * one that lands on the homepage in the picked language, like the homepage
 * menu. `helpLocale` is the page's locale, when it has one.
 *
 * Spec: ops/docs/archive/ui-patterns.md section 50.
 */
export function siteNav(opts: {
  active?: NavSection;
  language?: string;
  helpLocale?: string;
} = {}): string {
  const { active, helpLocale } = opts;
  const locale = helpLocale ?? 'en';
  const home = LOCALE_TO_SLUG[locale] ?? HOME_EN;
  const text = headerText(locale);
  const language = opts.language ?? languageMenu({ current: locale, label: 'Language', pathOf: (l) => LOCALE_TO_SLUG[l] });
  const labelOf: Partial<Record<FooterIcon, string>> = {
    faq: text.help,
    changelog: text.changelog,
    themes: text.themes,
    roadmap: text.roadmap,
  };
  // The Help center is the one destination that exists in every language, so
  // its nav link carries a locale. Translated pages know theirs at build time
  // (helpLocale); the English-only pages cannot, so they ship /help plus the
  // slug table and static-pages.js re-points it at the reader's own language.
  // Spec: ops/docs/archive/ui-patterns.md section 50.
  const helpSlugs = JSON.stringify(
    Object.fromEntries(Object.keys(LOCALE_TO_SLUG).map((l) => [l, helpPath(l)]))
  );
  const sectionLinks = NAV_SECTIONS
    .map((l) => {
      const label = labelOf[l.icon] ?? l.short;
      const on = l.icon === active ? ' on' : '';
      const current = l.icon === active ? ' aria-current="page"' : '';
      if (l.icon === 'faq') {
        const href = helpLocale ? helpPath(helpLocale) : l.href;
        const data = helpLocale ? '' : ` data-help-locales='${esc(helpSlugs)}'`;
        return `<a class="btn btn-ghost${on} nav-help" href="${href}"${current}${data}>${iconSvg(l.icon, 15)}${label}</a>`;
      }
      return `<a class="btn btn-ghost${on}" href="${l.href}"${current}>${iconSvg(l.icon, 15)}${label}</a>`;
    })
    .join('\n');
  return `<div class="brand-row">
<a class="brand" href="${home}">
<img src="/privacy-notes.webp" width="64" height="64" alt="" aria-hidden="true" draggable="false">
<span class="name">${brandMark()}</span>
</a>
<div class="actions">
<nav class="nav-secs" aria-label="${text.sections}">
<a class="btn btn-ghost" href="${home}#downloads">${iconSvg('download', 15)}${text.downloads}</a>
${sectionLinks}
</nav>
<span class="nav-div" aria-hidden="true"></span>
<div class="nav-ctl">
${language}
${THEME_TOGGLE_BUTTON}
<a class="btn nav-demo" href="${DEMO_HREF}">${text.tryDemo}${DEMO_ICON}</a>
<a class="btn nav-app" href="${APP_ORIGIN}"><span class="btn-lbl">App</span>${APP_ICON}</a>
</div>
</div>
</div>`;
}

const YEAR = new Date().getFullYear();

// Maps a shared footer icon key (from src/footerData.ts) to its inline SVG.
// `size` is 18 in the footer columns and 15 in the header rail, which is the
// only reason it is a parameter - both renderers draw the same glyph.
function iconSvg(icon: FooterIcon, size = 18): string {
  switch (icon) {
    case 'github': return ph(P.github, size);
    case 'shield': return ph(P.shieldCheck, size);
    case 'faq': return ph(P.question, size);
    case 'changelog': return ph(P.list, size);
    case 'roadmap': return `<svg width="${size}" height="${size}" viewBox="0 0 256 256" aria-hidden="true"><path d="M72 102V132Q72 172 112 172H162" fill="none" stroke="currentColor" stroke-width="18" stroke-linecap="round" stroke-linejoin="round"/><circle cx="72" cy="76" r="26" fill="currentColor"/><circle cx="188" cy="172" r="26" fill="currentColor"/></svg>`;
    case 'x': return ph(P.x, size);
    case 'reddit': return ph(P.reddit, size);
    case 'mastodon': return ph(P.mastodon, size);
    case 'youtube': return ph(P.youtube, size);
    case 'facebook': return ph(P.facebook, size);
    case 'lock': return ph(P.lock, size);
    case 'file': return ph(P.file, size);
    case 'refund': return ph(P.refund, size);
    case 'scales': return ph(P.scales, size);
    case 'download': return ph(P.download, size);
    case 'brand': return ph(P.shapes, size);
    case 'themes': return ph(P.palette, size);
    case 'print': return ph(P.printer, size);
  }
}

// Builds the footer link columns from the shared data. The first column
// also carries the brand wordmark + version pill above its heading, to
// match the homepage footer. The FAQ and Download links can be re-pointed
// at a locale's hub (/de/faq) and homepage (/de#downloads) so a translated
// page's footer stays in-language.
function footerColumns(faqHref: string, home: string): string {
  return FOOTER_COLUMNS.map((col, i) => {
    const brand = i === 0
      ? `<a class="f-brand" href="${home}">
<img src="/privacy-notes.webp" width="26" height="26" alt="" aria-hidden="true" draggable="false">
${brandMark()}
</a>
<a class="f-ver" href="/changelog"><span class="f-dot"></span>v${VERSION}<span class="f-latest">latest</span></a>
`
      : '';
    const links = col.links
      .map((l) => {
        const ext = l.external ? ` target="_blank" rel="noopener noreferrer${l.relMe ? ' me' : ''}"` : '';
        const href =
          l.icon === 'faq' ? faqHref : l.icon === 'download' ? `${home}#downloads` : l.href;
        return `<a class="f-link" href="${href}"${ext}>${iconSvg(l.icon)}${l.label}</a>`;
      })
      .join('\n');
    return `<div class="f-col">
${brand}<div class="f-head">// ${col.heading}</div>
${links}
</div>`;
  }).join('\n');
}

/**
 * The footer's typewriter words for the page at `home` (a LOCALE_TO_SLUG
 * value), from the same `common.json` the app reads, English as the fallback.
 */
const footerLinesCache = new Map<string, FooterLinesText>();
function footerLinesText(home: string): FooterLinesText {
  const hit = footerLinesCache.get(home);
  if (hit) return hit;
  const locale = Object.keys(LOCALE_TO_SLUG).find((l) => LOCALE_TO_SLUG[l] === home) ?? 'en';
  const read = (l: string) => {
    try {
      return JSON.parse(fs.readFileSync(new URL(`./src/locales/${l}/common.json`, import.meta.url), 'utf8')).loading ?? {};
    } catch {
      return {};
    }
  };
  const en = read('en');
  const own = locale === 'en' ? en : read(locale);
  const list = (key: string): string[] => (Array.isArray(own[key]) ? own[key] : Array.isArray(en[key]) ? en[key] : []);
  const text: FooterLinesText = {
    lines: list('lines'),
    loadingOnly: list('loadingOnly'),
    pause: own.pause ?? en.pause ?? 'Pause the lines',
    play: own.play ?? en.play ?? 'Play the lines',
  };
  footerLinesCache.set(home, text);
  return text;
}

/**
 * Editorial dark footer with a locale-aware FAQ link + logo. Dark in both themes.
 *
 * `lang` slots the page's language menu into the bottom row, right-aligned
 * next to the legal text - the same place and the same control the homepage
 * footer ends on (SiteFooter.tsx renders `<LanguageMenu dropUp dark />`
 * there). Callers pass the SAME menu markup they hand to topBar(), so the
 * header and footer switchers are one builder over one data source, never
 * two lists that can drift. Pages that ship English-only (changelog,
 * roadmap) pass nothing and the row collapses to the legal block.
 */
export function siteFooterFor(faqHref: string, home = HOME_EN, lang = ''): string {
  return `<footer class="site-footer">
<style>${FOOTER_LINES_CSS}</style>
${footerLinesHtml(footerLinesText(home))}
<div class="f-inner">
<div class="f-grid">
${footerColumns(faqHref, home)}
</div>
<div class="f-bottom">
<div class="f-legal">
<p>Data Stored in ${CH_FLAG} Switzerland. Encrypted on your device.</p>
<p>No subscriptions. Just Software. Not a service. &copy; ${YEAR} <a href="https://lifetimelabs.dev" target="_blank" rel="noopener noreferrer">Lifetime Labs LLC</a>. All rights reserved. <a href="https://lifetimelabs.dev/contact/" target="_blank" rel="noopener noreferrer">Contact</a></p>
</div>
${lang}
</div>
</div>
${FOOTER_LINES_SCRIPT_TAG}
</footer>`;
}

/** English-footer convenience for the pages that stay unlocalized. */
export const SITE_FOOTER = siteFooterFor('/help');

/**
 * The PrivacyNotes wordmark for the pre-rendered static pages. The static-side
 * twin of src/Brand.tsx, and the ONLY place these two spans exist outside it;
 * `check:house` fails on a hand-written copy. One weight, because the wordmark
 * is the logo set in text and the mark beside it is Inter Bold 700.
 *
 * @param suffix The display domain form, `.app`. Nothing else belongs here.
 * Spec: ops/docs/design-decisions.md (PrivacyNotes brand spelling)
 */
export function brandMark(suffix = ''): string {
  return `<span class="pn-mark"><span class="pn-mark-a">Privacy</span>Notes${suffix}</span>`;
}

/**
 * Three grounds, one wordmark, and the two exceptions live here rather than in
 * the page that owns them so the whole rule reads in one place.
 *
 * Both halves are named, never inherited. The ink half inheriting was the bug:
 * inside a `.sub` or a `.lead` the blue stayed full strength and the ink went
 * --muted, so the mark read as two colors of text rather than as one wordmark.
 *
 * The blue half is Fold Blue, the blue of the logo files, on every ground and
 * in both themes; it does not follow --accent, which links and buttons do. The
 * ink half follows --fg, except on two fixed grounds: `.site-footer`, a dark
 * slab in both themes, and `.sheet`, the printable shortcut card in
 * help-page.ts, which is light paper in both themes and reads no theme vars.
 */
export const BRAND_CSS = `.pn-mark{font-weight:700;color:var(--fg)}
.pn-mark-a{color:#4F6BD5}
.site-footer .pn-mark{color:#fff}
.sheet .pn-mark{color:#15171a}`;

/**
 * Shared base + chrome CSS: reset, body, links, .wrap, the brand row and its
 * nav rail, buttons, the footer, AND the docs-style page shell every static
 * page now uses (.pcols grid, .rail-col sidebar, .search box, .count line).
 * Pages add their own theme vars (themeVarsCss) and body-specific styles.
 *
 * Relies on these shared vars: --bg, --fg, --muted, --faint, --line,
 * --accent, --imp-bg, --rail, --chip, --on-accent, --mark-fg. Every page must declare
 * all of them - --chip arrived with the shell (it backs .ichip and the
 * search box's clear button) and pages that predate it need it added.
 * --on-accent is the text color ON the accent fill: white in light, deep
 * navy in dark, because the dark accent (#4A90D9) does not carry white
 * text at AA (3.34:1).
 * --mark-fg is the search-highlight text, and it exists so a match does NOT
 * follow --accent. Two reasons: on the dark tinted chip the accent measures
 * 4.74:1 where the retired one measured 5.98:1, and an accent-colored word
 * inside a sentence reads as a link the reader cannot click. Light is the
 * accent value written out; dark is a lighter tint of it, 6.96:1 on the chip.
 *
 * The header controls sit in one recessed rail (.actions): everything
 * inside loses its border, so the App button is the only filled control
 * on the page. Spec: ops/docs/archive/ui-patterns.md section 50.
 */
/** The full-screen screenshot viewer of /changelog and /themes, opened by
 *  the lightbox in static-pages.js. */
export { LIGHTBOX_CSS } from './src/lightboxCss.ts';

export const CHROME_CSS = `${BRAND_CSS}
*{box-sizing:border-box}
html{-webkit-text-size-adjust:100%}
body{margin:0;background:var(--bg);color:var(--fg);font-family:-apple-system,BlinkMacSystemFont,"Segoe UI",Roboto,Helvetica,Arial,sans-serif;line-height:1.6;font-size:16px}
a{color:var(--accent);text-decoration:none}
a:hover{text-decoration:underline}
/* One width for every static page: the homepage header row (1216px, its
   max-w-7xl less padding), so the brand lines up with the rail column below
   it. The header needs that room for the full rail beside the big brand.
   Pages that want a narrower reading measure constrain their CONTENT (see the
   roadmap timeline), never the shell. */
.wrap{max-width:1264px;margin:0 auto;padding:40px 24px 64px}
.brand-row{display:flex;align-items:center;justify-content:space-between;gap:12px 24px;margin-bottom:36px}
.brand-row .brand{margin-bottom:0}
/* Nothing in the rail may shrink. Letting these flex down is what let the
   language menu ride on top of the Brand link instead of forcing the layout
   to admit it had run out of room. If a future control makes the rail too
   wide, it overflows visibly (and the breakpoint below needs raising) rather
   than silently overlapping. */
.nav-secs{display:flex;align-items:center;gap:2px;flex:0 0 auto}
.nav-ctl{display:flex;align-items:center;gap:2px;flex:0 0 auto}
.nav-secs .btn,.nav-ctl .btn,.nav-ctl .langmenu{flex:0 0 auto}
.nav-div{width:1px;height:20px;background:var(--line);margin:0 5px;flex:0 0 auto}
.brand{display:flex;align-items:center;gap:12px;margin-bottom:6px;text-decoration:none;color:var(--fg);width:max-content}
.brand:hover{text-decoration:none}
.brand img{width:64px;height:64px}
.brand .name{font-size:36px;line-height:40px;letter-spacing:-.025em}
h1{font-size:30px;font-weight:800;margin:10px 0 4px;letter-spacing:-.03em;text-wrap:balance}
h2,h3{text-wrap:balance}
p{text-wrap:pretty}
.sub{margin:0;color:var(--muted);font-size:15px}
/* Language menu, base rules. They live here rather than in help-page.ts
   because the menu now renders TWICE per page - once in the header rail,
   once in the footer - exactly like the homepage, whose LanguageMenu sits
   in the nav and again at the end of SiteFooter. Placement overrides for
   the rail (.actions ...) and the black footer (.site-footer ...) follow
   below; both out-specify these. */
.langmenu{position:relative}
.langmenu summary{display:inline-flex;align-items:center;gap:8px;padding:6px 12px 6px 8px;border:1px solid var(--line);border-radius:99px;font-size:13px;font-weight:600;cursor:pointer;color:var(--fg)}
.langmenu summary:hover{border-color:var(--faint)}
.langmenu summary::-webkit-details-marker{display:none}
.langmenu summary svg:first-child{border-radius:2px}
.lm-caret{color:var(--faint)}
.langlist{position:absolute;right:0;top:calc(100% + 8px);z-index:10;width:192px;display:flex;flex-direction:column;background:var(--bg);border:1px solid var(--line);border-radius:12px;padding:5px;box-shadow:0 10px 30px rgba(0,0,0,.14)}
.langlist a{display:flex;align-items:center;gap:10px;padding:7px 10px;border-radius:8px;font-size:13.5px;color:var(--fg);text-decoration:none}
.langlist a:hover{background:var(--imp-bg);text-decoration:none}
.langlist a svg:first-child{width:22px;height:16px;border-radius:2px;flex:0 0 auto}
.langlist a span{flex:1}
.langlist a.on{color:var(--accent);font-weight:600}
.actions{display:flex;align-items:center;gap:2px;min-width:0;background:var(--rail);border-radius:11px;padding:4px;font-size:13px;line-height:1}
.btn{display:inline-flex;align-items:center;gap:6px;font-size:13px;line-height:1;padding:8px 14px;border-radius:8px;text-decoration:none;white-space:nowrap}
.btn:hover{text-decoration:none}
.btn svg{flex:0 0 auto}
.btn-primary{background:var(--accent);color:var(--on-accent);font-weight:600}
.btn-primary:hover{filter:brightness(1.08)}
.btn-ghost{color:var(--fg);border:1px solid var(--line)}
.btn-ghost:hover{border-color:var(--faint)}
.actions .btn{border:0;padding:7px 11px}
.actions .btn-ghost{color:var(--fg);background:none}
.actions .btn-ghost:hover{color:var(--accent)}
.actions .btn-ghost svg{color:var(--accent)}
/* The section you are already on. Not a fill - the App button owns the only
   fill on the page - just the same tinted chip the rail rows use. */
.actions .btn-ghost.on{background:var(--imp-bg);color:var(--accent);font-weight:600}
.actions #theme-toggle{width:30px;height:29px;padding:0;justify-content:center}
.actions .langmenu summary{border:0;height:29px;padding:0 8px;gap:4px;font-weight:400;font-size:13px}
.actions .langmenu summary:hover{color:var(--accent)}
.actions .langmenu summary .lm-caret{color:currentColor}
/* Try the demo and App, in the homepage rail's amber and ink. The amber pair
   is the homepage's washi amber in each mode; the ink is the page's own text
   colour, so App flips with the theme the way the homepage one does. */
:root{--demo-bg:#F7EAB8;--demo-line:#B45309;--demo-fg:#92400E}
:root[data-theme=dark]{--demo-bg:#2C230F;--demo-line:rgba(251,191,36,.55);--demo-fg:#FBBF24}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){--demo-bg:#2C230F;--demo-line:rgba(251,191,36,.55);--demo-fg:#FBBF24}}
.actions .nav-demo{margin-left:2px;padding:6px 11px;border:1px solid var(--demo-line);background:var(--demo-bg);color:var(--demo-fg);font-weight:600}
.actions .nav-demo:hover{color:var(--demo-fg);filter:brightness(.95)}
@property --pn-spin{syntax:"<angle>";initial-value:0deg;inherits:false}
@keyframes pn-spin{to{--pn-spin:360deg}}
.actions .nav-app{margin-left:2px;padding:5px 12px;border:2px solid transparent;font-weight:600;color:var(--bg);background:linear-gradient(var(--fg),var(--fg)) padding-box,linear-gradient(var(--fg),var(--fg)) border-box}
.actions .nav-app:hover{color:var(--bg);background:linear-gradient(var(--fg),var(--fg)) padding-box,conic-gradient(from var(--pn-spin,0deg),var(--fg) 0 70%,var(--accent) 80%,#f59e0b 90%,var(--fg) 100%) border-box;animation:pn-spin 1.2s linear infinite}
@media(hover:none),(prefers-reduced-motion:reduce){.actions .nav-app:hover{animation:none}}
/* Flag only in the HEADER rail; the footer switcher keeps its name. Spelling
   the language out here costs 90-140px depending on the locale, and Portuguese
   ("Portugues (Brasil)") pushed the rail past the page width - it
   overlapped the Brand link on a desktop monitor, not just a narrow one. The
   flag names the language, and the list one click away spells every one of
   them out. Spec: ops/docs/archive/ui-patterns.md section 50. */
.actions .langmenu summary .lm-name{display:none}
/* Two columns that mirror the header row: the rail sits under the brand,
   and the content column ends under the App button, so it starts about
   where the nav rail starts. The space between them grows on wide screens,
   which keeps the text at a reading measure without a gap on the right. */
.pcols{display:grid;grid-template-columns:minmax(208px,272px) minmax(0,800px);justify-content:space-between;grid-template-rows:auto auto 1fr;grid-template-areas:'rail crumb' 'rail head' 'rail body';column-gap:44px;align-items:start;margin-top:4px}
.col-head{grid-area:head;min-width:0}
.col-body{grid-area:body;min-width:0}
.col-head h1{margin:0 0 6px;text-wrap:pretty}
.col-head .sub{margin:0 0 4px}
/* The sticky rail scrolls itself once it is taller than the window. Without
   the cap it stays pinned at top:20px and everything past the fold is
   unreachable until you scroll the whole article to its end - on the Help
   hub, where the rail carries the topics, the documents and every import
   guide, that is half the menu on a laptop window. */
.rail-col{grid-area:rail;align-self:start;position:sticky;top:20px;max-height:calc(100dvh - 40px);overflow-y:auto;overscroll-behavior:contain;scrollbar-width:thin;scrollbar-color:color-mix(in srgb,var(--fg) 30%,transparent) transparent;display:flex;flex-direction:column}
/* The rail's own scrollbar: thin, on a transparent track, and tinted from
   the text colour rather than a surface token, because the two grounds pull
   in opposite directions - a thumb light enough to recede on the dark page
   disappears entirely on the white one. A reader whose system draws
   permanent scrollbars otherwise gets a 15px slab beside a 208px column,
   heavier than the menu it belongs to. The cut-off row is the affordance;
   the bar only has to be findable. Chrome takes scrollbar-width/-color and
   ignores the block below, which is Safari's path to the same look. */
.rail-col::-webkit-scrollbar{width:8px}
.rail-col::-webkit-scrollbar-track{background:transparent}
.rail-col::-webkit-scrollbar-thumb{background:color-mix(in srgb,var(--fg) 30%,transparent);border-radius:99px}
.rail-col::-webkit-scrollbar-thumb:hover{background:var(--faint)}
.rail{display:flex;flex-direction:column;gap:2px}
.rail .eyebrow{margin:0 4px 8px}
.rail .rail-sep{margin-top:22px}
.ritem{display:flex;align-items:center;gap:9px;padding:6px 10px;border-radius:8px;font-size:13.5px;color:var(--muted);text-decoration:none}
.ritem:hover{background:var(--imp-bg);color:var(--accent);text-decoration:none}
.ritem.on{background:var(--imp-bg);color:var(--accent);font-weight:600}
.ritem.dim{opacity:.45}
.rhome{color:var(--fg);font-weight:600}
.ritem svg{flex:0 0 auto;color:var(--faint)}
.ritem:hover svg,.ritem.on svg{color:var(--accent)}
.ichip{flex:0 0 auto;width:22px;height:22px;border-radius:6px;background:var(--chip);display:inline-flex;align-items:center;justify-content:center}
.ichip img{width:18px;height:18px;object-fit:contain}
.rlbl{flex:1;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.rct{flex:0 0 auto;color:var(--faint);font-size:12px;font-variant-numeric:tabular-nums}
.search{display:flex;align-items:center;gap:10px;border:1px solid var(--line);border-radius:12px;padding:12px 14px;margin:18px 0 0;background:var(--bg)}
.search[hidden]{display:none}
.search:focus-within{border-color:var(--accent)}
.search svg{flex:0 0 auto;color:var(--faint)}
.search input{flex:1;min-width:0;border:0;outline:0;background:transparent;color:var(--fg);font-size:15px;font-family:inherit}
.search input::-webkit-search-cancel-button{-webkit-appearance:none;appearance:none}
.search kbd{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:var(--faint);border:1px solid var(--line);border-radius:5px;padding:2px 7px}
.sclear{flex:0 0 auto;display:none;align-items:center;justify-content:center;width:24px;height:24px;padding:0;border:0;border-radius:7px;background:none;color:var(--faint);cursor:pointer}
.sclear:hover{background:var(--chip);color:var(--fg)}
.search.has-q .sclear{display:inline-flex}
mark{background:var(--imp-bg);color:var(--mark-fg);border-radius:3px;padding:0 1px}
.count{font-size:13px;color:var(--faint);margin:10px 2px 4px;min-height:18px}
.noresults{margin:6px 0 0}
.noresults p{margin:0 0 14px;font-size:15.5px;color:var(--muted)}
.noresults .btn{background:none;font-family:inherit;cursor:pointer}
/* Mid widths: the text needs the room more than the rail does. */
@media(max-width:1099px){.pcols{grid-template-columns:208px minmax(0,1fr)}}
@media(max-width:860px){
.pcols{grid-template-columns:minmax(0,1fr);grid-template-rows:none;grid-template-areas:'head' 'rail' 'body';margin-top:2px}
/* Un-stick the rail. In one column it is a band between the title and the
   body, and a sticky band pins itself over the article as you scroll - it
   reads as a z-index bug but it is the sticky from the two-column layout
   never being switched off. Pages whose rail becomes display:contents here
   (the Help leaves) out-specify this. */
.rail-col{position:static;max-height:none;overflow:visible;margin:14px 0 20px;padding-bottom:16px;border-bottom:1px solid var(--line)}
.rail{flex-direction:row;flex-wrap:wrap;gap:6px}
.rail .eyebrow{flex:1 1 100%;margin:2px 2px 4px}
/* A second group's heading needs air above it. In the column layout the
   22px top margin does that job; wrapped into rows the groups ran together
   and the heading read as a label for the pills ABOVE it. */
.rail + .rail{margin-top:16px}
.rail .rail-sep{margin-top:0}
.ritem{flex:0 0 auto;white-space:nowrap;border:1px solid var(--line);border-radius:99px;padding:5px 11px;font-size:12.5px;gap:7px}
.ritem .rct{font-size:11px}
.rlbl{flex:none;overflow:visible}
.ritem.on{border-color:transparent}
.ichip{width:18px;height:18px;border-radius:5px}
.ichip img{width:15px;height:15px}
}
.eyebrow{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.16em;color:var(--faint);margin:0}
.site-footer{background:var(--footer,#161210);border-top:1px solid var(--line);margin-top:64px}
.f-inner{max-width:1264px;margin:0 auto;padding:44px 24px 40px}
.f-grid{display:grid;grid-template-columns:repeat(4,1fr);gap:28px 24px}
.f-col{display:flex;flex-direction:column;align-items:flex-start;gap:9px}
.f-brand{display:flex;align-items:center;gap:9px;font-weight:700;color:#fff;text-decoration:none;font-size:15px}
.f-brand:hover{text-decoration:none}
.f-ver{display:inline-flex;align-items:center;gap:7px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#A69E8F;text-decoration:none;border:1px solid #2E2820;border-radius:999px;padding:4px 10px}
.f-ver:hover{color:#fff;border-color:#3D362A;text-decoration:none}
.f-dot{width:6px;height:6px;border-radius:50%;background:#4ade80;box-shadow:0 0 0 3px rgba(74,222,128,.15);flex:0 0 auto}
.f-latest{color:#8F8776}
.f-head{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px;font-weight:600;text-transform:uppercase;letter-spacing:.18em;color:#8F8776;margin:6px 0 2px}
.f-col:first-child .f-head{margin-top:14px}
.f-link{display:inline-flex;align-items:center;gap:8px;color:#A69E8F;font-size:14px;text-decoration:none}
.f-link:hover{color:#fff;text-decoration:none}
.f-link svg{flex:0 0 auto}
.f-bottom{margin-top:36px;padding-top:24px;border-top:1px solid #2E2820;font-size:13px;color:#A69E8F;display:flex;flex-direction:column;gap:16px}
.f-bottom p{margin:0 0 4px}
.f-bottom p:last-child{margin-bottom:0}
/* Scoped to .f-legal, NOT .f-bottom: the row now also holds the language
   menu, whose list is a light panel. Hanging these off .f-bottom painted
   its rows white-on-pale-blue, i.e. invisible. They only ever meant the
   Lifetime Labs + Contact links. NOTE: no backticks in this comment - it
   lives inside a template literal. */
.f-legal a{color:#A69E8F}
.f-legal a:hover{color:#fff;text-decoration:none}
/* Footer placement of the language menu. The slab is dark in BOTH themes,
   so the pill takes the homepage footer's dark-surface treatment (white/10
   on white/15) instead of the page's theme vars, and the list drops UP -
   it sits at the very bottom of the document. The list keeps the page
   theme (white in light, near-black in dark) rather than the homepage's
   always-white panel, which would flare on a dark-mode page. */
.site-footer .langmenu{flex:0 0 auto}
.site-footer .langmenu summary{padding:5px 11px 5px 8px;font-weight:500;color:#e5e5e5;background:rgba(255,255,255,.1);border-color:rgba(255,255,255,.15)}
.site-footer .langmenu summary:hover{background:rgba(255,255,255,.2);border-color:rgba(255,255,255,.15)}
.site-footer .lm-caret{color:#A69E8F}
.site-footer .langlist{top:auto;bottom:calc(100% + 8px);box-shadow:0 10px 30px rgba(0,0,0,.4)}
@media(min-width:601px){
.f-bottom{flex-direction:row;align-items:center;justify-content:space-between;gap:24px}
}
/* Below lg the brand steps down a size, as the homepage brand does. */
@media(max-width:1023px){
.brand{gap:8px}
.brand img{width:32px;height:32px}
.brand .name{font-size:18px;line-height:28px}
}
/* Once the sections no longer fit beside the brand and the controls, they
   drop to their own full-width strip that scrolls horizontally, and the rail
   shrinks to wrap only the controls. The homepage folds into Explore here;
   these pages ship no menu script, so they take the strip.
   Setting display:contents on .actions is what makes that possible without a
   second markup tree: its three children (strip, divider, controls) become
   grid items of .brand-row and can be placed on separate rows. Nothing is
   duplicated and there is no disclosure to open.
   The breakpoint is measured, not guessed: the widest header is a translated
   Help page, and it must switch BEFORE the pieces meet. Re-measure it if a
   section is added - the brand-row element's scrollWidth is the number.
   NOTE: no backticks in this comment - it lives inside a template literal,
   and a stray one closes it and breaks the whole config load.
   Spec: ops/docs/archive/ui-patterns.md section 50. */
@media(max-width:1279px){
.brand-row{display:grid;grid-template-columns:minmax(0,1fr) auto;align-items:center;gap:14px 12px}
.actions{display:contents}
.brand{grid-column:1;grid-row:1}
.nav-ctl{grid-column:2;grid-row:1;background:var(--rail);border-radius:11px;padding:4px}
.nav-div{display:none}
/* min-width:0 is load-bearing: a grid item defaults to min-width:auto, so the
   strip would size to its content and push the PAGE into a horizontal scroll
   instead of scrolling inside itself. */
.nav-secs{grid-column:1/-1;grid-row:2;min-width:0;overflow-x:auto;scrollbar-width:none;gap:6px;padding-bottom:2px}
.nav-secs::-webkit-scrollbar{display:none}
.nav-secs .btn{flex:0 0 auto;border:1px solid var(--line);border-radius:99px;padding:5px 11px;font-size:12.5px;gap:7px;color:var(--muted)}
.nav-secs .btn-ghost.on{background:var(--imp-bg);color:var(--accent);border-color:transparent;font-weight:600}
.nav-secs .btn-ghost.on svg{color:var(--accent)}
}
/* Phone widths. The brand and the controls have to share one line, so the
   demo pill goes first, as it does on the homepage, and below 430px App falls
   back to its glyph. The min-width:0 + ellipsis on the wordmark is the
   guarantee, not the plan - at the narrowest widths the name truncates
   instead of sliding under the controls, so no width can produce an overlap. */
@media(max-width:640px){
.nav-ctl .nav-demo{display:none}
}
@media(max-width:600px){
.wrap{padding:28px 18px 56px}
h1{font-size:26px}
.f-grid{grid-template-columns:repeat(2,1fr);gap:28px 20px}
/* width:max-content on the base .brand rule beats min-width:0, so the name
   would not shrink and rode over the controls at 320px. Both are needed. */
.brand{min-width:0;width:auto;gap:9px}
.brand .name{overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
}
@media(max-width:430px){
.nav-ctl .nav-app .btn-lbl{display:none}
.nav-ctl .nav-app{padding:5px 9px}
}`;
