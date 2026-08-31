import { transformWithOxc, type Plugin } from 'vite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { THEME_SCRIPT_TAG, THEME_TOGGLE_CSS, themeVarsCss } from './static-page-theme.ts';
import { brandMark, BUG_ICON, CHROME_CSS, LINK_ICON, OG_IMAGE_TAGS, ogLocaleTag, RSS_ICON, SITE_FOOTER, siteNav, TEXT_ICON } from './static-page-chrome.ts';

// Pre-renders a static /changelog page from the single source of
// truth: src/publicChangelog.ts. Emitted as changelog/index.html so
// Cloudflare Pages serves it directly at /changelog (a real file always
// wins over the SPA fallback), and it stays in sync with the in-app
// changelog because both read the same array. The same array also emits
// changelog/feed.xml and changelog.md, the plain-text twin AI agents read.
//
// The page uses the shared docs shell from static-page-chrome.ts (.pcols
// grid, 208px .rail-col, .search box) - the same skeleton as /help, at the
// same width. The rail carries the filters, the content column carries the
// search; /static-pages.js wires both.
//
// EVERY release is in the DOM, always. The 25-at-a-time reveal is done by
// hiding, never by truncating at build time, so a reader without JS and a
// crawler both get the complete history - and so a #v0.180 permalink can be
// expanded to instead of 404ing into a collapsed list.
//
// The page ships zero inline scripts: the deployed CSP allows
// 'unsafe-inline' for style-src but NOT script-src, so inline <script>
// would be blocked. The only JS is the external same-origin
// /theme-toggle.js + /static-pages.js, shared via static-page-theme.ts
// and public/static-pages.js. Anything the JS owns (type filters, the
// search box, the load-more button) ships with the `hidden` attribute so a
// no-JS reader never sees a dead control; the month index does NOT, because
// its rows are real anchors that work either way.
//
// The changelog stays English-only by policy (ops/docs/i18n-spec.md,
// translation tiers): it churns with every release and the audience
// reads English, so there are no locale variants of this page.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const CHANGELOG_SRC = path.resolve(__dirname, 'src/publicChangelog.ts');

const ORIGIN = 'https://privacynotes.app';
const FEED_PATH = '/changelog/feed.xml';
/** The plain-text twin, for AI agents. See renderMd. */
const MD_PATH = '/changelog.md';

/** How many releases are visible before the reader asks for more. */
// Spec: ops/docs/ui-patterns.md section 58 (changelog rail + reveal)
const PAGE_SIZE = 25;

type ChangelogItem = { type: 'new' | 'improved' | 'fixed'; text: string };
type ChangelogRelease = {
  version: string;
  date: string;
  title: string;
  items: ChangelogItem[];
};

// Transpile publicChangelog.ts (a self-contained module with no imports)
// with Oxc and import it as a data-URL ES module to pull out the data.
// Avoids a second copy of the changelog or a brittle regex parse.
export async function loadReleases(): Promise<ChangelogRelease[]> {
  const src = fs.readFileSync(CHANGELOG_SRC, 'utf8');
  const { code } = await transformWithOxc(src, CHANGELOG_SRC, { lang: 'ts' });
  const module = (await import(
    'data:text/javascript;base64,' + Buffer.from(code).toString('base64')
  )) as Record<string, unknown>;
  // The public /changelog page renders the full history (no cap); only the
  // in-app changelog is trimmed, by IN_APP_CHANGELOG_LIMIT.
  return module.PUBLIC_CHANGELOG as ChangelogRelease[];
}

const LABEL: Record<ChangelogItem['type'], string> = {
  new: 'New',
  improved: 'Improved',
  fixed: 'Fixed',
};

const TYPES: Array<ChangelogItem['type']> = ['new', 'improved', 'fixed'];

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

function fmtDate(iso: string): string {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'short',
    day: 'numeric',
    timeZone: 'UTC',
  });
}

function fmtMonth(iso: string): string {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString('en-US', {
    year: 'numeric',
    month: 'long',
    timeZone: 'UTC',
  });
}

/** Month name alone, for the rail rows that already sit under a year eyebrow. */
function monthName(iso: string): string {
  return new Date(`${iso}T00:00:00Z`).toLocaleDateString('en-US', {
    month: 'long',
    timeZone: 'UTC',
  });
}

/** Stable month key, and the id its eyebrow carries: 2026-08. */
function monthKey(iso: string): string {
  return iso.slice(0, 7);
}

/**
 * Everything a query can match on one release, lowercased: title, every item
 * body, the version, and the date in both the shapes a reader might type
 * ("0.294", "august", "aug 4, 2026", "2026-08-04"). Matching only the prose
 * would make the obvious searches - a version number, a month - come back
 * empty on a page whose whole job is versions and months.
 */
function haystack(r: ChangelogRelease): string {
  return (
    [
      r.title,
      r.items.map((i) => `${LABEL[i.type]} ${i.text}`).join(' '),
      `v${r.version}`,
      r.version,
      r.date,
      fmtDate(r.date),
      fmtMonth(r.date),
    ].join(' ')
    // Must match norm() in public/static-pages.js exactly: that function
    // strips diacritics off the QUERY, so a haystack that keeps them would
    // silently stop matching every accented word.
  )
    .normalize('NFD')
    .replace(/[̀-ͯ]/g, '')
    .toLowerCase();
}

const SEARCH_ICON =
  '<svg width="18" height="18" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="11" cy="11" r="7"/><line x1="21" y1="21" x2="16.65" y2="16.65"/></svg>';

const CLEAR_ICON =
  '<svg width="14" height="14" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" aria-hidden="true"><line x1="5" y1="5" x2="19" y2="19"/><line x1="19" y1="5" x2="5" y2="19"/></svg>';

const CHEVRON_ICON =
  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="6 9 12 15 18 9"/></svg>';

const STACK_ICON =
  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><polyline points="3 12 12 17 21 12"/><polyline points="3 17 12 22 21 17"/><polygon points="12 2 3 7 12 12 21 7 12 2"/></svg>';

const TYPE_ICON: Record<ChangelogItem['type'], string> = {
  new: '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M12 3v4M12 17v4M3 12h4M17 12h4M5.6 5.6l2.8 2.8M15.6 15.6l2.8 2.8M18.4 5.6l-2.8 2.8M8.4 15.6l-2.8 2.8"/></svg>',
  improved:
    '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="6" y1="18" x2="18" y2="6"/><polyline points="10 6 18 6 18 14"/></svg>',
  fixed: BUG_ICON.replace('width="15" height="15"', 'width="16" height="16"'),
};

function renderReleases(releases: ChangelogRelease[]): string {
  let prevMonth: string | null = null;
  return releases
    .map((r, index) => {
      const items = r.items
        .map(
          (it) =>
            `<li class="item" data-t="${it.type}"><span class="tag tag-${it.type}">${LABEL[it.type]}</span><span class="txt">${esc(it.text)}</span></li>`
        )
        .join('');
      const key = monthKey(r.date);
      const month = fmtMonth(r.date);
      const monthHead =
        month !== prevMonth
          ? `<h2 class="eyebrow cl-month" id="m-${key}">// ${esc(month)}</h2>\n`
          : '';
      prevMonth = month;
      const latest = index === 0 ? '<span class="latest">Latest</span>' : '';
      return `${monthHead}<article class="release" id="v${esc(r.version)}" data-m="${key}" data-s="${esc(haystack(r))}">
<div class="meta"><span class="vpill">v${esc(r.version)}</span><div class="date">${fmtDate(r.date)}</div>${latest}</div>
<div class="body"><div class="rhead"><h3>${esc(r.title)}</h3><button type="button" class="perma" data-v="v${esc(r.version)}" aria-label="Copy link to v${esc(r.version)}" title="Copy link" hidden>${LINK_ICON}</button></div><ul class="items">${items}</ul></div>
</article>`;
    })
    .join('\n');
}

/** Per-type item counts across the whole history, for the rail rows. */
function typeCounts(releases: ChangelogRelease[]): Record<string, number> {
  const counts: Record<string, number> = { new: 0, improved: 0, fixed: 0 };
  for (const r of releases) for (const it of r.items) counts[it.type]++;
  return counts;
}

/** Releases per month, newest first, grouped under their year. */
function monthIndex(releases: ChangelogRelease[]): Array<{ year: string; months: Array<{ key: string; name: string; count: number }> }> {
  const counts = new Map<string, number>();
  for (const r of releases) {
    const key = monthKey(r.date);
    counts.set(key, (counts.get(key) ?? 0) + 1);
  }
  const years: Array<{ year: string; months: Array<{ key: string; name: string; count: number }> }> = [];
  for (const [key, count] of counts) {
    const year = key.slice(0, 4);
    let bucket = years.find((y) => y.year === year);
    if (!bucket) {
      bucket = { year, months: [] };
      years.push(bucket);
    }
    bucket.months.push({ key, name: monthName(`${key}-01`), count });
  }
  return years;
}

function renderRail(releases: ChangelogRelease[]): string {
  const counts = typeCounts(releases);
  const totalItems = TYPES.reduce((n, t) => n + counts[t], 0);
  const typeRows = [
    `<a class="ritem ct on" href="#" data-t="all">${STACK_ICON}<span class="rlbl">Everything</span><span class="rct">${totalItems}</span></a>`,
    ...TYPES.map(
      (t) =>
        `<a class="ritem ct" href="#" data-t="${t}">${TYPE_ICON[t]}<span class="rlbl">${LABEL[t]}</span><span class="rct">${counts[t]}</span></a>`
    ),
  ].join('\n');

  // The type rows only mean anything with JS behind them, so they ship
  // hidden like the search box does. The month rows below are real anchors
  // to the month eyebrows and work either way, so they never hide.
  const months = monthIndex(releases)
    .map(
      (y) => `<nav class="rail rail-months" aria-label="Releases in ${y.year}">
<p class="eyebrow rail-sep">// ${y.year}</p>
${y.months
  .map(
    (m) =>
      `<a class="ritem cm" href="#m-${m.key}" data-m="${m.key}"><span class="rlbl">${m.name}</span><span class="rct">${m.count}</span></a>`
  )
  .join('\n')}
</nav>`
    )
    .join('\n');

  return `<div class="rail-col" id="cl-rail">
<nav class="rail rail-types" id="cl-types" aria-label="Filter by type" hidden>
<p class="eyebrow">// Type</p>
${typeRows}
</nav>
${months}
<div class="rail rail-extra">
<a class="ritem r-bug" href="https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues" target="_blank" rel="noopener noreferrer">${BUG_ICON}<span class="rlbl">Report a bug</span></a>
<a class="ritem r-rss" href="${FEED_PATH}">${RSS_ICON}<span class="rlbl">RSS feed</span></a>
<a class="ritem r-md" href="${MD_PATH}">${TEXT_ICON}<span class="rlbl">Plain text for AI</span></a>
</div>
</div>`;
}

const PAGE_CSS = `.cl-month{margin:30px 0 4px;scroll-margin-top:16px}
.cl-month:first-of-type{margin-top:16px}
.release{display:flex;gap:24px;padding:26px 0;border-top:1px solid var(--line);scroll-margin-top:16px}
.cl-month + .release{border-top:0}
.release[hidden],li.item[hidden],.cl-month[hidden],.rail[hidden]{display:none}
.meta{flex:0 0 104px;display:flex;flex-direction:column;align-items:flex-start;gap:5px;padding-top:2px}
.vpill{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11.5px;font-weight:600;color:var(--accent);background:var(--imp-bg);padding:3px 8px;border-radius:7px}
.date{font-size:12.5px;color:var(--faint)}
.latest{font-size:10px;font-weight:600;letter-spacing:.08em;text-transform:uppercase;color:var(--new-fg);background:var(--new-bg);padding:2px 7px;border-radius:6px}
.body{flex:1;min-width:0}
.rhead{display:flex;align-items:flex-start;gap:8px;margin:0 0 16px}
.body h3{font-size:18px;font-weight:600;margin:0;letter-spacing:-.01em;flex:1;min-width:0}
/* Revealed on hover like the Help leaves' perma, and always visible once
   focused so it is reachable from the keyboard. */
.perma{flex:0 0 auto;display:inline-flex;align-items:center;padding:2px;margin-top:2px;border:0;background:none;color:var(--faint);cursor:pointer;opacity:0;transition:opacity .12s ease}
.perma[hidden]{display:none}
.release:hover .perma,.perma:focus-visible{opacity:1}
.perma:hover{color:var(--accent)}
.perma.done{opacity:1;color:var(--new-fg)}
.items{list-style:none;margin:0;padding:0}
.item{display:flex;gap:10px;margin-bottom:11px;align-items:flex-start}
.item:last-child{margin-bottom:0}
.txt{font-size:15px;color:var(--fg)}
.tag{flex:0 0 auto;width:66px;text-align:center;font-size:11px;font-weight:600;letter-spacing:.01em;padding:3px 0;border-radius:6px;margin-top:1px}
.tag-new{background:var(--new-bg);color:var(--new-fg)}
.tag-improved{background:var(--imp-bg);color:var(--imp-fg)}
.tag-fixed{background:var(--fix-bg);color:var(--fix-fg)}
.rail-extra{margin-top:24px;padding-top:18px;border-top:1px solid var(--line)}
/* The only red control on the site's static pages: it is the only one that
   files something against us, and it should not read as a section link. */
.r-bug{color:var(--bad)}
.r-bug svg{color:var(--bad)}
.r-bug:hover{background:var(--bad-bg);color:var(--bad)}
.r-bug:hover svg{color:var(--bad)}
.cl-more{margin:4px 0 0;padding-top:26px;border-top:1px solid var(--line);display:flex;flex-direction:column;align-items:center;gap:10px}
.cl-more[hidden]{display:none}
.cl-more button{display:inline-flex;align-items:center;gap:8px;font-size:14px;font-weight:600;font-family:inherit;color:var(--fg);background:none;border:1px solid var(--line);border-radius:10px;padding:11px 20px;cursor:pointer}
.cl-more button:hover{border-color:var(--faint);color:var(--accent)}
.cl-more button:hover svg{color:var(--accent)}
.cl-more svg{color:var(--faint)}
.cl-rest{font-size:12.5px;color:var(--faint)}
.cl-origin{margin:34px 0 0;padding:22px 24px;border:1px solid var(--line);border-radius:12px;background:var(--card)}
.cl-origin .eyebrow{margin:0 0 10px}
.cl-origin p{margin:0;font-size:15px;line-height:1.62;color:var(--muted)}
@media(max-width:860px){
.rail-extra{margin-top:14px;padding-top:0;border-top:0}
}
@media(max-width:600px){
.release{flex-direction:column;gap:10px;padding:22px 0}
.meta{flex-direction:row;align-items:center;gap:8px;flex:none;padding-top:0}
.tag{width:60px}
.cl-origin{padding:20px}
}`;

export function renderHtml(releases: ChangelogRelease[]): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Changelog - PrivacyNotes</title>
<meta name="description" content="The latest updates to PrivacyNotes: your encrypted notes, tasks, files, and vault.">
<link rel="canonical" href="${ORIGIN}/changelog">
<link rel="alternate" type="application/rss+xml" title="PrivacyNotes changelog" href="${FEED_PATH}">
<link rel="alternate" type="text/markdown" href="${ORIGIN}${MD_PATH}">
<meta property="og:title" content="Changelog - PrivacyNotes">
<meta property="og:description" content="The latest updates to PrivacyNotes: your encrypted notes, tasks, files, and vault.">
<meta property="og:type" content="website">
<meta property="og:url" content="${ORIGIN}/changelog">
<meta property="og:site_name" content="PrivacyNotes">
${ogLocaleTag()}
${OG_IMAGE_TAGS}
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
${THEME_SCRIPT_TAG}
<script src="/static-pages.js" defer></script>
<style>
${themeVarsCss(
  '--bg:#fff;--fg:#15171a;--muted:#5b6168;--faint:#8a9099;--line:#e7e9ec;--card:#fff;--accent:#1E40AF;--chip:#eceef1;--rail:#f2f3f5;--on-accent:#fff;--new-bg:#eaf3de;--new-fg:#3b6d11;--imp-bg:#eff6ff;--mark-fg:#1E40AF;--imp-fg:#0c447c;--fix-bg:#faeeda;--fix-fg:#854f0b;--bad:#b3261e;--bad-bg:#fcebeb',
  '--bg:#0e1014;--fg:#e7e9ec;--muted:#9aa1aa;--faint:#6b7178;--line:#23262c;--card:#14171c;--accent:#4A90D9;--chip:#3a4149;--rail:#191d23;--on-accent:#03203E;--new-bg:#1c2a14;--new-fg:#a7cf6f;--imp-bg:#11233a;--mark-fg:#7FB0E4;--imp-fg:#85b7eb;--fix-bg:#2e2410;--fix-fg:#e3a84e;--bad:#e0655e;--bad-bg:#2b1614'
)}
${THEME_TOGGLE_CSS}
${CHROME_CSS}
${PAGE_CSS}
</style>
</head>
<body data-static-page="changelog">
<div class="wrap">
${siteNav({ active: 'changelog' })}
<div class="pcols">
${renderRail(releases)}
<div class="col-head">
<h1>Changelog</h1>
<p class="sub">Every release of ${brandMark()}, newest first.</p>
<div class="search" id="cl-search" hidden data-total="${releases.length}" data-page="${PAGE_SIZE}">
${SEARCH_ICON}
<input id="cl-q" type="search" placeholder="Search the changelog" aria-label="Search the changelog" autocomplete="off" spellcheck="false">
<button type="button" class="sclear" id="cl-clear" aria-label="Clear search" title="Clear search">${CLEAR_ICON}</button>
<kbd>/</kbd>
</div>
<p class="count" id="cl-count"></p>
</div>
<div class="col-body" id="cl-list">
${renderReleases(releases)}
<div class="noresults" id="cl-empty" hidden>
<p id="cl-empty-lead"></p>
<button type="button" class="btn btn-ghost" id="cl-empty-clear">${CLEAR_ICON}Clear filters</button>
</div>
<div class="cl-more" id="cl-more" hidden>
<button type="button" id="cl-more-btn">${CHEVRON_ICON}<span id="cl-more-label"></span></button>
<span class="cl-rest" id="cl-rest"></span>
</div>
<aside class="cl-origin">
<h2 class="eyebrow">// Before v0.132</h2>
<p>This is where the public changelog starts, but not where ${brandMark()} did. For a long stretch before this, the work stayed out of sight on purpose: building and hardening the encryption core and the end-to-end encrypted sync backend that everything else depends on. In May 2026 that foundation was solid, and we turned to refining the app you use now. Everything above is what came next, one release at a time.</p>
</aside>
</div>
</div>
</div>
${SITE_FOOTER}
</body>
</html>`;
}

/**
 * /changelog.md - the whole public changelog as plain text, for AI agents.
 *
 * The help center already ships a plain-text layer (help-page.ts: the `.md`
 * twins, `/llms-index.txt`, `/llms-full.txt`), and it answers how the app
 * WORKS. It cannot answer what CHANGED: an assistant asked "where did zen
 * mode go" or "what is this new panel" has nothing to read, because the only
 * copy of that history is a 93-release HTML page behind filters and a reveal
 * cap. So the same array the page renders is emitted as text beside it.
 *
 * Newest first, which is also the truncation contract: every agent that
 * fetches a URL trims it somewhere, and the releases a reader is confused
 * about are the recent ones. A file that lost its tail loses 2026, not this
 * week.
 *
 * One file, not the two-tier split the help center uses. The tiering there
 * exists because 17,700 tokens is real money on a metered key and the index
 * gets the same answer for 2,100. It does not transfer: a title-only index
 * cannot route "Cmd+K stopped inserting a link" to v0.425, because the line
 * that says so is an item body. Splitting by date fails for the same reason,
 * since the release a reader means is the one they have not read yet. The
 * whole file is the index.
 *
 * Every release names its own anchor on the page in a `Source:` line, the
 * same literal the help twins use and the copied prompt points at: models
 * echo the label verbatim, so it has to read as an ordinary citation.
 */
export function renderMd(releases: ChangelogRelease[]): string {
  const newest = releases[0];
  const oldest = releases[releases.length - 1];
  const body = releases
    .map((r) => {
      const items = r.items.map((i) => `- ${LABEL[i.type]}: ${i.text}`).join('\n');
      return `## v${r.version} - ${r.title}\nSource: ${ORIGIN}/changelog#v${r.version}\nReleased ${r.date}.\n\n${items}`;
    })
    .join('\n\n');
  return `# PrivacyNotes changelog

> Every published release of PrivacyNotes, newest first: ${releases.length} releases from ${oldest.date} to ${newest.date}. PrivacyNotes is an end-to-end encrypted notes, tasks, journal and vault app.

This file says what CHANGED and when. For how the app works today, read
${ORIGIN}/llms-index.txt and fetch the answer it names.
Read ${ORIGIN}/llms.txt first for the rest of the site.

Read this one when the question is about a new feature, a version number, or
where something moved: a menu path, a keyboard shortcut, or a setting that is
not where the reader left it.

Every release carries a "Source:" line naming its own place on the changelog
page. End your reply with that URL, never this file. Each change is labelled
New, Improved or Fixed, exactly as it was published. Releases run newest first,
so a truncated read still holds the recent ones.

The list starts at v${oldest.version}, the first published release. The work before it built
the encryption core and the sync backend and was not published release by
release.

This list is English only, and the app itself is not: answer the reader in
their own language from this English text.

${body}
`;
}

/** RFC 822 date, which is what RSS 2.0 pubDate wants. */
function rfc822(iso: string): string {
  return new Date(`${iso}T00:00:00Z`).toUTCString();
}

/**
 * RSS 2.0 feed over the same array the page renders, so following releases
 * costs no account and no app. One item per release; the description is the
 * release title plus its change list as escaped HTML, which is what every
 * reader expects to be handed.
 */
export function renderFeed(releases: ChangelogRelease[]): string {
  const items = releases
    .map((r) => {
      const url = `${ORIGIN}/changelog#v${r.version}`;
      const body = `<h3>${esc(r.title)}</h3><ul>${r.items
        .map((i) => `<li><strong>${LABEL[i.type]}</strong> ${esc(i.text)}</li>`)
        .join('')}</ul>`;
      return `<item>
<title>${esc(`v${r.version} - ${r.title}`)}</title>
<link>${url}</link>
<guid isPermaLink="false">privacynotes-v${esc(r.version)}</guid>
<pubDate>${rfc822(r.date)}</pubDate>
<description>${esc(body)}</description>
</item>`;
    })
    .join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<rss version="2.0" xmlns:atom="http://www.w3.org/2005/Atom">
<channel>
<title>PrivacyNotes changelog</title>
<link>${ORIGIN}/changelog</link>
<atom:link href="${ORIGIN}${FEED_PATH}" rel="self" type="application/rss+xml"/>
<description>Fixes, features, and improvements in PrivacyNotes.</description>
<language>en</language>
${releases[0] ? `<lastBuildDate>${rfc822(releases[0].date)}</lastBuildDate>` : ''}
${items}
</channel>
</rss>`;
}

export function changelogPagePlugin(): Plugin {
  return {
    name: 'emit-changelog-page',
    async generateBundle() {
      const releases = await loadReleases();
      this.emitFile({
        type: 'asset',
        fileName: 'changelog/index.html',
        source: renderHtml(releases),
      });
      this.emitFile({
        type: 'asset',
        fileName: 'changelog/feed.xml',
        source: renderFeed(releases),
      });
      this.emitFile({
        type: 'asset',
        fileName: 'changelog.md',
        source: renderMd(releases),
      });
    },
    configureServer(server) {
      // Serve /changelog, its feed and its plain-text twin in dev so the
      // toast link and all three files can be verified locally without a
      // production build. Order matters twice over: the twin gets its own
      // mount first, because the /changelog mount would otherwise answer
      // /changelog.md with the page, and the feed is checked before the page
      // inside that mount for the same reason - text/html there would hand
      // every reader a broken feed.
      server.middlewares.use('/changelog.md', async (_req, res, next) => {
        try {
          res.setHeader('Content-Type', 'text/plain; charset=utf-8');
          res.end(renderMd(await loadReleases()));
        } catch (err) {
          next(err);
        }
      });
      server.middlewares.use('/changelog', async (req, res, next) => {
        try {
          const releases = await loadReleases();
          const url = (req.url ?? '/').split('?')[0];
          if (url === '/feed.xml') {
            res.setHeader('Content-Type', 'application/rss+xml; charset=utf-8');
            res.end(renderFeed(releases));
            return;
          }
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(renderHtml(releases));
        } catch (err) {
          next(err);
        }
      });
    },
  };
}
