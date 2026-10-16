import { transformWithOxc, type Plugin } from 'vite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { THEME_SCRIPT_TAG, THEME_TOGGLE_CSS, themeVarsCss } from './static-page-theme.ts';
import { CHROME_CSS, LIGHTBOX_CSS, OG_IMAGE_TAGS, ogLocaleTag, SITE_FOOTER, siteNav } from './static-page-chrome.ts';
// Type-only, so they erase at build time and leave the import-free modules
// that loadThemes() transpiles and imports as data URLs.
import type * as ThemeCode from './src/themeCode.ts';
import type { CommunityTheme } from './src/communityThemes.ts';
import type { TeamTheme } from './src/teamThemes.ts';
import type { BUILTIN_THEME_CODES } from './src/builtinThemeCodes.ts';
import type { COMMUNITY_VOTES } from './src/communityVotes.ts';
import { THEME_SHOT_DIR, themeShotFile } from '../../ops/theme-shots/shotName.mjs';

// Pre-renders /themes: the community themes from src/communityThemes.ts, then
// the team's own, which the app already ships: the hand-tuned palettes as
// their exact codes (src/builtinThemeCodes.ts) and src/teamThemes.ts.
// Every code is read by the app's own parser (src/themeCode.ts), so the page
// shows exactly what the app would paint, and the build stops on a code the
// app would refuse, a theme that fails a contrast check, or a credit that is
// not a GitHub username. Each card shows a screenshot of the demo in its
// theme, which `pnpm theme:shots` (ops/theme-shots/run.mjs) captures and
// names after a hash of the code, so the build also stops on a theme whose
// code has no shot yet. Emitted as themes/index.html, so Cloudflare serves
// it at /themes. English-only by the i18n tier policy, like /roadmap.
//
// The page ships zero inline scripts (script-src is 'self' only): the Copy
// buttons ship hidden and /static-pages.js wires them (data-static-page
// "themes"), and the All, Light and Dark filter is three radio inputs and
// CSS. Every code stays selectable without JavaScript. The Load more buttons
// ship hidden too: without JavaScript every card shows.
// Spec: ops/docs/color-themes.md (section 6)

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(__dirname, 'src');
const CANONICAL = 'https://privacynotes.app/themes';
const TITLE = 'Themes - PrivacyNotes';
const DESC =
  'Color themes for PrivacyNotes, ready to copy. Copy a theme code and paste it into Settings, Appearance, Themes.';
/** The theme form: a new discussion in the Themes category of the public
 *  repository, where each theme keeps an open thread. */
const SUBMIT_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/discussions/new?category=themes';
/** Cards a list shows before its Load more button, and how many each press adds. */
const PAGE_SIZE = 40;

interface ThemeCard {
  name: string;
  mode: 'light' | 'dark';
  code: string;
  /** The GitHub username of a community theme; absent on a team theme. */
  author?: string;
  /** A community theme's day of adding (YYYY-MM-DD). */
  added?: string;
  /** A community theme's thread in the Themes discussions, and its upvotes there. */
  discussion?: number;
  votes?: number;
  /** Its place when the page lists the community themes newest first. */
  newestRank?: number;
  /** Its place when the page lists them by votes. */
  votesRank?: number;
  colors: Record<string, string>;
}

async function importTs<T>(file: string): Promise<T> {
  const src = fs.readFileSync(file, 'utf8');
  const { code } = await transformWithOxc(src, file, { lang: 'ts' });
  return (await import('data:text/javascript;base64,' + Buffer.from(code).toString('base64'))) as T;
}

interface ThemeLists {
  community: ThemeCard[];
  team: ThemeCard[];
  discussionsUrl: string;
}

async function loadThemes(): Promise<ThemeLists> {
  const tc = await importTs<typeof ThemeCode>(path.join(SRC, 'themeCode.ts'));
  const { COMMUNITY_THEMES, THEME_DISCUSSIONS_URL } = await importTs<{ COMMUNITY_THEMES: CommunityTheme[]; THEME_DISCUSSIONS_URL: string }>(
    path.join(SRC, 'communityThemes.ts'),
  );
  const { COMMUNITY_VOTES } = await importTs<{ COMMUNITY_VOTES: typeof COMMUNITY_VOTES }>(
    path.join(SRC, 'communityVotes.ts'),
  );
  const { TEAM_THEMES } = await importTs<{ TEAM_THEMES: TeamTheme[] }>(path.join(SRC, 'teamThemes.ts'));
  const builtin = await importTs<{ BUILTIN_THEME_CODES: typeof BUILTIN_THEME_CODES }>(path.join(SRC, 'builtinThemeCodes.ts'));
  // One id per theme across every list, and one name per mode: a pasted code
  // that matches a theme picks it by its canonical code, and a slot stores the
  // id, so a light and a dark theme may share a name; each card shows its mode.
  const ids = new Set<string>();
  const names = new Set<string>();
  const read = (code: string, where: string, credited: boolean): ThemeCard => {
    const theme = tc.parseThemeCode(code);
    if (!theme) throw new Error(`themes-page: ${where} is not a theme code`);
    if (tc.serializeThemeCode(theme) !== code) {
      throw new Error(`themes-page: "${theme.name}" is not in the form the app copies; use ${tc.serializeThemeCode(theme)}`);
    }
    const failing = tc.checkTheme(theme).filter((c) => !c.pass).map((c) => c.id);
    if (failing.length > 0) {
      throw new Error(`themes-page: "${theme.name}" fails ${failing.join(', ')}; run pnpm theme:check on it`);
    }
    // A community code carries its author's username (`by=`); a team code none.
    const author = theme.author;
    if (credited !== (author !== undefined)) {
      throw new Error(`themes-page: "${theme.name}" ${credited ? 'needs by=<GitHub username>' : 'is the team\'s and credits nobody'}`);
    }
    if ([...theme.name].length > tc.THEME_NAME_INPUT_MAX) {
      throw new Error(`themes-page: "${theme.name}" is longer than ${tc.THEME_NAME_INPUT_MAX} characters, the most the builder takes`);
    }
    const resolved = tc.resolveTheme(theme);
    const named = `${resolved.mode}:${theme.name}`;
    if (names.has(named)) throw new Error(`themes-page: two ${resolved.mode} themes are called "${theme.name}"`);
    names.add(named);
    return { name: theme.name, mode: resolved.mode, code, author, colors: resolved.colors };
  };
  const listed = ({ id, code }: { id: string; code: string }, where: string, credited: boolean): ThemeCard => {
    if (!/^[a-z0-9]{12}$/.test(id) || ids.has(id)) throw new Error(`themes-page: ${where} needs its own twelve-character id`);
    ids.add(id);
    return read(code, where, credited);
  };
  const palettes = [...Object.values(builtin.BUILTIN_THEME_CODES.light), ...Object.values(builtin.BUILTIN_THEME_CODES.dark)];
  // Newest first; a malformed date stops the build.
  const newest = [...COMMUNITY_THEMES]
      .map((t, i) => {
        if (!/^\d{4}-\d{2}-\d{2}$/.test(t.added) || Number.isNaN(Date.parse(t.added))) {
          throw new Error(`themes-page: community entry ${i + 1} needs added: 'YYYY-MM-DD'`);
        }
        if (t.discussion !== undefined && !(Number.isInteger(t.discussion) && t.discussion > 0)) {
          throw new Error(`themes-page: community entry ${i + 1} needs discussion: <a discussion number>`);
        }
        const votes = t.discussion ? (COMMUNITY_VOTES[t.discussion] ?? 0) : 0;
        if (!Number.isInteger(votes) || votes < 0) throw new Error(`themes-page: community entry ${i + 1} has a bad vote count`);
        return { ...listed(t, `community entry ${i + 1}`, true), added: t.added, votes, ...(t.discussion ? { discussion: t.discussion } : {}) };
      })
      .sort((a, b) => b.added!.localeCompare(a.added!))
      .map((t, i) => ({ ...t, newestRank: i }));
  return {
    // Most votes first, the app's order under Community; a tie goes to the newer.
    community: [...newest].sort((a, b) => b.votes - a.votes).map((t, i) => ({ ...t, votesRank: i })),
    discussionsUrl: THEME_DISCUSSIONS_URL,
    team: [...palettes.map((code) => read(code, 'a built-in palette', false)), ...TEAM_THEMES.map((t, i) => listed(t, `team entry ${i + 1}`, false))],
  };
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

const PUBLIC = path.resolve(__dirname, 'public');
/** A Phosphor glyph (regular weight) as inline SVG, for the steps and filters. */
const glyph = (d: string, size = 16) =>
  `<svg width="${size}" height="${size}" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="${d}"/></svg>`;
const P_COPY = 'M216,32H88a8,8,0,0,0-8,8V80H40a8,8,0,0,0-8,8V216a8,8,0,0,0,8,8H168a8,8,0,0,0,8-8V176h40a8,8,0,0,0,8-8V40A8,8,0,0,0,216,32ZM160,208H48V96H160Zm48-48H176V88a8,8,0,0,0-8-8H96V48H208Z';
const P_CLIPBOARD = 'M168,152a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h64A8,8,0,0,1,168,152Zm-8-40H96a8,8,0,0,0,0,16h64a8,8,0,0,0,0-16Zm56-64V216a16,16,0,0,1-16,16H56a16,16,0,0,1-16-16V48A16,16,0,0,1,56,32H92.26a47.92,47.92,0,0,1,71.48,0H200A16,16,0,0,1,216,48ZM96,64h64a32,32,0,0,0-64,0ZM200,48H173.25A47.93,47.93,0,0,1,176,64v8a8,8,0,0,1-8,8H88a8,8,0,0,1-8-8V64a47.93,47.93,0,0,1,2.75-16H56V216H200Z';
const P_DISK = 'M219.31,72,184,36.69A15.86,15.86,0,0,0,172.69,32H48A16,16,0,0,0,32,48V208a16,16,0,0,0,16,16H208a16,16,0,0,0,16-16V83.31A15.86,15.86,0,0,0,219.31,72ZM168,208H88V152h80Zm40,0H184V152a16,16,0,0,0-16-16H88a16,16,0,0,0-16,16v56H48V48H172.69L208,83.31ZM160,72a8,8,0,0,1-8,8H96a8,8,0,0,1,0-16h56A8,8,0,0,1,160,72Z';
const P_EXPAND = 'M216,48V96a8,8,0,0,1-16,0V67.31l-42.34,42.35a8,8,0,0,1-11.32-11.32L188.69,56H160a8,8,0,0,1,0-16h48A8,8,0,0,1,216,48ZM98.34,146.34,56,188.69V160a8,8,0,0,0-16,0v48a8,8,0,0,0,8,8H96a8,8,0,0,0,0-16H67.31l42.35-42.34a8,8,0,0,0-11.32-11.32ZM208,152a8,8,0,0,0-8,8v28.69l-42.34-42.35a8,8,0,0,0-11.32,11.32L188.69,200H160a8,8,0,0,0,0,16h48a8,8,0,0,0,8-8V160A8,8,0,0,0,208,152ZM67.31,56H96a8,8,0,0,0,0-16H48a8,8,0,0,0-8,8V96a8,8,0,0,0,16,0V67.31l42.34,42.35a8,8,0,0,0,11.32-11.32Z';
const P_SUN = 'M120,40V16a8,8,0,0,1,16,0V40a8,8,0,0,1-16,0Zm72,88a64,64,0,1,1-64-64A64.07,64.07,0,0,1,192,128Zm-16,0a48,48,0,1,0-48,48A48.05,48.05,0,0,0,176,128ZM58.34,69.66A8,8,0,0,0,69.66,58.34l-16-16A8,8,0,0,0,42.34,53.66Zm0,116.68-16,16a8,8,0,0,0,11.32,11.32l16-16a8,8,0,0,0-11.32-11.32ZM192,72a8,8,0,0,0,5.66-2.34l16-16a8,8,0,0,0-11.32-11.32l-16,16A8,8,0,0,0,192,72Zm5.66,114.34a8,8,0,0,0-11.32,11.32l16,16a8,8,0,0,0,11.32-11.32ZM48,128a8,8,0,0,0-8-8H16a8,8,0,0,0,0,16H40A8,8,0,0,0,48,128Zm80,80a8,8,0,0,0-8,8v24a8,8,0,0,0,16,0V216A8,8,0,0,0,128,208Zm112-88H216a8,8,0,0,0,0,16h24a8,8,0,0,0,0-16Z';
const P_MOON = 'M233.54,142.23a8,8,0,0,0-8-2,88.08,88.08,0,0,1-109.8-109.8,8,8,0,0,0-10-10,104.84,104.84,0,0,0-52.91,37A104,104,0,0,0,136,224a103.09,103.09,0,0,0,62.52-20.88,104.84,104.84,0,0,0,37-52.91A8,8,0,0,0,233.54,142.23ZM188.9,190.34A88,88,0,0,1,65.66,67.11a89,89,0,0,1,31.4-26A106,106,0,0,0,96,56,104.11,104.11,0,0,0,200,160a106,106,0,0,0,14.92-1.06A89,89,0,0,1,188.9,190.34Z';
const P_ARROW_UP = 'M205.66,117.66a8,8,0,0,1-11.32,0L136,59.31V216a8,8,0,0,1-16,0V59.31L61.66,117.66a8,8,0,0,1-11.32-11.32l72-72a8,8,0,0,1,11.32,0l72,72A8,8,0,0,1,205.66,117.66Z';
const GITHUB_ICON =
  '<svg width="14" height="14" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M216,104v8a56.06,56.06,0,0,1-48.44,55.47A39.8,39.8,0,0,1,176,192v40a8,8,0,0,1-8,8H104a8,8,0,0,1-8-8V216H72a40,40,0,0,1-40-40A24,24,0,0,0,8,152a8,8,0,0,1,0-16,40,40,0,0,1,40,40,24,24,0,0,0,24,24H96v-8a39.8,39.8,0,0,1,8.44-24.53A56.06,56.06,0,0,1,56,112v-8a58.14,58.14,0,0,1,7.69-28.32A59.78,59.78,0,0,1,69.07,28,8,8,0,0,1,76,24a59.75,59.75,0,0,1,48,24h24a59.75,59.75,0,0,1,48-24,8,8,0,0,1,6.93,4,59.74,59.74,0,0,1,5.37,47.68A58,58,0,0,1,216,104Z"/></svg>';
const COPY_ICON =
  '<svg class="ic-copy" width="15" height="15" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M216,32H88a8,8,0,0,0-8,8V80H40a8,8,0,0,0-8,8V216a8,8,0,0,0,8,8H168a8,8,0,0,0,8-8V176h40a8,8,0,0,0,8-8V40A8,8,0,0,0,216,32ZM160,208H48V96H160Zm48-48H176V88a8,8,0,0,0-8-8H96V48H208Z"/></svg>';
const DONE_ICON =
  '<svg class="ic-done" width="15" height="15" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M229.66,77.66l-128,128a8,8,0,0,1-11.32,0l-56-56a8,8,0,0,1,11.32-11.32L96,188.69,218.34,66.34a8,8,0,0,1,11.32,11.32Z"/></svg>';
/** The six colors a person picks, in the order the builder shows them. */
const SWATCHES: [string, string][] = [
  ['accent', 'Accent'], ['surface-2', 'Background'], ['surface-0', 'Sidebar'],
  ['divider', 'Border'], ['text', 'Text'], ['text-muted', 'Muted text'],
];

/** The screenshot of a theme, or a build error that says how to make it. */
function shotPath(t: ThemeCard): string {
  const file = themeShotFile(t.code);
  if (!fs.existsSync(path.join(PUBLIC, THEME_SHOT_DIR, file))) {
    throw new Error(`themes-page: "${t.name}" has no screenshot for its code; run pnpm theme:shots with the dev server up`);
  }
  return `/${THEME_SHOT_DIR}/${file}`;
}

function card(t: ThemeCard, i: number, discussionsUrl: string): string {
  const added = t.added
    ? ` <span class="added">&middot; ${new Date(`${t.added}T00:00:00Z`).toLocaleDateString('en-US', { month: 'short', day: 'numeric', year: 'numeric', timeZone: 'UTC' })}</span>`
    : '';
  // The credit opens the theme's discussion thread, where its author and its
  // users talk about it; a theme without one links the author's profile.
  const thread = t.discussion ? `${discussionsUrl}/${t.discussion}` : undefined;
  const creditHref = thread ?? `https://github.com/${t.author}`;
  // Votes happen on the thread; the count is the snapshot the page was built with.
  const vote = thread
    ? `<a class="vote" href="${thread}" target="_blank" rel="noopener noreferrer nofollow" data-thread="${t.discussion}" aria-label="${t.votes} ${t.votes === 1 ? 'vote' : 'votes'}, vote on GitHub">${glyph(P_ARROW_UP, 12)}<span class="vc">${t.votes}</span> &middot; Vote</a>`
    : '';
  const by = t.author
    ? `<span>by <a href="${creditHref}" target="_blank" rel="noopener noreferrer nofollow">@${t.author}</a>${added}</span>${vote}`
    : 'Made by the team, already in the app';
  const id = `theme-code-${i + 1}`;
  const dots = SWATCHES.map(
    ([k, label]) => `<li style="background:${t.colors[k]}" title="${label} ${t.colors[k]}"><span class="vh">${label} ${t.colors[k]}</span></li>`,
  ).join('');
  // The Worker rewrites --ov and the counts from the live votes (worker.ts, withThemeVotes).
  const rank = t.newestRank !== undefined && t.discussion
    ? ` data-thread="${t.discussion}" style="--ov:${t.votesRank};--on:${t.newestRank}"`
    : t.newestRank !== undefined ? ` style="--ov:${t.votesRank};--on:${t.newestRank}"` : '';
  return `<article class="tc" data-mode="${t.mode}"${rank}>
<figure class="shot"><a href="${shotPath(t)}" data-shot data-alt="${esc(t.name)}" aria-label="Show the ${esc(t.name)} screenshot full size"><img src="${shotPath(t)}" width="2560" height="1600" alt="The app in the ${esc(t.name)} theme" loading="${i < 4 ? 'eager' : 'lazy'}" decoding="async" draggable="false"><span class="zoom" aria-hidden="true">${glyph(P_EXPAND, 18)}View full size</span></a><span class="mode">${t.mode === 'dark' ? 'Dark' : 'Light'}</span></figure>
<div class="tc-body">
<div class="tc-head"><h2 dir="auto">${esc(t.name)}</h2><ul class="sw" aria-label="Colors">${dots}</ul></div>
<p class="by">${by}</p>
<button class="cbtn" type="button" data-copy="${id}" data-copy-icon data-label-done="Copied" hidden>${COPY_ICON}${DONE_ICON}<span class="cl">Copy code</span></button>
<details class="cd"><summary>Show code</summary><code id="${id}" class="code" dir="ltr">${esc(t.code)}</code></details>
</div>
</article>`;
}

const PAGE_CSS = `.hero{display:flex;align-items:flex-end;justify-content:space-between;flex-wrap:wrap;gap:12px 24px;margin:0 0 22px}
.hero h1{margin-bottom:6px}
.lead{color:var(--muted);font-size:16px;margin:0;max-width:640px}
.hero-cta{flex-shrink:0;display:inline-flex;align-items:center;gap:8px}
.steps{list-style:none;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:0 0 14px;padding:0}
.steps li{display:flex;flex-direction:column;gap:2px;border-radius:12px;background:var(--rail);border:1px solid var(--line);padding:14px 16px}
.steps li.lead-step{background:var(--imp-bg);border-color:transparent}
.st-top{display:flex;align-items:center;justify-content:space-between;margin-bottom:10px}
.st-ic{display:inline-flex;align-items:center;justify-content:center;width:34px;height:34px;border-radius:9px;background:var(--bg);color:var(--mark-fg);box-shadow:0 0 0 1px var(--line)}
.st-n{font-size:11.5px;font-weight:600;color:var(--faint)}
.lead-step .st-n{color:var(--mark-fg)}
.st-t{display:block;font-size:14.5px;font-weight:650;line-height:1.35;color:var(--fg)}
.st-d{display:block;font-size:13px;line-height:1.45;color:var(--muted)}
@media(max-width:640px){.steps{grid-template-columns:minmax(0,1fr);gap:8px}.steps li{display:grid;grid-template-columns:auto minmax(0,1fr);column-gap:12px;padding:10px 12px}.st-top{grid-row:span 2;margin:0}.st-n{display:none}}
.tfi{position:absolute;opacity:0;pointer-events:none}
.filters{display:flex;flex-wrap:wrap;justify-content:space-between;align-items:center;gap:10px 32px;margin:0 0 22px;padding:8px 10px;border:1px solid var(--line);border-radius:12px;background:var(--rail)}
@media(max-width:560px){.filters{justify-content:flex-start}}
.filter{display:flex;align-items:center;gap:2px}
.filter .fl{margin-right:8px}
.seg{display:inline-flex;gap:2px;padding:3px;border-radius:10px;background:var(--chip)}
.filter label{display:inline-flex;align-items:center;gap:5px;border-radius:7px;padding:5px 12px;font-size:13px;font-weight:600;cursor:pointer;color:var(--muted)}
.filter label:hover{color:var(--fg)}
#so-votes:checked~.filters label[for=so-votes],#so-new:checked~.filters label[for=so-new],#tf-all:checked~.filters label[for=tf-all],#tf-light:checked~.filters label[for=tf-light],#tf-dark:checked~.filters label[for=tf-dark],#mb-all:checked~.filters label[for=mb-all],#mb-community:checked~.filters label[for=mb-community],#mb-team:checked~.filters label[for=mb-team]{background:var(--bg);color:var(--fg);box-shadow:0 0 0 1px var(--line),0 1px 2px rgb(0 0 0/.08)}
#so-votes:focus-visible~.filters label[for=so-votes],#so-new:focus-visible~.filters label[for=so-new],#tf-all:focus-visible~.filters label[for=tf-all],#tf-light:focus-visible~.filters label[for=tf-light],#tf-dark:focus-visible~.filters label[for=tf-dark],#mb-all:focus-visible~.filters label[for=mb-all],#mb-community:focus-visible~.filters label[for=mb-community],#mb-team:focus-visible~.filters label[for=mb-team]{outline:2px solid var(--accent);outline-offset:2px}
#tf-light:checked~.tgrid .tc[data-mode=dark],#tf-dark:checked~.tgrid .tc[data-mode=light]{display:none}
#mb-community:checked~.by-team,#mb-team:checked~.by-community{display:none}
.sec-empty{display:none;margin:0;padding:16px 18px;border:1px dashed var(--line);border-radius:12px;color:var(--muted);font-size:14px}
.sec-empty a{font-weight:600}
#tf-light:checked~.sec-empty[data-empty=light],#tf-dark:checked~.sec-empty[data-empty=dark]{display:block}
#mb-team:checked~.sec-empty.by-community{display:none}
.filter .fl{font-size:13px;color:var(--muted);align-self:center;min-width:64px}
.sec{font-size:18px;margin:26px 0 4px}
.sec-d{color:var(--muted);font-size:14px;margin:0 0 12px}
.tgrid{display:grid;grid-template-columns:repeat(2,minmax(0,1fr));gap:22px}
@media(max-width:640px){.tgrid{grid-template-columns:minmax(0,1fr)}}
.tc{display:flex;flex-direction:column;min-width:0;border:1px solid var(--line);border-radius:14px;background:var(--bg);overflow:hidden;transition:border-color .15s,box-shadow .15s}
.tc:hover{border-color:color-mix(in srgb,var(--fg) 22%,var(--line));box-shadow:0 6px 24px rgb(0 0 0/.08)}
.shot{position:relative;margin:0;aspect-ratio:16/10;background:var(--chip);border-bottom:1px solid var(--line)}
.shot{user-select:none;-webkit-user-select:none}
/* The hand, not zoom-in: some systems draw zoom-in as a plain arrow. */
.shot,.shot *{cursor:pointer}
.shot a{position:relative;display:block;height:100%}
.shot a::after{content:'';position:absolute;inset:0;background:rgb(0 0 0/0);transition:background .15s;pointer-events:none}
.shot .zoom{position:absolute;left:50%;top:50%;z-index:1;display:inline-flex;align-items:center;gap:6px;padding:7px 12px;border-radius:999px;background:rgb(0 0 0/.65);color:#fff;font-size:13px;font-weight:600;transform:translate(-50%,-50%) scale(.96);opacity:0;transition:opacity .15s,transform .15s;pointer-events:none}
.shot a:hover::after,.shot a:focus-visible::after{background:rgb(0 0 0/.18)}
.shot a:hover .zoom,.shot a:focus-visible .zoom{opacity:1;transform:translate(-50%,-50%) scale(1)}
@media(hover:none){.shot .zoom{opacity:1;top:auto;bottom:10px;left:10px;transform:none;padding:5px 9px;font-size:12px}}
.shot img{display:block;width:100%;height:100%;object-fit:cover}
.shot .mode{position:absolute;top:10px;right:10px;font-size:11px;font-weight:600;padding:2px 9px;border-radius:999px;background:rgb(0 0 0/.62);color:#fff;pointer-events:none}
.tc-body{display:flex;flex-direction:column;gap:10px;padding:14px 16px 16px}
.tc-head{display:flex;align-items:center;justify-content:space-between;gap:10px}
.tc-head h2{font-size:17px;font-weight:650;margin:0;min-width:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.sw{display:flex;gap:4px;list-style:none;margin:0;padding:0;flex-shrink:0}
.sw li{width:16px;height:16px;border-radius:50%;box-shadow:inset 0 0 0 1px rgb(127 127 127/.35)}
.vh{position:absolute;width:1px;height:1px;overflow:hidden;clip:rect(0 0 0 0);white-space:nowrap}
.by{margin:-4px 0 0;font-size:13px;color:var(--muted);display:flex;flex-wrap:wrap;align-items:center;justify-content:space-between;gap:4px 10px}
.vote{display:inline-flex;align-items:center;gap:4px;padding:2px 8px;border:1px solid var(--line);border-radius:999px;font-size:12px;font-weight:600;color:var(--muted);text-decoration:none}
.vote:hover{color:var(--accent);border-color:var(--accent)}
.tgrid.by-community .tc{order:var(--ov)}
#so-new:checked~.tgrid.by-community .tc{order:var(--on)}
#mb-team:checked~.filters .by-order{display:none}
.cbtn{display:flex;align-items:center;justify-content:center;gap:6px;width:100%;padding:9px 12px;border:1px solid var(--line);border-radius:9px;background:var(--rail);color:var(--accent);font-size:13.5px;font-weight:600;cursor:pointer}
.cbtn[hidden]{display:none}
.cbtn:hover{border-color:var(--accent)}
.cbtn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.cbtn .ic-done{display:none}
.cbtn.on{color:var(--ok);border-color:var(--ok)}
.cbtn.on .ic-copy{display:none}
.cbtn.on .ic-done{display:block}
.cd summary{font-size:12px;color:var(--muted);cursor:pointer;width:max-content}
.cd summary:hover{color:var(--fg)}
.cd[open] summary{margin-bottom:6px}
.code{display:block;font-size:11.5px;background:var(--chip);border-radius:6px;padding:6px 8px;overflow-wrap:anywhere;color:var(--fg)}
.submit{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px 20px;border:1px solid var(--line);border-radius:12px;background:var(--rail);padding:16px 18px;margin-top:28px;font-size:14px}
.submit h2{font-size:16px;margin:0 0 4px}
.submit p{margin:0;color:var(--muted);max-width:620px}
.submit .btn{flex-shrink:0}
.tc.tc-more{display:none}
.more-btn{display:block;width:50%;margin:18px auto 0;padding:9px 18px;border:1px solid var(--line);border-radius:9px;background:var(--rail);color:var(--accent);font-size:13.5px;font-weight:600;cursor:pointer}
.more-btn[hidden]{display:none}
.more-btn:hover{border-color:var(--accent)}
.more-btn:focus-visible{outline:2px solid var(--accent);outline-offset:2px}
.btn-tint{background:var(--imp-bg);color:var(--mark-fg);font-size:14px;font-weight:600;padding:10px 16px;border:1px solid transparent}
.btn-tint:hover{border-color:var(--mark-fg)}`;

const MORE_BUTTON = (list: string) => `<button class="more-btn ${list}" type="button" data-more hidden>Load more</button>`;

function renderHtml({ community, team, discussionsUrl }: ThemeLists): string {
  // The threads newest first with their baked counts, for the Worker's live rewrite.
  const shipped = [...community]
    .filter((t) => t.discussion)
    .sort((a, b) => a.newestRank! - b.newestRank!)
    .map((t) => `${t.discussion}:${t.votes}`)
    .join(',');
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${TITLE}</title>
<meta name="description" content="${DESC}">
${shipped ? `<meta name="pn-theme-votes" content="${shipped}">` : ''}
<link rel="canonical" href="${CANONICAL}">
<meta property="og:title" content="${TITLE}">
<meta property="og:description" content="${DESC}">
<meta property="og:type" content="website">
<meta property="og:url" content="${CANONICAL}">
<meta property="og:site_name" content="PrivacyNotes">
${ogLocaleTag()}
${OG_IMAGE_TAGS}
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
${THEME_SCRIPT_TAG}
<style>
${themeVarsCss(
  '--bg:#fff;--fg:#15171a;--muted:#5b6168;--faint:#8a9099;--line:#e7e9ec;--accent:#1E40AF;--imp-bg:#eff6ff;--mark-fg:#1E40AF;--chip:#eceef1;--rail:#f7f8fa;--on-accent:#fff;--ok:#047857',
  '--bg:#0e1014;--fg:#e7e9ec;--muted:#9aa1aa;--faint:#6b7178;--line:#23262c;--accent:#4A90D9;--imp-bg:#11233a;--mark-fg:#7FB0E4;--chip:#23272e;--rail:#14171d;--on-accent:#03203E;--ok:#34D399'
)}
${THEME_TOGGLE_CSS}
${CHROME_CSS}
${PAGE_CSS}
${LIGHTBOX_CSS}
</style>
</head>
<body data-static-page="themes">
<div class="wrap">
${siteNav({ active: 'themes' })}
<header class="hero">
<div><h1>Themes</h1><p class="lead">Color themes for the app, ready to copy.</p></div>
<a class="btn btn-tint hero-cta" href="${SUBMIT_URL}" target="_blank" rel="noopener noreferrer">${GITHUB_ICON}Submit a theme</a>
</header>
<ol class="steps" role="list">
<li class="lead-step"><div class="st-top"><span class="st-ic">${glyph(P_COPY)}</span><span class="st-n">Step 1</span></div><span class="st-t">Copy a code</span><span class="st-d">Press Copy code on any theme below.</span></li>
<li><div class="st-top"><span class="st-ic">${glyph(P_CLIPBOARD)}</span><span class="st-n">Step 2</span></div><span class="st-t">Paste it in the app</span><span class="st-d">Settings &rsaquo; Appearance &rsaquo; Themes</span></li>
<li><div class="st-top"><span class="st-ic">${glyph(P_DISK)}</span><span class="st-n">Step 3</span></div><span class="st-t">Save it</span><span class="st-d">It shows at once. Saving needs Pro.</span></li>
</ol>
<input class="tfi" type="radio" name="tf" id="tf-all" checked>
<input class="tfi" type="radio" name="tf" id="tf-light">
<input class="tfi" type="radio" name="tf" id="tf-dark">
${community.length > 0 ? `<input class="tfi" type="radio" name="mb" id="mb-all" checked>
<input class="tfi" type="radio" name="mb" id="mb-community">
<input class="tfi" type="radio" name="mb" id="mb-team">
<input class="tfi" type="radio" name="so" id="so-votes" checked>
<input class="tfi" type="radio" name="so" id="so-new">
<div class="filters">
<div class="filter" role="group" aria-label="Made by"><span class="fl" aria-hidden="true">Made by</span><span class="seg"><label for="mb-all">All</label><label for="mb-community">Community</label><label for="mb-team">Team</label></span></div>
<div class="filter" role="group" aria-label="Mode"><span class="fl" aria-hidden="true">Mode</span><span class="seg"><label for="tf-all">All</label><label for="tf-light">${glyph(P_SUN, 14)}Light</label><label for="tf-dark">${glyph(P_MOON, 14)}Dark</label></span></div>
<div class="filter by-order" role="group" aria-label="Order"><span class="fl" aria-hidden="true">Order</span><span class="seg"><label for="so-votes">Most votes</label><label for="so-new">Newest</label></span></div>
</div>
<h2 class="sec by-community">Community themes</h2>
<p class="sec-d by-community">Made by people who use the app. Vote for the ones you like on their GitHub thread; the counts update once a day.</p>
<div class="tgrid by-community" data-page="${PAGE_SIZE}">
${community.map((t, i) => card(t, i, discussionsUrl)).join('\n')}
</div>
${MORE_BUTTON('by-community')}
${(['light', 'dark'] as const)
  .filter((m) => !community.some((t) => t.mode === m))
  .map((m) => `<p class="sec-empty by-community" data-empty="${m}">No ${m} themes from the community yet. <a href="${SUBMIT_URL}" target="_blank" rel="noopener noreferrer">Be the first</a>.</p>`)
  .join('\n')}` : `<div class="filters"><div class="filter" role="group" aria-label="Show"><span class="seg"><label for="tf-all">All</label><label for="tf-light">${glyph(P_SUN, 14)}Light</label><label for="tf-dark">${glyph(P_MOON, 14)}Dark</label></span></div></div>`}
<h2 class="sec by-team">Made by the team</h2>
<p class="sec-d by-team">Already in the app. Each code lists the colors, so you can change any of them and paste your own version.</p>
<div class="tgrid by-team" data-page="${PAGE_SIZE}">
${team.map((t, i) => card(t, community.length + i, discussionsUrl)).join('\n')}
</div>
${MORE_BUTTON('by-team')}
<section class="submit">
<div>
<h2>${community.length > 0 ? 'Made a theme you like?' : 'Be the first community theme'}</h2>
<p>Copy its code from the menu on its card in the app and send it to us on GitHub. Themes we add show your GitHub username, and we may adjust a color so text stays easy to read.</p>
</div>
<a class="btn btn-tint" href="${SUBMIT_URL}" target="_blank" rel="noopener noreferrer">${GITHUB_ICON}Submit a theme on GitHub</a>
</section>
</div>
${SITE_FOOTER}
<script src="/static-pages.js" defer></script>
</body>
</html>`;
}

export function themesPagePlugin(): Plugin {
  return {
    name: 'emit-themes-page',
    async generateBundle() {
      this.emitFile({ type: 'asset', fileName: 'themes/index.html', source: renderHtml(await loadThemes()) });
    },
    configureServer(server) {
      // Serve /themes in dev so the page can be verified locally without a
      // production build.
      server.middlewares.use('/themes', async (_req, res, next) => {
        try {
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          // A page that changes with every edit; a cached copy hides the edit.
          res.setHeader('Cache-Control', 'no-store');
          res.end(renderHtml(await loadThemes()));
        } catch (err) {
          next(err);
        }
      });
    },
  };
}
