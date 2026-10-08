import { transformWithOxc, type Plugin } from 'vite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { THEME_SCRIPT_TAG, THEME_TOGGLE_CSS, themeVarsCss } from './static-page-theme.ts';
import { CHROME_CSS, OG_IMAGE_TAGS, ogLocaleTag, SITE_FOOTER, siteNav } from './static-page-chrome.ts';
// Type-only, so they erase at build time and leave the two source files the
// import-free modules loadThemes() transpiles and imports as data URLs.
import type * as ThemeCode from './src/themeCode.ts';
import type { CommunityTheme } from './src/communityThemes.ts';
import type { TeamTheme } from './src/teamThemes.ts';
import type { BUILTIN_THEME_CODES } from './src/builtinThemeCodes.ts';

// Pre-renders /themes: the community themes from src/communityThemes.ts, then
// the team's own, which the app already ships: the hand-tuned palettes as
// their exact codes (src/builtinThemeCodes.ts) and src/teamThemes.ts.
// Every code is read by the app's own parser (src/themeCode.ts), so the page
// shows exactly what the app would paint, and the build stops on a code the
// app would refuse, a theme that fails a contrast check, or a credit that is
// not a GitHub username. Emitted as themes/index.html, so Cloudflare serves
// it at /themes. English-only by the i18n tier policy, like /roadmap.
//
// The page ships zero inline scripts (script-src is 'self' only): the Copy
// buttons ship hidden and /static-pages.js wires them (data-static-page
// "themes"), and the All, Light and Dark filter is three radio inputs and
// CSS. Every code stays selectable without JavaScript.
// Spec: ops/docs/color-themes.md (section 6)

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const SRC = path.resolve(__dirname, 'src');
const CANONICAL = 'https://privacynotes.app/themes';
const TITLE = 'Themes - PrivacyNotes';
const DESC =
  'Color themes for PrivacyNotes, ready to copy. Copy a theme code and paste it into Settings, Appearance, Themes.';
/** The theme form in the public repository's issues. */
const SUBMIT_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues/new?template=theme.yml';
/** What GitHub accepts as a username: letters, digits and single hyphens. */
const GITHUB_USER = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

interface ThemeCard {
  name: string;
  mode: 'light' | 'dark';
  code: string;
  /** The GitHub username of a community theme; absent on a team theme. */
  author?: string;
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
}

async function loadThemes(): Promise<ThemeLists> {
  const tc = await importTs<typeof ThemeCode>(path.join(SRC, 'themeCode.ts'));
  const { COMMUNITY_THEMES } = await importTs<{ COMMUNITY_THEMES: CommunityTheme[] }>(
    path.join(SRC, 'communityThemes.ts'),
  );
  const { TEAM_THEMES } = await importTs<{ TEAM_THEMES: TeamTheme[] }>(path.join(SRC, 'teamThemes.ts'));
  const builtin = await importTs<{ BUILTIN_THEME_CODES: typeof BUILTIN_THEME_CODES }>(path.join(SRC, 'builtinThemeCodes.ts'));
  // One id and one name per theme across every list: a pasted code that
  // matches a theme picks it by its canonical code, and a slot stores the id.
  const ids = new Set<string>();
  const names = new Set<string>();
  const read = (code: string, where: string, author?: string): ThemeCard => {
    const theme = tc.parseThemeCode(code);
    if (!theme) throw new Error(`themes-page: ${where} is not a theme code`);
    if (tc.serializeThemeCode(theme) !== code) {
      throw new Error(`themes-page: "${theme.name}" is not in the form the app copies; use ${tc.serializeThemeCode(theme)}`);
    }
    const failing = tc.checkTheme(theme).filter((c) => !c.pass).map((c) => c.id);
    if (failing.length > 0) {
      throw new Error(`themes-page: "${theme.name}" fails ${failing.join(', ')}; run pnpm theme:check on it`);
    }
    if (author !== undefined && !GITHUB_USER.test(author)) throw new Error(`themes-page: "${theme.name}" has no GitHub username`);
    if (names.has(theme.name)) throw new Error(`themes-page: two themes are called "${theme.name}"`);
    names.add(theme.name);
    const resolved = tc.resolveTheme(theme);
    return { name: theme.name, mode: resolved.mode, code, author, colors: resolved.colors };
  };
  const listed = ({ id, code, author }: { id: string; code: string; author?: string }, where: string): ThemeCard => {
    if (!/^[a-z0-9]{12}$/.test(id) || ids.has(id)) throw new Error(`themes-page: ${where} needs its own twelve-character id`);
    ids.add(id);
    return read(code, where, author);
  };
  const palettes = [...Object.values(builtin.BUILTIN_THEME_CODES.light), ...Object.values(builtin.BUILTIN_THEME_CODES.dark)];
  return {
    community: COMMUNITY_THEMES.map((t, i) => listed(t, `community entry ${i + 1}`)),
    team: [...palettes.map((code) => read(code, 'a built-in palette')), ...TEAM_THEMES.map((t, i) => listed(t, `team entry ${i + 1}`))],
  };
}

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;').replace(/"/g, '&quot;');
}

/** A small picture of the app in the theme: sidebar, list and note. */
function preview(c: Record<string, string>): string {
  const vars = [
    `--s0:${c['surface-0']}`, `--s1:${c['surface-1']}`, `--s2:${c['surface-2']}`, `--bd:${c.divider}`,
    `--tx:${c.text}`, `--so:${c['text-soft']}`, `--mu:${c['text-muted']}`, `--ac:${c.accent}`, `--fl:${c['accent-fill']}`,
  ].join(';');
  return `<div class="mini" aria-hidden="true" style="${vars}">
<div class="m-side"><i class="sel"></i><i class="ln so"></i><i class="ln so w6"></i><i class="ln mu w4"></i></div>
<div class="m-list"><i class="row"><b class="ln w9"></b><b class="ln mu w6"></b></i><i class="row plain"><b class="ln w7"></b><b class="ln mu w5"></b></i></div>
<div class="m-ed"><i class="ln h w7"></i><i class="ln so"></i><i class="ln so w8"></i><i class="ln ac w4"></i><b class="m-btn"></b></div>
</div>`;
}

function card(t: ThemeCard, i: number): string {
  const by = t.author
    ? `by <a href="https://github.com/${t.author}" target="_blank" rel="noopener noreferrer nofollow">@${t.author}</a>`
    : 'Already in the app';
  const id = `theme-code-${i + 1}`;
  return `<article class="tc" data-mode="${t.mode}">
${preview(t.colors)}
<div class="tc-head"><h2 dir="auto">${esc(t.name)}</h2><span class="tag">${t.mode === 'dark' ? 'Dark' : 'Light'}</span></div>
<p class="by">${by}</p>
<code id="${id}" class="code" dir="ltr">${esc(t.code)}</code>
<button class="pill cbtn" type="button" data-copy="${id}" hidden>Copy code</button>
</article>`;
}

const PAGE_CSS = `.lead{color:var(--muted);font-size:16px;margin:0 0 14px;max-width:640px}
.lead a{font-weight:600}
.steps{list-style:none;display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:10px;margin:0 0 22px;padding:0}
@media(max-width:640px){.steps{grid-template-columns:minmax(0,1fr)}}
.steps li{display:flex;align-items:flex-start;gap:10px;border:1px solid var(--line);border-radius:10px;background:var(--rail);padding:12px 14px}
.steps .n{flex-shrink:0;display:inline-flex;align-items:center;justify-content:center;width:22px;height:22px;border-radius:50%;background:var(--imp-bg);color:var(--mark-fg);font-size:12px;font-weight:700}
.st-t{display:block;font-size:14px;font-weight:600;line-height:22px;color:var(--fg)}
.st-d{display:block;font-size:13px;line-height:1.45;color:var(--muted)}
.tfi{position:absolute;opacity:0;pointer-events:none}
.filter{display:flex;gap:6px;margin:0 0 16px}
.filter label{border:1px solid var(--line);border-radius:999px;padding:3px 12px;font-size:13px;font-weight:600;cursor:pointer;color:var(--muted);background:var(--bg)}
.filter label:hover{color:var(--fg)}
#tf-all:checked~.filter label[for=tf-all],#tf-light:checked~.filter label[for=tf-light],#tf-dark:checked~.filter label[for=tf-dark],#mb-all:checked~.filter label[for=mb-all],#mb-community:checked~.filter label[for=mb-community],#mb-team:checked~.filter label[for=mb-team]{background:var(--fg);border-color:var(--fg);color:var(--bg)}
#tf-all:focus-visible~.filter label[for=tf-all],#tf-light:focus-visible~.filter label[for=tf-light],#tf-dark:focus-visible~.filter label[for=tf-dark],#mb-all:focus-visible~.filter label[for=mb-all],#mb-community:focus-visible~.filter label[for=mb-community],#mb-team:focus-visible~.filter label[for=mb-team]{outline:2px solid var(--accent);outline-offset:2px}
#tf-light:checked~.tgrid .tc[data-mode=dark],#tf-dark:checked~.tgrid .tc[data-mode=light]{display:none}
#mb-community:checked~.by-team,#mb-team:checked~.by-community{display:none}
.filter .fl{font-size:13px;color:var(--muted);align-self:center;min-width:64px}
.sec{font-size:18px;margin:26px 0 4px}
.sec-d{color:var(--muted);font-size:14px;margin:0 0 12px}
.tgrid{display:grid;grid-template-columns:repeat(3,minmax(0,1fr));gap:14px}
@media(max-width:860px){.tgrid{grid-template-columns:repeat(2,minmax(0,1fr))}}
@media(max-width:560px){.tgrid{grid-template-columns:minmax(0,1fr)}}
.tc{border:1px solid var(--line);border-radius:12px;background:var(--rail);padding:10px;display:flex;flex-direction:column;gap:6px;min-width:0}
.mini{display:grid;grid-template-columns:28% 32% 40%;height:92px;border-radius:8px;overflow:hidden;border:1px solid var(--bd)}
.mini>div{display:flex;flex-direction:column;gap:6px;padding:8px 6px;min-width:0}
.mini i,.mini b{display:block}
.m-side{background:var(--s0)}.m-list{background:var(--s1);border-left:1px solid var(--bd)}.m-ed{background:var(--s2);border-left:1px solid var(--bd)}
.ln{height:4px;border-radius:2px;background:var(--tx);width:100%}
.ln.so{background:var(--so)}.ln.mu{background:var(--mu)}.ln.ac{background:var(--ac)}.ln.h{height:6px}
.w9{width:90%}.w8{width:80%}.w7{width:70%}.w6{width:60%}.w5{width:50%}.w4{width:40%}
.sel{height:12px;border-radius:4px;background:color-mix(in srgb,var(--ac) 22%,var(--s0))}
.row{display:flex;flex-direction:column;gap:4px;padding:5px 4px;border-radius:4px;border-left:2px solid var(--ac);background:color-mix(in srgb,var(--ac) 14%,var(--s1))}
.row.plain{border-left-color:transparent;background:none}
.m-btn{width:44%;height:12px;border-radius:4px;background:var(--fl);margin-top:auto}
.tc-head{display:flex;align-items:center;justify-content:space-between;gap:8px;margin-top:4px}
.tc-head h2{font-size:15px;font-weight:650;margin:0;overflow:hidden;text-overflow:ellipsis;white-space:nowrap}
.tag{font-size:11px;color:var(--muted);border:1px solid var(--line);border-radius:999px;padding:0 8px;flex-shrink:0}
.by{margin:0;font-size:12.5px;color:var(--muted)}
.code{display:block;font-size:11.5px;background:var(--chip);border-radius:6px;padding:5px 7px;overflow-wrap:anywhere;color:var(--fg)}
.pill{align-self:flex-start;display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 12px;font-size:12px;font-weight:600;color:var(--accent);background:var(--bg);cursor:pointer}
.pill:hover{border-color:var(--accent)}
.cbtn[hidden]{display:none}
.cbtn.on{border-color:var(--accent)}
.submit{display:flex;align-items:center;justify-content:space-between;flex-wrap:wrap;gap:12px 20px;border:1px solid var(--line);border-radius:12px;background:var(--rail);padding:16px 18px;margin-top:28px;font-size:14px}
.submit h2{font-size:16px;margin:0 0 4px}
.submit p{margin:0;color:var(--muted);max-width:620px}
.submit .btn{flex-shrink:0}
.btn-tint{background:var(--imp-bg);color:var(--mark-fg);font-size:14px;font-weight:600;padding:10px 16px;border:1px solid transparent}
.btn-tint:hover{border-color:var(--mark-fg)}`;

function renderHtml({ community, team }: ThemeLists): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${TITLE}</title>
<meta name="description" content="${DESC}">
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
  '--bg:#fff;--fg:#15171a;--muted:#5b6168;--faint:#8a9099;--line:#e7e9ec;--accent:#1E40AF;--imp-bg:#eff6ff;--mark-fg:#1E40AF;--chip:#eceef1;--rail:#f7f8fa;--on-accent:#fff',
  '--bg:#0e1014;--fg:#e7e9ec;--muted:#9aa1aa;--faint:#6b7178;--line:#23262c;--accent:#4A90D9;--imp-bg:#11233a;--mark-fg:#7FB0E4;--chip:#23272e;--rail:#14171d;--on-accent:#03203E'
)}
${THEME_TOGGLE_CSS}
${CHROME_CSS}
${PAGE_CSS}
</style>
</head>
<body data-static-page="themes">
<div class="wrap">
${siteNav({ active: 'themes' })}
<h1>Themes</h1>
<p class="lead">Color themes for the app, ready to copy. Made one? <a href="${SUBMIT_URL}" target="_blank" rel="noopener noreferrer">Submit your theme<span aria-hidden="true"> &rarr;</span></a></p>
<ol class="steps" role="list">
<li><span class="n" aria-hidden="true">1</span><div><span class="st-t">Copy a code</span><span class="st-d">Press Copy code on any theme below.</span></div></li>
<li><span class="n" aria-hidden="true">2</span><div><span class="st-t">Paste it in the app</span><span class="st-d">Settings &rsaquo; Appearance &rsaquo; Themes</span></div></li>
<li><span class="n" aria-hidden="true">3</span><div><span class="st-t">Save it</span><span class="st-d">It shows at once. Saving needs Pro.</span></div></li>
</ol>
<input class="tfi" type="radio" name="tf" id="tf-all" checked>
<input class="tfi" type="radio" name="tf" id="tf-light">
<input class="tfi" type="radio" name="tf" id="tf-dark">
${community.length > 0 ? `<input class="tfi" type="radio" name="mb" id="mb-all" checked>
<input class="tfi" type="radio" name="mb" id="mb-community">
<input class="tfi" type="radio" name="mb" id="mb-team">
<div class="filter" role="group" aria-label="Made by"><span class="fl" aria-hidden="true">Made by</span><label for="mb-all">All</label><label for="mb-community">Community</label><label for="mb-team">Team</label></div>
<div class="filter" role="group" aria-label="Mode"><span class="fl" aria-hidden="true">Mode</span><label for="tf-all">All</label><label for="tf-light">Light</label><label for="tf-dark">Dark</label></div>
<h2 class="sec by-community">Community themes</h2>
<p class="sec-d by-community">Made by people who use the app.</p>
<div class="tgrid by-community">
${community.map(card).join('\n')}
</div>` : `<div class="filter" role="group" aria-label="Show"><label for="tf-all">All</label><label for="tf-light">Light</label><label for="tf-dark">Dark</label></div>`}
<h2 class="sec by-team">Made by the team</h2>
<p class="sec-d by-team">Already in the app. Each code lists the colors, so you can change any of them and paste your own version.</p>
<div class="tgrid by-team">
${team.map((t, i) => card(t, community.length + i)).join('\n')}
</div>
<section class="submit">
<div>
<h2>${community.length > 0 ? 'Made a theme you like?' : 'Be the first community theme'}</h2>
<p>Copy its code from the menu on its card in the app and send it to us on GitHub. Themes we add show your GitHub username, and we may adjust a color so text stays easy to read.</p>
</div>
<a class="btn btn-tint" href="${SUBMIT_URL}" target="_blank" rel="noopener noreferrer"><svg width="14" height="14" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M216,104v8a56.06,56.06,0,0,1-48.44,55.47A39.8,39.8,0,0,1,176,192v40a8,8,0,0,1-8,8H104a8,8,0,0,1-8-8V216H72a40,40,0,0,1-40-40A24,24,0,0,0,8,152a8,8,0,0,1,0-16,40,40,0,0,1,40,40,24,24,0,0,0,24,24H96v-8a39.8,39.8,0,0,1,8.44-24.53A56.06,56.06,0,0,1,56,112v-8a58.14,58.14,0,0,1,7.69-28.32A59.78,59.78,0,0,1,69.07,28,8,8,0,0,1,76,24a59.75,59.75,0,0,1,48,24h24a59.75,59.75,0,0,1,48-24,8,8,0,0,1,6.93,4,59.74,59.74,0,0,1,5.37,47.68A58,58,0,0,1,216,104Z"/></svg>Submit a theme on GitHub</a>
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
          res.end(renderHtml(await loadThemes()));
        } catch (err) {
          next(err);
        }
      });
    },
  };
}
