import { transformWithOxc, type Plugin } from 'vite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { THEME_SCRIPT_TAG, THEME_TOGGLE_CSS, themeVarsCss } from './static-page-theme.ts';
import { brandMark, CHROME_CSS, OG_IMAGE_TAGS, ogLocaleTag, SITE_FOOTER, siteNav } from './static-page-chrome.ts';
// Type-only, so it erases at build time and leaves src/roadmap.ts the
// import-free module loadRoadmap() transpiles and imports as a data URL.
import type { RoadmapIcon } from './src/roadmap.ts';

// Pre-renders a static /roadmap page from the single source of truth:
// src/roadmap.ts. Emitted as roadmap/index.html so Cloudflare serves it
// directly at /roadmap (a real file always wins over the SPA fallback),
// and it stays in sync with the in-app Roadmap tab because both read the
// same array.
//
// Layout is a centered zigzag: one spine down the middle, cards alternating
// left and right off it. The spine is the point of the page - solid through
// everything shipped, accent-colored across the work in flight, dashed
// beyond it - so the shape of the progress reads before a single word does.
// A "You are here" marker sits on the boundary.
//
// Why zigzag rather than the old single left-aligned column: the shell is
// 1040px because the header nav needs that room, and a one-sided timeline
// left half of every row empty. This uses the width it already has.
//
// Below 860px it folds back to exactly what it was - one column, spine on
// the left - because alternating sides needs width to read as alternating.
//
// The page ships zero inline scripts: the deployed CSP allows
// 'unsafe-inline' for style-src but NOT script-src, so inline <script>
// would be blocked. The only JS is the external same-origin
// /theme-toggle.js (script-src 'self'), shared via static-page-theme.ts.

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const ROADMAP_SRC = path.resolve(__dirname, 'src/roadmap.ts');

type RoadmapStatus = 'shipped' | 'in-progress' | 'in-review' | 'up-next' | 'final';
type RoadmapItem = {
  id: string;
  title: string;
  status: RoadmapStatus;
  description: string;
  icon: RoadmapIcon;
};

// Transpile roadmap.ts (a self-contained module with no imports) with
// Oxc and import it as a data-URL ES module to pull out the data. Same
// approach as help-page.ts and changelog-page.ts.
export async function loadRoadmap(): Promise<{
  items: RoadmapItem[];
  labels: Record<RoadmapStatus, string>;
}> {
  const src = fs.readFileSync(ROADMAP_SRC, 'utf8');
  const { code } = await transformWithOxc(src, ROADMAP_SRC, { lang: 'ts' });
  const module = (await import(
    'data:text/javascript;base64,' + Buffer.from(code).toString('base64')
  )) as Record<string, unknown>;
  return {
    items: module.PUBLIC_ROADMAP as RoadmapItem[],
    labels: module.ROADMAP_STATUS_LABEL as Record<RoadmapStatus, string>,
  };
}

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

// Milestone glyphs, in the same 24-box stroke family as the header icons so
// the whole static site draws one icon set. Keyed by RoadmapIcon in
// src/roadmap.ts, which holds keys only and no markup.
const S =
  '<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';

const ICONS: Record<RoadmapIcon, string> = {
  shield: `${S}<path d="M12 3l7 3v6c0 4.4-3 8-7 9-4-1-7-4.6-7-9V6z"/><polyline points="9 12 11 14 15 10"/></svg>`,
  globe: `${S}<circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a15 15 0 0 1 0 18"/><path d="M12 3a15 15 0 0 0 0 18"/></svg>`,
  download: `${S}<line x1="12" y1="3" x2="12" y2="15"/><polyline points="8 11 12 15 16 11"/><path d="M4 17v2a2 2 0 0 0 2 2h12a2 2 0 0 0 2-2v-2"/></svg>`,
  flame: `${S}<path d="M12 21c3.3 0 6-2.3 6-5.5 0-3.7-3-5.6-3.6-9.5-1.9 1.3-2.4 3.2-2.4 4.6C11 8.4 9.6 7 9.6 5 7.4 6.8 6 9.2 6 12.4 6 17 8.7 21 12 21z"/></svg>`,
  unlock: `${S}<rect x="4" y="11" width="16" height="10" rx="2"/><path d="M8 11V7a4 4 0 0 1 7.5-2"/></svg>`,
  bug: `${S}<path d="M8 9a4 4 0 0 1 8 0"/><rect x="7" y="9" width="10" height="10" rx="5"/><line x1="3" y1="13" x2="7" y2="13"/><line x1="17" y1="13" x2="21" y2="13"/><line x1="4.5" y1="8" x2="7.5" y2="10"/><line x1="19.5" y1="8" x2="16.5" y2="10"/><line x1="4.5" y1="18.5" x2="7.5" y2="16.5"/><line x1="19.5" y1="18.5" x2="16.5" y2="16.5"/></svg>`,
  rocket: `${S}<path d="M13 4c4 1 7 4 7 8-2.6 2.6-5 4-8 5l-3-3c1-3 2.4-5.4 4-8z"/><line x1="9" y1="14" x2="5" y2="18"/><path d="M7 11H5l-2 3 3 1"/><circle cx="14.5" cy="9.5" r="1.4"/></svg>`,
  play: `${S}<circle cx="12" cy="12" r="9"/><polygon points="10 8.5 16 12 10 15.5"/></svg>`,
  desktop: `${S}<rect x="3" y="4" width="18" height="12" rx="2"/><line x1="8" y1="20" x2="16" y2="20"/><line x1="12" y1="16" x2="12" y2="20"/></svg>`,
  windows: `${S}<path d="M4 6.5l7-1v6H4z"/><path d="M13 5.2l7-1v7.3h-7z"/><path d="M4 13.5h7v6l-7-1z"/><path d="M13 13.5h7v7.3l-7-1z"/></svg>`,
  linux: `${S}<path d="M9 4.5c0-1.4 1.3-2.5 3-2.5s3 1.1 3 2.5c0 2 .6 3.2 1.6 4.6C18 11 19 12.8 19 15c0 3.3-3.1 6-7 6s-7-2.7-7-6c0-2.2 1-4 2.4-5.9C8.4 7.7 9 6.5 9 4.5z"/><circle cx="10.3" cy="6.4" r=".85" fill="currentColor" stroke="none"/><circle cx="13.7" cy="6.4" r=".85" fill="currentColor" stroke="none"/></svg>`,
  android: `${S}<path d="M5 11a7 7 0 0 1 14 0z"/><line x1="7" y1="6" x2="8.6" y2="8.6"/><line x1="17" y1="6" x2="15.4" y2="8.6"/><rect x="5" y="12.5" width="14" height="7" rx="2"/></svg>`,
  apple: `${S}<path d="M16 12.6c0-2 1.6-3 1.7-3.1-1-1.4-2.4-1.6-2.9-1.6-1.2-.1-2.4.7-3 .7s-1.6-.7-2.6-.7C7.9 8 6.5 8.8 5.8 10c-1.5 2.5-.4 6.3 1 8.4.7 1 1.5 2.1 2.6 2.1s1.4-.7 2.7-.7 1.6.7 2.7.7 1.8-1 2.5-2a9 9 0 0 0 1.1-2.3c-1.4-.6-2.4-2-2.4-3.6z"/><path d="M14.2 5.6c.6-.7 1-1.7.9-2.6-.9 0-1.9.6-2.5 1.3-.5.6-1 1.6-.9 2.5 1 .1 2-.5 2.5-1.2z"/></svg>`,
  store: `${S}<path d="M6 3.5v17c0 .8.9 1.3 1.6.9l11-8.5c.6-.5.6-1.3 0-1.8l-11-8.5C6.9 2.2 6 2.7 6 3.5z"/><line x1="6.5" y1="3.2" x2="15.8" y2="12"/><line x1="6.5" y1="20.8" x2="15.8" y2="12"/></svg>`,
  github: `${S}<path d="M9 19c-4 1.3-4-2-6-2.5m12 4.5v-3.6c0-1 .1-1.5-.5-2 2.3-.3 4.5-1.2 4.5-5a4 4 0 0 0-1-2.7 3.7 3.7 0 0 0-.1-2.7s-.9-.3-3 1a10 10 0 0 0-5 0c-2.1-1.3-3-1-3-1a3.7 3.7 0 0 0-.1 2.7 4 4 0 0 0-1 2.7c0 3.8 2.2 4.7 4.5 5-.5.5-.5 1-.5 2V21"/></svg>`,
  certificate: `${S}<circle cx="12" cy="9" r="5.5"/><polyline points="8.5 13.6 7.5 21 12 18.5 16.5 21 15.5 13.6"/></svg>`,
  folder: `${S}<path d="M3 7a2 2 0 0 1 2-2h3.5l2 2.5H19a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>`,
  languages: `${S}<line x1="3.5" y1="6" x2="11.5" y2="6"/><path d="M7.5 4v2c0 3.5-1.8 6.4-4 8"/><path d="M5 11.5c1.8 2.2 3.9 3.6 6 4.5"/><path d="M12 21l4-10 4 10"/><line x1="13.4" y1="17.5" x2="18.6" y2="17.5"/></svg>`,
  help: `${S}<circle cx="12" cy="12" r="9"/><path d="M9.5 9.2A2.6 2.6 0 0 1 12 7.5c1.5 0 2.6 1 2.6 2.3 0 2-2.6 2-2.6 4"/><circle cx="12" cy="16.8" r=".95" fill="currentColor" stroke="none"/></svg>`,
  key: `${S}<circle cx="8" cy="14" r="4"/><line x1="11" y1="11.5" x2="20" y2="3"/><line x1="17" y1="6" x2="19.5" y2="8.5"/><line x1="14.5" y1="8.5" x2="17" y2="11"/></svg>`,
  pencil: `${S}<path d="M4 20h4L19.5 8.5a2.1 2.1 0 0 0-3-3L5 17z"/><line x1="14.5" y1="6.5" x2="17.5" y2="9.5"/></svg>`,
  grid: `${S}<rect x="3.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="3.5" width="7" height="7" rx="1.5"/><rect x="3.5" y="13.5" width="7" height="7" rx="1.5"/><rect x="13.5" y="13.5" width="7" height="7" rx="1.5"/></svg>`,
  sync: `${S}<path d="M20 11a8 8 0 0 0-14-4.5L4 9"/><polyline points="4 4 4 9 9 9"/><path d="M4 13a8 8 0 0 0 14 4.5L20 15"/><polyline points="20 20 20 15 15 15"/></svg>`,
  sparkles: `${S}<path d="M12 3l1.7 4.8L18.5 9.5l-4.8 1.7L12 16l-1.7-4.8L5.5 9.5l4.8-1.7z"/><path d="M18 16l.8 2.2L21 19l-2.2.8L18 22l-.8-2.2L15 19l2.2-.8z"/></svg>`,
  lock: `${S}<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1.2" fill="currentColor" stroke="none"/></svg>`,
  chart: `${S}<polyline points="3 19 3 5"/><line x1="3" y1="19.5" x2="21" y2="19.5"/><rect x="6" y="12" width="3.2" height="7"/><rect x="11.4" y="8" width="3.2" height="11"/><rect x="16.8" y="14.5" width="3.2" height="4.5"/></svg>`,
  check: `${S}<rect x="3.5" y="3.5" width="17" height="17" rx="3.5"/><polyline points="8.2 12.3 11 15 15.8 9.6"/></svg>`,
  fingerprint: `${S}<path d="M12 21c-1.4-2-2-4-2-6a2 2 0 0 1 4 0c0 1 .2 2.1.7 3.2"/><path d="M8 19.4c-1-2.1-1.5-4.2-1.5-6.4a5.5 5.5 0 0 1 11 0c0 1.4-.2 2.7-.6 4"/><path d="M4.6 15.6A9.4 9.4 0 0 1 4 13a8 8 0 0 1 12.6-6.6"/></svg>`,
  qr: `${S}<rect x="3.5" y="3.5" width="6.5" height="6.5" rx="1.4"/><rect x="14" y="3.5" width="6.5" height="6.5" rx="1.4"/><rect x="3.5" y="14" width="6.5" height="6.5" rx="1.4"/><line x1="14" y1="14" x2="14" y2="17.5"/><line x1="17.5" y1="20.5" x2="20.5" y2="20.5"/><line x1="20.5" y1="14" x2="20.5" y2="17"/></svg>`,
  devices: `${S}<rect x="2.5" y="4.5" width="12" height="9" rx="1.8"/><line x1="5.5" y1="17.5" x2="11.5" y2="17.5"/><line x1="8.5" y1="13.5" x2="8.5" y2="17.5"/><rect x="16.5" y="9" width="5" height="11" rx="1.6"/></svg>`,
  database: `${S}<ellipse cx="12" cy="6" rx="8" ry="3"/><path d="M4 6v12c0 1.7 3.6 3 8 3s8-1.3 8-3V6"/><path d="M4 12c0 1.7 3.6 3 8 3s8-1.3 8-3"/></svg>`,
  graph: `${S}<circle cx="5.5" cy="6.5" r="2.5"/><circle cx="18.5" cy="7.5" r="2.5"/><circle cx="12" cy="18" r="2.5"/><line x1="7.6" y1="8" x2="10.6" y2="15.7"/><line x1="16.9" y1="9.5" x2="13.6" y2="15.9"/><line x1="8" y1="6.9" x2="16" y2="7.2"/></svg>`,
  timer: `${S}<circle cx="12" cy="13.5" r="7.5"/><line x1="12" y1="9.5" x2="12" y2="13.5"/><line x1="12" y1="13.5" x2="15.2" y2="15.4"/><line x1="9.5" y1="2.8" x2="14.5" y2="2.8"/><line x1="12" y1="2.8" x2="12" y2="6"/></svg>`,
  bookmark: `${S}<path d="M6.5 3.5h11a1 1 0 0 1 1 1v16l-6.5-4.3-6.5 4.3v-16a1 1 0 0 1 1-1z"/></svg>`,
  sidebar: `${S}<rect x="3" y="4.5" width="18" height="15" rx="2"/><line x1="9.5" y1="4.5" x2="9.5" y2="19.5"/><line x1="5.7" y1="9" x2="7.3" y2="9"/><line x1="5.7" y1="12" x2="7.3" y2="12"/><line x1="5.7" y1="15" x2="7.3" y2="15"/></svg>`,
  robot: `${S}<rect x="4" y="8" width="16" height="11" rx="3"/><line x1="12" y1="4.3" x2="12" y2="8"/><circle cx="12" cy="3" r="1.3"/><circle cx="9.2" cy="13" r="1.1" fill="currentColor" stroke="none"/><circle cx="14.8" cy="13" r="1.1" fill="currentColor" stroke="none"/><line x1="2.4" y1="12.2" x2="4" y2="12.2"/><line x1="20" y1="12.2" x2="21.6" y2="12.2"/></svg>`,
};

/** Everything not yet shipped and not deferred past 1.0 is the live edge. */
function statusPhase(status: RoadmapStatus): 'done' | 'live' | 'future' {
  if (status === 'shipped') return 'done';
  if (status === 'final') return 'future';
  return 'live';
}

function counts(items: RoadmapItem[]) {
  const done = items.filter((i) => statusPhase(i.status) === 'done').length;
  const live = items.filter((i) => statusPhase(i.status) === 'live').length;
  return { done, live, future: items.length - done - live, total: items.length };
}

function renderItems(items: RoadmapItem[], labels: Record<RoadmapStatus, string>): string {
  const firstLive = items.findIndex((i) => statusPhase(i.status) === 'live');
  const firstFuture = items.findIndex((i) => statusPhase(i.status) === 'future');

  const rows = items
    .map((it, i) => {
      const phase = statusPhase(it.status);
      const side = i % 2 === 0 ? 'l' : 'r';
      const marker =
        i === firstLive
          ? '<li class="mark mark-now"><span>You are here</span></li>\n'
          : i === firstFuture
            ? `<li class="mark mark-later"><span>${esc(labels.final)}</span></li>\n`
            : '';
      const icon = ICONS[it.icon] ?? ICONS.rocket;
      return `${marker}<li class="item side-${side} p-${phase}" id="${esc(it.id)}">
<span class="node" aria-hidden="true"></span>
<span class="stub" aria-hidden="true"></span>
<div class="card">
<span class="ico">${icon}</span>
<div class="txt">
<span class="badge b-${esc(it.status)}">${esc(labels[it.status])}</span>
<h2 class="t">${esc(it.title)}</h2>
<p class="d">${esc(it.description)}</p>
</div>
</div>
</li>`;
    })
    .join('\n');

  const c = counts(items);
  const pctDone = ((c.done / c.total) * 100).toFixed(2);
  const pctLive = ((c.live / c.total) * 100).toFixed(2);

  return `<div class="meter">
<div class="bar" role="img" aria-label="${c.done} of ${c.total} milestones shipped">
<span class="bar-done" style="width:${pctDone}%"></span><span class="bar-live" style="width:${pctLive}%"></span>
</div>
<div class="legend">
<span class="lg lg-done">${c.done} shipped</span>
<span class="lg lg-live">${c.live} in flight</span>
<span class="lg lg-future">${c.future} after 1.0</span>
</div>
</div>
<ol class="tl">
${rows}
</ol>`;
}

/* Page CSS. NOTE: no backticks anywhere in here, including comments - this is
   a template literal, and a stray one closes it silently. That surfaces as a
   vite config that will not load, not as a CSS bug, so it is easy to misread. */
const PAGE_CSS = `.meter{display:flex;align-items:center;gap:20px;border:1px solid var(--line);border-radius:14px;padding:14px 18px;margin:22px 0 0}
.bar{flex:1;min-width:0;height:8px;border-radius:99px;background:var(--late-bg);overflow:hidden;display:flex}
.bar-done{background:var(--node-done)}
.bar-live{background:var(--next-fg)}
.legend{display:flex;gap:16px;font-size:12.5px;white-space:nowrap;flex-wrap:wrap}
.lg::before{content:"";display:inline-block;width:8px;height:8px;border-radius:50%;margin-right:6px;vertical-align:1px}
.lg-done{color:var(--done-fg)}.lg-done::before{background:var(--node-done)}
.lg-live{color:var(--next-fg)}.lg-live::before{background:var(--next-fg)}
.lg-future{color:var(--faint)}.lg-future::before{border:1.5px dashed var(--faint);box-sizing:border-box}

/* The spine, painted as one gradient rather than three stacked elements so
   the shipped-to-in-flight-to-speculative transition can never drift out of
   step with the list. Stops come from the real counts (--done-end,
   --live-end), computed in renderHtml. */
.tl{list-style:none;margin:34px 0 0;padding:0;position:relative}
.tl::before{content:"";position:absolute;left:50%;transform:translateX(-50%);top:0;bottom:0;width:3px;border-radius:2px;background:linear-gradient(var(--node-done) 0 var(--done-end),var(--next-fg) var(--done-end) var(--live-end),transparent var(--live-end) 100%)}
.tl::after{content:"";position:absolute;left:50%;transform:translateX(-50%);top:var(--live-end);bottom:0;width:3px;background:repeating-linear-gradient(var(--node) 0 7px,transparent 7px 14px)}

.item{position:relative;display:grid;grid-template-columns:1fr 1fr;column-gap:76px;margin-bottom:18px;scroll-margin-top:16px}
.item:last-child{margin-bottom:0}
.side-l .card{grid-column:1}
.side-r .card{grid-column:2}
.node{position:absolute;left:50%;top:26px;transform:translateX(-50%);width:14px;height:14px;border-radius:50%;box-sizing:border-box;z-index:2;background:var(--bg);border:2px solid var(--node)}
.p-done .node{background:var(--node-done);border-color:var(--node-done)}
.p-live .node{border:3px solid var(--next-fg);box-shadow:0 0 0 5px var(--next-halo)}
.p-future .node{border-style:dashed;border-color:var(--faint)}
/* Short connector from spine to card, so a card reads as attached to its own
   node rather than merely near it. */
.stub{position:absolute;top:32px;width:38px;height:2px;background:var(--line);z-index:1}
.side-l .stub{right:50%}
.side-r .stub{left:50%}
.p-live .stub{background:var(--next-fg)}

.card{display:flex;gap:13px;align-items:flex-start;border:1px solid var(--line);border-radius:14px;padding:14px 16px;background:var(--bg)}
.ico{flex:0 0 auto;width:36px;height:36px;border-radius:10px;background:var(--rail);color:var(--muted);display:flex;align-items:center;justify-content:center}
.txt{min-width:0}
.badge{display:inline-block;font-size:9.5px;font-weight:600;letter-spacing:.07em;text-transform:uppercase;padding:2px 7px;border-radius:20px;margin-bottom:6px}
.b-shipped{background:var(--done-bg);color:var(--done-fg)}
.b-in-progress{background:var(--prog-bg);color:var(--prog-fg)}
.b-in-review{background:var(--rev-bg);color:var(--rev-fg)}
.b-up-next{background:var(--next-bg);color:var(--next-fg)}
.b-final{background:var(--late-bg);color:var(--late-fg)}
.t{font-size:15px;font-weight:650;letter-spacing:-.01em;margin:0 0 3px}
.d{font-size:13px;color:var(--muted);margin:0}
/* Shipped work steps back so attention lands on what is next. Still fully
   legible at 78% - this is de-emphasis, not a grey-out. */
.p-done{opacity:.78}
.p-done .card{background:var(--rail)}
.p-live .card{border-color:var(--next-fg);border-width:2px;padding:13px 15px}
.p-live .ico{background:var(--next-bg);color:var(--next-fg)}
.p-future .card{border-style:dashed}

.mark{position:relative;display:flex;justify-content:center;margin:26px 0 20px;z-index:3}
.mark span{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10.5px;font-weight:600;letter-spacing:.16em;text-transform:uppercase;padding:5px 16px;border-radius:99px;background:var(--bg)}
.mark-now span{background:var(--next-bg);color:var(--next-fg)}
.mark-later span{color:var(--faint);border:1px dashed var(--node)}

/* One column below 860px. Alternating sides needs width to read as
   alternating; at phone size a zigzag is just a wobble. The spine moves to
   the left edge, which is the layout this page had before. */
@media(max-width:860px){
.tl::before,.tl::after{left:6px;transform:none}
.item{grid-template-columns:minmax(0,1fr);column-gap:0;padding-left:40px}
.side-l .card,.side-r .card{grid-column:1}
.node{left:6px;transform:none}
.stub{left:6px;right:auto;width:26px}
.mark{justify-content:flex-start;margin-left:-4px}
}
@media(max-width:600px){
.meter{flex-direction:column;align-items:stretch;gap:12px;padding:14px}
.legend{justify-content:space-between;gap:10px}
.item{padding-left:32px}
.stub{width:18px}
.card{padding:12px 13px;gap:11px}
.ico{width:32px;height:32px}
}`;

export function renderHtml(items: RoadmapItem[], labels: Record<RoadmapStatus, string>): string {
  // Spine color stops come from the real counts, so adding a milestone can
  // never leave the gradient describing a list that no longer exists.
  const c = counts(items);
  const doneEnd = ((c.done / c.total) * 100).toFixed(2);
  const liveEnd = (((c.done + c.live) / c.total) * 100).toFixed(2);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Roadmap - PrivacyNotes</title>
<meta name="description" content="Where PrivacyNotes is headed: native apps for every platform, then opening the full codebase and an independent security audit.">
<link rel="canonical" href="https://privacynotes.app/roadmap">
<meta property="og:title" content="Roadmap - PrivacyNotes">
<meta property="og:description" content="Where PrivacyNotes is headed: native apps for every platform, then opening the full codebase and an independent security audit.">
<meta property="og:type" content="website">
<meta property="og:url" content="https://privacynotes.app/roadmap">
<meta property="og:site_name" content="PrivacyNotes">
${ogLocaleTag()}
${OG_IMAGE_TAGS}
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
${THEME_SCRIPT_TAG}
<script src="/static-pages.js" defer></script>
<style>
${themeVarsCss(
  '--bg:#fff;--fg:#15171a;--muted:#5b6168;--faint:#8a9099;--line:#e7e9ec;--accent:#1E40AF;--imp-bg:#eff6ff;--mark-fg:#1E40AF;--chip:#eceef1;--rail:#f7f8fa;--on-accent:#fff;--done-bg:#eaf3de;--done-fg:#3b6d11;--prog-bg:#eff6ff;--prog-fg:#0c447c;--rev-bg:#f1e9fb;--rev-fg:#5b2ea6;--next-bg:#faeeda;--next-fg:#8f570b;--next-halo:rgba(239,159,39,.16);--late-bg:#eceef1;--late-fg:#5b6168;--node:#c9ced3;--node-done:#639922',
  '--bg:#0e1014;--fg:#e7e9ec;--muted:#9aa1aa;--faint:#6b7178;--line:#23262c;--accent:#4A90D9;--imp-bg:#11233a;--mark-fg:#7FB0E4;--chip:#3a4149;--rail:#14171d;--on-accent:#03203E;--done-bg:#1c2a14;--done-fg:#a7cf6f;--prog-bg:#11233a;--prog-fg:#85b7eb;--rev-bg:#251a3a;--rev-fg:#bda2f2;--next-bg:#2e2410;--next-fg:#e3a84e;--next-halo:rgba(227,168,78,.18);--late-bg:#23262c;--late-fg:#9aa1aa;--node:#3a3f47;--node-done:#97c459'
)}
${THEME_TOGGLE_CSS}
${CHROME_CSS}
:root{--done-end:${doneEnd}%;--live-end:${liveEnd}%}
${PAGE_CSS}
</style>
</head>
<body data-static-page="roadmap">
<div class="wrap">
${siteNav({ active: 'roadmap' })}
<h1>Roadmap</h1>
<p class="sub">Where ${brandMark()} is headed. ${c.done} of ${c.total} milestones are done.</p>
${renderItems(items, labels)}
</div>
${SITE_FOOTER}
</body>
</html>`;
}

export function roadmapPagePlugin(): Plugin {
  return {
    name: 'emit-roadmap-page',
    async generateBundle() {
      const { items, labels } = await loadRoadmap();
      this.emitFile({
        type: 'asset',
        fileName: 'roadmap/index.html',
        source: renderHtml(items, labels),
      });
    },
    configureServer(server) {
      // Serve /roadmap in dev so the page can be verified locally without
      // a production build.
      server.middlewares.use('/roadmap', async (_req, res, next) => {
        try {
          const { items, labels } = await loadRoadmap();
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(renderHtml(items, labels));
        } catch (err) {
          next(err);
        }
      });
    },
  };
}
