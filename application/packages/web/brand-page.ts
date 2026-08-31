import { type Plugin } from 'vite';
import { THEME_SCRIPT_TAG, THEME_TOGGLE_CSS, themeVarsCss } from './static-page-theme.ts';
import { brandMark, CHROME_CSS, OG_IMAGE_TAGS, ogLocaleTag, SITE_FOOTER, siteNav } from './static-page-chrome.ts';

// Pre-renders the static /brand page: brand assets + press kit. Emitted as
// brand/index.html so Cloudflare serves it directly at /brand, same pattern
// as roadmap-page.ts. English-only by the i18n tier policy (like changelog
// and roadmap).
//
// The downloadable files live in public/marketing/brand/ ON PURPOSE: the
// app build's pn-strip-marketing-assets plugin deletes dist/marketing/
// from native binaries, so the assets ride that gate automatically and
// never ship in a DMG/APK. Spec: ops/docs/bundle-size.md (static site out
// of the app payload). This page plugin itself sits in the isAppBuild
// exclusion list in vite.config.ts like the other static pages.
//
// The page ships zero inline scripts (CSP allows style-src 'unsafe-inline'
// but script-src is 'self' only). The copy buttons are wired by the
// external /static-pages.js via body data-static-page="brand"; they ship
// hidden and the page renders complete without JS - every text block is
// selectable as-is.
//
// Wordmark rule (the reason half these files exist): "Privacy" is always
// blue - Brand Blue #1E40AF on light backgrounds, Fold Blue #4F6BD5 on
// dark, where #1E40AF is illegible - and "Notes" is always ink, #0A0A0A
// on light, #FFFFFF on dark. The icon never changes between the light and
// dark lockups; only the wordmark adapts. Two-tone lives only in the logo,
// never in running text. Spec: ops/docs/design-decisions.md (brand kit)

const B = '/marketing/brand';
const CANONICAL = 'https://privacynotes.app/brand';
const DESC =
  'Official PrivacyNotes logos, icons, colors, and boilerplate. Download individual SVG and PNG assets and copy ready-made descriptions for articles and app round-ups.';

type Tile = 'light' | 'dark';
type Card = {
  file: string;
  title: string;
  tile: Tile;
  kind: 'lockup' | 'wordmark' | 'icon';
  png: string;
  note?: string;
};

// There is deliberately NO monochrome variant. Knocking the mark down to one
// color loses the corner fold (the fold reads only as a lighter blue against
// the body), so the document collapses into a plain rectangle. For one-color
// or busy-background contexts the rule is a solid light or dark panel behind
// the color logo, not a flattened mark.
const LOCKUPS: Card[] = [
  { file: 'privacynotes-lockup-color-light', title: 'Color, light backgrounds', tile: 'light', kind: 'lockup', png: '2048 x 373' },
  { file: 'privacynotes-lockup-color-dark', title: 'Color, dark backgrounds', tile: 'dark', kind: 'lockup', png: '2048 x 373' },
];

const ICONS: Card[] = [
  { file: 'privacynotes-icon-color', title: 'Icon, light and dark', tile: 'light', kind: 'icon', png: '943 x 1024' },
];

const WORDMARKS: Card[] = [
  { file: 'privacynotes-wordmark-light', title: 'Wordmark, light', tile: 'light', kind: 'wordmark', png: '1600 x 247' },
  { file: 'privacynotes-wordmark-dark', title: 'Wordmark, dark', tile: 'dark', kind: 'wordmark', png: '1600 x 247' },
];

function card(c: Card): string {
  const note = c.note ? `<span class="note">${c.note}</span>` : '';
  return `<div class="card">
<div class="tile t-${c.tile} k-${c.kind}"><img src="${B}/${c.file}.svg" alt="PrivacyNotes ${c.title}" loading="lazy"></div>
<div class="meta"><div><strong>${c.title}</strong><span class="dims">SVG + PNG ${c.png}</span>${note}</div>
<div class="dl"><a class="pill" href="${B}/${c.file}.svg" download>SVG</a><a class="pill" href="${B}/${c.file}.png" download>PNG</a></div></div>
</div>`;
}

type CopyBlock = { id: string; label: string; text: string };

const COPY: CopyBlock[] = [
  {
    id: 'cp-oneliner',
    label: 'One-liner',
    text: 'The end-to-end encrypted home for your notes, tasks, files, and journal.',
  },
  {
    id: 'cp-short',
    label: 'Short',
    text: 'An end-to-end encrypted workspace for notes, tasks, files, and journal. A 12-word key only you hold. No trackers, no ads.',
  },
  {
    id: 'cp-meta',
    label: 'Meta description',
    text: 'Your notes, encrypted on your device before they ever leave it. A 12-word key only you hold, so not even we can read them. No trackers, no ads, free to start.',
  },
  {
    id: 'cp-boiler',
    label: 'Boilerplate, press',
    text: 'PrivacyNotes is an end-to-end encrypted workspace for your notes, tasks, files, and journal. Every note is encrypted on your device before it syncs, and the only key is a 12-word recovery phrase that never leaves your hands. Lifetime Labs stores ciphertext, nothing else: no trackers, no ads, no telemetry. PrivacyNotes runs on the web and as native apps, and its apps are open source: the clients, the encryption layer and the database schema are all published for review. The free tier is free forever; Pro is a one-time purchase.',
  },
];

function esc(s: string): string {
  return s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/**
 * The page's own sections, in document order. Single source for BOTH the
 * sidebar rail and the h2 that opens each section, so a rail row can never
 * point at a heading that moved or was renamed. Ids are the anchor targets;
 * /brand is a long page and every section is worth linking to directly.
 */
const SECTIONS: Array<{ id: string; label: string; title?: string }> = [
  { id: 'lockup', label: 'Lockup' },
  { id: 'icon', label: 'Icon' },
  { id: 'wordmark', label: 'Wordmark' },
  { id: 'clearspace', label: 'Clearspace', title: 'Clearspace &amp; minimum sizes' },
  { id: 'color', label: 'Color' },
  { id: 'typography', label: 'Typography' },
  { id: 'descriptions', label: 'Descriptions', title: 'Name &amp; descriptions' },
  { id: 'facts', label: 'Fact sheet' },
  { id: 'usage', label: 'Usage' },
];

/** Opens a section: the h2 the rail's matching row scrolls to. */
function h2(id: string): string {
  const s = SECTIONS.find((x) => x.id === id);
  if (!s) throw new Error(`brand-page: unknown section "${id}"`);
  return `<h2 id="${s.id}">${s.title ?? s.label}</h2>`;
}

function sectionRail(): string {
  const rows = SECTIONS.map(
    (s) => `<a class="ritem bs" href="#${s.id}"><span class="rlbl">${s.label}</span></a>`
  ).join('\n');
  return `<div class="rail-col" id="brand-rail">
<nav class="rail" aria-label="On this page">
<p class="eyebrow">// On this page</p>
${rows}
</nav>
</div>`;
}

/**
 * The product name with its required two-tone split, for use in the page's
 * own prose. A brand page that spells its own name in flat text is arguing
 * against itself. Spec: ops/docs/design-decisions.md (brand spelling).
 *
 * Deliberately NOT applied to three kinds of text: the copy-ready
 * description blocks (they are verbatim strings, and coloring half a string
 * implies the color is part of it), the wrong forms being warned against,
 * and the quoted words "Privacy" / "Notes" in the two-tone rule itself -
 * that sentence names Brand Blue and Fold Blue by hex, and the page accent
 * is neither, so painting them there would state one blue and show another.
 */

function copyBlock(c: CopyBlock): string {
  return `<div class="cp"><div class="cph"><strong>${c.label}</strong><span class="cnt">${c.text.length} chars</span><button class="pill cbtn" type="button" data-copy="${c.id}" hidden>Copy</button></div>
<p id="${c.id}">${esc(c.text)}</p></div>`;
}

const FACTS: Array<[string, string]> = [
  ['Product', `${brandMark()}, an end-to-end encrypted personal workspace`],
  ['Developer', '<a href="https://lifetimelabs.dev" target="_blank" rel="noopener noreferrer">Lifetime Labs LLC</a>'],
  ['Website', '<a href="https://privacynotes.app/en">PrivacyNotes.app</a>'],
  ['Model', 'Free forever tier + one-time lifetime Pro purchase; optional storage add-ons billed yearly'],
  // "iOS coming soon" is a dated claim. When iOS ships, this row, the homepage
  // downloads availability line and the /help platforms answer all need the
  // same edit; the follow-up is tracked in ops/docs/mobile-release-status.md
  // (Open follow-ups) so it is not remembered only here.
  ['Platforms', 'Web, macOS, Windows, Linux, Android. iOS coming soon.'],
  ['Stack', 'React + TypeScript, local-first storage'],
  ['Source', 'Open source: <a href="https://github.com/LifetimeLabsDev/PrivacyNotes.app" target="_blank" rel="noopener noreferrer">github.com/LifetimeLabsDev/PrivacyNotes.app</a>'],
  ['Encryption', 'XChaCha20-Poly1305, BIP-39 12-word phrase, zero knowledge'],
  ['Press contact', '<a href="https://lifetimelabs.dev/contact/" target="_blank" rel="noopener noreferrer">LifetimeLabs.Dev/contact</a>'],
  ['Established', 'App in development since early 2025. Lifetime Labs LLC est. April 2026.'],
];

const SWATCHES: Array<{ name: string; hex: string; rgb: string; cmyk: string; role: string; border?: boolean }> = [
  { name: 'Brand Blue', hex: '#1E40AF', rgb: '30 64 175', cmyk: '83 63 0 31', role: 'icon body, "Privacy" on light' },
  { name: 'Fold Blue', hex: '#4F6BD5', rgb: '79 107 213', cmyk: '63 50 0 16', role: 'corner fold, "Privacy" on dark' },
  { name: 'Check Green', hex: '#10B981', rgb: '16 185 129', cmyk: '91 0 30 27', role: 'check badge only' },
  { name: 'Ink', hex: '#0A0A0A', rgb: '10 10 10', cmyk: '0 0 0 96', role: '"Notes" on light' },
  { name: 'Paper', hex: '#FFFFFF', rgb: '255 255 255', cmyk: '0 0 0 0', role: '"Notes" on dark, lock, check', border: true },
];

function swatches(): string {
  return SWATCHES.map(
    (s) => `<div class="sw"><div class="chip" style="background:${s.hex}${s.border ? ';border:1px solid var(--line)' : ''}"></div>
<strong>${s.name}</strong><code>${s.hex}</code><span>RGB ${s.rgb}</span><span>CMYK ${s.cmyk}</span><span class="role">${esc(s.role)}</span></div>`
  ).join('\n');
}

/* Page CSS. NOTE: no backticks anywhere in here, including comments - this
   is a template literal and a stray backtick closes it silently. */
const PAGE_CSS = `h2{font-size:20px;font-weight:750;letter-spacing:-.02em;margin:44px 0 4px;padding-top:22px;border-top:1px solid var(--line);scroll-margin-top:16px}
.col-body>h2:first-child{margin-top:26px}
.lead{color:var(--muted);font-size:14px;margin:0 0 16px}
.lead strong{color:var(--fg)}
.grid{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.grid.one{grid-template-columns:1fr}
.card{border:1px solid var(--line);border-radius:12px;overflow:hidden;background:var(--rail)}
.tile{display:flex;align-items:center;justify-content:center;padding:24px 16px;min-height:110px;border-bottom:1px solid var(--line);position:relative}
.tile::after{content:"transparent bg";position:absolute;top:7px;right:9px;font-size:9px;letter-spacing:.08em;text-transform:uppercase;color:var(--faint);opacity:.75}
.tile img{max-width:100%;height:auto}
.t-light{background:#fff}.t-dark{background:#0a0d12}
.t-light::after{color:#8b94a3}.t-dark::after{color:rgba(255,255,255,.45)}
.k-lockup img{height:38px}.k-wordmark img{height:34px}.k-icon img{height:72px}
.meta{display:flex;align-items:center;justify-content:space-between;gap:10px;padding:10px 14px;font-size:13px}
.meta strong{display:block;font-weight:650}
.dims{color:var(--faint);font-size:11.5px;display:block}
.note{color:var(--muted);font-size:11.5px;display:block}
.dl{display:flex;gap:6px;flex-shrink:0}
.pill{display:inline-block;border:1px solid var(--line);border-radius:999px;padding:3px 12px;font-size:12px;font-weight:600;color:var(--accent);text-decoration:none;background:var(--bg);cursor:pointer}
.pill:hover{border-color:var(--accent);text-decoration:none}
.cbtn[hidden]{display:none}
.panel{border:1px solid var(--line);border-radius:12px;background:var(--rail);padding:24px;display:flex;justify-content:center}
.only-dark{display:none}
:root[data-theme=dark] .only-light{display:none}
:root[data-theme=dark] .only-dark{display:revert}
@media(prefers-color-scheme:dark){
:root:not([data-theme=light]) .only-light{display:none}
:root:not([data-theme=light]) .only-dark{display:revert}
}
.minstrip{display:flex;align-items:center;gap:30px;border:1px solid var(--line);border-radius:12px;background:var(--rail);padding:18px 22px;flex-wrap:wrap;margin-top:14px}
.ms{display:flex;flex-direction:column;gap:8px;align-items:flex-start}
.minstrip span{font-size:11.5px;color:var(--faint)}
.ms-note{max-width:210px;margin-left:auto}
.sws{display:grid;grid-template-columns:repeat(5,1fr);gap:12px}
.sw{border:1px solid var(--line);border-radius:12px;background:var(--rail);padding:10px;font-size:12px;display:flex;flex-direction:column;gap:2px}
.sw .chip{height:48px;border-radius:8px;margin-bottom:6px}
.sw code{font-size:12px;color:var(--fg)}
.sw span{color:var(--muted);font-size:11px}
.sw .role{color:var(--faint)}
.cp{border:1px solid var(--line);border-radius:12px;background:var(--rail);padding:12px 16px;margin-bottom:12px}
.cph{display:flex;align-items:center;gap:10px;margin-bottom:2px}
.cph strong{font-size:13.5px}
.cnt{font-size:11px;color:var(--faint);border:1px solid var(--line);border-radius:99px;padding:1px 8px}
.cph .cbtn{margin-left:auto}
.cbtn.on{border-color:var(--accent)}
.cp p{margin:4px 0 2px;font-size:14px}
.facts{border:1px solid var(--line);border-radius:12px;background:var(--rail);padding:6px 18px;font-size:14px}
.facts>div{display:flex;gap:14px;padding:9px 0;border-bottom:1px solid var(--line)}
.facts>div:last-child{border-bottom:none}
.facts b{flex:0 0 118px;font-weight:650;color:var(--muted);font-size:12px;text-transform:uppercase;letter-spacing:.05em;padding-top:2px}
/* The Source and Press contact rows carry bare URLs with no break
   opportunity, which pushed the whole page into a horizontal scroll on a
   phone. Let them break mid-token rather than widen the document. */
.facts>div>span{min-width:0;overflow-wrap:anywhere}
.dd{display:grid;grid-template-columns:1fr 1fr;gap:14px}
.ddcol{border:1px solid var(--line);border-radius:12px;background:var(--rail);padding:14px 18px;font-size:14px}
.ddcol h3{margin:0 0 8px;font-size:13px;text-transform:uppercase;letter-spacing:.08em}
.ddcol.do h3{color:var(--ok)}
.ddcol.dont h3{color:var(--bad)}
.ddcol ul{margin:0;padding-left:18px}
.ddcol li{margin:5px 0}
.donts{display:grid;grid-template-columns:1fr 1fr 1fr;gap:14px;margin-top:14px}
.dont-tile{border:1px solid var(--line);border-radius:12px;background:#fff;padding:18px 10px;text-align:center;position:relative;overflow:hidden}
.dont-tile img{height:24px}
.dont-tile p{margin:10px 0 0;font-size:12px;color:#5b6472}
.dont-tile::before{content:"\\2715";position:absolute;top:6px;left:10px;color:var(--bad);font-weight:800}
.trademark{margin-top:40px;padding-top:16px;border-top:1px solid var(--line);color:var(--faint);font-size:12.5px}
@media(max-width:600px){
.grid,.dd,.donts{grid-template-columns:1fr}
.sws{grid-template-columns:1fr 1fr}
.facts b{flex-basis:96px}
}`;

function clearspaceDiagram(variant: 'light' | 'dark'): string {
  const img = variant === 'light' ? 'privacynotes-lockup-color-light' : 'privacynotes-lockup-color-dark';
  return `<div class="panel only-${variant}">
<svg viewBox="-34 -34 486 144" width="100%" style="max-width:620px" role="img" aria-label="Clearspace diagram: keep one fold width free on every side">
<rect x="-24" y="-24" width="465.5" height="124" fill="none" stroke="#e05252" stroke-width="1.2" stroke-dasharray="5 4"/>
<rect x="-24" y="-24" width="24" height="24" fill="#e05252" opacity=".14"/>
<rect x="417.5" y="76" width="24" height="24" fill="#e05252" opacity=".14"/>
<text x="-12" y="-8" font-size="10" fill="#e05252" text-anchor="middle" font-family="monospace">X</text>
<text x="429.5" y="92" font-size="10" fill="#e05252" text-anchor="middle" font-family="monospace">X</text>
<image href="${B}/${img}.svg" x="0" y="0" width="417.5" height="76"/>
</svg>
</div>`;
}

export function renderHtml(): string {
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Brand assets &amp; press kit - PrivacyNotes</title>
<meta name="description" content="${DESC}">
<link rel="canonical" href="${CANONICAL}">
<meta property="og:title" content="Brand assets &amp; press kit - PrivacyNotes">
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
  '--bg:#fff;--fg:#15171a;--muted:#5b6168;--faint:#8a9099;--line:#e7e9ec;--accent:#1E40AF;--imp-bg:#eff6ff;--mark-fg:#1E40AF;--chip:#eceef1;--rail:#f7f8fa;--on-accent:#fff;--ok:#3b6d11;--bad:#b3261e',
  '--bg:#0e1014;--fg:#e7e9ec;--muted:#9aa1aa;--faint:#6b7178;--line:#23262c;--accent:#4A90D9;--imp-bg:#11233a;--mark-fg:#7FB0E4;--chip:#3a4149;--rail:#14171d;--on-accent:#03203E;--ok:#a7cf6f;--bad:#e0655e'
)}
${THEME_TOGGLE_CSS}
${CHROME_CSS}
${PAGE_CSS}
</style>
</head>
<body data-static-page="brand">
<div class="wrap">
${siteNav({ active: 'brand' })}
<div class="pcols">
${sectionRail()}
<div class="col-head">
<h1>Brand assets</h1>
<p class="sub">Logos, colors, and copy for writing about ${brandMark()}.</p>
</div>
<div class="col-body">
<p class="lead" style="margin-top:14px">Use anything on this page to reference ${brandMark()} in articles, videos, directories, and app round-ups. Every file downloads individually, SVG for scale, PNG for convenience, all on transparent backgrounds.</p>

${h2('lockup')}
<p class="lead">The default way to show the brand. Pick by background: the icon never changes, only the wordmark adapts. There is no one-color version, because flattening the mark loses the corner fold; on a photo or a colored background, put the logo on a solid light or dark panel instead.</p>
<div class="grid">
${LOCKUPS.map(card).join('\n')}
</div>

${h2('icon')}
<p class="lead">For avatars, favicons, app tiles, and anywhere below minimum lockup size. One file, and it holds up on light and dark alike.</p>
<div class="grid one">
${ICONS.map(card).join('\n')}
</div>

${h2('wordmark')}
<p class="lead"><strong>The two-tone rule:</strong> "Privacy" is always blue, Brand Blue on light and Fold Blue on dark. "Notes" is always ink, near-black on light and white on dark. One word, never inverted, never two-toned in running text.</p>
<div class="grid">
${WORDMARKS.map(card).join('\n')}
</div>

${h2('clearspace')}
<p class="lead">X is the corner fold, about one third of the icon's height. Keep at least 1X clear on every side. For the wordmark alone, X is one third of its height.</p>
${clearspaceDiagram('light')}
${clearspaceDiagram('dark')}
<div class="minstrip">
<div class="ms"><img src="${B}/privacynotes-icon-color.svg" style="height:16px;width:auto" alt=""><span>icon minimum, 16 px</span></div>
<div class="ms"><img class="only-light" src="${B}/privacynotes-lockup-color-light.svg" style="height:22px;width:auto" alt=""><img class="only-dark" src="${B}/privacynotes-lockup-color-dark.svg" style="height:22px;width:auto" alt=""><span>lockup minimum, 22 px tall / 120 px wide</span></div>
<span class="ms-note">below lockup minimum, switch to the icon alone</span>
</div>

${h2('color')}
<p class="lead">Five colors, no exceptions in logo files. CMYK values are uncalibrated reference conversions.</p>
<div class="sws">
${swatches()}
</div>

${h2('typography')}
<p class="lead"><strong>Wordmark:</strong> Inter Bold (700), tracking -2%, shipped as outlines, so you never need the font installed to use the files. <strong>Product and site:</strong> the native system font stack. For collateral, Inter 400-800 (free, SIL Open Font License).</p>

${h2('descriptions')}
<p class="lead">Always ${brandMark()}: one word, capital P, capital N, with "Privacy" in the accent color wherever the medium allows it. The domain is written the same way, ${brandMark('.app')}, everywhere except inside an actual URL. Never "Privacy Notes", "Privacynotes", or "PN". The App Store listing name "PrivacyNotes - Zero Knowledge" is a store-name workaround, not the brand.</p>
${COPY.map(copyBlock).join('\n')}

${h2('facts')}
<div class="facts">
${FACTS.map(([k, v]) => `<div><b>${k}</b><span>${v}</span></div>`).join('\n')}
</div>

${h2('usage')}
<div class="dd">
<div class="ddcol do"><h3>Do</h3><ul>
<li>Use the files exactly as provided; prefer SVG</li>
<li>On photos or colored backgrounds, put the logo on a solid light or dark panel</li>
<li>Icon alone when space is below lockup minimums</li>
<li>Keep 1X (the fold) clearspace on all sides</li>
</ul></div>
<div class="ddcol dont"><h3>Don't</h3><ul>
<li>Recolor, stretch, rotate, or add effects and shadows</li>
<li>Re-set the wordmark in another font, or two-tone running text</li>
<li>Flatten the mark to one color, or drop it straight onto a busy image</li>
<li>Add a beta pill or any extra container; imply endorsement or partnership</li>
</ul></div>
</div>
<div class="donts">
<div class="dont-tile"><img src="${B}/privacynotes-lockup-color-light.svg" style="transform:scaleX(1.45)" alt=""><p>don't stretch</p></div>
<div class="dont-tile"><img src="${B}/privacynotes-lockup-color-light.svg" style="filter:hue-rotate(140deg)" alt=""><p>don't recolor</p></div>
<div class="dont-tile"><img src="${B}/dont-invert.svg" alt=""><p>don't invert the two-tone split</p></div>
</div>

<p class="trademark">${brandMark()} and the document-lock mark are trademarks of Lifetime Labs LLC. The assets on this page may be used to reference ${brandMark()}; they may not be used to imply endorsement.</p>
</div>
</div>
</div>
${SITE_FOOTER}
<script src="/static-pages.js" defer></script>
</body>
</html>`;
}

export function brandPagePlugin(): Plugin {
  return {
    name: 'emit-brand-page',
    generateBundle() {
      this.emitFile({
        type: 'asset',
        fileName: 'brand/index.html',
        source: renderHtml(),
      });
    },
    configureServer(server) {
      // Serve /brand in dev so the page can be verified locally without a
      // production build.
      server.middlewares.use('/brand', (_req, res) => {
        res.setHeader('Content-Type', 'text/html; charset=utf-8');
        res.end(renderHtml());
      });
    },
  };
}
