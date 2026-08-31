import { transformWithOxc, type Plugin } from 'vite';
import fs from 'node:fs';
import path from 'node:path';
import { fileURLToPath } from 'node:url';
import { brandMark, CHROME_CSS, OG_IMAGE_TAGS, ogLocaleTag, SITE_FOOTER } from './static-page-chrome.ts';
import { APP_ORIGIN } from './src/hosts.ts';
import {
  BENEFITS,
  CHIPS,
  SHARED_FAQS,
  VS_GROUP_LABELS,
  VS_ROWS,
  type Cell,
} from './src/landingData/registry.ts';
import { GUIDE_META } from './src/guides.ts';
import { EARLY_PRICE, PRO_PRICE } from './src/pricing.ts';

const FACTS = { earlyPrice: EARLY_PRICE, proPrice: PRO_PRICE } as const;

// Pre-renders the SEO landing pages: flat feature pages (/markdown-editor),
// comparison pages (/vs/<competitor>) and audience pages (/for/<audience>).
// One dataset file per page under src/landingData/pages/, import-free and
// evaluated as a data-URL module so the dev middleware re-reads it on every
// request (edit, reload, see it - no Vite restart). Shared content (chips,
// benefit cards, comparison rows, shared FAQs, prices) lives in
// src/landingData/registry.ts, which this module imports statically.
//
// English-only by design (decided 2026-08-19): one URL per page, bare-apex
// self-canonical, no hreflang cluster, no locale variants. Copy never enters
// the locale catalogs. The precedent is /roadmap, /brand and /changelog.
//
// Datasets are validated here at load time and the build fails loudly on an
// unknown registry id, a missing comparison cell, or a hardcoded price
// (copy must use {price}/{earlyPrice}/{proPrice} tokens so a price change
// in src/pricing.ts propagates on the next deploy).
//
// Presentation recycles the HOMEPAGE design language (src/LandingPage.tsx),
// not the docs chrome the other static pages wear: forced light, white
// ground, black and amber pills, blue mono "//" kickers, hard-bordered
// rounded cards, black contrast slabs, the rotated marquee ribbon. The
// header below is a static replica of the homepage header (no theme
// toggle, no language menu, no hamburger); the black SITE_FOOTER is shared
// with every other static page and stays as is.
//
// No inline scripts (deployed CSP is script-src 'self'); the typing hero and
// the sticky CTA live in public/static-pages.js behind
// data-static-page="landing", and every page renders complete without JS.
// Spec: ops/docs/plans/marketing-pages.md

const __dirname = path.dirname(fileURLToPath(import.meta.url));
const PAGES_DIR = path.resolve(__dirname, 'src/landingData/pages');
// Read at build time by readLandingSlugs below, which is why worker.ts is a
// build input rather than deployment-only config, and why the published tree
// has to carry it: a build without it fails closed here.
const WORKER_PATH = path.resolve(__dirname, 'worker.ts');
const ORIGIN = 'https://privacynotes.app';
const DEMO_ORIGIN = 'https://try.privacynotes.app';
const HOME = '/en';

// Same beta-price pick as marketing-shell.ts: the flag mirrors isBetaPricing()
// in src/paddle.ts.
const displayPrice = process.env.VITE_PADDLE_BETA_DISCOUNT_ID ? FACTS.earlyPrice : FACTS.proPrice;

function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/** Resolve price tokens, then escape. Every dataset string renders through this. */
function t(s: string): string {
  return esc(
    s
      .replace(/\{price\}/g, `$${displayPrice}`)
      .replace(/\{earlyPrice\}/g, `$${FACTS.earlyPrice}`)
      .replace(/\{proPrice\}/g, `$${FACTS.proPrice}`),
  );
}

type Faq = { q: string; a: string };
type LandingPage = {
  kind: 'feature' | 'vs' | 'for';
  slug: string;
  seo: { title: string; description: string; breadcrumb: string };
  [key: string]: unknown;
};

function pagePath(p: LandingPage): string {
  if (p.kind === 'feature') return `/${p.slug}`;
  return `/${p.kind}/${p.slug}`;
}

// ---------------------------------------------------------------------------
// Loading + validation

async function evalDataset(file: string): Promise<LandingPage> {
  const src = fs.readFileSync(file, 'utf8');
  const { code } = await transformWithOxc(src, file, { lang: 'ts' });
  const mod = (await import(
    'data:text/javascript;base64,' + Buffer.from(code).toString('base64')
  )) as { default?: LandingPage };
  if (!mod.default) throw new Error(`[landing-pages] ${file}: no default export`);
  return mod.default;
}

function walkStrings(v: unknown, visit: (s: string) => void): void {
  if (typeof v === 'string') visit(v);
  else if (Array.isArray(v)) v.forEach((x) => walkStrings(x, visit));
  else if (v && typeof v === 'object') Object.values(v).forEach((x) => walkStrings(x, visit));
}

function validate(p: LandingPage, file: string): void {
  const fail = (msg: string): never => {
    throw new Error(`[landing-pages] ${file}: ${msg}`);
  };
  if (!['feature', 'vs', 'for'].includes(p.kind)) fail(`unknown kind "${p.kind}"`);
  if (!p.slug || /[^a-z0-9-]/.test(p.slug)) fail(`bad slug "${p.slug}"`);
  if (!p.seo?.title || !p.seo?.description || !p.seo?.breadcrumb) fail('incomplete seo block');
  for (const key of ['chips'] as const) {
    const ids = p[key] as string[] | undefined;
    if (ids) for (const id of ids) if (!(id in CHIPS)) fail(`unknown chip "${id}"`);
  }
  const benefits = p.benefits as (string | object)[] | undefined;
  if (benefits)
    for (const b of benefits)
      if (typeof b === 'string' && !(b in BENEFITS)) fail(`unknown benefit "${b}"`);
  const faq = p.faq as (string | Faq)[] | undefined;
  if (faq)
    for (const f of faq)
      if (typeof f === 'string' && !(f in SHARED_FAQS)) fail(`unknown shared FAQ "${f}"`);
  if (p.kind === 'vs') {
    const cells = p.cells as Record<string, Cell> | undefined;
    if (!cells) fail('vs page without cells');
    for (const id of Object.keys(cells!)) if (!(id in VS_ROWS)) fail(`cell for unknown row "${id}"`);
    for (const id of Object.keys(VS_ROWS)) if (!(id in cells!)) fail(`missing cell for row "${id}"`);
    const guideId = (p.switching as { guideId?: string } | undefined)?.guideId;
    if (guideId && !(guideId in GUIDE_META)) fail(`unknown guideId "${guideId}"`);
  }
  const mesh = p.mesh as Record<string, string[]> | undefined;
  if (mesh?.guides) for (const g of mesh.guides) if (!(g in GUIDE_META)) fail(`unknown mesh guide "${g}"`);
  // Hardcoded prices rot silently when src/pricing.ts changes; tokens do not.
  const banned = [`$${FACTS.earlyPrice}`, `$${FACTS.proPrice}`];
  walkStrings(p, (s) => {
    for (const b of banned)
      if (s.includes(b)) fail(`hardcoded price "${b}" in "${s.slice(0, 60)}" - use {price}/{earlyPrice}/{proPrice} tokens`);
  });
}

// worker.ts hand-maintains LANDING_SLUGS as its app-host 301 list (a flat
// feature slug missing from it gets a duplicate-content twin on
// use.privacynotes.app instead of a redirect to the apex). Nothing else
// keeps that list in sync with the feature datasets, so this cross-check
// runs on every load - build and dev request alike - and fails closed: an
// unparsable worker.ts is treated the same as a real mismatch, never
// silently skipped.
function readLandingSlugs(): Set<string> {
  const src = fs.readFileSync(WORKER_PATH, 'utf8');
  const block = src.match(/LANDING_SLUGS\s*=\s*new Set\(\[([\s\S]*?)\]\)/);
  if (!block) {
    throw new Error(
      '[landing-pages] could not find "LANDING_SLUGS = new Set([...])" in packages/web/worker.ts - the cross-check regex needs updating',
    );
  }
  const slugs = new Set<string>();
  const re = /'([^']*)'/g;
  let m: RegExpExecArray | null;
  while ((m = re.exec(block[1]))) slugs.add(m[1]);
  return slugs;
}

function checkLandingSlugs(pages: LandingPage[]): void {
  const landingSlugs = readLandingSlugs();
  const featureSlugs = new Set(pages.filter((p) => p.kind === 'feature').map((p) => pagePath(p)));
  for (const slug of featureSlugs) {
    if (!landingSlugs.has(slug)) {
      throw new Error(
        `[landing-pages] feature slug "${slug}" is missing from LANDING_SLUGS - add '${slug}' to LANDING_SLUGS in packages/web/worker.ts`,
      );
    }
  }
  for (const slug of landingSlugs) {
    if (!featureSlugs.has(slug)) {
      throw new Error(
        `[landing-pages] LANDING_SLUGS in packages/web/worker.ts has a stale entry "${slug}" with no matching feature dataset - remove it`,
      );
    }
  }
}

export async function loadLandingPages(): Promise<LandingPage[]> {
  const files = fs
    .readdirSync(PAGES_DIR)
    .filter((f) => f.endsWith('.ts'))
    .sort();
  const pages: LandingPage[] = [];
  const seen = new Set<string>();
  for (const f of files) {
    const p = await evalDataset(path.join(PAGES_DIR, f));
    validate(p, f);
    const url = pagePath(p);
    if (seen.has(url)) throw new Error(`[landing-pages] duplicate page URL ${url}`);
    seen.add(url);
    pages.push(p);
  }
  checkLandingSlugs(pages);
  return pages;
}

// ---------------------------------------------------------------------------
// Shared fragments

function resolveFaq(items: (string | Faq)[]): Faq[] {
  return items.map((f) => (typeof f === 'string' ? SHARED_FAQS[f as keyof typeof SHARED_FAQS] : f));
}

function jsonLd(obj: unknown): string {
  return `<script type="application/ld+json">${JSON.stringify(obj).replace(/</g, '\\u003c')}</script>`;
}

const S24 =
  '<svg width="19" height="19" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="1.9" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true">';
const GLYPHS: Record<string, string> = {
  pencil: `${S24}<path d="M4 20h4L19.5 8.5a2.1 2.1 0 0 0-3-3L5 17z"/><line x1="14.5" y1="6.5" x2="17.5" y2="9.5"/></svg>`,
  lock: `${S24}<rect x="4" y="10" width="16" height="11" rx="2"/><path d="M8 10V7a4 4 0 0 1 8 0v3"/><circle cx="12" cy="15.5" r="1.2" fill="currentColor" stroke="none"/></svg>`,
  graph: `${S24}<circle cx="5.5" cy="6.5" r="2.5"/><circle cx="18.5" cy="7.5" r="2.5"/><circle cx="12" cy="18" r="2.5"/><line x1="7.6" y1="8" x2="10.6" y2="15.7"/><line x1="16.9" y1="9.5" x2="13.6" y2="15.9"/><line x1="8" y1="6.9" x2="16" y2="7.2"/></svg>`,
  check: `${S24}<rect x="3.5" y="3.5" width="17" height="17" rx="3.5"/><polyline points="8.2 12.3 11 15 15.8 9.6"/></svg>`,
  folder: `${S24}<path d="M3 7a2 2 0 0 1 2-2h3.5l2 2.5H19a2 2 0 0 1 2 2V17a2 2 0 0 1-2 2H5a2 2 0 0 1-2-2z"/></svg>`,
  globe: `${S24}<circle cx="12" cy="12" r="9"/><line x1="3" y1="12" x2="21" y2="12"/><path d="M12 3a15 15 0 0 1 0 18"/><path d="M12 3a15 15 0 0 0 0 18"/></svg>`,
};

const CELL_ICON: Record<Cell['v'], string> = {
  yes: '<svg width="17" height="17" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="8" class="ci-yes-bg"/><path d="M5 9.4l2.7 2.7L13 6.6" class="ci-yes-fg" fill="none" stroke-width="2" stroke-linecap="round"/></svg>',
  no: '<svg width="17" height="17" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="8" class="ci-no-bg"/><path d="M6 6l6 6M12 6l-6 6" class="ci-no-fg" stroke-width="1.8" stroke-linecap="round"/></svg>',
  partial:
    '<svg width="17" height="17" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="8" class="ci-warn-bg"/><path d="M5.5 9h7" class="ci-warn-fg" stroke-width="2" stroke-linecap="round"/></svg>',
  paid: '<svg width="17" height="17" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="8" class="ci-warn-bg"/><text x="9" y="12.6" text-anchor="middle" font-size="10" font-weight="700" class="ci-warn-tx">$</text></svg>',
  pro: '<svg width="17" height="17" viewBox="0 0 18 18" aria-hidden="true"><circle cx="9" cy="9" r="8" fill="none" class="ci-pro-ring" stroke-width="1.5"/><path d="M5 9.4l2.7 2.7L13 6.6" class="ci-yes-fg" fill="none" stroke-width="2" stroke-linecap="round"/></svg>',
};
const CELL_WORD: Record<Cell['v'], string> = {
  yes: 'Yes',
  no: 'No',
  partial: 'Partial',
  paid: 'Paid',
  pro: 'Pro',
};

function cellHtml(c: Cell): string {
  const note = c.note ? `<span class="cell-note">${t(c.note)}</span>` : '';
  return `<span class="cell v-${c.v}">${CELL_ICON[c.v]} ${CELL_WORD[c.v]}</span>${note}`;
}

/** Leaves-the-site marker on every demo CTA, same glyph as the homepage. */
const ARROW_UR =
  '<svg width="16" height="16" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2.2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><line x1="7" y1="17" x2="17" y2="7"/><polyline points="7 7 17 7 17 17"/></svg>';

/**
 * Static replica of the homepage header (src/LandingPage.tsx "Top brand
 * row", which carries the mirror-image comment): brand on the left, three
 * text links plus the outlined Log in and the filled App pill on the right.
 * That pill says "App" and is never translated, matching the homepage - the
 * reason lives next to the homepage button. Presentation is deliberately duplicated, not shared - the
 * homepage is React+Tailwind with JS auth buttons, these pages ship raw
 * HTML+CSS under a no-inline-script CSP - so a structural change on either
 * side updates the other in the same commit (the SiteFooter.tsx /
 * static-page-chrome.ts precedent). No theme toggle (forced light), no
 * language menu (English-only by design), no hamburger - the links drop out
 * below 900px and the outlined pill below 640px, leaving the brand and the
 * one black pill, which is what the homepage shows on a phone too.
 */
function landingHeader(): string {
  return `<header class="lp-head">
<a class="lp-brand" href="${HOME}">
<img src="/privacy-notes.webp" width="40" height="40" alt="" aria-hidden="true" draggable="false">
<span class="lp-word">${brandMark()}</span>
</a>
<nav class="lp-nav" aria-label="Site">
<a class="lp-nl" href="${HOME}#downloads">Downloads</a>
<a class="lp-nl" href="/help">Help</a>
<a class="lp-nl" href="/changelog">Changelog</a>
<a class="lp-login" href="${APP_ORIGIN}">Log in</a>
<a class="lp-vault" href="${APP_ORIGIN}">App</a>
</nav>
</header>`;
}

/**
 * The homepage's tilted marquee ribbon, built from the page's trust chips.
 * Two identical halves and a -50% translate make the loop seamless; the
 * sequence repeats enough times that a wide monitor never sees the seam.
 * Reduced motion parks it (rule lives next to the keyframes in PAGE_CSS).
 */
function ribbonHtml(ids: string[]): string {
  const half = esc(
    ids
      .map((id) => `${CHIPS[id as keyof typeof CHIPS].label}  ✦  `)
      .join('')
      .repeat(6),
  );
  return `<div class="l-ribbon-out"><div class="l-ribbon"><div class="l-ribbon-in"><span>${half}</span><span aria-hidden="true">${half}</span></div></div></div>`;
}

function crumbHtml(p: LandingPage): string {
  return `<nav class="l-crumb" aria-label="Breadcrumb"><a href="${HOME}">Home</a><span aria-hidden="true"> / </span><span>${esc(p.seo.breadcrumb)}</span></nav>`;
}

function sectionHead(s: { kicker?: string; h2: string; lead?: string }): string {
  return `${s.kicker ? `<div class="l-kicker">// ${t(s.kicker)}</div>` : ''}<h2 class="l-h2">${t(s.h2)}</h2>${s.lead ? `<p class="l-lead">${t(s.lead)}</p>` : ''}`;
}

function faqHtml(intro: { kicker: string; h2: string }, items: Faq[]): string {
  const rows = items
    .map(
      (f, i) =>
        `<details${i === 0 ? ' open' : ''}><summary>${t(f.q)}</summary><p>${t(f.a)}</p></details>`,
    )
    .join('\n');
  return `<section class="l-sec">${sectionHead(intro)}<div class="l-faq">${rows}</div></section>`;
}

function bandHtml(b: { h2: string; sub: string; cta: string; micro: string }): string {
  return `<section class="l-band"><h2 class="l-h2">${t(b.h2)}</h2><p class="l-lead">${t(b.sub)}</p><div class="l-ctas"><a class="l-cta" href="${DEMO_ORIGIN}">${t(b.cta)}${ARROW_UR}</a><a class="l-cta l-ghost" href="${APP_ORIGIN}">Create your vault</a></div><p class="l-micro">${t(b.micro)}</p></section>`;
}

function stickyHtml(s: { text: string; cta: string } | undefined): string {
  if (!s) return '';
  // Ships hidden; static-pages.js reveals it past the hero. No-JS readers
  // simply never see it, which is fine - it is an extra, not content.
  return `<div class="l-sticky" hidden><div class="l-sticky-in"><span>${t(s.text)}</span><a class="l-cta l-ghost l-cta-sm" href="${DEMO_ORIGIN}">${t(s.cta)}${ARROW_UR}</a></div></div>`;
}

function meshHtml(p: LandingPage, all: LandingPage[]): string {
  const mesh = (p.mesh ?? {}) as { compare?: string[]; features?: string[]; guides?: string[] };
  const links: string[] = [];
  for (const slug of mesh.compare ?? []) {
    const q = all.find((x) => x.kind === 'vs' && x.slug === slug);
    if (q) links.push(`<a href="${pagePath(q)}">PrivacyNotes vs ${esc(q.name as string)}</a>`);
  }
  for (const slug of mesh.features ?? []) {
    const q = all.find((x) => x.kind === 'feature' && x.slug === slug);
    if (q) links.push(`<a href="${pagePath(q)}">${esc(q.seo.breadcrumb)}</a>`);
  }
  for (const id of mesh.guides ?? []) {
    links.push(`<a href="/help/import/${id}">Import from ${esc(GUIDE_META[id].name)}</a>`);
  }
  if (!links.length) return '';
  return `<section class="l-mesh"><span class="l-mesh-t">See also</span>${links.join('')}</section>`;
}

// The primary always points at the demo, which leaves this origin, so it
// carries the arrow; the secondary is always an on-site link and does not.
function heroCtas(primary: string, secondary: string | undefined, secondaryHref: string): string {
  return `<div class="l-ctas"><a class="l-cta" href="${DEMO_ORIGIN}">${t(primary)}${ARROW_UR}</a>${
    secondary ? `<a class="l-cta l-ghost" href="${secondaryHref}">${t(secondary)}</a>` : ''
  }</div>`;
}

// ---------------------------------------------------------------------------
// Templates

/* eslint-disable @typescript-eslint/no-explicit-any */

function renderFeature(p: any, all: LandingPage[]): string {
  const editor = `<div class="l-editor" aria-hidden="true"><div class="l-ebar"><i></i><i></i><i></i><span class="l-fname">${esc(p.slug)}.md</span><span class="l-est"><b></b>Saved locally</span></div><div class="l-ebody" data-landing-typer>${(p.hero.editorLines as any[])
    .map((l) => `<span class="el ${esc(l.cls)}">${t(l.text) || '&nbsp;'}</span>`)
    .join('')}</div></div>`;

  const benefits = `<section class="l-sec">${sectionHead(p.benefitsIntro)}<div class="l-grid3 l-benefits">${(
    p.benefits as (string | { icon: string; title: string; body: string })[]
  )
    .map((b) => {
      const it = typeof b === 'string' ? BENEFITS[b as keyof typeof BENEFITS] : b;
      return `<div class="l-card"><span class="l-ico">${GLYPHS[it.icon] ?? GLYPHS.check}</span><b>${t(it.title)}</b><p>${t(it.body)}</p></div>`;
    })
    .join('')}</div></section>`;

  const disk = p.disk
    ? `<section class="l-sec">${sectionHead(p.disk)}<div class="l-2col"><div><p class="l-body">${t(p.disk.body1)}</p><p class="l-body"><strong>${t(p.disk.body2)}</strong></p><p class="l-micro">${t(p.disk.micro)}</p></div><div class="l-tree" aria-hidden="true">${(p.disk.tree as any[])
        .map((r) => `<span class="tr ${esc(r.cls)}">${t(r.text)}</span>`)
        .join('')}</div></div></section>`
    : '';

  const generic = p.generic
    ? `<section class="l-sec">${sectionHead(p.generic)}<div class="l-tblwrap"><table class="l-tbl"><thead><tr><th></th><th class="us">This editor</th><th>The typical online editor</th></tr></thead><tbody>${(
        p.generic.rows as any[]
      )
        .map(
          (r) =>
            `<tr><th>${t(r.label)}</th><td><span class="g-us">${t(r.us)}</span>${r.usNote ? `<span class="cell-note">${t(r.usNote)}</span>` : ''}</td><td><span class="g-them">${t(r.them)}</span>${r.themNote ? `<span class="cell-note">${t(r.themNote)}</span>` : ''}</td></tr>`,
        )
        .join('')}</tbody></table></div></section>`
    : '';

  const cheat = p.cheatsheet
    ? `<section class="l-sec">${sectionHead(p.cheatsheet)}<div class="l-2col l-cheat">${(
        p.cheatsheet.cols as any[]
      )
        .map(
          (col) =>
            `<table class="l-cheat-t"><tbody>${col
              .map((r: any) => `<tr><td class="syn">${t(r.syn)}</td><td>${t(r.res)}</td></tr>`)
              .join('')}</tbody></table>`,
        )
        .join('')}</div></section>`
    : '';

  const how = `<section class="l-sec">${sectionHead(p.how)}<div class="l-grid3">${(p.how.steps as any[])
    .map(
      (s, i) =>
        `<div class="l-card l-step"><span class="l-num">0${i + 1}</span><b>${t(s.title)}</b><p>${t(s.body)}</p></div>`,
    )
    .join('')}</div></section>`;

  return `${crumbHtml(p)}<div class="l-hero l-hero-split"><div><span class="l-badge">${t(p.hero.badge)}</span><h1>${t(p.hero.h1)}</h1><p class="l-sub">${t(p.hero.sub)}</p>${heroCtas(p.hero.cta, p.hero.ctaSecondary, `${HOME}#downloads`)}<p class="l-micro">${t(p.hero.micro)}</p></div>${editor}</div>${ribbonHtml(p.chips)}${benefits}${disk}${generic}${cheat}${how}${faqHtml(p.faqIntro, resolveFaq(p.faq))}${bandHtml(p.band)}${meshHtml(p, all)}`;
}

function renderVs(p: any, all: LandingPage[]): string {
  const name: string = p.name;
  const guideHref = `/help/import/${p.switching.guideId}`;

  const stats = `<div class="l-stats">${(p.stats as any[])
    .map((s) => `<div class="l-stat"><b>${t(s.big)}</b><small>${t(s.small)}</small></div>`)
    .join('')}</div>`;

  const li = (txt: string, kind: 'us' | 'them') =>
    `<li class="${kind}"><span class="dot" aria-hidden="true"></span><span>${t(txt)}</span></li>`;
  // One slab, two halves, no gap: the homepage "// THE MATH" element.
  const verdict = `<div class="l-verdict"><div class="l-vcard l-vcard-us"><h3 class="l-vterm">Pick PrivacyNotes if you want</h3><ul>${(
    p.pickUs as string[]
  )
    .map((x) => li(x, 'us'))
    .join('')}</ul></div><div class="l-vcard"><h3 class="l-vterm">Pick ${esc(name)} if you want</h3><ul>${(
    p.pickThem as string[]
  )
    .map((x) => li(x, 'them'))
    .join('')}</ul></div></div>`;

  const groups: Record<string, string[]> = { privacy: [], pillars: [], editor: [], price: [] };
  for (const [id, row] of Object.entries(VS_ROWS)) {
    const them: Cell = p.cells[id];
    groups[row.group].push(
      `<tr><th>${esc(row.label)}${row.small ? `<small>${esc(row.small)}</small>` : ''}</th><td>${cellHtml(row.us)}</td><td>${cellHtml(them)}</td></tr>`,
    );
  }
  const tbody = (Object.keys(groups) as (keyof typeof VS_GROUP_LABELS)[])
    .map((g) => `<tr class="grp"><td colspan="3">${esc(VS_GROUP_LABELS[g])}</td></tr>${groups[g].join('')}`)
    .join('');
  const table = `<section class="l-sec" id="table">${sectionHead(p.tableIntro)}<div class="l-tblwrap"><table class="l-tbl l-cmp"><thead><tr><th></th><th class="us">PrivacyNotes</th><th>${esc(name)}</th></tr></thead><tbody>${tbody}</tbody></table></div><p class="l-foot">${t(p.tableIntro.foot)}</p></section>`;

  const wins = `<section class="l-sec">${sectionHead(p.wins)}<div class="l-grid3">${(p.wins.items as any[])
    .map((w) => `<div class="l-card"><b>${t(w.title)}</b><p>${t(w.body)}</p></div>`)
    .join('')}</div></section>`;

  const dl = (rows: any[]) =>
    `<dl>${rows.map((r) => `<dt>${t(r.dt)}</dt><dd>${t(r.dd)}</dd>`).join('')}</dl>`;
  const model = `<section class="l-sec">${sectionHead(p.model)}<div class="l-2col"><div class="l-mrow l-mrow-us"><div class="who">PrivacyNotes</div>${dl(p.model.us)}</div><div class="l-mrow"><div class="who">${esc(name)}</div>${dl(p.model.them)}</div></div></section>`;

  // The homepage pricing slab: their subscription on the white half, the
  // one-time purchase on the accent half, with the same three cumulative
  // years spelled out under each so the comparison is arithmetic, not art.
  const perYear: number = p.price.theirPerYear;
  const rows = (amount: (year: number) => string) =>
    `<ul class="l-slab-rows">${[1, 2, 3]
      .map((y) => `<li><span>After year ${y}</span><b>${amount(y)}</b></li>`)
      .join('')}</ul>`;
  const price = `<section class="l-sec">${sectionHead(p.price)}<div class="l-slab"><div class="l-slab-a"><div class="l-slab-l">${esc(p.price.theirLabel)}</div><div class="l-slab-p">$${perYear * 3}</div><div class="l-slab-s">$${perYear} per year, three years in, and still counting.</div>${rows(
    (y) => `$${perYear * y}`,
  )}</div><div class="l-slab-b"><span class="l-tag">No subscription</span><div class="l-slab-l">PrivacyNotes Pro</div><div class="l-slab-p">$${displayPrice}</div><div class="l-slab-s">Paid once. Year four costs the same as year one: nothing.</div>${rows(
    (y) => (y === 1 ? `$${displayPrice}` : `still $${displayPrice}`),
  )}</div></div><p class="l-foot">${t(p.price.note)}</p></section>`;

  const comes = `<div class="l-comes">${(p.switching.comes as any[])
    .map((c) => `<span class="${c.ok ? 'ok' : 'meh'}">${t(c.label)}</span>`)
    .join('')}</div>`;
  const switching = `<section class="l-sec">${sectionHead(p.switching)}<div class="l-2col l-switch"><div class="l-card"><b>The whole process</b><ol>${(
    p.switching.steps as string[]
  )
    .map((s) => `<li>${t(s)}</li>`)
    .join('')}</ol>${comes}</div><div><div class="l-warn"><b>${t(p.switching.trap.title)}</b><p>${t(p.switching.trap.body)}</p></div><a class="l-guide" href="${guideHref}"><span class="gi">${esc(name.split(' ').map((w: string) => w[0]).join('').slice(0, 2))}</span><span class="gt"><b>Import guide: ${esc(name)}</b><span>Every step with screenshots, plus what carries over.</span></span><span class="go">Read the guide</span></a></div></div></section>`;

  return `${crumbHtml(p)}<div class="l-hero"><span class="l-checked"><i></i> Every claim on this page fact-checked: ${esc(p.lastChecked)}</span><h1>${t(p.hero.h1)}</h1><p class="l-sub">${t(p.hero.sub)}</p>${heroCtas(p.hero.cta, p.hero.ctaSecondary, guideHref)}<p class="l-micro">${t(p.hero.micro)}</p></div>${stats}${verdict}${table}${wins}${model}${price}${switching}${faqHtml(p.faqIntro, resolveFaq(p.faq))}${bandHtml(p.band)}${meshHtml(p, all)}`;
}

function renderFor(p: any, all: LandingPage[]): string {
  const pains = `<section class="l-sec">${sectionHead(p.pains)}<div class="l-grid3">${(p.pains.items as any[])
    .map((x) => `<div class="l-card"><p class="l-q">${t(x.q)}</p><p>${t(x.a)}</p></div>`)
    .join('')}</div></section>`;

  const arrow =
    '<span class="l-arr" aria-hidden="true"><svg width="22" height="22" viewBox="0 0 22 22" fill="none" stroke="currentColor" stroke-width="1.8" stroke-linecap="round"><path d="M4 11h13m-5-5l5 5-5 5"/></svg></span>';
  const mech = `<section class="l-sec" id="mechanism">${sectionHead(p.mechanism)}<div class="l-zk"><div class="l-zbox"><b>Your device</b><p>You write. The note is sealed here with XChaCha20-Poly1305 before anything is sent.</p><span class="mono plain">${t(p.mechanism.plain)}</span></div>${arrow}<div class="l-zbox sealed"><b>In transit and at rest</b><p>This is the only thing our servers ever store or see.</p><span class="mono">pk9X2f...vB1mJQ8na0==</span></div>${arrow}<div class="l-zbox"><b>Anyone who asks us</b><p>Staff, attackers, legal requests: everyone gets the same answer, because there is no key to hand over.</p><span class="mono">pk9X2f...vB1mJQ8na0==</span></div></div><p class="l-zkcap">${t(p.mechanism.cap)}</p></section>`;

  const timeline = `<section class="l-sec">${sectionHead(p.timeline)}<ol class="l-tl">${(
    p.timeline.steps as any[]
  )
    .map(
      (s) =>
        `<li><span class="tnode" aria-hidden="true"></span><b>${t(s.title)}</b> <span class="ttag">${t(s.tag)}</span><p>${t(s.body)}</p></li>`,
    )
    .join('')}</ol></section>`;

  // The verify table is a shared fixture: identical on every audience page.
  const verify = `<section class="l-sec">${sectionHead(p.verify)}<div class="l-tblwrap"><table class="l-tbl l-vf"><thead><tr><th>The claim</th><th>What enforces it</th><th>How you check it</th></tr></thead><tbody>
<tr><th>Notes are encrypted before they leave the device</th><td>XChaCha20-Poly1305 per note, keys derived from your phrase locally</td><td>Open the browser network tab while editing: every payload is ciphertext.</td></tr>
<tr><th>The crypto is not a black box</th><td>Open source: the app, its encryption code, the database schema and the threat model are published</td><td>Read the published source, or hand it to your IT for review.</td></tr>
<tr><th>No identity is required</th><td>Sign-in with a 12-word phrase; email is optional, not a prerequisite</td><td>Create a vault without entering an email address. Takes under a minute.</td></tr>
<tr><th>There is no readable copy to produce</th><td>Keys never reach the server, so neither does anything decryptable</td><td>The threat model documents exactly what we hold: ciphertext, timestamps, quota numbers.</td></tr>
</tbody></table></div><div class="l-warn l-honesty"><b>${t(p.honesty.title)}</b><p>${t(p.honesty.body)}</p></div></section>`;

  const pricing = `<section class="l-sec">${sectionHead(p.pricing)}<div class="l-pay"><div class="big">${t(p.pricing.big)}</div><p>${t(p.pricing.body)}</p></div></section>`;

  // The ribbon is full-bleed, so it sits outside the hero's text column.
  return `${crumbHtml(p)}<div class="l-hero"><div class="l-kicker">// ${t(p.hero.kicker)}</div><h1>${t(p.hero.h1)}</h1><p class="l-sub">${t(p.hero.sub)}</p>${heroCtas(p.hero.cta, p.hero.ctaSecondary, '#mechanism')}<p class="l-micro">${t(p.hero.micro)}</p></div>${ribbonHtml(p.chips)}${pains}${mech}${timeline}${verify}${pricing}${faqHtml(p.faqIntro, resolveFaq(p.faq))}${bandHtml(p.band)}${meshHtml(p, all)}`;
}

// ---------------------------------------------------------------------------
// Page shell

/* Page CSS. NOTE: no backticks anywhere in here, including comments - this is
   a template literal, and a stray one closes it silently.

   Forced light on purpose. These pages wear the HOMEPAGE design language,
   and the homepage is light-only; there is no toggle and no dark block, so
   the ten shared chrome vars below are declared once with the homepage's
   light values and everything else quotes the palette literally.
   Palette: accent #1E40AF, neutrals 950 #0a0a0a / 600 #525252 / 500 #737373
   / 400 #a3a3a3 / 200 #e5e5e5 / 100 #f5f5f5, amber #f59e0b #d97706 #b45309,
   emerald #34d399 #10b981 #059669, red #dc2626. */
const PAGE_CSS = `:root{color-scheme:light}
body{background:#fff;color:#0a0a0a}
.wrap{max-width:1024px}
.lp-head{display:flex;align-items:center;justify-content:space-between;gap:16px;padding-top:14px;margin-bottom:40px}
.lp-brand{display:flex;align-items:center;gap:12px;text-decoration:none;color:#0a0a0a}
.lp-brand:hover{text-decoration:none}
.lp-brand img{width:40px;height:40px;flex:0 0 auto}
.lp-word{font-size:26px;letter-spacing:-.03em}
.lp-nav{display:flex;align-items:center;gap:16px}
.lp-nl{font-size:14px;color:#525252;text-decoration:none}
.lp-nl:hover{color:var(--accent);text-decoration:none}
.lp-login{display:inline-flex;align-items:center;white-space:nowrap;border:1.5px solid #0a0a0a;color:#0a0a0a;border-radius:999px;padding:6px 16px;font-size:14px;font-weight:600;text-decoration:none}
.lp-login:hover{background:#f5f5f5;text-decoration:none}
.lp-vault{display:inline-flex;align-items:center;white-space:nowrap;background:#0a0a0a;color:#fff;border-radius:999px;padding:7.5px 16px;font-size:14px;font-weight:600;text-decoration:none}
.lp-vault:hover{background:#262626;color:#fff;text-decoration:none}
.l-crumb{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;font-weight:600;text-transform:uppercase;letter-spacing:.14em;color:#737373;margin:0 0 22px}
.l-crumb a{color:#737373}
.l-crumb a:hover{color:var(--accent);text-decoration:none}
.l-hero{padding:0 0 4px;max-width:760px}
.l-hero-split{display:grid;grid-template-columns:1.05fr .95fr;gap:48px;align-items:center;max-width:none}
.l-hero h1{font-size:clamp(38px,5vw,56px);font-weight:900;letter-spacing:-.035em;line-height:.95;margin:0}
.l-badge{display:inline-block;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#047857;background:#ecfdf5;border:1px solid rgba(52,211,153,.4);border-radius:999px;padding:5px 12px;margin-bottom:18px}
.l-kicker{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;font-weight:600;letter-spacing:.2em;text-transform:uppercase;color:var(--accent);margin:0 0 16px}
.l-sub{color:#525252;font-size:18px;line-height:1.65;margin:20px 0 0;max-width:640px}
.l-ctas{display:flex;gap:12px;margin-top:26px;flex-wrap:wrap;align-items:center}
.l-cta{display:inline-flex;align-items:center;gap:8px;background:#0a0a0a;color:#fff;font-weight:700;font-size:15px;padding:.875rem 1.75rem;border-radius:999px;text-decoration:none;line-height:1.2}
.l-cta:hover{text-decoration:none;background:#262626;color:#fff}
.l-cta.l-ghost{background:transparent;color:#d97706;border:2px solid #f59e0b;padding:calc(.875rem - 2px) calc(1.5rem - 2px)}
.l-cta.l-ghost:hover{background:#fffbeb;color:#b45309}
.l-cta.l-cta-sm{padding:.55rem 1.15rem;font-size:14px}
.l-cta.l-ghost.l-cta-sm{padding:calc(.55rem - 2px) calc(1.15rem - 2px)}
.l-micro{font-size:12.5px;color:#737373;margin-top:14px}
.l-checked{display:inline-flex;align-items:center;gap:8px;font-size:11px;font-weight:700;text-transform:uppercase;letter-spacing:.08em;color:#047857;background:#ecfdf5;border:1px solid rgba(52,211,153,.4);border-radius:999px;padding:5px 12px;margin:0 0 18px}
.l-checked i{width:7px;height:7px;border-radius:999px;background:#10b981;display:inline-block}
/* Full-bleed tilted ribbon. The outer strip is the clip: rotating an element
   as wide as its container pokes its corners past the viewport, which is a
   horizontal scrollbar on a phone. The negative margins cancel the shell
   padding (24px, 18px below 600px - keep them in step with CHROME_CSS). */
.l-ribbon-out{margin:36px -24px 44px;padding:10px 0;overflow:hidden}
.l-ribbon{transform:rotate(-1.5deg) scale(1.03);background:#0a0a0a;color:#fff;overflow:hidden;white-space:nowrap;padding:10px 0}
.l-ribbon-in{display:inline-flex;width:max-content;font-size:13px;font-weight:800;text-transform:uppercase;letter-spacing:.15em;animation:l-marquee 40s linear infinite}
@keyframes l-marquee{0%{transform:translateX(0)}100%{transform:translateX(-50%)}}
@media(prefers-reduced-motion:reduce){.l-ribbon-in{animation:none}}
.l-sec{margin-top:56px}
.l-h2{font-size:clamp(28px,3.4vw,36px);font-weight:900;letter-spacing:-.035em;line-height:1.08;margin:0 0 12px}
.l-lead{color:#525252;font-size:16px;line-height:1.65;max-width:680px;margin:0}
.l-body{font-size:15.5px;color:#0a0a0a;margin:0 0 14px;line-height:1.7}
.l-foot{font-size:12.5px;color:#737373;margin-top:14px;max-width:700px}
.l-grid3{display:grid;grid-template-columns:repeat(3,1fr);gap:16px;margin-top:26px}
.l-card{border:2px solid #0a0a0a;border-radius:16px;padding:24px;background:#fff}
.l-card b{display:block;font-size:16px;font-weight:800;letter-spacing:-.01em;margin-bottom:7px}
.l-card p{font-size:14px;color:#525252;margin:0;line-height:1.6}
.l-card ol{margin:12px 0 0 18px;padding:0;font-size:14px;color:#525252;display:grid;gap:9px}
.l-ico{display:flex;align-items:center;justify-content:center;width:44px;height:44px;border-radius:12px;background:#eff6ff;color:var(--accent);margin-bottom:16px}
/* Selected variety, the homepage card rhythm: one black, one blue, one
   emerald, the rest plain. Positional on purpose - the six benefit cards are
   a fixed grid, so a nth-child rule beats six data attributes. */
.l-benefits .l-card:nth-child(1){background:#0a0a0a;border-color:#0a0a0a;color:#fff}
.l-benefits .l-card:nth-child(1) p{color:#a3a3a3}
.l-benefits .l-card:nth-child(1) .l-ico{background:rgba(255,255,255,.1);color:#fff}
.l-benefits .l-card:nth-child(3){background:#eff6ff;border-color:rgba(30,64,175,.3)}
.l-benefits .l-card:nth-child(6){background:#ecfdf5;border-color:rgba(16,185,129,.3)}
.l-num{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:700;font-size:12px;letter-spacing:.14em;color:var(--accent);margin-bottom:10px}
.l-q{font-style:italic;font-weight:700;color:#0a0a0a;font-size:14.5px;margin:0 0 8px}
.l-2col{display:grid;grid-template-columns:1fr 1fr;gap:24px;margin-top:26px;align-items:start}
.l-editor{border:2px solid #0a0a0a;border-radius:14px;overflow:hidden;background:#fff}
.l-ebar{display:flex;align-items:center;gap:6px;padding:10px 14px;background:#f5f5f5;border-bottom:2px solid #0a0a0a}
.l-ebar i{width:9px;height:9px;border-radius:99px;background:#d4d4d4;display:inline-block}
.l-fname{margin-left:8px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#737373}
.l-est{margin-left:auto;font-size:11px;color:#737373;display:flex;align-items:center;gap:6px}
.l-est b{width:6px;height:6px;border-radius:99px;background:#10b981;display:inline-block}
.l-ebody{display:block;padding:16px 18px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:13px;line-height:1.85;min-height:270px}
.l-ebody .el{display:block;white-space:pre-wrap;word-break:break-word;color:var(--fg)}
.l-ebody .el.h{color:var(--accent);font-weight:700}
.l-ebody .el.done{color:var(--faint);text-decoration:line-through}
.l-ebody .el.lk{color:var(--accent)}
.el-caret{display:inline-block;width:7px;height:14px;background:var(--accent);vertical-align:-2px;margin-left:1px;animation:l-blink 1s steps(1) infinite}
@keyframes l-blink{50%{opacity:0}}
.l-tree{border:2px solid #0a0a0a;border-radius:14px;background:#fff;padding:16px 18px;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;line-height:2;overflow-x:auto}
.l-tree .tr{display:block;white-space:pre;color:#525252}
.l-tree .tr.dir{color:var(--accent);font-weight:700}
.l-tree .tr.hl{background:#eff6ff;border-radius:6px;color:#0a0a0a}
.l-tblwrap{overflow-x:auto;margin-top:26px;border:2px solid #0a0a0a;border-radius:16px;background:#fff}
.l-tbl{width:100%;border-collapse:collapse;min-width:600px;font-size:14px}
.l-tbl th,.l-tbl td{padding:13px 18px;text-align:left;border-top:1px solid #e5e5e5;vertical-align:top}
.l-tbl thead th{border-top:0;font-size:11px;font-weight:800;text-transform:uppercase;letter-spacing:.12em;color:#737373}
.l-tbl thead th.us{color:var(--accent)}
.l-tbl tbody th{font-weight:600;width:44%}
.l-tbl tbody th small{display:block;font-weight:400;color:#737373;font-size:12px;margin-top:3px}
.l-tbl tr.grp td{background:#f5f5f5;color:var(--accent);font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-weight:600;font-size:10px;letter-spacing:.18em;text-transform:uppercase;padding:9px 18px}
.cell{display:inline-flex;align-items:center;gap:7px;white-space:nowrap;font-weight:700}
.cell.v-yes,.cell.v-pro{color:#059669}
.cell.v-partial,.cell.v-paid{color:#b45309}
.cell.v-no{color:#737373}
.cell-note{display:block;font-size:12px;color:#737373;margin-top:4px;white-space:normal;font-weight:400}
.ci-yes-bg{fill:#d1fae5}.ci-yes-fg{stroke:#059669}
.ci-no-bg{fill:#f5f5f5}.ci-no-fg{stroke:#a3a3a3}
.ci-warn-bg{fill:#fef3c7}.ci-warn-fg{stroke:#d97706}.ci-warn-tx{fill:#b45309}
.ci-pro-ring{stroke:#059669}
.g-us{color:#059669;font-weight:700}
.g-them{color:#737373}
.l-cheat{gap:16px}
.l-cheat-t{width:100%;border-collapse:collapse;border:2px solid #0a0a0a;border-radius:16px;overflow:hidden;font-size:13.5px;background:#fff}
.l-cheat-t td{padding:10px 16px;border-top:1px solid #e5e5e5}
.l-cheat-t tr:first-child td{border-top:0}
.l-cheat-t td.syn{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:12.5px;color:var(--accent);white-space:nowrap;width:50%}
.l-stats{display:grid;grid-template-columns:repeat(4,1fr);gap:14px;margin-top:34px}
.l-stat{border:2px solid #0a0a0a;border-radius:16px;padding:18px 20px;background:#fff}
.l-stat b{display:block;font-size:22px;font-weight:900;letter-spacing:-.035em;color:#0a0a0a}
.l-stat small{color:#525252;font-size:12.5px;line-height:1.5;display:block;margin-top:4px}
/* The verdict pair, built as the homepage math slab: one hard-bordered box,
   two halves, no gap between them. */
.l-verdict{display:grid;grid-template-columns:1fr 1fr;gap:0;margin-top:26px;border:2px solid #0a0a0a;border-radius:16px;overflow:hidden;font-size:14px}
.l-vcard{padding:24px;background:#fff}
.l-vcard-us{background:#0a0a0a;color:#fff}
.l-vterm{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:#737373;margin:0 0 14px}
.l-vcard-us .l-vterm{color:#34d399}
.l-vcard ul{list-style:none;margin:0;padding:0;display:grid;gap:10px}
.l-vcard li{display:flex;gap:10px;color:#525252;line-height:1.55}
.l-vcard-us li{color:#d4d4d4}
.l-vcard li .dot{flex:0 0 auto;font-weight:800;line-height:1.55}
.l-vcard li.us .dot::before{content:"✓";color:#34d399}
.l-vcard li.them .dot::before{content:"×";color:#a3a3a3}
.l-mrow{border:2px solid #0a0a0a;border-radius:16px;padding:24px;background:#fff}
.l-mrow-us{background:#0a0a0a;color:#fff}
.l-mrow .who{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:#737373;margin-bottom:14px}
.l-mrow-us .who{color:#34d399}
.l-mrow dl{display:grid;grid-template-columns:auto 1fr;gap:8px 16px;font-size:13.5px;margin:0}
.l-mrow dt{color:#737373}
.l-mrow dd{color:#525252;margin:0}
.l-mrow-us dt{color:#a3a3a3}
.l-mrow-us dd{color:#e5e5e5}
/* Pricing slab: their subscription on white, the one-time price on accent. */
.l-slab{display:grid;grid-template-columns:1fr 1fr;gap:0;margin-top:26px;border:2px solid #0a0a0a;border-radius:16px;overflow:hidden}
.l-slab-a{background:#fff;padding:28px}
.l-slab-b{background:var(--accent);color:#fff;padding:28px}
.l-slab-l{font-size:11px;font-weight:800;letter-spacing:.15em;text-transform:uppercase;color:#737373}
.l-slab-b .l-slab-l{color:rgba(255,255,255,.75)}
.l-slab-p{font-size:44px;font-weight:900;letter-spacing:-.04em;line-height:1.05;margin-top:12px}
.l-slab-s{font-size:13px;color:#525252;margin-top:6px;line-height:1.5}
.l-slab-b .l-slab-s{color:rgba(255,255,255,.82)}
.l-tag{display:inline-block;background:#dc2626;color:#fff;font-size:10px;font-weight:700;letter-spacing:.1em;text-transform:uppercase;border-radius:999px;padding:3px 10px;margin-bottom:12px}
.l-slab-rows{list-style:none;margin:20px 0 0;padding:16px 0 0;border-top:1px solid #e5e5e5;display:grid;gap:8px;font-size:13px}
.l-slab-b .l-slab-rows{border-top-color:rgba(255,255,255,.25)}
.l-slab-rows li{display:flex;justify-content:space-between;gap:12px;color:#737373}
.l-slab-rows b{color:#0a0a0a;font-weight:700}
.l-slab-b .l-slab-rows li{color:rgba(255,255,255,.8)}
.l-slab-b .l-slab-rows b{color:#fff}
.l-switch .l-card b{font-size:15px}
.l-comes{display:flex;gap:8px;flex-wrap:wrap;margin-top:16px}
.l-comes span{font-size:12px;font-weight:600;color:#525252;border:1px solid #e5e5e5;border-radius:999px;padding:5px 12px}
.l-comes span::before{content:"";display:inline-block;width:7px;height:7px;border-radius:99px;margin-right:7px}
.l-comes span.ok::before{background:#10b981}
.l-comes span.meh::before{background:#f59e0b}
/* Amber dashed panel, the homepage markdown-note treatment. */
.l-warn{background:#fffbeb;border:2px dashed rgba(245,158,11,.7);border-radius:16px;padding:22px 24px}
.l-warn b{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;color:#b45309;font-size:11px;font-weight:600;letter-spacing:.16em;text-transform:uppercase}
.l-warn p{font-size:14px;color:#525252;margin:10px 0 0;line-height:1.65}
.l-honesty{margin-top:26px}
.l-guide{display:flex;gap:14px;align-items:center;border:2px solid #0a0a0a;border-radius:16px;padding:16px 18px;margin-top:16px;text-decoration:none;color:#0a0a0a;background:#fff}
.l-guide:hover{text-decoration:none;background:#f5f5f5}
.l-guide .gi{flex:none;width:40px;height:40px;border-radius:12px;background:#eff6ff;display:flex;align-items:center;justify-content:center;font-weight:800;font-size:13px;color:var(--accent)}
.l-guide .gt{flex:1;min-width:0}
.l-guide .gt b{display:block;font-size:14px;font-weight:800}
.l-guide .gt span{font-size:12.5px;color:#737373}
.l-guide .go{color:var(--accent);font-weight:700;font-size:13px;white-space:nowrap}
.l-zk{display:grid;grid-template-columns:1fr auto 1fr auto 1fr;gap:0;align-items:stretch;margin-top:26px}
.l-zbox{border:2px solid #0a0a0a;border-radius:16px;padding:20px;text-align:center;background:#fff}
.l-zbox.sealed{background:#0a0a0a;color:#fff}
.l-zbox b{font-size:14.5px;font-weight:800;display:block;margin-bottom:6px}
.l-zbox p{font-size:12.5px;color:#525252;margin:0;line-height:1.6}
.l-zbox.sealed p{color:#a3a3a3}
.l-zbox .mono{display:block;font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:11px;color:#737373;background:#f5f5f5;border:2px solid #0a0a0a;border-radius:10px;padding:8px 10px;margin-top:14px;word-break:break-all}
.l-zbox .mono.plain{color:#0a0a0a}
.l-zbox.sealed .mono{background:#171717;border-color:#404040;color:#34d399}
.l-arr{display:flex;align-items:center;justify-content:center;padding:0 10px;color:#a3a3a3}
.l-zkcap{text-align:center;font-size:13px;color:#737373;margin-top:16px}
.l-tl{list-style:none;margin:30px 0 0;padding:0 0 0 28px;position:relative}
.l-tl::before{content:"";position:absolute;left:7px;top:8px;bottom:8px;width:2px;background:#e5e5e5}
.l-tl li{position:relative;padding:0 0 24px}
.l-tl li:last-child{padding-bottom:0}
.l-tl .tnode{position:absolute;left:-27px;top:6px;width:12px;height:12px;border-radius:99px;background:#fff;border:3px solid var(--accent)}
.l-tl b{font-size:16px;font-weight:800}
.l-tl .ttag{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px;font-weight:600;letter-spacing:.16em;text-transform:uppercase;color:var(--accent);margin-left:8px}
.l-tl p{font-size:14px;color:#525252;margin:6px 0 0;max-width:660px;line-height:1.65}
.l-pay{display:flex;gap:20px;align-items:baseline;background:var(--accent);border:2px solid #0a0a0a;border-radius:16px;padding:28px;margin-top:26px;flex-wrap:wrap}
.l-pay .big{font-size:30px;font-weight:900;letter-spacing:-.035em;color:#fff}
.l-pay p{flex:1;min-width:260px;font-size:14px;color:rgba(255,255,255,.85);margin:0;line-height:1.65}
.l-faq{margin-top:16px}
.l-faq details{border-bottom:1px solid #e5e5e5;padding:16px 0}
.l-faq summary{cursor:pointer;font-weight:700;font-size:16px;list-style:none;display:flex;justify-content:space-between;gap:12px}
.l-faq summary::-webkit-details-marker{display:none}
.l-faq summary::after{content:"+";color:#a3a3a3;font-weight:400}
.l-faq details[open] summary::after{content:"-"}
.l-faq details p{color:#525252;font-size:15px;margin:10px 0 0;max-width:700px;line-height:1.7}
.l-band{margin-top:64px;padding:56px 0 8px;text-align:center;border-top:2px solid #0a0a0a;background:#fff}
.l-band .l-h2{font-size:clamp(30px,4vw,40px)}
.l-band .l-lead{margin:14px auto 26px;max-width:560px}
.l-band .l-ctas{justify-content:center}
.l-band .l-micro{margin-top:16px}
.l-mesh{margin-top:44px;padding-top:22px;border-top:1px solid #e5e5e5;font-size:13px;color:#737373;display:flex;gap:16px;flex-wrap:wrap;align-items:center}
.l-mesh .l-mesh-t{font-family:ui-monospace,SFMono-Regular,Menlo,monospace;font-size:10px;font-weight:600;letter-spacing:.18em;text-transform:uppercase;color:#737373}
.l-sticky{position:fixed;left:0;right:0;bottom:0;z-index:40;background:rgba(255,255,255,.9);-webkit-backdrop-filter:blur(8px);backdrop-filter:blur(8px);border-top:1px solid #e5e5e5;padding:10px 0}
.l-sticky-in{max-width:1024px;margin:0 auto;padding:0 24px;display:flex;align-items:center;gap:16px}
.l-sticky-in span{font-size:14px;font-weight:600;color:#0a0a0a}
.l-sticky-in .l-cta{margin-left:auto}
@media(max-width:900px){.lp-nl{display:none}.l-hero-split{grid-template-columns:1fr}.l-grid3{grid-template-columns:1fr}.l-2col{grid-template-columns:1fr}.l-stats{grid-template-columns:repeat(2,1fr)}.l-verdict{grid-template-columns:1fr}.l-slab{grid-template-columns:1fr}.l-zk{grid-template-columns:1fr}.l-arr{transform:rotate(90deg);padding:6px 0}}
@media(max-width:640px){.lp-login{display:none}.lp-word{font-size:22px}}
@media(max-width:600px){.l-ribbon-out{margin-left:-18px;margin-right:-18px}.l-stats{grid-template-columns:1fr}.l-band{padding-top:40px}.l-sticky-in{padding:0 18px}.l-sticky-in span{display:none}}`;

const ROOT_VARS =
  ':root{--bg:#fff;--fg:#0a0a0a;--muted:#525252;--faint:#737373;--line:#e5e5e5;--accent:#1E40AF;--imp-bg:#eff6ff;--mark-fg:#1E40AF;--chip:#e5e5e5;--rail:#f5f5f5;--on-accent:#fff}';

function pageJsonLd(p: LandingPage): string {
  const url = `${ORIGIN}${pagePath(p)}`;
  const crumbs = jsonLd({
    '@context': 'https://schema.org',
    '@type': 'BreadcrumbList',
    itemListElement: [
      { '@type': 'ListItem', position: 1, name: 'PrivacyNotes', item: ORIGIN },
      { '@type': 'ListItem', position: 2, name: p.seo.breadcrumb, item: url },
    ],
  });
  const faq = (p.faq as (string | Faq)[] | undefined)
    ? jsonLd({
        '@context': 'https://schema.org',
        '@type': 'FAQPage',
        mainEntity: resolveFaq(p.faq as (string | Faq)[]).map((f) => ({
          '@type': 'Question',
          name: f.q.replace(/\{price\}/g, `$${displayPrice}`),
          acceptedAnswer: {
            '@type': 'Answer',
            text: f.a.replace(/\{price\}/g, `$${displayPrice}`).replace(/\{proPrice\}/g, `$${FACTS.proPrice}`),
          },
        })),
      })
    : '';
  const app =
    p.kind === 'feature'
      ? jsonLd({
          '@context': 'https://schema.org',
          '@type': 'WebApplication',
          name: 'PrivacyNotes',
          url: ORIGIN,
          applicationCategory: 'ProductivityApplication',
          operatingSystem: 'Web, macOS, Windows, Linux, iOS, Android',
          offers: [
            { '@type': 'Offer', price: '0', priceCurrency: 'USD' },
            { '@type': 'Offer', price: String(displayPrice), priceCurrency: 'USD' },
          ],
        })
      : '';
  return crumbs + faq + app;
}

export function renderLandingHtml(p: LandingPage, all: LandingPage[]): string {
  const url = `${ORIGIN}${pagePath(p)}`;
  const body =
    p.kind === 'feature' ? renderFeature(p, all) : p.kind === 'vs' ? renderVs(p, all) : renderFor(p, all);
  return `<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>${esc(p.seo.title)}</title>
<meta name="description" content="${esc(p.seo.description)}">
<link rel="canonical" href="${url}">
<meta property="og:title" content="${esc(p.seo.title)}">
<meta property="og:description" content="${esc(p.seo.description)}">
<meta property="og:type" content="website">
<meta property="og:url" content="${url}">
<meta property="og:site_name" content="PrivacyNotes">
${ogLocaleTag()}
${OG_IMAGE_TAGS}
<link rel="icon" href="/favicon.svg" type="image/svg+xml">
<script src="/static-pages.js" defer></script>
${pageJsonLd(p)}
<style>
${ROOT_VARS}
${CHROME_CSS}
${PAGE_CSS}
</style>
</head>
<body data-static-page="landing">
<div class="wrap">
${landingHeader()}
${body}
</div>
${SITE_FOOTER}
${stickyHtml(p.sticky as { text: string; cta: string } | undefined)}
</body>
</html>`;
}

export function renderLandingSitemap(pages: LandingPage[]): string {
  const urls = pages.map((p) => `<url><loc>${ORIGIN}${pagePath(p)}</loc></url>`).join('\n');
  return `<?xml version="1.0" encoding="UTF-8"?>
<urlset xmlns="http://www.sitemaps.org/schemas/sitemap/0.9">
${urls}
</urlset>`;
}

/**
 * The publish switch. While false, the WEB BUILD EMITS NOTHING from this
 * plugin: no pages in dist/, no sitemap-landing.xml, and help-page.ts skips
 * the sitemap-index line (it imports this flag) - so a deploy publishes
 * nothing even by accident. The dev middleware and the landing builder
 * (pnpm landing:builder) keep working either way, so refinement continues
 * locally. Flip to true in the commit that launches the pages.
 * (Native apps never get these pages regardless: the plugin only runs
 * inside vite.config.ts's !isAppBuild array.)
 * Spec: ops/docs/plans/marketing-pages.md
 */
export const LANDING_PAGES_PUBLIC = false;

export function landingPagesPlugin(): Plugin {
  return {
    name: 'emit-landing-pages',
    async generateBundle() {
      // Load even when unpublished so the dataset validation and the
      // worker.ts LANDING_SLUGS cross-check still gate every build.
      const pages = await loadLandingPages();
      if (!LANDING_PAGES_PUBLIC) {
        this.info('landing pages: LANDING_PAGES_PUBLIC is false - emitting nothing');
        return;
      }
      for (const p of pages) {
        this.emitFile({
          type: 'asset',
          fileName: `${pagePath(p).slice(1)}/index.html`,
          source: renderLandingHtml(p, pages),
        });
      }
      this.emitFile({
        type: 'asset',
        fileName: 'sitemap-landing.xml',
        source: renderLandingSitemap(pages),
      });
    },
    configureServer(server) {
      // One catch-all middleware instead of a mount per slug so a dataset
      // file added while the dev server runs is picked up on the next
      // request. Datasets re-evaluate per request (live editing; the
      // landing builder relies on this for its preview iframe). Only exact
      // matches of known landing URLs are handled; everything else falls
      // through, so Vite's own assets are never intercepted.
      server.middlewares.use(async (req, res, next) => {
        try {
          const url = (req.url ?? '').split('?')[0].replace(/\/$/, '');
          if (url === '/sitemap-landing.xml') {
            const pages = await loadLandingPages();
            res.setHeader('Content-Type', 'application/xml; charset=utf-8');
            res.end(renderLandingSitemap(pages));
            return;
          }
          if (!/^\/(?:vs\/|for\/)?[a-z0-9-]+$/.test(url)) return next();
          const pages = await loadLandingPages();
          const page = pages.find((p) => pagePath(p) === url);
          if (!page) return next();
          res.setHeader('Content-Type', 'text/html; charset=utf-8');
          res.end(renderLandingHtml(page, pages));
        } catch (err) {
          next(err);
        }
      });
    },
  };
}
