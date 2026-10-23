import { buildPool, mountTypewriter, type TypewriterLook } from './typewriter';

// The typewriter lines as the site footer's closing line (owner, 2026-10-23,
// variant B of the mockups, moved onto the seam 2026-10-23): a pill with the
// lock screen's line and a pause button, centered on the footer's top edge,
// half on the page and half on the footer. The pill is as wide as the
// longest line of the page's language (`--fl-ch`, from footerLinesHtml), so
// it holds still while a line types inside it and no line wraps where the
// page is wide enough. On a narrow page a long line wraps and the pill grows
// both ways from the seam. A
// zero-height row, so the footer
// keeps its own spacing; it must be the footer's first child.
//
// One source for both footers. The markup, the CSS and the behavior are
// here; SiteFooter.tsx (homepage, React) and siteFooterFor() in
// static-page-chrome.ts (every static page) both render footerLinesHtml() with
// FOOTER_LINES_CSS and call mountFooterLines(), the static pages through the
// /footer-lines.js bundle of this module (footer-lines-script.ts). The line itself is the
// app's typewriter engine (./typewriter). Framework-free on purpose, so the
// static bundle stays small. Callers pass the words: the homepage from
// i18next, the static pages from the locale catalogs.

export type FooterLinesText = {
  /** `loading.lines` */
  lines: string[];
  /** `loading.loadingOnly`: the footer may say them too (owner, 2026-10-23). */
  loadingOnly: string[];
  /** `loading.pause` and `loading.play`, the button's label and tooltip. */
  pause: string;
  play: string;
};

/** Where the static pages load this module as a classic script. */
const FOOTER_LINES_SRC = '/footer-lines.js';
export const FOOTER_LINES_SCRIPT_TAG = `<script src="${FOOTER_LINES_SRC}" defer></script>`;

/** This browser's choice, shared by the homepage and the static pages (one origin). */
const PAUSED_KEY = 'privacynotes.footerLinesPaused';

const PAUSE_ICON =
  '<svg width="12" height="12" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><rect x="52" y="36" width="56" height="184" rx="12"/><rect x="148" y="36" width="56" height="184" rx="12"/></svg>';
const PLAY_ICON =
  '<svg width="12" height="12" viewBox="0 0 256 256" fill="currentColor" aria-hidden="true"><path d="M72 39.9v176.2a8 8 0 0 0 12.2 6.8l140.9-88.1a8 8 0 0 0 0-13.6L84.2 33.1A8 8 0 0 0 72 39.9Z"/></svg>';

/** The footer is a dark slab in both themes, so the colors are literals. */
const FOOTER_LOOK: TypewriterLook = {
  caret: 'fl-caret',
  caretBlink: 'fl-blink',
  caretPulse: 'fl-blink',
  select: 'fl-sel',
  strike: 'fl-strike',
  cipher: 'fl-cipher',
  scanner: 'fl-scan',
};

/**
 * The tooltip is CSS only: the button's own aria-label, shown above it on
 * hover and on keyboard focus, anchored to its right edge so it never leaves
 * the page on a phone.
 */
export const FOOTER_LINES_CSS = `.fl{position:relative;z-index:1;height:0;display:flex;align-items:flex-start;justify-content:center;padding:0 16px}
.fl-pill{display:flex;align-items:center;gap:10px;width:min(100%,calc(var(--fl-ch,49) * 1ch + 70px));padding:5px 5px 5px 16px;border:1px solid #3D362A;border-radius:20px;background:var(--wl-footer,var(--footer,#161210));transform:translateY(-50%);font:14px/1.5 ui-monospace,SFMono-Regular,Menlo,monospace;color:#A69E8F}
.fl-line{flex:1 1 auto;min-width:0;min-height:1.5em;text-align:center;overflow-wrap:anywhere;user-select:none;-webkit-user-select:none}
.fl-caret{background:#A69E8F}
.fl-blink{animation:fl-blink 1.1s steps(1,end) infinite}
@keyframes fl-blink{50%{opacity:0}}
.fl-sel{border-radius:2px;background:rgba(79,107,213,.4);color:#fff}
.fl-strike{text-decoration:line-through;text-decoration-thickness:1.5px}
.fl-cipher{color:#7B8CF0}
.fl-scan{border-radius:2px;background:rgba(79,107,213,.45);color:#fff}
.fl-btn{position:relative;flex:0 0 auto;display:inline-flex;align-items:center;justify-content:center;width:28px;height:28px;padding:0;border:1px solid #2E2820;border-radius:50%;background:transparent;color:#A69E8F;cursor:pointer;transition:color .15s,border-color .15s}
.fl-btn:hover{color:#fff;border-color:#3D362A}
.fl-btn:focus-visible{outline:2px solid #4F6BD5;outline-offset:2px}
.fl-btn::after{content:attr(aria-label);position:absolute;right:-6px;bottom:calc(100% + 10px);padding:5px 9px;border:1px solid #3D362A;border-radius:6px;background:#161210;color:#F2EEE6;font:500 12px/1.3 Inter,system-ui,sans-serif;white-space:nowrap;opacity:0;transform:translateY(4px);pointer-events:none;transition:opacity .15s,transform .15s}
.fl-btn:hover::after,.fl-btn:focus-visible::after{opacity:1;transform:none}
@media (hover:none){.fl-btn:hover::after{opacity:0}}
@media (max-width:639px){.fl{margin-bottom:10px}.fl-pill{gap:8px;padding-left:12px;font-size:12px}}
@media (prefers-reduced-motion:reduce){.fl-blink{animation:none}.fl-btn::after{transition:none}}`;

function esc(value: string): string {
  return value.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
}

/** How many monospace cells the longest line takes; a wide (CJK) letter takes two. */
function longest(lines: string[]): number {
  return Math.max(1, ...lines.map((line) => Array.from(line, (c) => (/[\u1100-\u115f\u2e80-\ua4cf\uac00-\ud7a3\uf900-\ufaff\uff00-\uff60]/.test(c) ? 2 : 1)).reduce((a: number, b: number) => a + b, 0)));
}

/** The closing line's markup, words included; mountFooterLines() brings it to life. */
export function footerLinesHtml(text: FooterLinesText): string {
  return `<div class="fl" style="--fl-ch:${longest([...text.lines, ...text.loadingOnly])}" data-footer-lines data-lines="${esc(JSON.stringify(text.lines))}" data-loading-lines="${esc(JSON.stringify(text.loadingOnly))}" data-pause="${esc(text.pause)}" data-play="${esc(text.play)}"><div class="fl-pill"><div class="fl-line" aria-hidden="true"></div><button type="button" class="fl-btn" aria-label="${esc(text.pause)}" aria-pressed="false">${PAUSE_ICON}</button></div></div>`;
}

function startPaused(): boolean {
  try {
    const saved = localStorage.getItem(PAUSED_KEY);
    if (saved !== null) return saved === '1';
  } catch {
    /* storage refused: fall through to the motion setting */
  }
  return window.matchMedia?.('(prefers-reduced-motion: reduce)').matches ?? false;
}

function strings(raw: string | undefined): string[] {
  try {
    const value: unknown = JSON.parse(raw ?? '[]');
    return Array.isArray(value) ? value.filter((v): v is string => typeof v === 'string') : [];
  } catch {
    return [];
  }
}

/**
 * Starts the line inside a footerLinesHtml() root. It types only while the
 * footer is on screen. Returns the cleanup.
 */
export function mountFooterLines(root: HTMLElement): () => void {
  const host = root.querySelector<HTMLElement>('.fl-line');
  const button = root.querySelector<HTMLButtonElement>('.fl-btn');
  if (!host || !button) return () => {};
  let paused = startPaused();
  const engine = mountTypewriter(host, {
    pool: buildPool(strings(root.dataset.lines), strings(root.dataset.loadingLines)),
    look: FOOTER_LOOK,
    human: true,
    paused,
    running: false,
  });

  function show() {
    const label = (paused ? root.dataset.play : root.dataset.pause) ?? '';
    button!.setAttribute('aria-label', label);
    button!.setAttribute('aria-pressed', String(paused));
    button!.innerHTML = paused ? PLAY_ICON : PAUSE_ICON;
  }
  function toggle() {
    paused = !paused;
    engine.setPaused(paused);
    show();
    try {
      localStorage.setItem(PAUSED_KEY, paused ? '1' : '0');
    } catch {
      /* the choice holds for this page only */
    }
  }
  show();
  button.addEventListener('click', toggle);

  const seen = typeof IntersectionObserver === 'undefined'
    ? null
    : new IntersectionObserver((entries) => {
      engine.setRunning(entries.some((e) => e.isIntersecting));
    });
  if (seen) seen.observe(root);
  else engine.setRunning(true);

  return () => {
    seen?.disconnect();
    button.removeEventListener('click', toggle);
    engine.destroy();
  };
}

// On a static page this module is /footer-lines.js, a classic deferred
// script, the one case with a currentScript: it starts every footer line on
// the page itself. Imported as a module (the homepage, the Node build) it
// does nothing here.
if (typeof document !== 'undefined' && document.currentScript?.getAttribute('src') === FOOTER_LINES_SRC) {
  for (const root of document.querySelectorAll<HTMLElement>('[data-footer-lines]')) mountFooterLines(root);
}
