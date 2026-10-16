/**
 * Keeps the reading position when a note switches between the formatted view
 * and the Markdown view. Both views scroll in the same pane but have very
 * different heights (a picture is tall in one and one line in the other), so
 * a scroll percent lands lines off. Instead the first block at the top of the
 * pane is the anchor: its first words are found in the other view, line by
 * line with the Markdown marks stripped, and the pane scrolls that place to
 * where the block was. The percent stays as the estimate that picks between
 * two places with the same words, and as the fallback when nothing matches.
 * Spec: ops/issues/0493.md (Reading position)
 */

/** What a switch carries from one view to the other. */
export type ViewAnchor = { words: string; offset: number; ratio: number };

/** Lower case, one space between words, no edge spaces. */
function normalizeText(text: string): string {
  return text.replace(/\s+/g, ' ').trim().toLowerCase();
}

/** The first words of a block, enough to find it again. */
export function anchorWords(text: string, count = 6): string {
  return normalizeText(text).split(' ').filter(Boolean).slice(0, count).join(' ');
}

/** A line that draws no text of its own in the formatted view: a code
 *  fence, a callout header, a table rule, a divider. */
const STRUCTURAL = /^\s*(?:(?:>\s?)*\[![\w-]+\][+-]?.*|`{3,}.*|~{3,}.*|\|?[\s:|-]*-{3,}[\s:|-]*|[-*_]{3,}\s*)$/;

/** One Markdown line as the formatted view shows its text; empty for a
 *  line that shows none. */
export function stripMarkdownLine(line: string): string {
  if (STRUCTURAL.test(line)) return '';
  return normalizeText(
    line
      .replace(/<[^>]*>/g, '')
      .replace(/^\s*(?:>\s?)+/, '')
      .replace(/^\s*#{1,6}\s+/, '')
      .replace(/^\s*(?:[-*+]|\d+[.)])\s+(?:\[[ xX]\]\s+)?/, '')
      .replace(/!\[[^\]]*\]\([^)]*\)/g, '')
      .replace(/\[\[([^\]|]*)(?:\|([^\]]*))?\]\]/g, (_, target: string, label?: string) => label ?? target)
      .replace(/\[([^\]]*)\]\([^)]*\)/g, '$1')
      .replace(/(\*\*|__|~~|\|\||`)/g, '')
      .replace(/(^|[\s(])[*_](?=\S)|(?<=\S)[*_](?=$|[\s).,!?:;])/g, '$1')
      .replace(/^\|/, '')
      .replace(/\|/g, ' '),
  );
}

/**
 * The index of the entry that starts with `words` (or, failing that, holds
 * them), nearest to `estimate`; fewer words are tried when the full run is
 * not found, down to two. -1 when nothing matches.
 */
export function findNearest(entries: readonly string[], words: string, estimate: number): number {
  const all = words.split(' ').filter(Boolean);
  for (let n = all.length; n >= Math.min(2, all.length) && n > 0; n--) {
    const needle = all.slice(0, n).join(' ');
    for (const test of [(e: string) => e.startsWith(needle), (e: string) => e.includes(needle)]) {
      let best = -1;
      entries.forEach((e, i) => {
        if (e && test(e) && (best === -1 || Math.abs(i - estimate) < Math.abs(best - estimate))) best = i;
      });
      if (best !== -1) return best;
    }
  }
  return -1;
}

// ------------------------------------------------------------------
// The DOM half: what sits at the top of the pane, and putting it back.
// ------------------------------------------------------------------

/** The blocks of the formatted view that carry text a reader sees. */
const RICH_BLOCKS = 'p, h1, h2, h3, h4, h5, h6, pre, th, td';

/** A block placed below the reading line keeps at most this gap, so a
 *  picture above it in one view does not push it down the other. */
const MAX_GAP = 48;

/** The top of the part of the pane the reader sees: under the sticky tag
 *  row, and under the format bar when it sits at the top. */
function readingLine(pane: HTMLElement): number {
  const top = pane.getBoundingClientRect().top;
  const tagRow = parseFloat(getComputedStyle(pane).getPropertyValue('--pn-tagrow-h')) || 0;
  const bar = pane.querySelector<HTMLElement>('.pn-editor-toolbar:not(.pn-toolbar-bottom)');
  return Math.max(top + tagRow, bar ? bar.getBoundingClientRect().bottom : 0);
}

function scrollRatio(pane: HTMLElement): number {
  const max = pane.scrollHeight - pane.clientHeight;
  return max > 0 ? pane.scrollTop / max : 0;
}

/** The top of each line of a textarea, from its own top, measured on a copy
 *  with the same font, width and wrapping. */
function lineTops(area: HTMLTextAreaElement, lines: readonly string[]): number[] {
  const cs = getComputedStyle(area);
  const mirror = document.createElement('div');
  for (const p of ['fontFamily', 'fontSize', 'fontWeight', 'lineHeight', 'letterSpacing', 'tabSize', 'paddingTop', 'paddingLeft', 'paddingRight'] as const) {
    mirror.style[p] = cs[p];
  }
  Object.assign(mirror.style, {
    position: 'absolute', visibility: 'hidden', top: '0', left: '-9999px',
    width: `${area.clientWidth}px`, whiteSpace: 'pre-wrap', overflowWrap: 'break-word', boxSizing: 'border-box',
  });
  for (const line of lines) {
    const row = document.createElement('div');
    row.textContent = line || ' ';
    mirror.appendChild(row);
  }
  document.body.appendChild(mirror);
  const tops = Array.from(mirror.children, (row) => (row as HTMLElement).offsetTop);
  mirror.remove();
  return tops;
}

/** Reads the anchor from whichever view is on screen; null when the pane
 *  is at its top, where both views already agree. */
export function captureAnchor(pane: HTMLElement): ViewAnchor | null {
  if (pane.scrollTop < 2) return null;
  const line = readingLine(pane);
  const ratio = scrollRatio(pane);
  const area = pane.querySelector<HTMLTextAreaElement>('textarea[data-pn-source]');
  if (area) {
    const lines = area.value.split('\n');
    const tops = lineTops(area, lines);
    const areaTop = area.getBoundingClientRect().top;
    let i = tops.findIndex((t, n) => areaTop + (tops[n + 1] ?? t + 1) > line + 2);
    while (i !== -1 && i < lines.length && !stripMarkdownLine(lines[i]!)) i++;
    if (i === -1 || i >= lines.length) return { words: '', offset: 0, ratio };
    return { words: anchorWords(stripMarkdownLine(lines[i]!)), offset: areaTop + tops[i]! - line, ratio };
  }
  const body = pane.querySelector<HTMLElement>('.ProseMirror');
  if (!body) return null;
  const block = Array.from(body.querySelectorAll<HTMLElement>(RICH_BLOCKS))
    .find((el) => el.getClientRects().length > 0 && el.getBoundingClientRect().bottom > line + 2 && normalizeText(el.textContent ?? '') !== '');
  if (!block) return { words: '', offset: 0, ratio };
  return { words: anchorWords(block.textContent ?? ''), offset: block.getBoundingClientRect().top - line, ratio };
}

/** Scrolls the view now on screen so the anchor sits where it was. False
 *  while that view has not drawn its text yet. */
export function restoreAnchor(pane: HTMLElement, anchor: ViewAnchor): boolean {
  const area = pane.querySelector<HTMLTextAreaElement>('textarea[data-pn-source]');
  const body = area ? null : pane.querySelector<HTMLElement>('.ProseMirror');
  if (!area && !body?.firstElementChild) return false;
  const max = pane.scrollHeight - pane.clientHeight;
  const line = readingLine(pane);
  let gap = Math.min(anchor.offset, MAX_GAP);
  let top: number | null = null;
  if (anchor.words && area) {
    const lines = area.value.split('\n');
    const at = findNearest(lines.map(stripMarkdownLine), anchor.words, anchor.ratio * lines.length);
    if (at !== -1) top = area.getBoundingClientRect().top + lineTops(area, lines)[at]!;
  } else if (anchor.words && body) {
    const blocks = Array.from(body.querySelectorAll<HTMLElement>(RICH_BLOCKS));
    const at = findNearest(blocks.map((b) => normalizeText(b.textContent ?? '')), anchor.words, anchor.ratio * blocks.length);
    // A block inside a folded callout has no box: the callout stands in.
    let shown: HTMLElement | null = at === -1 ? null : blocks[at]!;
    while (shown && shown.getClientRects().length === 0) shown = shown.parentElement;
    if (shown) top = shown.getBoundingClientRect().top;
    if (shown && shown !== blocks[at]) gap = 0;
  }
  pane.scrollTop = top === null
    ? Math.round(anchor.ratio * max)
    : Math.round(pane.scrollTop + top - line - gap);
  return true;
}
