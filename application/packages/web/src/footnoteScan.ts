/**
 * Footnotes in a Markdown string, for the readers that are not the editor:
 * the export renderer (HTML, PDF, the burn viewer) and the word count.
 *
 * The editor reads footnotes through markdown-it-footnote (footnotes.ts). This
 * is a second reader of the same syntax, so `tests/editorFootnotes.test.ts`
 * runs every case through both and fails when they see different footnotes.
 * It skips the places markdown-it does not read a footnote: code fences, code
 * spans and an escaped `\[^1]`.
 *
 * Spec: ops/docs/archive/footnotes.md (section 8)
 */

export interface ScannedFootnote {
  label: string;
  /** The definition's own Markdown, its four-space indent removed. */
  body: string;
}

export interface FootnoteScan {
  /** The Markdown with every definition taken out and inline notes turned into markers. */
  body: string;
  /** Definitions in file order; inline `^[...]` notes are added with a fresh label. */
  defs: ScannedFootnote[];
}

const DEF_LINE = /^ {0,3}\[\^([^\s\]]+)\]:[ \t]?(.*)$/;
const FENCE = /^ {0,3}(```|~~~)/;
const BLOCK_START = /^ {0,3}(?:#{1,6}\s|>|[-*+]\s|\d+[.)]\s|\||```|~~~|\[\^[^\s\]]+\]:)/;

/**
 * Calls `fn` on each run of text outside code spans, and keeps code spans and
 * escaped characters as they are.
 */
function mapOutsideCode(line: string, fn: (text: string) => string): string {
  let out = '';
  let i = 0;
  while (i < line.length) {
    const tick = line.indexOf('`', i);
    if (tick === -1) {
      out += fn(line.slice(i));
      break;
    }
    out += fn(line.slice(i, tick));
    let run = 0;
    while (line[tick + run] === '`') run++;
    const close = line.indexOf('`'.repeat(run), tick + run);
    if (close === -1) {
      out += line.slice(tick);
      break;
    }
    out += line.slice(tick, close + run);
    i = close + run;
  }
  return out;
}

/** Replaces each `[^label]` marker outside code with what `fn` returns for it. */
export function replaceMarkers(md: string, fn: (label: string) => string): string {
  let fence: string | null = null;
  return md
    .split('\n')
    .map((line) => {
      const f = FENCE.exec(line)?.[1];
      if (f && (fence === null || fence === f)) {
        fence = fence === null ? f : null;
        return line;
      }
      if (fence) return line;
      // Link and picture syntax is left whole: a marker there is part of a URL or an alt text.
      return mapOutsideCode(line, (text) =>
        text
          .split(/(!?\[(?:[^[\]\n]|\[[^\]\n]*\])*\]\([^)\n]*\))/)
          .map((part, i) => (i % 2 ? part : part.replace(/(\\?)\[\^([^\s\]]+)\](?!:)/g, (m, esc: string, label: string) => (esc ? m : fn(label)))))
          .join(''),
      );
    })
    .join('\n');
}

function nextLabel(used: Set<string>): string {
  let max = 0;
  // Nine digits at most: past 2^53 adding one changes nothing, and the
  // free-label loop below would never end.
  for (const l of used) if (/^\d{1,9}$/.test(l)) max = Math.max(max, Number(l));
  let n = max + 1;
  while (used.has(String(n))) n++;
  used.add(String(n));
  return String(n);
}

export function scanFootnotes(md: string): FootnoteScan {
  const lines = md.replace(/\r\n?/g, '\n').split('\n');
  const defs: ScannedFootnote[] = [];
  const kept: string[] = [];
  let fence: string | null = null;

  for (let i = 0; i < lines.length; i++) {
    const line = lines[i]!;
    const f = FENCE.exec(line)?.[1];
    if (fence || f) {
      if (f && (fence === null || fence === f)) fence = fence === null ? f : null;
      kept.push(line);
      continue;
    }
    const m = DEF_LINE.exec(line);
    if (!m) {
      kept.push(line);
      continue;
    }
    const body: string[] = [m[2] ?? ''];
    let j = i + 1;
    // Lazy lines: text that carries on the first paragraph without an indent.
    while (j < lines.length && lines[j]!.trim() !== '' && !/^ {4}|^\t/.test(lines[j]!) && !BLOCK_START.test(lines[j]!)) {
      body.push(lines[j]!);
      j++;
    }
    // Indented blocks, with the blank lines between them.
    for (;;) {
      let k = j;
      while (k < lines.length && lines[k]!.trim() === '') k++;
      if (k >= lines.length || !/^ {4}|^\t/.test(lines[k]!)) break;
      for (; j < k; j++) body.push('');
      while (j < lines.length && (/^ {4}|^\t/.test(lines[j]!) || (lines[j]!.trim() !== '' && !BLOCK_START.test(lines[j]!)))) {
        body.push(lines[j]!.replace(/^(?: {4}|\t)/, ''));
        j++;
      }
    }
    defs.push({ label: m[1]!, body: body.join('\n').trim() });
    i = j - 1;
  }

  const used = new Set(defs.map((d) => d.label));
  let fenceOn: string | null = null;
  const body = kept
    .map((line) => {
      const f = FENCE.exec(line)?.[1];
      if (f && (fenceOn === null || fenceOn === f)) {
        fenceOn = fenceOn === null ? f : null;
        return line;
      }
      if (fenceOn) return line;
      return mapOutsideCode(line, (text) =>
        text.replace(/(\\?)\^\[([^\]]+)\]/g, (whole, esc: string, note: string) => {
          if (esc) return whole;
          const label = nextLabel(used);
          defs.push({ label, body: note });
          return `[^${label}]`;
        }),
      );
    })
    .join('\n');

  return { body, defs };
}

/**
 * The definitions a reader shows, in the order it shows them: those a marker
 * uses, in marker order, then the rest in file order. The first definition of
 * a label is the one its markers point at.
 */
export function orderFootnotes(scan: FootnoteScan): { used: ScannedFootnote[]; unused: ScannedFootnote[] } {
  const first = new Map<string, ScannedFootnote>();
  for (const d of scan.defs) if (!first.has(d.label)) first.set(d.label, d);
  const used: ScannedFootnote[] = [];
  const seen = new Set<string>();
  const visit = (text: string) => {
    replaceMarkers(text, (label) => {
      const d = first.get(label);
      if (d && !seen.has(label)) {
        seen.add(label);
        used.push(d);
      }
      return '';
    });
  };
  visit(scan.body);
  for (let i = 0; i < used.length; i++) visit(used[i]!.body);
  const unused = scan.defs.filter((d) => !used.includes(d));
  return { used, unused };
}
