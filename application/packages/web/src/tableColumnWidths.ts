/**
 * Table column widths, stored in the note's own markdown.
 *
 * A pipe table carries its column widths in the dash counts of its delimiter
 * row: `| --- | ------- |` is 30% and 70%. That is the convention Pandoc reads,
 * and every other markdown renderer draws the same row as a plain table and
 * ignores the counts, so a resized table stays portable. A table nobody
 * resized is written `---` in every cell.
 *
 * In the document a width lives in the `colwidth` cell attribute that TipTap
 * and prosemirror-tables already maintain, but as a relative WEIGHT, not as
 * pixels. Everything that reads it goes through `effectiveWidths`, which turns
 * weights into whole percentages that add up to 100.
 *
 * No DOM and no ProseMirror here: the parse hook, the serializer, the node
 * view, the drag, the exporter and the word count all ask this module, so the
 * rules cannot drift between them.
 * Spec: ops/docs/plans/table-column-widths.md
 */
import { dashCounts } from './tableDelimiterRow';

/** A drag moves a border in steps of this many percent, which keeps the stored dash row short. */
const GRID = 5;

/** The narrowest a column may get, in whole percent. Half the table always stays free for the others. */
export function columnFloor(columns: number): number {
  return Math.ceil(Math.min(10, 50 / columns));
}

/** The drag step for a table of this many columns: the grid, unless the grid cannot hold them all. */
function gridFor(columns: number): number {
  return columns * Math.ceil(columnFloor(columns) / GRID) * GRID <= 100 ? GRID : 1;
}

/** Whole numbers that add up to exactly 100, each as close to its share as rounding allows. */
function largestRemainder(shares: number[]): number[] {
  const out = shares.map(Math.floor);
  const rest = 100 - out.reduce((a, b) => a + b, 0);
  shares
    .map((v, i) => [v - Math.floor(v), i] as const)
    .sort((a, b) => b[0] - a[0] || a[1] - b[1])
    .slice(0, rest)
    .forEach(([, i]) => { out[i]! += 1; });
  return out;
}

/**
 * Whole percentages for a table's columns, or null when the columns are equal.
 *
 * A missing weight (a column added after the widths were set) takes the mean
 * of the others. Every column is held at `columnFloor` or wider, and a table
 * whose columns differ by one point at most counts as equal, so an untouched
 * table keeps its `---` row.
 */
export function effectiveWidths(raw: readonly (number | null | undefined)[]): number[] | null {
  const n = raw.length;
  if (n < 2) return null;
  const set = raw.filter((v): v is number => typeof v === 'number' && v > 0);
  if (set.length === 0) return null;
  const floor = columnFloor(n);
  if (n * floor > 100) return null;
  const mean = set.reduce((a, b) => a + b, 0) / set.length;
  let w = raw.map((v) => (typeof v === 'number' && v > 0 ? v : mean));
  const total = w.reduce((a, b) => a + b, 0);
  w = w.map((v) => (v / total) * 100);
  for (let pass = 0; pass < n; pass++) {
    const low = w.map((v) => v < floor);
    if (!low.includes(true)) break;
    const need = w.reduce((a, v, i) => a + (low[i] ? floor - v : 0), 0);
    const spare = w.reduce((a, v, i) => a + (low[i] ? 0 : v - floor), 0);
    w = w.map((v, i) => (low[i] ? floor : v - ((v - floor) / spare) * need));
  }
  const p = largestRemainder(w);
  for (let i = 0; i < n; i++) {
    while (p[i]! < floor) {
      const widest = p.indexOf(Math.max(...p));
      p[widest]! -= 1;
      p[i]! += 1;
    }
  }
  return Math.max(...p) - Math.min(...p) <= 1 ? null : p;
}

/** The stretches between the pipes of a row, outer ones included, escaped pipes kept inside. */
function rawCells(line: string): string[] {
  const parts: string[] = [];
  let cur = '';
  for (let i = 0; i < line.length; i++) {
    const ch = line[i]!;
    if (ch === '\\') { cur += ch + (line[i + 1] ?? ''); i++; continue; }
    if (ch === '|') { parts.push(cur); cur = ''; } else cur += ch;
  }
  parts.push(cur);
  return parts;
}

/**
 * Whether a delimiter row was drawn to line up with its header: every cell
 * within two characters of the header cell above it. That is how people type
 * a table by hand and how formatters pad one, and in neither case do the dash
 * counts say anything about width. Measured on real tables from package
 * readmes and project docs, this keeps all but a fraction of a percent of
 * existing tables looking exactly as before.
 */
function followsHeader(header: string, delimiter: string): boolean {
  const h = rawCells(header.trim());
  const d = rawCells(delimiter.trim());
  return h.length === d.length && h.every((cell, i) => Math.abs(cell.length - d[i]!.length) <= 2);
}

/**
 * The widths a table's source asks for: its header line and its delimiter
 * line, container prefixes already removed. Null when the dashes are equal or
 * only follow the header.
 */
export function widthsFromTableLines(header: string, delimiter: string): number[] | null {
  const counts = dashCounts(delimiter);
  if (!counts || counts.every((c) => c === counts[0])) return null;
  if (followsHeader(header, delimiter)) return null;
  return effectiveWidths(counts);
}

const gcd = (a: number, b: number): number => (b ? gcd(b, a % b) : a);

/**
 * The delimiter row for a header line, the column widths (null for equal) and
 * the column alignments. Widths become the smallest dash counts that hold
 * their ratio exactly, three dashes at least. If that row would happen to line
 * up with the header, the reader would take it for typing and drop the
 * widths, so the counts grow until it does not.
 */
export function delimiterRow(header: string, widths: readonly number[] | null, aligns: readonly (string | null | undefined)[]): string {
  const cell = (dashes: number, align: string | null | undefined): string => {
    const run = '-'.repeat(dashes);
    return align === 'center' ? `:${run}:` : align === 'right' ? `${run}:` : run;
  };
  if (!widths) return `| ${aligns.map((a) => cell(3, a)).join(' | ')} |`;
  const g = widths.reduce(gcd);
  const ratio = widths.map((w) => w / g);
  let k = Math.ceil(3 / Math.min(...ratio));
  for (;;) {
    const row = `| ${ratio.map((r, i) => cell(r * k, aligns[i])).join(' | ')} |`;
    if (!followsHeader(header, row)) return row;
    k *= 2;
  }
}

/**
 * Where border `border` would mirror its partner across the middle of the
 * table: the border as far from the other edge as the partner is from this
 * one. For the middle border (two columns, or any even count) that is the
 * middle itself. The partner is never one of the two columns a drag moves,
 * so the answer holds for the whole drag. Null when the drag cannot reach it.
 */
export function mirrorEdge(widths: readonly number[], border: number): number | null {
  const n = widths.length;
  const partner = n - 2 - border;
  const edgeOf = (b: number) => widths.slice(0, b + 1).reduce((a, w) => a + w, 0);
  const target = partner === border ? 50 : 100 - edgeOf(partner);
  const floor = columnFloor(n);
  const before = edgeOf(border) - widths[border]!;
  const after = edgeOf(border + 1);
  return target >= before + floor && target <= after - floor ? target : null;
}

/**
 * The widths after dragging the border between column `border` and the one
 * after it by `delta` percent (reverse the sign in a right-to-left table).
 * Only that pair changes. The border lands on the drag grid, and each column
 * of the pair keeps at least the floor. Within half a grid step of `magnet`
 * (the mirror position) it lands exactly there, on the grid or not.
 */
export function dragWidths(start: readonly number[], border: number, delta: number, magnet: number | null = null): number[] {
  const n = start.length;
  const grid = gridFor(n);
  const floor = Math.ceil(columnFloor(n) / grid) * grid;
  const before = start.slice(0, border).reduce((a, b) => a + b, 0);
  const pair = start[border]! + start[border + 1]!;
  const lo = before + floor;
  const hi = before + pair - floor;
  if (hi < lo) return start.slice();
  let edge = Math.round((before + start[border]! + delta) / grid) * grid;
  edge = Math.min(Math.max(edge, Math.ceil(lo / grid) * grid), Math.floor(hi / grid) * grid);
  if (edge < lo || edge > hi) edge = Math.min(Math.max(before + start[border]! + delta, lo), hi);
  if (magnet !== null && Math.abs(before + start[border]! + delta - magnet) <= grid / 2) edge = magnet;
  const out = start.slice();
  out[border] = edge - before;
  out[border + 1] = pair - out[border]!;
  return out;
}

/**
 * Whole percentages to store after a drag. Every border lands on the grid
 * when the grid can hold the table, which keeps the dash row short; when it
 * cannot, the widths are rounded to whole percent instead. Null when the
 * result is equal columns, which is stored as no widths at all.
 */
export function commitWidths(widths: readonly number[]): number[] | null {
  const n = widths.length;
  const grid = gridFor(n);
  const floor = columnFloor(n);
  const out: number[] = [];
  let prev = 0;
  let edge = 0;
  for (let i = 0; i < n; i++) {
    edge += widths[i]!;
    const snapped = i === n - 1 ? 100 : Math.round(edge / grid) * grid;
    out.push(snapped - prev);
    prev = snapped;
  }
  if (!out.every((w) => w >= floor)) return effectiveWidths(widths);
  return Math.max(...out) - Math.min(...out) <= 1 ? null : out;
}
