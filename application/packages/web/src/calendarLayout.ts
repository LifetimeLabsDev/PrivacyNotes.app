import type { DayEntry, DayIndex } from './notesViewUtils';
import { dayNumber, minutesOf } from './schedule';

/**
 * Where the large calendar puts each item: the multi-day bars of a week row in
 * lanes, the chips of a day under them with a "+N more", and the timed cards of
 * the hour grid side by side when they overlap. Pure, so the layout is a table
 * of numbers in a test.
 * Spec: ops/docs/plans/calendar-pillar-spec.md (steps 1, 4 and 5)
 */

/** The most lanes of bars a week row draws; a further bar goes into "+N more". */
const MAX_LANES = 2;

export type WeekBar = {
  entry: DayEntry;
  /** 0..6, the first and last column the bar covers in this row. */
  startCol: number;
  endCol: number;
  lane: number;
  /** The item started before this row, or goes on after it: a flat end there. */
  contStart: boolean;
  contEnd: boolean;
};

/** A stable key for one occurrence of one item. */
export function entryKey(e: DayEntry): string {
  return `${e.id}|${e.span?.start ?? e.occurrence ?? ''}`;
}

/**
 * The bars of one week row: each multi-day item once, in the order the index
 * sorts it on its first day in the row, in the first lane free over its
 * columns. A bar past the last lane is left out of `bars` and counted in
 * `hidden` on each of its days, so the day's "+N more" includes it.
 */
export function weekBars(days: readonly string[], index: DayIndex, hidden?: (e: DayEntry) => boolean): { bars: WeekBar[]; hidden: Map<string, number> } {
  const first = days[0]!;
  const last = days[days.length - 1]!;
  const seen = new Set<string>();
  const found: { entry: DayEntry; startCol: number; endCol: number }[] = [];
  days.forEach((day, col) => {
    for (const e of index.entriesOf(day)) {
      if (!e.span || hidden?.(e)) continue;
      const key = entryKey(e);
      if (seen.has(key)) continue;
      seen.add(key);
      const startCol = e.span.start < first ? 0 : col;
      const endCol = Math.min(days.length - 1, col + dayNumber(e.span.end < last ? e.span.end : last) - dayNumber(days[col]!));
      found.push({ entry: e, startCol, endCol });
    }
  });
  const lanes: number[][] = [];
  const bars: WeekBar[] = [];
  const over = new Map<string, number>();
  for (const f of found) {
    let lane = lanes.findIndex((cols) => cols.every((c) => c < f.startCol || c > f.endCol));
    if (lane === -1) lane = lanes.length;
    if (lane >= MAX_LANES) {
      for (let c = f.startCol; c <= f.endCol; c++) over.set(days[c]!, (over.get(days[c]!) ?? 0) + 1);
      continue;
    }
    (lanes[lane] ??= []).push(...Array.from({ length: f.endCol - f.startCol + 1 }, (_, i) => f.startCol + i));
    bars.push({
      entry: f.entry,
      startCol: f.startCol,
      endCol: f.endCol,
      lane,
      contStart: f.entry.span!.start < days[f.startCol]!,
      contEnd: f.entry.span!.end > days[f.endCol]!,
    });
  }
  return { bars, hidden: over };
}

/** How many lanes a row's bars take, to keep the chips under them. */
export function lanesUsed(bars: readonly WeekBar[]): number {
  return bars.reduce((n, b) => Math.max(n, b.lane + 1), 0);
}

/**
 * The single-day chips of a day, as many as fit, and how many more the day
 * holds (the chips cut off plus the bars that found no lane).
 */
export function dayChips(entries: readonly DayEntry[], fit: number, hiddenBars = 0): { chips: DayEntry[]; more: number } {
  const single = entries.filter((e) => !e.span);
  if (single.length + hiddenBars <= fit) return { chips: single, more: hiddenBars };
  const shown = Math.max(0, fit - 1);
  return { chips: single.slice(0, shown), more: single.length - shown + hiddenBars };
}

// ── The hour grid ─────────────────────────────────────────────────

export type TimedBlock = {
  entry: DayEntry;
  /** Minutes after midnight on this column's day. */
  start: number;
  end: number;
  /** The part after midnight of an item that started the day before. */
  carried: boolean;
  col: number;
  cols: number;
};

/** An item with no end draws one hour. */
const DEFAULT_MINUTES = 60;
/** The shortest a card draws, so a five-minute item still has a title. */
const MIN_MINUTES = 20;

/**
 * The timed cards of one day: its own timed items, and the part after
 * midnight of an overnight item from the day before (an end time before its
 * start time means the next day). A multi-day item stays a bar in the
 * all-day band. Overlapping cards share the width: each
 * cluster of overlaps gets as many columns as it needs at most.
 */
export function timedBlocks(day: string, prevDay: string, index: DayIndex, hidden?: (e: DayEntry) => boolean): TimedBlock[] {
  const blocks: Omit<TimedBlock, 'col' | 'cols'>[] = [];
  for (const e of index.entriesOf(day)) {
    // A multi-day item is a bar in the all-day band, timed or not.
    if (!e.time || e.span || hidden?.(e)) continue;
    const start = minutesOf(e.time);
    const endRaw = e.timeEnd ? minutesOf(e.timeEnd) : start + DEFAULT_MINUTES;
    const end = Math.min(1440, endRaw <= start ? 1440 : endRaw);
    blocks.push({ entry: e, start, end: Math.max(end, Math.min(1440, start + MIN_MINUTES)), carried: false });
  }
  for (const e of index.entriesOf(prevDay)) {
    if (!e.time || !e.timeEnd || e.span || hidden?.(e)) continue;
    const end = minutesOf(e.timeEnd);
    if (end >= minutesOf(e.time) || end === 0) continue;
    blocks.push({ entry: e, start: 0, end: Math.max(end, MIN_MINUTES), carried: true });
  }
  blocks.sort((a, b) => a.start - b.start || b.end - a.end);
  const out: TimedBlock[] = [];
  let cluster: TimedBlock[] = [];
  let clusterEnd = -1;
  const close = () => {
    const cols = cluster.reduce((n, b) => Math.max(n, b.col + 1), 0);
    for (const b of cluster) b.cols = cols;
    out.push(...cluster);
    cluster = [];
  };
  for (const b of blocks) {
    if (b.start >= clusterEnd && cluster.length) close();
    const taken = new Set(cluster.filter((c) => c.end > b.start).map((c) => c.col));
    let col = 0;
    while (taken.has(col)) col++;
    cluster.push({ ...b, col, cols: 1 });
    clusterEnd = Math.max(clusterEnd, b.end);
  }
  if (cluster.length) close();
  return out;
}
