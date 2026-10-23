import type { ChartSpec, DaySeries, TrackerValue } from './wellnessTypes';

/**
 * The pure geometry of a tracker chart: rects, path strings, circles and cells
 * from a spec and a size. The React chart and the printable report both draw
 * from it, so the two pictures cannot drift. Every mark sits on a calendar
 * axis: one slot per day (or per week), a missing day keeps its slot empty.
 * Spec: ops/docs/archive/wellness-statistics.md (section 6)
 */

type CellState = 'value' | 'no' | 'missing' | 'outside';

export interface Geometry {
  bars: { x: number; y: number; w: number; h: number; date: string; value: number; fill: string }[];
  path?: string;
  dots: { cx: number; cy: number; r: number; date: string; value: TrackerValue; filled: boolean }[];
  /** `round` cells draw as circles (the strip); the calendar draws squares. */
  cells: { x: number; y: number; size: number; date: string; state: CellState; round?: boolean }[];
  /** One band per day or week in time order; the calendar form gives one per in-range cell. */
  hits: { x: number; w: number; date: string; value: TrackerValue | number | undefined }[];
  /** The y range the marks were drawn against, for the rolling average. */
  lo: number;
  hi: number;
}

const BAR_MAX = 24;
const BAR_GAP = 2;
const HIT_MIN = 24;
const TOP_PAD = 4;
const DOT_R = 3;
const CELL_GAP = 2;
const DAY_MS = 86_400_000;

const toUtc = (iso: string): number => Date.parse(`${iso}T00:00:00Z`);
// ISO days are calendar labels, not instants: the arithmetic runs on UTC midnights so no DST shift moves a day.
const toIso = (ms: number): string => {
  const d = new Date(ms);
  return `${d.getUTCFullYear()}-${String(d.getUTCMonth() + 1).padStart(2, '0')}-${String(d.getUTCDate()).padStart(2, '0')}`;
};
const addDays = (iso: string, n: number): string => toIso(toUtc(iso) + n * DAY_MS);
/** Monday of the week holding `iso`. */
const mondayOf = (iso: string): string => addDays(iso, -((new Date(toUtc(iso)).getUTCDay() + 6) % 7));
const r2 = (n: number): number => Math.round(n * 100) / 100;

/** A value as a number on the y axis: an ordinal by its level index, a yes as 1. */
function toNumber(v: TrackerValue | undefined, levels?: readonly string[]): number | undefined {
  if (typeof v === 'number') return Number.isFinite(v) ? v : undefined;
  if (typeof v === 'boolean') return v ? 1 : 0;
  if (typeof v === 'string' && levels) {
    const i = levels.indexOf(v);
    return i >= 0 ? i : undefined;
  }
  return undefined;
}

interface Slot { date: string; value: number | undefined; raw: TrackerValue | number | undefined }

/** Daily slots, or one per week holding the mean (a yes/no mean is the share of yes). */
function slotsOf(spec: ChartSpec, weekly: boolean): Slot[] {
  const pts = spec.series.points;
  if (!weekly) return pts.map((p) => {
    const value = toNumber(p.value, spec.levels);
    return { date: p.date, value, raw: p.value };
  });
  const weeks = new Map<string, { date: string; sum: number; n: number }>();
  for (const p of pts) {
    const key = mondayOf(p.date);
    let w = weeks.get(key);
    if (!w) weeks.set(key, (w = { date: p.date, sum: 0, n: 0 }));
    const v = toNumber(p.value, spec.levels);
    if (v !== undefined) { w.sum += v; w.n++; }
  }
  return [...weeks.values()].map((w) => {
    const value = w.n ? w.sum / w.n : undefined;
    return { date: w.date, value, raw: value };
  });
}

function rangeOf(spec: ChartSpec, values: (number | undefined)[]): { lo: number; hi: number } {
  const seen = values.filter((v): v is number => v !== undefined);
  let lo = spec.min ?? (seen.length ? Math.min(...seen) : 0);
  let hi = spec.max ?? (seen.length ? Math.max(...seen) : 1);
  const pad = hi > lo ? (hi - lo) * 0.1 : 1;
  if (spec.min === undefined) lo -= pad;
  if (spec.max === undefined) hi += pad;
  if (hi <= lo) hi = lo + 1;
  return { lo, hi };
}

const yOf = (v: number, lo: number, hi: number, height: number): number =>
  TOP_PAD + (1 - Math.min(1, Math.max(0, (v - lo) / (hi - lo)))) * (height - TOP_PAD);

function hitBands(slots: Slot[], width: number): Geometry['hits'] {
  const slotW = slots.length ? width / slots.length : width;
  const w = Math.min(width, Math.max(slotW, HIT_MIN));
  return slots.map((s, i) => {
    const cx = (i + 0.5) * slotW;
    const x = Math.min(Math.max(0, cx - w / 2), width - w);
    return { x: r2(x), w: r2(w), date: s.date, value: s.raw };
  });
}

/** A gap of this many missing days or fewer is bridged by the line; a longer one breaks it. */
const BRIDGE_DAYS = 3;

/** The polyline through the defined points; a short gap is bridged, a longer gap ends the segment and the next point starts a new M. */
function polyline(ys: (number | undefined)[], width: number): string {
  const slotW = ys.length ? width / ys.length : width;
  let d = '';
  let open = false;
  let missing = 0;
  ys.forEach((y, i) => {
    if (y === undefined) { missing += 1; if (missing > BRIDGE_DAYS) open = false; return; }
    d += `${open ? 'L' : 'M'}${r2((i + 0.5) * slotW)} ${r2(y)}`;
    open = true;
    missing = 0;
  });
  return d;
}

function cellState(v: TrackerValue | undefined, levels?: readonly string[]): CellState {
  if (v === undefined) return 'missing';
  if (v === false) return 'no';
  if (typeof v === 'string') return v === 'taken' || levels?.includes(v) ? 'value' : 'no';
  if (Array.isArray(v)) return v.length ? 'value' : 'missing';
  return 'value';
}

function calendar(spec: ChartSpec, width: number, height: number): Geometry {
  const { from, to } = spec.series;
  const values = new Map(spec.series.points.map((p) => [p.date, p.value]));
  const start = mondayOf(from);
  const cols = Math.floor((toUtc(to) - toUtc(start)) / DAY_MS / 7) + 1;
  const size = Math.max(1, Math.floor(Math.min(
    (width - (cols - 1) * CELL_GAP) / cols,
    (height - 6 * CELL_GAP) / 7,
  )));
  const cells: Geometry['cells'] = [];
  const hits: Geometry['hits'] = [];
  for (let c = 0; c < cols; c++) {
    for (let r = 0; r < 7; r++) {
      const date = addDays(start, c * 7 + r);
      const inRange = date >= from && date <= to;
      const x = c * (size + CELL_GAP);
      cells.push({ x, y: r * (size + CELL_GAP), size, date, state: inRange ? cellState(values.get(date), spec.levels) : 'outside' });
      if (inRange) hits.push({ x, w: size, date, value: values.get(date) });
    }
  }
  const nums = spec.series.points.map((p) => toNumber(p.value, spec.levels));
  return { bars: [], dots: [], cells, hits, ...rangeOf(spec, nums) };
}

/** One cell per day in one row, each centred in its slot of the width, so a mark above or below it lands on the same day. */
function strip(spec: ChartSpec, width: number, height: number): Geometry {
  const n = spec.series.points.length;
  const slot = n ? width / n : width;
  const size = Math.max(2, Math.min(Math.floor(slot - CELL_GAP), height));
  const y = (height - size) / 2;
  const cells: Geometry['cells'] = spec.series.points.map((p, i) => ({
    x: i * slot + (slot - size) / 2, y, size, date: p.date, state: cellState(p.value, spec.levels), round: true,
  }));
  const hits: Geometry['hits'] = spec.series.points.map((p, i) => ({ x: i * slot, w: slot, date: p.date, value: p.value }));
  const nums = spec.series.points.map((p) => toNumber(p.value, spec.levels));
  return { bars: [], dots: [], cells, hits, ...rangeOf(spec, nums) };
}

export function chartGeometry(spec: ChartSpec, width: number, height: number): Geometry {
  if (spec.form === 'calendar') return calendar(spec, width, height);
  if (spec.form === 'strip') return strip(spec, width, height);
  // Dots stay daily: a yes or a no has no weekly mean to draw as a dot.
  const slots = slotsOf(spec, !!spec.weekly && spec.form !== 'dots');
  const { lo, hi } = rangeOf(spec, slots.map((s) => s.value));
  const slotW = slots.length ? width / slots.length : width;
  const geo: Geometry = { bars: [], dots: [], cells: [], hits: hitBands(slots, width), lo, hi };

  if (spec.form === 'bars') {
    const w = Math.max(1, Math.min(BAR_MAX, slotW - BAR_GAP));
    slots.forEach((s, i) => {
      if (s.value === undefined) return;
      // A value at the floor still shows as a sliver, so it never reads as a gap.
      const h = Math.max(2, height - yOf(s.value, lo, hi, height));
      geo.bars.push({
        x: r2((i + 0.5) * slotW - w / 2), y: r2(height - h), w: r2(w), h: r2(h),
        date: s.date, value: s.value, fill: spec.ramp ? spec.ramp(s.value) : spec.color,
      });
    });
  } else if (spec.form === 'line') {
    const ys = slots.map((s) => (s.value === undefined ? undefined : yOf(s.value, lo, hi, height)));
    geo.path = polyline(ys, width);
    // A point with a gap on both sides has no segment to draw, so it gets a dot.
    const alone = (i: number) => {
      for (let k = 1; k <= BRIDGE_DAYS; k++) {
        if (ys[i - k] !== undefined || ys[i + k] !== undefined) return false;
      }
      return true;
    };
    slots.forEach((s, i) => {
      const y = ys[i];
      if (y !== undefined && s.value !== undefined && alone(i)) {
        geo.dots.push({ cx: r2((i + 0.5) * slotW), cy: r2(y), r: DOT_R, date: s.date, value: s.value, filled: true });
      }
    });
  } else {
    slots.forEach((s, i) => {
      const v = s.raw;
      if (v === undefined) return;
      const filled = v === true || v === 'taken' || (typeof v === 'number' && v > 0);
      geo.dots.push({ cx: r2((i + 0.5) * slotW), cy: r2(height / 2), r: DOT_R, date: s.date, value: v, filled });
    });
  }
  return geo;
}

/**
 * The seven-day average: for each day the mean of the observed values in the
 * seven calendar days ending on it, drawn only where that window holds at
 * least four. Never "the last seven entries". Daily slots, the chart's y map.
 */
export function rollingLine(series: DaySeries, width: number, height: number, min: number, max: number): string {
  const vals = series.points.map((p) => (typeof p.value === 'number' ? p.value : undefined));
  const ys = vals.map((_, i) => {
    let sum = 0;
    let n = 0;
    for (let j = Math.max(0, i - 6); j <= i; j++) {
      const v = vals[j];
      if (v !== undefined) { sum += v; n++; }
    }
    return n >= 4 ? yOf(sum / n, min, max, height) : undefined;
  });
  return polyline(ys, width);
}

/** A bar rounded 4px at the data end and square at the baseline. */
export function barPath(b: { x: number; y: number; w: number; h: number }): string {
  const r = Math.min(4, b.w / 2, b.h);
  const { x, y, w, h } = b;
  return `M${x} ${r2(y + h)}V${r2(y + r)}Q${x} ${y} ${r2(x + r)} ${y}H${r2(x + w - r)}Q${r2(x + w)} ${y} ${r2(x + w)} ${r2(y + r)}V${r2(y + h)}Z`;
}

export interface SvgLabel { x: number; y: number; text: string; anchor?: 'start' | 'middle' | 'end' }

/** A filled square or circle for a value, a ring for a no, a faint mark for a day without an entry. */
function cellSvg(c: Geometry['cells'][number], color: string): string {
  if (c.round) {
    const r = c.size / 2;
    if (c.state === 'no') return `<circle cx="${c.x + r}" cy="${c.y + r}" r="${Math.max(1, r - 1)}" fill="none" stroke="${color}" stroke-width="${Math.min(2, r)}"/>`;
    return `<circle cx="${c.x + r}" cy="${c.y + r}" r="${r}" fill="${c.state === 'missing' ? 'currentColor' : color}" fill-opacity="${c.state === 'missing' ? 0.12 : 1}"/>`;
  }
  const fill = c.state === 'missing' ? 'currentColor' : color;
  const op = c.state === 'value' ? 1 : c.state === 'no' ? 0.3 : 0.12;
  return `<rect x="${c.x}" y="${c.y}" width="${c.size}" height="${c.size}" rx="2" fill="${fill}" fill-opacity="${op}"/>`;
}

/**
 * The same picture as a standalone SVG string for the printable report. It
 * carries no user text: colors come from the descriptor and the only text is
 * the axis labels the caller passes in, already escaped.
 */
export function toSvgString(spec: ChartSpec, width: number, height: number, opts: { labels?: SvgLabel[]; average?: boolean } = {}): string {
  const g = chartGeometry(spec, width, height);
  const out: string[] = [`<svg xmlns="http://www.w3.org/2000/svg" width="${width}" height="${height}" viewBox="0 0 ${width} ${height}" color="#737373">`];
  if (spec.form !== 'calendar' && spec.form !== 'strip') {
    out.push(`<line x1="0" y1="${height - 0.5}" x2="${width}" y2="${height - 0.5}" stroke="currentColor" stroke-opacity="0.3" stroke-width="1"/>`);
  }
  for (const b of g.bars) out.push(`<path d="${barPath(b)}" fill="${b.fill}"/>`);
  if (g.path) out.push(`<path d="${g.path}" fill="none" stroke="${spec.color}" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`);
  for (const d of g.dots) {
    out.push(d.filled
      ? `<circle cx="${d.cx}" cy="${d.cy}" r="${d.r}" fill="${spec.color}"/>`
      : `<circle cx="${d.cx}" cy="${d.cy}" r="${d.r - 0.75}" fill="none" stroke="${spec.color}" stroke-width="1.5"/>`);
  }
  for (const c of g.cells) {
    if (c.state === 'outside') continue;
    out.push(cellSvg(c, spec.color));
  }
  if (opts.average) {
    const d = rollingLine(spec.series, width, height, g.lo, g.hi);
    if (d) out.push(`<path d="${d}" fill="none" stroke="currentColor" stroke-width="2" stroke-linejoin="round" stroke-linecap="round"/>`);
  }
  for (const l of opts.labels ?? []) {
    out.push(`<text x="${l.x}" y="${l.y}" font-size="10" fill="currentColor" text-anchor="${l.anchor ?? 'start'}">${l.text}</text>`);
  }
  out.push('</svg>');
  return out.join('');
}
