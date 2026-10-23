import { cloneElement, isValidElement, useMemo, useState, type ReactElement, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { CaretRight } from '../icons';
import { TRACKER_ICONS } from '../trackers/icons';
import { MoodMark } from '../moodMark';
import { moodWord as moodWordOf } from '../checkIn';
import { MOOD_COLORS, moodColor } from '../moodColors';
import { compare, qualifiesForInsight } from '../trackerCompare';
import { formatDay, weekdayLabel } from '../intlFormat';
import { toLocalIso } from '../notesViewUtils';
import { Button, GlyphTile } from '../ui';
import type { CompareResult, DaySeries, TrackerDescriptor, TrackerValue } from '../wellnessTypes';
import { formatNumber, formatValue, hasData, levelLabel, trackerName, type WellnessModel } from './wellnessModel';

/**
 * The small parts of the Statistics page, in the look of the check-in card
 * and the journal pills: the tracker glyph, the logged pill, the bar that
 * grows from the middle, the weekday chart, the mood mix and the calendar.
 * Spec: ops/docs/archive/wellness-statistics.md (section 22)
 */

/** Trackers where less is the better direction; a fall in them reads as good. */
const LOWER_IS_BETTER = new Set(['caffeine', 'pain', 'screenTime', 'heartRate']);
/** Trackers whose change is neither good nor bad on its own. */
const NEUTRAL = new Set(['weight']);

/** Days on the thinner side of a split for two dots, and for three. */
const SURE_TWO = 14;
const SURE_THREE = 30;

/** The tone of a change: good, bad, or neither, by the tracker's better direction. */
export function changeTone(d: TrackerDescriptor, delta: number): 'good' | 'bad' | 'neutral' {
  if (delta === 0 || d.source !== 'builtin' || NEUTRAL.has(d.id)) return 'neutral';
  const up = delta > 0;
  return up !== LOWER_IS_BETTER.has(d.id) ? 'good' : 'bad';
}
export const TONE_TEXT = { good: 'text-success', bad: 'text-danger', neutral: 'text-pn-muted' } as const;

/** The journal pill's glyph of a tracker, at a size; a custom tracker has none. */
function glyphOf(d: TrackerDescriptor, size: number): ReactNode {
  const key = d.source === 'medication' ? 'medication' : d.id === 'sleepHours' || d.id === 'sleepQuality' ? 'sleep' : d.id;
  const icon = TRACKER_ICONS[key];
  return isValidElement(icon) ? cloneElement(icon as ReactElement<{ size?: number }>, { size }) : null;
}

/** A tracker's glyph on a soft tile of its own color, or its dot when it has no glyph. */
export function TrackerTile({ d, size = 26 }: { d: TrackerDescriptor; size?: number }) {
  return <GlyphTile color={d.color} size={size}>{glyphOf(d, Math.round(size * 0.54))}</GlyphTile>;
}

/** The pill tints: the logged green, a worse value, a value in between, and no judgement. */
const PILL_TONE = {
  good: 'bg-success/10 text-success',
  bad: 'bg-danger/10 text-danger',
  warn: 'bg-warning/10 text-warning',
  neutral: 'bg-surface-0 text-pn-soft',
} as const;
type PillTone = keyof typeof PILL_TONE;

/** One logged pill, as on a journal entry: a glyph and a short value, never a control. `tint` paints it in a color of its own (a mood's band). */
export function StatPill({ icon, children, muted = false, tone, tint }: { icon?: ReactNode; children: ReactNode; muted?: boolean; tone?: PillTone; tint?: string }) {
  const look = tint ? 'text-pn' : tone ? PILL_TONE[tone] : muted ? 'bg-surface-0 text-pn-muted' : PILL_TONE.good;
  return (
    <span
      className={`inline-flex items-center gap-1.5 rounded-md px-2 h-7 text-xs font-medium whitespace-nowrap ${look}`}
      style={tint ? { backgroundColor: `color-mix(in srgb, ${tint} 18%, transparent)` } : undefined}
    >
      {icon}
      {children}
    </span>
  );
}

/** A tracker's pill: its glyph and a value. A neutral pill keeps the glyph in the tracker's own color. */
export function TrackerPill({ d, children, muted, tone, icon, tint }: { d: TrackerDescriptor; children: ReactNode; muted?: boolean; tone?: PillTone; icon?: ReactNode; tint?: string }) {
  const glyph = icon ?? glyphOf(d, 12) ?? <span className="w-2 h-2 rounded-full" style={{ backgroundColor: d.color }} />;
  const shown = tone === 'neutral' && !icon ? <span className="inline-flex" style={{ color: d.color }}>{glyph}</span> : glyph;
  return <StatPill icon={shown} muted={muted} tone={tone} tint={tint}>{children}</StatPill>;
}

/** How far from the range's average a day's value must sit, as a share of the tracker's spread, to be colored, and to be clearly worse. */
const TONE_NEAR = 0.1;
const TONE_FAR = 0.25;

/** Built-in levels where a higher level is the better day. */
const HIGHER_LEVEL_IS_BETTER = new Set(['sleepQuality', 'activity']);

/**
 * Which way a tracker is better, learned from the person's own mood: +1 when
 * mood runs clearly higher with more of it (or on its yes days), -1 when
 * lower, 0 when the days do not show it. Built-ins with a known direction
 * never ask.
 */
function learnedDirection(model: WellnessModel, d: TrackerDescriptor): 1 | -1 | 0 {
  const mood = model.byId('mood');
  if (!mood || d.id === 'mood') return 0;
  const r = compare(model.entries, d, mood, model.range, 0);
  if (!qualifiesForInsight(r) || r.delta === null) return 0;
  return r.delta > 0 ? 1 : -1;
}

/**
 * The tone of one day's value against the person's own days in the range:
 * green when better, amber when a little worse, red when clearly worse.
 * "Better" is the tracker's known direction, or for a custom tracker and a
 * yes or no the direction learned from mood (`dir`); a level counts higher
 * as better for sleep quality and activity. What has no direction stays
 * neutral; a medication reads as taken, skipped or missed.
 */
function dayTone(d: TrackerDescriptor, v: TrackerValue | undefined, series: DaySeries, dir: 1 | -1 | 0): PillTone {
  if (d.kind === 'medication') return v === 'taken' ? 'good' : v === 'missed' ? 'bad' : v === 'skipped' ? 'warn' : 'neutral';
  if (typeof v === 'boolean') {
    if (dir === 0) return 'neutral';
    // A yes that goes with a better mood is good, a yes that goes with a worse one is bad; a no is only good when it avoids the bad one.
    if (v) return dir > 0 ? 'good' : 'bad';
    return dir < 0 ? 'good' : 'neutral';
  }
  if (typeof v === 'string' && d.kind === 'ordinal' && d.levels && HIGHER_LEVEL_IS_BETTER.has(d.id)) {
    const idx = d.levels.indexOf(v);
    const idxs = series.points.map((p) => (typeof p.value === 'string' ? d.levels!.indexOf(p.value) : -1)).filter((i) => i >= 0);
    if (idx < 0 || idxs.length < 3) return 'neutral';
    const gap = idx - idxs.reduce((a, b) => a + b, 0) / idxs.length;
    return gap >= 0.5 ? 'good' : gap <= -1.5 ? 'bad' : gap <= -0.5 ? 'warn' : 'neutral';
  }
  if (typeof v !== 'number' || (d.kind !== 'scale' && d.kind !== 'measure')) return 'neutral';
  const nums = series.points.map((p) => p.value).filter((x): x is number => typeof x === 'number');
  if (nums.length < 3) return 'neutral';
  const avg = nums.reduce((a, b) => a + b, 0) / nums.length;
  const gap = Math.abs(v - avg) / spreadOf(d, series);
  if (gap < TONE_NEAR) return 'neutral';
  const known = changeTone(d, v - avg);
  const tone = known !== 'neutral' || d.source === 'builtin' ? known : dir === 0 ? 'neutral' : (v - avg) * dir > 0 ? 'good' : 'bad';
  if (tone === 'good') return 'good';
  if (tone === 'bad') return gap >= TONE_FAR ? 'bad' : 'warn';
  return 'neutral';
}

/**
 * How sure a day split is, as one to three dots: one while either side has
 * fewer than two weeks of days, three once both have a month. The day counts
 * are the tooltip and the name screen readers hear.
 */
export function SureDots({ r }: { r: CompareResult }) {
  const { t } = useTranslation('stats');
  const thin = Math.min(r.a.n, r.b.n);
  const level = thin >= SURE_THREE ? 3 : thin >= SURE_TWO ? 2 : 1;
  const label = t(level === 1 ? 'home.sureEarly' : 'home.sureDays', { a: r.a.n, b: r.b.n });
  return (
    <span role="img" aria-label={label} title={label} className="inline-flex shrink-0 items-center gap-0.5">
      {[1, 2, 3].map((i) => <span key={i} className={`w-1.5 h-1.5 rounded-full ${i <= level ? 'bg-pn-soft' : 'bg-divider'}`} />)}
    </span>
  );
}

/**
 * One row of a lifts or drags list: the glyph, a short name with how sure it
 * is, the days behind it, a bar that grows left or right from the middle, and
 * the signed difference. The whole row opens the tracker.
 */
export function EffectBarRow({ d, label, sub, delta, sure, share, text, tone, onOpen }: {
  d: TrackerDescriptor;
  label: ReactNode;
  sub: string;
  delta: number;
  /** How sure the split is: the dots of `SureDots`. */
  sure: ReactNode;
  /** How much of a half-bar the difference fills, 0 to 1. */
  share: number;
  /** The difference as written, in the outcome's own unit. */
  text?: string;
  /** Good or bad by the outcome's better direction; by the sign when absent. */
  tone?: 'good' | 'bad' | 'neutral';
  onOpen?: () => void;
}) {
  const up = delta > 0;
  const mood = tone ?? (up ? 'good' : 'bad');
  const bar = mood === 'good' ? 'bg-success' : mood === 'bad' ? 'bg-danger' : 'bg-pn-muted';
  const width = Math.min(50, Math.max(0, share) * 50);
  const signed = text ?? `${up ? '+' : '-'}${formatNumber(Math.abs(delta), 1)}`;
  const body = (
    <>
      <TrackerTile d={d} />
      <span className="flex-1 min-w-0">
        <span className="flex items-center gap-1.5 min-w-0">
          <span className="truncate text-sm text-pn">{label}</span>
          {sure}
        </span>
        <span className="block truncate text-[11px] text-pn-muted">{sub}</span>
      </span>
      <span aria-hidden="true" className="relative hidden @md:block w-24 h-2 shrink-0 rounded bg-surface-0">
        <span className="absolute inset-y-[-3px] start-1/2 w-px bg-divider" />
        <span className={`absolute inset-y-0 rounded ${up ? 'start-1/2' : 'end-1/2'} ${bar}`} style={{ width: `${width}%` }} />
      </span>
      <span className={`min-w-10 shrink-0 text-end text-sm font-semibold tabular-nums ${TONE_TEXT[mood]}`}>{signed}</span>
      {onOpen && <CaretRight size={14} className="shrink-0 text-pn-muted" aria-hidden="true" />}
    </>
  );
  return onOpen
    ? <button type="button" onClick={onOpen} className="w-full flex items-center gap-3 py-2.5 text-start min-w-0">{body}</button>
    : <div className="w-full flex items-center gap-3 py-2.5 min-w-0">{body}</div>;
}

/** Monday first, in the week order of the page's weekday chart. */
const WEEK_ORDER = [1, 2, 3, 4, 5, 6, 0];

/** The average of a numeric series per weekday, Monday first; null for a weekday with no value. */
export function weekdayAverages(series: DaySeries): (number | null)[] {
  const sum = new Array(7).fill(0);
  const n = new Array(7).fill(0);
  for (const p of series.points) {
    if (typeof p.value !== 'number') continue;
    const wd = new Date(`${p.date}T12:00:00`).getDay();
    sum[wd] += p.value;
    n[wd] += 1;
  }
  return WEEK_ORDER.map((wd) => (n[wd] ? sum[wd] / n[wd] : null));
}

/** A fixed Monday, so a weekday's short name comes from the locale. */
const weekdayDate = (i: number) => new Date(2024, 0, 1 + i, 12);

/** Seven bars, the highest one marked; `color` paints them all, or each takes its mood band. */
export function WeekdayChart({ values, color, format }: { values: (number | null)[]; color?: string; format: (v: number) => string }) {
  const known = values.filter((v): v is number => v !== null);
  const best = known.length ? Math.max(...known) : null;
  const low = known.length ? Math.min(...known) : 0;
  // From the lowest weekday to the highest, so a few tenths of difference still show.
  const height = (v: number) => (best === null || best === low ? 60 : 20 + ((v - low) / (best - low)) * 50);
  return (
    <div className="grid grid-cols-7 gap-1.5 items-end h-24">
      {values.map((v, i) => (
        <div key={i} className={`flex h-full flex-col items-center justify-end gap-1 text-[11px] ${v !== null && v === best ? 'font-semibold text-pn' : 'text-pn-muted'}`}>
          {v !== null && <span className="tabular-nums">{format(v)}</span>}
          <span
            className="block w-full rounded-t-md rounded-b-sm"
            style={{ height: v === null ? 3 : `${height(v)}%`, backgroundColor: v === null ? 'var(--pn-border, #d1d5db)' : color ?? MOOD_COLORS[Math.min(4, Math.max(0, Math.ceil(v / 2) - 1))], opacity: v === best ? 1 : 0.75 }}
          />
          <span>{weekdayLabel(weekdayDate(i), 'narrow')}</span>
        </div>
      ))}
    </div>
  );
}

/** The mood bands as one stacked bar with a count per band. */
export function MoodMix({ series }: { series: DaySeries }) {
  const { t } = useTranslation('stats');
  const counts = [0, 0, 0, 0, 0];
  for (const p of series.points) if (typeof p.value === 'number') counts[Math.min(4, Math.max(0, Math.ceil(p.value / 2) - 1))]! += 1;
  const total = counts.reduce((a, b) => a + b, 0);
  if (total === 0) return null;
  const anchors = ['1', '3', '5', '7', '10'] as const;
  return (
    <div>
      <div className="flex h-2.5 overflow-hidden rounded-full">
        {counts.map((c, i) => c > 0 && <span key={i} style={{ width: `${(c / total) * 100}%`, backgroundColor: MOOD_COLORS[i] }} />)}
      </div>
      <div className="mt-1.5 flex flex-wrap gap-x-3 gap-y-1 text-[11px] text-pn-muted">
        {counts.map((c, i) => (
          <span key={i} className="inline-flex items-center gap-1">
            <span className="w-2 h-2 rounded-sm" style={{ backgroundColor: MOOD_COLORS[i] }} />
            {t(`trackers:mood.anchor.${anchors[i]}`)} {c}
          </span>
        ))}
      </div>
    </div>
  );
}

/** A value of one day in words, by the tracker's kind. */
function formatPoint(d: TrackerDescriptor, v: TrackerValue | undefined, t: TFunction): string {
  if (typeof v === 'boolean') return v ? t('trackers:custom.yes') : t('trackers:custom.no');
  if (typeof v === 'number') return d.kind === 'scale' && d.max ? `${formatNumber(v, 1)}/${d.max}` : formatValue(d, v, t);
  if (typeof v === 'string') return d.kind === 'medication' ? t(`stats:wellness.medCalendar.${v}`, { defaultValue: v }) : levelLabel(d, v, t);
  if (Array.isArray(v)) return v.map((k) => levelLabel(d, String(k), t)).join(', ');
  return '';
}

function shiftDay(day: string, by: number): string {
  const d = new Date(`${day}T12:00:00`);
  d.setDate(d.getDate() + by);
  return toLocalIso(d);
}

/** The days of the month that holds `day`, as ISO dates. */
function monthDays(day: string): string[] {
  const first = `${day.slice(0, 8)}01`;
  const out: string[] = [];
  for (let d = first; d.slice(0, 7) === first.slice(0, 7); d = shiftDay(d, 1)) out.push(d);
  return out;
}

/** One grid of days, Monday first: the date and the day's mood square; a tap picks the day. */
function DayGrid({ title, days, mood, from, to, picked, onPick }: {
  title: string;
  days: string[];
  mood: Map<string, number>;
  from: string;
  to: string;
  picked: string | null;
  onPick: (day: string) => void;
}) {
  const lead = (new Date(`${days[0]}T12:00:00`).getDay() + 6) % 7;
  return (
    <div className="min-w-0">
      <p className="text-sm font-semibold text-pn mb-1.5">{title}</p>
      <div className="grid grid-cols-7 gap-1 text-center">
        {Array.from({ length: 7 }, (_, i) => <span key={`h${i}`} className="text-[11px] text-pn-muted">{weekdayLabel(weekdayDate(i), 'narrow')}</span>)}
        {Array.from({ length: lead }, (_, i) => <span key={`p${i}`} />)}
        {days.map((day) => {
          const inRange = day >= from && day <= to;
          const m = mood.get(day);
          const label = Number(day.slice(8));
          if (!inRange) return <span key={day} className="py-1 text-[11px] text-pn-muted/60">{label}</span>;
          return (
            <button
              key={day}
              type="button"
              onClick={() => onPick(day)}
              aria-pressed={picked === day}
              aria-label={formatDay(day, 'date')}
              className={`flex flex-col items-center gap-0.5 rounded-md border py-1 ${picked === day ? 'border-accent ring-1 ring-accent' : 'border-divider hover:border-pn-muted'}`}
            >
              <span className="text-[11px] text-pn-soft">{label}</span>
              {m !== undefined ? <MoodMark mood={m} size={20} /> : <span className="w-5 h-5 rounded-md border border-dashed border-divider" />}
            </button>
          );
        })}
      </div>
    </div>
  );
}

/**
 * The days of the range in the mood colors: the last two months side by side
 * where the pane is wide, the last thirty days on a phone. A tap shows that
 * day's values as pills below, without leaving Statistics.
 */
export function DayCalendar({ model, onOpenDay }: { model: WellnessModel; onOpenDay?: (date: string) => void }) {
  const { t } = useTranslation('stats');
  const moodD = model.byId('mood');
  const mood = useMemo(() => {
    const out = new Map<string, number>();
    if (moodD) for (const p of model.seriesOf(moodD).points) if (typeof p.value === 'number') out.set(p.date, p.value);
    return out;
  }, [model, moodD]);
  const to = model.range.to;
  const [picked, setPicked] = useState<string | null>(null);
  const thisMonth = monthDays(to);
  const lastMonth = monthDays(shiftDay(thisMonth[0]!, -1));
  const last30 = Array.from({ length: 30 }, (_, i) => shiftDay(to, i - 29));
  const monthTitle = (day: string) => formatDay(day, 'monthYear');
  const grid = { mood, from: model.range.from, to, picked, onPick: (d: string) => setPicked((p) => (p === d ? null : d)) };

  // Directions learned once per range, for the trackers that have no known one.
  const dirs = useMemo(() => new Map(model.registry
    .filter((d) => d.source === 'custom' || d.kind === 'yesno')
    .map((d) => [d.id, learnedDirection(model, d)] as const)), [model]);
  const pills = useMemo(() => {
    if (!picked) return [];
    return model.registry
      .filter((d) => hasData(model.seriesOf(d)))
      .map((d) => ({ d, v: model.seriesOf(d).points.find((p) => p.date === picked)?.value }))
      .filter(({ v }) => v !== undefined && !(Array.isArray(v) && v.length === 0));
  }, [model, picked]);

  return (
    <div className="@container">
      <div className="hidden @xl:grid grid-cols-2 gap-5">
        <DayGrid title={monthTitle(lastMonth[0]!)} days={lastMonth} {...grid} />
        <DayGrid title={monthTitle(thisMonth[0]!)} days={thisMonth} {...grid} />
      </div>
      <div className="@xl:hidden">
        <DayGrid title={t('home.last30')} days={last30} {...grid} />
      </div>
      {picked && (
        <div className="mt-3 border-t border-divider pt-3">
          <div className="flex items-center justify-between gap-2 mb-2">
            <p className="text-sm font-semibold text-pn">{formatDay(picked, 'date')}</p>
            {onOpenDay && <Button action="open" onClick={() => onOpenDay(picked)}>{t('home.openEntry')}</Button>}
          </div>
          {pills.length === 0 ? (
            <p className="text-xs text-pn-muted">{t('home.nothingThatDay')}</p>
          ) : (
            <div className="flex flex-wrap gap-1.5">
              {pills.map(({ d, v }) => (
                d.id === 'mood' && typeof v === 'number'
                  ? <TrackerPill key={d.id} d={d} tint={moodColor(v)} icon={<MoodMark mood={v} size={16} />}>{trackerName(d, t)}: {moodWordOf(v)}</TrackerPill>
                  : <TrackerPill key={d.id} d={d} tone={dayTone(d, v, model.seriesOf(d), dirs.get(d.id) ?? 0)}>{trackerName(d, t)}: {formatPoint(d, v, t)}</TrackerPill>
              ))}
            </div>
          )}
        </div>
      )}
    </div>
  );
}

/** The spread of a numeric outcome: its declared range, or the spread of its logged values. */
export function spreadOf(d: TrackerDescriptor, series: DaySeries): number {
  if (d.min !== undefined && d.max !== undefined && d.max > d.min) return d.max - d.min;
  const nums = series.points.map((p) => p.value).filter((v): v is number => typeof v === 'number');
  if (nums.length === 0) return 1;
  return Math.max(Math.max(...nums) - Math.min(...nums), 1e-9);
}

/** A difference written in a tracker's own unit, with its sign: "+1.8", "+1,740 steps". */
export function signedValue(d: TrackerDescriptor, delta: number, t: TFunction): string {
  const digits = d.unit === 'steps' || d.unit === 'bpm' ? 0 : 1;
  const abs = Math.round(Math.abs(delta) * 10 ** digits) / 10 ** digits;
  const value = d.unit ? formatValue(d, abs, t, digits) : formatNumber(abs, digits);
  return `${delta >= 0 ? '+' : '-'}${value}`;
}
