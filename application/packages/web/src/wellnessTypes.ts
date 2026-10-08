import type { JournalTrackerData } from './trackerTypes';

/**
 * The contract between the wellness statistics modules: the registry that
 * describes every tracker, the series on a calendar axis, the comparison of
 * one tracker against an outcome, and the chart geometry. Each module owns
 * its functions; the shapes they exchange live here so none of them imports
 * another for a type.
 * Spec: ops/docs/plans/wellness-statistics.md (sections 4 to 7)
 */

export type TrackerKind = 'scale' | 'measure' | 'yesno' | 'ordinal' | 'set' | 'medication';
type TrackerSource = 'builtin' | 'custom' | 'medication';
type TrackerUnit = 'h' | 'bpm' | 'kg' | 'lb' | 'steps' | 'glasses' | 'cups';
/** A logged value: a number, a yes or no, a level id, a medication status, or a tag set. */
export type TrackerValue = number | boolean | string | readonly string[];

export interface TrackerDescriptor {
  /** The built-in id, the custom template id, or the medication template id. */
  id: string;
  source: TrackerSource;
  /** `trackers:labels.<id>` for a built-in; the split sleep descriptors carry their own keys. */
  labelKey?: string;
  /** User text: the custom template's name or the medication's name. */
  name?: string;
  color: string;
  kind: TrackerKind;
  /** The declared range of a scale. */
  min?: number;
  max?: number;
  unit?: TrackerUnit;
  /** An ordinal's level ids low to high, or a set's tag keys. */
  levels?: readonly string[];
  /** What the card headline shows. */
  aggregate: 'avg' | 'share' | 'sum';
  read: (d: JournalTrackerData) => TrackerValue | undefined;
  stoppedAt?: string;
  deletedAt?: string;
  /** A value whose template is missing from the settings: listed, never compared. */
  unknown?: boolean;
}

export type RangeId = '7d' | '14d' | '30d' | '3mo' | '6mo' | '12mo' | 'all';
/** Local ISO days, both inclusive. */
export interface RangeBounds { from: string; to: string }

export interface DayPoint { date: string; value: TrackerValue | undefined }
/** One point per calendar day from `from` to `to`; a missing day carries `undefined`. */
export interface DaySeries { from: string; to: string; points: DayPoint[] }

export type CompareRuleKind = 'yesno' | 'halves' | 'median' | 'levels' | 'tag' | 'medication';
export interface CompareResult {
  trackerId: string;
  /** Set kind only: the tag this row is about. */
  tag?: string;
  outcomeId: string;
  range: RangeBounds;
  /** 0 pairs the same day, 1 pairs the tracker with the outcome of the next calendar day. */
  lag: 0 | 1;
  rule: { kind: CompareRuleKind; threshold?: number };
  /** With, high, top levels, or taken. */
  a: { n: number; mean: number | null };
  /** Without, low, bottom levels, or missed. */
  b: { n: number; mean: number | null };
  /** a.mean minus b.mean, full precision; null below the minimum. */
  delta: number | null;
  /** Pairs left out: a middle level, an unmarked dose, a missing outcome. */
  excluded: number;
  /** Set when a side is under the minimum; the row shows the days still missing. */
  shortfall?: { side: 'a' | 'b'; days: number };
}

/** `strip` is one row of day cells across the full width, on the same axis as a bar or line chart. */
type ChartForm = 'bars' | 'line' | 'dots' | 'calendar' | 'strip';
export interface ChartSpec {
  form: ChartForm;
  series: DaySeries;
  color: string;
  /** The y range of bars and lines; omitted means from the observed values. */
  min?: number;
  max?: number;
  /** Mood only: the color of a bar from its value. */
  ramp?: (value: number) => string;
  /** The ordinal's levels, for the tooltip and the level index of a bar. */
  levels?: readonly string[];
  /** One mark per week instead of per day, for the long ranges. */
  weekly?: boolean;
}
