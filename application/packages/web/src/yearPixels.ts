import type { DaySeries, RangeBounds } from './wellnessTypes';

/**
 * The year in pixels: twelve columns of thirty-one cells, one per calendar
 * day of one year, read from the mood series of that year. A cell past the
 * end of its month is null and stays blank; a day with no mood carries
 * `mood: undefined` and draws as an empty square.
 * Spec: ops/docs/archive/wellness-statistics.md (section 8)
 */

export interface PixelDay {
  date: string;
  mood: number | undefined;
}

export const PIXEL_ROWS = 31;

export function yearRange(year: number): RangeBounds {
  return { from: `${year}-01-01`, to: `${year}-12-31` };
}

function daysInMonth(year: number, month: number): number {
  return new Date(year, month, 0).getDate();
}

/** Column `m - 1` is month `m`; the series must cover the year's range. */
export function yearPixelGrid(series: DaySeries, year: number): (PixelDay | null)[][] {
  const moods = new Map<string, number>();
  for (const p of series.points) {
    if (typeof p.value === 'number') moods.set(p.date, p.value);
  }
  const columns: (PixelDay | null)[][] = [];
  for (let month = 1; month <= 12; month++) {
    const last = daysInMonth(year, month);
    const column: (PixelDay | null)[] = [];
    for (let day = 1; day <= PIXEL_ROWS; day++) {
      if (day > last) {
        column.push(null);
        continue;
      }
      const date = `${year}-${String(month).padStart(2, '0')}-${String(day).padStart(2, '0')}`;
      column.push({ date, mood: moods.get(date) });
    }
    columns.push(column);
  }
  return columns;
}

/** The years the switcher offers: from the first logged day to today, oldest first. */
export function pixelYears(firstDay: string | null, today: string): number[] {
  const last = Number(today.slice(0, 4));
  const first = firstDay ? Math.min(Number(firstDay.slice(0, 4)), last) : last;
  const years: number[] = [];
  for (let y = first; y <= last; y++) years.push(y);
  return years;
}
