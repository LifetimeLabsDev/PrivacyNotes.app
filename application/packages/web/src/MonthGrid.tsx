import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CaretDown, CaretLeft, CaretRight } from './icons';
import { formatInstant, toLocalIso, weekdayDate, weekdayLabel } from './intlFormat';
import { intlLocale } from './languages';

/**
 * One month of days. It draws and reports a click, nothing else: the hosts
 * own the data and decide what a picked day does. It replaces the browser
 * date field, whose calendar is a separate window the page cannot place,
 * mark or connect to an entry.
 * Spec: ops/docs/plans/journal-calendar.md
 */

/** A local ISO day as a Date at noon, so a daylight-saving change never moves
 *  the day. Every calendar surface turns a day into a Date through here. */
export function dayAtNoon(day: string): Date {
  return new Date(`${day}T12:00:00`);
}

export function addDays(day: string, n: number): string {
  const d = dayAtNoon(day);
  d.setDate(d.getDate() + n);
  return toLocalIso(d);
}

/** The same day of the month `n` months away, clamped to the month's last day. */
export function addMonths(day: string, n: number): string {
  const d = dayAtNoon(day);
  const target = new Date(d.getFullYear(), d.getMonth() + n, 1, 12);
  const last = new Date(target.getFullYear(), target.getMonth() + 1, 0, 12).getDate();
  target.setDate(Math.min(d.getDate(), last));
  return toLocalIso(target);
}

/** The first day of the week for a locale, 0 = Sunday. Monday where the engine cannot say. */
export function firstWeekday(locale: string): number {
  try {
    const l = new Intl.Locale(locale) as Intl.Locale & {
      getWeekInfo?: () => { firstDay: number };
      weekInfo?: { firstDay: number };
    };
    const first = l.getWeekInfo?.().firstDay ?? l.weekInfo?.firstDay;
    if (first) return first % 7;
  } catch {
    // An unknown tag falls through to the default.
  }
  return 1;
}

/** Six weeks of days around the month of `day`, so every month has the same height. */
export function monthCells(day: string, weekStart: number): string[] {
  const d = dayAtNoon(day);
  const first = new Date(d.getFullYear(), d.getMonth(), 1, 12);
  const start = addDays(toLocalIso(first), -((first.getDay() - weekStart + 7) % 7));
  return Array.from({ length: 42 }, (_, i) => addDays(start, i));
}

/** The seven days of the week that holds `day`. */
export function weekCells(day: string, weekStart: number): string[] {
  const start = addDays(day, -((dayAtNoon(day).getDay() - weekStart + 7) % 7));
  return Array.from({ length: 7 }, (_, i) => addDays(start, i));
}

function sameMonth(a: string, b: string): boolean {
  return a.slice(0, 7) === b.slice(0, 7);
}

type Props = {
  /** The days that get a dot. */
  marked: { has(day: string): boolean };
  /** The day drawn with a ring. */
  selected?: string;
  /** A day in the month to show first. Today when absent. */
  initialMonth?: string;
  onPick: (day: string) => void;
  /** One week or the whole month (six weeks). The arrows step by the same unit. */
  weeks?: 1 | 6;
  /** When set, the month title is a button that switches between week and month. */
  onToggleWeeks?: () => void;
  /** When set, a Today row heads the grid and calls this. */
  onToday?: () => void;
};

export function MonthGrid({ marked, selected, initialMonth, onPick, weeks = 6, onToggleWeeks, onToday }: Props) {
  const { t } = useTranslation('shell');
  const today = toLocalIso(new Date());
  const [focus, setFocus] = useState(initialMonth ?? selected ?? today);
  const moved = useRef(false);
  const gridRef = useRef<HTMLDivElement | null>(null);
  const locale = intlLocale();
  const weekStart = firstWeekday(locale);
  const cells = weeks === 1 ? weekCells(focus, weekStart) : monthCells(focus, weekStart);
  const step = (n: number) => (weeks === 1 ? addDays(focus, 7 * n) : addMonths(focus, n));
  const title = new Intl.DateTimeFormat(locale, { month: 'long', year: 'numeric' }).format(dayAtNoon(focus)); // date-ok: a month heading carries no day, so no date-order setting applies

  // Focus follows the arrow keys only, so opening the grid never steals focus.
  useEffect(() => {
    if (!moved.current) return;
    moved.current = false;
    gridRef.current?.querySelector<HTMLButtonElement>(`[data-day="${focus}"]`)?.focus();
  }, [focus]);

  function onKeyDown(e: React.KeyboardEvent) {
    const rtl = getComputedStyle(e.currentTarget).direction === 'rtl';
    const weekPos = (dayAtNoon(focus).getDay() - weekStart + 7) % 7;
    const step: Record<string, () => string> = {
      ArrowLeft: () => addDays(focus, rtl ? 1 : -1),
      ArrowRight: () => addDays(focus, rtl ? -1 : 1),
      ArrowUp: () => addDays(focus, -7),
      ArrowDown: () => addDays(focus, 7),
      PageUp: () => addMonths(focus, -1),
      PageDown: () => addMonths(focus, 1),
      Home: () => addDays(focus, -weekPos),
      End: () => addDays(focus, 6 - weekPos),
    };
    const next = step[e.key];
    if (!next) return;
    // The menus around the grid move focus with these keys too; the grid keeps them.
    e.preventDefault();
    e.stopPropagation();
    moved.current = true;
    setFocus(next());
  }

  const navBtn = 'inline-flex items-center justify-center w-8 h-8 [@media(hover:none)]:w-10 [@media(hover:none)]:h-10 rounded-md text-accent hover:bg-pn/5 transition';
  // Every calendar in the app draws through here: the hosts give a container
  // and nothing else, so the width, the title, the Today row and the day
  // states stay one design in the list, the popovers and the entry menu.
  const titleClass = 'inline-flex items-center gap-1 rounded-md px-2 py-1 text-[13px] font-medium text-pn';
  return (
    <div className="w-full max-w-[240px] mx-auto select-none">
      {onToday && (
        <button
          type="button"
          onClick={onToday}
          className="mb-2 w-full flex items-baseline justify-between gap-3 px-3 py-2 rounded-lg text-start ring-[1.5px] ring-inset ring-accent hover:bg-accent/10 transition"
        >
          <span className="text-[14px] font-medium text-pn">{t('backfillPopover.today')}</span>
          <span className="text-[12px] tabular-nums font-semibold text-accent">{formatInstant(dayAtNoon(today), 'dayMonth')}</span>
        </button>
      )}
      {/* The month arrows sit together at the end, so they never read as the
          back arrow a menu puts at the start of the same row. */}
      <div className="flex items-center justify-between mb-1">
        {onToggleWeeks ? (
          <button
            type="button"
            onClick={onToggleWeeks}
            aria-expanded={weeks === 6}
            aria-label={t(weeks === 6 ? 'monthGrid.showWeek' : 'monthGrid.showMonth', { month: title })}
            className={`${titleClass} hover:bg-pn/5 transition`}
          >
            <span aria-live="polite">{title}</span>
            <CaretDown size={12} aria-hidden="true" className={`text-accent transition-transform ${weeks === 6 ? 'rotate-180' : ''}`} />
          </button>
        ) : (
          <span className={titleClass}>
            <span aria-live="polite">{title}</span>
          </span>
        )}
        <span className="flex items-center">
          <button type="button" onClick={() => setFocus(step(-1))} aria-label={t(weeks === 1 ? 'monthGrid.previousWeek' : 'monthGrid.previousMonth')} className={navBtn}>
            <CaretLeft size={14} aria-hidden="true" />
          </button>
          <button type="button" onClick={() => setFocus(step(1))} aria-label={t(weeks === 1 ? 'monthGrid.nextWeek' : 'monthGrid.nextMonth')} className={navBtn}>
            <CaretRight size={14} aria-hidden="true" />
          </button>
        </span>
      </div>
      <div ref={gridRef} role="group" aria-label={title} onKeyDown={onKeyDown} className="grid grid-cols-7 gap-0.5 text-center">
        {Array.from({ length: 7 }, (_, i) => (
          <div key={i} aria-hidden="true" className="text-[11px] text-pn-muted py-1">
            {weekdayLabel(weekdayDate((weekStart + i) % 7), 'narrow')}
          </div>
        ))}
        {cells.map((day) => {
          const inMonth = weeks === 1 || sameMonth(day, focus);
          const isToday = day === today;
          const hasEntry = marked.has(day);
          const label = formatInstant(dayAtNoon(day), 'date');
          const isSelected = day === selected;
          // Selected: a filled circle. Today: a ring. A dotted day keeps its
          // dot in both, white on the fill, so no state hides another.
          const circle = isSelected
            ? 'bg-accent-fill text-white font-semibold'
            : isToday
              ? 'ring-[1.5px] ring-inset ring-accent text-accent font-semibold group-hover:bg-accent/10'
              : `${inMonth ? 'text-pn' : 'text-pn-muted opacity-60'} group-hover:bg-pn/5`;
          return (
            <button
              key={day}
              type="button"
              data-day={day}
              tabIndex={day === focus ? 0 : -1}
              aria-label={hasEntry ? t('monthGrid.dayWithEntry', { date: label }) : label}
              aria-current={isToday ? 'date' : undefined}
              aria-pressed={selected !== undefined ? isSelected : undefined}
              onClick={() => onPick(day)}
              className="group flex items-center justify-center h-9 [@media(hover:none)]:h-10 outline-none"
            >
              <span
                className={`relative flex items-center justify-center w-8 h-8 rounded-full text-[13px] tabular-nums transition group-focus-visible:outline group-focus-visible:outline-2 group-focus-visible:outline-offset-1 group-focus-visible:outline-accent ${circle}`}
              >
                {dayAtNoon(day).getDate()}
                {hasEntry && (
                  <span
                    aria-hidden="true"
                    className={`absolute bottom-[3px] inset-x-0 mx-auto w-[5px] h-[5px] rounded-full ${isSelected ? 'bg-white' : 'bg-accent'}`}
                  />
                )}
              </span>
            </button>
          );
        })}
      </div>
    </div>
  );
}
