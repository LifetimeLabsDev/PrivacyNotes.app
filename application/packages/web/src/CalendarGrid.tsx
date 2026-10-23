import { useEffect, useLayoutEffect, useRef, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { formatInstant, toLocalIso, weekdayLabel } from './intlFormat';
import { dayAtNoon } from './MonthGrid';
import { timedBlocks, type TimedBlock } from './calendarLayout';
import type { DayEntry, DayIndex } from './notesViewUtils';
import { shiftDay, timeFromMinutes } from './schedule';

/**
 * The hour layout of the Day and Week views: a day header row, the all-day
 * band (the host's chips and bars, the month cell's content), then the hours
 * from 00:00 to 24:00, opened at the first shown hour. A timed item is a card
 * at its hour with its length; overlapping cards sit side by side; an
 * overnight item draws in two parts; the red line is now. A drag on empty
 * hours, or a click, asks the host to create at that time. Layout only: the
 * data, the chips and the cards come from the host.
 * Spec: ops/docs/archive/calendar-pillar-spec.md (step 5)
 */

/** One hour, in pixels. */
const HOUR_PX = 48;
/** A drag snaps to this many minutes. */
const SNAP = 15;

type Props = {
  days: readonly string[];
  index: DayIndex;
  hidden: (e: DayEntry) => boolean;
  /** The hour the grid opens scrolled to (Settings › Date & Time › Calendar). */
  firstHour: number;
  /** A kept scroll position, so Back returns to it. */
  scrollRef: { current: number | null };
  renderAllDay: (day: string) => ReactNode;
  renderBars: (days: readonly string[]) => ReactNode;
  /** The band's height in lanes of bars, so the chips start under them. */
  renderCard: (block: TimedBlock, day: string) => ReactNode;
  onCreate: (day: string, start: string, end: string) => void;
  onPickDay: (day: string) => void;
  /** A card dropped on an hour: the item's id and the drop's day and time. */
  onDropAt?: (e: React.DragEvent, day: string, time: string) => void;
  accepts?: (e: React.DragEvent) => boolean;
};

export function CalendarGrid({ days, index, hidden, firstHour, scrollRef, renderAllDay, renderBars, renderCard, onCreate, onPickDay, onDropAt, accepts }: Props) {
  const { t } = useTranslation('shell');
  const scroller = useRef<HTMLDivElement | null>(null);
  const today = toLocalIso(new Date());
  const [now, setNow] = useState(() => new Date());
  const [draft, setDraft] = useState<{ day: string; from: number; to: number } | null>(null);
  const [dropAt, setDropAt] = useState<{ day: string; minutes: number } | null>(null);

  useLayoutEffect(() => {
    const el = scroller.current;
    if (!el) return;
    // A little above the first hour, so its label shows whole.
    el.scrollTop = scrollRef.current ?? Math.max(0, firstHour * HOUR_PX - 12);
    // The grid opens at the first shown hour; Back restores where it was.
  }, [firstHour, scrollRef]);

  useEffect(() => {
    const id = window.setInterval(() => setNow(new Date()), 60_000);
    return () => window.clearInterval(id);
  }, []);

  // Inline, because a class built at runtime never reaches the stylesheet.
  const cols = { gridTemplateColumns: `4rem repeat(${days.length}, minmax(0, 1fr))` };
  const minutesAt = (e: { clientY: number }, col: HTMLElement) => {
    const rect = col.getBoundingClientRect();
    const raw = ((e.clientY - rect.top) / HOUR_PX) * 60;
    return Math.max(0, Math.min(1440 - SNAP, Math.floor(raw / SNAP) * SNAP));
  };

  function onPointerDown(e: React.PointerEvent<HTMLDivElement>, day: string) {
    if (e.button !== 0 || e.target !== e.currentTarget) return;
    const col = e.currentTarget;
    const from = minutesAt(e, col);
    setDraft({ day, from, to: from + 60 });
    let moved = false;
    const move = (ev: PointerEvent) => {
      const at = minutesAt(ev, col) + SNAP;
      moved = true;
      setDraft({ day, from: Math.min(from, at - SNAP), to: Math.max(from + SNAP, at) });
    };
    const up = (ev: PointerEvent) => {
      window.removeEventListener('pointermove', move);
      window.removeEventListener('pointerup', up);
      const at = minutesAt(ev, col) + SNAP;
      const start = moved ? Math.min(from, at - SNAP) : from;
      const end = moved ? Math.max(from + SNAP, at) : from + 60;
      setDraft(null);
      onCreate(day, timeFromMinutes(start), timeFromMinutes(Math.min(end, 1439)));
    };
    window.addEventListener('pointermove', move);
    window.addEventListener('pointerup', up);
  }

  return (
    <div className="flex-1 min-h-0 flex flex-col select-none">
      {/* The three rows reserve the same scrollbar gutter, or the hour grid's
          scrollbar narrows its columns and they drift from the day headers. */}
      <div className="shrink-0 grid border-b border-divider overflow-y-hidden [scrollbar-gutter:stable]" style={cols}>
        <div />
        {days.map((day) => (
          <button
            key={day}
            type="button"
            onClick={() => onPickDay(day)}
            data-day={day}
            aria-label={formatInstant(dayAtNoon(day), 'date')}
            aria-current={day === today ? 'date' : undefined}
            className="flex flex-col items-center py-1 text-pn-muted hover:bg-pn/5 transition"
          >
            <span className="text-[11px]">{weekdayLabel(dayAtNoon(day), 'short')}</span>
            <span className={`text-[15px] font-semibold tabular-nums rounded-md px-1.5 ${day === today ? 'bg-accent-fill text-white' : 'text-pn'}`}>
              {dayAtNoon(day).getDate()}
            </span>
          </button>
        ))}
      </div>
      <div className="shrink-0 relative grid border-b border-divider max-h-[30%] overflow-y-auto [scrollbar-gutter:stable]" style={cols}>
        <div className="text-[10px] text-pn-muted text-end pe-1.5 pt-1.5">{t('calendar.allDay')}</div>
        {days.map((day) => (
          <div key={day} className={`relative min-w-0 min-h-9 p-1 flex flex-col gap-px border-s border-divider ${day === today ? 'bg-accent/5' : ''}`}>
            {renderAllDay(day)}
          </div>
        ))}
        {renderBars(days)}
      </div>
      <div ref={scroller} onScroll={(e) => { scrollRef.current = e.currentTarget.scrollTop; }} className="flex-1 min-h-0 overflow-y-auto overscroll-contain [scrollbar-gutter:stable]">
        <div className="relative grid" style={{ ...cols, height: 24 * HOUR_PX }}>
          <div className="relative">
            {Array.from({ length: 23 }, (_, i) => (
              <span key={i} className="absolute end-1.5 -translate-y-1/2 whitespace-nowrap text-[10px] text-pn-muted tabular-nums" style={{ top: (i + 1) * HOUR_PX }}>
                {formatInstant(new Date(2026, 0, 1, i + 1, 0), 'time')}
              </span>
            ))}
          </div>
          {days.map((day) => {
            const blocks = timedBlocks(day, shiftDay(day, -1), index, hidden);
            const nowTop = day === today ? ((now.getHours() * 60 + now.getMinutes()) / 60) * HOUR_PX : null;
            return (
              <div
                key={day}
                data-hours={day}
                onPointerDown={(e) => onPointerDown(e, day)}
                onDragEnter={onDropAt ? (e) => { if (accepts?.(e)) { e.preventDefault(); setDropAt({ day, minutes: minutesAt(e, e.currentTarget) }); } } : undefined}
                onDragOver={onDropAt ? (e) => { if (accepts?.(e)) { e.preventDefault(); e.dataTransfer.dropEffect = 'copy'; setDropAt({ day, minutes: minutesAt(e, e.currentTarget) }); } } : undefined}
                onDragLeave={onDropAt ? (e) => { if (!e.currentTarget.contains(e.relatedTarget as Node | null)) setDropAt(null); } : undefined}
                onDrop={onDropAt ? (e) => { if (accepts?.(e)) { e.preventDefault(); setDropAt(null); onDropAt(e, day, timeFromMinutes(minutesAt(e, e.currentTarget))); } } : undefined}
                className={`relative border-s border-divider cursor-cell ${day === today ? 'bg-accent/5' : ''}`}
                style={{ backgroundImage: `repeating-linear-gradient(to bottom, transparent 0, transparent ${HOUR_PX - 1}px, var(--color-divider) ${HOUR_PX - 1}px, var(--color-divider) ${HOUR_PX}px)` }}
              >
                {blocks.map((b) => (
                  <div
                    key={`${b.entry.id}|${b.entry.occurrence ?? ''}|${b.carried ? 'c' : ''}`}
                    className="absolute px-px"
                    style={{
                      top: (b.start / 60) * HOUR_PX,
                      height: Math.max(18, ((b.end - b.start) / 60) * HOUR_PX - 1),
                      insetInlineStart: `${(b.col / b.cols) * 100}%`,
                      width: `${100 / b.cols}%`,
                    }}
                  >
                    {renderCard(b, day)}
                  </div>
                ))}
                {draft?.day === day && (
                  <div
                    aria-hidden="true"
                    className="absolute inset-x-1 rounded-md bg-accent/20 ring-1 ring-accent pointer-events-none text-[11px] text-accent-strong px-1.5 py-0.5 tabular-nums"
                    style={{ top: (draft.from / 60) * HOUR_PX, height: ((draft.to - draft.from) / 60) * HOUR_PX }}
                  >
                    {formatInstant(new Date(2026, 0, 1, Math.floor(draft.from / 60), draft.from % 60), 'time')}
                  </div>
                )}
                {dropAt?.day === day && (
                  <div aria-hidden="true" className="absolute inset-x-0 h-0.5 bg-accent pointer-events-none" style={{ top: (dropAt.minutes / 60) * HOUR_PX }} />
                )}
                {nowTop !== null && (
                  <div aria-label={t('calendar.now')} className="absolute inset-x-0 h-0.5 bg-danger pointer-events-none z-10" style={{ top: nowTop }}>
                    <span className="absolute -start-1 -top-[3px] w-2 h-2 rounded-full bg-danger" />
                  </div>
                )}
              </div>
            );
          })}
        </div>
      </div>
    </div>
  );
}
