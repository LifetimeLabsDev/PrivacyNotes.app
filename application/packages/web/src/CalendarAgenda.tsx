import { Fragment, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowLineDown } from './icons';
import { MonthGrid, addDays, dayAtNoon } from './MonthGrid';
import { CalendarItemRow } from './JournalCalendar';
import { formatInstant, relativeDayName, toLocalIso } from './intlFormat';
import { intlLocale } from './languages';
import { textMatcher } from './textMatch';
import { setItemDragImage, writeItemDrag, type ItemDragPayload } from './itemDrag';
import type { DayEntry, DayIndex } from './notesViewUtils';
import { dayNumber } from './schedule';
import { ReminderPermissionHint } from './notesView/useReminders';

/**
 * The Calendar pillar's list pane: the agenda. The coming days with their
 * items, all-day first and then by time, under a sticky header per day. It
 * starts a week back and reaches two months ahead, and grows as it scrolls.
 * Days with nothing fold into one thin line. A Today pill floats in while
 * today is out of view. On a phone a week strip with dots heads it, pulled
 * down to a month by its grab bar or its title, and a tap on a day scrolls
 * the agenda there.
 * Spec: ops/docs/plans/calendar-pillar-spec.md (step 3)
 */

const BACK_DAYS = 7;
const AHEAD_DAYS = 60;
const SEARCH_DAYS = 366;
/** How far the grab bar travels before the strip opens or folds. */
const PULL_PX = 40;

type Props = {
  index: DayIndex;
  onOpen: (id: string, occurrence?: string) => void;
  search: string;
  /** The week strip above the agenda, on a phone. */
  strip: boolean;
  /** What a row drags: its id and its note-link, for a drop on a day of a
   *  calendar, a folder or an editor. */
  dragPayload?: (id: string) => ItemDragPayload;
  /** A row's right-click menu: the item menu, at the occurrence. */
  onItemMenu?: (e: React.MouseEvent, entry: DayEntry) => void;
};

/** A day's items in time order. The index puts the open space first, which a
 *  month cell needs when it runs out of room; a list of times reads by time,
 *  whatever the space. The sort is stable, so equal times keep that order. */
function byTime(entries: readonly DayEntry[]): readonly DayEntry[] {
  return [...entries].sort((a, b) =>
    (a.span ? 0 : 1) - (b.span ? 0 : 1)
    || (a.time ? 1 : 0) - (b.time ? 1 : 0)
    || (a.time ?? '').localeCompare(b.time ?? ''));
}

/** A header's two parts: "Today", "Tomorrow" or "Yesterday" where one fits, and the date. */
function dayHeader(day: string, today: string): { word: string | null; date: string } {
  const loc = intlLocale();
  const offset = dayNumber(day) - dayNumber(today);
  const date = formatInstant(dayAtNoon(day), 'weekdayDate');
  if (offset === 0 || offset === 1 || offset === -1) {
    const word = relativeDayName(offset as -1 | 0 | 1);
    return { word: `${word.charAt(0).toLocaleUpperCase(loc)}${word.slice(1)}`, date };
  }
  return { word: null, date };
}

export default function CalendarAgenda({ index, onOpen, search, strip, dragPayload, onItemMenu }: Props) {
  const { t } = useTranslation('shell');
  const today = toLocalIso(new Date());
  const [ahead, setAhead] = useState(AHEAD_DAYS);
  const [weeks, setWeeks] = useState<1 | 6>(1);
  const [stripDay, setStripDay] = useState(today);
  const [todayOut, setTodayOut] = useState<'above' | 'below' | null>(null);
  const scroller = useRef<HTMLDivElement | null>(null);
  const pending = useRef<string | null>(today);
  const query = search.trim();

  const days = useMemo(() => {
    const back = query ? SEARCH_DAYS : BACK_DAYS;
    const forward = query ? SEARCH_DAYS : ahead;
    const match = query ? textMatcher(query) : null;
    const out: { day: string; entries: readonly DayEntry[] }[] = [];
    for (let i = -back; i <= forward; i++) {
      const day = addDays(today, i);
      let entries = index.has(day) ? byTime(index.entriesOf(day)) : [];
      if (match) entries = entries.filter((e) => match(e.title));
      // Today always has its header, so the agenda has an anchor.
      if (entries.length || (day === today && !query)) out.push({ day, entries });
    }
    return out;
  }, [index, today, ahead, query]);

  // Scroll a day's header to the top: today on open, a picked strip day.
  useLayoutEffect(() => {
    const day = pending.current;
    if (!day) return;
    const el = scroller.current?.querySelector<HTMLElement>(`[data-agenda-day="${day}"]`)
      ?? [...(scroller.current?.querySelectorAll<HTMLElement>('[data-agenda-day]') ?? [])].find((h) => (h.dataset.agendaDay ?? '') >= day);
    if (el && scroller.current) {
      scroller.current.scrollTop = el.offsetTop;
      pending.current = null;
    }
  }, [days]);

  // The Today pill: shown while today's header is out of view.
  useEffect(() => {
    const root = scroller.current;
    const el = root?.querySelector(`[data-agenda-day="${today}"]`);
    if (!root || !el) {
      setTodayOut(null);
      return;
    }
    const io = new IntersectionObserver(([entry]) => {
      if (!entry) return;
      if (entry.isIntersecting) setTodayOut(null);
      else setTodayOut(entry.boundingClientRect.top < (entry.rootBounds?.top ?? 0) ? 'above' : 'below');
    }, { root });
    io.observe(el);
    return () => io.disconnect();
  }, [days, today]);

  function goTo(day: string) {
    if (dayNumber(day) - dayNumber(today) > ahead) setAhead(dayNumber(day) - dayNumber(today) + 14);
    pending.current = day;
    const el = scroller.current?.querySelector<HTMLElement>(`[data-agenda-day="${day}"]`)
      ?? [...(scroller.current?.querySelectorAll<HTMLElement>('[data-agenda-day]') ?? [])].find((h) => (h.dataset.agendaDay ?? '') >= day);
    if (el && scroller.current) {
      scroller.current.scrollTo({ top: el.offsetTop, behavior: 'smooth' });
      pending.current = null;
    }
  }

  function onScroll(e: React.UIEvent<HTMLDivElement>) {
    const el = e.currentTarget;
    if (!query && el.scrollTop + el.clientHeight > el.scrollHeight - 400) setAhead((n) => Math.min(n + AHEAD_DAYS, 3 * SEARCH_DAYS));
  }

  /** The grab bar: a drag down past `PULL_PX` opens the month, up folds it. */
  function onGrab(e: React.PointerEvent) {
    const y0 = e.clientY;
    const target = e.currentTarget as HTMLElement;
    target.setPointerCapture(e.pointerId);
    const up = (ev: PointerEvent) => {
      target.removeEventListener('pointerup', up);
      const dy = ev.clientY - y0;
      if (dy > PULL_PX) setWeeks(6);
      else if (dy < -PULL_PX) setWeeks(1);
      else if (Math.abs(dy) < 4) setWeeks((w) => (w === 6 ? 1 : 6));
    };
    target.addEventListener('pointerup', up);
  }

  return (
    <div className="relative flex-1 min-h-0 flex flex-col">
      {strip && (
        <div className="shrink-0 px-4 pt-2 bg-surface-2 border-b border-divider">
          <MonthGrid
            marked={index}
            selected={stripDay}
            weeks={weeks}
            onToggleWeeks={() => setWeeks((w) => (w === 6 ? 1 : 6))}
            onPick={(day) => { setStripDay(day); goTo(day); }}
          />
          <div
            role="presentation"
            onPointerDown={onGrab}
            className="flex justify-center py-2 touch-none cursor-grab"
          >
            <span className="w-9 h-1 rounded-full bg-pn/20" />
          </div>
        </div>
      )}
      <ReminderPermissionHint />
      <div ref={scroller} onScroll={onScroll} className="@container/agenda relative flex-1 min-h-0 overflow-y-auto overscroll-contain pb-16">
        {days.length === 0 && <p className="p-4 text-[13px] text-pn-muted text-center">{t('notes:empty.noMatches')}</p>}
        <ul>
          {days.map(({ day, entries }, i) => {
            const prev = days[i - 1];
            const gap = prev ? dayNumber(day) - dayNumber(prev.day) - 1 : 0;
            const mixed = new Set(entries.map((e) => e.space)).size > 1;
            return (
              <Fragment key={day}>
                {gap > 1 && !query && (
                  <li aria-hidden="true" className="px-4 py-1.5 flex items-center gap-2 text-[11px] text-pn-muted/80">
                    <span className="h-px flex-1 bg-divider/60" />
                    {t('calendar.nothingFor', { count: gap })}
                    <span className="h-px flex-1 bg-divider/60" />
                  </li>
                )}
                <li data-agenda-day={day}>
                  {(() => {
                    // The relative word leads in the day's tone; the date
                    // follows in a quieter one, or leads itself.
                    const { word, date } = dayHeader(day, today);
                    const tone = day === today ? 'text-accent' : day < today ? 'text-pn-muted/70' : 'text-pn';
                    return (
                      <div className="sticky top-0 z-10 bg-surface-1/95 backdrop-blur-sm border-b border-divider/50 px-4 pt-2.5 pb-1.5 flex items-baseline gap-2 min-w-0">
                        {word && <span className={`text-[13px] font-semibold shrink-0 ${tone}`}>{word}</span>}
                        <span className={`text-[12.5px] truncate ${word ? 'text-pn-muted' : `font-semibold ${tone}`}`}>{date}</span>
                      </div>
                    );
                  })()}
                  {entries.length === 0 ? (
                    <p className="px-4 py-2.5 text-[12.5px] text-pn-muted">{t('calendar.nothingToday')}</p>
                  ) : (
                    <div className={`px-2 py-1.5 flex flex-col gap-0.5 ${day < today ? 'opacity-70' : ''}`}>
                      {entries.map((entry) => (
                        <CalendarItemRow
                          key={`${entry.id}|${entry.occurrence ?? ''}`}
                          entry={entry}
                          day={day}
                          mixed={mixed}
                          size="agenda"
                          onOpen={(e) => onOpen(e.id, e.occurrence ?? e.span?.start)}
                          onMenu={onItemMenu}
                          dragProps={entry.kind === 'contact' || !dragPayload ? undefined : {
                            draggable: true,
                            onDragStart: (e) => {
                              const p = dragPayload(entry.id);
                              writeItemDrag(e.dataTransfer, p.ids, p.linkText);
                              setItemDragImage(e.dataTransfer, e.currentTarget, 1);
                            },
                          }}
                        />
                      ))}
                    </div>
                  )}
                </li>
              </Fragment>
            );
          })}
        </ul>
      </div>
      {todayOut && (
        <button
          type="button"
          onClick={() => goTo(today)}
          className="absolute bottom-4 start-1/2 -translate-x-1/2 rtl:translate-x-1/2 z-20 inline-flex items-center gap-1.5 rounded-full bg-accent-fill text-white shadow-lg px-3 py-1.5 text-[13px] font-semibold"
        >
          <ArrowLineDown size={13} aria-hidden="true" className={todayOut === 'above' ? 'rotate-180' : ''} />
          {(() => { const w = relativeDayName(0); return `${w.charAt(0).toLocaleUpperCase(intlLocale())}${w.slice(1)}`; })()}
        </button>
      )}
    </div>
  );
}
