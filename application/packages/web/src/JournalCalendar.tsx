import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { ArrowsOutSimple, BellSimple, Calendar, Gift, Repeat } from './icons';
import { SPACE_ICONS } from './SpaceSwitch';
import { typeGlyph } from './NoteRow';
import { HoverLabel } from './HoverLabel';
import { useEscapeToClose } from './useEscapeToClose';
import { usePopoverPosition } from './usePopoverPosition';
import { formatInstant, toLocalIso } from './intlFormat';
import { MonthGrid, dayAtNoon, dayKindColor } from './MonthGrid';
import type { DayEntry, DayIndex } from './notesViewUtils';
import type { Space } from './spaces';
import { dayNumber } from './schedule';

/**
 * Everything the calendar of dated items does, in one module: the pick rule,
 * the two device settings, the popover (Journals New button, footer button)
 * and the card at the top of the Journals, Notes, Tasks and All lists. Every
 * host reads one index of journal entries, notes, task lists and birthdays;
 * what differs is what an empty day creates. How a
 * calendar looks lives in MonthGrid, and nothing here styles the grid itself.
 * The Entry date view of the entry menu is the one other host, because a pick
 * there moves an entry.
 *
 * Today has its own callback because it is not a backfill: the ordinary
 * new-entry path inherits the open folder, the active tag and the pinned
 * state of the list the user is standing in, and a dated entry deliberately
 * inherits none of that.
 * Spec: ops/docs/plans/journal-calendar.md, ops/docs/plans/note-date.md (section 4)
 */
type Props = {
  /** Every dated item, by day. */
  entries: DayIndex;
  /** Opens an existing item; a repeating one names the occurrence's day. */
  onOpen: (id: string, occurrence?: string) => void;
  /** Creates the host's type for an ISO day (yyyy-mm-dd). Never today's date. */
  onPick: (isoDate: string) => void;
  /** Creates the host's type for today. */
  onToday: () => void;
  /** Called when the user clicks outside or presses Escape. */
  onClose: () => void;
  /** The trigger button: the popover hangs off it and ignores clicks on it. */
  anchorRef: React.RefObject<HTMLElement | null>;
  /** Which edge of the trigger the popover lines up with. */
  align?: 'end' | 'center';
  /** Whether a Today row heads the grid. The New menu has one; the footer
   *  button does not, because today's cell already does the same. */
  todayRow?: boolean;
};

type DayHandlers = Pick<Props, 'entries' | 'onOpen' | 'onPick' | 'onToday'>;

/** One rule for every calendar: an empty today is the host's ordinary new
 *  item, any other empty day a dated one, a day with one item opens it, and
 *  a day with several opens nothing and answers 'choose', so the calendar
 *  can unfold them.
 *  Spec: ops/docs/plans/note-date.md (section 4), ops/docs/plans/spaces.md (section 9) */
export function pickCalendarDay(day: string, { entries, onOpen, onPick, onToday }: DayHandlers): 'done' | 'choose' {
  const found = entries.entriesOf(day);
  if (found.length > 1) return 'choose';
  if (found[0]) onOpen(found[0].id, found[0].occurrence);
  else if (day === toLocalIso(new Date())) onToday();
  else onPick(day);
  return 'done';
}


/** A time of day ("15:00") as the clock setting writes it. */
export function timeLabel(day: string, time: string): string {
  const d = dayAtNoon(day);
  d.setHours(Number(time.slice(0, 2)), Number(time.slice(3, 5)), 0, 0);
  return formatInstant(d, 'time');
}

/** What an item's row says about its time on a day: "day 2 of 3" for a
 *  multi-day item, its time or its time range, or nothing for an all-day one. */
function entryWhen(entry: DayEntry, day: string, t: (key: string, opts?: Record<string, unknown>) => string): string {
  if (entry.span) {
    return t('notes:noteRow.dayOf', {
      n: dayNumber(day) - dayNumber(entry.span.start) + 1,
      total: dayNumber(entry.span.end) - dayNumber(entry.span.start) + 1,
    });
  }
  if (!entry.time) return '';
  return entry.timeEnd ? `${timeLabel(day, entry.time)} - ${timeLabel(day, entry.timeEnd)}` : timeLabel(day, entry.time);
}

/**
 * One item of a day, the one row every calendar list draws: the unfolded day
 * under a grid, the "+N more" popover and the agenda. Its type's icon and
 * color (a birthday wears a gift, because the user icon names a space), the
 * stored title only, so an item behind a PIN shows nothing from inside it,
 * then its time, a bell for alerts, the repeat glyph, and on a day that mixes
 * the spaces its space's icon.
 * Spec: ops/docs/plans/note-date.md (section 4), ops/docs/plans/calendar-pillar-spec.md (section 5)
 */
export function CalendarItemRow({ entry, day, mixed, onOpen, onMenu, onKeyDown, rowRef, size = 'small', dragProps }: {
  entry: DayEntry;
  /** The item's right-click menu, as every list row has it. */
  onMenu?: (e: React.MouseEvent, entry: DayEntry) => void;
  /** The day the row stands on, for its time and "day 2 of 3". */
  day: string;
  mixed: boolean;
  onOpen: (entry: DayEntry) => void;
  onKeyDown?: (e: React.KeyboardEvent) => void;
  rowRef?: (el: HTMLButtonElement | null) => void;
  /** `agenda` is the taller row of the list pane. */
  size?: 'small' | 'agenda';
  dragProps?: React.HTMLAttributes<HTMLButtonElement> & { draggable?: boolean };
}) {
  const { t } = useTranslation(['shell', 'common', 'notes']);
  const { Icon: TypeGlyph } = typeGlyph(entry.kind);
  const color = dayKindColor(entry.kind);
  const Glyph = entry.kind === 'contact' ? Gift : TypeGlyph;
  const title = entry.title || t('common:state.untitled');
  const when = entryWhen(entry, day, t);
  const spaceLabel = entry.space === null ? '' : t(entry.space === 'work' ? 'spaces.work' : 'spaces.personal');
  const SpaceGlyph = mixed && entry.space !== null ? SPACE_ICONS[entry.space] : null;
  const marks = entry.alerted || entry.repeating || SpaceGlyph ? (
    <span className={`shrink-0 inline-flex items-center gap-1.5 ${size === 'agenda' ? 'text-pn-muted' : 'text-accent'}`}>
      {entry.alerted && <BellSimple size={12} aria-hidden="true" />}
      {entry.repeating && <Repeat size={12} aria-hidden="true" />}
      {SpaceGlyph && <SpaceGlyph size={13} aria-hidden="true" />}
    </span>
  ) : null;
  return (
    <button
      ref={rowRef}
      type="button"
      onClick={() => onOpen(entry)}
      onContextMenu={onMenu ? (e) => onMenu(e, entry) : undefined}
      onKeyDown={onKeyDown}
      aria-label={[title, when, spaceLabel].filter(Boolean).join(', ')}
      {...dragProps}
      className={`shrink-0 flex w-full rounded-md px-2 text-pn hover:bg-pn/5 focus-visible:bg-pn/5 outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent ${
        size === 'agenda' ? 'items-stretch gap-2.5 py-2 text-[14px]' : 'items-center gap-2 py-1.5 text-[13px]'
      }`}
    >
      {size === 'agenda' ? (
        // The agenda reads like a timetable: the start time (and the end
        // under it) in a column of its own, a bar in the type's color, then
        // the icon, the title and its marks on one line. Only a multi-day
        // item adds a line, "day 2 of 3", under the title text. Below 270 px
        // of agenda (a narrow pane, window or sidebar beside it) the time
        // column would leave the title no room, so the title takes the line
        // and the time and the marks move to a small line under it.
        <>
          <span className="hidden @min-[270px]/agenda:flex w-[4.25rem] shrink-0 flex-col text-start tabular-nums leading-5">
            <span className={`text-[12.5px] whitespace-nowrap ${entry.time && !entry.span ? 'font-medium text-pn' : 'text-pn-muted'}`}>
              {entry.time && !entry.span ? timeLabel(day, entry.time) : t('calendar.allDay')}
            </span>
            {entry.time && entry.timeEnd && !entry.span && (
              <span className="text-[12px] text-pn-muted whitespace-nowrap">{timeLabel(day, entry.timeEnd)}</span>
            )}
          </span>
          <span aria-hidden="true" className={`w-[3px] shrink-0 rounded-full bg-current opacity-80 ${color}`} />
          <span className="min-w-0 flex-1 flex flex-col text-start leading-5">
            <span className="flex items-center gap-1.5 min-w-0">
              <span data-slot="icon" className="shrink-0 inline-flex">
                <Glyph size={14} aria-hidden="true" className={color} />
              </span>
              <span data-slot="title" dir="auto" className="min-w-0 truncate font-medium">{title}</span>
              {marks && <span className="hidden @min-[270px]/agenda:inline-flex ms-0.5">{marks}</span>}
            </span>
            {(entry.span || entry.time || marks) && (
              // The time keeps its line whole; the marks wrap under it when both do not fit.
              <span className={`ps-5 items-center flex-wrap gap-x-2 min-w-0 text-[12px] text-pn-muted ${entry.span ? 'flex' : 'flex @min-[270px]/agenda:hidden'}`}>
                {(entry.span || entry.time) && (
                  <span className={`tabular-nums whitespace-nowrap max-w-full truncate ${entry.span ? '' : '@min-[270px]/agenda:hidden'}`}>{when}</span>
                )}
                {marks && <span className="inline-flex shrink-0 @min-[270px]/agenda:hidden">{marks}</span>}
              </span>
            )}
          </span>
        </>
      ) : (
        <>
          <span data-slot="icon" className="shrink-0 inline-flex">
            <Glyph size={14} aria-hidden="true" className={color} />
          </span>
          <span data-slot="title" dir="auto" className="min-w-0 truncate text-start">{title}</span>
          <span className="ms-auto shrink-0 flex items-center gap-1.5 text-pn-muted">
            {when && <span className="text-[12px] tabular-nums whitespace-nowrap">{when}</span>}
            {marks}
          </span>
        </>
      )}
    </button>
  );
}

/**
 * A day's items, unfolded under the grid: one `CalendarItemRow` per item, the
 * open space first, the first row focused. A long day scrolls inside its own
 * band, so the card never pushes the list away. Up and Down move, Enter opens,
 * Escape folds it back.
 * Spec: ops/docs/plans/note-date.md (section 4), ops/docs/plans/spaces.md (section 9)
 */
export function DayChooser({ day, entries, onOpen, onFold, bare = false }: { day: string; entries: DayIndex; onOpen: (entry: DayEntry) => void; onFold: () => void; bare?: boolean }) {
  const { t } = useTranslation(['shell', 'common']);
  const rows = useRef<(HTMLButtonElement | null)[]>([]);
  useEffect(() => {
    rows.current[0]?.focus();
  }, [day]);
  useEscapeToClose(onFold);
  const found = entries.entriesOf(day);
  // A day that mixes the spaces marks each row with its space's icon.
  const mixed = new Set(found.map((e) => e.space)).size > 1;
  function onKeyDown(e: React.KeyboardEvent, i: number) {
    const next = e.key === 'ArrowDown' ? i + 1 : e.key === 'ArrowUp' ? i - 1 : null;
    if (next === null) return;
    e.preventDefault();
    rows.current[(next + found.length) % found.length]?.focus();
  }
  return (
    <div role="group" aria-label={t('backfillPopover.chooseEntry', { date: formatInstant(dayAtNoon(day), 'date') })} className={`${bare ? '' : 'mt-2 pt-2 border-t border-divider'} flex flex-col gap-0.5 max-h-60 overflow-y-auto overscroll-contain`}>
      {found.map((entry, i) => (
        <CalendarItemRow
          key={`${entry.id}|${entry.occurrence ?? ''}`}
          entry={entry}
          day={day}
          mixed={mixed}
          rowRef={(el) => { rows.current[i] = el; }}
          onKeyDown={(e) => onKeyDown(e, i)}
          onOpen={onOpen}
        />
      ))}
    </div>
  );
}

const SIZE_KEY = 'privacynotes.journalCalendar';
/** A device-local switch, on by default: its key holds '0' while it is off. */
function deviceSwitch(key: string): [() => boolean, (on: boolean) => void] {
  const listeners = new Set<() => void>();
  const read = (): boolean => {
    try {
      return localStorage.getItem(key) !== '0';
    } catch {
      return true;
    }
  };
  const subscribe = (l: () => void) => {
    listeners.add(l);
    return () => { listeners.delete(l); };
  };
  const set = (on: boolean): void => {
    try {
      if (on) localStorage.removeItem(key);
      else localStorage.setItem(key, '0');
    } catch {
      // Storage refused (a private window): the switch keeps its default.
    }
    listeners.forEach((l) => l());
  };
  return [() => useSyncExternalStore(subscribe, read), set];
}

/** Whether the calendar heads the Journals, Notes, Tasks and All lists. On by
 *  default, device-local, switched in the list options (Show calendar). */
export const [useJournalCalendarShown, setJournalCalendarShown] = deviceSwitch('privacynotes.journalCalendarShown');

const otherSpaceSwitches: Record<Space, [() => boolean, (on: boolean) => void]> = {
  personal: deviceSwitch('privacynotes.calendarOtherSpace.personal'),
  work: deviceSwitch('privacynotes.calendarOtherSpace.work'),
};

/** Whether the calendars show the other space's items while `open` is the
 *  open space, so Work can hide Personal while Personal shows Work. On by
 *  default: an item in the other space is the one people think lost.
 *  Device-local, switched in the list options ("Show Work items" or "Show
 *  Personal items", named for the space that is not open), shown only with
 *  Spaces on. Spec: ops/docs/plans/note-date.md (section 4) */
export function useCalendarShowsOther(open: Space): boolean {
  const personal = otherSpaceSwitches.personal[0]();
  const work = otherSpaceSwitches.work[0]();
  return open === 'work' ? work : personal;
}

export function setCalendarShowsOther(open: Space, on: boolean): void {
  otherSpaceSwitches[open][1](on);
}

/** Week or month, as this device last chose. Every screen starts on the
 *  week, so the list keeps its room. Device-local, like the screen it is about. */
function readSize(): 1 | 6 {
  try {
    if (localStorage.getItem(SIZE_KEY) === 'month') return 6;
  } catch {
    // Storage refused (a private window): the week.
  }
  return 1;
}

/**
 * The calendar at the top of the Journals, Notes, Tasks and All lists. In the list it is a flat
 * first row; in the grid it is the first tile, one cell wide, and the month spans
 * two rows. On a phone it is the one way to the calendar, because the footer
 * there has no room for its button.
 * Spec: ops/docs/plans/journal-calendar.md (section 4b)
 */
/** What a card offers beyond its days: the expand button that opens the
 *  Calendar pillar at the card's month, and a list row dropped on a day. */
export type CalendarCardExtras = {
  onExpand?: (month: string) => void;
  drop?: { accepts: (e: React.DragEvent) => boolean; onDrop: (day: string, e: React.DragEvent) => void };
};

export function JournalCalendarCard({ grid, onExpand, drop, ...handlers }: DayHandlers & CalendarCardExtras & { grid: boolean }) {
  const { t } = useTranslation('shell');
  const [weeks, setWeeks] = useState<1 | 6>(readSize);
  const [choosing, setChoosing] = useState<string | null>(null);
  const [month, setMonth] = useState(() => toLocalIso(new Date()));
  function pick(day: string) {
    const unfold = pickCalendarDay(day, handlers) === 'choose' && day !== choosing;
    setChoosing(unfold ? day : null);
  }
  function toggle() {
    const next = weeks === 6 ? 1 : 6;
    setWeeks(next);
    try {
      localStorage.setItem(SIZE_KEY, next === 6 ? 'month' : 'week');
    } catch {
      // Storage refused: the choice holds for this page only.
    }
  }
  // The grid gets the entry tiles' card; the list gets a flat full-width band
  // in the card's background, with the rows' padding and a divider.
  return (
    <li
      className={
        grid
          ? `rounded-xl border border-divider bg-surface-2 p-2 ${weeks === 6 ? 'row-span-2' : ''}`
          : 'px-4 pt-1 pb-1.5 md:pt-2 md:pb-3 bg-surface-2 border-b border-divider'
      }
    >
      <MonthGrid
        marked={handlers.entries}
        selected={choosing ?? undefined}
        onPick={pick}
        weeks={weeks}
        onToggleWeeks={toggle}
        onFocusChange={setMonth}
        drop={drop}
        headerEnd={onExpand && (
          <HoverLabel label={t('calendar.open')} position="below-end">
            <button
              type="button"
              onClick={() => onExpand(month)}
              aria-label={t('calendar.open')}
              className="inline-flex items-center justify-center w-8 h-8 [@media(hover:none)]:w-10 [@media(hover:none)]:h-10 rounded-md text-accent hover:bg-pn/5 transition"
            >
              <ArrowsOutSimple size={14} aria-hidden="true" />
            </button>
          </HoverLabel>
        )}
      />
      {choosing && (
        <DayChooser
          day={choosing}
          entries={handlers.entries}
          onOpen={(e) => { setChoosing(null); handlers.onOpen(e.id, e.occurrence); }}
          onFold={() => setChoosing(null)}
        />
      )}
    </li>
  );
}

export function JournalCalendarPopover({ entries, onOpen, onPick, onToday, onClose, anchorRef, align = 'end', todayRow = true }: Props) {
  const { t } = useTranslation('shell');
  const popoverRef = useRef<HTMLDivElement | null>(null);
  const pos = usePopoverPosition(true, anchorRef, popoverRef, { align });

  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (popoverRef.current && popoverRef.current.contains(target)) return;
      if (anchorRef.current && anchorRef.current.contains(target)) return;
      onClose();
    }
    window.addEventListener('pointerdown', handler, true);
    return () => window.removeEventListener('pointerdown', handler, true);
  }, [onClose, anchorRef]);

  useEscapeToClose(onClose);

  const [choosing, setChoosing] = useState<string | null>(null);
  const handlers: DayHandlers = { entries, onOpen, onPick, onToday };
  function pick(day: string) {
    if (pickCalendarDay(day, handlers) === 'choose' && day !== choosing) setChoosing(day);
    else if (choosing === day) setChoosing(null);
    else onClose();
  }

  return createPortal(
    <div
      ref={popoverRef}
      role="dialog"
      aria-label={t('backfillPopover.calendarLabel')}
      style={{ top: pos?.top ?? 0, left: pos?.left ?? 0, visibility: pos ? 'visible' : 'hidden' }}
      className="fixed z-50 max-w-[calc(100vw-16px)] max-h-[calc(100dvh-16px)] overflow-y-auto overscroll-contain rounded-md border border-divider bg-surface-2 shadow-lg p-2"
    >
      <div className="w-[240px] max-w-full">
        <MonthGrid marked={entries} selected={choosing ?? undefined} onPick={pick} onToday={todayRow ? () => { onToday(); onClose(); } : undefined} />
        {choosing && (
          <DayChooser
            day={choosing}
            entries={entries}
            onOpen={(e) => { onOpen(e.id, e.occurrence); onClose(); }}
            onFold={() => setChoosing(null)}
          />
        )}
      </div>
    </div>,
    document.body,
  );
}

/** What the footer calendar button opens and creates. */
export type JournalCalendarHandlers = DayHandlers;

/** The calendar button beside the footer stats. It shows and hides with them,
 *  so a phone footer keeps its three fixed places. */
export function JournalCalendarButton(handlers: DayHandlers) {
  const { t } = useTranslation('notes');
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLButtonElement | null>(null);
  return (
    <>
      <HoverLabel label={t('footer.journalCalendar')} position="above" disabled={open}>
        <button
          ref={ref}
          type="button"
          onClick={() => setOpen((o) => !o)}
          aria-label={t('footer.journalCalendar')}
          aria-haspopup="dialog"
          aria-expanded={open}
          className={`inline-flex items-center rounded-md p-1 transition ${open ? 'text-accent' : 'text-pn-muted hover:text-accent'}`}
        >
          <Calendar size={14} />
        </button>
      </HoverLabel>
      {open && <JournalCalendarPopover {...handlers} onClose={() => setOpen(false)} anchorRef={ref} align="center" todayRow={false} />}
    </>
  );
}
