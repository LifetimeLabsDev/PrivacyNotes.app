import { useEffect, useRef, useState, useSyncExternalStore } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { Briefcase, Calendar, User } from './icons';
import { HoverLabel } from './HoverLabel';
import { useEscapeToClose } from './useEscapeToClose';
import { usePopoverPosition } from './usePopoverPosition';
import { formatInstant, toLocalIso } from './intlFormat';
import { MonthGrid, dayAtNoon } from './MonthGrid';
import type { JournalDays } from './notesViewUtils';

/**
 * Everything the journal calendar does, in one module: the pick rule, the two
 * device settings, the popover (Journals New button, footer button) and the
 * card at the top of the Journals list. How a calendar looks lives in
 * MonthGrid, and nothing here styles the grid itself. The Entry date view of
 * the entry menu is the one other host, because a pick there moves an entry.
 *
 * A day with an entry opens that day's newest entry; any other day creates one.
 * Today has its own callback because it is not a backfill: the ordinary
 * new-entry path inherits the open folder, the active tag and the pinned
 * state of the list the user is standing in, and a dated entry deliberately
 * inherits none of that.
 * Spec: ops/docs/plans/journal-calendar.md
 */
type Props = {
  /** Local ISO day to that day's newest entry, and the newest of each space. */
  entries: JournalDays;
  /** Opens an existing entry. */
  onOpen: (id: string) => void;
  /** Creates an entry for an ISO day (yyyy-mm-dd). Never today's date. */
  onPick: (isoDate: string) => void;
  /** Creates today's entry. */
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

/** One rule for every journal calendar: a dotted day opens its newest entry,
 *  an empty today is an ordinary new entry, any other day a dated one. A day
 *  with an entry in each space opens nothing and answers 'choose', so the
 *  calendar can unfold the two. Spec: ops/docs/plans/spaces.md (section 9) */
export function pickJournalDay(day: string, { entries, onOpen, onPick, onToday }: DayHandlers): 'done' | 'choose' {
  const found = entries.entriesOf(day);
  if (found.length > 1) return 'choose';
  if (found[0]) onOpen(found[0].id);
  else if (day === toLocalIso(new Date())) onToday();
  else onPick(day);
  return 'done';
}

/**
 * A day with an entry in each space, unfolded under the grid: one row per
 * space, the open space first and focused. Up and Down move, Enter opens,
 * Escape folds it back. A row shows the stored title only, so an entry
 * behind a PIN shows nothing from inside it.
 * Spec: ops/docs/plans/spaces.md (section 9)
 */
function DayChooser({ day, entries, onOpen, onFold }: { day: string; entries: JournalDays; onOpen: (id: string) => void; onFold: () => void }) {
  const { t } = useTranslation(['shell', 'common']);
  const rows = useRef<(HTMLButtonElement | null)[]>([]);
  useEffect(() => {
    rows.current[0]?.focus();
  }, [day]);
  useEscapeToClose(onFold);
  const found = entries.entriesOf(day);
  function onKeyDown(e: React.KeyboardEvent, i: number) {
    const next = e.key === 'ArrowDown' ? i + 1 : e.key === 'ArrowUp' ? i - 1 : null;
    if (next === null) return;
    e.preventDefault();
    rows.current[(next + found.length) % found.length]?.focus();
  }
  return (
    <div role="group" aria-label={t('backfillPopover.chooseEntry', { date: formatInstant(dayAtNoon(day), 'date') })} className="mt-2 pt-2 border-t border-divider flex flex-col gap-0.5">
      {found.map((entry, i) => {
        const Glyph = entry.space === 'work' ? Briefcase : User;
        return (
          <button
            key={entry.id}
            ref={(el) => { rows.current[i] = el; }}
            type="button"
            onClick={() => onOpen(entry.id)}
            onKeyDown={(e) => onKeyDown(e, i)}
            className="flex items-center gap-2 w-full rounded-md px-2 py-1.5 text-[13px] text-pn hover:bg-pn/5 focus-visible:bg-pn/5 outline-none focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent"
          >
            <span aria-hidden="true" className={`shrink-0 w-[5px] h-[5px] ${entry.space === 'work' ? 'rounded-[1px] bg-warning' : 'rounded-full bg-accent'}`} />
            <Glyph size={14} className="shrink-0 text-pn-muted" />
            <span className="shrink-0">{t(entry.space === 'work' ? 'spaces.work' : 'spaces.personal')}</span>
            <span dir="auto" className="ms-auto min-w-0 truncate text-pn-muted">{entry.title || t('common:state.untitled')}</span>
          </button>
        );
      })}
    </div>
  );
}

const SIZE_KEY = 'privacynotes.journalCalendar';
const SHOWN_KEY = 'privacynotes.journalCalendarShown';
const shownListeners = new Set<() => void>();

function journalCalendarShown(): boolean {
  try {
    return localStorage.getItem(SHOWN_KEY) !== '0';
  } catch {
    return true;
  }
}

/** Whether the calendar heads the Journals list. On by default, device-local,
 *  switched in the list options (Show calendar). */
export function useJournalCalendarShown(): boolean {
  return useSyncExternalStore(
    (l) => {
      shownListeners.add(l);
      return () => shownListeners.delete(l);
    },
    journalCalendarShown,
  );
}

export function setJournalCalendarShown(on: boolean): void {
  try {
    if (on) localStorage.removeItem(SHOWN_KEY);
    else localStorage.setItem(SHOWN_KEY, '0');
  } catch {
    // Storage refused (a private window): the switch holds for this page only.
  }
  shownListeners.forEach((l) => l());
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
 * The calendar at the top of the Journals list. In the list it is a flat
 * first row; in the grid it is the first tile, one cell wide, and the month spans
 * two rows. On a phone it is the one way to the calendar, because the footer
 * there has no room for its button.
 * Spec: ops/docs/plans/journal-calendar.md (section 4b)
 */
export function JournalCalendarCard({ grid, ...handlers }: DayHandlers & { grid: boolean }) {
  const [weeks, setWeeks] = useState<1 | 6>(readSize);
  const [choosing, setChoosing] = useState<string | null>(null);
  function pick(day: string) {
    const unfold = pickJournalDay(day, handlers) === 'choose' && day !== choosing;
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
          : 'px-4 pt-2 pb-3 bg-surface-2 border-b border-divider'
      }
    >
      <MonthGrid marked={handlers.entries} selected={choosing ?? undefined} onPick={pick} weeks={weeks} onToggleWeeks={toggle} />
      {choosing && (
        <DayChooser
          day={choosing}
          entries={handlers.entries}
          onOpen={(id) => { setChoosing(null); handlers.onOpen(id); }}
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
  function pick(day: string) {
    if (pickJournalDay(day, { entries, onOpen, onPick, onToday }) === 'choose' && day !== choosing) setChoosing(day);
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
            onOpen={(id) => { onOpen(id); onClose(); }}
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
