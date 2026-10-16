import { useEffect, useLayoutEffect, useMemo, useRef, useState, useSyncExternalStore } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { BellSimple, CalendarDot, Columns, Gift, GridNine, List, ListDashes, Repeat } from './icons';
import { SPACE_ICONS } from './SpaceSwitch';
import { typeGlyph } from './NoteRow';
import { Switch } from './Switch';
import { HoverLabel } from './HoverLabel';
import { CalendarHeader, MonthGrid, addDays, dayAtNoon, dayKindColor, firstWeekday, monthCells, weekCells } from './MonthGrid';
import { CalendarGrid } from './CalendarGrid';
import { DayChooser, timeLabel } from './JournalCalendar';
import { dayChips, entryKey, lanesUsed, weekBars, type TimedBlock } from './calendarLayout';
import { formatInstant, toLocalIso } from './intlFormat';
import { intlLocale } from './languages';
import { isItemDrag, readItemDrag, writeItemDrag } from './itemDrag';
import { usePopoverPosition } from './usePopoverPosition';
import { useEscapeToClose } from './useEscapeToClose';
import type { DayEntry, DayIndex, DayKind } from './notesViewUtils';
import type { Space } from './spaces';
import type { CalendarPillar } from './notesView/useCalendarPillar';
import { dayNumber } from './schedule';

/**
 * The Calendar pillar's editor pane: Day, Week or Month over one index. The
 * month is `MonthGrid` at its large size with chips and the multi-day bars in
 * lanes; the day and the week are `CalendarGrid`, the hour layout. A chip
 * opens its item, an empty cell or hour creates, a chip or a bar dragged to
 * another day moves the whole schedule, the grip at a bar's end moves its end
 * day. Loaded on demand, so the boot chunk does not carry it.
 * Spec: ops/docs/plans/calendar-pillar-spec.md (steps 1, 3, 4 and 5)
 */

/** The drag of a chip or a bar inside the calendar: which occurrence, the
 *  day it was grabbed on, and whether it is a bar's end grip. It rides with
 *  the item ids of a list drag, so a folder row in the sidebar still files it. */
const CAL_TYPE = 'application/x-privacynotes-calendar';
type CalDrag = { id: string; occurrence?: string; grab: string; edge?: 'end' };

/** A move the pane asks for: the item, its occurrence, and how many days
 *  (and, dropped on an hour, to which time) it goes. */
type CalendarMove = { id: string; occurrence?: string; days: number; time?: string };

const CHIP_PX = 18;
const NUMBER_PX = 28;

// ── The legend: which types show, per device ─────────────────────────

const HIDDEN_KEY = 'privacynotes.calendarHiddenKinds';
const legendListeners = new Set<() => void>();
function readHidden(): string {
  try {
    return localStorage.getItem(HIDDEN_KEY) ?? '';
  } catch {
    return '';
  }
}
function setHidden(kinds: readonly DayKind[]) {
  try {
    if (kinds.length) localStorage.setItem(HIDDEN_KEY, kinds.join(','));
    else localStorage.removeItem(HIDDEN_KEY);
  } catch {
    // Storage refused: the legend resets on the next load.
  }
  legendListeners.forEach((l) => l());
}
function useHiddenKinds(): Set<DayKind> {
  const raw = useSyncExternalStore((l) => { legendListeners.add(l); return () => { legendListeners.delete(l); }; }, readHidden);
  return useMemo(() => new Set(raw.split(',').filter(Boolean) as DayKind[]), [raw]);
}

const LEGEND: readonly DayKind[] = ['event', 'note', 'task', 'journal', 'contact'];

// ── Drag helpers ──────────────────────────────────────────────────────

function writeCalDrag(e: React.DragEvent, data: CalDrag) {
  writeItemDrag(e.dataTransfer, [data.id], '');
  e.dataTransfer.setData(CAL_TYPE, JSON.stringify(data));
}
function readCalDrag(e: React.DragEvent): CalDrag | null {
  try {
    const v = JSON.parse(e.dataTransfer.getData(CAL_TYPE)) as Partial<CalDrag>;
    return typeof v.id === 'string' && typeof v.grab === 'string' ? (v as CalDrag) : null;
  } catch {
    return null;
  }
}
const accepts = (e: React.DragEvent) => isItemDrag(e.dataTransfer);

// ── A chip and a bar ──────────────────────────────────────────────────

function EntryGlyph({ entry, size = 12 }: { entry: DayEntry; size?: number }) {
  const { Icon } = typeGlyph(entry.kind);
  const Glyph = entry.kind === 'contact' ? Gift : Icon;
  return <Glyph size={size} aria-hidden="true" className={`shrink-0 ${dayKindColor(entry.kind)}`} />;
}

/** One item in a cell: its type's icon, the time in front of a timed one,
 *  the title, then a bell, the repeat glyph and the briefcase of Work. */
/** The views, each with the icon its switch shows. */
const VIEW_MODES = [
  { mode: 'day', Icon: CalendarDot },
  { mode: 'week', Icon: Columns },
  { mode: 'month', Icon: GridNine },
] as const;

/** A chip's, a bar's or a card's right-click menu. */
type ItemMenu = ((e: React.MouseEvent, entry: DayEntry) => void) | undefined;

function Chip({ entry, day, mixed, onOpen, onMenu }: { entry: DayEntry; day: string; mixed: boolean; onOpen: (e: DayEntry) => void; onMenu: ItemMenu }) {
  const { t } = useTranslation(['shell', 'common']);
  const title = entry.title || t('common:state.untitled');
  const SpaceGlyph = mixed && entry.space === 'work' ? SPACE_ICONS.work : null;
  const when = entry.time ? timeLabel(day, entry.time) : '';
  return (
    <button
      type="button"
      draggable={entry.kind !== 'contact'}
      onDragStart={(e) => writeCalDrag(e, { id: entry.id, occurrence: entry.occurrence, grab: day })}
      onClick={() => onOpen(entry)}
      onContextMenu={onMenu ? (e) => onMenu(e, entry) : undefined}
      aria-label={[when, title].filter(Boolean).join(' ')}
      className="shrink-0 flex items-center gap-1 min-w-0 h-[17px] px-1 rounded text-[11px] leading-[15px] text-pn hover:bg-accent/10 focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent text-start"
    >
      <span data-slot="icon" className="inline-flex shrink-0"><EntryGlyph entry={entry} /></span>
      {/* A narrow cell gives the title the room; the time stays in the label. */}
      {when && <span className="hidden @min-[128px]/cell:inline shrink-0 text-pn-muted tabular-nums text-[10.5px]">{when}</span>}
      <span data-slot="title" dir="auto" className="min-w-0 truncate">{title}</span>
      {entry.alerted && <BellSimple size={10} aria-hidden="true" className="shrink-0 text-accent" />}
      {entry.repeating && <Repeat size={10} aria-hidden="true" className="shrink-0 text-accent" />}
      {SpaceGlyph && <SpaceGlyph size={10} aria-hidden="true" className="shrink-0 text-accent" />}
    </button>
  );
}

/** The bars of one week row: a filled pill per multi-day item in its lane,
 *  flat where it runs past the row, with a grip at its end to move the end day. */
function Bars({ days, index, hidden, onOpen, onMenu, top, weekCol }: {
  onMenu: ItemMenu;
  days: readonly string[];
  index: DayIndex;
  hidden: (e: DayEntry) => boolean;
  onOpen: (e: DayEntry) => void;
  top: number;
  weekCol: string;
}) {
  const { t } = useTranslation(['shell', 'common']);
  const { bars } = weekBars(days, index, hidden);
  const n = days.length;
  return (
    <>
      {bars.map((b) => {
        const title = b.entry.title || t('common:state.untitled');
        const span = b.endCol - b.startCol + 1;
        const color = dayKindColor(b.entry.kind);
        return (
          <div
            key={entryKey(b.entry)}
            className={`absolute h-4 z-[1] px-0.5 ${color}`}
            style={{
              top: top + b.lane * CHIP_PX,
              insetInlineStart: `calc(${weekCol} + (100% - ${weekCol}) * ${b.startCol} / ${n})`,
              width: `calc((100% - ${weekCol}) * ${span} / ${n})`,
            }}
          >
            <div
              className={`h-full flex items-center bg-current/15 ${b.contStart ? 'rounded-s-none' : 'rounded-s'} ${b.contEnd ? 'rounded-e-none' : 'rounded-e'}`}
            >
              <button
                type="button"
                draggable
                onDragStart={(e) => {
                  // The day under the pointer is the one grabbed, so a bar
                  // picked up by its middle keeps its length where it lands.
                  const r = e.currentTarget.getBoundingClientRect();
                  const rtl = getComputedStyle(e.currentTarget).direction === 'rtl';
                  const x = rtl ? r.right - e.clientX : e.clientX - r.left;
                  const col = Math.min(span - 1, Math.max(0, Math.floor((x / r.width) * span)));
                  writeCalDrag(e, { id: b.entry.id, occurrence: b.entry.span?.start, grab: days[b.startCol + col]! });
                }}
                onClick={() => onOpen(b.entry)}
                onContextMenu={onMenu ? (e) => onMenu(e, b.entry) : undefined}
                aria-label={title}
                className="flex-1 min-w-0 h-full flex items-center gap-1 px-1.5 text-[10.5px] font-semibold text-pn text-start focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent rounded"
              >
                <span data-slot="icon" className="inline-flex shrink-0"><EntryGlyph entry={b.entry} size={11} /></span>
                <span data-slot="title" dir="auto" className="min-w-0 truncate">{title}</span>
                {b.entry.space === 'work' && <SPACE_ICONS.work size={10} aria-hidden="true" className="shrink-0 ms-auto text-pn-muted" />}
              </button>
              {!b.contEnd && b.entry.kind !== 'contact' && (
                <span
                  draggable
                  data-drag-handle
                  role="presentation"
                  onDragStart={(e) => writeCalDrag(e, { id: b.entry.id, occurrence: b.entry.span?.start, grab: b.entry.span!.end, edge: 'end' })}
                  title={t('calendar.dragEnd')}
                  className="shrink-0 w-2 h-full cursor-ew-resize flex items-center justify-center"
                >
                  <span className="w-[3px] h-2.5 rounded-full bg-current opacity-60" />
                </span>
              )}
            </div>
          </div>
        );
      })}
    </>
  );
}

/** The "+N more" popover: the day's whole list, the rows of the card. */
function MorePopover({ day, index, anchor, onOpen, onClose }: { day: string; index: DayIndex; anchor: HTMLElement; onOpen: (e: DayEntry) => void; onClose: () => void }) {
  const ref = useRef<HTMLDivElement | null>(null);
  const anchorRef = useRef<HTMLElement | null>(anchor);
  anchorRef.current = anchor;
  const pos = usePopoverPosition(true, anchorRef, ref, { align: 'center' });
  useEscapeToClose(onClose);
  useEffect(() => {
    const away = (e: PointerEvent) => {
      if (ref.current?.contains(e.target as Node)) return;
      onClose();
    };
    window.addEventListener('pointerdown', away, true);
    return () => window.removeEventListener('pointerdown', away, true);
  }, [onClose]);
  return (
    <div
      ref={ref}
      role="dialog"
      aria-label={formatInstant(dayAtNoon(day), 'date')}
      style={{ top: pos?.top ?? 0, left: pos?.left ?? 0, visibility: pos ? 'visible' : 'hidden' }}
      className="fixed z-50 w-[260px] max-w-[calc(100vw-16px)] rounded-md border border-divider bg-surface-2 shadow-lg p-2"
    >
      <div className="px-2 pb-1 text-[12px] font-semibold text-pn-muted">{formatInstant(dayAtNoon(day), 'date')}</div>
      <DayChooser day={day} entries={index} bare onOpen={(e) => { onClose(); onOpen(e); }} onFold={onClose} />
    </div>
  );
}

// ── The pane ──────────────────────────────────────────────────────────

type Props = {
  index: DayIndex;
  pillar: CalendarPillar;
  onOpen: (id: string, occurrence?: string) => void;
  /** An item's right-click menu: the item menu, at the occurrence. */
  onItemMenu?: (e: React.MouseEvent, entry: DayEntry) => void;
  /** A right-click on a day's empty space. */
  onDayMenu?: (e: React.MouseEvent, day: string) => void;
  /** Create on a day, at a time and to an end time when given. */
  onAdd: (day: string, time?: string, timeEnd?: string) => void;
  onMove: (move: CalendarMove) => void;
  onResize: (id: string, occurrence: string | undefined, end: string) => void;
  /** List rows dropped on a day (and an hour). */
  onDropItems: (ids: string[], day: string, time?: string) => void;
  /** The other space's switch, with Spaces on. */
  otherSpace: { space: Space; shown: boolean; set: (on: boolean) => void } | null;
  weekNumbers: boolean;
  firstHour: number;
  /** Opens the drawer, below lg where the folded agenda took its button along. */
  onMenu?: () => void;
  /** The agenda (the list pane) beside the grid: shown or folded, and the
   *  button that toggles it. Absent where the agenda is the whole screen. */
  agenda?: { open: boolean; toggle: () => void };
};

export default function CalendarPane({ index, pillar, onOpen, onItemMenu, onDayMenu, onAdd, onMove, onResize, onDropItems, otherSpace, weekNumbers, firstHour, onMenu, agenda }: Props) {
  const { t } = useTranslation(['shell', 'notes']);
  const { mode, setMode, focus, setFocus } = pillar;
  const hiddenKinds = useHiddenKinds();
  const hidden = (e: DayEntry) => hiddenKinds.has(e.kind);
  const shown = useMemo<DayIndex>(() => ({
    has: (day) => index.entriesOf(day).some((e) => !hiddenKinds.has(e.kind)),
    entriesOf: (day) => index.entriesOf(day).filter((e) => !hiddenKinds.has(e.kind)),
  }), [index, hiddenKinds]);
  const locale = intlLocale();
  const weekStart = firstWeekday(locale);
  const today = toLocalIso(new Date());
  const [more, setMore] = useState<{ day: string; anchor: HTMLElement } | null>(null);
  const body = useRef<HTMLDivElement | null>(null);
  const [cellH, setCellH] = useState(96);

  useLayoutEffect(() => {
    const el = body.current;
    if (!el || mode !== 'month') return;
    const measure = () => {
      const cell = el.querySelector<HTMLElement>('[role="gridcell"]');
      if (cell) setCellH(cell.clientHeight);
    };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [mode]);

  const open = (e: DayEntry) => onOpen(e.id, e.occurrence ?? e.span?.start);
  const drop = {
    accepts,
    onDrop: (day: string, e: React.DragEvent) => {
      const cal = readCalDrag(e);
      if (cal?.edge === 'end') onResize(cal.id, cal.occurrence, day);
      else if (cal) onMove({ id: cal.id, occurrence: cal.occurrence, days: dayNumber(day) - dayNumber(cal.grab) });
      else onDropItems(readItemDrag(e.dataTransfer), day);
    },
  };

  // The segmented control of Settings (Auto, Light, Dark): the track, the
  // raised option, an icon each. A narrow header keeps the icons and names
  // them on hover.
  const viewSwitch = (
    <div role="group" aria-label={t('calendar.viewLabel')} className="shrink-0 flex gap-1 rounded-md bg-track p-1">
      {VIEW_MODES.map(({ mode: m, Icon }) => (
        <HoverLabel key={m} label={t(`calendar.views.${m}`)} position="below" className="@min-[420px]/calhead:[&>:last-child]:hidden">
          <button
            type="button"
            aria-pressed={mode === m}
            aria-label={t(`calendar.views.${m}`)}
            onClick={() => setMode(m)}
            className={`inline-flex items-center gap-1.5 h-6 px-1.5 @min-[420px]/calhead:px-2.5 rounded text-xs transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 ${
              mode === m ? 'bg-surface-2 shadow-sm text-pn font-semibold' : 'text-pn-soft hover:text-pn font-medium'
            }`}
          >
            <Icon size={14} aria-hidden="true" />
            <span aria-hidden="true" className="hidden @min-[420px]/calhead:inline">{t(`calendar.views.${m}`)}</span>
          </button>
        </HoverLabel>
      ))}
    </div>
  );

  // The kinds on the left; the space switch at the end of the row, under the
  // view switch, since it is a view setting too.
  const legend = (
    <div className="w-full flex flex-wrap items-center gap-x-4 gap-y-1">
    <div role="group" aria-label={t('calendar.legendLabel')} className="flex flex-wrap items-center gap-x-3 gap-y-1">
      {LEGEND.map((kind) => {
        const off = hiddenKinds.has(kind);
        const { Icon } = typeGlyph(kind);
        const Glyph = kind === 'contact' ? Gift : Icon;
        return (
          <HoverLabel key={kind} label={t(`calendar.kinds.${kind}`)} position="below" className="@min-[560px]/calhead:[&>:last-child]:hidden">
            <button
              type="button"
              aria-pressed={!off}
              aria-label={t(`calendar.kinds.${kind}`)}
              onClick={() => setHidden(off ? [...hiddenKinds].filter((k) => k !== kind) : [...hiddenKinds, kind])}
              className={`inline-flex items-center gap-1 min-h-6 text-[12px] text-pn-muted hover:text-pn transition ${off ? 'opacity-45 line-through' : ''}`}
            >
              <Glyph size={12} aria-hidden="true" className={dayKindColor(kind)} />
              {/* A narrow header keeps the glyphs and names them on hover. */}
              <span aria-hidden="true" className="hidden @min-[560px]/calhead:inline">{t(`calendar.kinds.${kind}`)}</span>
            </button>
          </HoverLabel>
        );
      })}
    </div>
      {otherSpace && (
        <Switch
          label={<Trans t={t} i18nKey={otherSpace.space === 'work' ? 'listPrefs.showWorkItems' : 'listPrefs.showPersonalItems'} components={{ b: <b className="font-semibold" /> }} />}
          checked={otherSpace.shown}
          onChange={otherSpace.set}
          className="gap-2 ms-auto"
          labelClassName="text-[12px] text-pn-muted"
        />
      )}
    </div>
  );

  const headerEnd = viewSwitch;
  // The agenda button names what it does on hover, and wears the pressed
  // look while the agenda is open, so a folded agenda is never a secret.
  const agendaLabel = agenda ? t(agenda.open ? 'calendar.hideAgenda' : 'calendar.showAgenda') : '';
  const headerStart = onMenu || agenda ? (
    <>
      {onMenu && (
        <button type="button" onClick={onMenu} aria-label={t('mobileHeader.openMenu')} className="shrink-0 rounded p-1.5 -ms-1 text-pn-muted hover:bg-pn/10 transition">
          <List size={20} />
        </button>
      )}
      {agenda && (
        <HoverLabel label={agendaLabel} position="below-start">
          <button
            type="button"
            onClick={agenda.toggle}
            aria-label={agendaLabel}
            aria-pressed={agenda.open}
            className={`shrink-0 inline-flex items-center justify-center w-7 h-7 rounded-md border transition ${
              agenda.open ? 'bg-accent/10 border-accent/40 text-accent' : 'border-divider text-pn-muted hover:border-accent hover:text-accent'
            }`}
          >
            <ListDashes size={15} aria-hidden="true" />
          </button>
        </HoverLabel>
      )}
    </>
  ) : null;

  /** A day's chips under `lanes` lanes of bars, as many as `fit`, then "+N more". */
  const dayContent = (day: string, entries: readonly DayEntry[], lanes: number, fit: number, overBars: number) => {
    const { chips, more: extra } = dayChips(entries, fit, overBars);
    const mixed = new Set(shown.entriesOf(day).map((e) => e.space)).size > 1;
    return (
      <>
        {lanes > 0 && <div aria-hidden="true" style={{ height: lanes * CHIP_PX }} className="shrink-0" />}
        {chips.map((e) => <Chip key={entryKey(e)} entry={e} day={day} mixed={mixed} onOpen={open} onMenu={onItemMenu} />)}
        {extra > 0 && (
          <button
            type="button"
            onClick={(ev) => setMore({ day, anchor: ev.currentTarget })}
            className="shrink-0 self-start px-1 text-[10.5px] font-semibold text-accent hover:underline"
          >
            {t('calendar.more', { count: extra })}
          </button>
        )}
      </>
    );
  };

  let content: React.ReactNode;
  if (mode === 'month') {
    const weekCol = weekNumbers ? '2rem' : '0px';
    const rowLanes = new Map<string, { lanes: number; over: Map<string, number> }>();
    const cells = monthCells(focus, weekStart);
    for (let i = 0; i < cells.length; i += 7) {
      const days = cells.slice(i, i + 7);
      const { bars, hidden: over } = weekBars(days, shown);
      for (const d of days) rowLanes.set(d, { lanes: lanesUsed(bars), over });
    }
    content = (
      <MonthGrid
        onDayMenu={onDayMenu}
        size="large"
        marked={shown}
        focus={focus}
        onFocusChange={setFocus}
        onPick={(day) => { setFocus(day); setMode('day'); }}
        onToday={() => setFocus(today)}
        onAdd={(day) => onAdd(day)}
        headerEnd={headerEnd}
        headerBelow={legend}
        headerStart={headerStart}
        weekNumbers={weekNumbers}
        drop={drop}
        renderDay={(day) => {
          const row = rowLanes.get(day);
          const lanes = row?.lanes ?? 0;
          // Whole chips only: a cell with no room for one shows "+N more".
          const fit = Math.max(0, Math.floor((cellH - NUMBER_PX - 4 - lanes * CHIP_PX) / CHIP_PX));
          return dayContent(day, shown.entriesOf(day), lanes, fit, row?.over.get(day) ?? 0);
        }}
        renderWeek={(days) => <Bars days={days} index={shown} hidden={hidden} onOpen={open} onMenu={onItemMenu} top={NUMBER_PX} weekCol={weekCol} />}
      />
    );
  } else {
    const days = mode === 'week' ? weekCells(focus, weekStart) : [focus];
    const shortTitle = mode === 'day' ? formatInstant(dayAtNoon(focus), 'weekdayDate') : formatInstant(dayAtNoon(days[0]!), 'dayMonth');
    const title = mode === 'day'
      ? formatInstant(dayAtNoon(focus), 'date')
      : new Intl.DateTimeFormat(locale, { month: 'short', day: 'numeric', year: 'numeric' }) // date-ok: a week heading is a range, which no named style writes
        .formatRange(dayAtNoon(days[0]!), dayAtNoon(days[6]!));
    const stepDays = mode === 'week' ? 7 : 1;
    const band = weekBars(days, shown);
    const bandLanes = lanesUsed(band.bars);
    content = (
      <div className="flex flex-col h-full min-h-0">
        <CalendarHeader
          title={title}
          shortTitle={shortTitle}
          onPrev={() => setFocus(addDays(focus, -stepDays))}
          onNext={() => setFocus(addDays(focus, stepDays))}
          prevLabel={t(mode === 'week' ? 'monthGrid.previousWeek' : 'calendar.previousDay')}
          nextLabel={t(mode === 'week' ? 'monthGrid.nextWeek' : 'calendar.nextDay')}
          onToday={() => setFocus(today)}
          end={headerEnd}
          below={legend}
          start={headerStart}
        />
        <CalendarGrid
          days={days}
          index={shown}
          hidden={hidden}
          firstHour={firstHour}
          scrollRef={pillar.hourScroll}
          renderAllDay={(day) => dayContent(day, shown.entriesOf(day).filter((e) => !e.time), bandLanes, 3, band.hidden.get(day) ?? 0)}
          renderBars={(ds) => <Bars days={ds} index={shown} hidden={hidden} onOpen={open} onMenu={onItemMenu} top={4} weekCol="4rem" />}
          renderCard={(b: TimedBlock, day) => <TimedCard block={b} day={day} onOpen={open} onMenu={onItemMenu} />}
          onCreate={(day, start, end) => onAdd(day, start, end)}
          onPickDay={(day) => { setFocus(day); setMode('day'); }}
          accepts={accepts}
          onDropAt={(e, day, time) => {
            const cal = readCalDrag(e);
            if (cal && !cal.edge) onMove({ id: cal.id, occurrence: cal.occurrence, days: dayNumber(day) - dayNumber(cal.grab), time });
            else if (!cal) onDropItems(readItemDrag(e.dataTransfer), day, time);
          }}
        />
      </div>
    );
  }

  return (
    <div ref={body} className="flex-1 min-h-0 flex flex-col">
      {content}
      {more && <MorePopover day={more.day} index={shown} anchor={more.anchor} onOpen={open} onClose={() => setMore(null)} />}
    </div>
  );
}

/** A timed item on the hour grid: the type color's tint with its edge, the
 *  title, then the time. */
function TimedCard({ block, day, onOpen, onMenu }: { block: TimedBlock; day: string; onOpen: (e: DayEntry) => void; onMenu: ItemMenu }) {
  const { t } = useTranslation(['shell', 'common']);
  const e = block.entry;
  const title = e.title || t('common:state.untitled');
  const start = block.carried ? '' : e.time ? timeLabel(day, e.time) : '';
  const end = e.timeEnd ? timeLabel(day, e.timeEnd) : '';
  return (
    <button
      type="button"
      draggable={!block.carried}
      onDragStart={(ev) => writeCalDrag(ev, { id: e.id, occurrence: e.occurrence, grab: day })}
      onClick={() => onOpen(e)}
      onContextMenu={onMenu ? (ev) => onMenu(ev, e) : undefined}
      aria-label={[title, start && end ? `${start} - ${end}` : start].filter(Boolean).join(', ')}
      className={`w-full h-full overflow-hidden rounded-md border-s-[3px] border-current bg-current/15 px-1.5 py-0.5 text-start focus-visible:outline focus-visible:outline-2 focus-visible:outline-accent ${dayKindColor(e.kind)}`}
    >
      <span className="flex items-center gap-1 text-[11px] font-semibold text-pn">
        <span dir="auto" className="min-w-0 truncate">{title}</span>
        {e.alerted && <BellSimple size={10} aria-hidden="true" className="shrink-0 text-pn-muted" />}
        {e.repeating && <Repeat size={10} aria-hidden="true" className="shrink-0 text-pn-muted" />}
        {e.space === 'work' && <SPACE_ICONS.work size={10} aria-hidden="true" className="shrink-0 text-pn-muted" />}
      </span>
      {start && <span className="block truncate text-[10.5px] text-pn-muted tabular-nums">{end ? `${start} - ${end}` : start}</span>}
    </button>
  );
}
