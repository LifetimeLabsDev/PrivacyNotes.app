import { useEffect, useLayoutEffect, useMemo, useRef, useState, type ReactNode, type RefObject } from 'react';
import { setCheckInCardShown } from './checkInCardSwitch';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import { closedMenuJustNow, type ContextMenuItem } from './ContextMenu';
import { HoverLabel } from './HoverLabel';
import { ArrowCounterClockwise, CalendarPlus, CheckCircle, EyeSlash, Gear, LockSimple, SkipForward, SlidersHorizontal, X } from './icons';
import { MonthGrid } from './MonthGrid';
import { MoodScale } from './MoodScale';
import { Button } from './ui';
import { TrackerPills } from './TrackerPills';
import type { TrackerSetupTab } from './TrackerConfig';
import { useToday } from './ListGroupHeader';
import { formatDay } from './intlFormat';
import { journalDateOf } from './notesViewUtils';
import { MoodMark } from './moodMark';
import { checkInEntry, checkInParts, checkInStreak, moodWord, setCheckInSkipped, useCheckInSkipped } from './checkIn';
import { rainConfetti } from './confettiRain';
import {
  BOOKKEEPING_KEYS,
  hasLoggedTrackers,
  type FactorDef,
  type JournalTrackerData,
  type MedicationTemplate,
  type TrackerSettings,
} from './trackerTypes';
import type { CheckInSettings } from './userSettings';

/**
 * The daily check-in card at the top of Journals, and of All while Journals
 * is shown there (GitHub #439). Every tap moves the check-in forward; no tap
 * only reveals the next step:
 *
 *  - At rest the mood scale is there (`MoodScale`: 1 to 10 in the band
 *    colors), so one tap logs the mood.
 *  - That tap folds the scale into one line (the number on its chip, the
 *    band's word, Change to reopen the tiles) and opens the guided pass: the
 *    first tracker without a value opens its picker, a picker that commits
 *    opens the next one, and Next or Finish move on from the ones that take
 *    several values. The pass is always on; there is no switch for it.
 *  - Finish or Done fold the card to one line with what was
 *    logged and a short pop; a tap on that line opens the pass again.
 *
 * Every write goes through the editor's tracker handler (`onSave`), so the
 * entry, its history and its sync behave as if the entry's own pills were
 * used. An entry behind its PIN or set read-only is never read or written
 * here: the card shows a lock, and a tap opens the entry and its gate.
 * Spec: ops/issues/0439.md (Spec), ops/docs/archive/ui-patterns.md section 141
 */
type Props = {
  grid: boolean;
  /** The live items of the open space; the card finds the day's entry here. */
  notes: readonly LocalNote[];
  /** Whether the PIN guards an entry right now. */
  isGated: (n: LocalNote) => boolean;
  settings: CheckInSettings;
  onSettingsChange: (next: CheckInSettings) => void;
  trackerSettings: TrackerSettings;
  onTrackerSettingsChange: (next: TrackerSettings) => void;
  medications: MedicationTemplate[];
  factors: FactorDef[];
  isPro: boolean;
  onOpenUpgrade?: () => void;
  /** Merge `patch` into the day's entry, creating the entry when there is none. */
  onSave: (day: string, patch: JournalTrackerData) => Promise<void>;
  /** Open the day's entry in the editor, creating it when there is none. */
  onOpenDay: (day: string) => void;
  onOpenSettings: () => void;
  /** Opens Settings > Trackers on a tab: the one tracker setup. */
  onOpenTrackers: (tab: TrackerSetupTab) => void;
  /** The app's context menu, so the gear's rows look like every other menu. */
  openMenu?: (
    e: { clientX: number; clientY: number; preventDefault: () => void; stopPropagation: () => void },
    items: ContextMenuItem[],
    keyboard?: boolean,
    clear?: () => { top: number; bottom: number },
    alignEnd?: boolean,
  ) => void;
};

type Notice = 'skipped' | 'hidden' | 'cleared' | null;

/** A card at least this wide puts the open tracker beside the pills, in a
 *  column of the panel's width, so Next stays at the panel's edge. */
const SPLIT = 900;

/** After Finish the card stays open this long with its success state, as
 *  long as the confetti falls, then folds to the streak line. */
const OPEN_MS = 5000;
/** How long the folded card shows the streak line after Finish, counted
 *  from the Finish. */
const CELEBRATE_MS = 10000;

export function CheckInCard(p: Props) {
  const { t } = useTranslation('shell');
  const today = useToday();
  const skipped = useCheckInSkipped(today);
  const [day, setDay] = useState(today);
  const [flowOpen, setFlowOpen] = useState(false);
  // The tiles, reopened under the summary line with Change.
  const [scaleOpen, setScaleOpen] = useState(false);
  const [calOpen, setCalOpen] = useState(false);
  const [notice, setNotice] = useState<Notice>(null);
  // What "Start over" cleared, so its Undo can write it back.
  const cleared = useRef<{ day: string; data: JournalTrackerData } | null>(null);
  const [popKey, setPopKey] = useState(0);
  // The reward after every Finish: the streak line on the folded card, and
  // its number moving up to today's count a beat after the fold. A counter,
  // so a Finish inside the window starts the line over.
  const [celebration, setCelebration] = useState(0);
  const [counted, setCounted] = useState(false);
  // The open success state of the first seconds, before the fold.
  const [cheering, setCheering] = useState(false);
  const [root, setRoot] = useState<HTMLLIElement | null>(null);
  const rootRef = useRef<HTMLLIElement | null>(null);
  // The prompt sits above the scale at every width. A grid tile keeps the
  // open tracker under the pills; the split layout is for the band across
  // the list.
  const width = useWidth(root);
  const split = !p.grid && width >= SPLIT;

  useEffect(() => {
    if (celebration === 0) return;
    setCounted(false);
    setCheering(true);
    const still = window.matchMedia?.('(prefers-reduced-motion: reduce)').matches;
    const up = window.setTimeout(() => setCounted(true), still ? 0 : 420);
    const close = window.setTimeout(() => { setCheering(false); fold(); }, OPEN_MS);
    const end = window.setTimeout(() => { setCelebration(0); setCounted(false); }, CELEBRATE_MS);
    return () => { window.clearTimeout(up); window.clearTimeout(close); window.clearTimeout(end); };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the timers belong to one celebration
  }, [celebration]);

  // A new day starts on today, at rest.
  useEffect(() => {
    setDay(today);
    setFlowOpen(false);
    setCalOpen(false);
  }, [today]);

  function fold() {
    setFlowOpen(false);
    setScaleOpen(false);
    setCalOpen(false);
  }

  // Only Done and Finish fold the card. A tap outside or an Escape folded it
  // too, and a click elsewhere on the page or an Escape meant for a dialog
  // over it ended the pass the person was in the middle of.

  // A hide waits out its Undo and lands on unmount at the latest, on this
  // device's switch (checkInCardSwitch.ts).
  const pendingHide = useRef(false);
  const landHide = () => {
    if (!pendingHide.current) return;
    pendingHide.current = false;
    setCheckInCardShown(false);
  };
  useEffect(() => {
    if (notice === null) return;
    const timer = window.setTimeout(() => {
      if (notice === 'hidden') landHide();
      pendingHide.current = false;
      setNotice(null);
    }, 6000);
    return () => window.clearTimeout(timer);
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the timer belongs to the notice
  }, [notice]);
  useEffect(() => () => landHide(),
    // eslint-disable-next-line react-hooks/exhaustive-deps -- unmount only
    []);

  const journalDays = useMemo(() => {
    const days = new Set<string>();
    for (const n of p.notes) {
      if (n.type !== 'journal' || n.deleted !== 0 || n.trashed !== 0) continue;
      const d = journalDateOf(n);
      if (d) days.add(d);
    }
    return days;
  }, [p.notes]);

  const shell = (children: ReactNode, line = false) => (
    <Shell grid={p.grid} line={line} rootRef={rootRef} onRoot={setRoot}>{children}</Shell>
  );

  const noticeLine = notice && (
      <div className="flex items-center gap-2 min-h-8 text-[13px] text-pn-muted">
        <span className="min-w-0 flex-1 truncate">{notice === 'skipped' ? t('checkIn.skipped') : notice === 'cleared' ? t('checkIn.cleared') : t('checkIn.hidden')}</span>
        <button
          type="button"
          onClick={() => {
            if (notice === 'skipped') setCheckInSkipped(false);
            if (notice === 'cleared' && cleared.current) void p.onSave(cleared.current.day, cleared.current.data);
            pendingHide.current = false;
            setNotice(null);
          }}
          className="shrink-0 rounded-md px-2 py-1 text-[13px] font-medium text-accent hover:bg-accent/10"
        >
          {t('checkIn.undo')}
        </button>
      </div>
  );
  // Skip and hide take the card away, so the line stands alone until its Undo
  // runs out. Start over keeps the card: the line sits on top of the fresh
  // scale, so the next tap can log again at once.
  if (notice && notice !== 'cleared') return shell(noticeLine, true);
  if (skipped) return null;

  const entry = checkInEntry(p.notes, day);
  const guarded = !!entry && (p.isGated(entry) || entry.locked === 1);
  const data = (entry && !guarded ? (entry.trackers as JournalTrackerData | undefined) : undefined) ?? {};
  const mood = typeof data.mood === 'number' ? data.mood : null;
  const logged = hasLoggedTrackers(data as Record<string, unknown>, false);
  const isToday = day === today;
  const dayLabel = formatDay(day, 'tile');
  const prompt = isToday ? t('checkIn.prompt') : t('checkIn.promptOn', { date: dayLabel });
  // The pass needs at least one tracker besides the mood.
  const hasPass = p.trackerSettings.activeBuiltins.some((id) => id !== 'mood');

  async function pick(value: number) {
    if (mood === value) {
      // The chosen value again clears the mood: the card's undo.
      await p.onSave(day, { mood: undefined });
      return;
    }
    // A new pick ends the Undo of Start over: it would write the old day back.
    if (notice === 'cleared') setNotice(null);
    await p.onSave(day, { mood: value });
    setPopKey((k) => k + 1);
    setCalOpen(false);
    setScaleOpen(false);
    setFlowOpen(hasPass);
  }

  function finish() {
    setPopKey((k) => k + 1);
    // Only a check-in of today earns the reward: a day logged after the
    // fact builds the run but never celebrates it. The reward folds the
    // card itself, once the confetti has fallen.
    if (isToday && logged) {
      setCelebration((n) => n + 1);
      if (rootRef.current) rainConfetti(rootRef.current.getBoundingClientRect());
      return;
    }
    fold();
    if (!isToday) setDay(today);
  }

  function openGear(e: React.MouseEvent<HTMLButtonElement>) {
    if (closedMenuJustNow(e.currentTarget)) return;
    const r = e.currentTarget.getBoundingClientRect();
    const rtl = document.documentElement.dir === 'rtl';
    // One menu for Journals and All. "Hide this card" is the one card switch
    // (Show check-in in the list options), off; the toast's Undo takes
    // it back.
    const items: ContextMenuItem[] = [
      { label: t('checkIn.skipToday'), icon: <SkipForward size={14} />, onSelect: () => { fold(); setCheckInSkipped(true); setNotice('skipped'); } },
      { label: t('checkIn.anotherDay'), icon: <CalendarPlus size={14} />, onSelect: () => setCalOpen(true) },
      { label: t('checkIn.chooseTrackers'), icon: <SlidersHorizontal size={14} />, onSelect: () => p.onOpenTrackers('trackers') },
      // Clears the mood and every tracker value of the day; the entry's text
      // and its bookkeeping (the date) stay. The notice offers Undo, which writes them back.
      ...(logged ? [{ label: t('checkIn.startOver'), icon: <ArrowCounterClockwise size={14} />, onSelect: () => {
        const keep = { ...data };
        const patch: JournalTrackerData = {};
        for (const key of Object.keys(data)) {
          if (BOOKKEEPING_KEYS.has(key)) delete (keep as Record<string, unknown>)[key];
          else (patch as Record<string, unknown>)[key] = undefined;
        }
        cleared.current = { day, data: keep };
        void p.onSave(day, patch);
        fold();
        setNotice('cleared');
      } }] : []),
      { type: 'separator' },
      { label: t('checkIn.hide'), icon: <EyeSlash size={14} />, onSelect: () => { fold(); pendingHide.current = true; setNotice('hidden'); } },
      { label: t('checkIn.settings'), icon: <Gear size={14} />, onSelect: p.onOpenSettings },
    ];
    p.openMenu?.(
      { clientX: rtl ? r.left : r.right, clientY: r.bottom + 4, preventDefault: () => {}, stopPropagation: () => {} },
      items,
      e.detail === 0,
      undefined,
      !rtl,
    );
  }

  // In a narrow prompt row a mouse reveals the gear on hover, over the end of
  // the prompt, so the question keeps the whole row; a finger always sees it.
  // The negative end margin puts the glyph, not the button's padding, on the
  // edge the tiles end at (8px of a 32px button, 12px of a 40px one).
  const gear = (
    <span className="shrink-0 -me-2 [@media(hover:none)]:-me-3 rounded-md bg-surface-2 transition-opacity @max-[239.98px]/checkin:[@media(hover:hover)]:absolute @max-[239.98px]/checkin:[@media(hover:hover)]:end-0 @max-[239.98px]/checkin:[@media(hover:hover)]:opacity-0 @max-[239.98px]/checkin:[@media(hover:hover)]:group-hover/checkin:opacity-100 @max-[239.98px]/checkin:[@media(hover:hover)]:focus-within:opacity-100">
      <HoverLabel label={t('checkIn.options')} position="below-end">
        <button
          type="button"
          onClick={openGear}
          aria-label={t('checkIn.options')}
          aria-haspopup="menu"
          className="inline-flex items-center justify-center w-8 h-8 [@media(hover:none)]:w-10 [@media(hover:none)]:h-10 rounded-md text-pn-muted hover:text-pn-soft hover:bg-pn/5 transition"
        >
          <Gear size={16} aria-hidden="true" />
        </button>
      </HoverLabel>
    </span>
  );

  // Another day: the day, and the way back to today.
  const dayChip = !isToday && (
    <span className="shrink-0 inline-flex items-center gap-0.5 rounded-full border border-accent/50 ps-2.5 pe-1 h-7 text-[12px] font-medium text-accent whitespace-nowrap">
      {dayLabel}
      <button
        type="button"
        onClick={() => { setDay(today); fold(); }}
        aria-label={t('checkIn.backToToday')}
        className="inline-flex items-center justify-center w-5 h-5 rounded-full hover:bg-accent/15"
      >
        <X size={11} aria-hidden="true" />
      </button>
    </span>
  );

  const calendar = calOpen && (
    <div className="mt-2 max-w-[300px]">
      <MonthGrid
        marked={{ has: (d) => journalDays.has(d) }}
        selected={day}
        initialMonth={day}
        weeks={6}
        onPick={(d) => { setDay(d); setCalOpen(false); setFlowOpen(false); }}
      />
    </div>
  );

  const scale = (
    <MoodScale
      value={mood}
      onPick={(n) => void pick(n)}
      label={prompt}
      // Full width in the band across a list; a grid tile keeps the cap.
      className={p.grid ? 'w-full max-w-[420px]' : 'w-full'}
    />
  );

  // An entry the PIN or read-only guards: a lock, and the way to the entry.
  if (guarded) {
    return shell(
      <div className="flex items-center gap-2 min-h-8">
        <button
          type="button"
          onClick={() => p.onOpenDay(day)}
          className="min-w-0 flex-1 flex items-center gap-2 text-start text-[13px] text-pn-muted"
        >
          <span className="min-w-0 truncate">{isToday ? t('checkIn.locked') : t('checkIn.lockedOn', { date: dayLabel })}</span>
          <LockSimple size={16} aria-hidden="true" className="shrink-0" />
        </button>
        {dayChip}
        {gear}
      </div>,
      true,
    );
  }

  // The streak of the reward: today's count, and the last seven days as dots
  // with today last, so a run of any length keeps one width. The count and
  // today's dot move up a beat after Finish.
  const streak = celebration > 0 && isToday ? checkInStreak(p.notes, today, p.isGated) : null;
  const streakLabel = streak && (streak.run <= 1
    ? t('checkIn.streakFirst')
    : t('checkIn.streak', { n: counted ? streak.run : streak.run - 1 }));
  const streakDots = streak && (
    <span className="flex gap-1" aria-hidden="true">
      {streak.week.map((on, i) => {
        const lit = i === 6 ? on && counted : on;
        return <span key={i} className={`h-2 w-2 rounded-full ${lit ? 'bg-success' : 'bg-divider'} ${i === 6 && lit ? 'pn-pop' : ''}`} />;
      })}
    </span>
  );

  // Folded: what was logged, on one line. A tap opens the pass again.
  if (!flowOpen && logged) {
    const parts = checkInParts(data, p.trackerSettings, p.factors);
    return shell(
      <>
        <div className="flex items-center gap-2 min-h-8">
          <button
            type="button"
            onClick={() => setFlowOpen(true)}
            aria-label={t('checkIn.edit')}
            className="min-w-0 flex-1 flex items-center gap-2 text-start text-[13px]"
          >
            {mood !== null && <MoodMark mood={mood} size={26} />}
            {streak ? (
              <span className="min-w-0 leading-tight">
                <span className="block truncate font-semibold text-pn">{streakLabel}</span>
                <span className="mt-1 block">{streakDots}</span>
              </span>
            ) : (
              <>
                {mood !== null && <span className="shrink-0 font-semibold text-pn">{moodWord(mood)}</span>}
                {parts.length > 0 && <span className="min-w-0 truncate text-pn-muted">{(mood !== null ? '· ' : '') + parts.join(' · ')}</span>}
              </>
            )}
            <CheckCircle size={streak ? 22 : 16} weight="fill" aria-hidden="true" key={popKey} className={`shrink-0 text-success ${popKey ? 'pn-pop' : ''}`} />
          </button>
          {dayChip}
          {gear}
        </div>
        {calendar}
      </>,
      true,
    );
  }

  // At rest the scale is there to tap; in the pass it folds into a summary
  // line, and Change brings the tiles back under it.
  const writeLink = mood !== null && (
    <button
      type="button"
      onClick={() => p.onOpenDay(day)}
      className="min-w-0 truncate text-[12.5px] text-accent hover:underline"
    >
      {isToday ? t('checkIn.write') : t('checkIn.writeOn', { date: dayLabel })}
    </button>
  );
  const inPass = flowOpen && mood !== null;
  // The success state while the confetti falls: the big check, the words and
  // the streak, where the step bar and the open panel were.
  const cheer = cheering && streak && (
    <div role="status" className={`flex items-center gap-3.5 pb-1 ${split ? '' : 'mt-4 border-t border-divider pt-3'}`}>
      <CheckCircle size={56} weight="fill" aria-hidden="true" className="shrink-0 text-success pn-pop" />
      <span className="min-w-0 leading-tight">
        <span className="block text-base font-semibold text-pn">{t('checkIn.allDone')}</span>
        <span className="mt-0.5 block text-[13px] text-pn-muted">{t('checkIn.niceWork')}</span>
        <span className="mt-1.5 flex items-center gap-2 text-xs text-pn-muted">
          <span key={counted ? 'now' : 'before'} className={`inline-block ${counted ? 'pn-pop' : ''}`}>{streakLabel}</span>
          {streakDots}
        </span>
      </span>
    </div>
  );
  // The trackers' step bar carries Done beside Next; the summary line has
  // its own Done only when there is no step bar to hold it.
  const pills = inPass && hasPass && !!entry;
  const done = inPass && !pills && (
    <Button action="done" onClick={finish} className="shrink-0">
      {t('checkIn.done')}
    </Button>
  );
  const promptLine = <span className="min-w-0 truncate text-[13px] font-medium text-pn">{prompt}</span>;
  // One line at every list width: the chip, the word and Saved on the start,
  // the gear on the end; the chip itself reopens the tiles. Only the word
  // yields, and only on a card narrower than the list pane allows.
  const summary = inPass && (
    <div className="flex items-center gap-2 min-h-8">
      {/* The chip is the way back to the tiles: a tap shows them under the
          line, a second tap hides them. */}
      <button
        type="button"
        onClick={() => setScaleOpen((o) => !o)}
        aria-expanded={scaleOpen}
        aria-label={t('checkIn.change')}
        className="shrink-0 rounded-md outline-none transition hover:brightness-110 focus-visible:ring-2 focus-visible:ring-accent"
      >
        <MoodMark mood={mood} size={28} className={scaleOpen ? 'ring-2 ring-accent ring-offset-1 ring-offset-surface-2' : ''} />
      </button>
      <span className="min-w-0 flex-1 leading-tight">
        <span className="block truncate text-[13px] font-semibold text-pn">{moodWord(mood)}</span>
        <span className="flex items-center gap-1 text-[11px] text-success">
          <CheckCircle size={12} weight="fill" aria-hidden="true" key={popKey} className={popKey ? 'pn-pop' : ''} />
          {t('checkIn.saved')}
        </span>
      </span>
      <span className="flex shrink-0 items-center gap-0.5">
        {dayChip}
        {done}
        {gear}
      </span>
    </div>
  );

  return shell(
    <>
      {notice === 'cleared' && <div className="-mt-1 mb-1">{noticeLine}</div>}
      {inPass ? (
        <>
          {summary}
          {scaleOpen && <div className="pt-2">{scale}</div>}
          {!pills && cheer}
        </>
      ) : (
        // The prompt, the scale and the gear sit as one block in the middle
        // of the card, the gear above the 10, like the calendar below it.
        <div className={`@container/checkin group/checkin mx-auto my-auto w-full ${p.grid ? 'max-w-[420px]' : ''}`}>
          <div className="relative flex items-center gap-2 min-h-8">
            {promptLine}
            <span className="flex-1" />
            {dayChip}
            {gear}
          </div>
          {/* At rest the tiles are one neutral color, so the bands do not sit
              on every theme all day; a hover or the keyboard on the card
              shows them, and so does the open card after a pick. */}
          <div className="pt-1.5 [--pn-tile-shown:var(--color-surface-0)] group-hover/checkin:[--pn-tile-shown:initial] group-focus-within/checkin:[--pn-tile-shown:initial]">{scale}</div>
        </div>
      )}
      {calendar}
      {pills && entry && (
        // While the success state shows, the pills are there to look at only.
        <div className="pt-2.5" inert={cheering || undefined}>
          <TrackerPills
            key={day}
            variant="card"
            exclude={['mood']}
            data={data}
            onChange={(next) => void p.onSave(day, next)}
            trackerSettings={p.trackerSettings}
            onSettingsChange={p.onTrackerSettingsChange}
            medications={p.medications}
            factors={p.factors}
            isPro={p.isPro}
            onOpenUpgrade={p.onOpenUpgrade}
            flow={{ onFinish: finish, extra: writeLink, done: cheer || undefined }}
            onOpenSetup={p.onOpenTrackers}
            split={split}
          />
        </div>
      )}
    </>,
  );
}

/** The width of an element, kept current. */
function useWidth(el: HTMLElement | null): number {
  const [width, setWidth] = useState(0);
  useLayoutEffect(() => {
    if (!el) return;
    setWidth(el.getBoundingClientRect().width);
    if (typeof ResizeObserver === 'undefined') return;
    const ro = new ResizeObserver((entries) => setWidth(entries[0]?.contentRect.width ?? 0));
    ro.observe(el);
    return () => ro.disconnect();
  }, [el]);
  return width;
}

/** The card's frame: a band across the list. In the grid it is a tile two
 *  columns wide that the other tiles fill in around (the span is in
 *  index.css), and a one-line state is a strip across the grid, so a short
 *  line never sits in a tall empty tile. */
function Shell({ grid, line, rootRef, onRoot, children }: { grid: boolean; line: boolean; rootRef: RefObject<HTMLLIElement | null>; onRoot: (el: HTMLLIElement | null) => void; children: ReactNode }) {
  return (
    <li
      ref={(el) => {
        rootRef.current = el;
        onRoot(el);
      }}
      data-checkin-card=""
      className={
        grid
          ? `${line ? 'col-span-full' : 'pn-grid-checkin flex flex-col'} min-w-0 rounded-xl border border-divider bg-surface-2 px-3 py-2.5`
          : 'min-w-0 px-4 py-2.5 bg-surface-2 border-b border-divider'
      }
    >
      {children}
    </li>
  );
}
