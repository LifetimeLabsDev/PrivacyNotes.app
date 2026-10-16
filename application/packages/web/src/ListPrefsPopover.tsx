import { useContext, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import { createPortal } from 'react-dom';
import { useEscapeToClose } from './useEscapeToClose';
import { HoverLabel, TIP_SKIN } from './HoverLabel';
import { Switch } from './Switch';
import { ViewModeContext, setDeviceCompactRows, useCompactRows } from './viewMode';
import { ViewModeToggle } from './ViewModeToggle';
import type { Space } from './spaces';
import { SPACE_ICONS } from './SpaceSwitch';
import { setCalendarShowsOther, setJournalCalendarShown, useCalendarShowsOther, useJournalCalendarShown } from './JournalCalendar';
import { X, Question, ArrowsInLineVertical, Article, Calendar, Rows, Clock, HardDrive, PencilSimpleSlash, Shield, SortAscending, SortDescending, Tag, TextAlignJustify } from './icons';
import {
  resolvePrefs,
  setPillarPrefs,
  type ListPrefs,
  type ListPrefsStore,
  type Pillar,
  type SortField,
} from './listPrefs';

/**
 * Preferences popover for the notes list:
 *   - LAYOUT: Auto / List / Grid, this device only (viewMode.ts), and in
 *     Journals Show calendar (device-local, like the layout)
 *   - SORT BY: Modified / Created / Title + asc/desc arrow
 *   - VIEW: Show preview (+ Longer preview text) / Show date / Show tags, plus
 *     Show file size in the lists whose rows print one (`showSizeToggle`)
 *   - OTHER: Show read-only / Show protected
 * Every switch carries an accent icon, as the menus across the app do.
 *
 * Two pillar-specific switches deliberately do NOT live here: Files' "Show
 * notes with attachments" and Bookmarks' "Show links from notes". Each pillar
 * already draws its own inline row for it under the search bar, and one switch
 * in two places is one place too many (2026-08-25).
 *
 * Edits the copy the pane in front of you READS - `pillar`, defaulting to the
 * shared Global copy. This used to write Global unconditionally while every
 * list rendered from `resolvePrefs(store, pillar)`, so the moment a pillar
 * owned a copy the menu edited something that pillar no longer read: in Files,
 * one flip of the attachments toggle left "Show preview" reading ON in the
 * menu with the list stuck OFF forever. Passing the pillar is what keeps a
 * switch and its list from disagreeing.
 *
 * The store lives in UserSettings so changes sync across devices via
 * the encrypted user_settings pipeline.
 */
type Props = {
  /** Live prefs store - owner keeps this in sync with UserSettings. */
  store: ListPrefsStore;
  /** Called with the next store on every edit. Owner persists it. */
  onChange: (next: ListPrefsStore) => void;
  /** Called when the user clicks outside or presses Escape. */
  onClose: () => void;
  /** Anchor element - clicks on the trigger don't count as "outside". */
  anchorRef?: React.RefObject<HTMLElement | null>;
  /**
   * Which copy of the prefs this menu edits. Defaults to the shared Global
   * copy, which is what Notes, Tasks, Markdown, All, Pinned and Trash use.
   * A pillar that owns its view (bookmarks, files, journal, vault) passes its
   * own name, and MUST be the same pillar its list renders from.
   */
  pillar?: Pillar;
  /** This list draws the calendar card: show its device switches. */
  calendarRows?: boolean;
  /** With Spaces on, the space that is not open: the calendar's switch
   *  shows or hides its items, and the row names it. */
  otherSpace?: Space | null;
  /** CSS classes merged onto the popover container. Positioning only. */
  className?: string;
  /** Hide the VIEW toggles section (preview, date, tags). */
  hideViewSection?: boolean;
  /**
   * Add "Show file size" to the VIEW section. Only the lists that print a size
   * on every row pass it, so the other pillars do not offer a switch for
   * something their rows never show.
   */
  showSizeToggle?: boolean;
  /**
   * Add "Show groups" to the VIEW section. Only the panes that draw group
   * headers pass it. Spec: ops/docs/plans/list-groups.md
   */
  showGroupsToggle?: boolean;
  /** Hide the OTHER toggles section (read-only, protected). */
  hideOtherSection?: boolean;
  /** Label for the title/name sort option. Defaults to "Title". */
  titleLabel?: string;
  /** Label for the created sort option, which Journals reads as the day each
   *  entry is for. Defaults to "Date created". */
  createdLabel?: string;
};

/** The menu's width (w-72) and its gap to the list pane. */
const MENU_W = 288;
const MENU_GAP = 8;

/** Where the menu sits beside its list pane, or null when the window has no
 *  room there. The end side of the pane: right, or left in a right-to-left
 *  language. */
function besideList(anchor: HTMLElement | null): { top: number; left: number } | null {
  const pane = anchor?.closest<HTMLElement>('.pn-list-panel');
  if (!anchor || !pane) return null;
  const a = anchor.getBoundingClientRect();
  const p = pane.getBoundingClientRect();
  if (p.width === 0) return null;
  const rtl = getComputedStyle(pane).direction === 'rtl';
  const room = rtl ? p.left : window.innerWidth - p.right;
  if (room < MENU_W + MENU_GAP * 2) return null;
  return { top: a.top, left: rtl ? p.left - MENU_GAP - MENU_W : p.right + MENU_GAP };
}

export function ListPrefsPopover({
  store,
  onChange,
  onClose,
  anchorRef,
  className = '',
  hideViewSection = false,
  hideOtherSection = false,
  showSizeToggle = false,
  showGroupsToggle = false,
  titleLabel,
  createdLabel,
  pillar = 'global',
  calendarRows = false,
  otherSpace = null,
}: Props) {
  const { t } = useTranslation('shell');
  // Read and write the SAME copy the pane's list renders from.
  const prefs: ListPrefs = resolvePrefs(store, pillar);
  const calendarShown = useJournalCalendarShown();
  // The switch belongs to the open space, the one that is not `otherSpace`.
  const openSpace: Space = otherSpace === 'personal' ? 'work' : 'personal';
  const showsOther = useCalendarShowsOther(openSpace);
  const resolvedTitleLabel = titleLabel ?? t('listPrefs.title');

  const layout = useContext(ViewModeContext);
  const compactRows = useCompactRows();
  const popoverRef = useRef<HTMLDivElement | null>(null);

  // Click-outside to close. Pointerdown beats click so drags don't
  // stay trapped, and we skip clicks inside the anchor (the button
  // that opened the popover) to avoid the open/close flicker.
  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (popoverRef.current && popoverRef.current.contains(target)) return;
      if (anchorRef?.current && anchorRef.current.contains(target)) return;
      onClose();
    }
    window.addEventListener('pointerdown', handler, true);
    return () => window.removeEventListener('pointerdown', handler, true);
  }, [onClose, anchorRef]);

  useEscapeToClose(onClose);

  // Every other overlay in the app caps its height; this one hangs off its
  // trigger, so a viewport unit cannot express the room it has. Measure the
  // top it was placed at and keep the bottom inside the window. The floor
  // keeps a trigger near the window bottom from opening a menu too short to
  // read, which then overflows the way it always did - the lesser of the two.
  const [maxHeight, setMaxHeight] = useState<number | null>(null);

  // Beside the list, not over it: the menu changes the rows, so it opens at
  // the list pane's end edge, level with its button, where every switch shows
  // its effect at once. Without room for it there (a phone, a narrow window)
  // it hangs off its button inside the pane, as the pane's className says.
  const [beside, setBeside] = useState<{ top: number; left: number } | null>(() => besideList(anchorRef?.current ?? null));
  // Measured again after every render as well: a layout switch in this very
  // menu re-renders it in the commit that moves the pane's edge. The state is
  // set only when the place changed, so this cannot loop.
  useLayoutEffect(() => {
    const next = besideList(anchorRef?.current ?? null);
    setBeside((cur) => (cur?.top === next?.top && cur?.left === next?.left ? cur : next));
  });
  useLayoutEffect(() => {
    const place = () => setBeside(besideList(anchorRef?.current ?? null));
    window.addEventListener('resize', place);
    // The pane moves its edge without a window resize: a switch to the grid
    // in this very menu widens it, and the menu must step aside with it.
    const pane = anchorRef?.current?.closest('.pn-list-panel');
    const ro = pane ? new ResizeObserver(place) : null;
    if (pane) ro!.observe(pane);
    return () => {
      window.removeEventListener('resize', place);
      ro?.disconnect();
    };
  }, [anchorRef]);

  useLayoutEffect(() => {
    const el = popoverRef.current;
    if (!el) return;
    function fit() {
      const top = el!.getBoundingClientRect().top;
      setMaxHeight(Math.max(240, window.innerHeight - top - 8));
    }
    fit();
    window.addEventListener('resize', fit);
    return () => window.removeEventListener('resize', fit);
  }, [beside]);

  function update<K extends keyof ListPrefs>(key: K, value: ListPrefs[K]) {
    const nextPrefs: ListPrefs = { ...prefs, [key]: value };
    onChange(setPillarPrefs(store, pillar, nextPrefs));
  }

  function setSort(field: SortField) {
    update('sortField', field);
  }

  function toggleDir() {
    update('sortDir', prefs.sortDir === 'asc' ? 'desc' : 'asc');
  }

  const panel = (
    <div
      ref={popoverRef}
      role="dialog"
      aria-label={t('listPrefs.listPreferences')}
      className={`z-50 w-72 rounded-lg border border-divider bg-surface-2 shadow-lg overflow-y-auto overscroll-contain ${beside ? '' : className}`}
      style={{
        ...(maxHeight === null ? {} : { maxHeight }),
        ...(beside ? { position: 'fixed' as const, top: beside.top, left: beside.left } : {}),
      }}
    >
      {/* Closing is one click away wherever the menu opens: beside the list it
          sits far from the button that opened it. Escape and a click outside
          still close it too. */}
      <button
        type="button"
        onClick={onClose}
        aria-label={t('common:actions.close')}
        className="absolute top-2 end-2 z-10 inline-flex items-center justify-center w-7 h-7 rounded-md text-pn-muted hover:text-pn hover:bg-pn/5 transition"
      >
        <X size={15} />
      </button>
      {/* ── LAYOUT ───────────────────────────────────────────────── */}
      {layout && (
      <div className="px-4 pt-3 pb-3 border-b border-divider">
        <div className="text-[10px] font-semibold tracking-wider text-pn-muted uppercase mt-1">
          {t('listPrefs.layout')}
        </div>
        {/* The note scopes the whole section, so it sits under the heading. */}
        <div className="mb-2 text-[11.5px] text-pn-muted">{t('listPrefs.layoutDeviceOnly')}</div>
        <ViewModeToggle mode={layout.mode} onChange={layout.set} />
        <div className="mt-2">
          <ToggleRow
            label={t('listPrefs.compactRows')}
            icon={<ArrowsInLineVertical aria-hidden="true" className="shrink-0" />}
            hint={<HelpTip text={t('listPrefs.compactRowsHint')} />}
            checked={compactRows}
            onChange={setDeviceCompactRows}
          />
        </div>
        {/* Device-local like the layout, so it sits here and outside the synced prefs. */}
        {calendarRows && (
          <div className="mt-2 space-y-0.5">
            <ToggleRow
              label={t('listPrefs.showCalendar')}
              icon={<Calendar aria-hidden="true" className="shrink-0" />}
              checked={calendarShown}
              onChange={setJournalCalendarShown}
            />
            {calendarShown && otherSpace && (
              <ToggleRow
                label={(
                  // The space's name in bold: the one word that changes with the open space.
                  <Trans
                    t={t}
                    i18nKey={otherSpace === 'work' ? 'listPrefs.showWorkItems' : 'listPrefs.showPersonalItems'}
                    components={{ b: <b className="font-semibold" /> }}
                  />
                )}
                icon={(() => { const Glyph = SPACE_ICONS[otherSpace]; return <Glyph aria-hidden="true" className="shrink-0" />; })()}
                checked={showsOther}
                onChange={(on) => setCalendarShowsOther(openSpace, on)}
              />
            )}
          </div>
        )}
      </div>
      )}

      {/* ── SORT BY ──────────────────────────────────────────────── */}
      <div className="px-4 pt-3 pb-2">
        <div className="text-[10px] font-semibold tracking-wider text-pn-muted uppercase mb-1.5 mt-1">
          {t('listPrefs.sortBy')}
        </div>
        <div className="space-y-0.5">
          <SortRow
            label={createdLabel ?? t('listPrefs.dateCreated')}
            active={prefs.sortField === 'created'}
            dir={prefs.sortField === 'created' ? prefs.sortDir : null}
            onSelect={() => setSort('created')}
            onToggleDir={toggleDir}
          />
          <SortRow
            label={t('listPrefs.dateModified')}
            active={prefs.sortField === 'modified'}
            dir={prefs.sortField === 'modified' ? prefs.sortDir : null}
            onSelect={() => setSort('modified')}
            onToggleDir={toggleDir}
          />
          <SortRow
            label={resolvedTitleLabel}
            active={prefs.sortField === 'title'}
            dir={prefs.sortField === 'title' ? prefs.sortDir : null}
            onSelect={() => setSort('title')}
            onToggleDir={toggleDir}
          />
          <SortRow
            label={t('listPrefs.size')}
            active={prefs.sortField === 'size'}
            dir={prefs.sortField === 'size' ? prefs.sortDir : null}
            onSelect={() => setSort('size')}
            onToggleDir={toggleDir}
          />
        </div>
      </div>

      {/* ── VIEW ─────────────────────────────────────────────────── */}
      {!hideViewSection && (
      <div className="px-4 pt-2 pb-3 border-t border-divider">
        <div className="text-[10px] font-semibold tracking-wider text-pn-muted uppercase mb-1.5 mt-1">
          {t('listPrefs.view')}
        </div>
        <div className="space-y-0.5">
          <ToggleRow
            label={t('listPrefs.showPreview')}
            icon={<Article aria-hidden="true" className="shrink-0" />}
            checked={prefs.showPreview}
            onChange={(v) => update('showPreview', v)}
          />
          {prefs.showPreview && (
            <ToggleRow
              label={t('listPrefs.longPreview')}
              icon={<TextAlignJustify aria-hidden="true" className="shrink-0" />}
              checked={prefs.longPreview}
              onChange={(v) => update('longPreview', v)}
            />
          )}
          <ToggleRow
            label={t('listPrefs.showDate')}
            icon={<Clock aria-hidden="true" className="shrink-0" />}
            checked={prefs.showDate}
            onChange={(v) => update('showDate', v)}
          />
          {showSizeToggle && (
            <ToggleRow
              label={t('listPrefs.showSize')}
              icon={<HardDrive aria-hidden="true" className="shrink-0" />}
              checked={prefs.showSize}
              onChange={(v) => update('showSize', v)}
            />
          )}
          <ToggleRow
            label={t('listPrefs.showTags')}
            icon={<Tag aria-hidden="true" className="shrink-0" />}
            checked={prefs.showTags}
            onChange={(v) => update('showTags', v)}
          />
          {showGroupsToggle && (
            <ToggleRow
              label={t('listPrefs.showGroups')}
              icon={<Rows aria-hidden="true" className="shrink-0" />}
              // The sort decides the groups; size has none, so the switch
              // waits for a sort that has some instead of claiming to be on.
              checked={prefs.showGroups && prefs.sortField !== 'size'}
              disabled={prefs.sortField === 'size'}
              description={
                prefs.sortField === 'size'
                  ? t('listPrefs.groupsNoneForSize')
                  : prefs.sortField === 'title'
                    ? t('listPrefs.groupsByLetter')
                    : t('listPrefs.groupsByDate')
              }
              onChange={(v) => update('showGroups', v)}
            />
          )}
        </div>
      </div>
      )}

      {/* ── OTHER ────────────────────────────────────────────────── */}
      {!hideOtherSection && (
      <div className="px-4 pt-2 pb-3 border-t border-divider">
        <div className="text-[10px] font-semibold tracking-wider text-pn-muted uppercase mb-1.5 mt-1">
          {t('listPrefs.other')}
        </div>
        <div className="space-y-0.5">
          <ToggleRow
            label={t('listPrefs.showReadOnly')}
            icon={<IconPencilSlash />}
            checked={prefs.showLocked}
            onChange={(v) => update('showLocked', v)}
          />
          <ToggleRow
            label={t('listPrefs.showProtected')}
            icon={<IconShield />}
            checked={prefs.showProtected}
            onChange={(v) => update('showProtected', v)}
          />
        </div>
      </div>
      )}
    </div>
  );
  return beside ? createPortal(panel, document.body) : panel;
}

/* ────────────────────────────────────────────────────────────────
 * Sub-components
 * ──────────────────────────────────────────────────────────────── */

export function SortRow({
  label,
  hint,
  active,
  dir,
  onSelect,
  onToggleDir,
}: {
  label: string;
  /**
   * One line under the label, shown only while the row is selected. The
   * folder tree's Custom order needs it: no single word says "drag the
   * folders around", and a label long enough to say it does not fit
   * beside two one-word siblings.
   */
  hint?: string;
  active: boolean;
  dir: 'asc' | 'desc' | null;
  onSelect: () => void;
  onToggleDir: () => void;
}) {
  const { t } = useTranslation('shell');
  return (
    <>
    <div className="flex items-center gap-2 py-1">
      <button
        type="button"
        onClick={onSelect}
        className="flex items-center gap-1.5 flex-1 text-start group"
      >
        <span
          // 14 px, the size of the switch rows' icons, so both columns of labels start at one edge.
          className={`shrink-0 w-3.5 h-3.5 rounded-full border-[1.5px] flex items-center justify-center transition ${
            active
              ? 'border-accent'
              : 'border-pn-muted/50 group-hover:border-pn-muted'
          }`}
        >
          {active && (
            <span className="w-1.5 h-1.5 rounded-full bg-accent-fill" aria-hidden />
          )}
        </span>
        <span className="text-[14px] text-pn">
          {label}
        </span>
      </button>
      {active && dir && (
        <HoverLabel label={dir === 'asc' ? t('listPrefs.ascending') : t('listPrefs.descending')} position="above">
        <button
          type="button"
          onClick={onToggleDir}
          aria-label={dir === 'asc' ? t('listPrefs.switchToDescending') : t('listPrefs.switchToAscending')}
          // -my-1: the button keeps its 28 px target without making its row taller than a switch row.
          className="shrink-0 flex items-center gap-1 px-1.5 h-7 -my-1 rounded hover:bg-pn/5 transition"
        >
          <span className="text-[11px] font-medium text-accent uppercase">{dir === 'asc' ? t('listPrefs.asc') : t('listPrefs.desc')}</span>
          {dir === 'asc' ? (
            <SortAscending className="text-accent" />
          ) : (
            <SortDescending className="text-accent" />
          )}
        </button>
        </HoverLabel>
      )}
    </div>
    {active && hint && (
      <div className="ps-5 pb-1 -mt-0.5 text-[11.5px] text-pn-muted">{hint}</div>
    )}
    </>
  );
}

/**
 * A "?" beside a label that shows a short explanation in a tooltip: on hover
 * with a pointer, and on a tap or click anywhere, which also works on a touch
 * screen with no hover. The next tap outside closes it; a blur cannot, because
 * a tapped button takes no focus on iOS. The button's name is the explanation
 * itself, so a screen reader reads it without opening anything.
 */
function HelpTip({ text }: { text: string }) {
  const [open, setOpen] = useState(false);
  const ref = useRef<HTMLSpanElement | null>(null);
  useEffect(() => {
    if (!open) return;
    const close = (e: PointerEvent) => {
      if (!ref.current?.contains(e.target as Node)) setOpen(false);
    };
    window.addEventListener('pointerdown', close, true);
    return () => window.removeEventListener('pointerdown', close, true);
  }, [open]);
  return (
    <span ref={ref} className="group/help relative inline-flex">
      <button
        type="button"
        aria-label={text}
        aria-expanded={open}
        // Inside the switch's label: the click must not toggle the switch.
        onClick={(e) => {
          e.preventDefault();
          e.stopPropagation();
          setOpen((o) => !o);
        }}
        // A 16px glyph with a 40px touch target, through an invisible ring.
        // 1px down: the lowercase of the label centers below its line box,
        // and a glyph centered on the box reads high beside it.
        className="relative translate-y-px inline-flex items-center justify-center w-4 h-4 rounded-full text-pn-muted hover:text-accent transition before:absolute before:-inset-3 before:content-['']"
      >
        <Question size={13} aria-hidden="true" />
      </button>
      <span
        aria-hidden="true"
        // rtl-ok: centered under the button, the same in both directions
        className={`pointer-events-none absolute top-full left-1/2 -translate-x-1/2 mt-1.5 z-20 w-max max-w-[160px] ${TIP_SKIN} font-normal transition-opacity duration-75 ${
          open ? 'opacity-100' : 'opacity-0 [@media(hover:hover)]:group-hover/help:opacity-100'
        }`}
      >
        {text}
      </span>
    </span>
  );
}

function ToggleRow({
  label,
  icon,
  checked,
  disabled,
  description,
  hint,
  onChange,
}: {
  label: React.ReactNode;
  icon?: React.ReactNode;
  checked: boolean;
  disabled?: boolean;
  description?: string;
  hint?: React.ReactNode;
  onChange: (v: boolean) => void;
}) {
  return (
    <Switch
      label={label}
      hint={hint}
      icon={icon && <span className="inline-flex text-accent">{icon}</span>}
      checked={checked}
      disabled={disabled}
      // Indented past the icon, so the hint lines up with the label it explains.
      description={description && <span className="block ps-5">{description}</span>}
      onChange={onChange}
      className="gap-2 py-1 select-none"
      labelClassName="flex items-center gap-1.5 text-[14px] text-pn"
    />
  );
}

/* ────────────────────────────────────────────────────────────────
 * Icons - match NoteOptionsMenu's lock / shield so users see the
 * same visual language in both places.
 * ──────────────────────────────────────────────────────────────── */

function IconPencilSlash() {
  return <PencilSimpleSlash aria-hidden="true" className="shrink-0" />;
}

function IconShield() {
  return <Shield aria-hidden="true" className="shrink-0" />;
}

// Re-export default prefs for convenience
