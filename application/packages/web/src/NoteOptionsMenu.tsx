import { useEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import { useEscapeToClose } from './useEscapeToClose';
import { proUnlocked } from './demo';
import { noteActionGuards, type NoteActionGuardDeps } from './noteActionGuards';
import { usePopoverPosition } from './usePopoverPosition';
import { formatInstant } from './intlFormat';
import { prepareBurnPayload } from './burnShare';
import { ColorSwatch } from './ColorSwatch';
import { LOOK_COLORS, NOTE_NO_COLOR, type LookColor, type NoteOwnColor } from './itemStyles';
import { PencilSimpleSlash, Shield, ClockCounterClockwise, PushPin, Export, Trash, Repeat, Copy, Folder, Fire, ArrowCounterClockwise, FileMd, TextAa, Swap, ListChecks, Broom, SortAscending, Palette, Info, CaretLeft, CaretRight, Calendar, Check, PILLAR_GLYPHS, iconArchive } from './icons';
import { CONVERT_TARGETS, isConvertSource, type ConvertTarget } from './noteTypes';

/**
 * Per-note options dropdown, anchored to the "..." button in the
 * editor top bar. It is the ONE surface that carries every per-note
 * action, at every width.
 *
 * Layout, top to bottom: a strip of the three most-used actions (pin,
 * burn, duplicate, plus share where the header hides its own copy), the
 * color row, the editor rows, the organising rows, the per-note state
 * rows, the details row, and trash as the last, red row on its own.
 * The rows carry a label and at most a short value; the longer
 * explanations live with each feature, not here, so the menu fits a
 * short phone screen.
 *
 * Color, Entry date, Convert to and Details open a second view inside the same popover, with a
 * Back row, rather than a second floating layer. Escape and the Android
 * back button step back from that view before they close the menu.
 *
 * The markdown switch has a second home under the word count, a small
 * grey link that is easy to miss, which is why it is repeated here. Both
 * surfaces flip the same per-note, session-only override; neither writes
 * the synced default in Settings > Editor.
 *
 * In the trash view the menu carries Restore and Delete forever and
 * nothing else - the same two actions, the same two colours and the
 * same glyphs as the right-click menu on a trashed row.
 *
 * The Pro rows stay tappable for a free user: the tap opens the
 * UpgradeModal instead of applying the change, so the features are
 * discoverable without the free UI feeling crippled.
 * Spec: ops/docs/ui-patterns.md (section 80)
 */
export interface NoteColorInfo {
  /** The color set on the note itself; null when it takes its tag's or folder's. */
  own: NoteOwnColor | null;
  /** The color the note takes without its own, and where it comes from. */
  inherited: { color: LookColor; kind: 'tag' | 'folder'; name: string } | null;
}

/** "Move to Work" or "Move to Personal": the name, its glyph, and the move. */
export type SpaceMove = { label: string; icon: React.ReactNode; run: (ids: string[]) => void };

type Props = NoteActionGuardDeps & {
  /** The space move, while spaces are on. Spec: ops/docs/plans/spaces.md */
  spaceMove?: SpaceMove;
  /** Anchor so clicks on the "..." button don't count as outside. */
  anchorRef: React.RefObject<HTMLElement | null>;

  // Actions
  onDuplicate: () => void;
  /** Toggle pin/star. */
  onToggleStar?: () => void;
  /** Move to trash. */
  onTrash?: () => void;
  /** Archive or unarchive. */
  onToggleArchive?: () => void;
  /** Open share/export UI. Passed only where the header hides its own copy. */
  onShare?: () => void;
  /** Share and Burn After Reading. */
  onBurn?: () => void;
  /** Give the item another note-like type. */
  onConvertType?: (target: ConvertTarget) => void;
  /** The view the menu opens on. */
  initialView?: NoteOptionsView;
  /** Move a journal entry to another day. Journal entries only. */
  onSetJournalDate?: (day: string) => void;
  /** The days that hold a journal entry, dotted in the Entry date calendar. */
  journalDays?: JournalDays;
  /**
   * Body editor this note is currently showing. Absent wherever there is
   * no markdown editor to switch: bookmarks, vault items, a PIN-locked
   * note, and a read-only or trashed note (which is where the word-count
   * link hides too).
   */
  editorMode?: 'formatted' | 'markdown';
  /** Flip this note between the rich editor and the markdown source. */
  onToggleEditorMode?: () => void;
  /**
   * Open the find-and-replace bar. Present only while the note shows the
   * rich editor: the bar drives that editor's search plugin, which the
   * markdown textarea does not have. The Pro gate sits inside the editor,
   * one gate for this row and the keyboard shortcut.
   */
  onFindReplace?: () => void;
  /**
   * Uncheck every task in the note. Present only on an editable note with
   * more than one task and at least one of them checked.
   */
  onUncheckAllTasks?: () => void;
  /** Delete every checked task, after a confirm. Present only on an editable
   *  note with at least one checked task. */
  onDeleteCheckedTasks?: () => void;
  /** Put each task list in the order open first, checked after. Present only
   *  on an editable note where some list is out of that order. */
  onSortTasksByStatus?: () => void;
  /** The color row. Absent where a note has no color (vault items). */
  color?: NoteColorInfo;
  /** Pick a color, NOTE_NO_COLOR for none, or null to take the tag's or
   *  folder's again. Free: one note at a time; coloring a whole tag or
   *  folder is the Pro part. */
  onSetColor?: (color: NoteOwnColor | null) => void;
  /** Trash view: the menu carries only the two trash actions. */
  isTrash?: boolean;
  onRestore?: () => void;
  onDeleteForever?: () => void;
};

/** The name each convertible type goes by in the Convert to view. */
const TYPE_LABEL = {
  note: 'noteOptionsMenu.typeNote',
  journal: 'noteOptionsMenu.typeJournal',
  task: 'noteOptionsMenu.typeTask',
} as const;

/**
 * The Convert to view holds three short rows, so it takes the width of its
 * longest label instead of the 320px the main view needs. The menu stays
 * anchored by its end edge, so it narrows toward the "..." button.
 */
const CONVERT_WIDTH = 'w-max min-w-48';

/** A target wears the glyph of the pillar it moves the item to. */
const CONVERT_GLYPHS = {
  note: PILLAR_GLYPHS.notes,
  journal: PILLAR_GLYPHS.journals,
  task: PILLAR_GLYPHS.tasks,
} as const;

export type NoteOptionsView = 'main' | 'color' | 'details' | 'entryDate' | 'convert';

export function NoteOptionsMenu({
  note,
  isPro,
  onClose,
  anchorRef,
  onDuplicate,
  onSetLocked,
  onSetPinProtected,
  onOpenUpgrade,
  onRequestRemoveProtection,
  onOpenHistory,
  onToggleStar,
  onToggleArchive,
  onTrash,
  onShare,
  onBurn,
  onSetPin,
  onConvertType,
  initialView = 'main',
  onSetJournalDate,
  journalDays,
  onMoveToFolder,
  spaceMove,
  editorMode,
  onToggleEditorMode,
  onFindReplace,
  onUncheckAllTasks,
  onDeleteCheckedTasks,
  onSortTasksByStatus,
  color,
  onSetColor,
  isTrash,
  onRestore,
  onDeleteForever,
}: Props) {
  const { t } = useTranslation('shell');
  const { t: tEditor } = useTranslation('editor');
  const [view, setView] = useState<NoteOptionsView>(initialView);
  // A sub-view steps back first, so Escape never throws away the menu
  // the user drilled in from.
  useEscapeToClose(() => (view === 'main' ? onClose() : setView('main')));

  // The "Pro" badges below key off isPro, never the demo unlock, so the
  // menu keeps advertising the features the demo hands out for free.
  // The gates themselves are shared with the header's quick-action pill,
  // which offers the same four actions as bare icons on a wide pane.
  const unlocked = proUnlocked(isPro);
  const act = noteActionGuards({
    note, isPro, onClose, onSetLocked, onSetPinProtected, onRequestRemoveProtection,
    onOpenUpgrade, onOpenHistory, onSetPin, onMoveToFolder,
  });

  const ref = useRef<HTMLDivElement | null>(null);
  // Right-aligned dropdown under the "..." button. The hook measures the menu
  // (which changes height as items toggle) and keeps it on-screen, flipping
  // above when there's no room below. Spec: ops/docs/ui-patterns.md section 15.
  const pos = usePopoverPosition(true, anchorRef, ref, { align: 'end' });

  // Close on outside pointerdown. Anchor clicks are ignored so the
  // "..." button can toggle without a re-open flicker.
  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (ref.current && ref.current.contains(target)) return;
      if (anchorRef.current && anchorRef.current.contains(target)) return;
      onClose();
    }
    window.addEventListener('pointerdown', handler, true);
    return () => window.removeEventListener('pointerdown', handler, true);
  }, [onClose, anchorRef]);

  // Focus moves into the menu on open and on every view change, so the
  // arrow keys below have somewhere to start. The container takes it, not
  // the first row, so a mouse user sees no ring.
  useEffect(() => {
    ref.current?.focus({ preventScroll: true });
  }, [view]);

  function onKeyDown(e: React.KeyboardEvent) {
    if (!['ArrowDown', 'ArrowUp', 'Home', 'End'].includes(e.key)) return;
    const items = Array.from(
      ref.current?.querySelectorAll<HTMLButtonElement>('button:not([disabled])') ?? [],
    );
    if (items.length === 0) return;
    e.preventDefault();
    const i = items.indexOf(document.activeElement as HTMLButtonElement);
    const next =
      e.key === 'Home' ? 0
        : e.key === 'End' ? items.length - 1
          : e.key === 'ArrowDown' ? (i + 1) % items.length
            : i <= 0 ? items.length - 1 : i - 1;
    items[next]?.focus();
  }

  const showModeRow = !isTrash && !!onToggleEditorMode && !!editorMode;
  const showReplaceRow = !isTrash && !!onFindReplace;
  const showUncheckRow = !isTrash && !!onUncheckAllTasks;
  const showDeleteCheckedRow = !isTrash && !!onDeleteCheckedTasks;
  const showSortTasksRow = !isTrash && !!onSortTasksByStatus;
  const showTaskRows = showUncheckRow || showDeleteCheckedRow || showSortTasksRow;
  const showConvertRow = !!onConvertType && isConvertSource(note.type);

  const bytes = computeNoteTotalSize(note);
  // A media-only note has nothing left to send once images and files are
  // stripped, so the burn action refuses it. Dim the button rather than
  // let it fail on click. Spec: burnShare.ts (prepareBurnPayload).
  const burnable = prepareBurnPayload(note) !== null;

  const shownColor = color ? (color.own ?? color.inherited?.color ?? NOTE_NO_COLOR) : NOTE_NO_COLOR;
  const colorName = shownColor === NOTE_NO_COLOR ? t('noteOptionsMenu.colorNone') : tEditor(`color.names.${shownColor}`);

  return createPortal(
    <div
      ref={ref}
      role="dialog"
      tabIndex={-1}
      aria-label={t('noteOptionsMenu.noteOptions')}
      onKeyDown={onKeyDown}
      className={`fixed z-50 ${view === 'convert' ? CONVERT_WIDTH : 'w-80'} max-w-[calc(100vw-16px)] max-h-[calc(100dvh-16px)] overflow-y-auto overscroll-contain rounded-xl border border-divider bg-surface-2 shadow-lg outline-none divide-y divide-divider`}
      style={{
        top: pos?.top ?? 0,
        left: pos?.left ?? 0,
        visibility: pos ? 'visible' : 'hidden',
      }}
    >
      {/* Find-in-note deliberately does NOT live here: the magnifier sits in
          the editor's corner, on every note long enough to search. Find AND
          REPLACE does live here: it has no pill in the corner (GitHub #265)
          and no key on a phone, so its row is its only pointer path. Neither
          do a bookmark's Open/Copy or a vault item's Edit/Copy: those render
          inside the item itself, directly under this menu. */}
      {isTrash ? (
        <Group>
          {onRestore && (
            <ActionItem
              label={t('noteOptionsMenu.restore')}
              icon={<ArrowCounterClockwise size={16} aria-hidden="true" />}
              tone="success"
              onClick={() => { onRestore(); onClose(); }}
            />
          )}
          {onDeleteForever && (
            <ActionItem
              label={t('noteOptionsMenu.deleteForever')}
              icon={<Trash size={16} aria-hidden="true" />}
              tone="danger"
              onClick={() => { onDeleteForever(); onClose(); }}
            />
          )}
        </Group>
      ) : view === 'color' && color && onSetColor ? (
        <>
          <BackRow title={t('noteOptionsMenu.color')} onBack={() => setView('main')} />
          <NoteColorPanel color={color} onSetColor={onSetColor} />
        </>
      ) : view === 'entryDate' && onSetJournalDate ? (
        <>
          <BackRow title={t('noteOptionsMenu.entryDate')} onBack={() => setView('main')} />
          <div className="flex justify-center px-2 pt-3 pb-2">
            <MonthGrid
              key={note.id}
              marked={journalDays ?? new Set<string>()}
              selected={entryDayOf(note)}
              onPick={(day) => {
                if (day !== entryDayOf(note)) onSetJournalDate(day);
                setView('main');
              }}
            />
          </div>
        </>
      ) : view === 'convert' && showConvertRow ? (
        <>
          <BackRow title={t('noteOptionsMenu.convertTo')} onBack={() => setView('main')} />
          <Group>
            {CONVERT_TARGETS.map((target) => {
              const Glyph = CONVERT_GLYPHS[target];
              const current = note.type === target;
              return (
                <ActionItem
                  key={target}
                  label={t(TYPE_LABEL[target])}
                  icon={<Glyph size={16} aria-hidden="true" />}
                  disabled={current}
                  value={current ? <Check size={14} aria-hidden="true" /> : undefined}
                  onClick={() => { onConvertType?.(target); onClose(); }}
                />
              );
            })}
          </Group>
        </>
      ) : view === 'details' ? (
        <>
          <BackRow title={t('noteOptionsMenu.details')} onBack={() => setView('main')} />
          <div className="px-4 py-3 text-[13px] text-pn-muted space-y-1 leading-relaxed">
            <div>{t('noteOptionsMenu.lastModified', { date: formatInstant(editedAtOf(note), 'dateTime') })}</div>
            <div>{t('noteOptionsMenu.created', { date: formatInstant(note.createdAt, 'dateTime') })}</div>
            <div>
              {t('noteOptionsMenu.size', { size: formatBytes(bytes) })}
              {note.tags.length > 0 && <> · {t('noteOptionsMenu.tagCount', { count: note.tags.length })}</>}
            </div>
            <div className="text-[12px] text-pn-muted">{t('noteOptionsMenu.sizeHint')}</div>
          </div>
        </>
      ) : (
        <>
          {/* The three actions reached for most, as big targets. Share joins
              them only where the header hides its own copy (zen, a compact
              header), because two copies at one width would read as one
              control drawn twice. */}
          <div className="flex items-stretch p-1.5">
            {onToggleStar && (
              <StripButton
                label={note.starred === 1 ? t('noteOptionsMenu.unpin') : t('noteOptionsMenu.pin')}
                icon={<PushPin size={20} weight={note.starred === 1 ? 'fill' : 'bold'} aria-hidden="true" />}
                pressed={note.starred === 1}
                onClick={() => { onToggleStar(); onClose(); }}
              />
            )}
            {onBurn && (
              <StripButton
                label={t('noteOptionsMenu.burn')}
                icon={<Fire size={20} aria-hidden="true" />}
                tone="burn"
                disabled={!burnable}
                title={burnable ? undefined : t('notes:burn.mediaOnly')}
                onClick={() => { onBurn(); onClose(); }}
              />
            )}
            <StripButton
              label={t('noteOptionsMenu.duplicate')}
              icon={<Copy size={20} aria-hidden="true" />}
              onClick={() => { onDuplicate(); onClose(); }}
            />
            {onShare && (
              <StripButton
                label={t('noteOptionsMenu.share')}
                icon={<Export size={20} aria-hidden="true" />}
                onClick={() => { onShare(); onClose(); }}
              />
            )}
          </div>

          {color && onSetColor && (
            <Group>
              <ActionItem
                label={t('noteOptionsMenu.color')}
                icon={<Palette size={16} aria-hidden="true" />}
                value={
                  <span className="inline-flex items-center gap-2 min-w-0">
                    <span
                      aria-hidden
                      className="shrink-0 w-4 h-4 rounded-full border border-divider"
                      style={shownColor === NOTE_NO_COLOR ? undefined : { background: `var(--pn-label-${shownColor}-ink)` }}
                    />
                    <span className="truncate">{colorName}</span>
                  </span>
                }
                chevron
                onClick={() => setView('color')}
              />
            </Group>
          )}

          {(showModeRow || showReplaceRow || showTaskRows) && (
            <Group>
              {showModeRow && (
                <ActionItem
                  label={editorMode === 'markdown' ? t('notes:editor.showFormatted') : t('notes:editor.showMarkdown')}
                  // The glyph names the DESTINATION, so it changes with the label.
                  icon={editorMode === 'markdown' ? <TextAa size={17} aria-hidden="true" /> : <FileMd size={17} aria-hidden="true" />}
                  onClick={() => { onToggleEditorMode?.(); onClose(); }}
                />
              )}
              {showReplaceRow && (
                <ActionItem
                  label={t('noteOptionsMenu.findReplace')}
                  icon={<Swap size={16} aria-hidden="true" />}
                  pro={!isPro}
                  onClick={() => { onFindReplace?.(); onClose(); }}
                />
              )}
              {showUncheckRow && (
                <ActionItem
                  label={t('noteOptionsMenu.uncheckAllTasks')}
                  icon={<ListChecks size={16} aria-hidden="true" />}
                  onClick={() => { onUncheckAllTasks?.(); onClose(); }}
                />
              )}
              {showDeleteCheckedRow && (
                <ActionItem
                  label={t('noteOptionsMenu.deleteCheckedTasks')}
                  icon={<Broom size={16} aria-hidden="true" />}
                  onClick={() => { onDeleteCheckedTasks?.(); onClose(); }}
                />
              )}
              {showSortTasksRow && (
                <ActionItem
                  label={t('noteOptionsMenu.sortTasksByStatus')}
                  icon={<SortAscending size={16} aria-hidden="true" />}
                  onClick={() => { onSortTasksByStatus?.(); onClose(); }}
                />
              )}
            </Group>
          )}

          <Group>
            {onSetJournalDate && !isTrash && note.type === 'journal' && (
              <ActionItem
                label={t('noteOptionsMenu.entryDate')}
                icon={<Calendar size={16} aria-hidden="true" />}
                value={formatInstant(dayAtNoon(entryDayOf(note)), 'date')}
                chevron
                onClick={() => setView('entryDate')}
              />
            )}
            {onMoveToFolder && (
              <ActionItem
                label={t('noteOptionsMenu.moveToFolder')}
                icon={<Folder size={16} aria-hidden="true" />}
                pro={!isPro}
                onClick={act.moveToFolder}
              />
            )}
            {spaceMove && (
              <ActionItem
                label={spaceMove.label}
                icon={spaceMove.icon}
                onClick={() => { onClose(); spaceMove.run([note.id]); }}
              />
            )}
            <ActionItem
              label={t('noteOptionsMenu.noteHistory')}
              icon={<ClockCounterClockwise size={16} aria-hidden="true" />}
              pro={!isPro}
              disabled={unlocked && !onOpenHistory}
              value={unlocked && !onOpenHistory ? t('noteOptionsMenu.comingSoon') : undefined}
              onClick={act.openHistory}
            />
            {showConvertRow && (
              <ActionItem
                label={t('noteOptionsMenu.convertTo')}
                icon={<Repeat size={16} aria-hidden="true" />}
                chevron
                onClick={() => setView('convert')}
              />
            )}
          </Group>

          <Group>
            <ToggleItem
              label={t('noteOptionsMenu.readOnly')}
              icon={<PencilSimpleSlash size={16} aria-hidden="true" />}
              checked={note.locked === 1}
              pro={!isPro}
              onClick={act.toggleLock}
            />
            <ToggleItem
              label={t('noteOptionsMenu.protect')}
              icon={<Shield size={16} aria-hidden="true" />}
              checked={note.pinProtected === 1}
              pro={!isPro}
              onClick={act.toggleProtect}
            />
            {onToggleArchive && (
              <ActionItem
                label={note.archived === 1 ? t('noteOptionsMenu.unarchive') : t('noteOptionsMenu.archive')}
                icon={iconArchive(note.archived === 1, 16)}
                onClick={() => { onToggleArchive(); onClose(); }}
              />
            )}
          </Group>

          <Group>
            <ActionItem
              label={t('noteOptionsMenu.details')}
              icon={<Info size={16} aria-hidden="true" />}
              tone="muted"
              value={formatBytes(bytes)}
              chevron
              onClick={() => setView('details')}
            />
          </Group>

          {onTrash && (
            <Group>
              <ActionItem
                label={t('notes:editor.moveToTrash')}
                icon={<Trash size={16} aria-hidden="true" />}
                tone="danger"
                onClick={() => { onTrash(); onClose(); }}
              />
            </Group>
          )}
        </>
      )}
    </div>,
    document.body,
  );
}

/* ────────────────────────────────────────────────────────────────
 * Sub-items
 * ──────────────────────────────────────────────────────────────── */

/**
 * Colour of an item's icon. Blue is the standard; burn keeps the amber
 * it wears elsewhere, and anything that destroys keeps its red, so the
 * two actions worth a second thought are the two that stand out.
 */
type Tone = 'accent' | 'burn' | 'danger' | 'success' | 'muted';

const TONE_TEXT: Record<Tone, string> = {
  accent: 'text-accent',
  burn: 'text-orange-800 dark:text-orange-400',
  danger: 'text-danger',
  success: 'text-success',
  muted: 'text-pn-muted',
};

const ROW_TEXT: Record<Tone, string> = {
  accent: 'text-pn hover:bg-surface-1 focus-visible:bg-surface-1',
  burn: 'text-pn hover:bg-surface-1 focus-visible:bg-surface-1',
  muted: 'text-pn-muted hover:bg-surface-1 focus-visible:bg-surface-1',
  danger: 'text-danger hover:bg-red-50 dark:hover:bg-red-950/30 focus-visible:bg-red-50 dark:focus-visible:bg-red-950/30',
  success: 'text-success hover:bg-emerald-50 dark:hover:bg-emerald-950/30 focus-visible:bg-emerald-50 dark:focus-visible:bg-emerald-950/30',
};

/** Compact with a mouse, a full 44px finger target on a touch screen. */
const ROW = 'w-full flex items-center gap-3 px-4 min-h-9 py-1.5 [@media(hover:none)]:min-h-11 text-start text-[14px] outline-none transition';

/** One block between two hairlines. The dividers come from the parent. */
function Group({ children }: { children: React.ReactNode }) {
  return <div className="py-1">{children}</div>;
}

/** The quiet Pro marker: grey, no icon, never louder than the label. */
function ProBadge() {
  return (
    <span className="shrink-0 rounded-md px-1.5 py-0.5 text-[11px] font-medium leading-none bg-pn/10 text-pn-soft">
      Pro
    </span>
  );
}

function BackRow({ title, onBack }: { title: string; onBack: () => void }) {
  const { t } = useTranslation('common');
  return (
    <div className="flex items-center gap-1 px-1.5 py-1">
      <button
        type="button"
        onClick={onBack}
        aria-label={t('actions.back')}
        className="shrink-0 inline-flex items-center justify-center w-9 h-9 [@media(hover:none)]:w-11 [@media(hover:none)]:h-11 rounded-md text-accent hover:bg-surface-1 focus-visible:bg-surface-1 outline-none transition"
      >
        <CaretLeft size={16} aria-hidden="true" />
      </button>
      <span className="text-[14px] font-medium text-pn">{title}</span>
    </div>
  );
}

/**
 * The note's color, one tap per swatch. A color the note takes from its
 * tag or folder wears a dashed ring and names its source; a pick of its
 * own wears the solid ring, and "Use default" hands the note back to its
 * tag or folder. The menu stays open, so a pick can be seen on the note
 * before it closes. Free, unlike the folder and tag looks.
 * Spec: ops/docs/plans/folder-tag-icons.md (section 4.9)
 */
function NoteColorPanel({
  color,
  onSetColor,
}: {
  color: NoteColorInfo;
  onSetColor: (color: NoteOwnColor | null) => void;
}) {
  const { t } = useTranslation('shell');
  const { t: tEditor } = useTranslation('editor');
  const { own, inherited } = color;
  const shown = own ?? inherited?.color ?? NOTE_NO_COLOR;
  return (
    <div className="px-4 py-3">
      <div className="flex flex-wrap gap-1 [@media(hover:none)]:gap-0.5">
        <ColorSwatch
          label={t('noteOptionsMenu.colorNone')}
          none
          labelPosition="above-start"
          selected={own === NOTE_NO_COLOR || (own === null && !inherited)}
          className={TOUCH_SWATCH}
          onClick={() => onSetColor(NOTE_NO_COLOR)}
        />
        {LOOK_COLORS.map((c) => (
          <ColorSwatch
            key={c}
            label={tEditor(`color.names.${c}`)}
            background={`var(--pn-label-${c}-ink)`}
            selected={own === c}
            inherited={own === null && shown === c}
            className={TOUCH_SWATCH}
            onClick={() => onSetColor(c)}
          />
        ))}
      </div>
      {own === null && inherited && (
        <p className="mt-2 text-[12px] text-pn-muted truncate" dir="auto">
          {inherited.kind === 'folder'
            ? t('noteOptionsMenu.colorFromFolder', { name: inherited.name })
            : t('noteOptionsMenu.colorFromTag', { name: inherited.name })}
        </p>
      )}
      {own !== null && (
        <button
          type="button"
          onClick={() => onSetColor(null)}
          className="mt-2 -ms-2 text-[13px] font-medium px-2 py-1 [@media(hover:none)]:min-h-11 rounded-md text-accent hover:bg-accent/10 focus-visible:bg-accent/10 outline-none transition"
        >
          {t('noteOptionsMenu.colorUseDefault')}
        </button>
      )}
    </div>
  );
}

/** The touch floor of the look picker's swatches, which a finger picks from. */
const TOUCH_SWATCH = '[@media(hover:none)]:w-11 [@media(hover:none)]:h-11';

/** One cell in the strip: a 20px glyph over its own label. */
function StripButton({
  label,
  icon,
  tone = 'accent',
  onClick,
  disabled,
  pressed,
  title,
}: {
  label: string;
  icon: React.ReactNode;
  tone?: Tone;
  onClick: () => void;
  disabled?: boolean;
  pressed?: boolean;
  /** Native tooltip, used to say why a disabled button is disabled. */
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      aria-pressed={pressed}
      className="flex-1 min-w-0 min-h-11 flex flex-col items-center justify-center gap-1 rounded-lg py-2 hover:bg-surface-1 focus-visible:bg-surface-1 outline-none transition disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
    >
      <span className={TONE_TEXT[tone]}>{icon}</span>
      {/* Four cells across a 320px menu leave ~77px each, which fits the
          longest of these words in the languages we ship (German's
          "Duplizieren" measures 59px at this size). Keep any new strip
          label to one short word. break-words is the safety net, not the
          plan: a mid-word break here looks like a bug. */}
      <span className="w-full text-[12px] leading-tight text-center break-words text-pn">
        {label}
      </span>
    </button>
  );
}

function ToggleItem({
  label,
  icon,
  checked,
  pro,
  onClick,
}: {
  label: string;
  icon: React.ReactNode;
  checked: boolean;
  /** When true, the feature is Pro-gated for this user. Shown as a badge. */
  pro?: boolean;
  onClick: () => void;
}) {
  return (
    <button type="button" onClick={onClick} aria-pressed={checked} className={`${ROW} ${ROW_TEXT.accent}`}>
      <span className={`shrink-0 ${TONE_TEXT.accent}`}>{icon}</span>
      <span className="flex-1 min-w-0 truncate">{label}</span>
      {pro && <ProBadge />}
      <span
        aria-hidden
        className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${
          checked ? 'bg-accent-fill' : 'bg-pn-muted/35'
        }`}
      >
        <span
          className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${
            checked ? 'translate-x-4 rtl:-translate-x-4' : 'translate-x-0.5 rtl:-translate-x-0.5'
          }`}
        />
      </span>
    </button>
  );
}

function ActionItem({
  label,
  icon,
  onClick,
  pro,
  disabled,
  value,
  chevron,
  tone = 'accent',
}: {
  label: string;
  icon: React.ReactNode;
  onClick: () => void;
  pro?: boolean;
  disabled?: boolean;
  /** A short value at the end of the row: a size, a color. */
  value?: React.ReactNode;
  /** The row opens a second view of this menu. */
  chevron?: boolean;
  tone?: Tone;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`${ROW} ${ROW_TEXT[tone]} disabled:opacity-50 disabled:cursor-not-allowed`}
    >
      <span className={`shrink-0 ${TONE_TEXT[tone]}`}>{icon}</span>
      <span className="flex-1 min-w-0 truncate">{label}</span>
      {pro && <ProBadge />}
      {value !== undefined && (
        <span className="shrink min-w-0 max-w-[45%] text-[13px] text-pn-muted">
          {value}
        </span>
      )}
      {chevron && <CaretRight size={14} aria-hidden="true" className="shrink-0 text-pn-muted" />}
    </button>
  );
}

import { formatBytes } from './formatBytes';
import { computeNoteTotalSize, editedAtOf, entryDayOf } from './notesViewUtils';
import { MonthGrid, dayAtNoon } from './MonthGrid';
import type { JournalDays } from './notesViewUtils';
