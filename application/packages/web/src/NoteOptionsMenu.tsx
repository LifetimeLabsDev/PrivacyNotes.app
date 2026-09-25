import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import { IconUpgrade } from './UpgradeModal';
import { useEscapeToClose } from './useEscapeToClose';
import { proUnlocked } from './demo';
import { noteActionGuards, type NoteActionGuardDeps } from './noteActionGuards';
import { usePopoverPosition } from './usePopoverPosition';
import { intlLocale } from './languages';
import { prepareBurnPayload } from './burnShare';
import { PencilSimpleSlash, Shield, ClockCounterClockwise, PushPin, Export, Trash, Repeat, Copy, Folder, Fire, ArrowCounterClockwise, FileMd, TextAa, Swap } from './icons';

/**
 * Per-note options dropdown, anchored to the "..." button in the
 * editor top bar. It is the ONE surface that carries every per-note
 * action, at every width.
 *
 * That completeness is the point. The header's own icons - burn, pin,
 * share, trash - hide as soon as the header row is under 560px, which
 * happens on a narrow editor pane long before the viewport is narrow.
 * The strip at the top of this menu catches exactly what the header
 * dropped: it appears only once those icons are gone, carries them in
 * the header's own left-to-right order, and is absent while the header
 * still shows them. Nothing is ever in both places at once.
 *
 * The list below never moves. It opens with the markdown/formatted
 * switch, then holds the actions that were never in the toolbar - the
 * Pro toggles (read-only, PIN-protect), folders, duplicate, history,
 * and the note-to-journal conversion - then a note-info summary.
 * Duplicate belongs there rather than in the strip precisely because
 * the strip comes and goes.
 *
 * The markdown switch is first because it is the one row that changes
 * what you are looking at right now, and because its other home - a
 * small grey link under the word count - is easy to miss. Both surfaces
 * flip the same per-note, session-only override; neither writes the
 * synced default in Settings > Appearance.
 *
 * In the trash view the menu carries Restore and Delete forever and
 * nothing else - the same two actions, the same two colours and the
 * same glyphs as the right-click menu on a trashed row.
 *
 * The Pro toggles render as soft switches. Free users can still
 * flip them: doing so opens the UpgradeModal instead of applying
 * the change. This way the Pro capabilities are discoverable
 * without the free UI feeling crippled.
 */
type Props = NoteActionGuardDeps & {
  /** Anchor so clicks on the "..." button don't count as outside. */
  anchorRef: React.RefObject<HTMLElement | null>;

  // Actions
  onDuplicate: () => void;
  /** Toggle pin/star. In the strip, so it survives a narrow header. */
  onToggleStar?: () => void;
  /** Move to trash. In the strip, so it survives a narrow header. */
  onTrash?: () => void;
  /** Open share/export UI. In the strip, so it survives a narrow header. */
  onShare?: () => void;
  /** Share and Burn After Reading. In the strip, for the same reason. */
  onBurn?: () => void;
  /** Convert between note and journal types. */
  onConvertType?: () => void;
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
   * True once the header's own burn/pin/share/trash icons are hidden.
   * The strip renders only then, so the two surfaces never show the
   * same action twice. All four header buttons share one condition
   * today; if they ever diverge, this becomes a set, not a boolean.
   */
  /** Trash view: the menu carries only the two trash actions. */
  isTrash?: boolean;
  onRestore?: () => void;
  onDeleteForever?: () => void;
};

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
  onTrash,
  onShare,
  onBurn,
  onSetPin,
  onConvertType,
  onMoveToFolder,
  editorMode,
  onToggleEditorMode,
  onFindReplace,
  isTrash,
  onRestore,
  onDeleteForever,
}: Props) {
  const { t } = useTranslation('shell');
  useEscapeToClose(onClose);

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

  // Both halves have to be there: the caller only passes them when this
  // note actually has a markdown editor under the header.
  const showModeRow = !isTrash && !!onToggleEditorMode && !!editorMode;
  const showReplaceRow = !isTrash && !!onFindReplace;
  // The caller decides which cells exist by passing or omitting each handler,
  // so the strip has nothing to work out for itself. It just needs to know
  // whether it drew anything, because the row below it wears the hairline.
  const hasStrip = !isTrash && !!(onBurn || onToggleStar || onShare || onTrash);

  const bytes = computeNoteTotalSize(note);
  // A media-only note has nothing left to send once images and files are
  // stripped, so the burn action refuses it. Dim the button rather than
  // let it fail on click. Spec: burnShare.ts (prepareBurnPayload).
  const burnable = prepareBurnPayload(note) !== null;

  return createPortal(
    <div
      ref={ref}
      role="dialog"
      aria-label={t('noteOptionsMenu.noteOptions')}
      className="fixed z-50 w-80 max-h-[calc(100vh-16px)] overflow-y-auto rounded-lg border border-divider bg-surface-2 shadow-lg"
      style={{
        top: pos?.top ?? 0,
        left: pos?.left ?? 0,
        visibility: pos ? 'visible' : 'hidden',
      }}
    >
      {/* Find-in-note deliberately does NOT live here: the magnifier sits in
          the tag row, one row below this menu's own button, and a second
          entry for it only made this list longer. Find AND REPLACE does live
          here, under the editor-mode switch: it has no pill in the corner (a
          second one would crowd the note's first line, GitHub #265) and no
          key on a phone, so this row is its only pointer path. Neither do a
          bookmark's
          Open/Copy or a vault item's Edit/Copy: those render inside the item
          itself, directly under this menu, and no width ever hides them. */}
      {isTrash ? (
        <div className="py-1">
          {onRestore && (
            <ActionItem
              label={t('noteOptionsMenu.restore')}
              icon={<IconRestore />}
              tone="success"
              onClick={() => { onRestore(); onClose(); }}
            />
          )}
          {onDeleteForever && (
            <ActionItem
              label={t('noteOptionsMenu.deleteForever')}
              icon={<IconTrash />}
              tone="danger"
              onClick={() => { onDeleteForever(); onClose(); }}
            />
          )}
        </div>
      ) : (
        <>
          {/* Burn, pin and trash. This is their only home: the editor
              header stopped carrying them, so the strip is permanent rather
              than a stand-in that appears when the row runs out of width.
              Share is the exception and still comes and goes, because the
              header kept it - the caller passes onShare only where its own
              copy is hidden.
              Spec: ops/docs/ui-patterns.md (section 80) */}
          {hasStrip && (
            <div className="flex items-stretch gap-0 p-1.5">
              {onBurn && (
                <StripButton
                  label={t('noteOptionsMenu.burn')}
                  icon={<IconBurn />}
                  tone="burn"
                  disabled={!burnable}
                  title={burnable ? undefined : t('notes:burn.mediaOnly')}
                  onClick={() => { onBurn(); onClose(); }}
                />
              )}
              {onToggleStar && (
                <StripButton
                  label={note.starred === 1 ? t('noteOptionsMenu.unpin') : t('noteOptionsMenu.pin')}
                  icon={<IconPin filled={note.starred === 1} size={20} />}
                  onClick={() => { onToggleStar(); onClose(); }}
                />
              )}
              {onShare && (
                <StripButton
                  label={t('noteOptionsMenu.share')}
                  icon={<IconShare size={20} />}
                  onClick={() => { onShare(); onClose(); }}
                />
              )}
              {onTrash && (
                <StripButton
                  label={t('noteOptionsMenu.trash')}
                  icon={<IconTrash size={20} />}
                  tone="danger"
                  onClick={() => { onTrash(); onClose(); }}
                />
              )}
            </div>
          )}

          {(showModeRow || showReplaceRow) && (
            <div className={`${hasStrip ? 'border-t border-divider ' : ''}py-1`}>
              {showModeRow && (
                <ActionItem
                  label={editorMode === 'markdown' ? t('notes:editor.showFormatted') : t('notes:editor.showMarkdown')}
                  description={
                    editorMode === 'markdown'
                      ? t('noteOptionsMenu.showFormattedDescription')
                      : t('noteOptionsMenu.showMarkdownDescription')
                  }
                  icon={editorMode === 'markdown' ? <IconFormatted /> : <IconMarkdown />}
                  onClick={() => {
                    onToggleEditorMode?.();
                    onClose();
                  }}
                />
              )}
              {showReplaceRow && (
                <ActionItem
                  label={t('noteOptionsMenu.findReplace')}
                  icon={<IconReplace />}
                  pro={!isPro}
                  onClick={() => {
                    onFindReplace?.();
                    onClose();
                  }}
                />
              )}
            </div>
          )}

          <div className={`${hasStrip || showModeRow || showReplaceRow ? 'border-t border-divider ' : ''}py-1`}>
            <ToggleItem
              label={t('noteOptionsMenu.readOnly')}
              description={t('noteOptionsMenu.readOnlyDescription')}
              icon={<IconPencilSlash />}
              checked={note.locked === 1}
              pro={!isPro}
              onClick={act.toggleLock}
            />
            <ToggleItem
              label={t('noteOptionsMenu.protect')}
              description={t('noteOptionsMenu.protectDescription')}
              icon={<IconShield />}
              checked={note.pinProtected === 1}
              pro={!isPro}
              onClick={act.toggleProtect}
            />
          </div>

          <div className="border-t border-divider py-1">
            {onMoveToFolder && (
              <ActionItem
                label={t('noteOptionsMenu.moveToFolder')}
                icon={<IconFolder />}
                pro={!isPro}
                onClick={act.moveToFolder}
              />
            )}
            <ActionItem
              label={t('noteOptionsMenu.duplicate')}
              icon={<IconCopy />}
              onClick={() => {
                onDuplicate();
                onClose();
              }}
            />
            <ActionItem
              label={t('noteOptionsMenu.noteHistory')}
              description={t('noteOptionsMenu.noteHistoryDescription')}
              icon={<IconHistory />}
              pro={!isPro}
              disabled={unlocked && !onOpenHistory}
              suffix={unlocked && !onOpenHistory ? t('noteOptionsMenu.comingSoon') : undefined}
              onClick={act.openHistory}
            />
            {onConvertType && (note.type === 'note' || note.type === 'journal') && (
              <ActionItem
                label={note.type === 'note' ? t('noteOptionsMenu.convertToJournal') : t('noteOptionsMenu.convertToNote')}
                icon={<IconRepeat />}
                onClick={() => {
                  onConvertType();
                  onClose();
                }}
              />
            )}
          </div>
        </>
      )}

      {/* Note info - read-only metadata block. Matches SN's footer
          so heavy users of the menu get their stats at a glance. */}
      <div className="border-t border-divider px-4 py-3 text-[12px] text-neutral-500 dark:text-neutral-500 space-y-0.5 leading-relaxed">
        <div>
          {t('noteOptionsMenu.lastModified', { date: new Date(note.updatedAt).toLocaleString(intlLocale()) })}
        </div>
        <div>{t('noteOptionsMenu.created', { date: new Date(note.createdAt).toLocaleString(intlLocale()) })}</div>
        <div>
          {t('noteOptionsMenu.size', { size: formatBytes(bytes) })}
          {note.tags.length > 0 && <> · {t('noteOptionsMenu.tagCount', { count: note.tags.length })}</>}
        </div>
        <div className="text-neutral-400 dark:text-neutral-600">
          {t('noteOptionsMenu.sizeHint')}
        </div>
      </div>
    </div>,
    document.body,
  );
}

/* ────────────────────────────────────────────────────────────────
 * Sub-items
 * ──────────────────────────────────────────────────────────────── */

/**
 * Colour of an item's icon. Blue is the standard; burn keeps the amber
 * it wears in the header, and anything that destroys keeps its red, so
 * the two actions worth a second thought are the two that stand out.
 */
type Tone = 'accent' | 'burn' | 'danger' | 'success';

const TONE_TEXT: Record<Tone, string> = {
  accent: 'text-accent',
  burn: 'text-orange-600 dark:text-orange-400',
  danger: 'text-red-500 dark:text-red-400',
  success: 'text-emerald-600 dark:text-emerald-400',
};

/** One square in the strip: a 20px glyph over its own label. */
function StripButton({
  label,
  icon,
  tone = 'accent',
  onClick,
  disabled,
  title,
}: {
  label: string;
  icon: React.ReactNode;
  tone?: Tone;
  onClick: () => void;
  disabled?: boolean;
  /** Native tooltip, used to say why a disabled button is disabled. */
  title?: string;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      title={title}
      className="flex-1 min-w-0 flex flex-col items-center gap-1.5 rounded-md py-2 hover:bg-surface-1 transition disabled:opacity-40 disabled:cursor-not-allowed disabled:hover:bg-transparent"
    >
      <span className={TONE_TEXT[tone]}>{icon}</span>
      {/* Five cells across a 320px menu leave ~61px each, which fits the
          longest of these words in the languages we ship (German's
          "Duplizieren" measures 59px at this size). Keep any new strip
          label to one short word. break-words is the safety net, not the
          plan: a mid-word break here looks like a bug. */}
      <span className="w-full text-[11px] leading-tight text-center break-words text-neutral-500 dark:text-neutral-400">
        {label}
      </span>
    </button>
  );
}

function ToggleItem({
  label,
  description,
  icon,
  checked,
  pro,
  onClick,
}: {
  label: string;
  /** One-line explainer rendered under the label. */
  description?: string;
  icon: React.ReactNode;
  checked: boolean;
  /** When true, the feature is Pro-gated for this user. Shown as a badge. */
  pro?: boolean;
  onClick: () => void;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      aria-pressed={pro ? undefined : checked}
      className="w-full flex items-start gap-3 px-4 py-2 text-start text-[14px] text-pn hover:bg-surface-1 transition"
    >
      <span className="shrink-0 mt-0.5 text-accent">
        {icon}
      </span>
      <span className="flex-1 min-w-0">
        <span className="block truncate">{label}</span>
        {description && (
          <span className="block text-[12px] text-neutral-500 dark:text-neutral-400 leading-snug mt-0.5">
            {description}
          </span>
        )}
      </span>
      {pro ? (
        <span className="shrink-0 mt-0.5 inline-flex items-center gap-1 text-[11px] font-semibold text-accent">
          <IconUpgrade size={12} /> Pro
        </span>
      ) : (
        <span
          aria-hidden
          className={`relative mt-0.5 inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${
            checked ? 'bg-accent' : 'bg-neutral-300 dark:bg-neutral-700'
          }`}
        >
          <span
            className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${
              checked ? 'translate-x-4 rtl:-translate-x-4' : 'translate-x-0.5 rtl:-translate-x-0.5'
            }`}
          />
        </span>
      )}
    </button>
  );
}

function ActionItem({
  label,
  description,
  icon,
  onClick,
  pro,
  disabled,
  suffix,
  tone = 'accent',
}: {
  label: string;
  /** One-line explainer rendered under the label. */
  description?: string;
  icon: React.ReactNode;
  onClick: () => void;
  pro?: boolean;
  disabled?: boolean;
  suffix?: string;
  tone?: Tone;
}) {
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={disabled}
      className={`w-full flex items-start gap-3 px-4 py-2 text-start text-[14px] ${
        tone === 'danger'
          ? 'text-red-500 dark:text-red-400 hover:bg-red-50 dark:hover:bg-red-950/30'
          : tone === 'success'
            ? 'text-emerald-600 dark:text-emerald-400 hover:bg-emerald-50 dark:hover:bg-emerald-950/30'
            : 'text-pn hover:bg-surface-1'
      } transition disabled:opacity-50 disabled:cursor-not-allowed`}
    >
      <span className={`shrink-0 mt-0.5 ${TONE_TEXT[tone]}`}>
        {icon}
      </span>
      <span className="flex-1 min-w-0">
        <span className="block truncate">{label}</span>
        {description && (
          <span className="block text-[12px] text-neutral-500 dark:text-neutral-400 leading-snug mt-0.5">
            {description}
          </span>
        )}
      </span>
      {pro && (
        <span className="shrink-0 mt-0.5 inline-flex items-center gap-1 text-[11px] font-semibold text-accent">
          <IconUpgrade size={12} /> Pro
        </span>
      )}
      {!pro && suffix && (
        <span className="shrink-0 mt-0.5 text-[11px] text-neutral-400 dark:text-neutral-500">
          {suffix}
        </span>
      )}
    </button>
  );
}

import { formatBytes } from './formatBytes';
import { computeNoteTotalSize } from './notesViewUtils';

/* ────────────────────────────────────────────────────────────────
 * Icons - thin wrappers around the shared Phosphor module.
 * ──────────────────────────────────────────────────────────────── */

function IconPencilSlash() {
  return <PencilSimpleSlash size={16} aria-hidden="true" />;
}

function IconShield() {
  return <Shield size={16} aria-hidden="true" />;
}

function IconHistory() {
  return <ClockCounterClockwise size={16} aria-hidden="true" />;
}

function IconPin({ filled, size = 16 }: { filled?: boolean; size?: number }) {
  return <PushPin size={size} weight={filled ? 'fill' : 'bold'} aria-hidden="true" />;
}

function IconShare({ size = 16 }: { size?: number }) {
  return <Export size={size} aria-hidden="true" />;
}

function IconBurn() {
  return <Fire size={20} aria-hidden="true" />;
}

function IconTrash({ size = 16 }: { size?: number }) {
  return <Trash size={size} aria-hidden="true" />;
}

/** Restore from trash. The same curved arrow the right-click menu uses. */
function IconRestore() {
  return <ArrowCounterClockwise size={16} aria-hidden="true" />;
}

function IconRepeat() {
  return <Repeat size={16} aria-hidden="true" />;
}

function IconCopy({ size = 16 }: { size?: number }) {
  return <Copy size={size} aria-hidden="true" />;
}

function IconFolder() {
  return <Folder size={16} aria-hidden="true" />;
}

/* The mode row's glyph names the DESTINATION, so it changes with the row's
   label: a markdown file when the click opens the source, an "Aa" when it
   brings the formatted text back. The bare MarkdownLogo is deliberately not
   used for either - the tag row wears it for the formatting bar, and that
   is a different control. */
function IconReplace() {
  return <Swap size={16} aria-hidden="true" />;
}

function IconMarkdown() {
  return <FileMd size={17} aria-hidden="true" />;
}
function IconFormatted() {
  return <TextAa size={17} aria-hidden="true" />;
}
