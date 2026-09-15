/**
 * Selection toolbar - replaces the NotesView list header while one or
 * more notes are multi-selected. Works in two modes:
 *
 *   - 'normal': bulk Favorite / Tag / Export / Delete (move to trash)
 *   - 'trash':  bulk Restore / Delete Forever
 *
 * Layout matches the header it replaces: h-14, same horizontal padding
 * and bottom border, so there's no vertical jump when it swaps in.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { HoverLabel } from './HoverLabel';
import { TagPicker } from './TagPicker';
import { IconUpgrade } from './UpgradeModal';
import { X, PushPin, Tag, Folder, Download, Trash, ArrowCounterClockwise } from './icons';

type Mode = 'normal' | 'trash';

type Props = {
  mode: Mode;
  /** True iff every selected note is currently starred. Drives the
   *  favorite button label / icon fill. Mixed selections treat as
   *  "not all starred" → clicking favorites all of them. */
  allStarred: boolean;
  onClear: () => void;
  onFavorite: () => void;
  onTag: (tag: string) => void;
  /** Bulk move to folder (Pro). Opens the shared folder picker, or the
   *  folders upsell when the plan doesn't include them. */
  onMoveToFolder: () => void;
  /** False renders the Pro badge on the move-to-folder button; the click
   *  still fires, the handler routes it to the upsell. */
  foldersUnlocked: boolean;
  onExport: () => void;
  onDelete: () => void;
  onRestore: () => void;
  onDeleteForever: () => void;
  /** All existing tags with note counts, for the tag picker. */
  allTags?: [string, number][];
};

export function SelectionToolbar({
  mode,
  allStarred,
  onClear,
  onFavorite,
  onTag,
  onMoveToFolder,
  foldersUnlocked,
  onExport,
  onDelete,
  onRestore,
  onDeleteForever,
  allTags,
}: Props) {
  const { t } = useTranslation('shell');
  const [tagOpen, setTagOpen] = useState(false);

  return (
    <div className="shrink-0 h-14 px-4 border-b border-divider flex items-center justify-between gap-3 bg-accent/5 dark:bg-accent/10">
      <HoverLabel label={t('selectionToolbar.exitSelectionTooltip')} position="below">
      <button
        onClick={onClear}
        aria-label={t('selectionToolbar.exitSelection')}
        className="shrink-0 inline-flex items-center justify-center w-8 h-8 rounded-md text-neutral-600 hover:bg-neutral-200/70 hover:text-neutral-900 dark:text-neutral-300 dark:hover:bg-neutral-800 dark:hover:text-white transition"
      >
        <X size={18} />
      </button>
      </HoverLabel>

      <div className="shrink-0 flex items-center gap-1.5">
        {mode === 'normal' ? (
          <>
            <ToolbarButton
              label={allStarred ? t('selectionToolbar.unpin') : t('selectionToolbar.pin')}
              onClick={onFavorite}
              icon={
                <PushPin size={16} weight={allStarred ? 'fill' : 'bold'} />
              }
            />
            <ToolbarButton
              label={t('selectionToolbar.tag')}
              onClick={() => setTagOpen((v) => !v)}
              icon={
                <Tag size={16} />
              }
            />
            <ToolbarButton
              label={t('folders.moveTo')}
              onClick={onMoveToFolder}
              pro={!foldersUnlocked}
              icon={
                <Folder size={16} />
              }
            />
            <ToolbarButton
              label={t('selectionToolbar.export')}
              onClick={onExport}
              icon={
                <Download size={16} />
              }
            />
            <ToolbarButton
              label={t('selectionToolbar.delete')}
              tone="danger"
              onClick={onDelete}
              icon={
                <Trash size={16} />
              }
            />
          </>
        ) : (
          <>
            <ToolbarButton
              label={t('selectionToolbar.restore')}
              tone="success"
              onClick={onRestore}
              icon={
                <ArrowCounterClockwise size={16} />
              }
            />
            <ToolbarButton
              label={t('selectionToolbar.deleteForever')}
              tone="danger"
              onClick={onDeleteForever}
              icon={
                <Trash size={16} />
              }
            />
          </>
        )}
      </div>

      {tagOpen && (
        <TagPicker
          allTags={allTags ?? []}
          onSelect={(tag) => {
            setTagOpen(false);
            onTag(tag);
          }}
          onClose={() => setTagOpen(false)}
        />
      )}
    </div>
  );
}

// ── Toolbar button ─────────────────────────────────────────────────────

import { forwardRef } from 'react';

const ToolbarButton = forwardRef<
  HTMLButtonElement,
  {
    label: string;
    onClick: () => void;
    icon: React.ReactNode;
    tone?: 'default' | 'danger' | 'success';
    /** Corner upgrade badge, same treatment as the collapsed sidebar's
     *  Folders button. The button stays clickable - the handler routes to
     *  the upsell. */
    pro?: boolean;
  }
>(function ToolbarButton({ label, onClick, icon, tone = 'default', pro = false }, ref) {
  const base =
    'relative shrink-0 inline-flex items-center justify-center w-9 h-9 rounded-md transition';
  const toneClass =
    tone === 'danger'
      ? 'bg-red-500/10 hover:bg-red-500/20 text-red-600 dark:text-red-400'
      : tone === 'success'
        ? 'bg-emerald-500/10 hover:bg-emerald-500/20 text-emerald-600 dark:text-emerald-400'
        : 'bg-accent/10 hover:bg-accent/20 text-accent';
  return (
    <HoverLabel label={label} position="below">
    <button
      ref={ref}
      onClick={onClick}
      aria-label={label}
      className={`${base} ${toneClass}`}
    >
      {icon}
      {pro && (
        <span className="absolute -top-0.5 -end-0.5" aria-hidden="true">
          <IconUpgrade size={11} />
        </span>
      )}
    </button>
    </HoverLabel>
  );
});
