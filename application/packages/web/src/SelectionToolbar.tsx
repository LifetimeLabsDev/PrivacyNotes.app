/**
 * Selection toolbar - replaces the NotesView list header while one or
 * more notes are multi-selected. Works in two modes:
 *
 *   - 'normal': bulk Favorite / Archive / Tag / Export / Delete (move to trash)
 *   - 'trash':  bulk Restore / Delete Forever
 *
 * Layout matches the header it replaces: h-14 and the same bottom border,
 * so there's no vertical jump when it swaps in. The row is sized to fit
 * LIST_WIDTH_MIN (280 px): 12 px padding, a 32 px exit button, and six
 * 32 px actions 4 px apart need 272 px. Wider buttons or gaps push
 * Delete under the pane's resize strip.
 */

import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { HoverLabel } from './HoverLabel';
import { TagPicker } from './TagPicker';
import { IconUpgrade } from './UpgradeModal';
import { X, PushPin, Tag, Folder, Download, Trash, ArrowCounterClockwise, iconArchive } from './icons';

type Mode = 'normal' | 'trash';

type Props = {
  mode: Mode;
  /** True iff every selected note is currently starred. Drives the
   *  favorite button label / icon fill. Mixed selections treat as
   *  "not all starred" → clicking favorites all of them. */
  allStarred: boolean;
  /** True iff every selected note is archived: the button then unarchives. */
  allArchived: boolean;
  onClear: () => void;
  onFavorite: () => void;
  onArchive: () => void;
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
  allArchived,
  onClear,
  onFavorite,
  onArchive,
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
    <div className="shrink-0 h-14 px-3 border-b border-divider flex items-center justify-between gap-1 bg-accent/5 dark:bg-accent/10">
      <HoverLabel label={t('selectionToolbar.exitSelectionTooltip')} position="below">
      <button
        onClick={onClear}
        aria-label={t('selectionToolbar.exitSelection')}
        className="shrink-0 inline-flex items-center justify-center w-8 h-8 rounded-md text-pn-soft hover:bg-pn/5 hover:text-pn transition"
      >
        <X size={18} />
      </button>
      </HoverLabel>

      <div className="shrink-0 flex items-center gap-1">
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
              label={allArchived ? t('selectionToolbar.unarchive') : t('selectionToolbar.archive')}
              onClick={onArchive}
              icon={iconArchive(allArchived, 16)}
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
    'relative shrink-0 inline-flex items-center justify-center w-8 h-8 rounded-md transition';
  const toneClass =
    tone === 'danger'
      ? 'bg-red-500/10 hover:bg-red-500/20 text-danger'
      : tone === 'success'
        ? 'bg-emerald-500/10 hover:bg-emerald-500/20 text-success'
        : 'bg-accent/10 hover:bg-accent/20 text-accent-strong';
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
