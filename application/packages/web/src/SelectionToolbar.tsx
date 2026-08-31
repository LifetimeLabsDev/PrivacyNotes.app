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

import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { normalizeTag } from './notesRepo';
import { useEscapeToClose } from './useEscapeToClose';
import { usePopoverPosition } from './usePopoverPosition';
import { HoverLabel } from './HoverLabel';
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
  const tagBtnRef = useRef<HTMLButtonElement>(null);

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
              ref={tagBtnRef}
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
        <TagPopover
          anchorRef={tagBtnRef}
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

// ── Tag popover ────────────────────────────────────────────────────────

function TagPopover({
  anchorRef,
  allTags,
  onSelect,
  onClose,
}: {
  anchorRef: React.RefObject<HTMLButtonElement | null>;
  allTags: [string, number][];
  onSelect: (tag: string) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('shell');
  const [filter, setFilter] = useState('');
  const popoverRef = useRef<HTMLDivElement>(null);
  const inputRef = useRef<HTMLInputElement>(null);

  useEscapeToClose(onClose);

  // Focus the input on mount.
  useEffect(() => {
    const id = setTimeout(() => inputRef.current?.focus(), 50);
    return () => clearTimeout(id);
  }, []);

  // Outside-click dismiss (delayed to avoid the opening click).
  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (popoverRef.current && popoverRef.current.contains(target)) return;
      if (anchorRef.current && anchorRef.current.contains(target)) return;
      onClose();
    }
    const id = setTimeout(
      () => document.addEventListener('pointerdown', handler),
      50,
    );
    return () => {
      clearTimeout(id);
      document.removeEventListener('pointerdown', handler);
    };
  }, [onClose, anchorRef]);

  // Position: under the anchor, right edges aligned (the tag button sits in
  // the toolbar's right-hand cluster). The hook then slides it inward so it
  // can never spill off the viewport - hand-rolled `left: rect.left` used to
  // push it half off-screen on a phone, where the anchor is only ~120px from
  // the right edge and the popover is 200 wide. Spec: ops/docs/ui-patterns.md (also flips above the trigger when there is no room below)
  const pos = usePopoverPosition(true, anchorRef, popoverRef, {
    gap: 6,
    align: 'end',
  });

  // Filter tags alphabetically.
  const needle = filter.toLowerCase().replace(/^#/, '').trim();
  const filtered = useMemo(() => {
    const sorted = [...allTags].sort((a, b) => a[0].localeCompare(b[0]));
    if (!needle) return sorted;
    return sorted.filter(([t]) => t.toLowerCase().includes(needle));
  }, [allTags, needle]);

  // "Create" row: show when the normalized input doesn't match any
  // existing tag and isn't empty.
  const normalizedFilter = normalizeTag(filter);
  const showCreate =
    normalizedFilter &&
    !allTags.some(
      ([t]) => t.toLowerCase() === normalizedFilter.toLowerCase(),
    );

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Enter') {
      e.preventDefault();
      if (showCreate) {
        onSelect(normalizedFilter);
      } else if (filtered.length === 1 && filtered[0]) {
        onSelect(filtered[0][0]);
      }
    }
  }

  return createPortal(
    <div
      ref={popoverRef}
      className="fixed bg-surface-2 border border-divider rounded-lg overflow-hidden"
      style={{
        top: pos?.top ?? 0,
        left: pos?.left ?? 0,
        width: 200,
        zIndex: 50,
        visibility: pos ? 'visible' : 'hidden',
      }}
    >
      {/* Search / create input */}
      <div className="p-2">
        <input
          ref={inputRef}
          value={filter}
          onChange={(e) => setFilter(e.target.value)}
          onKeyDown={handleKeyDown}
          placeholder={t('selectionToolbar.addTagPlaceholder')}
          autoComplete="off"
          className="w-full text-sm bg-transparent border border-divider rounded-md px-2.5 py-1.5 focus:outline-none focus:border-accent placeholder:text-neutral-400 dark:placeholder:text-neutral-600 text-pn"
        />
      </div>

      <div className="border-t border-divider" />

      {/* Tag list */}
      <div className="max-h-[200px] overflow-y-auto py-1">
        {filtered.map(([tag]) => (
          <button
            key={tag}
            type="button"
            onClick={() => onSelect(tag)}
            className="w-full flex items-center gap-2 px-3 py-2 text-sm cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors min-h-[36px]"
          >
            <span className="text-neutral-400 dark:text-neutral-600 text-xs">#</span>
            <span className="text-pn truncate">
              {tag}
            </span>
          </button>
        ))}

        {filtered.length === 0 && !showCreate && (
          <div className="px-3 py-2 text-sm text-neutral-400 dark:text-neutral-600">
            {t('selectionToolbar.noTagsFound')}
          </div>
        )}

        {showCreate && (
          <>
            {filtered.length > 0 && (
              <div className="border-t border-divider" />
            )}
            <button
              type="button"
              onClick={() => onSelect(normalizedFilter)}
              className="w-full flex items-center gap-2 px-3 py-2 text-sm cursor-pointer hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors text-neutral-500 dark:text-neutral-400 min-h-[36px]"
            >
              <span className="text-xs">+</span>
              <span>{t('selectionToolbar.createTag', { tag: normalizedFilter })}</span>
            </button>
          </>
        )}
      </div>
    </div>,
    document.body,
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
