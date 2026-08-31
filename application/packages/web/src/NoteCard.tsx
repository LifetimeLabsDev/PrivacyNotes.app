import React, { useMemo } from 'react';
import { useTranslation } from 'react-i18next';
import type { NoteRowProps } from './NoteRow';
import { RowIcon, TagChips, CardGlyph, noteFaviconDomain } from './NoteRow';
import { deriveDisplayTitle, deriveExcerpt, formatModifiedShort, rowSizeLabel } from './notesViewUtils';
import { Check, PushPin, Shield, PencilSimpleSlash } from './icons';

/**
 * Grid-mode tile. A superset of NoteRow: same type icon, title, preview,
 * full date, and tags, laid out as a card. Shares NoteRowProps so
 * NotesList can render NoteRow or NoteCard interchangeably (same handlers,
 * same selection/context behavior).
 *
 * React.memo mirrors NoteRow: unchanged notes keep object identity and
 * skip the render on every keystroke - critical for large vaults.
 */
export default React.memo(function NoteCard({
  note: n,
  isOpen,
  listPrefs,
  isNoteLocked: locked,
  onClick,
  onContextMenu,
  onTouchStart,
  onTouchEnd,
  onTouchMove,
  onTouchCancel,
  selectionMode = false,
  isMultiSelected = false,
  onToggleSelect,
  isContextTarget = false,
  showTypeIcons = false,
  sortAwareDate = false,
  trashTint = false,
  sizeLabel,
  iconOverride,
  glyphOverride,
  trailing,
}: NoteRowProps) {
  const { t } = useTranslation('notes');
  const isVault = n.type === 'login' || n.type === 'card' || n.type === 'ssh-key';
  const isFile = n.type === 'file';
  const isJournal = n.type === 'journal';
  const isTask = n.type === 'task';
  const hasTasks = isTask;
  const hasStatusIcons =
    (showTypeIcons && n.starred === 1) || n.pinProtected === 1 || n.locked === 1;

  const displayTitle = useMemo(() => deriveDisplayTitle(n), [n]);
  /** Shared with `NoteRow` - one rule for when a size appears. */
  const sizeText = rowSizeLabel(n, listPrefs.sortField, sizeLabel) || undefined;
  const excerpt = useMemo(() => deriveExcerpt(n), [n]);
  /** Favicon for the mini glyph - bookmarks and logins only, never in trash
   *  (the boxed chip drops the favicon there too, for the amber icon). */
  const faviconDomain = useMemo(() => (trashTint ? '' : noteFaviconDomain(n)), [n, trashTint]);
  const dateLabel = sortAwareDate && listPrefs.sortField === 'created' ? t('noteRow.created') : t('noteRow.modified');
  const dateValue = useMemo(
    () =>
      formatModifiedShort(
        sortAwareDate && listPrefs.sortField === 'created' ? n.createdAt : n.updatedAt,
      ),
    [n, sortAwareDate, listPrefs.sortField],
  );

  return (
    <li
      onClick={onClick}
      onContextMenu={onContextMenu}
      onTouchStart={onTouchStart}
      onTouchEnd={onTouchEnd}
      onTouchMove={onTouchMove}
      onTouchCancel={onTouchCancel}
      // Same touch-only rule as NoteRow - long-press selects the card, it
      // must not start a text selection too. Spec: issue #208.
      className={`pn-card pn-lazy-card relative flex flex-col gap-1.5 rounded-xl border p-3 cursor-pointer transition [@media(hover:none)]:select-none ${
        selectionMode ? 'pn-card--select ' : ''
      }${
        isMultiSelected
          ? 'bg-accent/15 border-accent dark:bg-accent/20'
          : isOpen
          ? 'bg-accent/10 border-accent dark:bg-accent/15'
          : isContextTarget
          ? 'bg-neutral-200/70 border-divider dark:bg-neutral-800/70'
          : 'bg-surface-2 border-divider hover:border-accent/60 hover:bg-neutral-200/40 dark:hover:bg-neutral-900/40'
      }`}
    >
      {/* Bookmark ribbon - see the .pn-ribbon rules in index.css. It owns the
          tile's top END corner, which is why the checkbox below sits at the
          START edge the way the list row's does. */}
      {n.type === 'link' && <span className="pn-ribbon" aria-hidden="true" />}
      {selectionMode && (
        <span
          onClick={(e) => {
            e.stopPropagation();
            onToggleSelect?.(e);
          }}
          aria-label={isMultiSelected ? t('noteRow.deselect') : t('noteRow.select')}
          role="checkbox"
          aria-checked={isMultiSelected}
          className={`absolute start-2 top-2 z-10 w-5 h-5 rounded border flex items-center justify-center transition shrink-0 ${
            isMultiSelected
              ? 'bg-accent border-accent text-white'
              : 'bg-surface-2 border-divider hover:border-accent'
          }`}
        >
          {isMultiSelected && <Check size={12} />}
        </span>
      )}
      {/* Header: type icon + title. On small tiles (the docked list panel
          and the phone grid) CSS hides the boxed icon, reveals the inline
          glyph, and lets the title wrap to 3 lines instead of truncating.
          See the .pn-card mini rules in index.css. */}
      <div className="pn-card-head flex items-center gap-2.5 min-w-0">
        <span className="pn-card-icbox contents">
          {/* Same override the row honours: a Markdown file is adapted into a
              note's shape to reuse these components, so its type says 'note'
              and it would otherwise draw a note glyph in the tile while the
              row drew the MD one. */}
          {iconOverride ?? <RowIcon note={n} isVault={isVault} isFile={isFile} isJournal={isJournal} hasTasks={hasTasks} trashTint={trashTint} />}
        </span>
        <div className="pn-card-title min-w-0 flex-1 text-sm font-semibold truncate flex items-center gap-1.5 text-neutral-900 dark:text-white">
          {/* The mini layout's counterpart to `iconOverride`: below 640px the
              container query hides the icon box above and shows this instead,
              so an override that stopped at the box would leave a Markdown
              tile drawing a note glyph in exactly the layouts where the tile
              is too small to say anything else about the file. */}
          <CardGlyph type={n.type} override={glyphOverride} domain={faviconDomain} />
          <span className="pn-card-titletext truncate" dir="auto">{displayTitle}</span>
        </div>
      </div>
      {/* Preview - up to 2 lines (1 line on small tiles, via .pn-card-preview) */}
      {listPrefs.showPreview && !locked && (
        <div className="pn-card-preview text-[13px] text-neutral-500 dark:text-neutral-400 leading-snug" dir="auto">
          {excerpt || (isFile ? t('noteRow.file') : isVault ? t('noteRow.empty') : t('noteRow.noContent'))}
        </div>
      )}
      {/* Tags - sit with the content above the date so the date can stay pinned
          to the very bottom of the tile. */}
      {listPrefs.showTags && <TagChips tags={n.tags} folderId={n.folderId} />}
      {/* Meta line: date, then the status icons (starred / PIN-protected /
          read-only) directly beside it, same rule as the list row - anchored
          to the date rather than to the tile's right edge. Keeping the icons
          down here off the title row is what stops a narrow tile from crowding
          them against the title (they used to sit inline before it).
          `margin-top:auto` in the grid (see index.css) drops this row to the
          tile's bottom so dates line up across a row. */}
      {(listPrefs.showDate || hasStatusIcons || sizeText) && (
        <div className="pn-card-meta flex items-center gap-1.5">
          {listPrefs.showDate && (
            <span className="pn-card-date min-w-0 text-[12px] text-neutral-400 dark:text-neutral-600 whitespace-nowrap overflow-hidden text-ellipsis">
              {dateLabel} {dateValue}
            </span>
          )}
          <span className="pn-card-status shrink-0 flex items-center gap-1.5 text-accent">
            {showTypeIcons && n.starred === 1 && (
              <PushPin size={12} />
            )}
            {n.pinProtected === 1 && (
              <Shield size={12} aria-label={t('noteRow.pinProtected')} />
            )}
            {n.locked === 1 && (
              <PencilSimpleSlash size={12} aria-label={t('noteRow.readOnly')} />
            )}
          </span>
          {/* Anchored to the date, as in the row - section 66. */}
          {sizeText && (
            <span className="shrink-0 text-[11px] text-neutral-400 dark:text-neutral-500 font-medium tabular-nums">
              {sizeText}
            </span>
          )}
        </div>
      )}
      {/* Same slot as NoteRow's: always-visible per-item actions on the
          card's footer (bookmarks' pencil/delete pair). The buttons stop
          propagation themselves, so the card's own onClick stays intact. */}
      {trailing && (
        <span className="pn-card-actions flex items-center gap-1 pt-1">{trailing}</span>
      )}
    </li>
  );
});
