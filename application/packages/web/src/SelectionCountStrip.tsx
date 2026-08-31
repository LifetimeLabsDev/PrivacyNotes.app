/**
 * The "N of M selected" strip that sits under a list's search row while
 * multi-select is active. ONE component, because Notes and Bookmarks drew it
 * from two copies of the same JSX (Bookmarks reaching into the notes namespace
 * for the keys) - the same drift trap `ListFilterChips` exists to close.
 *
 * It carries TWO ways out, not one. The trailing link only offers "Select all"
 * until everything is selected, so a partial selection had no visible way back
 * to nothing: people selected all 15 items first, purely to make "Deselect all"
 * appear, and then pressed it. The X beside the count is that action in every
 * state. It calls `deselectAll`, so it empties the selection and STAYS in
 * selection mode - the same thing the link does, and the reason both exist:
 * clearing a mis-click should not also throw you out of the mode you are in.
 * The toolbar's own X is the one that leaves.
 *
 * Spec: ops/docs/ui-patterns.md section 79 (selection count strip)
 */

import { useTranslation } from 'react-i18next';
import { HoverLabel } from './HoverLabel';
import { X } from './icons';

export function SelectionCountStrip({
  selectedCount,
  totalCount,
  onSelectAll,
  onDeselectAll,
}: {
  selectedCount: number;
  totalCount: number;
  onSelectAll: () => void;
  onDeselectAll: () => void;
}) {
  const { t } = useTranslation('notes');
  const allSelected = selectedCount >= totalCount;

  return (
    <div className="shrink-0 px-4 py-2 border-b border-divider bg-accent/5 dark:bg-accent/10 flex items-center justify-between gap-2 text-[13px]">
      <span className="flex items-center gap-2 min-w-0">
        <span className="font-medium text-neutral-700 dark:text-neutral-200 tabular-nums truncate">
          {t('selection.countOf', { selected: selectedCount, total: totalCount })}
        </span>
        <HoverLabel label={t('selection.deselectAll')} position="below">
          <button
            type="button"
            onClick={onDeselectAll}
            aria-label={t('selection.deselectAll')}
            className="shrink-0 w-5 h-5 rounded border border-divider bg-surface-1 inline-flex items-center justify-center text-neutral-500 dark:text-neutral-400 transition hover:text-accent hover:border-accent"
          >
            <X size={12} />
          </button>
        </HoverLabel>
      </span>
      {totalCount > 0 && (
        <button
          type="button"
          onClick={allSelected ? onDeselectAll : onSelectAll}
          className="shrink-0 font-semibold text-accent hover:underline"
        >
          {allSelected ? t('selection.deselectAll') : t('selection.selectAll')}
        </button>
      )}
    </div>
  );
}
