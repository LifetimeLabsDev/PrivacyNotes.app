import { useTranslation } from 'react-i18next';
import { ListEntryCard } from './ListEntryCard';
import { OverflowTip } from './OverflowTip';
import { Backspace, Folder, FunnelSimple, Hash, Prohibit, X } from './icons';

/**
 * Dismissable "this list is filtered" chips - one per active filter.
 *
 * Rendered directly under the h-14 title row by every pillar list that can be
 * scoped - notes, tasks, files and bookmarks - so the four cannot drift apart.
 * The title above stays a plain view label; these chips carry the (truncating)
 * folder name and tag, and one click clears that one filter. An empty list can
 * therefore never silently be a forgotten selection.
 *
 * Amber on purpose, and the same amber for both: the chips answer "why am I
 * not seeing everything?", so they must not read as the accent-coloured
 * furniture the rest of the pane is built from.
 *
 * The folder, the tag and the open view compose into one combined filter, so
 * two chips can stand side by side. They wrap rather than truncate the band.
 *
 * The band copies the search row below it exactly - `p-3 border-b
 * border-divider` - so the two read as one stack of bands and the chips line
 * up with the funnel button under them. It used to be `px-4 pt-2`, which put
 * the chip 4px right of everything below it.
 *
 * Renders nothing when no filter is active, so callers can mount it
 * unconditionally.
 *
 * Spec: ops/docs/ui-patterns.md (section 41)
 */

/** Sentinel for the "Untagged" bucket - notes carrying no tag at all. */
const UNTAGGED = '__untagged__';

const CHIP_CLASS =
  'max-w-full inline-flex items-center gap-1.5 rounded-full bg-amber-500/10 hover:bg-amber-500/20 text-amber-700 dark:text-amber-400 ps-2.5 pe-2 py-1 text-[12px] font-medium transition';

export function ListFilterChips({
  folderName,
  tag,
  onClearFolder,
  onClearTag,
}: {
  folderName: string | null;
  tag: string | null;
  onClearFolder: () => void;
  onClearTag: () => void;
}) {
  const { t } = useTranslation('notes');
  if (folderName === null && tag === null) return null;
  const untagged = tag === UNTAGGED;
  const tagLabel = untagged ? t('headerLabel.untagged') : tag;
  return (
    <div className="shrink-0 p-3 border-b border-divider flex flex-wrap items-center gap-1.5 min-w-0">
      {folderName !== null && (
        <OverflowTip text={folderName} className="min-w-0 flex">
          <button
            type="button"
            onClick={onClearFolder}
            aria-label={t('folderChip.clear', { folder: folderName })}
            className={CHIP_CLASS}
          >
            <Folder size={13} className="shrink-0" aria-hidden="true" />
            <span className="truncate" dir="auto">{folderName}</span>
            <X size={11} className="shrink-0" aria-hidden="true" />
          </button>
        </OverflowTip>
      )}
      {tagLabel !== null && (
        <OverflowTip text={tagLabel} className="min-w-0 flex">
          <button
            type="button"
            onClick={onClearTag}
            aria-label={t('tagChip.clear', { tag: tagLabel })}
            className={CHIP_CLASS}
          >
            {untagged ? (
              <Prohibit size={13} className="shrink-0" aria-hidden="true" />
            ) : (
              <Hash size={13} className="shrink-0" aria-hidden="true" />
            )}
            <span className="truncate" dir="auto">{tagLabel}</span>
            <X size={11} className="shrink-0" aria-hidden="true" />
          </button>
        </OverflowTip>
      )}
    </div>
  );
}

/**
 * The empty state a list shows when its filters hid everything.
 *
 * "No notes yet." on a list that is filtered down to nothing is the single
 * most alarming thing this app can say - it reads as "your notes are gone",
 * and the user has no reason to connect it to a chip at the top of the pane.
 * So the message names the cause, promises nothing was deleted, and offers
 * the one click that undoes it.
 *
 * Renders nothing when no filter is active, so a caller can hand it the same
 * props it hands the chips and let it decide.
 *
 * The caller keeps its own empty state for the unfiltered case, and for an
 * empty search - "No matches." already names its own cause, and the chips
 * above stay visible either way.
 *
 * Spec: ops/docs/ui-patterns.md (section 41)
 */
export function FilteredEmpty({
  folderName,
  tag,
  onClearFolder,
  onClearTag,
}: {
  folderName: string | null;
  tag: string | null;
  onClearFolder: () => void;
  onClearTag: () => void;
}) {
  const { t } = useTranslation('notes');
  if (folderName === null && tag === null) return null;
  return (
    <div className="flex flex-col items-center justify-center text-center px-6 py-12">
      <div className="w-12 h-12 rounded-full bg-amber-500/10 flex items-center justify-center mb-3">
        <FunnelSimple size={22} className="text-amber-700 dark:text-amber-400" aria-hidden="true" />
      </div>
      {/* One sentence with the button inside it: "No items match your
          filters. [Clear filters] To display them." The button is the verb,
          so the copy never has to spell out what to press. Three keys rather
          than one because the fragments sit either side of an element; each
          locale phrases its own half. */}
      <p className="text-sm font-medium text-neutral-600 dark:text-neutral-300 mb-3">
        {t('empty.filtered')}
      </p>
      <button
        type="button"
        onClick={() => { onClearFolder(); onClearTag(); }}
        className="text-xs font-medium text-white bg-accent hover:bg-accent-hover px-4 py-1.5 rounded-md transition"
      >
        {t('empty.clearFilters')}
      </button>
      {/* Same weight as the line above the button, never muted: the two are
          one sentence, and a muted half reads as a footnote instead. */}
      <p className="text-sm font-medium text-neutral-600 dark:text-neutral-300 max-w-[260px] mt-3">
        {t('empty.filteredAfter')}
      </p>
    </div>
  );
}

/**
 * The standing "a filter is on" entry, drawn among a pillar's items whenever a
 * filter is active AND the pane still has something to show.
 *
 * `FilteredEmpty` above answers the alarming case; this one answers the quiet
 * case, which is more common and easier to miss: the list is not empty, it is
 * just SHORT, and a short list reads as the whole collection. The chips at the
 * top of the pane are the other carrier of the same fact, but a person looking
 * at a list of three items is looking at the list, not at the band above it.
 *
 * It wears the import offer's shell on purpose (`ListEntryCard`): a pillar
 * already teaches that the entry after the items is an action rather than an
 * item, so the hint costs no new vocabulary. Amber and the funnel say which
 * kind of action, and the label is the one `FilteredEmpty` already uses, so no
 * locale gains a string.
 *
 * One click clears every active filter at once, exactly like the button in
 * `FilteredEmpty`. There is no dismiss button: the entry describes the pane's
 * own state, and clearing the filter is what removes it.
 *
 * Renders nothing when no filter is active, so a caller can hand it the same
 * props it hands the chips and let it decide.
 *
 * Spec: ops/docs/ui-patterns.md (section 41)
 */
export function ActiveFilterEntry({
  folderName,
  tag,
  onClearFolder,
  onClearTag,
  variant,
  as,
}: {
  folderName: string | null;
  tag: string | null;
  onClearFolder: () => void;
  onClearTag: () => void;
  /** 'tile' in a grid pane, 'row' in a list pane. */
  variant: 'row' | 'tile';
  /** 'div' in the Files pane, whose rows are buttons in a plain container. */
  as?: 'li' | 'div';
}) {
  const { t } = useTranslation('notes');
  if (folderName === null && tag === null) return null;
  return (
    <ListEntryCard
      variant={variant}
      as={as}
      tone="amber"
      icon={FunnelSimple}
      label={t('empty.clearFilters')}
      onClick={() => {
        onClearFolder();
        onClearTag();
      }}
    />
  );
}

/**
 * `ActiveFilterEntry`'s sibling, for the other thing that narrows a list.
 *
 * It lives in this file rather than beside the search input because the two
 * entries are one idea - "here is why you are seeing less, and here is the
 * click that undoes it" - and they share a slot, a shape and an amber. Split
 * across two files they would drift.
 *
 * It appears ONLY when the search found nothing, which is the asymmetry that
 * matters: a search explains itself, because the text sits in the box the
 * person just typed into, so an entry beside results would be noise. An empty
 * pane is the exception - there is nothing else in it to explain the silence,
 * and the input's own clear button is 40px of easily-missed chrome.
 *
 * The label is `common:actions.clearSearch`, which that clear button already
 * uses, so no locale gains a string.
 *
 * Renders nothing when the search box is empty.
 *
 * Spec: ops/docs/ui-patterns.md (section 41)
 */
export function ActiveSearchEntry({
  search,
  onClearSearch,
  variant,
  as,
}: {
  search: string;
  onClearSearch: () => void;
  /** 'tile' in a grid pane, 'row' in a list pane. */
  variant: 'row' | 'tile';
  /** 'div' in the Files pane, whose rows are buttons in a plain container. */
  as?: 'li' | 'div';
}) {
  const { t } = useTranslation('common');
  if (!search.trim()) return null;
  return (
    <ListEntryCard
      variant={variant}
      as={as}
      tone="amber"
      icon={Backspace}
      label={t('actions.clearSearch')}
      onClick={onClearSearch}
    />
  );
}
