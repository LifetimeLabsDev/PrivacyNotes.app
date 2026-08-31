import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from './db';
import { HoverLabel } from './HoverLabel';
import { PencilSimple, Trash } from './icons';

/**
 * The edit / delete pair a bookmark row wears on hover.
 *
 * Passed as `trailing` to NoteRow and NoteCard, so the reveal, the placement
 * and the truncation bargain all come from the row itself (`pn-row-actions`
 * in index.css). Lives in its own file because a bookmark is a bookmark in
 * every pillar: the Bookmarks pane draws these, and so do the All and Pinned
 * lists, which showed a link row with no way to edit or delete it until
 * 2026-08-25.
 *
 * Delete is armed, not immediate: the first click swaps the pair for a
 * labelled confirm pill, a second click inside three seconds does it, and
 * silence disarms. Each row owns that state, so arming one never disturbs
 * another.
 *
 * Spec: ops/docs/ui-patterns.md (section 74)
 */
export function BookmarkRowActions({
  note,
  onEdit,
  onTrash,
  tipPos,
}: {
  note: LocalNote;
  onEdit: (note: LocalNote) => void;
  onTrash: (note: LocalNote) => void;
  /** Grid tiles put the tip above the cluster; list rows put it before it. */
  tipPos: 'above-start' | 'start';
}) {
  const { t } = useTranslation('shell');
  const [armed, setArmed] = useState(false);
  const timer = useRef<ReturnType<typeof setTimeout> | null>(null);
  useEffect(() => () => { if (timer.current) clearTimeout(timer.current); }, []);

  function arm(e: React.MouseEvent) {
    e.stopPropagation();
    if (timer.current) clearTimeout(timer.current);
    if (armed) {
      setArmed(false);
      onTrash(note);
      return;
    }
    setArmed(true);
    timer.current = setTimeout(() => setArmed(false), 3000);
  }

  if (armed) {
    return (
      <button
        type="button"
        onClick={arm}
        /* Opaque, and bordered like the two icon buttons it replaces. This
           cluster leaves the flow on a tile and on a hovered row, so it sits
           ON the title - `dark:bg-red-950/30` let the title read straight
           through the armed pill, worst on a mini tile where the two overlap
           almost completely (reported 2026-08-23).
           Spec: ops/docs/ui-patterns.md (section 74) */
        className="inline-flex items-center gap-1 rounded-full border border-red-200 bg-red-50 px-2.5 py-1 text-xs font-medium text-red-600 transition hover:bg-red-100 dark:border-red-900 dark:bg-red-950 dark:text-red-400 dark:hover:bg-red-900"
      >
        <Trash size={13} />
        {t('media:attachment.deleteConfirm')}
      </button>
    );
  }

  return (
    <>
      <HoverLabel label={t('common:actions.edit')} position={tipPos}>
        <button
          type="button"
          onClick={(e) => { e.stopPropagation(); onEdit(note); }}
          aria-label={t('common:actions.edit')}
          className="w-7 h-7 rounded-md border border-divider bg-surface-1 text-neutral-500 dark:text-neutral-400 inline-flex items-center justify-center transition hover:text-accent hover:border-accent"
        >
          <PencilSimple size={14} />
        </button>
      </HoverLabel>
      <HoverLabel label={t('bookmarks.moveToTrash')} position={tipPos}>
        <button
          type="button"
          onClick={arm}
          aria-label={t('bookmarks.moveToTrash')}
          /* Opaque on hover, for the same reason the armed pill above is:
             this cluster leaves the flow and sits ON the row title, so a
             tinted `dark:hover:bg-red-950/30` let the title read straight
             through the button (reported 2026-08-25).
             Spec: ops/docs/ui-patterns.md (section 74) */
          className="w-7 h-7 rounded-md border border-divider bg-surface-1 text-red-600 dark:text-red-400 inline-flex items-center justify-center transition hover:border-red-400 hover:bg-red-50 dark:hover:bg-red-950"
        >
          <Trash size={14} />
        </button>
      </HoverLabel>
    </>
  );
}
