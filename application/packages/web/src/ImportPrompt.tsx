import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ListEntryCard } from './ListEntryCard';
import { Download } from './icons';

/**
 * The standing import offer: a row in a list pane, a tile in the grid,
 * drawn after the items a pillar already holds.
 *
 * It exists because every importer used to have exactly one door inside its
 * pillar, the empty state, which the first saved item closed - and the person
 * most likely to want their whole collection is the one who just proved they
 * use the pillar at all. Every pillar that has an importer gets the same
 * entry, differing only in its label and in the tab it opens.
 *
 * Spec: ops/docs/design-decisions.md (bookmarks import prompt)
 */

export type ImportPromptKind = 'notes' | 'journal' | 'tasks' | 'vault' | 'bookmarks' | 'contacts';

/**
 * The offer retires at this many items in the pillar: past it the pillar is
 * plainly in use, and a permanent nudge to fill it is noise. The threshold is
 * per pillar because the collections are not the same shape. Bookmarks and
 * passwords arrive by the hundred and in one file, so 50 is still early days
 * for someone who has not imported yet. Notes, tasks and journals are written
 * one at a time, so 25 of them already say the pillar is in use.
 * Spec: ops/docs/design-decisions.md (bookmarks import prompt)
 */
const IMPORT_PROMPT_MAX_ITEMS: Record<ImportPromptKind, number> = {
  notes: 25,
  journal: 25,
  tasks: 25,
  vault: 50,
  bookmarks: 50,
  contacts: 50,
};

/** Device-local UI chrome, like the sidebar collapse flags. One key per
 *  pillar: hiding the passwords offer says nothing about the notes one. */
const storageKey = (kind: ImportPromptKind) => `privacynotes.importPrompt.hidden.${kind}`;

function readHidden(kind: ImportPromptKind): boolean {
  try {
    return localStorage.getItem(storageKey(kind)) === '1';
  } catch {
    return false;
  }
}

/**
 * `count` is the pillar's own item count, `suppressed` the conditions that
 * are not about the offer itself: a live search or an active folder/tag filter
 * (a promo among scoped results reads as a result, and the slot belongs to the
 * `ActiveFilterEntry` that explains the scope), and selection mode (it is the
 * one entry that cannot be selected).
 *
 * The hidden flag is READ per render rather than seeded into state, because
 * one NotesList instance serves Notes, Journals and the Vault: state seeded
 * at mount would carry one pillar's dismissal into the next view the user
 * switches to.
 */
export function useImportPrompt(
  kind: ImportPromptKind,
  { count, suppressed = false }: { count: number; suppressed?: boolean },
) {
  const [dismissals, setDismissals] = useState(0);
  const hidden = useMemo(() => readHidden(kind), [kind, dismissals]);

  function dismiss() {
    try {
      localStorage.setItem(storageKey(kind), '1');
    } catch {
      /* storage full / disabled - the entry just comes back next session */
    }
    setDismissals((n) => n + 1);
  }

  return { show: !hidden && !suppressed && count < IMPORT_PROMPT_MAX_ITEMS[kind], dismiss };
}

export function ImportPromptEntry({
  kind,
  variant,
  onOpen,
  onDismiss,
}: {
  kind: ImportPromptKind;
  /** 'tile' in a grid pane, 'row' in a list pane. */
  variant: 'row' | 'tile';
  onOpen: () => void;
  onDismiss: () => void;
}) {
  const { t } = useTranslation('shell');
  return (
    <ListEntryCard
      variant={variant}
      icon={Download}
      label={t(`importPrompt.${kind}`)}
      onClick={onOpen}
      onDismiss={onDismiss}
      dismissLabel={t('importPrompt.dismiss')}
    />
  );
}
