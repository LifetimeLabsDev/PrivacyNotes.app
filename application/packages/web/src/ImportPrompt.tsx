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

/**
 * One dismissal hides the offer in every pillar and on every device: it is
 * the synced `importPromptDismissed` flag, never a per-pillar key. A person
 * who closes "Import notes" and then meets "Import journal" reads the second
 * one as the first coming back.
 */
export type ImportOffer = { dismissed: boolean; onDismiss: () => void };

const LEGACY_KINDS: ImportPromptKind[] = ['notes', 'journal', 'tasks', 'vault', 'bookmarks', 'contacts'];
const legacyKey = (kind: ImportPromptKind) => `privacynotes.importPrompt.hidden.${kind}`;

/**
 * True when this device holds a dismissal from the per-pillar keys that came
 * before the synced flag. The keys are removed, so the answer is given once.
 */
export function takeLegacyImportDismissal(): boolean {
  let found = false;
  try {
    for (const kind of LEGACY_KINDS) {
      if (localStorage.getItem(legacyKey(kind)) === '1') found = true;
      localStorage.removeItem(legacyKey(kind));
    }
  } catch {
    /* storage unavailable - nothing to carry over */
  }
  return found;
}

/**
 * `count` is the pillar's own item count, `suppressed` the conditions that
 * are not about the offer itself: a live search or an active folder/tag filter
 * (a promo among scoped results reads as a result, and the slot belongs to the
 * `ActiveFilterEntry` that explains the scope), and selection mode (it is the
 * one entry that cannot be selected).
 */
export function importPromptFor(
  kind: ImportPromptKind,
  { count, suppressed = false, offer }: { count: number; suppressed?: boolean; offer: ImportOffer },
) {
  return {
    show: !offer.dismissed && !suppressed && count < IMPORT_PROMPT_MAX_ITEMS[kind],
    dismiss: offer.onDismiss,
  };
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
