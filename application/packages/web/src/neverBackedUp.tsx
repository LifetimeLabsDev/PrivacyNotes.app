import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { WarningCircle } from './icons';
import { db, type LocalNote } from './db';
import { deriveDisplayTitle } from './notesViewUtils';
import { isDemoMode } from './demo';
import { getPushFailures } from './pushFailures';

/**
 * "Never backed up": a note the server has never confirmed.
 *
 * Every accepted push and every pulled row stamps `syncedNonce`, so a row
 * with an unsynced change and no nonce exists on this device only. That
 * is the one class of note a permanent delete or a chosen sign-out
 * destroys outright, and the confirms for both say so before the click.
 * A stale row with a nonce is deliberately NOT in this class: the server
 * holds an older copy, so deleting it loses an edit, never the note. The
 * one stale case that still gets a line is a note the last pass could
 * not push (pushFailures.ts): its latest changes exist here only, and a
 * note that grew past the size limit after one successful push is
 * exactly that.
 *
 * Demo never syncs, so every demo row would qualify; the queries return
 * nothing there rather than warn about a promise demo never made.
 * Spec: ops/docs/ui-patterns.md (the not-backed-up state)
 */
export function isNeverBackedUp(n: Pick<LocalNote, 'dirty' | 'syncedNonce'>): boolean {
  return n.dirty !== 0 && n.syncedNonce == null;
}

/** `only`: ids that exist on this device only. `changes`: ids with a
 *  server copy whose latest changes the last pass could not push. */
async function countNotBackedUp(ids: readonly string[]): Promise<{ only: number; changes: number }> {
  if (ids.length === 0 || isDemoMode()) return { only: 0, changes: 0 };
  const rows = await db.notes.bulkGet([...ids]);
  const failing = getPushFailures();
  let only = 0;
  let changes = 0;
  for (const r of rows) {
    if (!r) continue;
    if (isNeverBackedUp(r)) only += 1;
    else if (r.dirty !== 0 && failing.has(r.id)) changes += 1;
  }
  return { only, changes };
}

/** Every live note whose latest version exists on this device only, for
 *  the sign-out confirm: never pushed, or refused on the last pass. */
export async function listNeverBackedUp(): Promise<Array<{ id: string; title: string }>> {
  if (isDemoMode()) return [];
  const rows = await db.notes.where('dirty').anyOf(1, 2).toArray();
  const failing = getPushFailures();
  return rows
    .filter((r) => r.deleted !== 1 && (r.syncedNonce == null || failing.has(r.id)))
    .map((r) => ({ id: r.id, title: deriveDisplayTitle(r) }));
}

/** Reactive counts for a confirm dialog. Keyed on the id list's content,
 *  so a caller may pass a fresh array on every render. */
function useNotBackedUpCounts(ids: readonly string[] | null): { only: number; changes: number } {
  const [counts, setCounts] = useState({ only: 0, changes: 0 });
  const key = ids ? ids.join('|') : '';
  useEffect(() => {
    let cancelled = false;
    if (!key) {
      setCounts({ only: 0, changes: 0 });
      return;
    }
    void countNotBackedUp(key.split('|')).then((n) => {
      if (!cancelled) setCounts(n);
    });
    return () => {
      cancelled = true;
    };
  }, [key]);
  return counts;
}

/**
 * The amber line inside a permanent-delete confirm. Renders nothing when
 * every target has a server copy, so the confirms stay as they were for
 * the common case.
 */
export function NeverBackedUpNotice({ ids }: { ids: readonly string[] | null }) {
  const { t } = useTranslation('common');
  const { only, changes } = useNotBackedUpCounts(ids);
  if (only === 0 && changes === 0) return null;
  const single = (ids?.length ?? 0) === 1;
  return (
    <div className="mt-3 flex items-start gap-2 rounded-md border border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 text-amber-800 dark:text-amber-300 text-[13px] leading-snug p-3">
      <WarningCircle size={16} className="shrink-0 mt-0.5" />
      <span className="space-y-1">
        {only > 0 && <span className="block">{single ? t('neverBackedUp.one') : t('neverBackedUp.some', { count: only })}</span>}
        {changes > 0 && <span className="block">{single ? t('neverBackedUp.changesOne') : t('neverBackedUp.changesSome', { count: changes })}</span>}
      </span>
    </div>
  );
}
