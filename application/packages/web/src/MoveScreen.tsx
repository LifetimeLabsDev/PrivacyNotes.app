import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuth } from './auth';
import { db } from './db';
import { sync } from './sync';
import { startMove } from './migrate';
import { marketingHomeHref } from './siteLinks';

/**
 * Full-page apex retirement screen (web apex, signed-in, non-demo).
 *
 * The apex stopped booting the notes app (domain-split retirement): a
 * straggler whose session still lives on privacynotes.app lands here
 * instead of NotesView, with exactly one job - move this device to
 * use.privacynotes.app. Same forced-sync gate as the MoveBanner: a
 * full sync, then a dirty-row count, and only a clean state hands off
 * via startMove(). Nothing on the apex is wiped, ever.
 *
 * The escape hatch: a sync error or conflict cannot be fixed on this
 * screen, so those states offer one legacy boot of the notes app
 * (onOpenNotes; App.tsx then renders NotesView for this session). Its
 * own sync pass re-raises any conflict into the ConflictModal, the
 * MoveBanner it still carries offers the move again, and the
 * retirement metric (NotesView-chunk fetches on the apex) stays honest
 * because only stuck sessions ever take this path.
 *
 * App lock needs no special handling here: the LockScreen and the
 * normal auth restore run before App.tsx picks this screen, so the
 * in-memory phrase the handoff needs always exists by now (the
 * relocation traps in ops/docs/domain-split.md are about reading the
 * stored phrase directly, which this screen never does).
 *
 * Spec: ops/docs/domain-split.md (retirement phase)
 */

type MoveState = 'idle' | 'syncing' | 'error' | 'conflict';

export function MoveScreen({ onOpenNotes }: { onOpenNotes: () => void }) {
  const { t } = useTranslation('notesChrome');
  const { auth, supabase } = useAuth();
  const [state, setState] = useState<MoveState>('idle');

  // Rendered only for an authenticated session (App.tsx routing), but
  // the union still needs narrowing before the fields can be captured.
  if (auth.status !== 'authenticated') return null;
  const { phrase, pubkey, encryptionKey, deviceId } = auth;

  async function handleMove() {
    setState('syncing');
    let pushErrors = 0;
    let conflicts = 0;
    try {
      await sync(
        supabase,
        pubkey,
        encryptionKey,
        deviceId,
        undefined,
        () => {
          pushErrors++;
        },
        () => {
          conflicts++;
        },
      );
      const dirty = await db.notes.where('dirty').anyOf(1, 2).count();
      if (conflicts > 0) {
        setState('conflict');
        return;
      }
      if (pushErrors > 0 || dirty > 0) {
        setState('error');
        return;
      }
    } catch {
      setState('error');
      return;
    }
    // Clean state confirmed - hand off. Navigates away; nothing wiped.
    startMove(phrase);
  }

  const stuck = state === 'error' || state === 'conflict';

  return (
    <div className="min-h-dvh bg-surface-0 text-pn flex items-center justify-center p-4">
      <div className="w-full max-w-md space-y-5 rounded-xl border border-divider bg-surface-2 p-6 sm:p-8">
        <h1 className="text-xl font-semibold">{t('moveScreen.title')}</h1>
        <p className="text-sm leading-relaxed text-neutral-600 dark:text-neutral-400">
          {t('moveScreen.body')}
        </p>
        {stuck && (
          <p className="text-sm leading-relaxed text-amber-700 dark:text-amber-400">
            {state === 'conflict' ? t('moveBanner.conflict') : t('moveBanner.error')}
          </p>
        )}
        <button
          type="button"
          disabled={state === 'syncing'}
          onClick={() => void handleMove()}
          className="w-full rounded-lg bg-accent hover:bg-accent-hover text-white text-sm font-semibold px-4 py-2.5 transition disabled:opacity-60"
        >
          {state === 'syncing' ? t('moveBanner.syncing') : t('moveBanner.cta')}
        </button>
        {stuck && (
          <button
            type="button"
            onClick={onOpenNotes}
            className="w-full rounded-lg border border-divider hover:bg-surface-1 text-sm font-medium px-4 py-2.5 transition"
          >
            {t('moveScreen.openNotes')}
          </button>
        )}
        <p className="text-center text-sm">
          <a
            href={marketingHomeHref()}
            className="text-neutral-500 dark:text-neutral-400 underline underline-offset-2 hover:text-pn transition"
          >
            {t('moveScreen.website')}
          </a>
        </p>
      </div>
    </div>
  );
}
