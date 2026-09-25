import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { useAuth } from './auth';
import { db } from './db';
import { sync } from './sync';
import { hasMovedFromApexFlag, clearMovedFromApexFlag } from './migrate';
import { APP_ORIGIN, isApexHost, isAppHost } from './hosts';
import { isDemoMode } from './demo';
import { detectPlatform } from './devices';
import { X } from './icons';
import type { NoteConflict } from './sync';

/**
 * The two user-facing halves of the domain move, both rendered as
 * in-flow bars at the top of NotesView's column (the DemoBanner
 * pattern from ui-patterns.md section 39 - a bar in the flow cannot
 * occlude anything):
 *
 *   - MoveBanner (apex): the MoveScreen in one line. It says where the
 *     app lives and how to sign in there, and its button refuses to leave
 *     with unsynced work: it runs a full sync, then counts dirty rows,
 *     and only a clean state opens use.privacynotes.app. Nothing on the
 *     apex is ever wiped. NotesView on the apex is reachable only
 *     through the MoveScreen's stuck-state escape hatch, so this banner
 *     is the second chance after the user fixed what blocked the sync.
 *
 *   - MovedBookmarkHint (app host): one-time "update your bookmark"
 *     notice, keyed off the movedFromApex flag (migrate.ts).
 *
 * Spec: ops/docs/domain-split.md (cutover checklist: move trigger +
 * user comms)
 */

type MoveState = 'idle' | 'syncing' | 'error' | 'conflict';

const DISMISS_KEY = 'pn:moveBannerDismissed';

const APP_HOME = `${APP_ORIGIN}/`;

/** Retirement banner on the apex: a button to the app host behind a forced sync. */
export function MoveBanner({ onConflict }: { onConflict: (conflict: NoteConflict) => void }) {
  const { t } = useTranslation('notesChrome');
  const { auth, supabase } = useAuth();
  const [state, setState] = useState<MoveState>('idle');
  const [dismissed, setDismissed] = useState(() => {
    try {
      return sessionStorage.getItem(DISMISS_KEY) === '1';
    } catch {
      return false;
    }
  });

  if (dismissed) return null;
  if (!isApexHost() || isDemoMode() || detectPlatform() !== 'web') return null;
  if (auth.status !== 'authenticated') return null;

  // Capture the authenticated fields for the async handler: the state
  // union narrows here, and the handler must not re-read a possibly
  // changed auth object mid-flight.
  const { pubkey, encryptionKey, deviceId } = auth;

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
        (conflict) => {
          conflicts++;
          onConflict(conflict);
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
    // Clean state confirmed - leave for the app host's sign-in screen.
    // Navigates away; nothing wiped.
    window.location.assign(APP_HOME);
  }

  function handleDismiss() {
    try {
      sessionStorage.setItem(DISMISS_KEY, '1');
    } catch {
      /* ignore */
    }
    setDismissed(true);
  }

  const showFeedback = state === 'error' || state === 'conflict';

  return (
    <div className="shrink-0 flex items-center gap-2 sm:gap-3 border-b border-accent/40 bg-accent/5 dark:bg-accent/10 px-3 sm:px-4 py-2">
      <p
        className={`min-w-0 flex-1 text-[13px] leading-snug text-pn ${showFeedback ? '' : 'truncate'}`}
      >
        <span className={showFeedback ? 'hidden sm:inline font-semibold' : 'font-semibold'}>
          {t('moveScreen.title')}
        </span>
        {/* Mini on phones: the description drops, leaving title + CTA.
            Error/conflict feedback instead REPLACES the title there and
            is allowed to wrap - feedback inside the hidden span made a
            failed move look like a dead button on phones. */}
        <span
          className={`${showFeedback ? 'inline' : 'hidden sm:inline'} text-neutral-600 dark:text-neutral-400`}
        >
          {' '}
          {state === 'conflict'
            ? t('moveBanner.conflict')
            : state === 'error'
              ? t('moveBanner.error')
              : t('moveBanner.bodySignIn', { scanQr: t('importPhrase.scanQr', { ns: 'auth' }) })}
        </span>
      </p>
      <button
        type="button"
        disabled={state === 'syncing'}
        onClick={() => void handleMove()}
        className="shrink-0 rounded-lg bg-accent hover:bg-accent-hover text-white text-[13px] font-semibold px-3 py-1.5 transition disabled:opacity-60"
      >
        {state === 'syncing' ? t('moveBanner.syncing') : t('moveBanner.cta')}
      </button>
      <button
        type="button"
        onClick={handleDismiss}
        aria-label={t('dismiss')}
        className="shrink-0 rounded-md p-1 text-neutral-500 dark:text-neutral-400 hover:bg-accent/10 transition"
      >
        <X />
      </button>
    </div>
  );
}

/**
 * One-time bookmark hint on the app host. Visible while the movedFromApex
 * flag is set on this install (migrate.ts); Got it clears it.
 */
export function MovedBookmarkHint() {
  const { t } = useTranslation('notesChrome');
  const [visible, setVisible] = useState(
    // Web-only by explicit intent (not just because tauri://localhost
    // never matches the app host): bookmarks and home-screen shortcuts
    // are browser concepts, so native builds must never show this.
    () =>
      detectPlatform() === 'web' && isAppHost() && hasMovedFromApexFlag(),
  );

  if (!visible) return null;

  function handleGotIt() {
    clearMovedFromApexFlag();
    setVisible(false);
  }

  return (
    <div className="shrink-0 flex items-center gap-2 sm:gap-3 border-b border-emerald-300/80 dark:border-emerald-800/70 bg-emerald-50 dark:bg-emerald-950/90 px-3 sm:px-4 py-2">
      <p className="min-w-0 flex-1 truncate text-[13px] leading-snug text-emerald-950 dark:text-emerald-100">
        {t('movedHint.body')}
      </p>
      <button
        type="button"
        onClick={handleGotIt}
        className="shrink-0 rounded-lg bg-emerald-700 hover:bg-emerald-800 text-white text-[13px] font-semibold px-3 py-1.5 transition"
      >
        {t('movedHint.gotIt')}
      </button>
    </div>
  );
}
