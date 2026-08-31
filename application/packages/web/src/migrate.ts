/**
 * Domain-move handoff, emitter side.
 *
 * Hands a signed-in apex session to use.privacynotes.app without a
 * re-login: the phrase, deviceSecret, trust flag and language travel in
 * the URL FRAGMENT, which the browser never sends to any server - the
 * same reasoning as the QR sign-in flow (qrSignIn.ts). The receiving
 * side is the existing consumePhraseFragment() -> QrSignInPrompt
 * confirm in App.tsx; the carried extras are adopted only after the
 * user confirms there.
 *
 * Three triggers, all apex-only: the MoveScreen (the retired apex's
 * only signed-in surface, behind a forced sync so no dirty rows are
 * left behind), the MoveBanner in NotesView (same gate; reachable only
 * through the MoveScreen's stuck-state escape hatch since retirement),
 * and the ?move=1 manual test switch, which assumes the tester checked
 * for a green sync state first. Either way nothing on the apex is ever
 * wiped, so a missed row pushes on the next apex visit instead of
 * being lost.
 *
 * Spec: ops/docs/domain-split.md
 */

import { APP_ORIGIN, isApexHost } from './hosts';
import { getStoredDeviceSecretHex } from './devices';
import { isTrustedDevice } from './trustStorage';
import { activeLocale } from './languages';

// The MOVE_PROMPT_ENABLED cutover switch lived here from 2026-07-28
// until the apex retirement (2026-08-25) removed it: with the apex no
// longer booting the notes app, the cutover is not a togglable state
// anymore, and rollback means reverting the retirement commit.
// Spec: ops/docs/domain-split.md

/**
 * localStorage marker set on the app host right after a successful
 * migration handoff sign-in. MovedBookmarkHint reads it to show the
 * one-time "update your bookmark" notice; Got it clears it.
 */
const MOVED_FLAG_KEY = 'privacynotes.movedFromApex';

export function markMovedFromApex(): void {
  try {
    localStorage.setItem(MOVED_FLAG_KEY, '1');
  } catch {
    /* ignore */
  }
}

export function hasMovedFromApexFlag(): boolean {
  try {
    return localStorage.getItem(MOVED_FLAG_KEY) === '1';
  } catch {
    return false;
  }
}

export function clearMovedFromApexFlag(): void {
  try {
    localStorage.removeItem(MOVED_FLAG_KEY);
  } catch {
    /* ignore */
  }
}

/** True when this page load explicitly requested the move (apex + ?move=1). */
export function moveRequested(): boolean {
  if (!isApexHost()) return false;
  try {
    return new URLSearchParams(window.location.search).get('move') === '1';
  } catch {
    return false;
  }
}

/**
 * Build the handoff URL and leave for the app host. Both callers hold
 * an authenticated session and pass its in-memory phrase. The stored
 * copy must NOT be read here: app lock (PinTab/BiometricTab) removes
 * the plaintext phrase and keeps only the wrapped blob, so the storage
 * read this used to do returned null for every app-lock user and
 * silently killed their move (found 2026-08-13, the dead Move-now
 * report). Wipes nothing on either origin.
 */
export function startMove(phrase: string): void {
  const params = new URLSearchParams();
  const device = getStoredDeviceSecretHex();
  if (device) params.set('device', device);
  params.set('trust', isTrustedDevice() ? '1' : '0');
  params.set('lang', activeLocale());

  // Same encoding as buildSignInUrl: BIP-39 words are lowercase ASCII,
  // spaces become `+` so the fragment stays readable.
  const encoded = phrase.trim().replace(/\s+/g, '+');
  window.location.replace(
    `${APP_ORIGIN}/#phrase=${encoded}&${params.toString()}`,
  );
}
