/**
 * The moved-from-apex marker. MovedBookmarkHint (MoveBanner.tsx) shows its
 * one-time "update your bookmark" notice on the app host while this
 * localStorage flag is set; Got it clears it, and sign-out removes it with
 * the rest of the install's local state (authStorage.ts). This build never
 * sets it: an install that already carries it keeps the notice until Got it.
 *
 * Spec: ops/docs/domain-split.md
 */

const MOVED_FLAG_KEY = 'privacynotes.movedFromApex';

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
