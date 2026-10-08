import { isDemoMode } from './demo';
import { mayWriteUnstamped } from './liveSignIn';
import { settingsLocalKey } from './settingsLocalKey';

/**
 * Advance the created-in-app item counter by one. createNote() is the
 * only caller - the importer writes rows directly (import/apply.ts), so
 * an import never moves the counter, and a create that brings content in
 * from elsewhere passes `counted: false`. See the notesCreated field doc in
 * userSettings.ts for the sync and merge rules.
 *
 * This is a raw JSON patch on the cached settings blob, not a
 * read-hydrate-save through userSettings.ts, on purpose: notesRepo.ts
 * must stay importable in node (the parser tests use normalizeTag), and
 * the userSettings import chain reads browser globals at module load.
 * The blob is re-hydrated and validated on every normal read.
 */
export function bumpNotesCreated(): void {
  // The same fence as saveLocalSettings: after a sign-out this writer would
  // mint the cache again, or put back a whole envelope read before another
  // tab's sign-out cleared it, PIN wrap included.
  const allowed = () => isDemoMode() || mayWriteUnstamped();
  if (!allowed()) return;
  try {
    const key = settingsLocalKey();
    const raw = localStorage.getItem(key);
    const cache: { settings?: unknown; updatedAt?: string; dirty?: boolean; everPulled?: boolean } =
      raw ? JSON.parse(raw) : {};
    if (!raw) {
      // Minting the cache from nothing: this device has never pulled, and
      // it must SAY so. readLocal defaults an absent everPulled to true
      // (for caches that predate the field), so leaving it off here would
      // classify a fresh device as pulled and reopen the defaults-over-
      // server wipe through the one writer that bypasses saveLocalSettings.
      // An existing cache keeps whatever it has - absent stays absent.
      cache.everPulled = false;
    }
    if (!cache.settings || typeof cache.settings !== 'object') {
      cache.settings = {};
    }
    const s = cache.settings as Record<string, unknown>;
    const cur = s.notesCreated;
    const base =
      typeof cur === 'number' && Number.isFinite(cur) && cur >= 0
        ? Math.floor(cur)
        : 0;
    s.notesCreated = base + 1;
    // The settings freshness counter moves with any write that will be pushed,
    // and this is the one writer that bypasses saveLocalSettings. A blob that
    // reached the server with a higher number and then a lower one from here
    // would read as a rollback on the next device to pull it.
    const rev = s.settingsRev;
    s.settingsRev =
      (typeof rev === 'number' && Number.isFinite(rev) && rev >= 0 ? Math.floor(rev) : 0) + 1;
    cache.updatedAt = new Date().toISOString();
    cache.dirty = true;
    localStorage.setItem(key, JSON.stringify(cache));
    if (!allowed()) localStorage.removeItem(key);
  } catch {
    /* storage full / disabled - the counter is best-effort */
  }
}
