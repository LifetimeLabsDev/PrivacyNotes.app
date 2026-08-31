import { useSyncExternalStore } from 'react';

/**
 * "A newer build exists" as app-wide state, so the signal outlives the toast.
 *
 * Since v0.305.0 an optional update's toast can be dismissed for 48h
 * (updateSnooze.ts), which would otherwise mean the only notice of an update
 * disappears the moment the user pushes it away. The rail's Downloads button
 * carries a dot for as long as the update is outstanding: quiet, permanent,
 * and one click from the page that has the newer build. Same trade the demo
 * banner makes against SyncStatus - one carrier may be dismissed precisely
 * because the other one cannot.
 *
 * Written by whichever checker already runs for this platform (DesktopUpdater
 * for macOS/Windows/Linux, AndroidUpdateToast for the direct APK), so the badge
 * costs no extra polling and no second manifest fetch. Set BEFORE the snooze
 * check in both, or a dismissed toast would take the dot with it.
 *
 * Deliberately not set on web: there the remedy is a page refresh
 * (VersionUpdateToast), and pointing someone at the downloads page for that
 * would be a lie.
 *
 * Spec: ops/docs/android-update-check.md (optional vs required updates)
 */

let available: string | null = null;
const listeners = new Set<() => void>();

/** Record the newer version (or null to clear). Idempotent. */
export function setUpdateAvailable(version: string | null): void {
  if (available === version) return;
  available = version;
  for (const listener of listeners) listener();
}

/** The outstanding newer version, or null. */
export function useUpdateAvailable(): string | null {
  return useSyncExternalStore(
    (onChange) => {
      listeners.add(onChange);
      return () => {
        listeners.delete(onChange);
      };
    },
    () => available,
    () => null,
  );
}
