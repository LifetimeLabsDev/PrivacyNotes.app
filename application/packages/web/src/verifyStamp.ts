import { useSyncExternalStore } from 'react';

/**
 * The last CLEAN "Verify sync" result on this device: when it ran and
 * how many items matched. Feeds the one-line "Verified 2 h ago - 562
 * items match" in the sync panel, so the green word above it is at most
 * one glance away from the last time it was actually tested.
 *
 * Only clean results are recorded (in_sync, no blobs still queued): the
 * line is a claim of full agreement, and a diverged or busy check must
 * not refresh it. Cleared with the rest of local state on sign-out via
 * the shared localStorage wipe.
 */

export type VerifyStamp = { at: number; items: number };

const STORAGE_KEY = 'privacynotes.verifyStamp';

function readStored(): VerifyStamp | null {
  try {
    if (typeof localStorage === 'undefined') return null;
    const raw = localStorage.getItem(STORAGE_KEY);
    if (!raw) return null;
    const parsed = JSON.parse(raw) as VerifyStamp;
    if (typeof parsed?.at !== 'number' || typeof parsed?.items !== 'number') return null;
    return parsed;
  } catch {
    return null;
  }
}

let stamp: VerifyStamp | null = readStored();
const listeners = new Set<() => void>();

export function recordCleanVerify(items: number): void {
  stamp = { at: Date.now(), items };
  try {
    localStorage.setItem(STORAGE_KEY, JSON.stringify(stamp));
  } catch {
    // Storage blocked - the in-memory stamp still serves this session.
  }
  for (const cb of listeners) cb();
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

export function useVerifyStamp(): VerifyStamp | null {
  return useSyncExternalStore(subscribe, () => stamp, () => null);
}
