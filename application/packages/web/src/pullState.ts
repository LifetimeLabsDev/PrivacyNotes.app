import { useSyncExternalStore } from 'react';
import { isDemoMode } from './demo';
import { isServerWriteBlocked, useSyncPaused } from './syncPause';
import { isBelowVersionFloor, useBelowVersionFloor } from './versionFloor';

/**
 * Whether this device has pulled the account since its local copy was last
 * emptied, and the gate a restore of our own backup waits behind.
 *
 * A restore matches each note of the backup to the vault by id, and the vault
 * it asks is this device's local copy: a note it does not find there comes in
 * under a fresh id (import/apply.ts). Until a pull has run over the copy as it
 * stands, the copy can lack notes the account holds, all of them on a new
 * device or after a wipe, and a restore would add each one again beside the
 * original the pull then brings. Both restore doors (the .zip and .pnbackupz
 * in ImportModal, the .pnbackup in useExports) read the gate before they write
 * anything. Foreign importers mint new ids by design and never wait.
 *
 * The orchestrator marks the pull after a pass that ran, finished its notes
 * pull and read the settings from the server: the rule that opens the trash
 * purge (pullOpensTrashPurge in trashPurge.ts). The two local wipes in
 * notesRepo.ts clear the mark as they begin. A sign-out, a forced sign-out and
 * an account switch all empty the copy without reloading the app, so the next
 * session in the same tab reopens the gate only with its own pull. A page load
 * starts shut. The demo has no server to double, so its gate is always open.
 */

let pulledClean = false;
/** Counts the local wipes, so a pass that began before one cannot mark after it. */
let wipeGeneration = 0;
const listeners = new Set<() => void>();

/** The generation a pass captures as it starts, and hands back with its mark. */
export function wipeGenerationNow(): number {
  return wipeGeneration;
}

/**
 * Mark the pull. `startedAt` is the wipe generation the pass captured before
 * it began: a pass whose pull finished before a wipe and whose settings read
 * lands after it would otherwise reopen the gate over an emptied copy, and
 * the next session in the same tab would restore before its own first pull.
 */
export function markPulledClean(startedAt: number = wipeGeneration): void {
  if (startedAt !== wipeGeneration) return;
  if (pulledClean) return;
  pulledClean = true;
  for (const cb of listeners) cb();
}

/** Called by the local wipes: the copy no longer holds what the pull brought. */
export function resetPulledClean(): void {
  wipeGeneration += 1;
  if (!pulledClean) return;
  pulledClean = false;
  for (const cb of listeners) cb();
}

export function hasPulledClean(): boolean {
  return pulledClean;
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

/** 'open' lets a restore run; every other value is why it waits. A device
 *  whose sync cannot run never pulls, so its value names that reason. */
export type RestoreGate = 'open' | 'wait' | 'paused' | 'belowFloor';

export function restoreGate(s: {
  pulled: boolean;
  demo: boolean;
  /** isServerWriteBlocked(): below the release floor, or paused by the user. */
  blocked: boolean;
  belowFloor: boolean;
}): RestoreGate {
  if (s.pulled || s.demo) return 'open';
  if (!s.blocked) return 'wait';
  return s.belowFloor ? 'belowFloor' : 'paused';
}

/** The gate as it stands, for the door about to write. */
export function restoreGateNow(): RestoreGate {
  return restoreGate({
    pulled: pulledClean,
    demo: isDemoMode(),
    blocked: isServerWriteBlocked(),
    belowFloor: isBelowVersionFloor(),
  });
}

/** Reactive restoreGateNow(), so the Restore tab opens when the pull lands. */
export function useRestoreGate(): RestoreGate {
  const pulled = useSyncExternalStore(subscribe, hasPulledClean, () => false);
  const paused = useSyncPaused();
  const belowFloor = useBelowVersionFloor();
  return restoreGate({ pulled, demo: isDemoMode(), blocked: paused || belowFloor, belowFloor });
}

/** The line each closed gate shows, from the importExport catalog. */
export const RESTORE_WAIT_LINE: Record<Exclude<RestoreGate, 'open'>, string> = {
  wait: 'importExport:restoreGate.wait',
  paused: 'importExport:restoreGate.paused',
  belowFloor: 'importExport:restoreGate.belowFloor',
};
