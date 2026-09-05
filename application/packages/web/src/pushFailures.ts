import { useSyncExternalStore } from 'react';
import { NOTE_TOO_LARGE_MSG } from './sync';

/**
 * The notes the last sync pass could not push, by id.
 *
 * A push failure used to be one dismissable banner counter while the pill
 * kept its green check, so a note the server refuses for size could sit
 * on one device for a day with every surface reading "Synced". This store
 * is the per-note truth behind the pill's "Not backed up" state, the list
 * of affected notes in ID & Sync, the bar inside the note and the badge
 * on its list row.
 *
 * Written once per pass by the orchestrator with that pass's complete
 * failure list, so a pass that pushed clean clears it. A skipped pass
 * never writes: it attempted nothing, so its empty list says nothing
 * about the notes that failed last time. Runtime only - the next pass
 * rebuilds it from scratch.
 */

export type PushFailureReason = 'too_large' | 'other';

export interface PushFailure {
  id: string;
  reason: PushFailureReason;
  /** The message sync.ts handed to onPushError, verbatim. */
  message: string;
  /** When the pass that reported it ended (epoch ms). */
  at: number;
}

const EMPTY: ReadonlyMap<string, PushFailure> = new Map();
let failures: ReadonlyMap<string, PushFailure> = EMPTY;
const listeners = new Set<() => void>();

/** The size rejection is the one failure a retry can never turn into a success. */
export function classifyPushFailure(message: string): PushFailureReason {
  return message === NOTE_TOO_LARGE_MSG ? 'too_large' : 'other';
}

function sameFailures(
  a: ReadonlyMap<string, PushFailure>,
  b: ReadonlyMap<string, PushFailure>,
): boolean {
  if (a.size !== b.size) return false;
  for (const [id, f] of a) {
    const g = b.get(id);
    if (!g || g.reason !== f.reason || g.message !== f.message) return false;
  }
  return true;
}

/**
 * Replace the set with one pass's failures. Only the orchestrator calls
 * this, and only after a pass that ran its push phase.
 */
export function recordPassPushFailures(
  list: ReadonlyArray<{ id: string; message: string }>,
  at: number = Date.now(),
): void {
  const next = new Map<string, PushFailure>();
  for (const { id, message } of list) {
    next.set(id, { id, reason: classifyPushFailure(message), message, at });
  }
  // The same ids with the same reasons keep the old snapshot, so the row
  // subscribers (one per visible note) do not re-render every 30 seconds
  // while a stuck note stays stuck.
  if (sameFailures(failures, next)) return;
  failures = next;
  for (const cb of listeners) cb();
}

/** The current set, outside React. */
export function getPushFailures(): ReadonlyMap<string, PushFailure> {
  return failures;
}

function subscribe(cb: () => void) {
  listeners.add(cb);
  return () => {
    listeners.delete(cb);
  };
}

/** Every note the last pass could not push. */
export function usePushFailures(): ReadonlyMap<string, PushFailure> {
  return useSyncExternalStore(subscribe, getPushFailures);
}

/** The failure for one note, or undefined when the server has it. */
export function usePushFailure(id: string | null | undefined): PushFailure | undefined {
  const all = usePushFailures();
  return id ? all.get(id) : undefined;
}
