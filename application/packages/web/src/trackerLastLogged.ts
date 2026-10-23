import { useSyncExternalStore } from 'react';
import type { LocalNote } from './db';
import { journalDateOf } from './notesViewUtils';
import type { JournalTrackerData } from './trackerTypes';

/**
 * The last value a person logged for a number, so an empty panel starts from
 * it: the stepper shows it as its starting number, and minus or plus move
 * from there. Nothing is written until the person taps or types. One store
 * for every number panel, in the check-in card and in the journal entry
 * alike; the notes view writes the history, newest day first.
 * Spec: ops/docs/archive/ui-patterns.md section 141
 */

let history: readonly JournalTrackerData[] = [];
const listeners = new Set<() => void>();

/** The tracker values of the journal entries in `notes`, newest day first.
 *  An entry behind its PIN gives nothing, or an open entry would show its
 *  value. */
export function trackerHistoryOf(notes: readonly LocalNote[], isGated: (n: LocalNote) => boolean): JournalTrackerData[] {
  return notes
    .filter((n) => n.type === 'journal' && n.trackers && !isGated(n))
    .map((n) => ({ day: journalDateOf(n) ?? '', data: n.trackers as JournalTrackerData }))
    .sort((a, b) => (a.day < b.day ? 1 : a.day > b.day ? -1 : 0))
    .map((d) => d.data);
}

/** The tracker values of the live journal entries, newest day first. */
export function setTrackerHistory(next: readonly JournalTrackerData[]): void {
  history = next;
  listeners.forEach((l) => l());
}

function subscribe(l: () => void): () => void {
  listeners.add(l);
  return () => { listeners.delete(l); };
}

/** The newest value `read` finds in `days`, in the unit `read` returns. */
export function lastLogged(
  days: readonly JournalTrackerData[],
  read: (d: JournalTrackerData) => number | undefined,
): number | undefined {
  for (const d of days) {
    const v = read(d);
    if (v !== undefined && Number.isFinite(v)) return v;
  }
  return undefined;
}

/** `lastLogged` over the current history, kept current. */
export function useLastLogged(read: (d: JournalTrackerData) => number | undefined): number | undefined {
  const days = useSyncExternalStore(subscribe, () => history);
  return lastLogged(days, read);
}

/** The whole history, kept current: the Meds pill counts the supply from it. */
export function useTrackerHistory(): readonly JournalTrackerData[] {
  return useSyncExternalStore(subscribe, () => history);
}
