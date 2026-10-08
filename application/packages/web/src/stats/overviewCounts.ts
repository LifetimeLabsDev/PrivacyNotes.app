import type { LocalNote } from '../db';
import { countTasks } from '../tasks';
import { countWords } from '../wordCountUtils';

// The two readers of note bodies on the Statistics Overview. A note the PIN
// guards right now is left out of both, as every reader past the gate does.

/** Checked items across the open task notes. */
export function checkedTaskCount(tasks: LocalNote[], isNoteLocked: (n: LocalNote) => boolean): number {
  return tasks.filter((n) => !isNoteLocked(n)).reduce((s, n) => s + countTasks(n.body).done, 0);
}

/** The longest live notes that are not journals, by words. */
export function longestNotes(notes: LocalNote[], isNoteLocked: (n: LocalNote) => boolean, limit = 5): { n: LocalNote; w: number }[] {
  return notes
    .filter((n) => n.deleted === 0 && n.trashed === 0 && n.type !== 'journal' && !isNoteLocked(n))
    .map((n) => ({ n, w: countWords(n.body) }))
    .sort((a, b) => b.w - a.w)
    .slice(0, limit);
}
