import type { LocalNote } from './db';
import { countWords } from './wordCountUtils';
import { toLocalIso } from './notesViewUtils';

/**
 * Writing statistics - all computed client-side from the local Dexie DB.
 * Nothing leaks to the server.
 */

export type Stats = {
  totalNotes: number;
  totalWords: number;
  totalChars: number;
  /** Unique tag count across all non-trashed notes. */
  uniqueTags: number;
  currentStreak: number;
  longestStreak: number;
  firstNoteDate: string | null;
  heatmap: Record<string, number>; // YYYY-MM-DD -> edit count
  longestNote: LocalNote | null;
  ageDays: number;
};

/**
 * The LOCAL calendar day a stamp falls on.
 *
 * `iso.slice(0, 10)` is the UTC day, and the grids that render this
 * heatmap walk local days - so east of Greenwich a note written after
 * local midnight-minus-the-offset landed in tomorrow's cell, and the mood
 * overlay (keyed by `trackers.journalDate`, a local date) sat one column
 * away from the writing squares it is drawn on top of.
 */
function dayKey(iso: string): string {
  return toLocalIso(new Date(iso));
}

const DAY_MS = 86_400_000;

export function computeStats(notes: LocalNote[]): Stats {
  // Exclude both hard-deleted tombstones and trashed notes from writing stats.
  const alive = notes.filter((n) => n.deleted === 0 && n.trashed === 0);

  let totalWords = 0;
  let totalChars = 0;
  let longestNote: LocalNote | null = null;
  // Track the longest note's word count instead of re-deriving it with a second
  // countWords(longestNote.body) every iteration. That redundant call doubled the
  // per-note work, and countWords runs the full stripMarkdown regex pass over the
  // raw body - costly when a note holds a big HTML table. This runs on every list
  // change (footer stats chip), so halving it keeps editing snappy. Perf fix #150.
  let longestWords = -1;
  const heatmap: Record<string, number> = {};
  const tagSet = new Set<string>();

  for (const n of alive) {
    const w = countWords(n.body);
    totalWords += w;
    totalChars += n.body.length;
    if (w > longestWords) { longestWords = w; longestNote = n; }

    for (const t of n.tags) tagSet.add(t);

    const c = dayKey(n.createdAt);
    const u = dayKey(n.updatedAt);
    heatmap[c] = (heatmap[c] ?? 0) + 1;
    if (u !== c) heatmap[u] = (heatmap[u] ?? 0) + 1;
  }

  const daySet = new Set(Object.keys(heatmap));

  // Current streak: consecutive days ending today (or yesterday).
  let currentStreak = 0;
  {
    const cursor = new Date();
    // Allow today to be missing without breaking the streak.
    if (!daySet.has(toLocalIso(cursor))) {
      cursor.setDate(cursor.getDate() - 1);
    }
    while (daySet.has(toLocalIso(cursor))) {
      currentStreak++;
      cursor.setDate(cursor.getDate() - 1);
    }
  }

  // Longest streak: scan sorted days.
  let longestStreak = 0;
  {
    const sorted = Array.from(daySet).sort();
    let run = 0;
    let prevMs: number | null = null;
    for (const d of sorted) {
      const ms = new Date(d).getTime();
      if (prevMs !== null && ms - prevMs === DAY_MS) {
        run++;
      } else {
        run = 1;
      }
      if (run > longestStreak) longestStreak = run;
      prevMs = ms;
    }
  }

  const firstNoteDate =
    alive.length > 0
      ? alive.reduce(
          (min, n) => (n.createdAt < min ? n.createdAt : min),
          alive[0]!.createdAt
        )
      : null;

  const ageDays = firstNoteDate
    ? Math.floor((Date.now() - new Date(firstNoteDate).getTime()) / DAY_MS)
    : 0;

  return {
    totalNotes: alive.length,
    totalWords,
    totalChars,
    uniqueTags: tagSet.size,
    currentStreak,
    longestStreak,
    firstNoteDate,
    heatmap,
    longestNote,
    ageDays,
  };
}
