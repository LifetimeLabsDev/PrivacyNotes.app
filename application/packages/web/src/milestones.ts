import type { Stats } from './stats';
import i18n from './i18n';
import { intlLocale } from './languages';

/**
 * Milestones: the thresholds the app shows progress toward and celebrates.
 *
 * Four families. Two of them have an honest source, a number an import
 * cannot move: `notes` reads the synced count of items created IN the app
 * (`UserSettings.notesCreated`), and `age` reads the account's first
 * sighting (`UserSettings.firstSeenAt`). The other two, `streak` and
 * `words`, read the writing statistics, which an import of dated notes
 * inflates on day one. So every family shows PROGRESS, the meters in the
 * Statistics pane, which carry the same numbers the pane shows anyway,
 * and only the honest families CELEBRATE with the toast, until the streak
 * and the words have a source of their own.
 * Spec: ops/docs/archive/wellness-statistics.md (section 21)
 *
 * The module is pure: the caller passes the seen keys in and persists the
 * ones it spends. Seen state lives in `UserSettings.milestonesSeen` and
 * syncs, so a milestone fires once per ACCOUNT, never once per device.
 *
 * A small subset of the note family opens the rating modal instead of a
 * toast: `RATING_TRIGGERS`, consumed by `ratingPrompt.ts`, which also owns
 * the rules that decide whether the ask may happen. The celebration never
 * shows or spends those keys, so a toast can never cost the ask.
 */

type MilestoneFamily = 'notes' | 'streak' | 'words' | 'age';

const THRESHOLDS: Record<MilestoneFamily, readonly number[]> = {
  notes: [10, 25, 50, 100, 250, 500, 1000, 2500, 5000],
  streak: [3, 7, 14, 30, 100, 365],
  words: [1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000],
  age: [30, 365, 730, 1825],
};

/** The families whose number an import cannot move. Only these celebrate. */
const CELEBRATED_FAMILIES: readonly MilestoneFamily[] = ['notes', 'age'];

/**
 * The two milestones that may open the rating modal, and the only two
 * ever: 25 items written IN the app, then 50.
 *
 * Both read `notesCreated`, never `stats.totalNotes`: an import inflates
 * the latter on day one, and an ask earned by an importer is not earned.
 * Deliberately low: someone who has written 25 notes by hand has decided
 * they like the app, and asking a heavy user at 500 wastes the goodwill
 * of the 24 lighter users who would also have said something kind.
 * Spec: ops/docs/archive/rating-prompt-handoff.md (section 3)
 */
export const RATING_TRIGGERS = new Set<string>(['notes:25', 'notes:50']);

export type NewMilestone = { key: string; label: string };

type MilestoneProgress = {
  family: MilestoneFamily;
  /** The family's number today: notes created, streak days, words, days with the app. */
  current: number;
  /** The thresholds at or below the number, ascending. */
  reached: number[];
  /** The next threshold, or null past the last one. */
  next: number | null;
  /** 0 to 1 of the way to `next`; 1 past the last threshold. */
  progress: number;
};

const DAY_MS = 86_400_000;

/** Whole days since the account was first seen; null without a stamp. */
export function accountAgeDays(firstSeenAt: string | null | undefined, now = Date.now()): number | null {
  if (!firstSeenAt) return null;
  const start = Date.parse(firstSeenAt);
  if (!Number.isFinite(start)) return null;
  return Math.max(0, Math.floor((now - start) / DAY_MS));
}

function ageLabel(days: number): string {
  if (days === 30) return i18n.t('stats:milestone.age30');
  if (days === 365) return i18n.t('stats:milestone.age365');
  if (days === 730) return i18n.t('stats:milestone.age730');
  if (days === 1825) return i18n.t('stats:milestone.age1825');
  return i18n.t('stats:milestone.ageDefault', { count: days });
}

/** The sentence for one threshold, in the language on screen. */
export function milestoneLabel(family: MilestoneFamily, threshold: number): string {
  switch (family) {
    case 'notes':
      return i18n.t('stats:milestone.notes', { count: threshold });
    case 'streak':
      return i18n.t('stats:milestone.streak', { count: threshold });
    case 'words':
      return i18n.t('stats:milestone.words', {
        count: threshold,
        formatted: threshold.toLocaleString(intlLocale()),
      });
    case 'age':
      return ageLabel(threshold);
  }
}

function progressOf(family: MilestoneFamily, current: number): MilestoneProgress {
  const all = THRESHOLDS[family];
  const reached = all.filter((t) => current >= t);
  const next = all.find((t) => current < t) ?? null;
  const progress = next === null ? 1 : Math.min(1, Math.max(0, current / next));
  return { family, current, reached, next, progress };
}

/**
 * Progress toward the next milestone of every family, in display order.
 * The age family is left out while the account carries no first-seen stamp.
 */
export function milestoneProgress(
  stats: Pick<Stats, 'currentStreak' | 'totalWords'>,
  notesCreated: number,
  firstSeenAt: string | null | undefined,
  now = Date.now(),
): MilestoneProgress[] {
  const rows = [
    progressOf('notes', notesCreated),
    progressOf('streak', stats.currentStreak),
    progressOf('words', stats.totalWords),
  ];
  const age = accountAgeDays(firstSeenAt, now);
  if (age !== null) rows.push(progressOf('age', age));
  return rows;
}

/**
 * What the honest families have newly reached, and what to do with it.
 *
 * `spend` is every new key, the rating keys excepted, for the caller to
 * record on the account. `milestone` is the one toast to show, or null: a
 * key is shown only when it is the highest threshold its family has
 * reached, so an account that meets this code with 73 notes spends the
 * key for 10 quietly instead of announcing "10 notes written" on a number
 * that was passed long ago. A rating key is never shown either; when it is
 * the highest, nothing is shown and `ratingPrompt.ts` has its turn.
 */
export function nextCelebration(
  notesCreated: number,
  firstSeenAt: string | null | undefined,
  seen: readonly string[],
  now = Date.now(),
): { milestone: NewMilestone | null; spend: string[] } {
  const already = new Set(seen);
  const spend: string[] = [];
  let milestone: NewMilestone | null = null;
  const values: Partial<Record<MilestoneFamily, number>> = { notes: notesCreated };
  const age = accountAgeDays(firstSeenAt, now);
  if (age !== null) values.age = age;
  for (const family of CELEBRATED_FAMILIES) {
    const current = values[family];
    if (current === undefined) continue;
    const reached = THRESHOLDS[family].filter((t) => current >= t);
    const highest = reached[reached.length - 1];
    for (const threshold of reached) {
      const key = `${family}:${threshold}`;
      if (already.has(key) || RATING_TRIGGERS.has(key)) continue;
      spend.push(key);
      if (threshold === highest && milestone === null) {
        milestone = { key, label: milestoneLabel(family, threshold) };
      }
    }
  }
  return { milestone, spend };
}
