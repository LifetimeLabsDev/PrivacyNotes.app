import type { Stats } from './stats';
import i18n from './i18n';
import { intlLocale } from './languages';

/**
 * Milestone tracking. Celebrates thresholds as the user writes more.
 * Each milestone fires once per ACCOUNT, ever.
 *
 * This module is pure: the caller passes the seen keys in and persists
 * the ones it consumes. Seen state used to be a localStorage set written
 * from here, which made every milestone re-fire the first time someone
 * opened the app on their second device. It now lives on
 * `UserSettings.milestonesSeen` and syncs like every other preference.
 *
 * A small curated subset also opens the rating modal - see
 * `RATING_TRIGGERS` and `ratingPrompt.ts` for the suppression rules that
 * decide whether the ask is allowed to happen at all.
 */

const NOTE_MILESTONES = [10, 25, 50, 100, 250, 500, 1000, 2500, 5000];
const STREAK_MILESTONES = [3, 7, 14, 30, 100, 365];
const WORD_MILESTONES = [
  1_000, 5_000, 10_000, 50_000, 100_000, 500_000, 1_000_000,
];
const AGE_MILESTONES = [30, 365, 730, 1825];

/**
 * The two milestones that may open the rating modal, and the only two
 * ever: 25 items written IN the app, then 50.
 *
 * Both read `notesCreated`, never `stats.totalNotes` - an import inflates
 * the latter on day one, and an ask earned by an importer is not earned.
 * Deliberately low: someone who has written 25 notes by hand has decided
 * they like the app, and asking a heavy user at 500 wastes the goodwill
 * of the 24 lighter users who would also have said something kind.
 * Spec: ops/docs/plans/rating-prompt-handoff.md (section 3)
 */
export const RATING_TRIGGERS = new Set<string>(['notes:25', 'notes:50']);

export type NewMilestone = {
  key: string;
  label: string;
  /** True when this key may open the rating modal - subject to ratingPrompt.ts. */
  triggerRating: boolean;
};

function ageLabel(days: number): string {
  if (days === 30) return i18n.t('stats:milestone.age30');
  if (days === 365) return i18n.t('stats:milestone.age365');
  if (days === 730) return i18n.t('stats:milestone.age730');
  if (days === 1825) return i18n.t('stats:milestone.age1825');
  return i18n.t('stats:milestone.ageDefault', { count: days });
}

/**
 * Every milestone newly reached, in threshold order.
 *
 * @knipignore Dormant by design, and deliberately so as of v1 of the rating
 * ask: only `ratingPrompt.ts` consumes milestones today, and it reads
 * RATING_TRIGGERS directly. The celebration toast stays unwired until the
 * word, streak and age families have an honest source - all three still
 * read numbers a single import inflates, and a false "365 days!" on day two
 * costs more trust than silence buys.
 * See ops/docs/plans/streaks-and-milestones.md.
 *
 * `notesCreated` is the synced counter of items created IN the app. The
 * note family reads it, never `stats.totalNotes`: an import inflates
 * totalNotes on day one, and a milestone earned by an importer is not
 * earned at all. Spec: ops/docs/plans/rating-prompt-handoff.md (step 2)
 *
 * `seen` is `UserSettings.milestonesSeen`. Nothing is persisted here -
 * the caller records the keys it acts on, so a milestone the app decided
 * not to show is not silently spent.
 */
export function checkNewMilestones(
  stats: Stats,
  notesCreated: number,
  seen: readonly string[]
): NewMilestone[] {
  const already = new Set(seen);
  const hits: NewMilestone[] = [];

  const add = (key: string, label: string) => {
    if (already.has(key)) return;
    already.add(key);
    hits.push({ key, label, triggerRating: RATING_TRIGGERS.has(key) });
  };

  for (const m of NOTE_MILESTONES) {
    if (notesCreated >= m) add(`notes:${m}`, i18n.t('stats:milestone.notes', { count: m }));
  }
  for (const m of STREAK_MILESTONES) {
    if (stats.currentStreak >= m) add(`streak:${m}`, i18n.t('stats:milestone.streak', { count: m }));
  }
  for (const m of WORD_MILESTONES) {
    if (stats.totalWords >= m)
      add(`words:${m}`, i18n.t('stats:milestone.words', { count: m, formatted: m.toLocaleString(intlLocale()) }));
  }
  for (const m of AGE_MILESTONES) {
    if (stats.ageDays >= m) add(`age:${m}`, ageLabel(m));
  }

  return hits;
}
