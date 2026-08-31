import { isDemoMode } from './demo';
import { RATING_TRIGGERS } from './milestones';
import type { UserSettings } from './userSettings';

/**
 * Whether the app may ask this user for a public rating right now.
 *
 * The ask is the one piece of UI that spends goodwill instead of
 * creating it, so every rule here is a reason NOT to ask. Kept in its
 * own module, free of React and i18n, so the rules are readable in one
 * screen and testable without a DOM.
 *
 * Spec: ops/docs/plans/rating-prompt-handoff.md (section 6)
 */

/**
 * No ask in the first two weeks, whatever the counter says. Someone who
 * wrote 25 notes on day one is still deciding whether they trust the
 * app; asking then reads as a sales pitch rather than a thank-you.
 * Spec: ops/docs/plans/rating-prompt-handoff.md (section 6, rule 3)
 */
const RATING_MIN_ACCOUNT_DAYS = 14;

const DAY_MS = 86_400_000;

/**
 * The rating milestones this user has earned and not yet been asked
 * about. Empty means do not ask - which is the answer in every
 * suppressed case, so callers need no other check.
 *
 * Returns every met key rather than one, so a user who crosses both
 * thresholds between two checks spends both on a single ask instead of
 * being asked twice in a row.
 */
export function pendingRatingMilestones(
  settings: UserSettings,
  isPro: boolean | null | undefined,
  now: number = Date.now()
): string[] {
  // Pro buyers already paid. Asking them as well reads as double-dipping.
  if (isPro) return [];
  // Demo has no account to rate from, and every session is a stranger's
  // first thirty seconds.
  if (isDemoMode()) return [];
  // They already went and did it. Never ask a second time.
  if (settings.ratingDone) return [];
  // No stamp yet means this run is the first: the 14-day clock starts now.
  if (!settings.firstSeenAt) return [];
  const age = now - new Date(settings.firstSeenAt).getTime();
  if (!Number.isFinite(age) || age < RATING_MIN_ACCOUNT_DAYS * DAY_MS) return [];

  const seen = new Set(settings.milestonesSeen);
  return [...RATING_TRIGGERS]
    .filter((key) => !seen.has(key))
    .filter((key) => settings.notesCreated >= thresholdOf(key));
}

/** The count a `notes:<n>` key stands for. Non-note keys never match. */
function thresholdOf(key: string): number {
  const n = Number(key.slice(key.indexOf(':') + 1));
  return Number.isFinite(n) ? n : Infinity;
}
