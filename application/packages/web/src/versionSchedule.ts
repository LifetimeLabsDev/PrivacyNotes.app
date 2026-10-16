/**
 * When an edit makes a note history version. A version is always the note
 * as it stood BEFORE the edit, so it holds a finished state, never a word
 * typed halfway, and the text an edit removes is what the history keeps.
 *
 * Three moments take one:
 * - the first edit of a session, a session being edits less than
 *   SESSION_IDLE_MS apart;
 * - an edit CHECKPOINT_MS after the session's last version, so a long
 *   writing session keeps points along the way;
 * - an edit that removes most of the text, at most once per LOSS_GAP_MS,
 *   because "I deleted it by mistake" is what history is for.
 *
 * The end of a session needs no version: it is the note itself, and the
 * next session's first edit records it.
 * Spec: ops/docs/supabase.md (Note history: when a version is made)
 */

export const SESSION_IDLE_MS = 5 * 60_000;
export const CHECKPOINT_MS = 10 * 60_000;
export const LOSS_GAP_MS = 30_000;

export type VersionSession = { lastEditAt: number; lastVersionAt: number };

export function planVersion(
  session: VersionSession | undefined,
  now: number,
  bigLoss: boolean,
): { take: boolean; session: VersionSession } {
  const since = session ? now - session.lastVersionAt : Infinity;
  const take =
    !session ||
    now - session.lastEditAt >= SESSION_IDLE_MS ||
    since >= CHECKPOINT_MS ||
    (bigLoss && since >= LOSS_GAP_MS);
  return { take, session: { lastEditAt: now, lastVersionAt: take ? now : (session as VersionSession).lastVersionAt } };
}

/** An edit that leaves less than half of a text of some length. */
export function isBigLoss(before: string, after: string): boolean {
  return before.length >= 200 && after.length < before.length / 2;
}
