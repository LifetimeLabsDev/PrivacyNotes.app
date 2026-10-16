/**
 * What an edit is, for the "last edited" date (`LocalNote.editedAt`): a
 * change to the title, the body, or a tracker value. The day a journal entry
 * is for and the backfill mark are the app's bookkeeping, and a flag, a tag,
 * a folder or the type is metadata, so none of them moves the date. The one
 * comparison behind it, for the writers (notesRepo.ts, useNoteEditing.ts),
 * the pull (sync.ts) and the merge (noteMerge.ts mergedEditedAt) alike.
 * Tested in tests/editStamp.test.ts.
 */
import { BOOKKEEPING_KEYS, trackersEqual } from './trackerTypes';
import { SCHEDULE_KEYS } from './schedule';

/** What a person wrote into a note. */
interface Content {
  title: string;
  body: string;
  trackers?: Record<string, unknown>;
}

/** A journal entry's tracker values, without the bookkeeping keys. */
export function trackerContent(trackers: Record<string, unknown> | undefined): Record<string, unknown> {
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(trackers ?? {})) {
    if (!BOOKKEEPING_KEYS.has(key)) out[key] = value;
  }
  return out;
}

/** `trackers` with its tracker values replaced by `values`: the entry's
 *  date, the backfill mark and its schedule (time, alerts) stay, as a
 *  restore from history needs. A restore brings back what was written, and
 *  the reminder the entry rings now is not part of that. */
export function withTrackerContent(
  trackers: Record<string, unknown> | undefined,
  values: Record<string, unknown>,
): Record<string, unknown> {
  const kept = (key: string) => BOOKKEEPING_KEYS.has(key) || SCHEDULE_KEY_SET.has(key);
  const out: Record<string, unknown> = {};
  for (const [key, value] of Object.entries(values)) {
    if (!kept(key)) out[key] = value;
  }
  for (const [key, value] of Object.entries(trackers ?? {})) {
    if (kept(key)) out[key] = value;
  }
  return out;
}

const SCHEDULE_KEY_SET: ReadonlySet<string> = new Set(SCHEDULE_KEYS);

/** Whether two versions hold the same content. */
export function sameContent(a: Content, b: Content): boolean {
  return (
    a.title === b.title &&
    a.body === b.body &&
    trackersEqual(trackerContent(a.trackers), trackerContent(b.trackers))
  );
}

/** Whether a patch changes the content of a note. */
export function changesContent(current: Content, patch: Partial<Content>): boolean {
  return (
    (patch.title !== undefined && patch.title !== current.title) ||
    (patch.body !== undefined && patch.body !== current.body) ||
    (patch.trackers !== undefined &&
      !trackersEqual(trackerContent(patch.trackers), trackerContent(current.trackers)))
  );
}
