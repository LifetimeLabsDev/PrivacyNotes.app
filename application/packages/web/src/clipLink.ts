/**
 * The link between a bookmark and the note its page was clipped into.
 *
 * The clipped note carries the bookmark's address in `trackers.clipSource`;
 * the bookmark body stays as it is, because `parseLinkBody` drops a field it
 * does not know and an older client editing the bookmark would erase it.
 * Spec: ops/docs/archive/web-clipper-stage1.md (section 3.4)
 */
import { linkDedupeKey } from './linkBody';
import { CLIP_SOURCE_KEY } from './schedule';

type NoteLike = { id: string; type?: string; trashed?: number; trackers?: Record<string, unknown>; createdAt: string };

/** The bookmark address a clipped note names, or null for any other note. */
function clipSourceOf(note: NoteLike): string | null {
  const v = note.trackers?.[CLIP_SOURCE_KEY];
  return typeof v === 'string' && v ? v : null;
}

/**
 * Every clipped note the account holds, as `linkDedupeKey` of its source ->
 * the note. Trashed notes do not count. When one address was clipped more
 * than once, the newest note is the one a bookmark opens; the others stay
 * ordinary notes.
 */
export function buildClipNoteMap<N extends NoteLike>(notes: readonly N[]): Map<string, N> {
  const map = new Map<string, N>();
  for (const n of notes) {
    if (n.trashed === 1 || n.type === 'link') continue;
    const source = clipSourceOf(n);
    if (!source) continue;
    const key = linkDedupeKey(source);
    const held = map.get(key);
    if (!held || n.createdAt > held.createdAt) map.set(key, n);
  }
  return map;
}

/** The tracker values of a new clipped note for the bookmark at `url`. */
export function clipTrackers(url: string): Record<string, unknown> {
  return { [CLIP_SOURCE_KEY]: url };
}
