import type { Editor as TipTapEditor, JSONContent } from '@tiptap/react';
import { db } from './db';

/**
 * Parsed-doc cache for big notes (#150).
 *
 * `useEditor` parses its `content` markdown synchronously in the first
 * render, and at huge sizes that IS the open freeze: measured 1,415 ms for
 * a 665 KB / 4,201-block note, linear in size. Rebuilding the identical
 * doc from its JSON takes ~3 ms. So the parse result is cached per note in
 * Dexie and reused on the next open.
 *
 * Correctness rests on EXACT body-string equality, not a hash: a row whose
 * stored body differs from the note's current body in any byte is a miss
 * and the normal parse runs. A stale or orphaned row can therefore never
 * surface wrong content - the worst it can do is waste its disk footprint
 * until pruned. The cache is local-only derived data, never synced, and
 * lives in the same demo-bucketed Dexie database as everything else.
 */

/** Only notes at least this big are cached - below it the parse is well
 *  under the #150 freeze bar and the cache would just burn disk. */
export const DOC_CACHE_MIN_BYTES = 100_000;

/** Rows are ~3x the note body (body copy + JSON); keep only the most
 *  recently cached handful. */
const DOC_CACHE_MAX_ROWS = 12;

/** The cached doc for this note, or undefined when the body has changed
 *  since it was cached (or was never cached). */
export async function readDocCache(noteId: string, body: string): Promise<JSONContent | undefined> {
  if (body.length < DOC_CACHE_MIN_BYTES) return undefined;
  try {
    const row = await db.editorDocCache.get(noteId);
    return row && row.body === body ? (row.json as JSONContent) : undefined;
  } catch {
    return undefined;
  }
}

export async function writeDocCache(noteId: string, body: string, json: JSONContent): Promise<void> {
  if (body.length < DOC_CACHE_MIN_BYTES) return;
  try {
    await db.editorDocCache.put({ noteId, body, json, cachedAt: Date.now() });
    if ((await db.editorDocCache.count()) > DOC_CACHE_MAX_ROWS) {
      const oldest = await db.editorDocCache.orderBy('cachedAt').first();
      if (oldest && oldest.noteId !== noteId) await db.editorDocCache.delete(oldest.noteId);
    }
  } catch {
    /* best-effort cache */
  }
}

/** Save-path variant: refresh the cache from a live (possibly just-
 *  destroyed) editor, so reopening a big note right after editing it
 *  still hits. Never throws - the save it rides on must not care. */
export function writeDocCacheFromEditor(noteId: string | undefined, body: string, editor: TipTapEditor): void {
  if (!noteId || body.length < DOC_CACHE_MIN_BYTES) return;
  try {
    void writeDocCache(noteId, body, editor.getJSON());
  } catch {
    /* editor may be destroyed mid-flush */
  }
}
