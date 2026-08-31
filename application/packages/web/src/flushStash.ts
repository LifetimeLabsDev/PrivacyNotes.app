import { getNote, updateNote } from './notesRepo';
import { sealedWritesOn } from './localSeal';
import { localDataKeyCopy } from './localKey';
import {
  encryptJsonAad,
  decryptJsonAad,
  bytesToBase64,
  base64ToBytes,
} from '@notes/shared';
import { logAuthEvent } from './authDiag';

/**
 * Last-chance durable copy of an in-flight body edit.
 *
 * The editor's beforeunload/pagehide flush hands the serialized markdown
 * to the async save pipeline, but a tab closed within the debounce
 * window (~300 ms after the last keystroke) dies before the IndexedDB
 * write commits and the edit is lost. localStorage writes are
 * synchronous and survive page death, so the flush stashes the body
 * here and the next boot folds it back in if it is newer than the
 * stored note.
 *
 * Two shapes coexist during the at-rest rollout, and the versioning is
 * load-bearing for rollback safety:
 *  - legacy: { noteId, body, at } - plaintext, what reader-mode builds
 *    write and every already-shipped reader validates via
 *    `typeof body === 'string'`.
 *  - v2:     { v: 2, noteId, sealed: "<b64 nonce>:<b64 ct>", at } - what
 *    sealed-writer builds write. It deliberately has NO `body` field,
 *    so every older reader discards it instead of folding base64 in as
 *    note content. This reader accepts both: the legacy shape is
 *    honored once (the last pre-writer session's in-flight edit must
 *    not be dropped on upgrade day).
 * The seal runs synchronously (noble), which is what makes sealing
 * possible inside pagehide at all.
 *
 * Spec: ops/docs/plans/local-at-rest.md (section 3.4, flushStash)
 */

const KEY = 'privacynotes.flushStash';
const STASH_AAD_PREFIX = 'pn-local-v1:stash:';

/** Refuse to stash absurdly large bodies rather than risk a quota throw
 *  during page teardown. Matches the adaptive-debounce ceiling. */
const MAX_STASH_BYTES = 2_000_000;

export function stashPendingEdit(noteId: string, body: string): void {
  if (body.length > MAX_STASH_BYTES) return;
  try {
    if (sealedWritesOn()) {
      const key = localDataKeyCopy();
      if (!key) {
        // Teardown after sign-out zeroed the key: skip rather than
        // write plaintext. Losing one in-flight edit on that edge is
        // the pre-stash world; writing plaintext would defeat the seal.
        logAuthEvent('seal:stash-skipped-no-key');
        return;
      }
      const { ciphertext, nonce } = encryptJsonAad(body, key, `${STASH_AAD_PREFIX}${noteId}`);
      key.fill(0);
      localStorage.setItem(
        KEY,
        JSON.stringify({
          v: 2,
          noteId,
          sealed: `${bytesToBase64(nonce)}:${bytesToBase64(ciphertext)}`,
          at: new Date().toISOString(),
        }),
      );
      return;
    }
    localStorage.setItem(
      KEY,
      JSON.stringify({ noteId, body, at: new Date().toISOString() })
    );
  } catch {
    /* quota or private-mode failure - the async save path may still win */
  }
}

/**
 * Fold a stashed edit back into the note it belongs to. Called once at
 * boot, before or alongside the first refresh. Returns true when a note
 * was updated so the caller can refresh the list.
 */
export async function reconcileFlushStash(): Promise<boolean> {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(KEY);
  } catch {
    return false;
  }
  if (!raw) return false;
  try {
    localStorage.removeItem(KEY);
  } catch {
    /* ignore */
  }
  try {
    const stash = JSON.parse(raw) as {
      v?: number;
      noteId?: string;
      body?: string;
      sealed?: string;
      at?: string;
    };
    if (!stash.noteId || !stash.at) return false;
    let body: string;
    if (typeof stash.body === 'string') {
      // Legacy plaintext shape - written by reader-mode builds, and
      // honored exactly once so the last pre-writer session's in-flight
      // edit survives the upgrade boot.
      body = stash.body;
    } else if (stash.v === 2 && typeof stash.sealed === 'string') {
      const key = localDataKeyCopy();
      if (!key) return false;
      try {
        const [n, ct] = stash.sealed.split(':');
        if (!n || !ct) return false;
        body = decryptJsonAad<string>(
          base64ToBytes(ct),
          base64ToBytes(n),
          key,
          `${STASH_AAD_PREFIX}${stash.noteId}`,
        );
      } catch {
        // Wrong account's key, or corruption: the stash is already
        // removed above, so skip-and-clear with a breadcrumb.
        logAuthEvent('seal:stash-open-failed');
        return false;
      } finally {
        key.fill(0);
      }
    } else {
      return false;
    }
    const note = await getNote(stash.noteId);
    // Only apply when the stash is strictly newer than the stored note
    // and the note still exists un-deleted. The normal case is that the
    // async save DID land (same content, later updatedAt) and this is a
    // no-op.
    if (!note || note.deleted === 1 || note.updatedAt >= stash.at) return false;
    if (note.body === body) return false;
    await updateNote(stash.noteId, { body });
    return true;
  } catch {
    return false;
  }
}
