import { getNote, updateNote } from './notesRepo';
import { sealedWritesOn } from './localSeal';
import { localDataKeyCopy } from './localKey';
import {
  encryptJsonAad,
  decryptJsonAad,
  bytesToBase64,
  bytesToHex,
  base64ToBytes,
} from '@notes/shared';
import { logAuthEvent } from './authDiag';
import { credentialKey, isDemoMode } from './demo';

/**
 * Last-chance durable copy of an in-flight body edit.
 *
 * The editor's beforeunload/pagehide flush hands the serialized markdown
 * to the async save pipeline, but a tab closed within the debounce
 * window (~300 ms after the last keystroke) dies before the IndexedDB
 * write commits and the edit is lost. localStorage writes are
 * synchronous and survive page death, so the flush stashes the body
 * here and the next boot folds it back in.
 *
 * Two slots, so a fresh stash and a kept text never compete. Only the
 * flush writes the fresh slot. A stash its note refuses at boot (the note
 * is read-only) moves to the kept slot, and the fresh slot is free again
 * for the next close. A refused text left in the fresh slot, protected
 * from being overwritten, would instead let one note that stays read-only
 * switch the last-chance copy off for every other note on the device,
 * with nothing to show it. The kept slot holds ONE text: when a second
 * note refuses its stash, the newer refusal replaces the text kept before
 * it, and a breadcrumb says so. A kept text that cannot be saved (storage
 * is full) is dropped with a breadcrumb, never kept in a weaker form.
 *
 * Three shapes coexist, and the versioning is load-bearing for rollback
 * safety:
 *  - legacy: { noteId, body, at } - plaintext, what reader-mode builds
 *    write and every already-shipped reader validates via
 *    `typeof body === 'string'`.
 *  - v2:     { v: 2, noteId, sealed: "<b64 nonce>:<b64 ct>", at } - what
 *    sealed-writer builds write. It deliberately has NO `body` field,
 *    so every older reader discards it instead of folding base64 in as
 *    note content. This reader accepts both: the legacy shape is
 *    honored once (the last pre-writer session's in-flight edit must
 *    not be dropped on upgrade day).
 *  - v3:     the same envelope, written only to the kept slot by a boot
 *    whose note refused the text. Its sealed payload is [text,
 *    fingerprint of the body the refusal saw], under its own AAD, and it
 *    has no `body` field either, so every older reader discards it too.
 * The seal runs synchronously (noble), which is what makes sealing
 * possible inside pagehide at all.
 *
 * Which rule decides. A stash is written while the page is being torn
 * down, when the stored row cannot be read, so a fresh stash carries no
 * fingerprint and applies only when it is newer than the stored note. A
 * read-only note refuses the text, and turning read-only off moves the
 * note's stamp past the stash, so a refusal seals the fingerprint in and
 * the stamps stop deciding: the text applies while the note still holds
 * the body the refusal saw, and is dropped once anybody has changed it,
 * because applying it then would overwrite that change. Reader mode seals
 * nothing, so there a refused stash is kept as it was written, under the
 * stamp rule.
 *
 * Spec: ops/docs/plans/local-at-rest.md (section 3.4, flushStash)
 */

// Demo-bucketed like the credential keys: `?demo=1` runs on the same
// origin as a real install, and the demo must never fold in, overwrite
// or drop the real account's pending edit or kept text.
export const STASH_KEY = credentialKey('privacynotes.flushStash');
export const KEPT_STASH_KEY = credentialKey('privacynotes.flushStash.kept');
const STASH_AAD_PREFIX = 'pn-local-v1:stash:';
const KEPT_AAD_PREFIX = 'pn-local-v1:stash-kept:';

/** Refuse to stash absurdly large bodies rather than risk a quota throw
 *  during page teardown. Matches the adaptive-debounce ceiling. */
const MAX_STASH_BYTES = 2_000_000;

type Stash = { v?: number; noteId?: string; body?: string; sealed?: string; at?: string };

/** `"<b64 nonce>:<b64 ct>"` under the local key, or null when none is registered. */
function seal(value: unknown, aad: string): string | null {
  const key = localDataKeyCopy();
  if (!key) return null;
  try {
    const { ciphertext, nonce } = encryptJsonAad(value, key, aad);
    return `${bytesToBase64(nonce)}:${bytesToBase64(ciphertext)}`;
  } finally {
    key.fill(0);
  }
}

/** First 16 bytes of the body's SHA-256, as hex. It only ever travels inside
 *  a sealed stash, never beside one, so a reader of this device's storage
 *  learns nothing about the note from it. */
async function fingerprint(body: string): Promise<string> {
  const digest = await crypto.subtle.digest('SHA-256', new TextEncoder().encode(body));
  return bytesToHex(new Uint8Array(digest, 0, 16));
}

export function stashPendingEdit(noteId: string, body: string): void {
  // The demo keeps nothing once its tab closes, so it has nothing to stash.
  if (isDemoMode()) return;
  if (body.length > MAX_STASH_BYTES) return;
  try {
    if (sealedWritesOn()) {
      const sealed = seal(body, `${STASH_AAD_PREFIX}${noteId}`);
      if (!sealed) {
        // Teardown after sign-out zeroed the key: skip rather than
        // write plaintext. Losing one in-flight edit on that edge is
        // the pre-stash world; writing plaintext would defeat the seal.
        logAuthEvent('seal:stash-skipped-no-key');
        return;
      }
      localStorage.setItem(
        STASH_KEY,
        JSON.stringify({ v: 2, noteId, sealed, at: new Date().toISOString() }),
      );
      return;
    }
    localStorage.setItem(
      STASH_KEY,
      JSON.stringify({ noteId, body, at: new Date().toISOString() })
    );
  } catch {
    /* quota or private-mode failure - the async save path may still win */
  }
}

/** Read one slot, clearing it first when asked: the fresh slot is cleared
 *  before anything opens what it held, so a stash that fails on every boot
 *  cannot come back on every boot. */
function readSlot(slot: string, clear: boolean): string | null {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(slot);
  } catch {
    return null;
  }
  if (raw && clear) {
    try {
      localStorage.removeItem(slot);
    } catch {
      /* ignore */
    }
  }
  return raw;
}

/** One stash against its note: written in, dropped, or the form to keep. */
async function settle(raw: string): Promise<'applied' | 'dropped' | { keep: string }> {
  try {
    const stash = JSON.parse(raw) as Stash;
    if (!stash.noteId || !stash.at) return 'dropped';
    // The text, and the fingerprint a refusal sealed in (none before one).
    let opened: [string, string?];
    if (typeof stash.body === 'string') {
      // Legacy plaintext shape - written by reader-mode builds, and
      // honored exactly once so the last pre-writer session's in-flight
      // edit survives the upgrade boot.
      opened = [stash.body];
    } else if ((stash.v === 2 || stash.v === 3) && stash.sealed) {
      const key = localDataKeyCopy();
      if (!key) return 'dropped';
      try {
        const [n = '', ct = ''] = stash.sealed.split(':');
        const aad = `${stash.v === 3 ? KEPT_AAD_PREFIX : STASH_AAD_PREFIX}${stash.noteId}`;
        const payload = decryptJsonAad<string | [string, string]>(base64ToBytes(ct), base64ToBytes(n), key, aad);
        opened = stash.v === 3 ? (payload as [string, string]) : [payload as string];
      } catch {
        // Wrong account's key, or corruption: skip-and-clear, with a
        // breadcrumb.
        logAuthEvent('seal:stash-open-failed');
        return 'dropped';
      } finally {
        key.fill(0);
      }
    } else {
      return 'dropped';
    }
    const [body, base] = opened;
    const note = await getNote(stash.noteId);
    // The normal case is that the async save DID land (same content),
    // and this is a no-op. A deleted note takes nothing.
    if (!note || note.deleted === 1 || note.body === body) return 'dropped';
    if (base === undefined) {
      if (note.updatedAt >= stash.at) return 'dropped';
    } else if ((await fingerprint(note.body)) !== base) {
      logAuthEvent('seal:stash-superseded');
      return 'dropped';
    }
    if (await updateNote(stash.noteId, { body })) return 'applied';
    // Refused: the note is read-only, a flag that can arrive by sync
    // mid-edit. The typed text is kept, fingerprinted against the body
    // this refusal saw the first time and byte for byte after that.
    if (base === undefined && sealedWritesOn()) {
      const sealed = seal([body, await fingerprint(note.body)], `${KEPT_AAD_PREFIX}${stash.noteId}`);
      if (sealed) return { keep: JSON.stringify({ v: 3, noteId: stash.noteId, sealed, at: stash.at }) };
    }
    return { keep: raw };
  } catch {
    return 'dropped';
  }
}

/**
 * Fold stashed edits back into the notes they belong to: the fresh slot
 * first, then the kept one, each by its own rule. Called once at boot,
 * before or alongside the first refresh. Returns true when a note was
 * updated so the caller can refresh the list. Tested in
 * tests/flushStashRefused.test.ts and tests/lockGateWrites.test.ts.
 */
export async function reconcileFlushStash(): Promise<boolean> {
  // The demo's own buckets are always empty, and the real account's
  // stashes are not the demo's to read.
  if (isDemoMode()) return false;
  const fresh = readSlot(STASH_KEY, true);
  // The kept text stays on disk until this boot knows what becomes of it:
  // it waits across boots by design, and a tab closed mid-boot must not
  // lose it.
  const kept = readSlot(KEPT_STASH_KEY, false);
  let applied = false;
  let keep: string | null = null;
  let displaced = false;
  for (const raw of [fresh, kept]) {
    if (!raw) continue;
    const outcome = await settle(raw);
    if (outcome === 'applied') applied = true;
    else if (outcome === 'dropped') continue;
    else if (keep === null) keep = outcome.keep;
    else displaced = true;
  }
  if (keep === kept) return applied;
  if (keep === null) {
    try {
      localStorage.removeItem(KEPT_STASH_KEY);
    } catch {
      /* ignore */
    }
    return applied;
  }
  try {
    localStorage.setItem(KEPT_STASH_KEY, keep);
    // One text is all the kept slot holds, and the fresh refusal, the
    // newer one, is the text it keeps.
    if (displaced) logAuthEvent('seal:stash-kept-replaced');
  } catch {
    // Storage is full. The new text is dropped rather than kept in a
    // weaker form, and the slot keeps what it held, for the next boot.
    logAuthEvent('seal:stash-kept-lost');
  }
  return applied;
}
