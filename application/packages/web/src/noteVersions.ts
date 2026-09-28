/**
 * Client helpers for Pro note-history (server-backed snapshots).
 *
 * Each saved version is an encrypted snapshot of the note's
 * title/body/tags at the moment of save, plus a login's custom fields
 * and extra websites. The server never sees
 * plaintext. Versions live in the `note_versions` table with a
 * BEFORE INSERT trigger that caps each note at 20 rows.
 *
 * Version creation is debounced at the call site: we only snapshot
 * after the user has been idle for a few seconds AND the content
 * hashes out different from the previous version. Hash-compare
 * prevents burning capacity on no-op saves (the editor calls
 * updateNote on every keystroke-ish debounce).
 */

import {
  encryptNote,
  decryptNote,
  bytesToBase64,
  base64ToBytes,
  type SupabaseClient,
} from '@notes/shared';
import { db, type LocalNote } from './db';
import { computeSnapshotTotalSize } from './notesViewUtils';
import { isServerWriteBlocked } from './syncPause';
import { isDemoMode } from './demo';

const TABLE = 'note_versions';

/**
 * Rows the server's BEFORE INSERT trigger keeps per note. The demo path
 * below enforces the same number itself, so the two behave alike.
 * Spec: ops/docs/pro-features.md (also a 60s min gap, enforced in useNoteEditing.ts)
 */
const MAX_VERSIONS = 20;

/** Compact shape the UI panel renders. `bodyBytes` drives the
 *  "how much changed" hint without exposing the plaintext body. */
export type NoteVersion = {
  id: string;
  noteId: string;
  createdAt: string; // ISO
  title: string;
  body: string;
  tags: string[];
  /** A login's custom fields and extra websites as recorded: undefined when
   *  the version did not record them (an older client, or not a login), null
   *  when it recorded none. */
  login?: unknown;
  bodyBytes: number;
};

/** What a snapshot records beside the title, body and tags: for a login,
 *  its extras, with null standing for "recorded, and there were none". */
function loginOf(note: LocalNote): { login?: unknown } {
  return note.type === 'login' ? { login: note.trackers?.login ?? null } : {};
}

function loginFromTrackers(trackers: Record<string, unknown> | undefined): { login?: unknown } {
  return trackers && Object.prototype.hasOwnProperty.call(trackers, 'login') ? { login: trackers.login } : {};
}

type RemoteRow = {
  id: string;
  note_id: string;
  user_pubkey: string;
  ciphertext: string;
  nonce: string;
  created_at: string;
};

/**
 * Result of a snapshot attempt. Callers can ignore `ok=true` and
 * surface a UI hint when `code === '42501'` (RLS rejection - Pro
 * lapsed). Other errors stay silent.
 */
export type CreateNoteVersionResult =
  | { ok: true }
  | { ok: false; code: string; message: string };

/**
 * Write a new version snapshot for `note`. Returns a structured
 * result so the caller can detect the Pro-lapsed RLS rejection
 * (code 42501) and surface a one-time toast. Other errors are
 * logged. The caller is expected to debounce + dedupe before
 * calling this.
 */
export async function createNoteVersion(
  supabase: SupabaseClient,
  pubkey: string,
  encryptionKey: Uint8Array,
  note: LocalNote
): Promise<CreateNoteVersionResult> {
  // Below the release floor server writes pause (see sync.ts). This one is
  // per-edit and would otherwise ship every keystroke batch to the server
  // while note sync itself is paused, defeating the pause. Guarded here so
  // both call sites (edit snapshots, pre-restore snapshots) are covered.
  if (isServerWriteBlocked()) {
    return { ok: false, code: 'below_version_floor', message: 'client below release floor' };
  }
  // The demo has no session and makes no server calls, so it keeps its own
  // snapshots in the throwaway demo database. Same cap, same order, no
  // encryption: the demo database already holds the notes in plaintext, and
  // nothing in it leaves the tab.
  if (isDemoMode()) {
    try {
      await db.demoVersions.add({
        id: crypto.randomUUID(),
        noteId: note.id,
        createdAt: new Date().toISOString(),
        title: note.title,
        body: note.body,
        tags: note.tags,
        ...loginOf(note),
      });
      const ids = await db.demoVersions.where('noteId').equals(note.id).sortBy('createdAt');
      if (ids.length > MAX_VERSIONS) {
        await db.demoVersions.bulkDelete(ids.slice(0, ids.length - MAX_VERSIONS).map((v) => v.id));
      }
      return { ok: true };
    } catch (err) {
      return { ok: false, code: '', message: (err as Error).message };
    }
  }
  try {
    const { ciphertext, nonce } = encryptNote(
      {
        title: note.title,
        body: note.body,
        tags: note.tags,
        trashed: note.trashed === 1,
        starred: note.starred === 1,
        locked: note.locked === 1,
        pinProtected: note.pinProtected === 1,
        type: note.type,
        ...(note.type === 'login' ? { trackers: loginOf(note) } : {}),
      },
      encryptionKey
    );
    const { error } = await supabase.from(TABLE).insert({
      note_id: note.id,
      user_pubkey: pubkey,
      ciphertext: bytesToBase64(ciphertext),
      nonce: bytesToBase64(nonce),
    });
    if (error) {
      console.error('[note_versions] insert failed:', error);
      return { ok: false, code: error.code ?? '', message: error.message };
    }
    return { ok: true };
  } catch (err) {
    console.error('[note_versions] encrypt failed:', err);
    return { ok: false, code: '', message: (err as Error).message };
  }
}

/**
 * List all versions for a note, newest first. Decrypted in memory
 * so the caller can render previews without a second round trip.
 *
 * A read that fails throws; an empty list means the note has no
 * versions. The blob GC depends on that difference: it skips when the
 * read throws, because history it could not read may still hold a blob.
 * postgrest-js reports a failed fetch, offline included, as an error
 * object rather than a rejection, so the check below is what turns it
 * into a throw.
 */
export async function listNoteVersions(
  supabase: SupabaseClient,
  encryptionKey: Uint8Array,
  noteId: string
): Promise<NoteVersion[]> {
  if (isDemoMode()) {
    const rows = await db.demoVersions.where('noteId').equals(noteId).sortBy('createdAt');
    return rows.reverse().map((v) => ({
      id: v.id,
      noteId: v.noteId,
      createdAt: v.createdAt,
      title: v.title,
      body: v.body,
      tags: v.tags,
      ...(v.login !== undefined ? { login: v.login } : {}),
      bodyBytes: computeSnapshotTotalSize(v.title, v.body, v.tags),
    }));
  }
  const { data, error } = await supabase
    .from(TABLE)
    .select('*')
    .eq('note_id', noteId)
    .order('created_at', { ascending: false });
  if (error) {
    console.error('[note_versions] list failed:', error);
    throw new Error(error.message || 'note_versions list failed');
  }
  const rows = (data ?? []) as RemoteRow[];
  const out: NoteVersion[] = [];
  for (const row of rows) {
    try {
      const decrypted = decryptNote(
        base64ToBytes(row.ciphertext),
        base64ToBytes(row.nonce),
        encryptionKey
      );
      out.push({
        id: row.id,
        noteId: row.note_id,
        createdAt: row.created_at,
        title: decrypted.title,
        body: decrypted.body,
        tags: decrypted.tags,
        ...loginFromTrackers(decrypted.trackers),
        bodyBytes: computeSnapshotTotalSize(
          decrypted.title ?? '', decrypted.body ?? '', decrypted.tags ?? [],
        ),
      });
    } catch (err) {
      console.error('[note_versions] decrypt failed for', row.id, err);
    }
  }
  return out;
}
