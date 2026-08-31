import Dexie, { type EntityTable } from 'dexie';
import type { NoteType } from '@notes/shared';
import type { AttachmentMeta } from './attachmentStore';
import { isDemoMode, DEMO_DB_NAME } from './demo';
import { localSealMiddleware } from './localSeal';

/**
 * Local shape of a note - decrypted, ready for the UI to use.
 * Mirrors DecryptedNote from @notes/shared plus sync bookkeeping.
 *
 * `dirty`, `deleted`, `trashed`, `starred`, `locked`, `pinProtected`
 * are numbers (0 / 1) because Dexie's indexing is happier with
 * numeric booleans than real booleans.
 *
 * Field meanings:
 * - `dirty = 1`        → has unsynced local changes
 * - `deleted = 1`      → hard-delete tombstone; sync will remove from server
 *                         and from the local DB. Used when user "empties trash".
 * - `trashed = 1`      → in the trash bin. Still synced; hidden from the main
 *                         notes list until user restores or empties trash.
 * - `starred = 1`      → marked favorite; appears in the Starred view.
 * - `locked = 1`       → Pro: note is read-only. Toggle off in note options to edit again.
 * - `pinProtected = 1` → Pro: note is gated behind the user's PIN.
 */
export interface LocalNote {
  id: string;
  title: string;
  body: string;
  tags: string[];
  createdAt: string;
  updatedAt: string;
  dirty: number;
  deleted: number;
  trashed: number;
  starred: number;
  locked: number;
  pinProtected: number;
  /** Note type discriminator. 'note' = standard markdown, 'login' = password entry. */
  type: NoteType;
  /** Mood & wellness tracker data for journal entries. */
  trackers?: Record<string, unknown>;
  /** Pro: id of the folder this note lives in, or null when unfiled. */
  folderId: string | null;
  /**
   * Nonce (base64) of the server generation this row is known to match -
   * recorded on push success and on pull apply. Lets the pull tell its own
   * echo from a foreign row carrying an EQUAL updated_at stamp (#156):
   * same stamp + same nonce = our own push coming back, skip; same stamp +
   * different nonce = another device won an equal-stamp race, apply it.
   * Absent on rows that never synced (pre-upgrade rows included).
   */
  syncedNonce?: string;
}

/**
 * Cached decrypted image blob. Stored locally so opening a note
 * with images doesn't re-download every time. Keyed by image UUID.
 */
interface CachedImage {
  id: string;
  data: Uint8Array;
  cachedAt: string;
}

/**
 * Content-hash → UUID dedup index. When the same image is pasted
 * twice, we skip the upload and reuse the existing UUID.
 * Keyed by SHA-256 hex of the processed (pre-encryption) WebP bytes.
 */
interface ImageDedup {
  hash: string;
  uuid: string;
  /** Encrypted blob size in bytes (for image_bytes quota tracking). */
  encryptedSize?: number;
  /** 1 = blob cached locally but not yet uploaded to Supabase. */
  pendingUpload?: number;
  /** 1 = pending upload known not to fit the storage quota. The retry
   *  sweep skips it without touching the wire and the status surfaces
   *  say "doesn't fit" instead of "uploading" (backlog #143). */
  quotaBlocked?: number;
}

/**
 * Cached decrypted attachment blob. Same pattern as CachedImage but
 * includes metadata (filename, MIME, size) alongside the raw bytes.
 */
interface CachedAttachment {
  id: string;
  meta: AttachmentMeta;
  data: Uint8Array;
  cachedAt: string;
}

/**
 * Content-hash → UUID dedup index for attachments.
 * Keyed by SHA-256 hex of the raw file bytes (pre-encryption).
 */
interface AttachmentDedup {
  hash: string;
  uuid: string;
  encryptedSize?: number;
  /** 1 = blob cached locally but not yet uploaded to Supabase. */
  pendingUpload?: number;
  /** 1 = pending upload known not to fit the storage quota - see ImageDedup. */
  quotaBlocked?: number;
}

/**
 * Deferred blob GC queue. A row means the local cache/dedup rows for
 * this blob are already gone and quota was already decremented, but
 * the Supabase Storage object itself has NOT been removed yet - see
 * imageGC.ts sweepBlobGC() for why. Keyed by blob uuid.
 */
interface BlobGCEntry {
  uuid: string;
  kind: 'image' | 'attachment';
  size: number;
  /** ISO timestamp of when the blob was enqueued for deletion. */
  enqueuedAt: string;
}

/**
 * Parsed-doc cache for big notes (#150). Parsing megabytes of markdown into
 * a ProseMirror doc blocks the main thread for seconds; rebuilding the same
 * doc from its JSON takes milliseconds. Validated by EXACT body-string
 * equality (no hashing), so a stale row can never surface wrong content -
 * any body difference is a miss and falls back to the normal parse.
 * Local-only derived data; never synced. See editorDocCache.ts.
 */
interface EditorDocCacheEntry {
  noteId: string;
  /** The exact markdown body the cached doc was parsed from. */
  body: string;
  /** The ProseMirror doc as TipTap JSON. */
  json: unknown;
  /** Epoch ms, for pruning the oldest rows. */
  cachedAt: number;
}

/**
 * One note-history snapshot in the public DEMO.
 *
 * The real feature stores encrypted snapshots server-side, which demo
 * cannot do and must not do: it holds no session and promises zero server
 * calls. So demo keeps its snapshots here, in the throwaway demo database,
 * in the same plaintext form the notes themselves are stored in locally.
 * They die with the tab session like everything else in that database.
 * Spec: ops/docs/pro-features.md (note history: Pro-only, 20 versions per note)
 */
interface DemoNoteVersion {
  id: string;
  noteId: string;
  /** ISO, matching the server column the real path reads. */
  createdAt: string;
  title: string;
  body: string;
  tags: string[];
}

/**
 * Tiny key-value store for facts that must survive localStorage
 * eviction. First tenant: the pubkey-owner mirror (`ownerPubkey`) -
 * the localStorage owner marker can be evicted while the notes in
 * IndexedDB survive, and that asymmetry made the owner-unknown wipe
 * destroy the user's own credentials (session audit 2026-08-25).
 * Second tenant: the phrase wrap key (`phraseWrapKey`) - a
 * NON-EXTRACTABLE CryptoKey persisted as an object via structured
 * clone, never as exported bytes (phraseAtRest.ts). No schema change:
 * Dexie only declares the primary key, and IndexedDB clones CryptoKey
 * natively.
 */
interface KvEntry {
  key: string;
  value: string | CryptoKey;
}

class NotesDb extends Dexie {
  notes!: EntityTable<LocalNote, 'id'>;
  demoVersions!: EntityTable<DemoNoteVersion, 'id'>;
  imageCache!: EntityTable<CachedImage, 'id'>;
  imageDedup!: EntityTable<ImageDedup, 'hash'>;
  attachmentCache!: EntityTable<CachedAttachment, 'id'>;
  attachmentDedup!: EntityTable<AttachmentDedup, 'hash'>;
  blobGC!: EntityTable<BlobGCEntry, 'uuid'>;
  editorDocCache!: EntityTable<EditorDocCacheEntry, 'noteId'>;
  kv!: EntityTable<KvEntry, 'key'>;

  constructor(raw = false) {
    // Demo mode uses a separate, throwaway database so demo data never
    // shares storage with a real install. See demo.ts.
    super(isDemoMode() ? DEMO_DB_NAME : 'privacynotes');

    // v1 - original schema.
    this.version(1).stores({
      notes: 'id, updatedAt, dirty, deleted',
    });

    // v2 - add trashed + starred.
    // Existing rows get back-filled with 0/0 by the upgrade function.
    this.version(2)
      .stores({
        notes: 'id, updatedAt, dirty, deleted, trashed, starred',
      })
      .upgrade(async (tx) => {
        await tx
          .table<LocalNote>('notes')
          .toCollection()
          .modify((n) => {
            if (typeof n.trashed !== 'number') n.trashed = 0;
            if (typeof n.starred !== 'number') n.starred = 0;
          });
      });

    // v3 - add imageCache table for decrypted image blobs.
    this.version(3).stores({
      notes: 'id, updatedAt, dirty, deleted, trashed, starred',
      imageCache: 'id, cachedAt',
    });

    // v4 - add imageDedup table for content-hash deduplication.
    // `locked` and `pinProtected` joined the note shape (Pro release)
    // without a migration: existing rows back-fill on their next write
    // (via notesRepo defaults) or on the initial sync pull (decryptNote
    // defaults both flags to false).
    this.version(4).stores({
      notes: 'id, updatedAt, dirty, deleted, trashed, starred',
      imageCache: 'id, cachedAt',
      imageDedup: 'hash, uuid',
    });

    // v5 - add `type` field. Migrate existing #login-tagged notes to
    // type='login' and strip the tag so it no longer serves as a type
    // discriminator. All other notes get type='note'.
    this.version(5)
      .stores({
        notes: 'id, updatedAt, dirty, deleted, trashed, starred, type',
        imageCache: 'id, cachedAt',
        imageDedup: 'hash, uuid',
      })
      .upgrade(async (tx) => {
        await tx
          .table<LocalNote>('notes')
          .toCollection()
          .modify((n) => {
            if (n.tags.includes('login')) {
              n.type = 'login';
              n.tags = n.tags.filter((t) => t !== 'login');
              n.dirty = 1; // re-sync so the server gets the updated payload
            } else {
              n.type = 'note';
            }
          });
      });

    // v6 - add attachmentCache + attachmentDedup tables for file attachments.
    this.version(6).stores({
      notes: 'id, updatedAt, dirty, deleted, trashed, starred, type',
      imageCache: 'id, cachedAt',
      imageDedup: 'hash, uuid',
      attachmentCache: 'id, cachedAt',
      attachmentDedup: 'hash, uuid',
    });

    // v7 - migrate journal entries from #journal tag to type='journal'.
    // Same pattern as v5 login migration. Strip the tag so pillar
    // membership is driven by type, not user-removable metadata.
    this.version(7)
      .stores({
        notes: 'id, updatedAt, dirty, deleted, trashed, starred, type',
        imageCache: 'id, cachedAt',
        imageDedup: 'hash, uuid',
        attachmentCache: 'id, cachedAt',
        attachmentDedup: 'hash, uuid',
      })
      .upgrade(async (tx) => {
        await tx
          .table<LocalNote>('notes')
          .toCollection()
          .modify((n) => {
            if (n.tags.includes('journal')) {
              n.type = 'journal';
              n.tags = n.tags.filter((t) => t !== 'journal');
              n.dirty = 1;
            }
          });
      });

    // v8 - strict note type classification: add type='task'.
    // Body-sniffing (HAS_TASKS_RE) is removed from icon logic; the
    // icon now follows the type field. Migrate notes whose body is
    // predominantly a checklist (>50% task lines) to type='task'.
    // Prose notes with incidental checklists keep type='note'.
    this.version(8)
      .stores({
        notes: 'id, updatedAt, dirty, deleted, trashed, starred, type',
        imageCache: 'id, cachedAt',
        imageDedup: 'hash, uuid',
        attachmentCache: 'id, cachedAt',
        attachmentDedup: 'hash, uuid',
      })
      .upgrade(async (tx) => {
        const TASK_LINE = /^- \[[ x]\] /;
        await tx
          .table<LocalNote>('notes')
          .toCollection()
          .modify((n) => {
            if (n.type !== 'note') return;
            const lines = n.body.split('\n').filter((l) => l.trim());
            if (lines.length === 0) return;
            const taskLines = lines.filter((l) => TASK_LINE.test(l)).length;
            // >50% task lines → this is a task note, not prose with a checklist
            if (taskLines / lines.length > 0.5) {
              n.type = 'task';
              // Don't mark dirty - avoids a sync storm on migration.
              // The type change is cosmetic (icon); it syncs naturally
              // when the user next edits the note.
            }
          });
      });

    // v9 - add `folderId` (Pro folders). Indexed so folder filtering is
    // fast. Existing rows back-fill to null (unfiled); no dirty flag -
    // null is the implicit default in every ciphertext, so there is
    // nothing to push.
    this.version(9)
      .stores({
        notes: 'id, updatedAt, dirty, deleted, trashed, starred, type, folderId',
        imageCache: 'id, cachedAt',
        imageDedup: 'hash, uuid',
        attachmentCache: 'id, cachedAt',
        attachmentDedup: 'hash, uuid',
      })
      .upgrade(async (tx) => {
        await tx
          .table<LocalNote>('notes')
          .toCollection()
          .modify((n) => {
            if (n.folderId === undefined) n.folderId = null;
          });
      });

    // v10 - add blobGC table for the deferred blob-deletion queue (#125).
    // New table, no upgrade function needed - nothing to back-fill.
    this.version(10).stores({
      notes: 'id, updatedAt, dirty, deleted, trashed, starred, type, folderId',
      imageCache: 'id, cachedAt',
      imageDedup: 'hash, uuid',
      attachmentCache: 'id, cachedAt',
      attachmentDedup: 'hash, uuid',
      blobGC: 'uuid, enqueuedAt',
    });

    // v11 - parsed-doc cache for big notes (#150).
    this.version(11).stores({
      notes: 'id, updatedAt, dirty, deleted, trashed, starred, type, folderId',
      imageCache: 'id, cachedAt',
      imageDedup: 'hash, uuid',
      attachmentCache: 'id, cachedAt',
      attachmentDedup: 'hash, uuid',
      blobGC: 'uuid, enqueuedAt',
      editorDocCache: 'noteId, cachedAt',
    });

    // v12 - kv store (owner-pubkey mirror). New table, nothing to
    // back-fill; the mirror is written on the next successful auth.
    this.version(12).stores({
      notes: 'id, updatedAt, dirty, deleted, trashed, starred, type, folderId',
      imageCache: 'id, cachedAt',
      imageDedup: 'hash, uuid',
      attachmentCache: 'id, cachedAt',
      attachmentDedup: 'hash, uuid',
      blobGC: 'uuid, enqueuedAt',
      editorDocCache: 'noteId, cachedAt',
      kv: 'key',
    });

    // v13 - note-history snapshots for the public demo. The real feature is
    // server-backed and demo makes no server calls, so demo keeps its own
    // snapshots here. The table is declared on both databases because Dexie
    // versions the schema, not the instance; only demo ever writes to it.
    this.version(13).stores({
      notes: 'id, updatedAt, dirty, deleted, trashed, starred, type, folderId',
      imageCache: 'id, cachedAt',
      imageDedup: 'hash, uuid',
      attachmentCache: 'id, cachedAt',
      attachmentDedup: 'hash, uuid',
      blobGC: 'uuid, enqueuedAt',
      editorDocCache: 'noteId, cachedAt',
      demoVersions: 'id, noteId, createdAt',
      kv: 'key',
    });

    // The at-rest seal layer. Read surfaces open sealed rows wherever
    // they exist; writes stay plaintext until the writer release turns
    // sealed writes on. Inert in demo mode. The raw escape hatch below
    // skips it for exactly two callers with a legitimate need to see
    // stored bytes: the sweep's scan and its conversions.
    // Spec: ops/docs/plans/local-at-rest.md (section 3.3)
    if (!raw) this.use(localSealMiddleware());
  }
}

export const db = new NotesDb();

/**
 * A second connection WITHOUT the seal middleware. For the sweep only:
 * it must SEE the sealed-or-not state of stored rows, and it converts
 * plaintext rows without paying an unseal round trip. Everything else
 * reads through `db` and the middleware.
 */
export function openRawDb(): NotesDb {
  return new NotesDb(true);
}

/**
 * Close and reopen the Dexie/IndexedDB handle. iOS WebKit can sever the
 * IndexedDB connection when a home-screen (standalone) web app is
 * backgrounded or killed, after which reads reject with
 * InvalidStateError / DatabaseClosedError. Reopening re-establishes the
 * connection without a full page reload, which a soft reload alone does
 * not fix. (#112)
 */
export async function reopenDb(): Promise<void> {
  try {
    db.close();
  } catch {
    /* already closed - ignore */
  }
  await db.open();
}

/**
 * Ask the browser to mark this origin's storage as persistent so the
 * user's encrypted notes can't be silently evicted under storage
 * pressure. Best-effort and idempotent:
 *
 * - Chrome / Safari decide silently from engagement heuristics (no prompt).
 * - Firefox shows a one-time permission prompt. We only reach this from a
 *   real save (see notesRepo), never on app boot, so the ask is contextual.
 * - A denial is harmless: IndexedDB keeps working, the data is just
 *   evictable - the same state every origin is in by default. Sync to the
 *   server stays the real durability backstop.
 *
 * Runs at most once per tab session and never in demo mode (demo storage
 * is intentionally throwaway - see demo.ts).
 */
let persistenceRequested = false;
export async function requestPersistence(): Promise<void> {
  if (persistenceRequested) return;
  persistenceRequested = true;
  if (isDemoMode()) return;
  try {
    if (!navigator.storage?.persist) return;
    if (await navigator.storage.persisted()) return;
    await navigator.storage.persist();
  } catch {
    /* best-effort - ignore unsupported / blocked */
  }
}
