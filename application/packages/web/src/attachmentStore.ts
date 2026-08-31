/**
 * Attachment store - upload, fetch, delete for encrypted file blobs.
 *
 * Local-first architecture:
 * - Upload: encrypt → cache in IndexedDB → return UUID instantly →
 *   background upload to Supabase Storage + quota adjustment.
 * - Fetch: check IndexedDB cache → fall back to Supabase download.
 * - On init: processPendingUploads() retries blobs that were cached
 *   locally but never made it to the server (app closed, network error).
 *
 * Blob format: [4-byte header length (LE)] [JSON header] [file bytes]
 * All of this is then encrypted as a single blob via encryptBlob().
 *
 * URI scheme: pn:file/<uuid> (vs pn:img/<uuid> for images)
 */

import { encryptBlob, decryptBlob, type SupabaseClient } from '@notes/shared';
import { db } from './db';
import { isDemoMode } from './demo';
import { ownsLocalData } from './authStorage';
import { logAuthEvent } from './authDiag';
import { isServerWriteBlocked } from './syncPause';
import { uploadsHeldForWifi } from './wifiOnly';
import { fetchQuotaUsage } from './devices';

const BUCKET = 'encrypted-images'; // Same bucket as images - it's all encrypted blobs

/** Metadata stored alongside the file, encrypted in the blob header. */
export interface AttachmentMeta {
  name: string;     // Original filename
  mime: string;     // MIME type
  size: number;     // Original file size in bytes
}

/** Decrypted attachment: metadata + raw file bytes. */
export interface DecryptedAttachment {
  meta: AttachmentMeta;
  data: Uint8Array;
}

/** Encode metadata + file data into a single Uint8Array for encryption. */
function packAttachment(meta: AttachmentMeta, data: Uint8Array): Uint8Array {
  const headerJson = JSON.stringify(meta);
  const headerBytes = new TextEncoder().encode(headerJson);
  const headerLen = headerBytes.length;

  const combined = new Uint8Array(4 + headerLen + data.length);
  combined[0] = headerLen & 0xff;
  combined[1] = (headerLen >> 8) & 0xff;
  combined[2] = (headerLen >> 16) & 0xff;
  combined[3] = (headerLen >> 24) & 0xff;
  combined.set(headerBytes, 4);
  combined.set(data, 4 + headerLen);

  return combined;
}

/** Unpack a decrypted blob into metadata + file data. */
function unpackAttachment(combined: Uint8Array): DecryptedAttachment {
  if (combined.length < 5) {
    throw new Error('Attachment blob too short');
  }

  const headerLen =
    combined[0]! |
    (combined[1]! << 8) |
    (combined[2]! << 16) |
    (combined[3]! << 24);

  if (headerLen < 2 || headerLen > 10000 || 4 + headerLen > combined.length) {
    throw new Error('Invalid attachment header length');
  }

  const headerBytes = combined.slice(4, 4 + headerLen);
  const headerJson = new TextDecoder().decode(headerBytes);
  const meta: AttachmentMeta = JSON.parse(headerJson);
  const data = combined.slice(4 + headerLen);

  return { meta, data };
}

/** SHA-256 hash of raw bytes, returned as hex string. */
async function hashBytes(data: Uint8Array): Promise<string> {
  const buf = await crypto.subtle.digest('SHA-256', data as ArrayBufferView<ArrayBuffer>);
  const arr = new Uint8Array(buf);
  let hex = '';
  for (const b of arr) hex += b.toString(16).padStart(2, '0');
  return hex;
}

/** Errors that will never succeed on retry - don't keep pendingUpload. */
function isPermanentError(msg: string): boolean {
  return (
    msg.includes('exceeded the maximum allowed size') ||
    msg.includes('Payload too large') ||
    msg.includes('413')
  );
}

/** Quota failures are retryable (e.g. after the user frees space or upgrades). */
function isQuotaError(msg: string): boolean {
  return msg.includes('Quota exceeded');
}

export class AttachmentStore {
  private supabase: SupabaseClient;
  private encryptionKey: Uint8Array;
  private pubkey: string;
  /** Called when a background upload fails permanently. UI should show a toast. */
  onBackgroundError?: (filename: string, error: string) => void;
  /**
   * UUIDs with a _backgroundUpload currently in flight. The post-sync retry
   * hook can call processPendingUploads() while a just-uploaded blob's
   * initial background upload is still running and its dedup row still says
   * pendingUpload === 1. Without this guard both paths upload the same uuid
   * concurrently; the second upload hits Storage as an upsert over an object
   * that already exists and fails with an RLS violation (the bucket has no
   * UPDATE policy). The in-flight upload owns the pendingUpload bookkeeping,
   * so a concurrent caller for the same uuid just returns.
   */
  private uploading = new Set<string>();
  /**
   * True while a processPendingUploads() sweep is running. The post-sync
   * retry hook fires on a timer and a sweep can still be in flight from a
   * previous trigger - without this guard two overlapping sweeps would walk
   * the same pending rows and race each other into the same RLS failure
   * the uploading guard above exists to prevent.
   */
  private sweepRunning = false;

  constructor(
    supabase: SupabaseClient,
    encryptionKey: Uint8Array,
    pubkey: string,
  ) {
    this.supabase = supabase;
    this.encryptionKey = encryptionKey;
    this.pubkey = pubkey;
  }

  /**
   * True when this browser's local storage no longer belongs to this
   * store's account. An account switch rebuilds the stores, but an
   * instance captured by an in-flight upload or a scheduled sweep
   * survives it holding the OLD pubkey beside a client whose JWT is
   * already the NEW account's. Storage RLS refuses its uploads, but
   * adjust_blob_bytes derives its target from the JWT alone, so a stale
   * instance would silently move the NEW account's quota. Every server
   * write below checks this and skips; local rows need no care, the
   * switch wipe owns them.
   */
  private ownershipLost(): boolean {
    if (ownsLocalData(this.pubkey)) return false;
    if (!this.ownershipLogged) {
      this.ownershipLogged = true;
      logAuthEvent('attachmentStore:ownership-lost', { expectedPk: this.pubkey.slice(0, 8) });
    }
    return true;
  }
  private ownershipLogged = false;

  /**
   * Private copy of the key for one encrypt operation. signOut zeroes
   * `this.encryptionKey` in place (the shared buffer passed into the
   * constructor), so a copy that comes back all-zero means sign-out is
   * already in progress - callers must bail rather than encrypt with a
   * dead key. Same pattern as sync.ts.
   */
  private keyCopy(): Uint8Array | null {
    const copy = new Uint8Array(this.encryptionKey);
    if (copy.every((b) => b === 0)) return null;
    return copy;
  }

  /**
   * Upload an attachment: pack + encrypt → cache locally → return UUID
   * immediately. Supabase upload + quota adjustment runs in background.
   */
  async uploadAttachment(file: File): Promise<{ uuid: string; meta: AttachmentMeta; uploaded: Promise<void> }> {
    const data = new Uint8Array(await file.arrayBuffer());

    // Content-hash dedup check.
    const hashHex = await hashBytes(data);
    const existing = await db.attachmentDedup.get(hashHex);
    if (existing) {
      return {
        uuid: existing.uuid,
        meta: { name: file.name, mime: file.type || 'application/octet-stream', size: file.size },
        uploaded: Promise.resolve(),
      };
    }

    const meta: AttachmentMeta = {
      name: file.name,
      mime: file.type || 'application/octet-stream',
      size: file.size,
    };

    const packed = packAttachment(meta, data);
    // signOut can zero this.encryptionKey mid-upload. This is a
    // user-initiated path, not a background retry - throw rather than
    // silently encrypt with a dead key; callers already handle upload
    // errors.
    const passKey = this.keyCopy();
    if (!passKey) {
      throw new Error('Sign-out in progress');
    }
    const encrypted = encryptBlob(packed, passKey);
    passKey.fill(0);
    const uuid = crypto.randomUUID();

    // --- Local-first: cache + dedup record, return immediately ---
    await db.attachmentCache.put({
      id: uuid,
      meta,
      data,
      cachedAt: new Date().toISOString(),
    });
    await db.attachmentDedup.put({
      hash: hashHex,
      uuid,
      encryptedSize: encrypted.length,
      pendingUpload: 1,
    });

    // --- Background: upload to Supabase + adjust quota ---
    const uploaded = this._backgroundUpload(uuid, meta.name, encrypted);

    return { uuid, meta, uploaded };
  }

  /**
   * Upload encrypted blob to Supabase and adjust quota.
   * On permanent failure: clears pendingUpload but keeps local cache
   * so restored attachments remain viewable offline.
   * On transient failure: keeps pendingUpload for retry on next init.
   */
  private async _backgroundUpload(
    uuid: string,
    filename: string,
    encrypted: Uint8Array,
  ): Promise<void> {
    // Demo mode makes zero server calls - the blob lives only in the
    // throwaway local cache. Still do the bookkeeping the upload would
    // have done so the dedup row carries a real size for the Files view.
    if (isDemoMode()) {
      const cached = await db.attachmentDedup.where('uuid').equals(uuid).first();
      if (cached) {
        await db.attachmentDedup.put({ ...cached, pendingUpload: 0, encryptedSize: encrypted.length });
      }
      return;
    }

    // Server writes blocked (release floor or user pause - see syncPause.ts).
    // Unlike the demo branch, do NOT clear pendingUpload: the blob must
    // upload once the block lifts, and the retry sweep (also gated) handles
    // that. Same hold while "Files on wifi only" waits for wifi.
    if (isServerWriteBlocked() || uploadsHeldForWifi()) return;
    if (this.ownershipLost()) return;

    // A concurrent upload of this same uuid is already running (the
    // post-sync retry hook can overlap with the initial upload from
    // uploadAttachment) - let the in-flight one own the pendingUpload
    // bookkeeping rather than racing it to the same Storage path.
    if (this.uploading.has(uuid)) {
      return;
    }
    this.uploading.add(uuid);
    try {
      const path = `${this.pubkey}/${uuid}`;

      const { error } = await this.supabase.storage
        .from(BUCKET)
        .upload(path, encrypted, {
          contentType: 'application/octet-stream',
          upsert: true, // idempotent for retries
        });

      if (error) {
        const msg = error.message || '';
        if (isPermanentError(msg)) {
          // Keep local cache so restored attachments remain viewable offline.
          // Just clear pendingUpload so we don't retry a doomed upload.
          const dedup = await db.attachmentDedup.where('uuid').equals(uuid).first();
          if (dedup) {
            await db.attachmentDedup.put({ ...dedup, pendingUpload: 0 });
          }
          this.onBackgroundError?.(filename, msg);
          console.error('[attachmentStore] permanent upload failure, kept local cache:', uuid, msg);
          throw new Error(msg);
        }
        if (isQuotaError(msg)) {
          // Retryable - pendingUpload stays 1, but still toast the user now.
          // quotaBlocked keeps the retry sweep off the wire while the blob
          // cannot fit (backlog #143).
          const dedupRec = await db.attachmentDedup.where('uuid').equals(uuid).first();
          if (dedupRec) await db.attachmentDedup.put({ ...dedupRec, quotaBlocked: 1 });
          this.onBackgroundError?.(filename, msg);
        }
        // Transient - leave pendingUpload=1 for retry on next init.
        console.warn('[attachmentStore] transient upload failure, will retry:', uuid, msg);
        throw new Error(msg);
      }

      if (this.ownershipLost()) return;
      const { error: rpcErr } = await this.supabase.rpc('adjust_blob_bytes', {
        delta: encrypted.length,
      });
      if (rpcErr) {
        const msg = rpcErr.message || '';
        if (isQuotaError(msg)) {
          // Remove the remote blob we just uploaded (it must not sit in
          // Storage uncounted), but leave pendingUpload=1 so a later pass
          // retries the whole upload. quotaBlocked makes that later pass
          // wait for real headroom instead of re-uploading the full blob
          // just to land back here (backlog #143).
          await this.supabase.storage.from(BUCKET).remove([path]).catch(() => {});
          const dedupRec = await db.attachmentDedup.where('uuid').equals(uuid).first();
          if (dedupRec) await db.attachmentDedup.put({ ...dedupRec, quotaBlocked: 1 });
          this.onBackgroundError?.(filename, msg);
          console.error('[attachmentStore] quota exceeded, will retry:', uuid);
          throw new Error(msg);
        }
        if (isPermanentError(msg)) {
          // Remove the remote blob we just uploaded, but keep local cache.
          await this.supabase.storage.from(BUCKET).remove([path]).catch(() => {});
          const dedupRec = await db.attachmentDedup.where('uuid').equals(uuid).first();
          if (dedupRec) {
            await db.attachmentDedup.put({ ...dedupRec, pendingUpload: 0 });
          }
          this.onBackgroundError?.(filename, msg);
          console.error('[attachmentStore] permanent upload failure, kept local cache:', uuid, msg);
          throw new Error(msg);
        }
        // Transient failure: same contract as imageStore - the object is
        // uploaded (upsert, idempotent) but uncounted, so keep
        // pendingUpload=1 for the retry sweep instead of silently
        // understating usage (backlog #131).
        console.warn('[attachmentStore] adjust_blob_bytes failed, will retry:', msg);
        throw new Error(msg);
      }

      // Clear pending flag and update encryptedSize (may have been 0 from
      // restoreBlobs - now we know the real size after encrypting).
      const dedup = await db.attachmentDedup.where('uuid').equals(uuid).first();
      if (dedup) {
        await db.attachmentDedup.put({ ...dedup, pendingUpload: 0, quotaBlocked: 0, encryptedSize: encrypted.length });
      }
    } finally {
      this.uploading.delete(uuid);
    }
  }

  /**
   * Retry uploads that were cached locally but never made it to the server.
   * Called once on store init. Re-encrypts from cached data (nonce is random
   * per call - fine, server doesn't care about specific ciphertext).
   */
  async processPendingUploads(): Promise<void> {
    // Blocked or held: pending rows survive and upload once the block lifts.
    if (isDemoMode() || isServerWriteBlocked() || uploadsHeldForWifi()) return;
    if (this.ownershipLost()) return;
    // Single-flight: the post-sync retry hook can fire again before a
    // previous sweep has finished walking the pending rows. Let the
    // running sweep own the pass rather than starting a second one that
    // would just re-race the uploading guard below.
    if (this.sweepRunning) return;
    this.sweepRunning = true;
    try {
      const pending = await db.attachmentDedup
        .filter((r) => r.pendingUpload === 1)
        .toArray();

      // Quota preflight - same contract as ImageStore.processPendingUploads
      // (backlog #143): one quota read per pass, rows that cannot fit are
      // marked quotaBlocked and never touch the wire.
      let freeBytes: number | null = null;
      if (pending.length > 0) {
        try {
          const q = await fetchQuotaUsage(this.supabase, true);
          freeBytes = Math.max(0, q.maxTotalBytes - q.totalBytes - q.imageBytes);
        } catch {
          freeBytes = null; // unknown - behave like before the preflight
        }
      }

      // One key copy for the whole retry pass. If signOut zeroes
      // this.encryptionKey before we can take this copy, bail entirely -
      // rows keep pendingUpload=1 for the next authenticated pass to retry.
      const passKey = this.keyCopy();
      if (!passKey) {
        console.warn('[attachmentStore] sign-out in progress - pending uploads deferred');
        return;
      }
      try {
        for (const record of pending) {
          try {
            // Already being uploaded by another in-flight call (e.g. the
            // initial upload from uploadAttachment) - skip the pointless
            // re-encrypt.
            if (this.uploading.has(record.uuid)) continue;

            const cached = await db.attachmentCache.get(record.uuid);
            if (!cached) {
              // Cache lost - remove orphan dedup record.
              await db.attachmentDedup.delete(record.hash);
              continue;
            }

            if (freeBytes !== null) {
              if (cached.data.length > freeBytes) {
                if (record.quotaBlocked !== 1) {
                  await db.attachmentDedup.put({ ...record, quotaBlocked: 1 });
                }
                continue;
              }
              if (record.quotaBlocked === 1) {
                await db.attachmentDedup.put({ ...record, quotaBlocked: 0 });
              }
              // Reserve the headroom for this attempt so one pass cannot
              // overshoot the cap with several large blobs.
              freeBytes -= cached.data.length;
            }

            const packed = packAttachment(cached.meta, cached.data);
            const encrypted = encryptBlob(packed, passKey);
            await this._backgroundUpload(record.uuid, cached.meta.name, encrypted);
          } catch (err) {
            console.warn('[attachmentStore] pending retry failed:', record.uuid, err);
          }
        }
      } finally {
        passKey.fill(0);
      }
    } finally {
      this.sweepRunning = false;
    }
  }

  /**
   * Get a decrypted attachment by UUID. Checks cache first.
   */
  async getAttachment(uuid: string): Promise<DecryptedAttachment | null> {
    // Check cache.
    const cached = await db.attachmentCache.get(uuid);
    if (cached) {
      return { meta: cached.meta, data: cached.data };
    }

    // Download from Supabase Storage, with one retry on auth errors.
    const path = `${this.pubkey}/${uuid}`;
    const result = await this._downloadWithRetry(path);
    if (!result) return null;

    const encrypted = new Uint8Array(await result.arrayBuffer());
    const decrypted = decryptBlob(encrypted, this.encryptionKey);
    const attachment = unpackAttachment(decrypted);

    // Cache for next time.
    await db.attachmentCache.put({
      id: uuid,
      meta: attachment.meta,
      data: attachment.data,
      cachedAt: new Date().toISOString(),
    });

    return attachment;
  }

  /**
   * Download a blob from Storage. If the error is "Bucket not found"
   * (Supabase returns this for private buckets when the JWT is expired
   * or invalid - it's an auth error, not a missing-file error), refresh
   * the session once and retry. Returns null only when the object
   * genuinely doesn't exist.
   */
  private async _downloadWithRetry(path: string): Promise<Blob | null> {
    const { data, error } = await this.supabase.storage
      .from(BUCKET)
      .download(path);

    if (!error) return data ?? null;

    // "Bucket not found" = auth/session issue, not a missing file.
    if (error.message?.includes('Bucket not found')) {
      const { error: refreshErr } = await this.supabase.auth.refreshSession();
      if (refreshErr) {
        throw new Error(`Attachment download failed (session refresh failed): ${refreshErr.message}`);
      }
      const retry = await this.supabase.storage.from(BUCKET).download(path);
      if (retry.error) {
        if (retry.error.message?.includes('not found') || retry.error.message?.includes('404')) {
          return null;
        }
        throw new Error(`Attachment download failed: ${retry.error.message}`);
      }
      return retry.data ?? null;
    }

    // Genuine "object not found".
    if (error.message?.includes('not found') || error.message?.includes('404')) {
      return null;
    }

    throw new Error(`Attachment download failed: ${error.message}`);
  }

  /** Delete an attachment from Storage and local cache. */
  async deleteAttachment(uuid: string): Promise<void> {
    const dedup = await db.attachmentDedup.where('uuid').equals(uuid).first();
    const size = dedup?.encryptedSize ?? 0;

    // Demo mode never uploaded the blob, so there is nothing remote to
    // remove and no quota to decrement - only the local cache is real.
    // Below the release floor the remote half pauses too (see sync.ts);
    // reconcileOrphanBlobs cleans up the leftover object after the update.
    const remote = !isDemoMode() && !isServerWriteBlocked();

    if (remote) {
      const path = `${this.pubkey}/${uuid}`;
      const { error } = await this.supabase.storage
        .from(BUCKET)
        .remove([path]);

      if (error) {
        console.warn(`Attachment delete failed for ${uuid}:`, error.message);
      }
    }

    await db.attachmentCache.delete(uuid);
    await db.attachmentDedup.where('uuid').equals(uuid).delete();

    if (!this.ownershipLost() && remote && size > 0) {
      this.supabase
        .rpc('adjust_blob_bytes', { delta: -size })
        .then(({ error: rpcErr }) => {
          if (rpcErr) console.warn('[attachmentStore] adjust_blob_bytes failed:', rpcErr.message);
        });
    }
  }

  /**
   * Defer deletion of multiple attachments: remove local cache + dedup
   * rows and decrement quota immediately, but leave the Supabase
   * Storage object in place. The uuid is enqueued in db.blobGC so
   * sweepBlobGC (imageGC.ts) can remove the remote object later, once
   * a clean sync pull has proven the local mirror is complete enough
   * to trust the reference re-check. See imageGC.ts for the full
   * two-phase design.
   */
  async deferDelete(uuids: string[]): Promise<void> {
    if (uuids.length === 0) return;

    // Demo mode never uploaded these blobs and makes zero server calls -
    // fall back to the immediate local-only delete, no queue entry.
    if (isDemoMode()) {
      await this.deleteAttachments(uuids);
      return;
    }

    let totalSize = 0;
    const now = new Date().toISOString();
    for (const uuid of uuids) {
      const dedup = await db.attachmentDedup.where('uuid').equals(uuid).first();
      const size = dedup?.encryptedSize ?? 0;
      totalSize += size;

      await db.attachmentCache.delete(uuid);
      await db.attachmentDedup.where('uuid').equals(uuid).delete();
      await db.blobGC.put({ uuid, kind: 'attachment', size, enqueuedAt: now });
    }

    // Below the release floor server writes pause (see sync.ts). The local
    // blobGC queue above survives, so the (also floor-gated) sweep deletes
    // the objects and settles quota once the user updates.
    if (isServerWriteBlocked()) return;

    // Server-side pending set (migration 0068) - same contract as
    // ImageStore.deferDelete; see the comment there.
    // Spec: packages/supabase/migrations/history/0068_pending_blob_gc_server_side.sql
    this.supabase
      .from('pending_blob_gc')
      .upsert(
        uuids.map((uuid) => ({ user_pubkey: this.pubkey, uuid })),
        { onConflict: 'user_pubkey,uuid', ignoreDuplicates: true }
      )
      .then(({ error: gcErr }) => {
        if (gcErr) console.warn('[attachmentStore] pending_blob_gc enqueue failed:', gcErr.message);
      });

    // Decrement image_bytes quota (best-effort) - the blob still counts
    // against Storage until the sweep removes it, but the user's quota
    // must reflect the delete now, matching deleteAttachments' UX.
    if (!this.ownershipLost() && totalSize > 0) {
      this.supabase
        .rpc('adjust_blob_bytes', { delta: -totalSize })
        .then(({ error: rpcErr }) => {
          if (rpcErr) console.warn('[attachmentStore] adjust_blob_bytes failed:', rpcErr.message);
        });
    }
  }

  /**
   * Remove Storage objects only - no local row deletion, no quota
   * adjustment (both already happened at deferDelete time). Used by
   * sweepBlobGC once a queued uuid has cleared the grace period and
   * the reference re-check.
   *
   * The Supabase JS client's storage.remove() reports one aggregate
   * error for the whole batch, not per-path, so on error we can't tell
   * which paths actually failed. Treat a "not found" style aggregate
   * error as success (the blobs are already gone, which is the desired
   * end state); treat any other error as every uuid failing, so the
   * sweep retries the whole batch next time.
   */
  async removeRemoteOnly(uuids: string[]): Promise<{ removed: string[]; failed: string[] }> {
    if (uuids.length === 0) return { removed: [], failed: [] };

    const paths = uuids.map((uuid) => `${this.pubkey}/${uuid}`);
    const { error } = await this.supabase.storage.from(BUCKET).remove(paths);

    if (!error) return { removed: uuids, failed: [] };

    if (error.message?.includes('not found') || error.message?.includes('404')) {
      return { removed: uuids, failed: [] };
    }

    console.warn('[attachmentStore] sweepBlobGC remote removal failed:', error.message);
    return { removed: [], failed: uuids };
  }

  /** Delete multiple attachments at once. */
  async deleteAttachments(uuids: string[]): Promise<void> {
    if (uuids.length === 0) return;

    let totalSize = 0;
    for (const uuid of uuids) {
      const dedup = await db.attachmentDedup.where('uuid').equals(uuid).first();
      if (dedup?.encryptedSize) totalSize += dedup.encryptedSize;
    }

    // Demo mode never uploaded these blobs - local cache only. Below the
    // release floor the remote half pauses too (see sync.ts).
    const remote = !isDemoMode() && !isServerWriteBlocked();

    if (remote) {
      const paths = uuids.map((uuid) => `${this.pubkey}/${uuid}`);
      const { error } = await this.supabase.storage
        .from(BUCKET)
        .remove(paths);

      if (error) {
        console.warn('Bulk attachment delete failed:', error.message);
      }
    }

    await db.attachmentCache.bulkDelete(uuids);
    for (const uuid of uuids) {
      await db.attachmentDedup.where('uuid').equals(uuid).delete();
    }

    if (!this.ownershipLost() && remote && totalSize > 0) {
      this.supabase
        .rpc('adjust_blob_bytes', { delta: -totalSize })
        .then(({ error: rpcErr }) => {
          if (rpcErr) console.warn('[attachmentStore] adjust_blob_bytes failed:', rpcErr.message);
        });
    }
  }
}
