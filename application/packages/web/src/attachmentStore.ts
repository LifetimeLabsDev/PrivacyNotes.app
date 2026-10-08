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
import { fetchQuotaUsage, recalculateQuota } from './devices';
import { claimRemoval, isAlreadyExists, markIfPending, sameBytes, settleUnlessClaimed } from './blobUploadRecovery';
import { PENDING_GC_WAIT_MS, settleWithin } from './pendingGcWait';

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

/** Errors that will never succeed on retry - mark the row refused. */
function isPermanentError(msg: string): boolean {
  return (
    msg.includes('exceeded the maximum allowed size') ||
    msg.includes('Payload too large') ||
    msg.includes('413')
  );
}

/** pendingUpload value for a file the server refused for good: never
 *  retried or counted as waiting, and still the only copy. Same meaning
 *  as in imageStore.ts. */
const UPLOAD_REFUSED = 2;

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
   * UUIDs with an upload or a settle in flight in this instance. The
   * post-sync retry sweep can reach a uuid whose first background upload is
   * still running and whose dedup row still says pendingUpload === 1; both
   * would send the same create-only upload, and the second would answer 409
   * and settle an object whose first upload has not finished its own
   * bookkeeping. The in-flight call owns the row, so a second caller for the
   * same uuid returns.
   */
  private uploading = new Set<string>();
  /**
   * True while a processPendingUploads() sweep is running. The post-sync
   * retry hook fires on a timer, and a sweep can still be walking the pending
   * rows from the trigger before; a second sweep would only meet the guard
   * above row by row.
   */
  private sweepRunning = false;
  /** UUIDs whose object this instance already asked Storage about during a
   *  sweep, so a row that does not fit costs one probe per app start. */
  private probed = new Set<string>();

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
   * On permanent failure: marks the row UPLOAD_REFUSED and keeps the
   * local cache, now the only copy, so restored attachments remain
   * viewable offline.
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
        await db.attachmentDedup.update(cached.hash, { pendingUpload: 0, encryptedSize: encrypted.length });
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

      // A removal claimed after this moment can be of the object a 409
      // below proves, so the settle compares against it.
      const attemptAt = Date.now();
      const { error } = await this.supabase.storage
        .from(BUCKET)
        .upload(path, encrypted, {
          contentType: 'application/octet-stream',
          // Create-only, same as images: the bucket grants no UPDATE, so an
          // upsert over an earlier attempt is refused. blobUploadRecovery.ts.
          upsert: false,
        });

      if (error) {
        const msg = error.message || '';
        if (isAlreadyExists(error)) {
          await this._settleExistingObject(uuid, path, encrypted, attemptAt);
          return;
        }
        if (isPermanentError(msg)) {
          // Keep local cache so restored attachments remain viewable offline,
          // and mark the row refused so the doomed upload is never retried.
          const dedup = await db.attachmentDedup.where('uuid').equals(uuid).first();
          if (dedup) {
            await db.attachmentDedup.update(dedup.hash, { pendingUpload: UPLOAD_REFUSED });
          }
          this.onBackgroundError?.(filename, msg);
          console.error('[attachmentStore] permanent upload failure, kept local cache:', uuid, msg);
          throw new Error(msg);
        }
        if (isQuotaError(msg)) {
          // Retryable - pendingUpload stays 1, but still toast the user now.
          // quotaBlocked keeps the retry sweep off the wire while the blob
          // cannot fit (backlog #143).
          await markIfPending(db.attachmentDedup, uuid, { quotaBlocked: 1 });
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
          if (await claimRemoval(db.attachmentDedup, uuid)) {
            await this.supabase.storage.from(BUCKET).remove([path]).catch(() => {});
          }
          await markIfPending(db.attachmentDedup, uuid, { quotaBlocked: 1 });
          this.onBackgroundError?.(filename, msg);
          console.error('[attachmentStore] quota exceeded, will retry:', uuid);
          throw new Error(msg);
        }
        if (isPermanentError(msg)) {
          // Remove the remote blob we just uploaded; the local cache stays,
          // refused, as the only copy.
          if (await claimRemoval(db.attachmentDedup, uuid)) {
            await this.supabase.storage.from(BUCKET).remove([path]).catch(() => {});
          }
          await markIfPending(db.attachmentDedup, uuid, { pendingUpload: UPLOAD_REFUSED });
          this.onBackgroundError?.(filename, msg);
          console.error('[attachmentStore] permanent upload failure, kept local cache:', uuid, msg);
          throw new Error(msg);
        }
        // Transient failure: same contract as imageStore - the object is in
        // Storage but uncounted, so keep pendingUpload=1 for the retry sweep
        // instead of silently understating usage (backlog #131). That sweep
        // meets a 409 and settles the accounting with a server recount.
        console.warn('[attachmentStore] adjust_blob_bytes failed, will retry:', msg);
        throw new Error(msg);
      }

      // Clear pending flag and update encryptedSize (may have been 0 from
      // restoreBlobs - now we know the real size after encrypting).
      const dedup = await db.attachmentDedup.where('uuid').equals(uuid).first();
      if (dedup) {
        await db.attachmentDedup.update(dedup.hash, { pendingUpload: 0, quotaBlocked: 0, encryptedSize: encrypted.length });
      }
    } finally {
      this.uploading.delete(uuid);
    }
  }

  /**
   * An earlier attempt at this uuid already committed. Same contract as
   * ImageStore._settleExistingObject: prove the object holds our content,
   * settle the bytes with a server recount rather than re-posting a delta
   * that may already have been applied, and clear the pending flag only
   * after both. Anything short of a proven match keeps the row pending and
   * the local cache, and a plaintext mismatch stops the retries for good.
   */
  private async _settleExistingObject(uuid: string, path: string, encrypted: Uint8Array | null, attemptAt: number): Promise<void> {
    const cached = await db.attachmentCache.get(uuid);
    const remote = await this._downloadWithRetry(path);
    if (!remote) {
      console.warn('[attachmentStore] existing blob could not be read back:', uuid);
      return;
    }
    const remoteBytes = new Uint8Array(await remote.arrayBuffer());
    // A probe has no ciphertext of its own to compare, only the plaintext.
    let matches = encrypted !== null && sameBytes(remoteBytes, encrypted);
    if (!matches && cached) {
      // A fresh nonce per encryption means identical plaintext yields
      // different bytes, so the comparison has to be on what they mean. What
      // an object holds is the PACKED form, metadata header and bytes, which
      // is what the upload sends and not what the cache row stores. The key
      // is a COPY, like every other crypto call in this class: sign-out
      // zeroes the live one in place, and decrypting with zeros would refuse
      // a blob that is perfectly fine on the server.
      const passKey = this.keyCopy();
      if (!passKey) {
        console.warn('[attachmentStore] sign-out in progress - blob settle deferred:', uuid);
        return;
      }
      try {
        matches = sameBytes(
          decryptBlob(remoteBytes, passKey),
          packAttachment(cached.meta, cached.data),
        );
      } catch {
        matches = false;
      } finally {
        passKey.fill(0);
      }
    }
    if (!matches) {
      // The download and the decrypt were awaits: an account switch inside
      // them would mark the next account's row.
      if (this.ownershipLost()) return;
      const dedup = await db.attachmentDedup.where('uuid').equals(uuid).first();
      if (dedup) await db.attachmentDedup.update(dedup.hash, { pendingUpload: UPLOAD_REFUSED });
      console.error('[attachmentStore] blob name holds different content, kept local cache:', uuid);
      return;
    }
    if (!await recalculateQuota(this.supabase)) {
      console.warn('[attachmentStore] recovered blob not cleared - no server recount:', uuid);
      return;
    }
    // Two awaits have passed since the ownership check at the top of the
    // upload, and an account switch inside that window would write this
    // account's hash-to-uuid row into the next account's database.
    if (this.ownershipLost()) return;
    // A removal claimed meanwhile by the instance that uploaded the object
    // leaves the row pending, and the next pass uploads again.
    if (!await settleUnlessClaimed(db.attachmentDedup, uuid, attemptAt, { pendingUpload: 0, quotaBlocked: 0, encryptedSize: remoteBytes.length })) {
      console.warn('[attachmentStore] recovered blob not cleared - its uploader is removing it:', uuid);
    }
  }

  /**
   * Settle an object an earlier attempt stored, without uploading again.
   * True when the object is there, or when Storage did not answer, so the
   * caller leaves the row unmarked and the next sweep asks again; false only
   * when Storage says the object is not there.
   */
  private async _settleIfStored(uuid: string): Promise<boolean> {
    if (this.uploading.has(uuid)) return true;
    this.uploading.add(uuid);
    try {
      const path = `${this.pubkey}/${uuid}`;
      const attemptAt = Date.now();
      let stored: boolean;
      try {
        const { data } = await this.supabase.storage.from(BUCKET).exists(path);
        stored = data === true;
      } catch {
        return true;
      }
      this.probed.add(uuid);
      if (!stored) return false;
      if (this.ownershipLost()) return true;
      await this._settleExistingObject(uuid, path, null, attemptAt);
      return true;
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
                // Headroom is a question for a new upload. An earlier attempt
                // can have stored this object and lost only its answer, so
                // each row asks Storage once per store instance and settles
                // what is there. Once per instance rather than once ever, so
                // a wrong "not there" heals on the next start.
                if (!this.probed.has(record.uuid) && await this._settleIfStored(record.uuid)) continue;
                if (record.quotaBlocked !== 1) {
                  await markIfPending(db.attachmentDedup, record.uuid, { quotaBlocked: 1 });
                }
                continue;
              }
              if (record.quotaBlocked === 1) {
                await db.attachmentDedup.update(record.hash, { quotaBlocked: 0 });
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
   *
   * A file whose upload is still pending, or was refused for good, keeps
   * its bytes and dedup row and is queued at size 0, for the reasons
   * ImageStore.deferDelete gives.
   */
  async deferDelete(uuids: string[]): Promise<void> {
    if (uuids.length === 0) return;

    // The demo never uploads and never sweeps, so its cache holds the only
    // copy of every blob. Nothing is deleted: the demo database is
    // discarded with the tab session.
    if (isDemoMode()) return;

    let totalSize = 0;
    const now = new Date().toISOString();
    for (const uuid of uuids) {
      const dedup = await db.attachmentDedup.where('uuid').equals(uuid).first();
      if (dedup?.pendingUpload === 1 || dedup?.pendingUpload === UPLOAD_REFUSED) {
        await db.blobGC.put({ uuid, kind: 'attachment', size: 0, enqueuedAt: now });
        continue;
      }
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
    // ImageStore.deferDelete, awaited for the same reason; see the comment
    // there.
    // Spec: packages/supabase/migrations/history/0068_pending_blob_gc_server_side.sql
    await settleWithin(
      Promise.resolve(
        this.supabase
          .from('pending_blob_gc')
          .upsert(
            uuids.map((uuid) => ({ user_pubkey: this.pubkey, uuid })),
            { onConflict: 'user_pubkey,uuid', ignoreDuplicates: true }
          )
      ).then(({ error: gcErr }) => {
        if (gcErr) console.warn('[attachmentStore] pending_blob_gc enqueue failed:', gcErr.message);
      }),
      PENDING_GC_WAIT_MS,
    );

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
   * adjustment (deferDelete settled quota when it queued the uuid, and
   * sweepBlobGC drops any local rows it kept). Used by sweepBlobGC once
   * a queued uuid has cleared the grace period and the reference re-check.
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
