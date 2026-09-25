/**
 * Image store - upload, fetch, cache for encrypted image blobs.
 *
 * Local-first architecture:
 * - Upload: encrypt → cache in IndexedDB → return UUID instantly →
 *   background upload to Supabase Storage + quota adjustment.
 * - Fetch: check IndexedDB cache → fall back to Supabase download.
 * - On init: processPendingUploads() retries blobs that were cached
 *   locally but never made it to the server (app closed, network error).
 *
 * Blob naming: `<pubkey>/<uuid>` - RLS on the bucket restricts access
 * to rows where the path prefix matches the user's pubkey.
 */

import { encryptBlob, decryptBlob, type SupabaseClient } from '@notes/shared';
import { db } from './db';
import { isDemoMode } from './demo';
import { ownsLocalData } from './authStorage';
import { logAuthEvent } from './authDiag';
import { isServerWriteBlocked } from './syncPause';
import { uploadsHeldForWifi } from './wifiOnly';
import { fetchQuotaUsage } from './devices';

const BUCKET = 'encrypted-images';

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

/**
 * pendingUpload value for a blob the server refused for good. The retry
 * sweep and every pending count look for 1, so the row is never retried
 * or shown as waiting. The local cache still holds the only copy, and the
 * row's encryptedSize was never charged, so deferDelete keeps it the way
 * it keeps a pending blob.
 */
const UPLOAD_REFUSED = 2;

/** Quota failures are retryable (e.g. after the user frees space or upgrades). */
function isQuotaError(msg: string): boolean {
  return msg.includes('Quota exceeded');
}

/**
 * Encrypted blob sizes learned from a Storage listing, keyed by uuid.
 *
 * imageDedup carries the same number, but it is keyed by the SHA-256 of the
 * pre-encryption bytes, which only the device that uploaded the image holds.
 * A new phone, a fresh browser or a cleared cache has no row to update, so a
 * size read off Storage lives here instead. A blob is immutable, so a uuid
 * keeps its size for good and this never needs invalidating.
 *
 * The listing that fills this scans the whole bucket, so the cache is what
 * holds it to once per device rather than once per render.
 */
const IMAGE_SIZES_KEY = 'imageSizesByUuid';

export async function readImageSizes(): Promise<Record<string, number>> {
  const entry = await db.kv.get(IMAGE_SIZES_KEY);
  if (typeof entry?.value !== 'string') return {};
  try {
    const parsed: unknown = JSON.parse(entry.value);
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return {};
    return parsed as Record<string, number>;
  } catch {
    return {};
  }
}

export async function rememberImageSizes(sizes: Record<string, number>): Promise<void> {
  if (Object.keys(sizes).length === 0) return;
  const merged = { ...(await readImageSizes()), ...sizes };
  await db.kv.put({ key: IMAGE_SIZES_KEY, value: JSON.stringify(merged) });
}

/** Storage returns at most this many names per listing call. */
const LIST_PAGE = 1000;

/**
 * Look up blob sizes in Storage and remember what the listing resolves.
 *
 * The listing pages, because an account can hold more blobs than one call
 * returns and Storage answers with the first page only: a blob past that page
 * has no size any single call can reach. Paging stops the moment every wanted
 * uuid is accounted for, so a full scan is the worst case rather than the norm,
 * and one call already costs a scan of the whole bucket.
 *
 * `absent` names the uuids the listing walked past without finding, which is
 * what a note referencing a removed blob leaves behind. Nothing here remembers
 * them: the same blob can still arrive from another device, so how long to stop
 * asking belongs to the caller.
 */
export async function listImageSizes(
  supabase: SupabaseClient,
  pubkey: string,
  wanted: string[],
): Promise<{ sizes: Map<string, number>; absent: string[] }> {
  const sizes = new Map<string, number>();
  const outstanding = new Set(wanted);
  if (outstanding.size === 0) return { sizes, absent: [] };

  const learned: Record<string, number> = {};
  for (let offset = 0; outstanding.size > 0; offset += LIST_PAGE) {
    const { data, error } = await supabase.storage
      .from(BUCKET)
      .list(pubkey, { limit: LIST_PAGE, offset });
    // A failed page leaves the rest outstanding rather than absent: the
    // caller must not read a network error as "this blob is gone".
    if (error) return { sizes, absent: [] };
    const page = data ?? [];
    for (const obj of page) {
      const size = (obj.metadata as Record<string, unknown> | null)?.size;
      if (typeof size === 'number' && size > 0) {
        sizes.set(obj.name, size);
        learned[obj.name] = size;
      }
      outstanding.delete(obj.name);
    }
    if (page.length < LIST_PAGE) break;
  }
  await rememberImageSizes(learned);
  return { sizes, absent: [...outstanding] };
}

export class ImageStore {
  private supabase: SupabaseClient;
  private encryptionKey: Uint8Array;
  private pubkey: string;
  /** Called when a background upload fails permanently. UI should show a toast. */
  onBackgroundError?: (error: string) => void;
  /**
   * UUIDs with a _backgroundUpload currently in flight. The post-sync retry
   * hook can now call processPendingUploads() while a just-uploaded blob's
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
      logAuthEvent('imageStore:ownership-lost', { expectedPk: this.pubkey.slice(0, 8) });
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
   * Upload an image: encrypt → cache locally → return UUID instantly.
   * Supabase upload + quota adjustment runs in background.
   *
   * Deduplication: hashes the processed bytes with SHA-256. If the same
   * content was uploaded before, returns the existing UUID without
   * hitting the server again.
   */
  async uploadImage(data: Uint8Array): Promise<string> {
    // Content-hash dedup check.
    const hashHex = await hashBytes(data);
    const existing = await db.imageDedup.get(hashHex);
    if (existing) {
      return existing.uuid;
    }

    const uuid = crypto.randomUUID();
    // signOut can zero this.encryptionKey mid-upload. This is a
    // user-initiated path, not a background retry - throw rather than
    // silently encrypt with a dead key; callers already handle upload
    // errors.
    const passKey = this.keyCopy();
    if (!passKey) {
      throw new Error('Sign-out in progress');
    }
    const encrypted = encryptBlob(data, passKey);
    passKey.fill(0);

    // --- Local-first: cache + dedup record, return immediately ---
    await db.imageCache.put({ id: uuid, data, cachedAt: new Date().toISOString() });
    await db.imageDedup.put({
      hash: hashHex,
      uuid,
      encryptedSize: encrypted.length,
      pendingUpload: 1,
    });

    // --- Background: upload to Supabase + adjust quota ---
    this._backgroundUpload(uuid, encrypted).catch(() => {
      // Already handled inside _backgroundUpload.
    });

    return uuid;
  }

  /**
   * Upload encrypted blob to Supabase and adjust quota.
   * On permanent failure: marks the row UPLOAD_REFUSED and keeps the
   * local cache, now the only copy, so restored/pasted images remain
   * viewable offline.
   * On transient failure: keeps pendingUpload for retry on next init.
   */
  private async _backgroundUpload(uuid: string, encrypted: Uint8Array): Promise<void> {
    // Demo mode makes zero server calls - the blob lives only in the
    // throwaway local cache. Still do the bookkeeping the upload would
    // have done so the dedup row carries a real size for the Files view.
    if (isDemoMode()) {
      const cached = await db.imageDedup.where('uuid').equals(uuid).first();
      if (cached) {
        await db.imageDedup.put({ ...cached, pendingUpload: 0, encryptedSize: encrypted.length });
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
    // post-sync retry hook can now overlap with the initial upload from
    // uploadImage) - let the in-flight one own the pendingUpload bookkeeping
    // rather than racing it to the same Storage path.
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
          upsert: true,
        });

      if (error) {
        const msg = error.message || '';
        if (isPermanentError(msg)) {
          // Keep local cache so restored/pasted images remain viewable offline,
          // and mark the row refused so the doomed upload is never retried.
          const dedup = await db.imageDedup.where('uuid').equals(uuid).first();
          if (dedup) {
            await db.imageDedup.put({ ...dedup, pendingUpload: UPLOAD_REFUSED });
          }
          this.onBackgroundError?.(msg);
          console.error('[imageStore] permanent upload failure, kept local cache:', uuid, msg);
          return;
        }
        if (isQuotaError(msg)) {
          // Retryable - pendingUpload stays 1, but still toast the user now.
          // Mark the row so the retry sweep skips it while it cannot fit
          // and the status surfaces say "doesn't fit" (backlog #143).
          const dedupRec = await db.imageDedup.where('uuid').equals(uuid).first();
          if (dedupRec) await db.imageDedup.put({ ...dedupRec, quotaBlocked: 1 });
          this.onBackgroundError?.(msg);
        }
        console.warn('[imageStore] transient upload failure, will retry:', uuid, msg);
        throw new Error(msg);
      }

      if (this.ownershipLost()) return;
      const { error: rpcErr } = await this.supabase.rpc('adjust_blob_bytes', { delta: encrypted.length });
      if (rpcErr) {
        const msg = rpcErr.message || '';
        if (isQuotaError(msg)) {
          // Remove the remote blob we just uploaded (it must not sit in
          // Storage uncounted), but leave pendingUpload=1 so a later pass
          // retries the whole upload. quotaBlocked makes that later pass
          // wait for real headroom instead of re-uploading the full blob
          // just to land back here (backlog #143).
          await this.supabase.storage.from(BUCKET).remove([path]).catch(() => {});
          const dedupRec = await db.imageDedup.where('uuid').equals(uuid).first();
          if (dedupRec) await db.imageDedup.put({ ...dedupRec, quotaBlocked: 1 });
          this.onBackgroundError?.(msg);
          console.error('[imageStore] quota exceeded, will retry:', uuid);
          return;
        }
        if (isPermanentError(msg)) {
          // Remove the remote blob we just uploaded; the local cache stays,
          // refused, as the only copy.
          await this.supabase.storage.from(BUCKET).remove([path]).catch(() => {});
          const dedupRec = await db.imageDedup.where('uuid').equals(uuid).first();
          if (dedupRec) {
            await db.imageDedup.put({ ...dedupRec, pendingUpload: UPLOAD_REFUSED });
          }
          this.onBackgroundError?.(msg);
          console.error('[imageStore] permanent upload failure, kept local cache:', uuid, msg);
          return;
        }
        // Transient failure (network blip, 5xx, timeout): the object IS in
        // Storage but not yet counted. Keep pendingUpload=1 so the
        // post-sync retry re-runs the upload (upsert, idempotent) and
        // re-posts the delta - clearing it here would understate usage
        // until the next recalc, permanently if none ran (backlog #131). A
        // response lost after the server committed double-charges briefly;
        // recalculate_my_quota recomputes from Storage ground truth.
        console.warn('[imageStore] adjust_blob_bytes failed, will retry:', msg);
        return;
      }

      // Clear pending flag and update encryptedSize (may have been 0 from
      // restoreBlobs - now we know the real size after encrypting).
      const dedup = await db.imageDedup.where('uuid').equals(uuid).first();
      if (dedup) {
        await db.imageDedup.put({ ...dedup, pendingUpload: 0, quotaBlocked: 0, encryptedSize: encrypted.length });
      }
    } finally {
      this.uploading.delete(uuid);
    }
  }

  /**
   * Retry uploads that were cached locally but never made it to the server.
   * Called once on store init. Re-encrypts from cached data.
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
      const pending = await db.imageDedup
        .filter((r) => r.pendingUpload === 1)
        .toArray();

      // Quota preflight: a blob bigger than the free headroom can only be
      // re-uploaded, fail the accounting RPC and be deleted server-side -
      // a 45 MB blob was re-uploaded every boot and every retry tick that
      // way (backlog #143). One quota read gates the whole pass; rows that
      // cannot fit are marked quotaBlocked and cost zero wire traffic.
      // isPro=true only shapes the fallback ceiling when every quota RPC
      // fails - it must never underestimate a Pro cap into false blocks.
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
        console.warn('[imageStore] sign-out in progress - pending uploads deferred');
        return;
      }
      try {
        for (const record of pending) {
          try {
            // Already being uploaded by another in-flight call (e.g. the
            // initial upload from uploadImage) - skip the pointless re-encrypt.
            if (this.uploading.has(record.uuid)) continue;

            const cached = await db.imageCache.get(record.uuid);
            if (!cached) {
              // Cache lost - remove orphan dedup record.
              await db.imageDedup.delete(record.hash);
              continue;
            }

            if (freeBytes !== null) {
              if (cached.data.length > freeBytes) {
                if (record.quotaBlocked !== 1) {
                  await db.imageDedup.put({ ...record, quotaBlocked: 1 });
                }
                continue;
              }
              if (record.quotaBlocked === 1) {
                await db.imageDedup.put({ ...record, quotaBlocked: 0 });
              }
              // Reserve the headroom for this attempt so one pass cannot
              // overshoot the cap with several large blobs.
              freeBytes -= cached.data.length;
            }

            const encrypted = encryptBlob(cached.data, passKey);
            await this._backgroundUpload(record.uuid, encrypted);
          } catch (err) {
            console.warn('[imageStore] pending retry failed:', record.uuid, err);
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
   * Get a decrypted image by UUID. Checks IndexedDB cache first,
   * then falls back to downloading + decrypting from Supabase Storage.
   * Returns null if the image doesn't exist.
   */
  async getImage(uuid: string): Promise<Uint8Array | null> {
    // Check cache first.
    const cached = await db.imageCache.get(uuid);
    if (cached) return cached.data;

    // Download from Supabase Storage, with one retry on auth errors.
    const path = `${this.pubkey}/${uuid}`;
    const result = await this._downloadWithRetry(path);
    if (!result) return null;

    const encrypted = new Uint8Array(await result.arrayBuffer());
    const decrypted = decryptBlob(encrypted, this.encryptionKey);

    // Cache for next time.
    await db.imageCache.put({ id: uuid, data: decrypted, cachedAt: new Date().toISOString() });

    return decrypted;
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
        throw new Error(`Image download failed (session refresh failed): ${refreshErr.message}`);
      }
      const retry = await this.supabase.storage.from(BUCKET).download(path);
      if (retry.error) {
        if (retry.error.message?.includes('not found') || retry.error.message?.includes('404')) {
          return null;
        }
        throw new Error(`Image download failed: ${retry.error.message}`);
      }
      return retry.data ?? null;
    }

    // Genuine "object not found".
    if (error.message?.includes('not found') || error.message?.includes('404')) {
      return null;
    }

    throw new Error(`Image download failed: ${error.message}`);
  }

  /**
   * Delete an image from Supabase Storage and local cache.
   */
  async deleteImage(uuid: string): Promise<void> {
    // Look up encrypted size before deleting dedup record.
    const dedup = await db.imageDedup.where('uuid').equals(uuid).first();
    const size = dedup?.encryptedSize ?? 0;

    // Demo mode never uploaded the blob, so there is nothing remote to
    // remove and no quota to decrement - only the local cache is real.
    // Below the release floor the remote half pauses too (see sync.ts);
    // reconcileOrphanBlobs cleans up the leftover object after the update.
    const remote = !isDemoMode() && !isServerWriteBlocked();

    const path = `${this.pubkey}/${uuid}`;
    if (remote) {
      const { error } = await this.supabase.storage
        .from(BUCKET)
        .remove([path]);

      if (error) {
        // Log but don't throw - image may already be gone.
        console.warn(`Image delete failed for ${uuid}:`, error.message);
      }
    }

    // Remove from local cache + dedup index.
    await db.imageCache.delete(uuid);
    await db.imageDedup.where('uuid').equals(uuid).delete();

    // Decrement image_bytes quota (best-effort).
    if (!this.ownershipLost() && remote && size > 0) {
      this.supabase.rpc('adjust_blob_bytes', { delta: -size })
        .then(({ error: rpcErr }) => {
          if (rpcErr) console.warn('[imageStore] adjust_blob_bytes failed:', rpcErr.message);
        });
    }
  }

  /**
   * Defer deletion of multiple images: remove local cache + dedup rows
   * and decrement quota immediately, but leave the Supabase Storage
   * object in place. The uuid is enqueued in db.blobGC so sweepBlobGC
   * (imageGC.ts) can remove the remote object later, once a clean sync
   * pull has proven the local mirror is complete enough to trust the
   * reference re-check. See imageGC.ts for the full two-phase design.
   *
   * A blob whose upload is still pending, or was refused for good,
   * exists nowhere but this cache, and a cut and paste or an undo brings
   * its reference back a moment later, so its bytes and dedup row stay:
   * processPendingUploads needs both. It is queued at size 0, since no
   * upload was ever charged for it, and the sweep drops its local rows
   * once the re-check finds it unreferenced.
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
      const dedup = await db.imageDedup.where('uuid').equals(uuid).first();
      if (dedup?.pendingUpload === 1 || dedup?.pendingUpload === UPLOAD_REFUSED) {
        await db.blobGC.put({ uuid, kind: 'image', size: 0, enqueuedAt: now });
        continue;
      }
      const size = dedup?.encryptedSize ?? 0;
      totalSize += size;

      await db.imageCache.delete(uuid);
      await db.imageDedup.where('uuid').equals(uuid).delete();
      await db.blobGC.put({ uuid, kind: 'image', size, enqueuedAt: now });
    }

    // Below the release floor server writes pause (see sync.ts). The local
    // blobGC queue above survives, so the (also floor-gated) sweep deletes
    // the objects and settles quota once the user updates.
    if (isServerWriteBlocked()) return;

    // Server-side pending set (migration 0068): the recalc exclusion must
    // not depend on which device asks - db.blobGC is device-local, and a
    // peer recalculating re-inflated the quota row (backlog #131, seen in
    // the wild 2026-08-05). Best-effort here: the local queue still drives
    // the sweep, which re-asserts these rows on every pass, so a lost
    // enqueue converges at the next clean pull.
    // Spec: packages/supabase/migrations/history/0068_pending_blob_gc_server_side.sql
    void this.ensurePendingGC(uuids);

    // Decrement image_bytes quota (best-effort) - the blob still counts
    // against Storage until the sweep removes it, but the user's quota
    // must reflect the delete now, matching deleteImages' UX.
    if (!this.ownershipLost() && totalSize > 0) {
      this.supabase.rpc('adjust_blob_bytes', { delta: -totalSize })
        .then(({ error: rpcErr }) => {
          if (rpcErr) console.warn('[imageStore] adjust_blob_bytes failed:', rpcErr.message);
        });
    }
  }

  /**
   * Idempotently (re-)assert server-side pending rows for queued
   * deletions. deferDelete fires it best-effort at delete time; the sweep
   * re-asserts the whole surviving queue on every pass, so an enqueue
   * lost to a network blip converges at the next clean pull instead of
   * waiting out the orphan reconcile. The table is per-account, so one
   * store's client covers image and attachment entries alike.
   * Spec: packages/supabase/migrations/history/0068_pending_blob_gc_server_side.sql
   */
  async ensurePendingGC(uuids: string[]): Promise<void> {
    if (uuids.length === 0) return;
    const { error } = await this.supabase
      .from('pending_blob_gc')
      .upsert(
        uuids.map((uuid) => ({ user_pubkey: this.pubkey, uuid })),
        { onConflict: 'user_pubkey,uuid', ignoreDuplicates: true }
      );
    if (error) console.warn('[imageStore] pending_blob_gc enqueue failed:', error.message);
  }

  /**
   * Best-effort removal of server-side pending-GC rows once their objects
   * are actually gone (or the deletion was cancelled). A row left behind
   * only stops excluding after the 7-day expiry, so failures here cost
   * accuracy for a bounded window, never correctness.
   */
  async clearPendingGC(uuids: string[]): Promise<void> {
    if (uuids.length === 0) return;
    const { error } = await this.supabase
      .from('pending_blob_gc')
      .delete()
      .eq('user_pubkey', this.pubkey)
      .in('uuid', uuids);
    if (error) console.warn('[imageStore] pending_blob_gc clear failed:', error.message);
  }

  /**
   * Best-effort quota delta adjustment, exposed for sweepBlobGC
   * (imageGC.ts) to re-credit quota for a deferred-delete entry that
   * turned out to still be referenced. Same sign convention as the RPC
   * itself: positive increases usage, negative decreases it.
   */
  async adjustQuota(delta: number): Promise<void> {
    if (delta === 0) return;
    if (this.ownershipLost()) return;
    const { error } = await this.supabase.rpc('adjust_blob_bytes', { delta });
    if (error) console.warn('[imageStore] adjust_blob_bytes failed:', error.message);
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

    console.warn('[imageStore] sweepBlobGC remote removal failed:', error.message);
    return { removed: [], failed: uuids };
  }

  /**
   * Delete multiple images at once, Storage object included. The GC never
   * calls this: every removal waits in deferDelete's queue for the sweep.
   */
  async deleteImages(uuids: string[]): Promise<void> {
    if (uuids.length === 0) return;

    // Sum encrypted sizes before deleting dedup records.
    let totalSize = 0;
    for (const uuid of uuids) {
      const dedup = await db.imageDedup.where('uuid').equals(uuid).first();
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
        console.warn('Bulk image delete failed:', error.message);
      }
    }

    // Remove from local cache + dedup index.
    await db.imageCache.bulkDelete(uuids);
    for (const uuid of uuids) {
      await db.imageDedup.where('uuid').equals(uuid).delete();
    }

    // Decrement image_bytes quota (best-effort).
    if (!this.ownershipLost() && remote && totalSize > 0) {
      this.supabase.rpc('adjust_blob_bytes', { delta: -totalSize })
        .then(({ error: rpcErr }) => {
          if (rpcErr) console.warn('[imageStore] adjust_blob_bytes failed:', rpcErr.message);
        });
    }
  }
}
