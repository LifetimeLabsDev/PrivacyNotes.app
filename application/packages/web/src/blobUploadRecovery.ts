/**
 * Recovering an upload whose response was lost.
 *
 * A blob object is immutable by design. Its name carries a random uuid, and
 * the bucket's policies grant INSERT, SELECT and DELETE and no UPDATE, so
 * nothing can rewrite the bytes at a name once they are there. An upload sent
 * with `upsert: true` asks Storage for an UPDATE whenever the object already
 * exists, and that request is refused - the server log carries it as "new row
 * violates row-level security policy (USING expression) for table objects".
 *
 * The retry that triggers it is ordinary, not exotic. The upload commits, the
 * response is lost to a dead socket, or it arrives and the byte-accounting
 * call after it fails; either way the row keeps its pending flag, and the next
 * sweep uploads the same uuid again. Per-instance in-flight guards cannot help
 * here, because the retry comes after a reload or from a second tab. The
 * refusal is neither a size refusal nor a quota refusal, so treated as
 * transient it would keep the blob pending for good, retried on every boot and
 * every post-sync tick, re-sending the whole blob each time.
 *
 * So uploads are create-only, and a 409 is a signal rather than a failure: it
 * says a previous attempt of ours landed. Settling it needs two things, each
 * checked rather than assumed.
 *
 * First, the object has to be the intended one. Byte length does not establish
 * that: the retry re-encrypts the cached plaintext with a fresh nonce, so the
 * bytes it holds differ from the committed ones while the plaintext matches,
 * and two unrelated blobs can share a length. The proof is to download what is
 * there, decrypt it, and compare the plaintext.
 *
 * Second, the bytes have to be counted once. The first attempt may or may not
 * have reached the accounting call, and nothing on the client records which,
 * so re-posting the same delta is as likely to double-charge as to correct the
 * books. A server-side recount replaces the guess with the ground truth.
 * Spec: ops/docs/plans/supabase-performance-2026-09.md (batch 4)
 */
import type { Table } from 'dexie';

/** Byte-for-byte, in constant-ish time. Lengths differ far more often. */
export function sameBytes(a: Uint8Array, b: Uint8Array): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i] !== b[i]) return false;
  return true;
}

/**
 * True when Storage refused a create-only upload because the object is
 * already there. Matched on the 409 status first, because that is the part of
 * the contract that does not change with wording; the message forms are the
 * fallback for a client or gateway that drops the status.
 */
export function isAlreadyExists(error: { message?: string; statusCode?: string | number } | null): boolean {
  if (!error) return false;
  if (String(error.statusCode ?? '') === '409') return true;
  const msg = error.message ?? '';
  return /already exists|duplicate/i.test(msg);
}

/**
 * The removal of a just-uploaded object, against a second instance settling
 * the same uuid.
 *
 * The accounting call after an upload can be refused on quota or on size, and
 * the uploader then removes its object so no bytes sit in Storage uncounted.
 * Another instance (a second tab, or this one after a reload) can be retrying
 * the same uuid: it meets the 409, proves the object, recounts and clears the
 * pending flag. If the remove lands between its proof and its clear, the row
 * reads uploaded over an object that is gone, nothing retries it, and the
 * local cache is the only copy. A check of the flag before the remove does not
 * close that, because the settle writes after the check.
 *
 * So the remover claims the row in one IndexedDB transaction, while it still
 * reads pending, and leaves the claim in place. The settle clears the row in
 * one transaction, and not when a claim was made after its own attempt began
 * (less the time one remove request can take), because the object it proved
 * may be the one being removed. A claimed row stays pending, and the next pass
 * uploads again. A claim older than the attempt is history: that remove ran or
 * failed before this instance met the object.
 */
type PendingRow = { uuid: string; pendingUpload?: number; removingAt?: number };

/** How long one remove request can take between its claim and its landing. */
const REMOVAL_CLAIM_MS = 10 * 60 * 1000;

// eslint-disable-next-line @typescript-eslint/no-explicit-any
type PendingTable<T extends PendingRow> = Table<T, any, any>;

/** Claim the row for the removal of this instance's own upload, and answer
 *  whether the remove may go ahead. No when the row no longer reads pending,
 *  because somebody settled it. A remover suspended past half the window
 *  after its claim (a frozen tab) checks again before it removes, and gives
 *  up when its claim is gone, replaced or too old: a settle may already have
 *  taken the row, and an object left uncounted is the server recount's to
 *  correct, while an object removed under a settled row is lost. */
export async function claimRemoval<T extends PendingRow>(table: PendingTable<T>, uuid: string): Promise<boolean> {
  const claim = Date.now();
  const claimed = await table.db.transaction('rw', table, async () => {
    const row = await table.where('uuid').equals(uuid).first();
    if (row?.pendingUpload !== 1) return false;
    await table.where('uuid').equals(uuid).modify({ removingAt: claim } as Partial<T>);
    return true;
  });
  if (!claimed) return false;
  const row = await table.where('uuid').equals(uuid).first();
  return row?.pendingUpload === 1 && row.removingAt === claim && Date.now() - claim < REMOVAL_CLAIM_MS / 2;
}

/** Write the settle's clear for an attempt that began at `attemptAt`, unless
 *  a removal was claimed since. */
export function settleUnlessClaimed<T extends PendingRow>(
  table: PendingTable<T>,
  uuid: string,
  attemptAt: number,
  patch: Partial<T>,
): Promise<boolean> {
  return table.db.transaction('rw', table, async () => {
    const row = await table.where('uuid').equals(uuid).first();
    if (!row) return false;
    if (row.removingAt !== undefined && row.removingAt >= attemptAt - REMOVAL_CLAIM_MS) return false;
    const { removingAt: _claim, ...rest } = row;
    await table.put({ ...rest, ...patch } as T);
    return true;
  });
}

/** A field change that applies only while the row still reads pending: the
 *  refusal and quota branches after an upload must not mark a row another
 *  instance settled meanwhile. */
export async function markIfPending<T extends PendingRow>(table: PendingTable<T>, uuid: string, patch: Partial<T>): Promise<void> {
  await table.where('uuid').equals(uuid).and((r) => r.pendingUpload === 1).modify(patch);
}
