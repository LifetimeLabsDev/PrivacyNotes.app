import {
  encryptNote,
  decryptNote,
  bytesToBase64,
  base64ToBytes,
  type SupabaseClient,
} from '@notes/shared';
import { logAuthEvent } from './authDiag';
import { ownsLocalData } from './authStorage';
import { db, type LocalNote } from './db';
import { heartbeat } from './devices';
import { isDemoMode } from './demo';
import { isServerWriteBlocked } from './syncPause';
import { mergeTrackers } from './trackerTypes';

/* ── Conflict types ─────────────────────────────────────────────── */

/** A note conflict that couldn't be auto-merged (both sides changed body). */
export interface NoteConflict {
  noteId: string;
  localNote: LocalNote;
  /** Decrypted server version (newer updated_at). */
  serverTitle: string;
  serverBody: string;
  serverTags: string[];
  serverTrackers?: Record<string, unknown>;
  serverStarred: boolean;
  serverTrashed: boolean;
  serverLocked: boolean;
  serverPinProtected: boolean;
  serverType: import('@notes/shared').NoteType;
  serverFolderId: string | null;
  serverUpdatedAt: string;
  /** The encrypted row from the server (for re-push after resolution). */
  serverRow: { ciphertext: string; nonce: string; updated_at: string };
}

const LAST_SYNC_KEY = 'privacynotes.lastSync';

/**
 * Set once per device after the one-time full pull that recovers notes
 * stranded behind the cursor by a backdated import. Presence means the
 * heal already ran; absence on an existing install means it has not.
 * Never cleared. Do not reuse this key for a future forced resync - add
 * a new one, or devices that already healed will skip it.
 * Spec: packages/supabase/migrations/history/0063_note_ingested_at.sql
 */
const INGESTED_HEAL_KEY = 'privacynotes.ingestedHeal';
/** One-time full re-pull after migration 0065. See the heal block below. */
const KEYSET_HEAL_KEY = 'privacynotes.keysetHeal';

/** Cursor at the very beginning of time, before any row exists. */
const EPOCH_CURSOR = '1970-01-01T00:00:00Z';

/**
 * The cursor is stored as `<changed_at>|<id>` so the sweep can resume
 * mid-tie. Values written before migration 0065 are a bare timestamp:
 * read those as "start of that instant, no id", which re-reads that one
 * instant and is harmless (re-applying a row is idempotent), where
 * guessing an id could skip one.
 */
function parseCursor(raw: string): [string, string | null] {
  const bar = raw.indexOf('|');
  if (bar === -1) return [raw, null];
  return [raw.slice(0, bar), raw.slice(bar + 1)];
}

function formatCursor(at: string, id: string | null): string {
  return id === null ? at : `${at}|${id}`;
}

/** Shallow string-array equality check for tag comparison. */
function arraysEqual(a: string[], b: string[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) {
    if (a[i] !== b[i]) return false;
  }
  return true;
}

/** Mutex - prevents overlapping sync calls from racing on dirty-flag clears. */
let syncInFlight = false;

/** Bumped by suspendSync(). A pass captures the value at start and
 * refuses to persist its cursor or consume heal flags if it changed:
 * a pass that outlives sign-out used to re-create
 * `privacynotes.lastSync` AFTER the wipe removed it, leaving the
 * locally wiped rows behind the resurrected cursor - invisible forever
 * on the next same-user sign-in. */
let syncGeneration = 0;
/** While set, sync() refuses to start new passes. */
let syncSuspended = false;

/** Called by auth when the sign-out wipe begins (after its own rescue
 * flush). The in-flight pass, if any, finishes its writes but loses
 * the right to persist cursor/heal state; new passes no-op until
 * resumeSync(). Also called on the stale-tab bailout, where a pass
 * from the OLD account must not persist its cursor into storage that
 * now belongs to a different account. */
export function suspendSync(): void {
  syncGeneration++;
  syncSuspended = true;
}

/** Re-enables sync. Called at the end of sign-out and at the start of
 * authentication, so a failed sign-out can never leave sync dead. */
export function resumeSync(): void {
  syncSuspended = false;
  claimGateBrokenSince = 0;
}

/** How long the session claim may stay broken before it escalates to
 * SessionExpiredError. Measured in wall-clock time, never in passes:
 * `runSync()` is event-driven (mount, visibilitychange, online, and
 * ~25 user-action call sites) on top of the 30 s poll, and a
 * claim-mismatch pass returns after a single local storage read. A
 * strike budget was therefore spendable in milliseconds - alt-tabbing
 * twice during boot burned all three and popped the re-auth modal long
 * before a re-mint that legitimately takes seconds could finish.
 * Sized to match AUTH_TIMEOUT_MS in auth.tsx, the point at which the
 * blocking sign-in path gives up on the network. */
const CLAIM_GATE_GRACE_MS = 15_000;
/** When the current run of claim mismatches began; 0 when the claim is
 * healthy. Reset by a passing gate and by resumeSync(). */
let claimGateBrokenSince = 0;
/** One breadcrumb per broken episode, not one per failing pass - the
 * poll would otherwise flood the ring buffer while the modal is up. */
let claimGateExpiredLogged = false;

/** Set to true when account deletion starts. Subsequent `sync()` calls
 * become no-ops so an in-flight client can't repopulate notes seconds
 * after the server-side delete completes. Reset is implicit: the page
 * reloads at the end of deletion. See gap #3. */
let deletingAccount = false;

/** Flip the deletion flag. DangerZone calls this with `true` immediately
 * before invoking delete-account. */
export function setDeletingAccount(value: boolean): void {
  deletingAccount = value;
}

/** Phase 1: fetch the first page of the sweep and render immediately
 * so the user has something to work with within ~1-2 s of login. */
const PHASE1_SIZE = 100;

/** Phase 2: pull the rest in chunks of this size (keep it at or below
 * 1000, the PostgREST max rows per request).
 * No intermediate renders - the UI updates once when phase 2 finishes. */
const PHASE2_CHUNK = 500;

/** Error thrown when the server reports our device was revoked. The caller
 * (NotesView sync loop) catches this and invokes `forceSignOut`. */
export class DeviceRevokedError extends Error {
  constructor() {
    super('device_revoked');
    this.name = 'DeviceRevokedError';
  }
}

/** Error thrown when a push fails due to storage quota being exceeded.
 * The caller should show a user-facing notification. */
export class QuotaExceededError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'QuotaExceededError';
  }
}

/** Error thrown when the Supabase session is expired or invalid.
 * The caller should show a re-auth prompt. */
export class SessionExpiredError extends Error {
  constructor() {
    super('session_expired');
    this.name = 'SessionExpiredError';
  }
}

/**
 * The server refused the sign-in for want of a CAPTCHA token.
 *
 * Extends SessionExpiredError on purpose: every existing `instanceof
 * SessionExpiredError` caller already does the right thing with it
 * (surface the re-auth path rather than treat it as offline), and the
 * sign-in screen narrows to this subtype when it needs to know that a
 * token specifically is what is missing.
 *
 * Every sign-in path attempts a tokenless handshake first and mounts
 * the Turnstile widget only when the server says a token is required
 * (the web-only gate in the link-pubkey edge function - natives are
 * never asked). That way the server's TURNSTILE_WEB_ENFORCE secret is
 * the single source of truth - flipping enforcement on does not
 * require a release.
 * Spec: ops/docs/design-decisions.md (Turnstile is web-only, enforced at link-pubkey)
 */
export class CaptchaRequiredError extends SessionExpiredError {
  constructor() {
    super();
    this.name = 'CaptchaRequiredError';
  }
}

/**
 * The server refused a session re-mint for want of QUOTA, not for want
 * of credentials: HTTP 429 / `over_request_rate_limit`.
 *
 * Deliberately NOT a SessionExpiredError subclass, unlike
 * CaptchaRequiredError above. Every `instanceof SessionExpiredError`
 * site routes to the re-auth prompt, and re-auth is the one thing that
 * cannot help here: signing out wipes the local session and the
 * sign-in that follows burns another anonymous sign-in against the
 * same cap. This is a third category - not "offline" (no verdict, stay
 * quiet), not "needs re-auth" (only the user can fix it), but "not
 * now" (nobody needs to do anything; it comes good on its own).
 *
 * Carries the server's own wording as its message because the
 * interactive sign-in path surfaces `err.message` verbatim.
 *
 * Anonymous sign-ins are capped per IP per hour and every re-mint
 * creates a brand new anonymous user, so a machine running several
 * browser profiles, or reloading through a session that has already
 * gone bad, exhausts the cap quickly.
 * Spec: ops/docs/design-decisions.md (rate-limited re-mint)
 */
export class RateLimitedError extends Error {
  constructor(message: string) {
    super(message);
    this.name = 'RateLimitedError';
  }
}

/**
 * True when a sign-in refusal is a quota refusal rather than a
 * credential problem. Kept as a pure predicate (and unit-tested) so
 * the classification cannot drift: it is the single thing standing
 * between "back off and retry" and a re-auth prompt that makes the
 * problem worse.
 *
 * Matches on three signals because GoTrue has reworded this before:
 * the HTTP status, the stable error code, and the message as a last
 * resort.
 */
export function isRateLimitError(
  err: { status?: number; code?: string; message?: string } | null | undefined,
): boolean {
  if (!err) return false;
  return (
    err.status === 429 ||
    err.code === 'over_request_rate_limit' ||
    /rate limit/i.test(err.message ?? '')
  );
}

/** Set while a session re-mint is known to be refused on quota. See
 * RateLimitedError and the claim gate in syncInner. */
let remintBlockedUntil = 0;

/** Called by auth when a re-mint is refused on quota (`ms` > 0, the
 * length of the planned backoff) and again when one finally lands
 * (`ms` === 0). Keeps the claim gate from escalating a session that is
 * unminted rather than expired. */
export function setRemintBlocked(ms: number): void {
  remintBlockedUntil = ms > 0 ? Date.now() + ms : 0;
}

/** Check if a Supabase error indicates an expired/invalid JWT. */
function isAuthError(err: { code?: string; message?: string } | null): boolean {
  if (!err) return false;
  const msg = (err.message ?? '').toLowerCase();
  const code = err.code ?? '';
  return (
    code === '401' ||
    code === 'PGRST301' ||
    msg.includes('jwt expired') ||
    msg.includes('invalid jwt') ||
    msg.includes('jwt claim') ||
    msg.includes('token is expired') ||
    msg.includes('not authorized') ||
    msg.includes('invalid claim')
  );
}

/** A genuine account-level storage rejection. The quota triggers RAISE
 * with "Quota exceeded: ..."; the 90-day freeze RAISEs "Sync frozen: ...".
 * Both carry SQLSTATE 23514, so match on the message - this is what
 * drives the account-level "Storage full" banner. */
/** A row-level-security refusal is an identity verdict, not a transient
 *  fault: the server is saying this session may not write these rows at
 *  all, so retrying the same rows - or walking the rest of the queue
 *  into the same wall, one console error per note - helps nobody. The
 *  live incident produced a thousand-error storm this way. Treated like
 *  an ownership loss: end the push quietly, rows stay dirty. */
function isRlsError(err: { code?: string; message?: string } | null): boolean {
  if (!err) return false;
  return err.code === '42501' || (err.message ?? '').includes('row-level security');
}

function isQuotaError(err: { message?: string } | null): boolean {
  const msg = err?.message ?? '';
  return msg.includes('Quota exceeded') || msg.includes('Sync frozen');
}

/** A single note that breached the per-row size CHECK constraint
 * (notes_ciphertext_max_1mb). Shares SQLSTATE 23514 with the quota
 * triggers but is NOT an account-storage problem - this one note is too
 * big. Must route to the per-note retry banner, never the global
 * "Storage full" banner. */
function isNoteTooLargeError(err: { code?: string; message?: string } | null): boolean {
  return err?.code === '23514' && !!err.message?.includes('notes_ciphertext_max_1mb');
}

/** The server's per-row ceiling: `octet_length(ciphertext) <= 1048576`.
 * The column holds base64, which is ASCII, so a JavaScript string length
 * counts the same bytes the CHECK does. Measuring the row here keeps a
 * note the server can only refuse off the wire entirely.
 * Spec: packages/supabase/migrations/history/0009_abuse_limits.sql */
const CIPHERTEXT_MAX_BYTES = 1_048_576;

/** Surfaced via onPushError when a note exceeds the 1 MB per-note size
 * limit. pushFailures.ts matches this exact string to mark the note
 * "not backed up" in the pill, the ID & Sync list and the editor. */
export const NOTE_TOO_LARGE_MSG = 'a note is over the 1 MB size limit';

type RemoteRow = {
  id: string;
  user_pubkey: string;
  ciphertext: string;
  nonce: string;
  created_at: string;
  updated_at: string;
  /** Tombstone timestamp. NULL = live row. Set by client on permanent delete. */
  deleted_at: string | null;
  /**
   * Server-assigned arrival time (DEFAULT now(), never sent by the client).
   * Distinct from updated_at, which is client-authoritative and can be
   * backdated by importers preserving the source app's dates.
   * Spec: packages/supabase/migrations/history/0063_note_ingested_at.sql
   */
  ingested_at: string;
  /**
   * Server-assigned change clock: set to now() by trigger on every
   * INSERT and UPDATE, never influenced by the client. The single key
   * the pull filters, sorts and keyset-pages on. Being pure server time
   * is what makes the ascending sweep safe: no client clock (skewed, or
   * an edit-time updated_at pushed hours later) can land a change
   * behind a cursor that already passed it.
   * Spec: packages/supabase/migrations/history/0066_notes_changed_at_server_assigned.sql
   */
  changed_at: string;
};

/**
 * Pull-then-push sync, last-write-wins by updated_at.
 *
 * 1. Pull remote rows where `changed_at > cursor`, sweeping ascending
 *    and keyset-paging on `(changed_at, id)` (migration 0065). Rows
 *    with `deleted_at` set are tombstones - we bulkDelete them locally
 *    instead of upserting. For non-tombstones, if remote is newer than
 *    the local copy (or local doesn't exist), overwrite local.
 * 2. Push all rows flagged dirty. Hard-deletes (`deleted=1` locally)
 *    become server-side `update({deleted_at: now()})` so other devices
 *    see the tombstone on their next pull. Everything else is upserted.
 *
 * The `trashed` and `starred` flags live inside the encrypted payload, so
 * they roundtrip the server without leaking any metadata.
 *
 * As of v0.126.0 (Tier 2): pushes use a conditional update with an
 * `lte('updated_at')` guard. If the server has a newer version, we
 * detect the conflict and either auto-merge (metadata-only changes)
 * or surface a ConflictModal for body-vs-body edits. No data is
 * silently lost. Real CRDT merge still deferred.
 *
 * If an offline device pushes an edit for a row that was tombstoned
 * elsewhere, the server-side BEFORE UPDATE trigger (migration 0034)
 * silently drops the write - the row stays deleted, the offline edit
 * is discarded, and the next pull tells the device the note is gone.
 */
export async function sync(
  supabase: SupabaseClient,
  pubkey: string,
  encryptionKey: Uint8Array,
  deviceId: string,
  /** Called after each pull batch is written to IndexedDB. The caller
   * typically triggers a UI refresh here so notes appear progressively. */
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onBatch?: () => any,
  /** Called once per note that failed to push for non-quota / non-auth
   * reasons. The note stays dirty=1 and retries next sync, but the
   * caller should surface a banner so silent stuck rows aren't invisible.
   * See gap #4. */
  onPushError?: (noteId: string, message: string) => void,
  /** Called when a body-vs-body conflict can't be auto-merged. The
   * caller should queue the conflict and show a resolution UI. */
  onConflict?: (conflict: NoteConflict) => void,
  /** flushOnly: push dirty rows and nothing else - no heartbeat, no
   * pull, no cursor advance. Used by sign-out to rescue unsynced notes
   * before the local wipe. Skipping the heartbeat is the point: a
   * revoked device fails the heartbeat gate (DeviceRevokedError) before
   * the push phase ever runs, but its JWT still authorizes note writes
   * (notes RLS keys off the pubkey claim only, not device registration),
   * so its unsynced rows can still be saved. */
  opts?: { flushOnly?: boolean },
): Promise<SyncResult> {
  // Demo mode never touches the server. No session, no pushes, no pulls.
  if (isDemoMode()) return { ran: false, pullOk: false, changed: false };
  // Below the release floor, or paused by the user, sync STOPS: the floor is
  // only raised for a sync/auth protocol change, a security fix, or a
  // data-corruption fix, and the pause is the user's explicit "this device
  // talks to no one" (syncPause.ts). The app stays fully usable locally; rows
  // stay dirty and push once the block lifts. Deliberately unconditional -
  // the sign-out rescue flush (flushOnly) is blocked too, because a bulk push
  // of old-protocol rows at sign-out is the worst-case write, and the
  // sign-out confirm already warns with the unsynced count. Heartbeat is NOT
  // gated (it is the revocation channel). Spec: ops/docs/android-update-check.md
  // (also the planned channel for a future server-side floor check)
  if (isServerWriteBlocked()) return { ran: false, pullOk: false, changed: false };
  // If account deletion is in flight, do nothing - we don't want to
  // upsert dirty rows that would land after the server-side wipe.
  if (deletingAccount) return { ran: false, pullOk: false, changed: false };
  // Sign-out wipe in progress - see suspendSync().
  if (syncSuspended) return { ran: false, pullOk: false, changed: false };
  // Mutex guard - if a sync is already running, skip silently.
  if (syncInFlight) return { ran: false, pullOk: false, changed: false };
  syncInFlight = true;
  // Private copy of the key for this pass: signOut zeroes the caller's
  // Uint8Array in place once its flush budget expires, and a pass still
  // in flight at that moment used to encrypt the remaining dirty notes
  // with the zeroed buffer - pushing permanently undecryptable
  // ciphertext over good server rows, then clearing the dirty flags.
  const passKey = new Uint8Array(encryptionKey);
  try {
    const inner = await syncInner(supabase, pubkey, passKey, deviceId, onBatch, onPushError, onConflict, opts);
    return { ran: true, pullOk: inner.pullOk, changed: inner.changed, pushed: inner.pushed ?? 0, pulled: inner.pulled ?? 0 };
  } finally {
    passKey.fill(0);
    syncInFlight = false;
  }
}

/**
 * What a `sync()` call actually did. Callers that make decisions based
 * on post-sync local state (e.g. the welcome-note seed gate) MUST check
 * `ran` and `pullOk`: a mutex-skipped or failed-pull pass leaves
 * IndexedDB unrepresentative of the server, and acting on it produced
 * a false "fresh vault" verdict while a concurrent first pull was still
 * in flight.
 */
export type SyncResult = {
  /** False when the call was a no-op (demo mode, below the release floor,
   *  deletion in flight, or another sync already running). */
  ran: boolean;
  /** True when the pull phase completed without errors. Only meaningful
   *  when `ran` is true. */
  pullOk: boolean;
  /** Dirty rows the push phase attempted this pass (0 when skipped). */
  pushed?: number;
  /** Rows plus tombstones the pull phase applied locally this pass. */
  pulled?: number;
  /** True when the pass moved data in either direction (rows pulled or
   *  applied, or dirty rows pushed). A clean no-op poll tick reports
   *  false so callers can skip vault-sized post-pass work. */
  changed: boolean;
};

async function syncInner(
  supabase: SupabaseClient,
  pubkey: string,
  encryptionKey: Uint8Array,
  deviceId: string,
  // eslint-disable-next-line @typescript-eslint/no-explicit-any
  onBatch?: () => any,
  onPushError?: (noteId: string, message: string) => void,
  onConflict?: (conflict: NoteConflict) => void,
  opts?: { flushOnly?: boolean },
): Promise<{ pullOk: boolean; changed: boolean; pushed?: number; pulled?: number }> {
  // Flush-only mode (sign-out rescue): no heartbeat, no pull, no cursor
  // advance - jump straight to the push phase. See sync() docs.
  const flushOnly = opts?.flushOnly === true;

  // Captured before any server work: if sign-out begins mid-pass
  // (suspendSync bumps the generation), this pass may finish its writes
  // but must not persist cursor or heal state afterwards.
  const generation = syncGeneration;

  // The session must prove it is THIS vault's session before any server
  // call. Under a missing or foreign pubkey claim, RLS does not error -
  // it silently filters every row to nothing - so a pass would pull an
  // empty vault, false-confirm tombstones against a blind confirming
  // SELECT (destroying the only record that a delete was pending), and
  // classify every dirty row as never-uploaded. Migration 0064 made the
  // heartbeat fail OPEN for exactly this broken-session state, so the
  // gate has to live here instead.
  //
  // The gate must never punish states that are not the session's fault:
  // - A refresh that failed because the server was UNREACHABLE (offline,
  //   captive portal, Supabase outage) is not a verdict. Skipping the
  //   pass quietly preserves the invariant that offline use never
  //   demotes the session (auth.tsx documents it for revalidation).
  // - A mismatched or missing claim can be the 1-3s window where the
  //   fast-boot path renders the app while authenticateWithPhrase is
  //   still re-minting the session (anon sign-in, then link-pubkey).
  //   Three quiet strikes ride out that transient; only a session that
  //   stays broken with the server REACHABLE escalates to the re-auth
  //   prompt. A skipped pass performs no reads and no writes, so the
  //   RLS blindness above cannot do damage in the meantime.
  const { data: sessionData, error: sessionErr } = await supabase.auth.getSession();
  if (sessionErr && sessionErr.name === 'AuthRetryableFetchError') {
    return { pullOk: false, changed: false };
  }
  const sessionPubkey = sessionData.session?.user?.app_metadata?.pubkey as
    | string
    | undefined;
  if (sessionPubkey !== pubkey) {
    if (claimGateBrokenSince === 0) {
      claimGateBrokenSince = Date.now();
      claimGateExpiredLogged = false;
      logAuthEvent('sync:claim-gate-broken', {
        hasSession: sessionData.session !== null,
        sessionPk: sessionPubkey?.slice(0, 8) ?? null,
        expectedPk: pubkey.slice(0, 8),
      });
    }
    // A re-mint refused on quota is not an expired session. Keep
    // skipping - a skipped pass reads nothing and writes nothing, so
    // the RLS blindness above still cannot do damage - until the
    // backoff window closes. Escalating here would show a re-auth
    // prompt whose only button burns another sign-in against the very
    // cap that is already exhausted. See RateLimitedError.
    if (Date.now() < remintBlockedUntil) return { pullOk: false, changed: false };
    if (flushOnly || Date.now() - claimGateBrokenSince < CLAIM_GATE_GRACE_MS) return { pullOk: false, changed: false };
    if (!claimGateExpiredLogged) {
      claimGateExpiredLogged = true;
      logAuthEvent('sync:claim-gate-expired', {
        brokenForMs: Date.now() - claimGateBrokenSince,
      });
    }
    throw new SessionExpiredError();
  }
  claimGateBrokenSince = 0;

  let lastSync =
    localStorage.getItem(LAST_SYNC_KEY) || '1970-01-01T00:00:00Z';

  // Heal flags are only committed after a clean sweep (see the persist
  // block after the pull). Setting them up front consumed the one-time
  // full re-read even when the healing pull failed or was aborted.
  const healFlagsPending: string[] = [];

  // One-time heal for notes stranded behind the cursor by a backdated
  // import (see migration 0063). Adding ingested_at stops FUTURE imports
  // from hiding, but it cannot rescue rows already on the server with an
  // old updated_at: this device's cursor is already past them, so no
  // filter clause matches. The only way back is a single full pull.
  //
  // This is a client-side flag rather than a server backfill timestamp on
  // purpose. Backfilling ingested_at = now() and relying on
  // ingested_at.gt.lastSync looks like it heals, but it races: the cursor
  // advances to the max updated_at of any row pulled, so a user who edits
  // one note between the migration and their client upgrade moves their
  // cursor past the backfill and the stranded rows stay hidden forever.
  // A flag is deterministic and does not care when the device upgrades.
  //
  // Runs once per device. The full pull is safe: processBatch skips rows
  // where local.dirty === 1 or local.updatedAt >= row.updated_at, so no
  // pending local edit is clobbered and no note is duplicated.
  if (!flushOnly && !localStorage.getItem(INGESTED_HEAL_KEY)) {
    if (lastSync > '1970-01-01T00:00:00Z') {
      console.warn('[sync] one-time full pull to recover backdated imported notes');
      lastSync = '1970-01-01T00:00:00Z';
      localStorage.removeItem(LAST_SYNC_KEY);
    }
    healFlagsPending.push(INGESTED_HEAL_KEY);
  }

  // One-time full re-pull for rows stranded by the offset-paging race
  // this cursor scheme replaced (migration 0065).
  //
  // Every device that ever ran a pull while another device was pushing
  // may hold silently stale rows: the old DESC+OFFSET pull could skip
  // them and then advance the cursor beyond them, after which no filter
  // could ever match them again. Measured on a live account at 503 of
  // 525 rows stale, reporting "Synced" throughout. Switching to the
  // keyset sweep stops NEW divergence but cannot rescue rows that are
  // already behind this device's cursor - only a full re-read can.
  //
  // Same shape as the 0063 heal above, and safe for the same reason:
  // processBatch skips rows where local.dirty === 1 or the local copy is
  // already newer, so no pending edit is clobbered and nothing is
  // duplicated. Costs one full pull, once per device, ever.
  if (!flushOnly && !localStorage.getItem(KEYSET_HEAL_KEY)) {
    if (lastSync > EPOCH_CURSOR) {
      console.warn('[sync] one-time full pull to recover rows stranded by offset paging');
      lastSync = EPOCH_CURSOR;
      localStorage.removeItem(LAST_SYNC_KEY);
    }
    healFlagsPending.push(KEYSET_HEAL_KEY);
  }

  // Guard: if IndexedDB is empty but lastSync claims we've synced
  // before, something wiped the local DB without resetting the cursor
  // (browser storage pressure, user clearing site data, session loss
  // without explicit sign-out). Reset to epoch so the pull fetches
  // everything instead of only the delta - otherwise all pre-existing
  // notes become permanently invisible. GitHub #73.
  if (!flushOnly && lastSync > '1970-01-01T00:00:00Z') {
    const localCount = await db.notes.count();
    if (localCount === 0) {
      console.warn('[sync] empty IndexedDB with stale lastSync - resetting cursor for full pull');
      lastSync = '1970-01-01T00:00:00Z';
      localStorage.removeItem(LAST_SYNC_KEY);
    }
  }

  // Track whether the pull succeeded so we only advance the lastSync
  // cursor when we're sure nothing was missed. Advancing after a failed
  // pull causes all skipped rows to become invisible until lastSync is
  // reset (the root cause of "empty app after sign-in").
  let pullOk = false;
  // True once this pass actually moved data in either direction. Callers
  // use it to skip the post-pass refresh() on no-op poll ticks, which at
  // a few thousand notes costs a few hundred ms of main-thread work
  // every 30 s while idle (backlog #130).
  let changed = false;
  // Pass counters for the sync activity log (syncLog.ts). Pushed counts
  // ATTEMPTS (per-row failures surface through onPushError); pulled counts
  // rows plus tombstones actually applied.
  let pushedCount = 0;
  let pulledCount = 0;

  // ── 1. PULL (two-phase ascending sweep) ─────────────────────────
  // Phase 1: apply the first page (PHASE1_SIZE rows) and render it
  // immediately so the user sees content within ~1-2 s.  Phase 2:
  // sweep the rest in PHASE2_CHUNK-row pages with NO intermediate
  // renders - the UI updates exactly once when phase 2 finishes.
  // Result: two total re-renders regardless of vault size.

  let batchHadError = false;

  // The keyset cursor: the (changed_at, id) of the last row this device
  // has applied. Both halves are server-assigned, never the client
  // clock, which is what closes the skew gap where a client running
  // ahead of the server permanently skipped rows whose timestamp fell
  // in between. GitHub #127.
  let [cursorAt, cursorId] = parseCursor(lastSync);

  // Safety valve: a cursor sitting in the FUTURE can never be caught up
  // to - every server-stamped changed_at lands behind it, so the device
  // pulls nothing while reporting Synced. Since migration 0066 the
  // server cannot mint future values, but cursors persisted during the
  // 0065 window can carry a fast client clock's timestamp (the 0066
  // backfill stamps rows at migration time, which is BEHIND such a
  // cursor, so the fleet-wide re-read never reaches these devices).
  // Comparing against this device's clock is imperfect either way it
  // errs: a slow local clock triggers one redundant full re-read
  // (idempotent), a fast one just leaves the clamp idle - and the
  // device that IS fast never victimises itself, only its peers, whose
  // normal clocks catch this. 5 minutes of slack for ordinary skew.
  if (cursorAt > EPOCH_CURSOR) {
    const atMs = Date.parse(cursorAt);
    if (Number.isFinite(atMs) && atMs > Date.now() + 5 * 60 * 1000) {
      console.warn('[sync] cursor is in the future - resetting for a full re-read');
      cursorAt = EPOCH_CURSOR;
      cursorId = null;
      lastSync = EPOCH_CURSOR;
      localStorage.removeItem(LAST_SYNC_KEY);
    }
  }

  /**
   * Process a batch of remote rows: split into upserts to write
   * locally and tombstone IDs to delete locally. Tombstones override
   * local dirty edits - the server says the note is gone, so the
   * device-local edit is discarded along with the row.
   */
  async function processBatch(rows: RemoteRow[]): Promise<{
    toPut: Array<{
      id: string; title: string; body: string; tags: string[];
      createdAt: string; updatedAt: string;
      dirty: 0 | 1; deleted: 0 | 1; trashed: 0 | 1; starred: 0 | 1;
      locked: 0 | 1; pinProtected: 0 | 1;
      type: import('@notes/shared').NoteType;
      trackers?: Record<string, unknown>;
      folderId: string | null;
      syncedNonce: string;
    }>;
    tombstoneIds: string[];
  }> {
    const toPut: Array<{
      id: string; title: string; body: string; tags: string[];
      createdAt: string; updatedAt: string;
      dirty: 0 | 1; deleted: 0 | 1; trashed: 0 | 1; starred: 0 | 1;
      locked: 0 | 1; pinProtected: 0 | 1;
      type: import('@notes/shared').NoteType;
      trackers?: Record<string, unknown>;
      folderId: string | null;
      syncedNonce: string;
    }> = [];
    const tombstoneIds: string[] = [];
    // Bulk-fetch local copies to avoid N sequential db.notes.get() calls.
    const ids = rows.map((r) => r.id);
    const locals = await db.notes.bulkGet(ids);
    const localMap = new Map(
      locals.filter(Boolean).map((n) => [n!.id, n!])
    );
    for (const row of rows) {
      // Tombstone wins over everything - including a local dirty edit.
      // We discard the local edit on purpose: the user permanently
      // deleted the note from another device; bringing it back via a
      // pending edit would be the resurrection bug we're closing.
      if (row.deleted_at) {
        tombstoneIds.push(row.id);
        continue;
      }
      const local = localMap.get(row.id);
      // Both dirty values win over a pull: 1 is a plaintext-era unsynced
      // edit, 2 is a sealed unsynced edit (the value old bundles cannot
      // see). Spec: ops/docs/plans/local-at-rest.md (5.2, the dirty fence)
      if (local && (local.dirty === 1 || local.dirty === 2)) continue;
      if (local && local.updatedAt > row.updated_at) continue;
      // Equal stamps: our own pushed generation echoing back carries the
      // nonce we recorded at push time - skip it, it is our own echo. A
      // DIFFERENT nonce under an equal stamp is another device's write
      // that won an equal-stamp race on the push guard's `.lte` (#156):
      // apply it, or this device keeps its losing copy with dirty=0 and
      // the two sides diverge silently until the next edit. Rows with no
      // recorded nonce (never synced from this device, pre-upgrade rows)
      // are still skipped - their equal-stamp case is the harmless echo,
      // and applying would re-write the whole vault on a cursor heal.
      if (
        local &&
        local.updatedAt === row.updated_at &&
        (local.syncedNonce == null || local.syncedNonce === row.nonce)
      ) continue;
      try {
        const decrypted = decryptNote(
          base64ToBytes(row.ciphertext),
          base64ToBytes(row.nonce),
          encryptionKey
        );
        toPut.push({
          id: row.id,
          title: decrypted.title,
          body: decrypted.body,
          tags: decrypted.tags,
          createdAt: row.created_at,
          updatedAt: row.updated_at,
          dirty: 0,
          deleted: 0,
          trashed: decrypted.trashed ? 1 : 0,
          starred: decrypted.starred ? 1 : 0,
          // locked / pinProtected / type are optional on DecryptedNote -
          // older encrypted blobs predate them. Missing = false / 'note'.
          locked: decrypted.locked ? 1 : 0,
          pinProtected: decrypted.pinProtected ? 1 : 0,
          type: decrypted.type ?? 'note',
          trackers: decrypted.trackers,
          folderId: decrypted.folderId ?? null,
          syncedNonce: row.nonce,
        });
      } catch (err) {
        console.error('[sync] decrypt failed for', row.id, err);
      }
    }
    return { toPut, tombstoneIds };
  }

  if (!flushOnly) {
    // Heartbeat - if the server tells us our device row is gone, stop and
    // let the caller force a sign-out. Fired here but NOT awaited yet: it
    // runs in parallel with the phase-1 pull request below, saving a full
    // round-trip (~400 ms) on the first sync after boot. The verdict is
    // still awaited BEFORE any pulled row is processed or written, so a
    // revoked device never persists fresh server data; its in-flight pull
    // response is discarded when DeviceRevokedError unwinds the sync.
    const heartbeatPromise = heartbeat(supabase, deviceId);

    // Ascending keyset sweep over `changed_at` (migrations 0065 + 0066).
    //
    // `changed_at` is a server-assigned change clock - a trigger stamps
    // now() on every INSERT and UPDATE, and no client value can touch
    // it. One column replaces the three ORed clauses this filter used
    // to carry (edits, tombstones, and backdated imports per 0063).
    //
    // ASCENDING and keyset, not DESC and offset, and that is the whole
    // point. Offset paging assumes the result set holds still; a device
    // pushing concurrently rewrites updated_at to now(), which moves
    // that row to the front of a DESC ordering and pushes unread rows
    // past the window the reader has already gone by. Those rows are
    // never returned, and the cursor then advances beyond them, so no
    // later filter can match them - silent permanent divergence, with
    // the client still reporting "Synced" (measured 2026-08-03: a
    // second client at 503 of 525 rows stale). Sorting ascending
    // inverts the failure: a write can only move a row FORWARD, toward
    // rows the sweep has not reached yet, so it can never hide one.
    //
    // The keyset is compound because ties are guaranteed, not rare: a
    // bulk import or bulk trash commits in one transaction, so hundreds
    // of rows share a changed_at to the microsecond. Paging on
    // changed_at alone would skip a whole tie group at a page boundary
    // or spin on it forever.
    /** One page of the sweep, oldest first. */
    const pullPage = (afterAt: string, afterId: string | null, limit: number) => {
      const base = supabase.from('notes').select('*');
      const filtered = afterId === null
        ? base.gt('changed_at', afterAt)
        : base.or(
            `changed_at.gt.${afterAt},and(changed_at.eq.${afterAt},id.gt.${afterId})`,
          );
      return filtered
        .order('changed_at', { ascending: true })
        .order('id', { ascending: true })
        .limit(limit);
    };

    // ── Phase 1: first page, rendered as soon as it lands ─────────
    // Promise.resolve() subscribes to the PostgREST builder immediately so
    // the request goes out in parallel with the heartbeat above.
    const phase1Promise = Promise.resolve(
      pullPage(cursorAt, cursorId, PHASE1_SIZE),
    );

    // Await the heartbeat verdict before touching any pulled data.
    const stillRegistered = await heartbeatPromise;
    if (!stillRegistered) {
      throw new DeviceRevokedError();
    }

    const { data: phase1, error: p1Err } = await phase1Promise;

    if (p1Err) {
      if (isAuthError(p1Err)) throw new SessionExpiredError();
      console.error('[sync] phase 1 pull failed:', p1Err);
      batchHadError = true;
    } else {
      /**
       * Apply one page and step the keyset to its last row.
       *
       * The cursor only ever moves to a row this sweep has actually
       * written, which is what makes an interrupted pull safe. Note the
       * durability boundary: the in-memory advance is only persisted
       * after a CLEAN sweep (see the persist block after the pull), so
       * a failed page discards this pass's progress and the next pass
       * re-reads from the last persisted cursor - idempotent, and the
       * safe direction. Rows the sweep skips on purpose (a local dirty
       * edit, a local copy already newer) still count as applied - the
       * client has deliberately decided their fate and re-reading them
       * forever would strand the cursor.
       */
      const applyPage = async (rows: RemoteRow[]) => {
        // Sign-out began mid-pass: stop writing. The wipe has run (or
        // is running), and repopulating the freshly cleared IndexedDB
        // with decrypted rows would leave this account's plaintext
        // sitting on a signed-out machine until the next sign-in. The
        // owner marker covers the cross-tab account switch the same
        // way: local storage that another account now owns must not
        // receive this account's decrypted rows.
        if (generation !== syncGeneration || !ownsLocalData(pubkey)) return;
        const { toPut, tombstoneIds } = await processBatch(rows);
        if (toPut.length > 0 || tombstoneIds.length > 0) {
          // Re-check inside one transaction before writing: an autosave
          // can land between processBatch's bulkGet snapshot and this
          // write, and blind-putting the server copy would erase the
          // fresh keystrokes AND mark the row clean, so the edit would
          // never push. The push side has carried the equivalent guard
          // (clearDirty's timestamp check) from day one; this is the
          // pull side of the same hazard. Tombstones stay unconditional
          // - the server says the note is gone.
          await db.transaction('rw', db.notes, async () => {
            const current = await db.notes.bulkGet(toPut.map((n) => n.id));
            const safe = toPut.filter((n, i) => {
              const c = current[i];
              if (!c) return true;
              if (c.dirty === 1 || c.dirty === 2) return false;
              // Same predicate processBatch applied, re-evaluated against
              // the live row: strictly newer, or the equal-stamp
              // foreign-nonce case (#156).
              return (
                c.updatedAt < n.updatedAt ||
                (c.updatedAt === n.updatedAt &&
                  c.syncedNonce != null &&
                  c.syncedNonce !== n.syncedNonce)
              );
            });
            if (safe.length > 0) await db.notes.bulkPut(safe);
            if (tombstoneIds.length > 0) await db.notes.bulkDelete(tombstoneIds);
            if (safe.length > 0 || tombstoneIds.length > 0) changed = true;
            pulledCount += safe.length + tombstoneIds.length;
          });
        }
        const last = rows[rows.length - 1];
        if (last) {
          cursorAt = last.changed_at;
          cursorId = last.id;
        }
      };

      const rows = (phase1 ?? []) as RemoteRow[];
      if (rows.length > 0) {
        await applyPage(rows);
        // Render immediately so the user has something to work with.
        if (onBatch) await onBatch();
      }

      // ── Phase 2: sweep to the end, no intermediate renders ──────
      // A short page means the server had nothing left AT THAT MOMENT.
      // Anything written afterwards carries a larger changed_at, so it
      // sits ahead of the cursor and the next pass picks it up. The one
      // residual window is commit visibility: a transaction that was
      // assigned now() before our read but commits after it can land
      // just behind the cursor. Documented as accepted in
      // sync-protocol.md section 7 - do not treat this comment as a
      // no-window guarantee.
      if (rows.length === PHASE1_SIZE) {
        // eslint-disable-next-line no-constant-condition
        while (true) {
          // Sign-out began mid-sweep: applyPage above has stopped
          // writing AND stopped advancing the in-memory cursor, so
          // looping would refetch the same page forever. The persist
          // is generation-gated too, so nothing from this pass lands.
          if (generation !== syncGeneration || !ownsLocalData(pubkey)) {
            batchHadError = true;
            break;
          }
          const { data: chunk, error: chunkErr } = await pullPage(
            cursorAt,
            cursorId,
            PHASE2_CHUNK,
          );

          if (chunkErr) {
            if (isAuthError(chunkErr)) throw new SessionExpiredError();
            console.error('[sync] phase 2 pull failed after', cursorAt, chunkErr);
            batchHadError = true;
            break;
          }

          const chunkRows = (chunk ?? []) as RemoteRow[];
          if (chunkRows.length === 0) break;

          await applyPage(chunkRows);

          if (chunkRows.length < PHASE2_CHUNK) break;
        }
      }
    }

    pullOk = !batchHadError;

    // Persist pull progress NOW, before the push phase. A push that
    // throws (quota freeze, expired session) must not cost the pull its
    // cursor: the heal above may have just removed the stored value, and
    // losing the advance here made a quota-frozen account with one dirty
    // row re-pull its ENTIRE vault on every pass, forever. The cursor is
    // the (changed_at, id) of the last row the sweep applied - both
    // server-assigned (migration 0066), never the client clock, which is
    // what closes the skew gap from GitHub #127/#134. The generation
    // gate keeps a pass that outlived sign-out from re-creating the
    // cursor after the wipe removed it (see suspendSync).
    if (pullOk && generation === syncGeneration && ownsLocalData(pubkey)) {
      const advanced = formatCursor(cursorAt, cursorId);
      if (advanced !== lastSync && cursorAt > EPOCH_CURSOR) {
        localStorage.setItem(LAST_SYNC_KEY, advanced);
      }
      // Heal flags commit only alongside a clean sweep - consuming them
      // on a failed or aborted heal would void the one-time full
      // re-read they exist to guarantee.
      for (const flag of healFlagsPending) {
        localStorage.setItem(flag, '1');
      }
    }
  }

  // ── 2. PUSH (batched) ───────────────────────────────────────────
  // The claim gate above ran ONCE, when this pass started. An account
  // switch can land mid-pass: a same-tab authenticate over a different
  // phrase swaps the supabase session and bumps the generation, and
  // another tab's authenticate flips the owner marker in the shared
  // localStorage. A push loop that keeps going after that writes one
  // account's rows against another account's token - server RLS refuses
  // each row, and that refusal is the ONLY backstop. So every write
  // boundary below re-checks all three ownership signals and ends the
  // push phase quietly: no error, rows stay dirty, and the storage's
  // rightful owner decides what happens to them (the switch wipe).
  const pushOwnershipLost = async (): Promise<boolean> => {
    if (generation !== syncGeneration) return true;
    if (!ownsLocalData(pubkey)) return true;
    const { data: liveSession } = await supabase.auth.getSession();
    const liveClaim = liveSession.session?.user?.app_metadata?.pubkey as
      | string
      | undefined;
    return liveClaim !== pubkey;
  };
  let pushEnded = false;
  const endPush = (stage: string): void => {
    if (pushEnded) return;
    pushEnded = true;
    logAuthEvent('sync:push-aborted-ownership', {
      stage,
      expectedPk: pubkey.slice(0, 8),
    });
  };

  // anyOf, not equals(1): sealed unsynced rows carry dirty 2 so that
  // bundles without the seal reader cannot pick them up and push
  // gutted payloads. This bundle reads both and pushes both.
  const dirty = await db.notes.where('dirty').anyOf(1, 2).toArray();
  const toDelete = dirty.filter((n) => n.deleted === 1);
  const toUpsert = dirty.filter((n) => n.deleted !== 1);
  if (dirty.length > 0) changed = true;
  pushedCount = dirty.length;

  // 2a. Batch tombstone - set deleted_at on the server. Other devices
  // see the tombstone via the changed_at pull sweep and bulkDelete locally.
  // The pg_cron purge (migration 0034) hard-deletes after 30 days.
  // `.is('deleted_at', null)` makes the operation idempotent: rows
  // already tombstoned by another device are skipped without error.
  // Chunked in groups of 50 to keep the `.in()` URL under server limits.
  // On chunk failure, continue pushing remaining chunks so one bad note
  // doesn't block others. Failed chunks stay in Dexie for retry. (#91)
  if (toDelete.length > 0) {
    const deleteIds = toDelete.map((n) => n.id);
    const TOMBSTONE_CHUNK = 50;
    for (let i = 0; i < deleteIds.length; i += TOMBSTONE_CHUNK) {
      if (pushEnded || (await pushOwnershipLost())) {
        endPush('tombstones');
        break;
      }
      const chunk = deleteIds.slice(i, i + TOMBSTONE_CHUNK);
      // `.select('id')` is load-bearing: without it PostgREST answers 204
      // with no body and no row count, so an UPDATE that matched NOTHING
      // is indistinguishable from one that tombstoned every row. This
      // code then bulkDeleted the local tombstones either way, which
      // destroyed the only record that the delete was still pending -
      // the note stayed alive on the server, kept counting against the
      // quota, and came back on the next device to pull from epoch.
      const { data: tombstoned, error } = await supabase
        .from('notes')
        .update({ deleted_at: new Date().toISOString() })
        .in('id', chunk)
        .is('deleted_at', null)
        .select('id');
      if (!error) {
        const confirmed = new Set((tombstoned ?? []).map((r) => r.id as string));
        // Rows the UPDATE did not touch are not automatically failures.
        // The `.is('deleted_at', null)` guard makes this idempotent, so a
        // row another device already tombstoned is legitimately skipped,
        // and a row that never reached the server has nothing to
        // tombstone. Both are done. What must NOT be dropped is a row
        // that is still alive and simply out of reach - an RLS rejection
        // under a session whose pubkey link is broken looks exactly like
        // a successful no-op from here.
        const unaccounted = chunk.filter((id) => !confirmed.has(id));
        if (unaccounted.length > 0) {
          const { data: survivors, error: checkErr } = await supabase
            .from('notes')
            .select('id')
            .in('id', unaccounted)
            .is('deleted_at', null);
          if (checkErr) {
            // Cannot prove they are gone, so keep them dirty and retry
            // on the next pass rather than guess.
            if (isAuthError(checkErr)) throw new SessionExpiredError();
            console.error('[sync] tombstone confirmation failed', checkErr);
            if (onPushError) {
              for (const id of unaccounted) {
                onPushError(id, checkErr.message ?? 'tombstone confirmation failed');
              }
            }
          } else {
            const stillAlive = new Set((survivors ?? []).map((r) => r.id as string));
            for (const id of unaccounted) {
              if (!stillAlive.has(id)) confirmed.add(id);
            }
            if (stillAlive.size > 0 && onPushError) {
              for (const id of stillAlive) {
                onPushError(id, 'delete not accepted by the server');
              }
            }
          }
        }
        if (confirmed.size > 0) {
          await db.notes.bulkDelete([...confirmed]);
        }
      } else {
        if (isAuthError(error)) throw new SessionExpiredError();
        console.error('[sync] batch tombstone failed', error);
        if (onPushError) {
          for (const id of chunk) {
            onPushError(id, error.message ?? 'tombstone failed');
          }
        }
        // continue - don't break; remaining chunks may succeed
      }
    }
  }

  /** Encrypt a note into the row shape the server stores. */
  const buildRow = (note: LocalNote) => {
    const { ciphertext, nonce } = encryptNote(
      {
        title: note.title,
        body: note.body,
        tags: note.tags,
        trashed: note.trashed === 1,
        starred: note.starred === 1,
        locked: note.locked === 1,
        pinProtected: note.pinProtected === 1,
        type: note.type ?? 'note',
        trackers: note.trackers,
        folderId: note.folderId ?? null,
      },
      encryptionKey,
    );
    return {
      id: note.id,
      user_pubkey: pubkey,
      ciphertext: bytesToBase64(ciphertext),
      nonce: bytesToBase64(nonce),
      created_at: note.createdAt,
      updated_at: note.updatedAt,
    };
  };

  /** Clear the dirty flag for rows the server accepted, keeping the
   *  per-note timestamp guard so an edit made mid-push stays dirty.
   *  `nonces` maps note id to the nonce the accepted row carries, so a row
   *  that lands here is stamped as synced exactly like one from the
   *  per-note path. Anything keyed off syncedNonce reads a bulk-inserted
   *  note as present on the server, which it is. */
  const clearDirty = async (notes: LocalNote[], nonces?: Map<string, string>) => {
    await db.transaction('rw', db.notes, async () => {
      for (const note of notes) {
        const current = await db.notes.get(note.id);
        if (current && current.updatedAt === note.updatedAt) {
          const nonce = nonces?.get(note.id);
          await db.notes.update(
            note.id,
            nonce == null ? { dirty: 0 } : { dirty: 0, syncedNonce: nonce },
          );
        }
      }
    });
  };

  // 2b-i. Bulk-insert first-time pushes.
  //
  // The conflict-aware path below costs up to THREE sequential round
  // trips per note that does not exist server-side yet: a conditional
  // update that matches nothing, a select to find out why, then the
  // insert. On a 500-note import that is ~1500 requests in strict
  // series - about ten minutes, during which the app reports each pass
  // as a successful sync while other devices watch the notes trickle in
  // twenty at a time.
  //
  // One batched probe tells us which ids the server already has. The
  // ones it does not can be inserted in bulk, with no conflict to
  // detect: there is nothing on the server to conflict with. Everything
  // else falls through to the per-note path completely unchanged, so
  // conflict detection for real edits is untouched.
  let pending = toUpsert;
  if (toUpsert.length > 1 && !pushEnded) {
    const PROBE_CHUNK = 200;
    const INSERT_CHUNK = 50;
    const known = new Set<string>();
    let probeOk = true;
    for (let i = 0; i < toUpsert.length && probeOk; i += PROBE_CHUNK) {
      const ids = toUpsert.slice(i, i + PROBE_CHUNK).map((n) => n.id);
      const { data, error } = await supabase
        .from('notes')
        .select('id')
        .in('id', ids);
      if (error) {
        if (isAuthError(error)) throw new SessionExpiredError();
        // A malformed id 400s the whole chunk, and quietly treating a
        // failed probe as "none of these exist" would bulk-insert over
        // live rows. Fall back to the per-note path for everything.
        console.warn('[sync] existence probe failed, falling back to per-note push', error);
        probeOk = false;
        break;
      }
      for (const row of data ?? []) known.add(row.id as string);
    }

    if (probeOk) {
      const fresh = toUpsert.filter((n) => !known.has(n.id));
      const retry: LocalNote[] = [];
      for (let i = 0; i < fresh.length; i += INSERT_CHUNK) {
        if (pushEnded || (await pushOwnershipLost())) {
          endPush('bulk-insert');
          break;
        }
        const batch = fresh.slice(i, i + INSERT_CHUNK);
        // A row over the per-row ceiling fails the whole chunk and takes
        // its neighbours down to the slow path with it, every pass, for as
        // long as the note exists. Hold it back and report it here: that
        // report is what marks it "not backed up", and it is the only one
        // this pass makes, because the per-note path never sees it either.
        const rows: ReturnType<typeof buildRow>[] = [];
        const sendable: LocalNote[] = [];
        for (const note of batch) {
          const built = buildRow(note);
          if (built.ciphertext.length > CIPHERTEXT_MAX_BYTES) {
            if (onPushError) onPushError(note.id, NOTE_TOO_LARGE_MSG);
            continue;
          }
          rows.push(built);
          sendable.push(note);
        }
        if (rows.length === 0) continue;
        const { error } = await supabase.from('notes').insert(rows);
        if (error) {
          if (isAuthError(error)) throw new SessionExpiredError();
          if (isQuotaError(error)) throw new QuotaExceededError(error.message);
          if (isRlsError(error)) {
            endPush('rls-refused');
            break;
          }
          // One bad row (oversized note, malformed id) fails the whole
          // batch, so hand this chunk to the per-note path where each
          // note gets its own verdict and its own error message.
          console.warn('[sync] batch insert failed, retrying these per note', error);
          retry.push(...sendable);
          continue;
        }
        await clearDirty(sendable, new Map(rows.map((r) => [r.id, r.nonce])));
      }
      pending = toUpsert.filter((n) => known.has(n.id)).concat(retry);
    }
  }

  // 2b-ii. Conflict-aware push - encrypt each dirty note and push with a
  // conditional update (lte guard on updated_at). If the server has a
  // newer version, we detect the conflict instead of silently overwriting.
  const pushOne = async (note: LocalNote) => {
    if (pushEnded || (await pushOwnershipLost())) {
      endPush('per-note');
      return;
    }
    const { ciphertext, nonce } = encryptNote(
      {
        title: note.title,
        body: note.body,
        tags: note.tags,
        trashed: note.trashed === 1,
        starred: note.starred === 1,
        locked: note.locked === 1,
        pinProtected: note.pinProtected === 1,
        type: note.type ?? 'note',
        trackers: note.trackers,
        folderId: note.folderId ?? null,
      },
      encryptionKey
    );
    const row = {
      id: note.id,
      user_pubkey: pubkey,
      ciphertext: bytesToBase64(ciphertext),
      nonce: bytesToBase64(nonce),
      created_at: note.createdAt,
      updated_at: note.updatedAt,
    };

    // No retry can make this row fit, so it costs nothing but the report.
    // The note stays dirty and keeps its "not backed up" marking until an
    // edit brings it under the ceiling, when this check simply passes.
    if (row.ciphertext.length > CIPHERTEXT_MAX_BYTES) {
      if (onPushError) onPushError(note.id, NOTE_TOO_LARGE_MSG);
      return;
    }

    // Try conditional update: only succeeds if server isn't newer.
    const { data: updated, error: updateErr } = await supabase
      .from('notes')
      .update({
        ciphertext: row.ciphertext,
        nonce: row.nonce,
        updated_at: row.updated_at,
      })
      .eq('id', note.id)
      .eq('user_pubkey', pubkey)
      .lte('updated_at', note.updatedAt)
      .select('id');

    if (updateErr) {
      if (isAuthError(updateErr)) throw new SessionExpiredError();
      if (isQuotaError(updateErr)) throw new QuotaExceededError(updateErr.message);
      // One oversized note breaching the per-note 1 MB CHECK is not an
      // account-storage problem - surface the per-note retry banner, not
      // the global "Storage full" banner.
      if (isNoteTooLargeError(updateErr)) {
        if (onPushError) onPushError(note.id, NOTE_TOO_LARGE_MSG);
        return;
      }
      // Invalid UUID (e.g. old seed note with non-hex sentinel "we11") -
      // delete the local note so it stops retrying forever.
      if (updateErr.message?.includes('invalid input syntax for type uuid')) {
        console.warn('[sync] deleting note with invalid UUID:', note.id);
        await db.notes.delete(note.id);
        return;
      }
      console.error('[sync] push failed for', note.id, updateErr);
      if (onPushError) {
        onPushError(note.id, updateErr.message ?? 'unknown error');
      }
      return;
    }

    if (updated && updated.length > 0) {
      // Update succeeded - clear dirty flag (with timestamp guard) and
      // record the pushed nonce so the pull can tell this generation's
      // echo from a foreign equal-stamp row (#156).
      await db.transaction('rw', db.notes, async () => {
        const current = await db.notes.get(note.id);
        if (current && current.updatedAt === note.updatedAt) {
          await db.notes.update(note.id, { dirty: 0, syncedNonce: row.nonce });
        }
      });
      return;
    }

    // 0 rows updated - either conflict (server is newer) or note
    // doesn't exist on server yet (first push). Check which.
    const { data: existing, error: fetchErr } = await supabase
      .from('notes')
      .select('ciphertext, nonce, updated_at')
      .eq('id', note.id)
      .eq('user_pubkey', pubkey)
      .maybeSingle();

    if (fetchErr) {
      if (isAuthError(fetchErr)) throw new SessionExpiredError();
      console.error('[sync] conflict check failed for', note.id, fetchErr);
      if (onPushError) onPushError(note.id, fetchErr.message ?? 'conflict check failed');
      return;
    }

    if (!existing) {
      // No row on server - first-time insert.
      const { error: insertErr } = await supabase.from('notes').insert(row);
      if (insertErr) {
        if (isAuthError(insertErr)) throw new SessionExpiredError();
        if (isQuotaError(insertErr)) throw new QuotaExceededError(insertErr.message);
        if (isNoteTooLargeError(insertErr)) {
          if (onPushError) onPushError(note.id, NOTE_TOO_LARGE_MSG);
          return;
        }
        if (insertErr.message?.includes('invalid input syntax for type uuid')) {
          console.warn('[sync] deleting note with invalid UUID:', note.id);
          await db.notes.delete(note.id);
          return;
        }
        if (isRlsError(insertErr)) {
          endPush('rls-refused');
          return;
        }
        console.error('[sync] insert failed for', note.id, insertErr);
        if (onPushError) onPushError(note.id, insertErr.message ?? 'insert failed');
      } else {
        await db.transaction('rw', db.notes, async () => {
          const current = await db.notes.get(note.id);
          if (current && current.updatedAt === note.updatedAt) {
            await db.notes.update(note.id, { dirty: 0, syncedNonce: row.nonce });
          }
        });
      }
      return;
    }

    // ── Conflict: server has a newer version ──────────────────────
    console.warn('[sync] conflict detected for note', note.id);
    try {
      const serverDecrypted = decryptNote(
        base64ToBytes(existing.ciphertext),
        base64ToBytes(existing.nonce),
        encryptionKey
      );

      // Auto-merge: without a stored pre-edit base we cannot know which
      // side changed the body, so merge silently only when the bodies
      // are identical - the local side then carries at most title and
      // metadata changes, and local wins (the user's most recent intent).
      const bodyIdentical = note.body === serverDecrypted.body;
      const titleIdentical = note.title === serverDecrypted.title;

      if (bodyIdentical && titleIdentical) {
        // Body + title unchanged - only metadata differs. Auto-merge:
        // local metadata wins (it's the user's latest action on this
        // device - e.g. they starred or tagged the note).
        const mergedAt = new Date().toISOString();
        const mergedTrackers = mergeTrackers(note.trackers, serverDecrypted.trackers);
        const { ciphertext: mergedCt, nonce: mergedNonce } = encryptNote(
          {
            title: note.title,
            body: note.body,
            tags: note.tags,
            trashed: note.trashed === 1,
            starred: note.starred === 1,
            locked: note.locked === 1,
            pinProtected: note.pinProtected === 1,
            type: note.type ?? 'note',
            trackers: mergedTrackers,
            folderId: note.folderId ?? null,
          },
          encryptionKey
        );
        // Guarded like the main push: `lte` on the version this merge
        // was computed against, plus `.select('id')` to learn whether
        // the write landed. Unguarded, this overwrote a NEWER version
        // pushed by another device in the window since the conflict
        // read (and a trigger-dropped write to a tombstoned row looked
        // identical to success).
        const { data: mergedRows, error: mergeErr } = await supabase
          .from('notes')
          .update({
            ciphertext: bytesToBase64(mergedCt),
            nonce: bytesToBase64(mergedNonce),
            updated_at: mergedAt,
          })
          .eq('id', note.id)
          .eq('user_pubkey', pubkey)
          .lte('updated_at', existing.updated_at)
          .select('id');
        if (!mergeErr && mergedRows && mergedRows.length > 0) {
          await db.transaction('rw', db.notes, async () => {
            const current = await db.notes.get(note.id);
            if (current && current.updatedAt === note.updatedAt) {
              await db.notes.update(note.id, {
                dirty: 0,
                updatedAt: mergedAt,
                // The merged tracker payload has to land locally too. The
                // row is about to match the server's stamp and nonce, so
                // the next pull SKIPS it as its own echo - without this
                // write the device would keep only its own half of the
                // merge it just pushed, forever.
                trackers: mergedTrackers,
                syncedNonce: bytesToBase64(mergedNonce),
              });
            }
          });
          console.log('[sync] auto-merged metadata for note', note.id);
        } else if (mergeErr) {
          console.error('[sync] auto-merge push failed for', note.id, mergeErr);
          if (onPushError) onPushError(note.id, mergeErr.message ?? 'auto-merge failed');
        } else {
          // 0 rows: the server moved again (or the row was tombstoned)
          // since the conflict read. Stay dirty; the next pass re-runs
          // conflict detection against the newer row.
          console.warn('[sync] auto-merge lost a second race for', note.id);
        }
      } else if (note.body === serverDecrypted.body) {
        // Body identical but title differs. Local title wins (more
        // recent intent), keep server body.
        const mergedAt = new Date().toISOString();
        const mergedTrackers = mergeTrackers(note.trackers, serverDecrypted.trackers);
        const { ciphertext: mergedCt, nonce: mergedNonce } = encryptNote(
          {
            title: note.title,
            body: serverDecrypted.body,
            tags: note.tags,
            trashed: note.trashed === 1,
            starred: note.starred === 1,
            locked: note.locked === 1,
            pinProtected: note.pinProtected === 1,
            type: note.type ?? 'note',
            trackers: mergedTrackers,
            folderId: note.folderId ?? null,
          },
          encryptionKey
        );
        // Same guard as the metadata-only merge above: this write is
        // computed against `existing` and must not land on anything
        // newer.
        const { data: mergedRows, error: mergeErr } = await supabase
          .from('notes')
          .update({
            ciphertext: bytesToBase64(mergedCt),
            nonce: bytesToBase64(mergedNonce),
            updated_at: mergedAt,
          })
          .eq('id', note.id)
          .eq('user_pubkey', pubkey)
          .lte('updated_at', existing.updated_at)
          .select('id');
        if (!mergeErr && mergedRows && mergedRows.length > 0) {
          await db.transaction('rw', db.notes, async () => {
            const current = await db.notes.get(note.id);
            if (current && current.updatedAt === note.updatedAt) {
              await db.notes.update(note.id, {
                dirty: 0,
                updatedAt: mergedAt,
                // The merged tracker payload has to land locally too. The
                // row is about to match the server's stamp and nonce, so
                // the next pull SKIPS it as its own echo - without this
                // write the device would keep only its own half of the
                // merge it just pushed, forever.
                trackers: mergedTrackers,
                syncedNonce: bytesToBase64(mergedNonce),
              });
            }
          });
          console.log('[sync] auto-merged title+metadata for note', note.id);
        } else if (mergeErr) {
          console.error('[sync] auto-merge push failed for', note.id, mergeErr);
          if (onPushError) onPushError(note.id, mergeErr.message ?? 'auto-merge failed');
        } else {
          console.warn('[sync] auto-merge lost a second race for', note.id);
        }
      } else if (note.title === serverDecrypted.title && arraysEqual(note.tags, serverDecrypted.tags)) {
        // Title+tags identical, body differs. Server body is newer
        // (it has the later updated_at), but local may have edits too.
        // If server body is strictly newer and local only changed
        // metadata, we can merge: keep server body, local metadata.
        // But we can't tell if local changed body without a base copy.
        // So this is a real body conflict - surface it.
        if (onConflict) {
          onConflict({
            noteId: note.id,
            localNote: note,
            serverTitle: serverDecrypted.title,
            serverBody: serverDecrypted.body,
            serverTags: serverDecrypted.tags,
            serverTrackers: serverDecrypted.trackers,
            serverStarred: serverDecrypted.starred ?? false,
            serverTrashed: serverDecrypted.trashed ?? false,
            serverLocked: serverDecrypted.locked ?? false,
            serverPinProtected: serverDecrypted.pinProtected ?? false,
            serverType: serverDecrypted.type ?? 'note',
            serverFolderId: serverDecrypted.folderId ?? null,
            serverUpdatedAt: existing.updated_at,
            serverRow: existing,
          });
        } else {
          // No conflict handler - the sign-out rescue flush. Do NOT
          // fall back to server-wins here: overwriting the local body
          // and clearing dirty moments before the wipe destroyed the
          // unsynced edit on both sides (keepUnsyncedNotes can only
          // rescue rows still flagged dirty). Leave the row dirty; the
          // next authenticated pass re-detects the conflict with the
          // modal wired.
          console.warn('[sync] conflict for', note.id, 'left dirty (no handler)');
        }
      } else {
        // Both sides changed body (and possibly title/tags too).
        // This is a full conflict - surface to the user.
        if (onConflict) {
          onConflict({
            noteId: note.id,
            localNote: note,
            serverTitle: serverDecrypted.title,
            serverBody: serverDecrypted.body,
            serverTags: serverDecrypted.tags,
            serverTrackers: serverDecrypted.trackers,
            serverStarred: serverDecrypted.starred ?? false,
            serverTrashed: serverDecrypted.trashed ?? false,
            serverLocked: serverDecrypted.locked ?? false,
            serverPinProtected: serverDecrypted.pinProtected ?? false,
            serverType: serverDecrypted.type ?? 'note',
            serverFolderId: serverDecrypted.folderId ?? null,
            serverUpdatedAt: existing.updated_at,
            serverRow: existing,
          });
        } else {
          // No conflict handler (sign-out rescue flush) - keep the row
          // dirty rather than server-wins. See the branch above.
          console.warn('[sync] conflict for', note.id, 'left dirty (no handler)');
        }
      }
    } catch (err) {
      console.error('[sync] conflict resolution failed for', note.id, err);
      if (onPushError) onPushError(note.id, 'conflict resolution failed');
    }
  };

  // Run the per-note pushes with bounded concurrency rather than one at
  // a time.
  //
  // Serially, every note the server ALREADY HAS costs one strictly
  // serialized round trip, and the 2b-i bulk path above never helps
  // them - it only batches first-time inserts. So any bulk action over
  // existing notes (trash 500, restore 500, star 500, retag 500, move
  // 500 to a folder) paid 500 sequential round trips with the sync
  // mutex held: about 40 s at an 80 ms RTT and 100 s at 200 ms, during
  // which the app reports itself as merely "syncing".
  //
  // Every iteration of pushOne is independent and order-free: the `lte`
  // guard, the zero-rows conflict probe and the clearDirty timestamp
  // check are all keyed on one note.id, and no cross-note ordering
  // exists server-side either - each write gets its own trigger-stamped
  // changed_at (migration 0066) and the pull applies rows one by one.
  // Concurrency therefore changes throughput only, never the outcome of
  // any single note. Deliberately modest: concurrent writes contend on
  // the same pubkey_quotas row through the notes_enforce_quota trigger,
  // so a high number buys little and just moves the queue into the
  // database.
  // Spec: ops/docs/design-decisions.md (sync push concurrency)
  const PUSH_CONCURRENCY = 8;

  // The first SessionExpiredError or QuotaExceededError wins and stops
  // the workers from picking up further notes, mirroring the sequential
  // loop's throw. Requests already in flight are allowed to settle
  // instead of being abandoned: each carries the same per-note guards
  // as any other pass, so letting them finish is safe, and it keeps
  // clearDirty from being skipped on a write the server did accept.
  let pushAbort: unknown = null;
  let pushCursor = 0;
  const pushWorker = async () => {
    while (pushAbort === null && !pushEnded) {
      const index = pushCursor++;
      if (index >= pending.length) return;
      const note = pending[index];
      if (!note) return;
      try {
        await pushOne(note);
      } catch (err) {
        if (pushAbort === null) pushAbort = err;
        return;
      }
    }
  };
  await Promise.all(
    Array.from(
      { length: Math.min(PUSH_CONCURRENCY, pending.length) },
      pushWorker,
    ),
  );
  if (pushAbort !== null) throw pushAbort;

  // The cursor was already persisted at the end of the pull phase (see
  // the block after `pullOk = !batchHadError`), so a push-phase throw
  // above never costs the pull its progress.
  return { pullOk, changed, pushed: pushedCount, pulled: pulledCount };
}
