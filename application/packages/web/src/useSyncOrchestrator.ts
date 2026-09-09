import { useCallback, useEffect, useRef, useState } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import type { AuthState } from './auth';
import { invalidateDeviceRegistration } from './authStorage';
import type { SupabaseClient } from '@notes/shared';
import { createNote, listNotes } from './notesRepo';
import { db, type LocalNote } from './db';
import { sync, CaptchaRequiredError, DeviceRevokedError, QuotaExceededError, SessionExpiredError, type NoteConflict } from './sync';
import { logAuthEvent } from './authDiag';
import { fetchQuotaUsage } from './devices';
import { hasSettingsPulled, loadLocalSettings, saveLocalSettings, syncUserSettings, type UserSettings } from './userSettings';
import { syncPinCache } from './pin';
import { syncPinWrap } from './pinRecovery';
import { seedOnboardingNotes, SEED_MEDICATION } from './welcomeNote';
import { mergeTrackers, trackersEqual } from './trackerTypes';
import { isDemoMode } from './demo';
import { reconcileOrphanBlobs, sweepBlobGC } from './imageGC';
import { perfSpan } from './perf';
import { setSyncingFlag } from './syncingStore';
import { recordSyncPass } from './syncLog';
import { classifyPushFailure, recordPassPushFailures } from './pushFailures';
import { reconcileFlushStash } from './flushStash';
import type { ImageStore } from './imageStore';
import type { AttachmentStore } from './attachmentStore';

// A quota-failed blob retry re-uploads the full blob then deletes it
// server-side on repeat failure - don't hammer that on every sync pass.
const PENDING_BLOB_RETRY_MS = 30 * 60_000;

type Authed = Extract<AuthState, { status: 'authenticated' }>;

export function useSyncOrchestrator({
  auth,
  supabase,
  forceSignOut,
  setUserSettings,
  setNotes,
  flushEditingBodyRef,
  imageStoreRef,
  attachmentStoreRef,
  selectedId,
  editingBodyRef,
  setEditorRevision,
  editorFocusedRef,
}: {
  auth: Authed;
  supabase: SupabaseClient;
  forceSignOut: (reason?: string) => Promise<void>;
  setUserSettings: Dispatch<SetStateAction<UserSettings>>;
  setNotes: Dispatch<SetStateAction<LocalNote[]>>;
  flushEditingBodyRef: MutableRefObject<() => void>;
  imageStoreRef: MutableRefObject<ImageStore | null>;
  attachmentStoreRef: MutableRefObject<AttachmentStore | null>;
  selectedId: string | null;
  editingBodyRef: { readonly current: Map<string, string> };
  setEditorRevision: Dispatch<SetStateAction<number>>;
  editorFocusedRef: { readonly current: boolean };
}) {
  const [quotaExceeded, setQuotaExceeded] = useState(false);
  /** ISO timestamp of when the user first exceeded quota (from server). */
  const [quotaExceededSince, setQuotaExceededSince] = useState<string | null>(null);
  const [sessionExpired, setSessionExpired] = useState(false);
  /** Per-sync-pass push-error tracking for the dismissable banner. Cleared
   * at the start of each `runSync` and populated by the `onPushError`
   * callback. Size rejections stay out of it: the banner's "retries
   * automatically" is false for them, so they surface through
   * pushFailures.ts (pill, ID & Sync list, editor bar) instead. See gap #4. */
  const [pushErrors, setPushErrors] = useState<{ count: number; lastMessage: string } | null>(null);
  /** Fingerprint of dismissed push errors. When the user dismisses,
   *  we store `count:lastMessage`. Banner stays hidden until the
   *  error signature changes (different note fails, or count changes).
   *  See gap #42. */
  const pushErrorsDismissedKey = useRef<string | null>(null);
  /** Queue of note conflicts that couldn't be auto-merged. Shown one
   *  at a time via ConflictModal. */
  const [conflictQueue, setConflictQueue] = useState<NoteConflict[]>([]);
  /** Shared enqueue behavior for any sync pass that surfaces a conflict -
   *  runSync's own pass and MoveBanner's pre-move sync both feed the
   *  same queue so ConflictModal is the one place conflicts get resolved. */
  const enqueueConflict = useCallback((conflict: NoteConflict) => {
    setConflictQueue((q) => {
      // Dedupe by noteId - don't queue the same note twice.
      if (q.some((c) => c.noteId === conflict.noteId)) return q;
      return [...q, conflict];
    });
  }, []);
  /** Set when any storage subscription is past_due (card failed).
   *  Surfaces a "your card needs updating" banner. See gap #38. */
  const [storagePastDue, setStoragePastDue] = useState(false);
  const [storagePastDueDismissed, setStoragePastDueDismissed] = useState(false);
  // "New vault created" notice for the sign-in-with-existing-phrase
  // path when the server has no data for the derived pubkey.
  const [freshVaultNotice, setFreshVaultNotice] = useState(false);
  // Monotonic counter bumped on every local settings mutation.
  // runSync snapshots it before calling syncUserSettings and skips
  // the setUserSettings write if it changed mid-flight (GitHub #71).
  const settingsGenRef = useRef(0);
  const quotaRef = useRef<{ usedBytes: number; maxBytes: number } | null>(null);
  // Cooldown gate for the post-sync pending-blob retry - see PENDING_BLOB_RETRY_MS.
  const lastPendingBlobRetryRef = useRef(0);
  /** Note ids whose conflict decision is in flight - see resolveConflict. */
  const resolvingConflictsRef = useRef<Set<string>>(new Set());
  // Mirror of the selectedId prop for runSync, whose deps deliberately
  // exclude it: adding it would re-create runSync (and re-register the
  // poller) on every note switch. resolveConflict keeps using the prop
  // directly - it lists selectedId in its deps and stays fresh that way.
  const selectedIdRef = useRef(selectedId);
  selectedIdRef.current = selectedId;

  const refresh = useCallback(async () => {
    const end = perfSpan('refresh');
    const all = await listNotes();
    // The search index follows the notes STATE (useSearchIndexSync in
    // NotesView), not this refresh: local mutations (create, rename,
    // per-keystroke saves) update state without any refresh, and an
    // index rebuilt only here missed them until the next tab focus.
    setNotes(all);
    end();
    return all;
  }, []);

  const runSync = useCallback(async () => {
    if (isDemoMode()) return;
    if (!navigator.onLine) return;
    // Flush any in-flight body edits into React state so the sync
    // picks up the latest content and dirty flags are correct.
    flushEditingBodyRef.current();
    // Snapshot the OPEN note's row as of pass start (after the flush, so
    // it includes the user's latest keystrokes). Compared post-pass to
    // detect a pull that rewrote the note under the mounted editor (#142).
    const openNoteId = selectedIdRef.current;
    const openNoteBefore = openNoteId ? await db.notes.get(openNoteId) : undefined;
    const endPass = perfSpan('syncPass');
    setSyncingFlag(true);
    // Per-pass error accumulator for the banner. The callback below feeds
    // it from sync.ts.
    let passErrors: { count: number; lastMessage: string } | null = null;
    // Every failure of this pass by note id, for pushFailures.ts. Recorded
    // only after a pass that ran: a skipped pass attempted nothing, so its
    // empty list says nothing about the notes that failed last time.
    const passFailures: Array<{ id: string; message: string }> = [];
    let passRan = false;
    const onPushError = (id: string, message: string) => {
      passFailures.push({ id, message });
      // An RLS rejection means this session's pubkey link is broken
      // server-side; retrying the push can never succeed. Invalidate
      // the registration throttle so the next boot re-runs the full
      // link + register handshake instead of fast-booting back into
      // the same broken session for up to 24 h.
      if (message.includes('row-level security')) {
        invalidateDeviceRegistration();
      }
      // A size rejection has its own surfaces and no retry that can
      // succeed, so it never reaches the banner's "retries automatically".
      if (classifyPushFailure(message) === 'too_large') return;
      passErrors = {
        count: (passErrors?.count ?? 0) + 1,
        lastMessage: message,
      };
    };
    // Capture BEFORE sync writes lastSync - the welcome-note seed
    // guard uses this to distinguish genuinely-new users from existing
    // ones. Without this, the first sync's own lastSync write fools
    // the guard into thinking the user has synced before.
    const hadSyncedBefore = (localStorage.getItem('privacynotes.lastSync') ?? '1970') > '1970';
    try {
      // Progressive mid-pull rendering (sync's onBatch after phase 1) only
      // earns its keep when the screen would otherwise be EMPTY - a fresh
      // device's first full pull, or the #73 wiped-DB recovery. On a warm
      // boot the list is already painted from the mount refresh, so the
      // mid-pass refresh was a redundant full listNotes + index rebuild
      // that contended with the pull's own decrypt work (555 ms listNotes
      // spikes, #140); the post-pass refresh below covers the delta.
      const localCount = await db.notes.count();
      const onBatch = localCount === 0 ? refresh : undefined;
      const passStartedAt = Date.now();
      const syncResult = await sync(supabase, auth.pubkey, auth.encryptionKey, auth.deviceId, onBatch, onPushError, enqueueConflict);
      passRan = syncResult.ran;
      // Feed the sync activity log (syncLog.ts). Skipped passes (demo,
      // floor, pause, mutex) report ran: false and are non-events.
      if (syncResult.ran) {
        // `pushed` counts attempted rows; the log separates the accepted
        // ones from the refused, so a stuck note never reads as "1 up".
        const failedCount = new Set(passFailures.map((f) => f.id)).size;
        recordSyncPass({
          at: passStartedAt,
          ms: Date.now() - passStartedAt,
          ok: syncResult.pullOk,
          up: Math.max(0, (syncResult.pushed ?? 0) - failedCount),
          down: syncResult.pulled ?? 0,
          failed: failedCount,
        });
      }
      // A pass that actually ran proves the session carries this vault's
      // claim again (the gate is the first thing sync() checks), so the
      // re-auth modal must come back down. Without this the flag was
      // write-once: a transient claim gap during a background re-mint
      // latched the modal for the life of the mount, and its only button
      // signs the user out. Mirrors how auth.tsx clears revalidationExpired
      // on any successful re-auth. A mutex-skipped pass proves nothing.
      if (syncResult.ran) setSessionExpired(false);
      // Sync the user_settings blob right after notes. Order matters:
      // notes first so the user's newest edits land fastest, settings
      // second so a favorites toggle doesn't block a note upload.
      const settingsGen = settingsGenRef.current;
      let merged = await syncUserSettings(supabase, auth.pubkey, auth.encryptionKey);
      syncPinCache(merged);

      // Carries the account's PIN wrap onto this device, and off it again
      // when the account no longer has one. The phrase goes with it so a
      // device the removal leaves with no door can put it back at rest.
      syncPinWrap(merged, auth.phrase);

      // One-shot welcome-note seed. Runs exactly once per user, ever
      // - gated on the synced `welcomeNoteSeeded` flag so a second
      // device signing in with the same phrase doesn't re-seed. The
      // note itself has a deterministic ID (derived from pubkey), so
      // even if StrictMode double-mounts us in dev, Dexie .put just
      // overwrites the first insertion with the second, identical
      // one - never two notes. If the user deletes the welcome note,
      // the flag stays true forever and we respect their choice.
      let effective = merged;
      // The gate below only runs when THIS pass actually completed a
      // successful pull. A mutex-skipped sync (another pass already in
      // flight) or a failed pull leaves IndexedDB unrepresentative of
      // the server: a concurrent first pull mid-flight means zero local
      // notes and no lastSync cursor, which made this gate fire a false
      // "fresh vault" verdict (and previously, seed welcome notes) on a
      // populated account. Skipping is safe - the gate re-evaluates on
      // the next clean pass, and the phraseImport marker stays put
      // until consumed.
      if (syncResult.ran && syncResult.pullOk && !merged.welcomeNoteSeeded) {
        // One-shot marker set by Onboarding's "Sign in with existing
        // phrase" form. Consumed here so a stale marker can't leak into
        // a later signup in the same tab.
        let fromPhraseImport = false;
        try {
          fromPhraseImport = sessionStorage.getItem('privacynotes.phraseImport') === '1';
          sessionStorage.removeItem('privacynotes.phraseImport');
        } catch { /* ignore */ }
        // Guard: if the user already has notes OR has synced before,
        // they're not new - the flag just didn't survive (settings pull
        // failed, multi-browser race, account switch in same browser,
        // or corrupted server state from the pre-fix blind upsert era).
        // Set the flag and skip seeding.
        const existingCount = await db.notes.where('deleted').equals(0).count();
        if (existingCount > 0 || hadSyncedBefore) {
          effective = { ...merged, welcomeNoteSeeded: true };
          saveLocalSettings(effective);
          void syncUserSettings(supabase, auth.pubkey, auth.encryptionKey).catch(
            (err) => console.error('[welcome] push seeded flag (existing notes) failed:', err)
          );
        } else if (fromPhraseImport && auth.method === 'phrase') {
          // The user picked "Sign in with existing phrase" but the first
          // pull (sync above) returned nothing for this pubkey: either
          // the vault was deleted, or the phrase is valid-but-wrong.
          // Phrase identity is derived client-side, so signing in always
          // (re)creates an account - but fabricating onboarding content
          // here made a fresh vault look like surviving data. Skip the
          // seed and tell the user explicitly that this vault is new.
          effective = { ...merged, welcomeNoteSeeded: true };
          saveLocalSettings(effective);
          void syncUserSettings(supabase, auth.pubkey, auth.encryptionKey).catch(
            (err) => console.error('[welcome] push seeded flag (fresh vault) failed:', err)
          );
          setFreshVaultNotice(true);
        } else {
          try {
            // Seeds all four onboarding notes (Welcome, Getting started,
            // Tokyo journal, Wellness journal) so every pillar has a live
            // example on first open. Each seed is individually idempotent.
            await seedOnboardingNotes(auth.pubkey);
            // Seed the example medication template if not already present.
            // It has to fold back into `merged`: the `welcomeNoteSeeded`
            // write below is built from `merged`, so a separate save here
            // was overwritten one line later and the seeded journal
            // entries referenced a medication that did not exist.
            if (!merged.medications?.some((m) => m.id === SEED_MEDICATION.id)) {
              merged = { ...merged, medications: [...(merged.medications ?? []), SEED_MEDICATION] };
              saveLocalSettings(merged);
            }
            // Push the seeded notes to the server BEFORE marking seeding
            // as done. Without this, the flag can land on the server while
            // the notes themselves are still local-only (dirty: 1). If the
            // user signs out before the next sync pass, re-login sees the
            // flag, skips seeding, and the app is empty.
            await sync(supabase, auth.pubkey, auth.encryptionKey, auth.deviceId, undefined, onPushError);
            // Re-read rather than reuse `merged`: seeding writes the starter
            // folder tree into settings itself, and a snapshot taken before
            // the seed would drop those folders one line later. The
            // medications fold-back above is the same trap, found first.
            effective = { ...loadLocalSettings(), welcomeNoteSeeded: true };
            saveLocalSettings(effective);
            // Push the flag now that the notes are safely on the server.
            void syncUserSettings(supabase, auth.pubkey, auth.encryptionKey).catch(
              (err) => console.error('[welcome] push seeded flag failed:', err)
            );
          } catch (err) {
            console.error('[welcome] seed failed:', err);
          }
        }
      }
      // First run on this account: start the rating clock (ratingPrompt.ts).
      // The stamp waits for a settings pass that has actually SEEN the
      // server (hasSettingsPulled): it used to be minted by NotesView at
      // mount, BEFORE the first pull, and that write armed the dirty flag
      // that made a fresh device push its default blob over the account's
      // real settings - the folder-wipe bug. Post-pull, a null stamp means
      // the account genuinely has none yet, so this device mints it. The
      // dirty flag it sets rides the next pass. The settingsGen check is
      // the same stale-pass rule as the setUserSettings below: `effective`
      // is a snapshot from when syncUserSettings returned, and writing it
      // over a mutation that landed mid-pass would revert that mutation's
      // scalars (saveLocalSettings merge-protects only the monotonic
      // fields). Skipping just defers the mint to the next pass.
      if (
        !effective.firstSeenAt &&
        settingsGenRef.current === settingsGen &&
        hasSettingsPulled()
      ) {
        effective = { ...effective, firstSeenAt: new Date().toISOString() };
        saveLocalSettings(effective);
      }
      // Only apply the sync result if no local settings mutation happened
      // while the async sync was in-flight. A stale result would briefly
      // revert the optimistic UI state, causing a visible flicker
      // (e.g. auto-delete toggle snapping back, GitHub #71).
      if (settingsGenRef.current === settingsGen) {
        // syncUserSettings re-parses localStorage, so `effective` is a
        // FRESH object every pass even when nothing changed - handing it
        // to React re-rendered the whole tree on every idle 30 s tick
        // (#141). Keep the previous reference when the content is
        // identical so React bails out of the re-render.
        setUserSettings((prev) =>
          JSON.stringify(prev) === JSON.stringify(effective) ? prev : effective,
        );
      }
      // Skip the vault-sized rebuild when the pass moved nothing: at a
      // few thousand notes refresh() costs ~300 ms of main-thread work,
      // and the 30 s poller was paying it on every idle tick (#130).
      // A mutex-skipped pass (ran: false) proves nothing and skips too.
      if (syncResult.ran && syncResult.changed) {
        const all = await refresh();
        // A pull that rewrote the OPEN note leaves the mounted editor
        // showing pre-pull content: Editor reads `value` at construction
        // only, so editing the stale view forks from the newer server
        // body and manufactures avoidable conflicts (#142). Remount it
        // via the revision key - but only while the editor is idle:
        // never with the body focused, and never while editingBodyRef
        // holds buffered keystrokes (an actively-edited note is dirty,
        // the pull leaves its row alone, and the conflict path is the
        // one that must engage - same contract as resolveConflict above).
        if (
          openNoteId &&
          openNoteId === selectedIdRef.current &&
          openNoteBefore &&
          !editorFocusedRef.current &&
          !editingBodyRef.current.has(openNoteId)
        ) {
          const after = all.find((n) => n.id === openNoteId);
          if (after && after.body !== openNoteBefore.body) {
            setEditorRevision((r) => r + 1);
          }
        }
      }
      // Signal image components to retry any downloads that failed earlier
      // (e.g. images uploaded from another device whose blobs arrived mid-sync).
      window.dispatchEvent(new Event('privacynotes:sync-complete'));
      // Retry quota-failed blob uploads beyond just app boot, gated by a
      // cooldown so repeat quota failures don't re-upload-then-delete on
      // every sync pass. See PENDING_BLOB_RETRY_MS.
      if (syncResult.ran && syncResult.pullOk && !isDemoMode()) {
        const now = Date.now();
        if (now - lastPendingBlobRetryRef.current > PENDING_BLOB_RETRY_MS) {
          const pendingImages = await db.imageDedup.filter((r) => r.pendingUpload === 1).count();
          const pendingAttachments = await db.attachmentDedup.filter((r) => r.pendingUpload === 1).count();
          if (pendingImages > 0 || pendingAttachments > 0) {
            lastPendingBlobRetryRef.current = now;
            imageStoreRef.current?.processPendingUploads().catch((err) =>
              console.warn('[imageStore] post-sync processPendingUploads failed:', err),
            );
            attachmentStoreRef.current?.processPendingUploads().catch((err) =>
              console.warn('[attachmentStore] post-sync processPendingUploads failed:', err),
            );
          }
        }
        // Sweep the deferred blob GC queue (#125). Cheap when the queue is
        // empty (one indexed Dexie query), so no cooldown needed like the
        // pending-upload retry above.
        if (imageStoreRef.current) {
          void sweepBlobGC(imageStoreRef.current, attachmentStoreRef.current).catch((err) =>
            console.warn('[imageGC] sweepBlobGC failed:', err),
          );
          // Reclaim blobs nothing tracks any more - the backstop for every
          // orphan source the queue cannot cover (sign-out wipes it, only the
          // deleting device ever held it, several delete paths never enqueue).
          // Self-throttled to once a day and gated on a provably complete
          // local mirror; see reconcileOrphanBlobs.
          void reconcileOrphanBlobs(
            supabase, auth.pubkey, auth.encryptionKey, imageStoreRef.current,
          ).catch((err) => console.warn('[imageGC] reconcileOrphanBlobs failed:', err));
        }
      }
      // Refresh the quota snapshot so image pre-flight checks have
      // up-to-date numbers. Non-blocking - don't hold up the sync.
      fetchQuotaUsage(supabase, auth.isPro)
        .then((q) => {
          quotaRef.current = { usedBytes: q.totalBytes + q.imageBytes, maxBytes: q.maxTotalBytes };
          if (q.quotaExceededSince) {
            setQuotaExceeded(true);
            setQuotaExceededSince(q.quotaExceededSince);
          } else {
            // Storage back under quota - clear the banner. Fixes #69.
            setQuotaExceeded(false);
            setQuotaExceededSince(null);
          }
        })
        .catch(() => { /* best-effort */ });
      // Check for past_due storage subs alongside quota. See gap #38.
      supabase.rpc('get_storage_sub_status')
        .then(({ data }) => {
          if (data && Array.isArray(data) && data.length > 0 && data[0].has_past_due) {
            setStoragePastDue(true);
          } else if (data && !Array.isArray(data) && (data as { has_past_due?: boolean })?.has_past_due) {
            setStoragePastDue(true);
          } else {
            setStoragePastDue(false);
            setStoragePastDueDismissed(false);
          }
        }, () => { /* best-effort */ });
    } catch (err) {
      // A pass that threw still gets a log entry - the activity list is
      // where "why is nothing syncing" gets answered.
      recordSyncPass({ at: Date.now(), ms: 0, ok: false, up: 0, down: 0 });
      // If the server told us this device was revoked elsewhere, blow
      // up the local session + IndexedDB copy and return the user to
      // onboarding. Any other error is just logged.
      if (err instanceof DeviceRevokedError) {
        await forceSignOut('device revoked');
        return;
      }
      if (err instanceof QuotaExceededError) {
        setQuotaExceeded(true);
        return;
      }
      if (err instanceof SessionExpiredError) {
        // A CAPTCHA demand is a definitive server "no" that only the
        // widget-bearing re-auth flow can answer - never verify it away.
        if (err instanceof CaptchaRequiredError) {
          setSessionExpired(true);
          return;
        }
        // Verify before the hard-block modal. SessionExpiredError is
        // thrown from ten shape-matched classification sites in sync.ts
        // with no grace and no retry, and the 2026-08-25 session audit
        // confirmed transients can wear the right shape (an expired
        // access token seconds before its refresh, clock skew, a
        // proxy-mangled 401 body). One getUser round trip settles it:
        // it refreshes an expired access token as a side effect, so the
        // self-healing cases heal right here. The modal shows only for
        // a dead session (definitive 401/403 or no session at all) or a
        // live session whose pubkey claim is genuinely wrong (the claim
        // gate's escalation case - waiting cannot fix it, because
        // background revalidation already failed to repair the link).
        // An unreachable server is no verdict: skip the modal, the next
        // pass re-checks.
        try {
          const { data: check, error: checkErr } = await supabase.auth.getUser();
          if (!checkErr && check.user) {
            const claimPk = (check.user.app_metadata as { pubkey?: string } | undefined)?.pubkey;
            if (claimPk === auth.pubkey) {
              logAuthEvent('sync:session-expired-suppressed', {
                reason: 'session verified healthy',
              });
              return;
            }
            logAuthEvent('sync:session-expired-claim-mismatch', {
              claimPk: claimPk?.slice(0, 8) ?? null,
            });
            setSessionExpired(true);
            return;
          }
          const checkStatus = (checkErr as { status?: number } | null)?.status;
          const definitive =
            checkErr?.name === 'AuthSessionMissingError' ||
            (checkErr?.name === 'AuthApiError' &&
              (checkStatus === 401 || checkStatus === 403));
          if (definitive) {
            logAuthEvent('sync:session-expired-confirmed', {
              name: checkErr?.name,
              status: checkStatus,
            });
            setSessionExpired(true);
            return;
          }
          logAuthEvent('sync:session-expired-unverifiable', {
            name: checkErr?.name,
            status: checkStatus,
          });
          return;
        } catch {
          // The verification itself blew up (offline mid-call): no
          // verdict, no modal, next pass re-checks.
          logAuthEvent('sync:session-expired-unverifiable', {
            name: 'exception',
          });
          return;
        }
      }
      console.error('[sync]', err);
    } finally {
      endPass();
      setSyncingFlag(false);
      // If this pass surfaced push errors, banner them. If it was clean,
      // clear the prior banner and reset the dismissed key so a future
      // error will surface fresh. See gap #42.
      const pe = passErrors as { count: number; lastMessage: string } | null;
      if (!pe || pe.count === 0) {
        pushErrorsDismissedKey.current = null;
      }
      setPushErrors(passErrors);
      if (passRan) recordPassPushFailures(passFailures);
    }
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [supabase, auth.pubkey, auth.encryptionKey, auth.deviceId, auth.isPro, refresh, forceSignOut, enqueueConflict]);

  /** Resolve a queued note conflict. Called from ConflictModal. */
  const resolveConflict = useCallback(async (conflict: NoteConflict, resolution: 'local' | 'server' | 'both') => {
    const { noteId, localNote, serverUpdatedAt } = conflict;
    // One decision per conflict. Every ConflictModal button calls
    // onResolve AND then onClose, and onClose is wired to a second,
    // contradictory 'server' resolution - so "Use mine" force-pushed the
    // local version and then immediately overwrote the local row with the
    // server's, losing the version the user had just chosen to keep. The
    // guard clears when the first decision finishes, by which point the
    // conflict has left the queue and the modal is gone.
    if (resolvingConflictsRef.current.has(noteId)) return;
    resolvingConflictsRef.current.add(noteId);
    const now = new Date().toISOString();
    try {
      if (resolution === 'local') {
        // Snapshot the key synchronously, before the import await:
        // signOut zeroes auth.encryptionKey in place, and encrypting
        // with a zeroed key pushes undecryptable ciphertext the server
        // accepts as valid. An all-zero snapshot means sign-out already
        // began - bail; the note stays dirty for the next authenticated
        // pass to re-detect. (Sync passes carry their own key copy for
        // the same reason - see sync.ts.)
        const keySnapshot = new Uint8Array(auth.encryptionKey);
        if (keySnapshot.every((b) => b === 0)) {
          console.warn('[conflict] sign-out in progress - keep-mine deferred for', noteId);
          return;
        }
        // The modal asks which BODY to keep. A journal entry's medication
        // log is not part of that question, and the losing side's day was
        // being thrown away with it - so trackers merge field-by-field
        // whichever body wins. Same rule as sync.ts's auto-merge.
        const keptTrackers = mergeTrackers(localNote.trackers, conflict.serverTrackers);
        // Force-push the local version (unconditional update).
        const { encryptNote: enc, bytesToBase64: b64 } = await import('@notes/shared');
        const { ciphertext, nonce } = enc(
          {
            title: localNote.title,
            body: localNote.body,
            tags: localNote.tags,
            trashed: localNote.trashed === 1,
            starred: localNote.starred === 1,
            locked: localNote.locked === 1,
            pinProtected: localNote.pinProtected === 1,
            type: localNote.type ?? 'note',
            trackers: keptTrackers,
            folderId: localNote.folderId ?? null,
          },
          keySnapshot
        );
        const { data: forced, error: forceErr } = await supabase
          .from('notes')
          .update({
            ciphertext: b64(ciphertext),
            nonce: b64(nonce),
            updated_at: now,
          })
          .eq('id', noteId)
          .eq('user_pubkey', auth.pubkey)
          .select('id');
        if (!forceErr && forced && forced.length > 0) {
          await db.notes.update(noteId, { dirty: 0, updatedAt: now, trackers: keptTrackers, syncedNonce: b64(nonce) });
        } else {
          // The write did not land: supabase-js reports network and
          // HTTP failures via `error` without throwing, and a write to
          // a row tombstoned while the modal was open is silently
          // dropped by the 0034 trigger (204, zero rows). Recording
          // either as synced stranded the kept version on this device
          // only, forever, under a green Synced check. Keep it dirty
          // with the fresh timestamp instead: the next pass force-
          // pushes it through the lte guard, or the tombstone pull
          // removes it - sync owns the truth either way.
          console.error('[conflict] keep-mine push did not land for', noteId, forceErr);
          await db.notes.update(noteId, { dirty: 1, updatedAt: now });
        }
      } else if (resolution === 'server') {
        // Accept the server version - write it locally. The tracker
        // payload merges rather than being replaced (see the keep-mine
        // branch above): "use the newer version" is a statement about the
        // text, not a decision to discard this device's medication log.
        const mergedTrackers = mergeTrackers(localNote.trackers, conflict.serverTrackers);
        const trackersDiverged = !trackersEqual(mergedTrackers, conflict.serverTrackers);
        await db.notes.update(noteId, {
          title: conflict.serverTitle,
          body: conflict.serverBody,
          tags: conflict.serverTags,
          trackers: mergedTrackers,
          starred: conflict.serverStarred ? 1 : 0,
          trashed: conflict.serverTrashed ? 1 : 0,
          locked: conflict.serverLocked ? 1 : 0,
          pinProtected: conflict.serverPinProtected ? 1 : 0,
          type: conflict.serverType,
          folderId: conflict.serverFolderId,
          // A merge that added anything is a local change the server has
          // not seen. Leaving it clean would strand it on this device
          // under a green tick - the exact shape of the loss reports.
          updatedAt: trackersDiverged ? now : serverUpdatedAt,
          dirty: trackersDiverged ? 1 : 0,
        });
        // The editor may still be holding a stale in-flight body for this
        // note in editingBodyRef - if we leave it, the next flush writes
        // it back into React state with dirty=1 and re-pushes it, silently
        // undoing the "use newer" choice. Clear the buffer and reload from
        // Dexie (same pattern as the history-restore path below) so the
        // open editor re-renders the server content instead.
        if (selectedId === noteId) {
          editingBodyRef.current.delete(noteId);
        }
        // Order matters: reload state BEFORE bumping the editor key. The
        // bump remounts the editor with whatever body React state holds
        // at that render - bumping first remounted it with the stale
        // local body, and the fresh server body arriving one render
        // later was ignored (Editor treats `value` as initial content).
        await refresh();
        if (selectedId === noteId) {
          setEditorRevision((r) => r + 1);
        }
      } else {
        // Keep both: accept server version for the original note,
        // create a duplicate with the local version. Capture the freshest
        // local content first (buffered keystrokes, else the current Dexie
        // row, else the conflict snapshot) so the duplicate doesn't lose
        // anything typed after the conflict was detected.
        const buffered = editingBodyRef.current.get(noteId);
        const row = await db.notes.get(noteId);
        const freshBody = buffered ?? row?.body ?? localNote.body;
        const freshTitle = row?.title ?? localNote.title;
        // The whole tracker payload lands on the ORIGINAL, merged from
        // both sides. It used to be overwritten with the server's copy
        // here and forked into the duplicate from a stale snapshot, so
        // this device's medication log for the day ended up on neither
        // note the user was looking at. `row` is the freshest local copy.
        const keptTrackers = mergeTrackers(
          (row?.trackers as Record<string, unknown> | undefined) ?? localNote.trackers,
          conflict.serverTrackers
        );
        const trackersDiverged = !trackersEqual(keptTrackers, conflict.serverTrackers);
        await db.notes.update(noteId, {
          title: conflict.serverTitle,
          body: conflict.serverBody,
          tags: conflict.serverTags,
          trackers: keptTrackers,
          starred: conflict.serverStarred ? 1 : 0,
          trashed: conflict.serverTrashed ? 1 : 0,
          locked: conflict.serverLocked ? 1 : 0,
          pinProtected: conflict.serverPinProtected ? 1 : 0,
          type: conflict.serverType,
          folderId: conflict.serverFolderId,
          updatedAt: trackersDiverged ? now : serverUpdatedAt,
          dirty: trackersDiverged ? 1 : 0,
        });
        // Same stale-buffer hazard as the 'server' branch above - clear it
        // and reload so the open editor shows the resolved server content
        // rather than the body that just got forked into the duplicate.
        if (selectedId === noteId) {
          editingBodyRef.current.delete(noteId);
        }
        // Reload before the key bump - same ordering rationale as the
        // 'server' branch above.
        await refresh();
        if (selectedId === noteId) {
          setEditorRevision((r) => r + 1);
        }
        // Create the duplicate with local content.
        const suffix = ' (conflict)';
        const dupTitle = (freshTitle || 'Untitled') + suffix;
        const dup = await createNote(
          dupTitle,
          freshBody,
          localNote.tags,
          localNote.starred === 1,
          localNote.type ?? 'note',
        );
        // The duplicate is deliberately a BODY fork with no tracker
        // payload. The merge above already carries both sides' trackers
        // on the original, and copying them here would give a journal
        // entry a twin with the same `journalDate` - two entries for one
        // calendar day, which every statistic then has to collapse.

      }
    } catch (err) {
      console.error('[conflict] resolution failed for', noteId, err);
    } finally {
      resolvingConflictsRef.current.delete(noteId);
    }
    // Remove from queue.
    setConflictQueue((q) => q.filter((c) => c.noteId !== noteId));
    await refresh();
  }, [supabase, auth.pubkey, auth.encryptionKey, refresh, selectedId]);

  // Fold back any body edit stashed by the close-flush path
  // (flushStash.ts). Runs once at mount; an applied stash marks the
  // note dirty, so the next pass pushes it like any other edit.
  useEffect(() => {
    void reconcileFlushStash().then((applied) => {
      if (applied) void refresh();
    });
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Re-sync when connectivity returns so offline edits land immediately.
  // Also poll every 30s so changes from other devices appear without a
  // manual refresh (GitHub #45). Skip ticks while the tab is hidden to
  // save battery; fire immediately on visibilitychange→visible instead.
  useEffect(() => {
    const onOnline = () => void runSync();
    window.addEventListener('online', onOnline);

    // "Files on wifi only": the moment wifi returns, drain the held
    // upload queues instead of waiting out the post-sync retry cooldown.
    const onWifiRestored = () => {
      imageStoreRef.current?.processPendingUploads().catch(() => { /* retried next pass */ });
      attachmentStoreRef.current?.processPendingUploads().catch(() => { /* retried next pass */ });
    };
    window.addEventListener('privacynotes:wifi-restored', onWifiRestored);

    const SYNC_POLL_MS = 30_000;
    const tick = () => { if (!document.hidden) void runSync(); };
    const interval = setInterval(tick, SYNC_POLL_MS);

    const onVisibility = () => { if (!document.hidden) void runSync(); };
    document.addEventListener('visibilitychange', onVisibility);

    return () => {
      window.removeEventListener('online', onOnline);
      window.removeEventListener('privacynotes:wifi-restored', onWifiRestored);
      clearInterval(interval);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [runSync]);

  return {
    refresh,
    runSync,
    resolveConflict,
    quotaExceeded,
    setQuotaExceeded,
    quotaExceededSince,
    setQuotaExceededSince,
    sessionExpired,
    pushErrors,
    setPushErrors,
    pushErrorsDismissedKey,
    conflictQueue,
    enqueueConflict,
    storagePastDue,
    storagePastDueDismissed,
    setStoragePastDueDismissed,
    freshVaultNotice,
    setFreshVaultNotice,
    settingsGenRef,
    quotaRef,
  };
}
