> Status: living reference. Last verified: v0.413.2 (2026-08-19, #156 equal-stamp fix verified against the simulator; prior full verification v0.294.1 2026-08-04, `changed_at` becomes a pure server clock via trigger - migration 0066; session claim gate, key-copy-per-pass, cursor persists at end of pull, heal flags commit only after a clean sweep, suspend/resume around the sign-out wipe, guarded auto-merge and keep-mine writes). Section 7 amended 2026-08-19: the LWW bullet gained its precise firing condition, and the equal-stamp divergence limit (#156) was closed the same day (monotonic edit stamps + syncedNonce echo detection), both simulator-pinned. Section 6's shared-browser hazard list was corrected against the at-rest seal on 2026-08-31: the blob caches are ciphertext at rest, and the rest of the section stands. Not yet measured in a browser: the per-note push in step 4 runs at `PUSH_CONCURRENCY = 8` rather than strictly serially (backlog #129). Treat that paragraph as unverified until the measurement protocol in backlog #129 has been run.

# Sync protocol

How notes move between IndexedDB and Supabase, how deletes propagate
across devices, and how cross-user contamination on shared browsers is
prevented. Anything in this doc that contradicts the source is a bug
in the doc - primary source of truth is `packages/web/src/sync.ts` plus
the migrations referenced inline.

---

## 1. Shape

Single Postgres table - `public.notes` - holds encrypted ciphertext +
nonce per row, keyed by client-generated UUID, scoped by
`user_pubkey`. Schema (current):

| Column        | Type        | Notes                                              |
|---------------|-------------|----------------------------------------------------|
| `id`          | uuid        | Client-generated; same id used in IndexedDB        |
| `user_pubkey` | text        | Owner. RLS keys off `app_metadata.pubkey` claim    |
| `ciphertext`  | text        | base64 of `xchacha20poly1305(plaintext, key)`      |
| `nonce`       | text        | base64                                             |
| `created_at`  | timestamptz | Client-set on first push                           |
| `updated_at`  | timestamptz | Client-set on every write                          |
| `deleted_at`  | timestamptz | Tombstone. NULL = live. Set on permanent delete    |

Plaintext `title`, `body`, `tags`, `trashed`, `starred`, `locked`,
`pinProtected`, `type`, and `trackers` all ride inside the encrypted
payload. The server never sees them.

Local mirror lives in Dexie (`packages/web/src/db.ts`, table `notes`)
with extra bookkeeping columns: `dirty` (1 = unsynced local change),
`deleted` (1 = local-side tombstone awaiting push), `trashed`,
`starred`, etc. The client-side `deleted` flag is a transient state
between "user permanently deleted" and "next sync pushed the
tombstone." After a successful push the row is `bulkDelete`d locally.

---

## 2. Pull-then-push, last-write-wins

Each sync pass runs in this order:

0. **Session claim gate.** Before any server call, the pass reads the
   Supabase session and requires `app_metadata.pubkey` to equal the
   vault's pubkey. This is the guard migration 0064 made necessary:
   under a missing or foreign claim RLS does not error, it silently
   filters every row to nothing, so a blind pass would pull an empty
   vault, false-confirm tombstones against a blind confirming SELECT,
   and classify every dirty row as never-uploaded. A failing gate
   SKIPS the pass (no reads, no writes - the blindness cannot do
   damage); it only escalates to `SessionExpiredError` after three
   consecutive strikes, riding out the fast-boot window where the app
   renders while `authenticateWithPhrase` is still re-minting the
   session. A `getSession` refresh that failed because the server was
   UNREACHABLE (offline, captive portal, outage) never counts as a
   strike at all: an unreachable server is not a verdict about the
   session, and offline use must never demote it. Applies to
   flush-only passes too, which skip quietly and never throw.
1. **Heartbeat.** `device_heartbeat` RPC. Fired in parallel with the
   phase-1 pull request (saves a round-trip), but its verdict is
   awaited before any pulled row is processed. If the server says this
   device row is gone (revoked from another device, banned, account
   deleted), throw `DeviceRevokedError` and abort - the in-flight pull
   response is discarded, nothing is written. The caller force-signs
   out. Only an explicit `false` from a caller the server could
   identify counts as that verdict: since migration 0064 a missing
   `app_metadata.pubkey` claim RAISEs instead, and every RPC error
   fails **open** (`return true`). A client that cannot prove who it is
   has learned nothing about whether it was revoked, and treating that
   as revocation silently wiped sessions back to onboarding - see
   design-decisions.md (heartbeat revocation verdict).
2. **Pull.** Fetch all rows where `changed_at > cursor`, **oldest
   first**, keyset-paging on `(changed_at, id)`. Phase 1 takes the
   first 100 and renders immediately; phase 2 sweeps the rest in
   500-row pages with no intermediate renders. Apply tombstones
   (`bulkDelete`) and upserts (`bulkPut`).

   `changed_at` (migration 0065, redefined by 0066) is a pure
   server-assigned change clock: a BEFORE INSERT OR UPDATE trigger
   stamps `now()` on every write, and no client value can influence it.
   It replaces the three ORed filter clauses. 0065 first shipped it as
   `GREATEST(updated_at, deleted_at, ingested_at)`, but two of those
   inputs are client-written, which broke the sweep's invariant twice
   over: an edit made offline and pushed hours later landed with its
   edit-time `updated_at` behind every peer cursor (permanently
   invisible, and a later stale-base edit then destroyed the hidden
   content everywhere), and a skewed clock on delete either stranded
   the tombstone behind peer cursors or inflated every peer's cursor
   into the future. Server time only, by trigger, closes the whole
   class; `updated_at` stays fully client-authoritative for
   last-write-wins.

   **Ascending and keyset, not DESC and offset, is the whole point.**
   Offset paging assumes the result set holds still. It does not: a
   device pushing concurrently rewrites `updated_at` to `now()`, which
   moves that row to the front of a DESC ordering and shoves unread
   rows past the window the reader has already passed. Those rows are
   never returned, and the cursor then advances beyond them, so no
   later filter can match them. The client reports "Synced" while
   silently holding stale copies forever - measured in production
   2026-08-03 with a second client at 503 of 525 rows stale, its
   cursor exactly equal to the newest server timestamp. Sorting
   ascending inverts it: a write can only move a row **forward**,
   toward rows the sweep has not reached, so it can never hide one.

   **The keyset is compound because ties are guaranteed.** A bulk
   import or bulk trash commits in one transaction, so hundreds of rows
   share a `changed_at` to the microsecond. Paging on `changed_at`
   alone would skip a whole tie group at a page boundary or spin on it
   forever.
3. **Advance cursor.** Immediately after the pull, BEFORE the push
   phase: a push that throws (quota freeze, expired session) must not
   cost the pull its progress, or a quota-frozen account with one
   dirty row re-pulls its entire vault on every pass. Only if the pull
   succeeded. Cursor is `localStorage.privacynotes.lastSync`, stored
   as `<changed_at>|<id>` - the last row the sweep actually
   **applied**, not the maximum timestamp it saw. Both halves are
   server-assigned rather than the client clock, which would
   reintroduce the skew gap from #127. Because the cursor never moves
   past an applied row, an interrupted pull resumes exactly where it
   stopped; the cost of a failed page is re-reading a few pages, which
   is idempotent. The write is generation-gated (`suspendSync` in
   sync.ts): a pass that outlives sign-out must not re-create the
   cursor after the wipe removed it, or the locally wiped rows sit
   behind the resurrected cursor forever on the next same-user
   sign-in. The heal flags (`ingestedHeal`, `keysetHeal`) commit at
   this same point, only alongside a clean sweep - consuming them up
   front voided the one-time full re-read whenever the healing pull
   itself failed or was aborted.

   Values written before 0065 are a bare timestamp with no `|`. They
   parse as "that instant, no id", which re-reads one instant - safe,
   where guessing an id could skip a row. A one-time
   `privacynotes.keysetHeal` flag additionally resets the cursor to
   epoch once per device, because rows stranded behind the old offset
   race are already past the cursor and only a full re-read recovers
   them (same shape as the 0063 heal in section 4).
4. **Push.** Read all dirty rows. Split into tombstones (`deleted = 1`
   locally) and live edits. Tombstones go out in batches of 50, as
   described in section 3. Live edits are partitioned by one batched
   existence probe (`select('id').in('id', ids)`, 200 ids per request):
   ids the server does not have yet are **bulk-inserted in chunks of
   50**, because a row that does not exist server-side has nothing to
   conflict with; everything else goes through the per-note conditional
   update (`lte` guard on `updated_at`) that detects conflicts. A failed
   insert batch falls back to the per-note path so one oversized or
   malformed row cannot fail its neighbours, and a failed probe falls
   back entirely rather than risk bulk-inserting over live rows.
   Before this split every first-time push cost up to three sequential
   round-trips (conditional update that matches nothing, select to find
   out why, insert), so a 500-note import was ~1500 serial requests and
   took minutes while each pass still reported success.

   The bulk-insert split helps only notes the server has NEVER seen -
   `pending` is explicitly `toUpsert.filter((n) => known.has(n.id))`.
   Every note the server already has still goes one per round trip, so
   the per-note path is run with **bounded concurrency**
   (`PUSH_CONCURRENCY = 8`) rather than strictly serially. Sequentially,
   a bulk action over existing notes (trash 500, restore 500, star 500,
   retag 500, move 500 to a folder) cost 500 serialized round trips with
   the sync mutex held, roughly 40 s at an 80 ms RTT - which is what
   backlog #129 was actually hitting, in the bulk-trash step rather than
   the empty-trash step it named. Concurrency is safe because each push
   is independent and order-free: the `lte` guard, the zero-rows
   conflict probe and the `clearDirty` timestamp re-check are all keyed
   on a single `note.id`, and no cross-note ordering exists server-side
   either, since every write gets its own trigger-stamped `changed_at`
   and the pull applies rows one at a time. The first
   `SessionExpiredError` or `QuotaExceededError` stops workers claiming
   further notes and is re-thrown once the pool drains, matching the old
   loop's throw; requests already in flight are allowed to settle, since
   abandoning one could skip `clearDirty` on a write the server accepted.
   Spec: `ops/docs/design-decisions.md` (sync push concurrency).

   The conflict path's auto-merge writes carry the same `lte` guard
   plus `.select('id')` as the main conditional update: unguarded,
   they overwrote a newer version pushed by another device in the
   window since the conflict read, and a merge the 0034 trigger
   silently dropped looked identical to success. Zero merged rows
   means the server moved again - the note stays dirty and the next
   pass re-detects. When no conflict handler is wired (the sign-out
   rescue flush), a conflicted note is left dirty rather than resolved
   server-wins: overwriting the local body and clearing dirty moments
   before the wipe destroyed the unsynced edit on both sides, because
   `keepUnsyncedNotes` can only rescue rows still flagged dirty.

Conflict policy is last-write-wins on `updated_at`, with a safety
valve: the conditional push detects when the server is newer, metadata
and title-only divergence auto-merges (guarded, see step 4), and a
body-vs-body conflict surfaces the ConflictModal (keep mine / keep
server / keep both). "Keep mine" verifies its force-push actually
landed (`.select('id')`); a write that did not land leaves the note
dirty instead of recording an unpushed version as synced. Tombstones
override local edits - if a note was permanently deleted on device A,
an offline edit on device B is discarded along with the row on B's
next sync.

### Flush-only mode

`sync(..., { flushOnly: true })` runs ONLY the push phase: no
heartbeat, no pull, no cursor advance. Sign-out uses it to rescue
unsynced rows before the local wipe. Skipping the heartbeat gate is
the point, not an optimization: a revoked device throws
`DeviceRevokedError` at that gate before the push phase ever runs,
but its JWT still authorizes note writes (notes RLS keys off the
`app_metadata.pubkey` claim only, never the devices table), so its
dirty rows can still be saved. Do not "fix" flush-only by adding the
heartbeat back.

---

## 3. Tombstone lifecycle (migration 0034)

Before v0.117.0, "permanently delete" used `.delete()` to physically
remove the row. Other devices had no way to learn about the deletion
through the standard pull (which filtered `updated_at > lastSync`),
so they kept stale local copies forever. Touching a stale copy
re-upserted the row and resurrected it server-side.

Current behavior:

1. **Client side, soft-delete intent.** `permanentlyDelete(id)` /
   `bulkPermanentlyDelete(ids)` / `emptyTrash()` set the local row
   `{ deleted: 1, dirty: 1, updatedAt: now }`. The row is hidden from
   `listNotes()` but still in Dexie until the push completes.
2. **Push tombstone.** Sync push sends
   `update({ deleted_at: now() }).in('id', ids).is('deleted_at', null)
   .select('id')`.
   The `.is('deleted_at', null)` clause makes the operation idempotent:
   rows already tombstoned by another device are silently skipped
   without an error. **`.select('id')` is load-bearing** and only Dexie
   rows the server names in the response are deleted locally. Without
   it PostgREST answers 204 with no body and no row count, so an UPDATE
   that matched nothing is indistinguishable from one that tombstoned
   every row - and the old code `bulkDelete`d the local tombstones
   either way, destroying the only record that the delete was still
   pending. Ids the UPDATE did not return get one confirming SELECT:
   absent means gone (nothing to tombstone, or another device got
   there first) and is safe to drop locally; still present with
   `deleted_at IS NULL` means the delete was rejected - typically RLS
   under a session whose pubkey link is broken - so the row stays dirty
   and is reported through `onPushError` for the next pass.
3. **Other devices pull tombstone.** Their next pull's OR filter
   matches the tombstone row. `processBatch` sees `deleted_at !==
   null`, pushes the id to `tombstoneIds`. Caller calls
   `db.notes.bulkDelete(tombstoneIds)`. The note disappears from the
   second device's UI on that sync's render pass.
4. **30-day server purge.** `pg_cron` job `purge_deleted_notes` runs
   nightly at 04:23 UTC (see `ops/docs/cronjobs.md`) and hard-deletes
   rows where `deleted_at < now() - interval '30 days'`. 30 days is
   long enough for any reasonable offline-and-back-online window.

### Resurrection guard

Migration 0034 also installs a BEFORE UPDATE trigger
(`block_writes_to_deleted_notes`) on `public.notes`. It returns NULL
when `OLD.deleted_at IS NOT NULL`, silently dropping any UPDATE
targeting a soft-deleted row.

This closes the offline-edit-after-remote-delete vector: device B was
offline, made an edit, came back online, and tried to upsert the row.
Without the trigger, the upsert (`INSERT ... ON CONFLICT (id) DO
UPDATE SET ...`) would rewrite the ciphertext and "resurrect" the
note - even though `deleted_at` would still be set, the row would
have a fresh `updated_at`, and other devices pulling it would see
new content for an already-deleted note. The trigger drops the UPDATE
silently (no error to the sync push), so device B's offline edit is
discarded and the next pull tells device B the note is gone.

We `RETURN NULL` rather than `RAISE EXCEPTION` because surfacing the
race as a hard sync failure would be confusing - the user's intent
was already invalidated by the prior delete elsewhere; a silent
discard plus the next-pull tombstone is the right UX. If we ever want
a "your edit was discarded because the note was deleted" toast, the
hook is to detect `tombstoneIds` containing an id that was also in
the recent push payload during the same sync pass.

---

## 4. Backdated rows and `ingested_at` (migration 0063)

`updated_at` is client-authoritative (0002 dropped the server trigger,
because last-write-wins needs the client's edit time) and it doubled as
the pull cursor. Those two jobs conflict whenever a row's edit time is
older than its arrival time.

Importers preserve the source app's modification date on purpose, so a
note imported today can land on the server with `updated_at = 2023`. A
device whose cursor already sits at "now" asks for rows newer than now,
the server correctly answers "none", and the note stays on the server
intact but permanently invisible to that device. Only devices that
synced *before* the import are affected - a fresh device pulls from
epoch and sees everything, which is why this went unnoticed until a
user imported a multi-year Notesnook vault onto a phone that was
already caught up. It affected every importer that keeps source
timestamps, plus `.pnbackup` restore.

This is the same structural failure as hard-deletes in section 3 (a row
whose meaningful change time is not in `updated_at`), and takes the same
fix: `ingested_at`, ORed into the pull filter and tracked in the cursor
advance.

- **Server-assigned only.** `DEFAULT now()`, never sent by the client.
  The push `.update()`s only `ciphertext`/`nonce`/`updated_at`, and the
  first-push `.insert(row)` omits the column, so an edit never resets
  arrival time. Arrival time and edit time stay independent, and the
  user keeps their real 2023 date and their sort order.
- **The column fixes future imports; it does not heal past ones.** Rows
  already stranded on the server with an old `updated_at` cannot be
  rescued by any filter clause, because the affected device's cursor is
  already past them. Recovery is a one-time full pull, triggered by the
  `privacynotes.ingestedHeal` localStorage flag in `sync.ts`. It runs
  once per device and cannot clobber anything: `processBatch` skips rows
  where `local.dirty === 1` or `local.updatedAt >= row.updated_at`. The
  re-pull cost is negligible at current scale (the whole `notes` table
  was ~13k rows fleet-wide when this shipped), so do not treat it as a
  reason to weaken the heal.
- **Do not "simplify" the heal into a `now()` backfill.** Backfilling
  `ingested_at = now()` looks like it heals stranded rows (they would
  match `ingested_at.gt.lastSync`) but it races and fails silently: the
  cursor advances to the max `updated_at` of any pulled row, so a user
  who edits one note between the migration and their client upgrade
  moves their cursor past the backfill and stays broken forever. The
  client flag does not care when the device upgrades. Backfill is
  `updated_at`.
- **The 0034 trigger had to be disabled for the backfill.** It silently
  `RETURN NULL`s writes to soft-deleted rows, so a plain `UPDATE` would
  have skipped every tombstone and then failed `SET NOT NULL`.
- **Deploy order: migration before web deploy.** The new client filters
  on `ingested_at`; against a database without the column PostgREST 400s
  and every pull fails. The reverse order is harmless.
- **Old clients do not self-heal.** A device still running a build
  without the `ingested_at` filter and the heal flag stays blind to its
  stranded notes until it updates. This is why the Android direct APK's
  update prompt (`AndroidUpdateToast`) matters more than it looks: a
  sideloaded user who never gets the prompt never gets the fix.

Do not "simplify" this by stamping `updatedAt = now` at import time
(`import/apply.ts`). That fixes sync by destroying the chronology the
importers parse, makes an entire imported vault read "modified today",
and does nothing for users already stranded.

`import/apply.ts` deliberately keeps passing the source `updatedAt`
through. That is correct and must stay correct - the fix belongs in the
cursor, not in the data.

The deeper flaw is unfixed: `updated_at` is still a plaintext column
doing triple duty as cursor, conflict guard, and user-visible edit date.
Moving the display timestamp into the encrypted blob and leaving the
plaintext column as a pure server-assigned sequence would resolve it,
and would close the metadata leak where the server sees exact edit times
for every note. That is a much larger migration with a
backward-compatibility window for old clients.

---

## 5. Trash vs permanent delete

Two distinct flows:

- **Trash** (`trashNote`, `bulkTrash`): sets `trashed = 1` inside the
  encrypted payload, bumps `updated_at`. The server row stays. Other
  devices pull the new ciphertext and decode `trashed: true`. The
  note moves to the Trash bin on every device. Reversible via
  `restoreNote`. No tombstone involvement.
- **Permanent delete** (`permanentlyDelete`, `bulkPermanentlyDelete`,
  `emptyTrash`): sets the client-side `deleted = 1, dirty = 1`. Sync
  push converts that into a server-side `deleted_at` UPDATE (a
  tombstone). Not reversible. After 30 days the row is hard-deleted
  by `pg_cron`.

The two flags are unrelated. A note can be trashed for weeks and
never permanently deleted; permanently deleting from the trash bin
is a separate user action that triggers the tombstone path.

---

## 6. Cross-user IndexedDB safety (v0.117.0)

The Dexie database name is the constant `'privacynotes'` (see
`db.ts`). It is **not** scoped by pubkey. Every user signed-in on a
given browser shares the same database. Without explicit handling,
this leaks data across users on shared browsers in three ways:

1. **Dirty notes from prior user push under new pubkey.** User A
   types and never syncs. User B signs in (same browser, no signOut).
   B's first sync push includes A's `dirty=1` rows. They land in
   the server `notes` table under B's pubkey.
2. **Blob caches survive sign-out.** `imageCache` and
   `attachmentCache` hold what the prior user opened. The bytes seal
   at rest under that user's key, so a reader with browser access
   (DevTools → Application → IndexedDB) meets ciphertext; rows written
   before the seal existed stay readable until the sweep converts
   them.
3. **Pending-upload re-encryption.** Cached blobs with `pendingUpload
   = 1` get retried on every `ImageStore` / `AttachmentStore` init
   (`processPendingUploads`). On a shared browser, that init runs
   under the *new* user's encryption key + pubkey, encrypting and
   uploading the prior user's plaintext into the new user's storage
   bucket and quota.

### Pubkey-owner check

`localStorage.privacynotes.currentPubkey` records which pubkey
"owns" the local IndexedDB. At the top of `_authenticateWithPhrase`
(covers both phrase sign-in and OAuth-derived sign-in via
`hydrateFromOAuthSession`), the new pubkey is compared to the stored
owner. On mismatch:

1. `clearLocalDatabase()` - wipes `notes`, `imageCache`, `imageDedup`,
   `attachmentCache`, `attachmentDedup` (rows only, schema preserved
   so Dexie stays usable).
2. `clearLocalSettings()` - clears the cached `user_settings` blob.
3. `localStorage.removeItem('privacynotes.lastSync')` and the
   sessionStorage variant - forces the next pull to scan from the
   epoch.
4. `supabase.auth.signOut({scope: 'local'})` - drops the cached anon
   session that still carries the prior user's
   `app_metadata.pubkey` claim until `link-pubkey` overwrites it.

After the wipe, `currentPubkey` is set to the new pubkey and
authentication proceeds normally. Same-user re-sign-in compares
equal and skips the wipe - the cache survives, image fetches stay
fast.

### sign-out behavior

`signOut()` calls `clearLocalDatabase()` (not just `db.notes.clear()`
as it did before v0.117.0). Since v0.286.0 the wipe is preceded by a
flush-only sync (10s budget when dirty rows exist), and FORCED
sign-outs (device revoked, session expired, device-cap dead end) pass
`keepUnsyncedNotes`: rows with `dirty=1` and never-uploaded blobs
(pendingUpload=1 dedup records plus their cached bytes) survive the
wipe, because destroying data the server never confirmed is permanent
loss the user did not choose. A same-pubkey re-sign-in pushes the
survivors; a different user signing in still gets the unconditional
owner-mismatch wipe at the top of `_authenticateWithPhrase`, which is
the backstop that keeps this compatible with the three hazards above -
never make that wipe dirty-aware. Voluntary sign-out (confirmed
through SignOutConfirmModal, which shows the unsynced count) still
wipes everything. The four cache tables are wiped on every sign-out so
that:

- DevTools-fluent attackers on a shared device can't read the prior
  session's images after the user signs out.
- `processPendingUploads` on the next sign-in finds no pending
  records and can't re-encrypt prior-session bytes under the next
  user's key.

Two sign-out races are closed in code, not by timing. First, every
sync pass encrypts with a **private copy** of the encryption key
(`sync.ts`), because `signOut` zeroes the caller's buffer in place
once its flush budget expires - a pass still pushing at that moment
used to encrypt the remaining dirty notes with the zeroed key and
overwrite good server ciphertext with permanently undecryptable bytes.
Second, `signOut` calls `suspendSync()` before the wipe: the in-flight
pass (if the flush lost its mutex race against it) finishes its writes
but is generation-blocked from persisting the cursor, and new passes
no-op until `resumeSync()` at the end of sign-out or the start of the
next authentication. Without that, a pass outliving sign-out
re-created `privacynotes.lastSync` after the wipe removed it, and the
wiped rows sat behind the resurrected cursor forever on the next
same-user sign-in.

`PUBKEY_OWNER_KEY` is **not** cleared on sign-out. This is on purpose:
when User A signs out and walks away, A's pubkey stays recorded so
the mismatch check still fires correctly when User B signs in later.
Same-user re-sign-in continues to skip the wipe.

The trust flag, biometric blob, and PIN-wrapped phrase blob have
their own lifecycles - see `auth.tsx::signOut` and `biometric.ts`.
Out of scope for this doc.

---

## 7. Known limits / accepted trade-offs

- **Last-write-wins drops concurrent edits.** No CRDT, no conflict
  UI. If you edit the same note on two offline devices simultaneously,
  one of the edits is silently lost. Documented in `ops/docs/roadmap.md`.
  Precisely: the ConflictModal fires only when the EARLIER-stamped edit
  pushes second (the `lte` guard finds the server newer); a LATER-stamped
  edit pushing second overwrites silently. Both orderings are pinned by
  `tests/sync/scenarios-concurrent-edit.test.ts` (2026-08-19, the #139
  investigation).
- **Equal-timestamp concurrent edits converge by push order (#156,
  fixed 2026-08-19).** The push guard passes on equality, so the second
  pusher wins the tie by push order - unchanged. What #156 fixed is the
  divergence that used to follow: the loser's pull-apply skip
  (`local.updatedAt >= row.updated_at`) never applied the winning row,
  leaving both devices clean with different bodies until the next edit.
  Two mechanisms close it. (1) Edit stamps are strictly monotonic per
  row: `nextStamp` in `notesRepo.ts` stamps `max(now, current + 1ms)`
  on every edit path, so one device (or two windows sharing one
  IndexedDB) can never produce two generations with an equal stamp.
  (2) For genuinely cross-device ties, the client records the nonce of
  the server generation its row matches (`LocalNote.syncedNonce`, set
  on push success and pull apply); the pull-apply skip on an EQUAL
  stamp now applies the row when its nonce differs from the recorded
  one - a foreign write that won the tie - and still skips the row when
  the nonce matches (our own echo) or when no nonce was ever recorded
  (pre-upgrade rows; keeps cursor heals from re-applying the vault).
  The loser's copy is dropped in favor of the winner - the LWW residual
  above, minus the divergence. Pinned green by
  `tests/sync/scenarios-concurrent-edit.test.ts` (tie-break pin + the
  promoted convergence scenario).
- **Resurrection-blocked edits are silently discarded.** Offline edit
  on a note deleted elsewhere → the edit is dropped, no toast. The
  note disappears on the next pull. Acceptable for MVP; future hook
  is described in §3.
- **`lastSync` cursor uses server-side values, never the client clock
  (v0.173.20+, keyset since 0065).** It advances to the `(changed_at,
  id)` of the last row actually applied. This eliminates the clock-skew
  vulnerability where a forward-drifting client clock could permanently
  skip rows.
- **The sweep's safety rests on `changed_at` never moving backwards,
  and since 0066 that holds by construction.** An ascending keyset can
  only be skipped by a row that appears at a position the sweep has
  already passed. `changed_at` is stamped `now()` by trigger on every
  INSERT and UPDATE and no client value can influence it, so a change
  always surfaces ahead of every cursor regardless of the writing
  device's clock or how stale its `updated_at` is. (0065's original
  GREATEST definition mixed in the client-written `updated_at` and
  `deleted_at`, which let a delayed edit push or a skewed clock land a
  change behind peer cursors - the class of silent stranding 0065 was
  meant to close. Do not reintroduce client input into this column.)
- **Commit order can differ from `now()` order by milliseconds.** Two
  concurrent transactions can be assigned `changed_at` in one order and
  become visible in the other, so a sweep landing in that window could
  pass a row that commits just behind it. The window is sub-second and
  no occurrence has been observed; the fix, if it ever matters, is to
  persist the cursor a second or two behind the newest row applied and
  accept the idempotent re-reads.
- **`signOut` cache wipe is a small perf hit on re-sign-in.** First
  paste-of-same-image after re-sign-in re-uploads instead of
  dedup-hitting; image renders re-download on demand. Trade-off is
  intentional - privacy hygiene wins.
- **`PUBKEY_OWNER_KEY` survives `signOut`** so different-user
  detection works even after a clean sign-out. This is a tiny
  metadata leak (the pubkey of the last user of this browser is
  visible in localStorage) but the pubkey itself is not a secret -
  the server already has it, and possessing it grants no access
  without the encryption key.

---

## 8. Reference

- Source: `packages/web/src/sync.ts`,
  `packages/web/src/auth.tsx::_authenticateWithPhrase`,
  `packages/web/src/notesRepo.ts::clearLocalDatabase`.
- Schema: `packages/supabase/migrations/history/0034_note_tombstones.sql`,
  plus `0001_init.sql` for the base `notes` table.
- Cron job: `ops/docs/cronjobs.md` → `purge_deleted_notes`.
- Threat model context: `ops/docs/THREAT_MODEL.md`.
- Audit history: gap #1 closed by v0.117.0 (the old gaps.md was removed; details in changelog).
