import { useCallback, useEffect, useRef } from 'react';
import type { SupabaseClient } from '@notes/shared';
import type { LocalNote } from './db';
import type { JournalTrackerData } from './trackerTypes';
import { bulkRewriteBody, getNote, updateNote, updateNoteFrom } from './notesRepo';
import { createNoteVersion } from './noteVersions';
import { isDemoMode, proUnlocked } from './demo';
import { gcOnBodyChange, holdBlobsForVersion, markVersionActivity } from './imageGC';
import { noteLinkKey, retargetNoteLinks } from './noteLinks';
import { hasStructuredBody, noteLinkName } from './notesViewUtils';
import { changesContent, trackerContent } from './editStamp';
import { dropPendingEdit, setEditorBaseLookup, settlePendingEdit, stashGeneration } from './flushStash';
import { isBigLoss, LOSS_GAP_MS, planVersion, type VersionSession } from './versionSchedule';
import type { ImageStore } from './imageStore';
import type { AttachmentStore } from './attachmentStore';

interface UseNoteEditingArgs {
  auth: { isPro: boolean; pubkey: string; encryptionKey: Uint8Array };
  supabase: SupabaseClient;
  notes: LocalNote[];
  setNotes: React.Dispatch<React.SetStateAction<LocalNote[]>>;
  saveTimer: React.MutableRefObject<number | null>;
  lastSyncAt: React.MutableRefObject<number>;
  runSync: () => Promise<void>;
  imageStoreRef: React.RefObject<ImageStore | null>;
  attachmentStoreRef: React.RefObject<AttachmentStore | null>;
  /** Called when a snapshot insert is rejected by RLS (Pro lapsed
   *  mid-edit). Caller decides how to surface - typically a one-time
   *  banner explaining that history is paused. See gap #6. */
  onSnapshotForbidden?: () => void;
  /** An open editor tried to save over a row that changed under it (a pull
   *  stored another device's version). The row is left alone; this keeps the
   *  editor's text as a copy and brings the editor up to date. `body` is null
   *  when the editor held nothing the row does not supersede. Resolves with
   *  the copy's id, or null when none was made. */
  onStaleEditorWrite?: (current: LocalNote, body: string | null) => Promise<string | null>;
}

interface UseNoteEditingReturn {
  handleTitleChange: (id: string, title: string) => Promise<void>;
  /** Remember the title a note carries, so a later blur can tell whether
   *  it was renamed. Call from the title field's focus handler. */
  handleTitleFocus: (id: string) => void;
  /** Commit a rename: point every note-link that named the old title at the
   *  new one. Resolves with the number of notes rewritten. */
  handleTitleBlur: (id: string) => Promise<number>;
  /** Save a body. An editor passes its `editorKey`, and the save is refused
   *  when the row no longer holds the body that editor last loaded or wrote. */
  handleBodyChange: (id: string, body: string, editorKey?: string) => Promise<void>;
  /** Record the body an editor mount shows, when it mounts. */
  registerEditorBody: (editorKey: string, body: string) => void;
  /** The open editor of this note now shows `body`: the app replaced its
   *  text in place, so its next save starts from there. */
  resetEditorBody: (noteId: string, body: string) => void;
  /** True when the open editor of this note was found behind its row. */
  isEditorStale: (noteId: string) => boolean;
  handleTagsChange: (id: string, tags: string[]) => Promise<void>;
  handleTrackersChange: (id: string, trackers: JournalTrackerData) => Promise<void>;
  /** Commit a vault form's Save: the body, and for a login its tracker map,
   *  in one write. Resolves false when the write was refused. */
  handleVaultSave: (id: string, body: string, trackers?: Record<string, unknown>) => Promise<boolean>;
  scheduleSync: () => void;
  patchLocal: (id: string, patch: Partial<LocalNote>, nextUpdatedAt: string, opts?: { edit?: false }) => void;
  contentHash: (n: LocalNote) => Promise<string>;
  lastVersionHashRef: React.MutableRefObject<Map<string, string>>;
  /** The note's text was replaced from outside its editing session (a
   *  restore from history): the next edit starts a new session, so the state
   *  it starts from is kept as a version. */
  restartVersionSession: (id: string) => void;
  /** Flush any pending body edits into React state. Call on note switch
   *  and before sync so the notes array is current. */
  flushEditingBody: () => void;
  /** Ref holding the in-flight body for the currently-editing note.
   *  Keyed by note id → body string. Only one entry at a time. */
  editingBodyRef: React.MutableRefObject<Map<string, string>>;
}

const MIN_SYNC_INTERVAL_MS = 10000;
/** Editor instances whose loaded body is remembered. Only the open editor and
 *  the one it just replaced still save (the replaced one through its unmount
 *  flush), so a short history is enough. */
const EDITOR_KEYS_KEPT = 32;

let editorMounts = 0;
/** A key for one editor mount, passed with each of its saves. Unique per
 *  mount, so a replaced editor's late flush is never taken for the editor
 *  that replaced it, even when both show the same note. */
export function newEditorKey(noteId: string): string {
  editorMounts += 1;
  return `${noteId}#${editorMounts}`;
}
const noteOfKey = (editorKey: string) => editorKey.slice(0, editorKey.lastIndexOf('#'));
const SYNC_DEBOUNCE_MS = 1500;
const TITLE_MAX_LENGTH = 200;

export function useNoteEditing({
  auth,
  supabase,
  notes,
  setNotes,
  saveTimer,
  lastSyncAt,
  runSync,
  imageStoreRef,
  attachmentStoreRef,
  onSnapshotForbidden,
  onStaleEditorWrite,
}: UseNoteEditingArgs): UseNoteEditingReturn {
  /** The content hash of the last version this run saved, per note. */
  const lastVersionHashRef = useRef<Map<string, string>>(new Map());
  /** Each note's editing session, for versionSchedule.ts. */
  const versionSessionsRef = useRef<Map<string, VersionSession>>(new Map());
  /** A version that failed to save (offline, a server error), kept to try
   *  again on a later edit: it is the state before an edit, and no later
   *  version holds it. */
  const pendingVersionRef = useRef<Map<string, { note: LocalNote; at: number }>>(new Map());
  /** Releases the blobs the state in a note's retry slot names (imageGC.ts
   *  holdBlobsForVersion): no GC path may remove them before it is saved. */
  const pendingHoldRef = useRef<Map<string, () => void>>(new Map());
  /** Set once this view is gone: a version save that fails after that has no
   *  one left to try it again, so it takes no retry slot and no hold. */
  const disposedRef = useRef(false);
  /** Version saves still on their way, per note. The blob GC of an edit waits
   *  for them, so the history it reads holds the state an edit removed. */
  const versionSavesRef = useRef<Map<string, Set<Promise<void>>>>(new Map());
  /** In-flight body edits that haven't been flushed to React state yet.
   *  Avoids triggering setNotes (and the full re-render cascade) on
   *  every keystroke. Map<noteId, body>. */
  const editingBodyRef = useRef<Map<string, string>>(new Map());
  /** Previous body before editing started, used for image GC diff. */
  const editingBodyOldRef = useRef<Map<string, string>>(new Map());
  /** The "last edited" date each buffered body's write stored, so the flush
   *  shows it rather than the one from before the edit. */
  const editingEditedAtRef = useRef<Map<string, string>>(new Map());
  /** The notes array of the latest render. A save that runs from a debounce
   *  timer carries the closure of the render it was typed in, whose array
   *  can predate a pull that has landed since. */
  const latestNotesRef = useRef(notes);
  latestNotesRef.current = notes;
  /** The body each editor instance last loaded or wrote, by editor key. */
  const editorBodyRef = useRef<Map<string, string>>(new Map());
  /** Editor instances found stale: where their later saves go (the copy's id,
   *  once made), and the body the instance last knew. */
  const staleEditorRef = useRef<Map<string, { copy: Promise<string | null>; known: string }>>(new Map());

  /** The latest editor mount of each note, for resetEditorBody. */
  const latestEditorKeyRef = useRef<Map<string, string>>(new Map());

  // The tab-close stash seals in the body the open editor of a note was
  // showing, so a boot replays it only onto a row that still holds that body
  // (flushStash.ts).
  useEffect(() => {
    setEditorBaseLookup((noteId) => {
      const key = latestEditorKeyRef.current.get(noteId);
      return key === undefined ? undefined : editorBodyRef.current.get(key);
    });
    const holds = pendingHoldRef.current;
    disposedRef.current = false;
    return () => {
      disposedRef.current = true;
      setEditorBaseLookup(null);
      // A retry slot dies with this view (a sign-out), and its hold with it.
      for (const release of holds.values()) release();
      holds.clear();
    };
  }, []);

  const registerEditorBody = useCallback((editorKey: string, body: string) => {
    const map = editorBodyRef.current;
    map.delete(editorKey);
    map.set(editorKey, body);
    while (map.size > EDITOR_KEYS_KEPT) map.delete(map.keys().next().value as string);
    const latest = latestEditorKeyRef.current;
    latest.delete(noteOfKey(editorKey));
    latest.set(noteOfKey(editorKey), editorKey);
    while (latest.size > EDITOR_KEYS_KEPT) latest.delete(latest.keys().next().value as string);
  }, []);

  const resetEditorBody = useCallback((noteId: string, body: string) => {
    const key = latestEditorKeyRef.current.get(noteId);
    if (key !== undefined && editorBodyRef.current.has(key)) editorBodyRef.current.set(key, body);
    // The buffer held the body from before the rewrite.
    if (editingBodyRef.current.has(noteId)) editingBodyRef.current.set(noteId, body);
  }, []);

  /** True when the open editor of this note was found behind its row: its
   *  text belongs to the copy, so nothing may replace that text in place. */
  const isEditorStale = useCallback((noteId: string) => {
    const key = latestEditorKeyRef.current.get(noteId);
    return key !== undefined && staleEditorRef.current.has(key);
  }, []);

  function scheduleSync() {
    if (saveTimer.current) window.clearTimeout(saveTimer.current);
    const sinceLast = Date.now() - lastSyncAt.current;
    const delay = Math.max(SYNC_DEBOUNCE_MS, MIN_SYNC_INTERVAL_MS - sinceLast);
    saveTimer.current = window.setTimeout(() => {
      lastSyncAt.current = Date.now();
      void runSync();
    }, delay);
  }

  /** The in-memory twin of a write, by the same "last edited" rule as
   *  updateNote: a content change under a new stamp moves the date; a write
   *  that keeps the stamp, or says `edit: false`, keeps it. */
  function patchLocal(id: string, patch: Partial<LocalNote>, nextUpdatedAt: string, opts?: { edit?: false }) {
    setNotes((prev) =>
      prev.map((n) => {
        if (n.id !== id) return n;
        const edited = opts?.edit !== false && nextUpdatedAt !== n.updatedAt && changesContent(n, patch);
        return {
          ...n,
          ...patch,
          updatedAt: nextUpdatedAt,
          editedAt: edited ? nextUpdatedAt : (n.editedAt ?? n.updatedAt),
          dirty: 1,
        };
      })
    );
  }

  async function contentHash(n: LocalNote): Promise<string> {
    // A login's custom fields and a journal entry's tracker values are part
    // of what a version records.
    const extra = n.type === 'login' ? [n.trackers?.login ?? null] : n.type === 'journal' ? [trackerContent(n.trackers)] : [];
    const payload = JSON.stringify([n.title, n.body, n.tags, ...extra]);
    const bytes = new TextEncoder().encode(payload);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  /**
   * An edit happened to `id`; `before` is the note as it stood before it.
   * versionSchedule.ts decides whether that state becomes a version. Only an
   * edit made on this device counts: a pull of another device's version
   * never comes through here, and that device keeps its own history.
   */
  function recordEdit(id: string, before: LocalNote | undefined, bodyAfter?: string) {
    // proUnlocked, not isPro: the demo keeps versions too, in its own local
    // table rather than on the server (noteVersions.ts).
    if (!before || !proUnlocked(auth.isPro)) return;
    const bigLoss = bodyAfter !== undefined && isBigLoss(before.body, bodyAfter);
    const now = Date.now();
    const pending = pendingVersionRef.current.get(id);
    const plan = planVersion(versionSessionsRef.current.get(id), now, bigLoss);
    versionSessionsRef.current.set(id, plan.session);
    // A state that failed to save goes first: it is older than any new one.
    const retry = pending && (plan.take || now - pending.at >= LOSS_GAP_MS) ? pending.note : undefined;
    if (!retry && !plan.take) return;
    const saves = versionSavesRef.current.get(id) ?? new Set<Promise<void>>();
    versionSavesRef.current.set(id, saves);
    // The state to keep names blobs the edit may have just removed; they stay
    // until it is saved, or until the retry slot holds them in its place.
    const release = plan.take ? holdBlobsForVersion(before.body) : () => {};
    const saving: Promise<void> = (async () => {
      if (retry) await saveVersion(id, retry);
      if (plan.take) await saveVersion(id, before);
    })()
      .catch((err: unknown) => console.error('[history] could not keep a version', err))
      .finally(() => {
        release();
        saves.delete(saving);
        if (saves.size === 0 && versionSavesRef.current.get(id) === saves) versionSavesRef.current.delete(id);
      });
    saves.add(saving);
  }

  /** Put a state in a note's retry slot, or empty it (null), holding the
   *  blobs the slot's state names for as long as it stays there. */
  function setPendingVersion(id: string, entry: { note: LocalNote; at: number } | null) {
    if (entry && disposedRef.current) return;
    const previous = pendingHoldRef.current.get(id);
    if (entry) {
      pendingVersionRef.current.set(id, entry);
      pendingHoldRef.current.set(id, holdBlobsForVersion(entry.note.body));
    } else {
      pendingVersionRef.current.delete(id);
      pendingHoldRef.current.delete(id);
    }
    previous?.();
  }

  function restartVersionSession(id: string) {
    versionSessionsRef.current.delete(id);
  }

  /** Resolves once every version save of this note started so far is done. */
  async function versionSavesSettled(id: string): Promise<void> {
    await Promise.all(versionSavesRef.current.get(id) ?? []);
  }

  async function saveVersion(id: string, note: LocalNote) {
    // Nothing to go back to: a body without a letter or a digit, such as a
    // new note, an empty task list or a journal entry's blank template, and
    // for a journal entry no tracker value either.
    const tracked = note.type === 'journal' && Object.keys(trackerContent(note.trackers)).length > 0;
    if (!tracked && !/[\p{L}\p{N}]/u.test(note.body)) return;
    // A version row holds a foreign key into notes, so the server must
    // already hold the note. syncedNonce is the one field that proves it:
    // both the push and the pull stamp it. A note born a moment ago has no
    // earlier state worth keeping anyway. The demo never syncs and keeps its
    // versions locally, so it has no parent to wait for.
    if (note.syncedNonce == null && !isDemoMode()) return;
    // Only the kept state itself leaves the retry slot: a newer state that
    // saves says nothing about the older one.
    const settle = () => {
      if (pendingVersionRef.current.get(id)?.note === note) setPendingVersion(id, null);
    };
    const h = await contentHash(note);
    // The same state already went out: a request still on its way holds its
    // blobs until it lands (below), and a failure puts it back in the slot.
    if (lastVersionHashRef.current.get(id) === h) return settle();
    const prevHash = lastVersionHashRef.current.get(id);
    lastVersionHashRef.current.set(id, h);
    // The state names blobs no saved version may name yet: they stay for as
    // long as its request is out.
    const release = holdBlobsForVersion(note.body);
    try {
      const result = await createNoteVersion(supabase, auth.pubkey, auth.encryptionKey, note);
      if (result.ok) {
        markVersionActivity();
        return settle();
      }
      if (prevHash === undefined) lastVersionHashRef.current.delete(id);
      else lastVersionHashRef.current.set(id, prevHash);
      // RLS rejection - Pro lapsed mid-edit. Bubble to the caller
      // (NotesView), which dedupes to one banner per session. Nothing to retry.
      if (result.code === '42501') {
        setPendingVersion(id, null);
        onSnapshotForbidden?.();
        return;
      }
      // One slot, holding the oldest state that failed: a later version cannot
      // stand in for it. A newer failure waits for the next edit to recur.
      const kept = pendingVersionRef.current.get(id);
      setPendingVersion(id, { note: kept ? kept.note : note, at: Date.now() });
    } finally {
      release();
    }
  }

  /** The note as the app holds it now, with a body still in the buffer. */
  function currentNote(id: string): LocalNote | undefined {
    const n = latestNotesRef.current.find((x) => x.id === id);
    const body = editingBodyRef.current.get(id);
    return n && body !== undefined ? { ...n, body } : n;
  }

  async function handleTitleChange(id: string, title: string) {
    const clamped = title.slice(0, TITLE_MAX_LENGTH);
    const before = currentNote(id);
    const now = new Date().toISOString();
    patchLocal(id, { title: clamped }, now);
    if (await updateNote(id, { title: clamped })) recordEdit(id, before);
    scheduleSync();
  }

  /* ---------------------------------------------------------------- */
  /* Rename propagation (#238)                                         */
  /* ---------------------------------------------------------------- */

  /**
   * The title a note carried when its title field last took focus.
   *
   * Blur is the commit point, not the keystroke: `handleTitleChange` fires
   * once per typed character, so propagating from there would rewrite every
   * referencing note once per letter and would retarget links at half-typed
   * titles on the way. Blur fires on Tab to the tags, on a click into the
   * body, and on picking another note, which covers every way a rename ends
   * except closing the tab mid-word.
   */
  const titleAtFocusRef = useRef<Map<string, string>>(new Map());

  function handleTitleFocus(id: string) {
    const current = notes.find((n) => n.id === id);
    // The NAME a link could have used, not the stored title. For an unnamed
    // bookmark those differ: it stores '' and is called by its domain, so
    // giving it a name has to move the `[[github.com]]` links, and clearing
    // that name again has to move them back.
    titleAtFocusRef.current.set(id, current ? noteLinkName(current) : '');
  }

  /**
   * Point every note-link that named the old title at the new one, so a
   * rename does not orphan the links into that note (#238). Returns the
   * number of LINKS moved, not notes, because that is what the user just
   * watched change.
   */
  async function handleTitleBlur(id: string): Promise<number> {
    const from = titleAtFocusRef.current.get(id);
    titleAtFocusRef.current.delete(id);
    if (from === undefined) return 0;
    const renamed = notes.find((n) => n.id === id);
    const to = renamed ? noteLinkName(renamed) : '';
    if (!from || !to || from === to) return 0;

    // Ambiguous rename: another live note still carries the old title, so a
    // link naming it cannot be attributed to the note that just changed.
    // Leaving those links alone is the only answer that cannot retarget a
    // link at the wrong note.
    const key = noteLinkKey(from);
    if (notes.some((n) => n.id !== id && n.trashed === 0 && noteLinkKey(noteLinkName(n)) === key)) {
      return 0;
    }

    // Collect first, write once. A rename can touch many notes at a time, and
    // the naive shape (patchLocal + updateNote per note, in the loop) costs a
    // full pass over the notes array and a separate Dexie transaction EACH,
    // so its price grows with the library rather than with the rewrite. The
    // scan itself is cheap - most bodies hold no `[[` at all and exit on a
    // substring test - so the collect pass is the affordable half.
    // The other live notes by name, so `[[C# tips]]` is not read as a link
    // to "C" at the heading "tips" when "C# tips" is a note of its own.
    const others = new Set(
      notes.filter((n) => n.id !== id && n.trashed === 0).map((n) => noteLinkKey(noteLinkName(n))),
    );
    const hasOtherNote = (name: string) => others.has(noteLinkKey(name));
    // Skipped on purpose, each for its own reason:
    //   the renamed note itself - the editor holds its live document and
    //     overwrites the rewrite on its next save;
    //   trashed notes - a body write bumps updatedAt, which is the signal
    //     the trash auto-purge reads, so it would reset the purge clock;
    //   read-only notes - the flag exists to stop writes the user did not
    //     make, and this is one.
    // Structured bodies are JSON consumed by a form, not markdown. Rewriting
    // inside one would corrupt a stored field. Same exemption, and the same
    // reasoning, that `import/linkify.ts` carries.
    const skipped = (n: LocalNote) => n.id === id || n.trashed !== 0 || n.locked === 1 || hasStructuredBody(n.type);
    // The notes this view shows linking the old title are the ones read
    // again; the rewrite is made from each row inside the write, so a body a
    // pull stored since this view last drew it is rewritten, not replaced.
    const candidates = notes.filter((n) => !skipped(n) && retargetNoteLinks(n.body, from, to, hasOtherNote) !== null);
    if (candidates.length === 0) return 0;
    let count = 0;
    const written = await bulkRewriteBody(candidates.map((n) => n.id), (current) => {
      if (skipped(current)) return null;
      const next = retargetNoteLinks(current.body, from, to, hasOtherNote);
      if (next === null) return null;
      count += next.count;
      return next.body;
    });
    if (written.length === 0) return 0;

    const now = new Date().toISOString();
    const byId = new Map(written.map((u) => [u.id, u.body]));
    setNotes((prev) =>
      prev.map((n) => {
        const body = byId.get(n.id);
        // Nobody edited these notes, so their "last edited" date stays.
        return body === undefined
          ? n
          : { ...n, body, updatedAt: now, editedAt: n.editedAt ?? n.updatedAt, dirty: 1 };
      }),
    );
    // No image GC pass: a retarget only rewrites link text, so it can never
    // drop the last reference to a stored image. No version snapshot either,
    // for the same reason plus the burst it would push at the server.
    scheduleSync();
    return count;
  }

  /** Flush pending body edits into React state. Call before sync, on
   *  note switch, and anywhere the notes array must reflect the latest
   *  body. This is the ONLY place body edits touch setNotes. */
  const flushEditingBody = useCallback(() => {
    const map = editingBodyRef.current;
    if (map.size === 0) return;
    const entries = Array.from(map.entries());
    const editedAts = new Map(editingEditedAtRef.current);
    map.clear();
    editingBodyOldRef.current.clear();
    editingEditedAtRef.current.clear();
    setNotes((prev) =>
      prev.map((n) => {
        const entry = entries.find(([id]) => id === n.id);
        if (!entry) return n;
        const [, body] = entry;
        const editedAt = editedAts.get(n.id);
        // Typed and then undone: the body is back, but the writes were edits.
        if (n.body === body) return editedAt && editedAt !== n.editedAt ? { ...n, editedAt } : n;
        return { ...n, body, ...(editedAt ? { editedAt } : {}), dirty: 1 };
      }),
    );
  // Refs are stable; setNotes is a React dispatch - stable by contract.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setNotes]);

  /** Keep the text of a stale editor: the first save makes the copy, every
   *  later save of that instance goes into it. */
  async function keepStaleText(id: string, editorKey: string, body: string): Promise<void> {
    const dead = staleEditorRef.current.get(editorKey);
    if (!dead) return;
    const pending = dead.copy;
    const copyId = await pending.catch(() => null);
    // Another save of this instance made the copy while this one waited.
    if (dead.copy !== pending) return keepStaleText(id, editorKey, body);
    if (copyId && (await updateNote(copyId, { body }))) return;
    // No copy yet: nothing was kept when the instance was found stale, or the
    // copy failed, or it now refuses edits. A text with something in it gets
    // a copy of its own.
    if (body === dead.known) return;
    dead.copy = getNote(id).then((current) => (current ? keepAsCopy(current, body) : null)).catch(() => null);
    await dead.copy;
  }

  /** onStaleEditorWrite that never rejects: a failure leaves no copy, and
   *  the next save of the stale editor tries again. */
  function keepAsCopy(current: LocalNote, body: string | null): Promise<string | null> {
    if (!onStaleEditorWrite) return Promise.resolve(null);
    return onStaleEditorWrite(current, body).catch((err: unknown) => {
      console.error('[edit] could not keep the text of a stale editor', err);
      return null;
    });
  }

  async function handleBodyChange(id: string, body: string, editorKey?: string) {
    if (editorKey !== undefined && staleEditorRef.current.has(editorKey)) {
      dropPendingEdit(id);
      await keepStaleText(id, editorKey, body);
      return;
    }
    // Check against the ref first (most recent), then fall back to notes array
    const prevBody = editingBodyRef.current.get(id)
      ?? latestNotesRef.current.find((n) => n.id === id)?.body;
    if (prevBody === body) return;

    // Track old body for image GC (only set once per editing session)
    if (!editingBodyOldRef.current.has(id)) {
      const oldBody = notes.find((n) => n.id === id)?.body ?? '';
      editingBodyOldRef.current.set(id, oldBody);
    }
    const gcOldBody = editingBodyOldRef.current.get(id) ?? '';

    // The body this editor instance last showed, and from here on the one it
    // shows now. Set before the write, so a second save that starts while
    // this one is in flight expects this body, not the one before it.
    const known = editorKey === undefined ? undefined : editorBodyRef.current.get(editorKey);
    // A key the record no longer holds belongs to an editor long replaced:
    // nothing says what it showed, so its save is refused like a stale one.
    const unknownKey = editorKey !== undefined && known === undefined;
    if (editorKey !== undefined && known !== undefined) editorBodyRef.current.set(editorKey, body);
    // Behind its row already, as far as this render can tell: the notes
    // array holds a body this editor never showed. Its text stays out of the
    // buffer, because everything that reads "the freshest body" (exports,
    // the task actions of the menu) reads the buffer first, and would carry
    // the old text out or write it back. The tab-close stash goes too.
    const behind = unknownKey || (known !== undefined && prevBody !== known);
    if (behind) dropPendingEdit(id);

    // Store in ref - does NOT trigger React re-render
    if (!behind) editingBodyRef.current.set(id, body);

    // Dexie write + sync scheduling still happen immediately. No explicit
    // timestamp: updateNote's monotonic nextStamp keeps same-millisecond
    // generations strictly ordered (#156).
    //
    // A row that no longer holds the body this editor knew was rewritten
    // under it, by a pull of another device's version. Writing would put
    // the editor's old text over that version with the new version's nonce
    // as its base, and the push would take it as an ordinary edit (#497).
    // The check runs inside the write's transaction, so a pull that lands
    // between a read and the write cannot slip past it.
    // Stashes this tab wrote up to now hold typing this save carries.
    const stashedUpTo = stashGeneration();
    let refused = false;
    let staleRow: LocalNote | null = null;
    // The row as it stood before this save: the state a version keeps.
    let rowBefore: LocalNote | undefined;
    let settleCopy: (copyId: string | null) => void = () => {};
    const written = await updateNoteFrom(
      id,
      (current) => {
        if (editorKey === undefined || (known !== undefined && current.body === known)) {
          rowBefore = current;
          return { body };
        }
        refused = true;
        if (!staleEditorRef.current.has(editorKey)) {
          staleRow = current;
          staleEditorRef.current.set(editorKey, {
            copy: new Promise((resolve) => { settleCopy = resolve; }),
            known: known ?? current.body,
          });
        }
        return null;
      },
      {
        onWrite: (stored) => {
          if (editingBodyRef.current.has(id)) editingEditedAtRef.current.set(id, stored.editedAt);
          // The body was already flushed (an editor mode switch flushes while
          // the write is in flight), so the date goes straight to the list.
          else setNotes((prev) => prev.map((n) => (n.id === id && n.editedAt !== stored.editedAt ? { ...n, editedAt: stored.editedAt } : n)));
        },
      },
    );
    if (refused && editorKey !== undefined) {
      dropPendingEdit(id);
      // Only this save's own entry leaves the buffer: a newer editor of the
      // same note may hold one by now.
      if (editingBodyRef.current.get(id) === body) {
        editingBodyRef.current.delete(id);
        editingBodyOldRef.current.delete(id);
        editingEditedAtRef.current.delete(id);
      }
      const found = staleRow as LocalNote | null;
      if (!found) {
        // A save that started alongside the one that found the editor stale.
        await keepStaleText(id, editorKey, body);
        return;
      }
      const copyId = await keepAsCopy(found, body === known || body === found.body ? null : body);
      settleCopy(copyId);
      while (staleEditorRef.current.size > EDITOR_KEYS_KEPT) {
        staleEditorRef.current.delete(staleEditorRef.current.keys().next().value as string);
      }
      return;
    }
    // Not written and not stale: the row refused the edit (read-only). The
    // editor still shows what it showed before, so its record goes back.
    if (!written && editorKey !== undefined && known !== undefined && editorBodyRef.current.get(editorKey) === body) {
      editorBodyRef.current.set(editorKey, known);
      return;
    }
    // Written after all: the row had caught up by the time the write ran. The
    // buffer takes the body now, as it does for every save that writes.
    if (behind && editorBodyRef.current.get(editorKey as string) === body) editingBodyRef.current.set(id, body);
    // A tab-close stash this save carries is done once it is in the row.
    if (written) settlePendingEdit(id, stashedUpTo);

    // The state before this edit may become a version, and that version can
    // be the only thing still naming an image the edit removed.
    if (written) recordEdit(id, rowBefore as LocalNote | undefined, body);
    // Image GC: diff against the original body from before editing started.
    // After the write, so a refused save never collects an image the row
    // still shows, and after the note's version saves, so the history it
    // reads holds them. A state still waiting to be saved again holds its
    // blobs through holdBlobsForVersion.
    const imageStore = imageStoreRef.current;
    if (imageStore) {
      const attachmentStore = attachmentStoreRef.current;
      void (async () => {
        await versionSavesSettled(id);
        await gcOnBodyChange(
          imageStore,
          gcOldBody,
          body,
          id,
          auth.isPro ? { supabase, encryptionKey: auth.encryptionKey, noteId: id } : undefined,
          attachmentStore,
        );
      })();
    }
    // A STRUCTURED body is not a live editor document. A bookmark's `{url}`,
    // a login, a card and an SSH key are each committed once, by a form, and
    // every surface that draws them renders from the notes array: the row's
    // URL line and favicon, the vault view mode, the editor's own field.
    // Leaving the new body in the ref (right for the markdown editor, which
    // writes per keystroke and owns its text) left all of those on the OLD
    // body until something else flushed - which is why a bookmark's favicon
    // only caught up after switching pillars. Same type list, and the same
    // reasoning, as the note-link retarget skip above.
    const type = notes.find((n) => n.id === id)?.type;
    if (hasStructuredBody(type)) {
      flushEditingBody();
    }
    scheduleSync();
  }

  async function handleTagsChange(id: string, tags: string[]) {
    const now = new Date().toISOString();
    patchLocal(id, { tags }, now);
    await updateNote(id, { tags });
    scheduleSync();
    // No version: a tag change alone is not worth one of the 50 slots, and
    // the next version records the tags as they are then.
  }

  async function handleTrackersChange(id: string, trackers: JournalTrackerData) {
    const before = currentNote(id);
    const now = new Date().toISOString();
    patchLocal(id, { trackers: trackers as Record<string, unknown> }, now);
    const written = await updateNote(id, { trackers: trackers as Record<string, unknown> });
    scheduleSync();
    // A tracker value is part of what a version records; the entry's date
    // and the backfill mark are bookkeeping and make none.
    if (written && before && changesContent(before, { trackers: trackers as Record<string, unknown> })) recordEdit(id, before);
  }

  async function handleVaultSave(id: string, body: string, trackers?: Record<string, unknown>): Promise<boolean> {
    const patch = trackers === undefined ? { body } : { body, trackers };
    const before = currentNote(id);
    const ok = await updateNote(id, patch);
    if (!ok) return false;
    editingBodyRef.current.delete(id);
    patchLocal(id, patch, new Date().toISOString());
    scheduleSync();
    recordEdit(id, before, body);
    return true;
  }

  return {
    handleTitleChange,
    handleTitleFocus,
    handleTitleBlur,
    handleBodyChange,
    registerEditorBody,
    resetEditorBody,
    isEditorStale,
    handleTagsChange,
    handleTrackersChange,
    handleVaultSave,
    scheduleSync,
    patchLocal,
    contentHash,
    lastVersionHashRef,
    restartVersionSession,
    flushEditingBody,
    editingBodyRef,
  };
}

export { TITLE_MAX_LENGTH };
