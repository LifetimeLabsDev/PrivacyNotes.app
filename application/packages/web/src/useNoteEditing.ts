import { useCallback, useRef } from 'react';
import type { SupabaseClient } from '@notes/shared';
import type { LocalNote } from './db';
import type { JournalTrackerData } from './trackerTypes';
import { bulkSetBody, getNote, updateNote } from './notesRepo';
import { createNoteVersion } from './noteVersions';
import { isDemoMode, proUnlocked } from './demo';
import { gcOnBodyChange } from './imageGC';
import { noteLinkKey, retargetNoteLinks } from './noteLinks';
import { noteLinkName } from './notesViewUtils';
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
}

interface UseNoteEditingReturn {
  handleTitleChange: (id: string, title: string) => Promise<void>;
  /** Remember the title a note carries, so a later blur can tell whether
   *  it was renamed. Call from the title field's focus handler. */
  handleTitleFocus: (id: string) => void;
  /** Commit a rename: point every note-link that named the old title at the
   *  new one. Resolves with the number of notes rewritten. */
  handleTitleBlur: (id: string) => Promise<number>;
  handleBodyChange: (id: string, body: string) => Promise<void>;
  handleTagsChange: (id: string, tags: string[]) => Promise<void>;
  handleTrackersChange: (id: string, trackers: JournalTrackerData) => Promise<void>;
  scheduleSync: () => void;
  patchLocal: (id: string, patch: Partial<LocalNote>, nextUpdatedAt: string) => void;
  contentHash: (n: LocalNote) => Promise<string>;
  lastVersionHashRef: React.MutableRefObject<Map<string, string>>;
  lastVersionAtRef: React.MutableRefObject<Map<string, number>>;
  /** Flush any pending body edits into React state. Call on note switch
   *  and before sync so the notes array is current. */
  flushEditingBody: () => void;
  /** Ref holding the in-flight body for the currently-editing note.
   *  Keyed by note id → body string. Only one entry at a time. */
  editingBodyRef: React.MutableRefObject<Map<string, string>>;
}

const MIN_SYNC_INTERVAL_MS = 10000;
const SYNC_DEBOUNCE_MS = 1500;
const TITLE_MAX_LENGTH = 200;
// Spec: ops/docs/design-decisions.md (note history: 60-second per-note rate limit)
const VERSION_MIN_GAP_MS = 60_000;

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
}: UseNoteEditingArgs): UseNoteEditingReturn {
  const lastVersionHashRef = useRef<Map<string, string>>(new Map());
  const lastVersionAtRef = useRef<Map<string, number>>(new Map());
  /** In-flight body edits that haven't been flushed to React state yet.
   *  Avoids triggering setNotes (and the full re-render cascade) on
   *  every keystroke. Map<noteId, body>. */
  const editingBodyRef = useRef<Map<string, string>>(new Map());
  /** Previous body before editing started, used for image GC diff. */
  const editingBodyOldRef = useRef<Map<string, string>>(new Map());

  function scheduleSync() {
    if (saveTimer.current) window.clearTimeout(saveTimer.current);
    const sinceLast = Date.now() - lastSyncAt.current;
    const delay = Math.max(SYNC_DEBOUNCE_MS, MIN_SYNC_INTERVAL_MS - sinceLast);
    saveTimer.current = window.setTimeout(() => {
      lastSyncAt.current = Date.now();
      void runSync();
    }, delay);
  }

  function patchLocal(id: string, patch: Partial<LocalNote>, nextUpdatedAt: string) {
    setNotes((prev) =>
      prev.map((n) =>
        n.id === id ? { ...n, ...patch, updatedAt: nextUpdatedAt, dirty: 1 } : n
      )
    );
  }

  async function contentHash(n: LocalNote): Promise<string> {
    const payload = JSON.stringify([n.title, n.body, n.tags]);
    const bytes = new TextEncoder().encode(payload);
    const digest = await crypto.subtle.digest('SHA-256', bytes);
    return Array.from(new Uint8Array(digest))
      .map((b) => b.toString(16).padStart(2, '0'))
      .join('');
  }

  function scheduleVersionSnapshot(id: string) {
    // proUnlocked, not isPro: the demo snapshots too, into its own local
    // table rather than the server (noteVersions.ts).
    if (!proUnlocked(auth.isPro)) return;
    const lastAt = lastVersionAtRef.current.get(id) ?? 0;
    if (Date.now() - lastAt < VERSION_MIN_GAP_MS) return;
    void (async () => {
      const note = await getNote(id);
      if (!note) return;
      // A version row holds a foreign key into notes, so the server must
      // already hold the note. A note born in this session is local-only
      // until the next push, which trails the first keystroke by seconds,
      // and the insert is refused for a parent row that is not there yet.
      // syncedNonce is the one field that proves the server holds it: both
      // the push and the pull stamp it. The demo keeps its snapshots in its
      // own local table and never syncs, so it has no parent to wait for.
      // Return before the two refs below rather than after, so the skip
      // leaves the rate-limit slot free and the next edit tries again.
      if (note.syncedNonce == null && !isDemoMode()) return;
      const h = await contentHash(note);
      if (lastVersionHashRef.current.get(id) === h) return;
      lastVersionHashRef.current.set(id, h);
      lastVersionAtRef.current.set(id, Date.now());
      const result = await createNoteVersion(supabase, auth.pubkey, auth.encryptionKey, note);
      // RLS rejection - Pro lapsed mid-edit. Bubble to the caller
      // (NotesView), which dedupes to one banner per session.
      if (!result.ok && result.code === '42501') {
        onSnapshotForbidden?.();
      }
    })();
  }

  async function handleTitleChange(id: string, title: string) {
    const clamped = title.slice(0, TITLE_MAX_LENGTH);
    const now = new Date().toISOString();
    patchLocal(id, { title: clamped }, now);
    await updateNote(id, { title: clamped });
    scheduleSync();
    scheduleVersionSnapshot(id);
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
    const updates: Array<{ id: string; body: string }> = [];
    let count = 0;
    for (const n of notes) {
      // Skipped on purpose, each for its own reason:
      //   the renamed note itself - the editor holds its live document and
      //     overwrites the rewrite on its next save;
      //   trashed notes - a body write bumps updatedAt, which is the signal
      //     the trash auto-purge reads, so it would reset the purge clock;
      //   read-only notes - the flag exists to stop writes the user did not
      //     make, and this is one.
      if (n.id === id || n.trashed !== 0 || n.locked === 1) continue;
      // Structured bodies are JSON consumed by a form, not markdown: a
      // bookmark's `{url}`, a login, a card, an SSH key. Rewriting inside one
      // would corrupt a stored field. Same exemption, and the same reasoning,
      // that `import/linkify.ts` carries; any future structured type inherits it.
      if (n.type === 'link' || n.type === 'login' || n.type === 'card' || n.type === 'ssh-key') continue;
      const next = retargetNoteLinks(n.body, from, to);
      if (next === null) continue;
      updates.push({ id: n.id, body: next.body });
      count += next.count;
    }
    if (updates.length === 0) return 0;

    const now = new Date().toISOString();
    const byId = new Map(updates.map((u) => [u.id, u.body]));
    setNotes((prev) =>
      prev.map((n) => {
        const body = byId.get(n.id);
        return body === undefined ? n : { ...n, body, updatedAt: now, dirty: 1 };
      }),
    );
    await bulkSetBody(updates);
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
    map.clear();
    editingBodyOldRef.current.clear();
    setNotes((prev) =>
      prev.map((n) => {
        const entry = entries.find(([id]) => id === n.id);
        if (!entry) return n;
        const [, body] = entry;
        if (n.body === body) return n;
        return { ...n, body, dirty: 1 };
      }),
    );
  // Refs are stable; setNotes is a React dispatch - stable by contract.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [setNotes]);

  async function handleBodyChange(id: string, body: string) {
    // Check against the ref first (most recent), then fall back to notes array
    const prevBody = editingBodyRef.current.get(id)
      ?? notes.find((n) => n.id === id)?.body;
    if (prevBody === body) return;

    // Track old body for image GC (only set once per editing session)
    if (!editingBodyOldRef.current.has(id)) {
      const oldBody = notes.find((n) => n.id === id)?.body ?? '';
      editingBodyOldRef.current.set(id, oldBody);
    }

    // Image GC: diff against the original body from before editing started
    const gcOldBody = editingBodyOldRef.current.get(id) ?? '';
    if (imageStoreRef.current) {
      void gcOnBodyChange(
        imageStoreRef.current,
        gcOldBody,
        body,
        id,
        auth.isPro ? { supabase, encryptionKey: auth.encryptionKey, noteId: id } : undefined,
        attachmentStoreRef.current,
      );
    }

    // Store in ref - does NOT trigger React re-render
    editingBodyRef.current.set(id, body);

    // Dexie write + sync scheduling still happen immediately. No explicit
    // timestamp: updateNote's monotonic nextStamp keeps same-millisecond
    // generations strictly ordered (#156).
    await updateNote(id, { body });
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
    if (type === 'link' || type === 'login' || type === 'card' || type === 'ssh-key') {
      flushEditingBody();
    }
    scheduleSync();
    scheduleVersionSnapshot(id);
  }

  async function handleTagsChange(id: string, tags: string[]) {
    const now = new Date().toISOString();
    patchLocal(id, { tags }, now);
    await updateNote(id, { tags });
    scheduleSync();
    scheduleVersionSnapshot(id);
  }

  async function handleTrackersChange(id: string, trackers: JournalTrackerData) {
    const now = new Date().toISOString();
    patchLocal(id, { trackers: trackers as Record<string, unknown> }, now);
    await updateNote(id, { trackers: trackers as Record<string, unknown> });
    scheduleSync();
  }

  return {
    handleTitleChange,
    handleTitleFocus,
    handleTitleBlur,
    handleBodyChange,
    handleTagsChange,
    handleTrackersChange,
    scheduleSync,
    patchLocal,
    contentHash,
    lastVersionHashRef,
    lastVersionAtRef,
    flushEditingBody,
    editingBodyRef,
  };
}

export { TITLE_MAX_LENGTH };
