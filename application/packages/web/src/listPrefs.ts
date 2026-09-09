/**
 * Notes-list display preferences - pure store helpers.
 *
 * Controls sort order and which row metadata (preview / date / tags) is
 * visible in the middle column. Modeled on Standard Notes' panel:
 * a Global default plus per-pillar overrides.
 *
 * Pillars with a notes list of their own: 'notes' (the 'all' view),
 * 'tasks', 'journal'. Non-pillar views ('trash', 'starred') always
 * resolve against Global - they have no override of their own.
 *
 * This module is intentionally pure - no localStorage, no events. The
 * store is owned by `UserSettings` (see `userSettings.ts`) so prefs
 * sync across devices via the existing encrypted user_settings
 * pipeline. Components read/write through the settings state.
 */

export type SortField = 'modified' | 'created' | 'title' | 'size';
type SortDir = 'asc' | 'desc';

export type ListPrefs = {
  sortField: SortField;
  sortDir: SortDir;
  /**
   * Whether a row carries its preview line - the note's first words, a
   * bookmark's URL, a login's username. Default true, but three pillars
   * start it off; see PILLAR_DEFAULTS.
   * Spec: ops/docs/design-decisions.md (per-pillar list settings)
   */
  showPreview: boolean;
  /**
   * Whether a row carries its date. Default true, off in the pillars whose
   * rows say it already; see PILLAR_DEFAULTS.
   * Spec: ops/docs/design-decisions.md (per-pillar list settings)
   */
  showDate: boolean;
  /**
   * Whether a row shows its folder chip and its tag chips. Default true:
   * both are the browse axis a free account has, so a new user who tags or
   * files a note sees the chip on the row without finding the pref first.
   * Named "Show folder & tags" in the interface.
   */
  showTags: boolean;
  /**
   * Whether notes marked "Read-only" (locked) appear in the
   * list. Turn off to hide them entirely - handy if you use locks
   * on reference material you rarely open. Default true.
   */
  showLocked: boolean;
  /**
   * Whether PIN-protected notes appear in the list. Independent of
   * unlock state: turning this off hides the "Protected note"
   * placeholder rows too. Default true.
   */
  showProtected: boolean;
  /**
   * Files pillar only: whether to show files that are embedded in
   * content notes (true) or only standalone file-upload notes (false).
   * Default true.
   */
  showAttachedNotes: boolean;
  /**
   * Bookmarks pillar only: mix in read-only rows derived from URLs found
   * inside note bodies. Computed locally, never stored. Off in Global, on
   * from the start in the bookmarks pillar (PILLAR_DEFAULTS).
   * Spec: ops/docs/plans/bookmarks-pillar.md (section 8)
   */
  showNoteLinks: boolean;
};

/**
 * A "pillar" is a note-type bucket the user can configure
 * independently. 'global' is the fallback applied to views that have
 * no override.
 */
import type { View } from './views';

export type Pillar = 'global' | 'notes' | 'tasks' | 'journal' | 'vault' | 'files' | 'bookmarks' | 'contacts';

/**
 * The full prefs document: a global default plus optional per-pillar
 * overrides. A missing pillar key means "inherit Global."
 */
export type ListPrefsStore = {
  global: ListPrefs;
  notes?: ListPrefs;
  tasks?: ListPrefs;
  journal?: ListPrefs;
  vault?: ListPrefs;
  files?: ListPrefs;
  bookmarks?: ListPrefs;
  contacts?: ListPrefs;
};

const DEFAULT_PREFS: ListPrefs = {
  sortField: 'modified',
  sortDir: 'desc',
  showPreview: true,
  showDate: true,
  showTags: true,
  showLocked: true,
  showProtected: true,
  showAttachedNotes: true,
  showNoteLinks: false,
};

export const DEFAULT_STORE: ListPrefsStore = {
  global: { ...DEFAULT_PREFS },
};

/**
 * Per-pillar starting positions, applied on top of Global for a pillar that
 * has not been touched yet. A pillar listed here is NOT an override: it holds
 * no stored copy, so it still follows Global for every key the delta does not
 * name. The first edit inside that pillar writes a real copy and the delta
 * stops applying.
 *
 * A delta rather than a seeded store entry, for two reasons. It reaches
 * existing accounts with no migration, because nothing has to be written for
 * it to take effect. And it keeps "no copy means inherit Global" true, which
 * a seeded entry would quietly break.
 *
 * Why each one, since every entry here is a claim about what a row IS:
 *   - bookmarks: the URL line stays, because the address IS the bookmark.
 *     The date of a saved link is noise, tags and folders belong to the
 *     filter chips above the list rather than to every row, and the links
 *     found inside notes are what the pillar is for.
 *   - files: the row always carries its size, which is the number that
 *     matters, and the preview line only names the type again.
 *   - journal: the title IS the date (`journalTitle`), so a date line under
 *     it says the same thing twice.
 *   - vault: a login's second line is its username, so the preview stays ON
 *     here - the exact opposite of bookmarks, through the same switch. Only
 *     the date goes.
 * Notes and Tasks are deliberately absent: a preview line is how you tell two
 * untitled notes apart.
 * Spec: ops/docs/design-decisions.md (per-pillar list settings)
 */
const PILLAR_DEFAULTS: Partial<Record<Pillar, Partial<ListPrefs>>> = {
  bookmarks: { showDate: false, showTags: false, showNoteLinks: true },
  // Contacts: a person's row says who they are and how to reach them; the
  // date of the last edit is noise there. Sort stays the global default
  // (date modified), by decision, and A to Z is one click away.
  // Spec: ops/docs/plans/contacts-pillar.md (section 10, PILLAR_DEFAULTS)
  contacts: { showDate: false },
  files: { showPreview: false, showDate: false },
  journal: { showDate: false },
  vault: { showDate: false },
};

/* ────────────────────────────────────────────────────────────────
 * Hydration - validate untrusted input (from a stored settings blob
 * or an older client schema) into a well-formed store.
 * ──────────────────────────────────────────────────────────────── */

function hydratePrefs(raw: unknown): ListPrefs {
  const base: ListPrefs = { ...DEFAULT_PREFS };
  if (!raw || typeof raw !== 'object') return base;
  const obj = raw as Partial<ListPrefs>;
  if (
    obj.sortField === 'modified' ||
    obj.sortField === 'created' ||
    obj.sortField === 'title' ||
    obj.sortField === 'size'
  ) {
    base.sortField = obj.sortField;
  }
  if (obj.sortDir === 'asc' || obj.sortDir === 'desc') {
    base.sortDir = obj.sortDir;
  }
  if (typeof obj.showPreview === 'boolean') base.showPreview = obj.showPreview;
  if (typeof obj.showDate === 'boolean') base.showDate = obj.showDate;
  if (typeof obj.showTags === 'boolean') base.showTags = obj.showTags;
  if (typeof obj.showLocked === 'boolean') base.showLocked = obj.showLocked;
  if (typeof obj.showProtected === 'boolean') base.showProtected = obj.showProtected;
  if (typeof obj.showAttachedNotes === 'boolean') base.showAttachedNotes = obj.showAttachedNotes;
  if (typeof obj.showNoteLinks === 'boolean') base.showNoteLinks = obj.showNoteLinks;
  return base;
}

export function hydrateListPrefsStore(raw: unknown): ListPrefsStore {
  const base: ListPrefsStore = { global: { ...DEFAULT_PREFS } };
  if (!raw || typeof raw !== 'object') return base;
  const obj = raw as Partial<ListPrefsStore>;
  if (obj.global !== undefined) base.global = hydratePrefs(obj.global);
  if (obj.notes !== undefined) base.notes = hydratePrefs(obj.notes);
  if (obj.tasks !== undefined) base.tasks = hydratePrefs(obj.tasks);
  if (obj.journal !== undefined) base.journal = hydratePrefs(obj.journal);
  if (obj.vault !== undefined) base.vault = hydratePrefs(obj.vault);
  if (obj.files !== undefined) base.files = hydratePrefs(obj.files);
  if (obj.bookmarks !== undefined) base.bookmarks = hydratePrefs(obj.bookmarks);
  if (obj.contacts !== undefined) base.contacts = hydratePrefs(obj.contacts);
  // Migrate legacy 'logins' key to 'vault'.
  if (!obj.vault && (obj as Record<string, unknown>).logins !== undefined) {
    base.vault = hydratePrefs((obj as Record<string, unknown>).logins);
  }
  return base;
}

/* ────────────────────────────────────────────────────────────────
 * Pure store operations - every mutator returns a new store so
 * callers can pipe the result into React state without worrying
 * about shared references.
 * ──────────────────────────────────────────────────────────────── */

/**
 * Resolve the effective prefs for a pillar: its own copy if it has one, else
 * Global with that pillar's starting delta laid over it. For 'global' this is
 * just Global itself.
 *
 * The delta branch builds a NEW object every call, so a caller that feeds the
 * result into a dependency array must memoize it (NotesView does). Returning a
 * fresh object into `useMemo` deps re-sorts and re-filters the whole library
 * on every render.
 */
export function resolvePrefs(
  store: ListPrefsStore,
  pillar: Pillar
): ListPrefs {
  if (pillar === 'global') return store.global;
  const own = store[pillar];
  if (own) return own;
  const delta = PILLAR_DEFAULTS[pillar];
  return delta ? { ...store.global, ...delta } : store.global;
}

/** Write prefs for the given pillar and return a new store. */
export function setPillarPrefs(
  store: ListPrefsStore,
  pillar: Pillar,
  prefs: ListPrefs
): ListPrefsStore {
  if (pillar === 'global') return { ...store, global: prefs };
  return { ...store, [pillar]: prefs };
}

/* ────────────────────────────────────────────────────────────────
 * View → pillar mapping
 * ──────────────────────────────────────────────────────────────── */

/**
 * Map the app's internal `view` state to a pillar. Views that don't
 * correspond to a pillar ('trash', 'starred', 'markdown') map to 'global' so
 * they always inherit and never own an override.
 *
 * Takes `View` rather than a local restatement of it. A local union would be
 * one more copy of the same strings and the only one that would NOT fail the
 * build when a view is added - a missing member silently stops being
 * assignable rather than erroring at the definition, so the drift would
 * surface as a call-site type error far from the cause.
 */
export function viewToPillar(view: View): Pillar {
  if (view === 'all') return 'notes';
  if (view === 'journal') return 'journal';
  if (view === 'tasks') return 'tasks';
  if (view === 'vault') return 'vault';
  if (view === 'files') return 'files';
  if (view === 'bookmarks') return 'bookmarks';
  if (view === 'contacts') return 'contacts';
  return 'global';
}
