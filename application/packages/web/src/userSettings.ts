/**
 * Synced user settings.
 *
 * The one and only cross-device user preference blob, end-to-end
 * encrypted with the same phrase-derived key as notes. The full field
 * list is the UserSettings type below; favoriteTags holds the tags
 * pinned by the user, shown in a "Favorites" section above the
 * regular Tags list.
 *
 * Shape is intentionally forward-compatible: new fields default to
 * sensible values at decode time so older clients never crash on
 * newer blobs, and newer clients tolerate missing keys from older
 * blobs.
 *
 * Storage:
 *   - In-memory React state (the caller owns this)
 *   - localStorage.`privacynotes.settings` - local cache so the UI
 *     paints instantly on reload, before the network sync lands. On a
 *     device the user marked untrusted it never carries the PIN wrap
 *     fields; see the note above LocalCache.
 *   - public.user_settings row on Supabase - remote truth, last-
 *     write-wins on updated_at (same merge rule as notes)
 *
 * All server I/O goes through `syncUserSettings`, which does a
 * pull-then-push pass just like notes/sync.ts. It's safe to call
 * this repeatedly - it no-ops when nothing is dirty and remote is
 * up to date.
 */

import {
  encryptJson,
  decryptJson,
  bytesToBase64,
  base64ToBytes,
  type SupabaseClient,
} from '@notes/shared';
import {
  DEFAULT_STORE as DEFAULT_LIST_PREFS_STORE,
  hydrateListPrefsStore,
  type ListPrefsStore,
} from './listPrefs';
import {
  defaultTrackerSettings,
  WEIGHT_UNITS,
  type TrackerSettings,
  type WeightUnit,
  type CustomTrackerTemplate,
  type MedicationTemplate,
} from './trackerTypes';
import { isColorTheme, type ColorTheme } from './theme';
import {
  isJournalTitleFormat,
  JOURNAL_SUFFIX_MAX,
  type JournalTitleFormat,
} from './notesViewUtils';
import { credentialKey, isDemoMode } from './demo';
import { settingsLocalKey } from './settingsLocalKey';
import { isTrustedDevice } from './trustStorage';
import { hasPinWrap } from './pin';
import type { View } from './views';
import { isServerWriteBlocked } from './syncPause';
import { logAuthEvent } from './authDiag';
import {
  folderTreesEqual,
  isFolderSortField,
  mergeFolderTrees,
  validateFolders,
  validateFolderTombstones,
  type FolderDef,
  type FolderSortDir,
  type FolderSortField,
  type FolderTombstone,
  type FolderTree,
} from './folders';

// ------------------------------------------------------------------
// Shape
// ------------------------------------------------------------------

/**
 * One app-wide image switch. A string rather than a boolean so a third
 * state can be added later without a migration.
 * Spec: ops/docs/plans/image-quality-handoff.md (section 3)
 */
export type ImageSwitch = 'on' | 'off';

/**
 * Every field here is part of ONE encrypted row that every device shares,
 * so whoever writes the row writes all of it. A field holding a COLLECTION
 * therefore needs a merge rule, or the last device to write silently
 * deletes what the others put in it. That has cost user data three times:
 * medication templates, custom trackers, and folders twice.
 *
 * `tests/settingsFieldRules.test.ts` fails when a field is added here
 * without being classified, which is the only thing that has ever made
 * somebody ask the question before shipping rather than after.
 */
export type UserSettings = {
  favoriteTags: string[];
  /**
   * Announcement-banner ids this account dismissed (backlog #175). A
   * set of ids, never a boolean, so the next announcement shows to
   * somebody who dismissed the last one. Synced so one dismiss hides
   * the banner on every device.
   */
  dismissedAnnouncements: string[];
  /**
   * Whether we've already inserted the one-shot "Welcome to
   * PrivacyNotes" starter note for this user. Gated via user_settings
   * (not localStorage) so that signing in on a second device doesn't
   * re-seed the note - the flag syncs across devices just like
   * favorites. Once true, never flipped back to false; if the user
   * deletes the welcome note, it stays deleted.
   */
  welcomeNoteSeeded: boolean;
  /**
   * Legacy: the dismissible sidenav "Import your notes" hint was
   * replaced by a permanent Import button in the sidebar footer, so
   * nothing renders from this flag anymore. Kept for sync compat
   * (like autoProtectLogins); import completion still sets it.
   */
  importHintDismissed: boolean;
  /**
   * How long a successful PIN unlock stays valid for the phrase view and
   * for PIN-protected notes. The app lock screen has a window of its own
   * (`appLockTimeoutMinutes`), because a person who wants the whole app to
   * shut after a minute rarely wants the note they are typing in to do the
   * same.
   *
   * Sentinel values:
   *   - 0  → always ask ("Immediately")
   *   - -1 → valid for the rest of this browser session ("Never re-ask")
   *
   * Positive integers are minutes. Default 5. The actual unlock
   * timestamp lives in sessionStorage - it is intentionally NOT
   * synced so closing the tab re-locks.
   */
  pinTimeoutMinutes: number;
  /**
   * How long the app lock screen stays open before an idle device locks
   * itself again. Same option list and same sentinels as
   * `pinTimeoutMinutes`; the two are configured separately, in the
   * Biometric Lock tab and the PIN tab.
   *
   * A blob written without this field inherits `pinTimeoutMinutes`, so an
   * account that configured one window keeps the window it chose.
   */
  appLockTimeoutMinutes: number;
  /**
   * Notes-list display preferences: sort order + visible row
   * metadata, with a Global default plus per-pillar overrides.
   * Synced so the user sees the same sort/view across devices.
   * See `listPrefs.ts` for the type and helpers.
   */
  listPrefs: ListPrefsStore;
  /**
   * Which layout the Tasks pillar renders.
   *   - 'hybrid': 3 newest task-containing notes up top + aggregated
   *     task list below. Default.
   *   - 'aggregated': current grouped-by-note task list only.
   *   - 'list': task-containing notes as a standard notes list.
   */
  tasksView: 'hybrid' | 'aggregated' | 'list';
  /**
   * Whether the Tasks view shows completed task items. Synced so
   * toggling on one device carries to the others - matches the
   * sync-everything design rule.
   */
  tasksShowDone: boolean;
  /**
   * Legacy field - kept for sync compat but no longer used.
   * PIN-protect is always off on creation; users toggle per-item.
   */
  autoProtectLogins: boolean;
  /**
   * PBKDF2-hashed PIN salt (base64), synced across devices. `null`
   * means no PIN is set. Together with `pinHash`, this replaces the
   * old per-device localStorage PIN storage so the user has the same
   * PIN everywhere.
   */
  pinSalt: string | null;
  /**
   * PBKDF2-hashed PIN digest (base64). See `pinSalt`.
   */
  pinHash: string | null;
  /**
   * PBKDF2 iteration count used when hashing the PIN. Legacy PINs
   * used 100,000; new PINs use 600,000 (OWASP 2024 guidance). `null`
   * means legacy (100k). Stored so `verifyPin` knows which count to
   * use without trial-and-error.
   */
  pinIterations: number | null;
  /**
   * Active medications the user is currently taking. Pre-filled into
   * every journal entry's medication tracker. Configured inline during
   * journaling - not from the settings page.
   */
  medications: MedicationTemplate[];
  /**
   * Mood & wellness tracker settings: which trackers are enabled,
   * custom tracker definitions, archived medications, and safety
   * prompt preferences.
   */
  trackerSettings: TrackerSettings;
  /**
   * Auto-delete trashed notes older than this many days. Runs
   * client-side on app load (server can't see trashed status -
   * it's inside the encrypted payload). 0 = disabled. Default 30.
   */
  autoDeleteTrashDays: number;
  /**
   * @deprecated As of v0.103.5, biometric is purely device-local.
   * Kept for hydration compat with older settings blobs.
   * Nothing reads this field - use `hasBiometricCredential()` instead.
   */
  biometricEnabled: boolean;
  /**
   * Whether the full-app lock screen is enabled. Requires PIN or
   * biometric (or both) to be set up. When active, the phrase is
   * cryptographically wrapped at rest - no plaintext in storage.
   */
  appLockEnabled: boolean;
  /**
   * PIN-wrapped phrase blob, synced across devices. Unlike biometric
   * wraps (hardware-bound), PIN wraps are pure crypto - same PIN +
   * same blob = same unwrap on any device. Stored as base64 strings.
   * `null` when no PIN wrap exists.
   */
  pinWrapSalt: string | null;
  pinWrapIV: string | null;
  pinWrapCiphertext: string | null;
  pinWrapIterations: number | null;
  /**
   * Carried in the blob, but inert: the palette lives in localStorage
   * (`theme.ts` owns every appearance axis and none of them reaches the
   * server), and no path writes a picked theme into this field or reads
   * one back out of it. It is still parsed and migrated so an older
   * client's stored value survives a round trip instead of being
   * dropped. Default 'default'.
   */
  colorTheme: ColorTheme;
  /**
   * Which layout notes render in: 'list' (narrow rows), 'grid'
   * (full-width tiles), or 'auto' (grid on wide screens, list on
   * narrow). Global across every view and synced, so a phone and a
   * desktop agree.
   * Default 'list' so new accounts land on the familiar list + editor
   * layout; an explicit Auto/Grid toggle switches away from it.
   */
  viewMode: 'auto' | 'list' | 'grid';
  /**
   * Views the user switched off in the sidebar's Views list.
   *
   * Stores the REMOVALS, never the keepers: a kept-list written today
   * would not contain a pillar added next year, so that pillar would be
   * invisible on every existing account while the code looked correct.
   * 'home' is never in here - All cannot be hidden.
   * Spec: ops/docs/plans/sidebar-views.md (synced account-wide, not per-device)
   */
  hiddenViews: View[];
  /**
   * Views whose items the user switched off in the All list. Same shape
   * and same reasoning as hiddenViews, and deliberately a separate
   * setting: hiding the Vault row and keeping logins out of All are two
   * different wishes. Applies to the mixed lists only (All, plus the tag
   * and folder views, which are All with a filter on top); a single-type
   * pillar never filters itself.
   * Spec: ops/docs/plans/sidebar-views.md (synced account-wide, not per-device)
   */
  hiddenInAll: View[];
  /**
   * The view the app opens on at a cold start. 'home' is the All list,
   * which is what the app has always done and stays the default.
   *
   * Synced rather than device-local, and that is not only for consistency
   * with the two settings above: this value is validated against
   * hiddenViews, which syncs. A device-local choice coupled to a synced
   * hidden list leaves a repair no code path can perform - hide a view on
   * one device, and another device's stored start view is invalid with
   * nothing able to reach it.
   * Spec: ops/docs/plans/start-view.md (cold start only, All is the default)
   */
  startView: View;
  /**
   * Default editor mode for note bodies: 'formatted' (the live rich
   * editor) or 'markdown' (a plain markdown textarea). Synced like
   * viewMode so the choice follows the user across devices. The
   * per-note "Show markdown" link overrides this for the selected note
   * only, for the current session - it never writes this value.
   */
  editorMode: 'formatted' | 'markdown';
  /**
   * Date shape new journal entry titles are born with. Synced like
   * viewMode: someone who prefers ISO dates prefers them on every
   * device. Only new entries are affected - existing titles are free
   * text the user may already have edited, so nothing rewrites them.
   * GitHub #200. Spec: ops/docs/design-decisions.md (journal entry titles)
   */
  journalTitleFormat: JournalTitleFormat;
  /**
   * Optional text appended after the date, e.g. "Journal". Empty by
   * default so the title stays just the date, as it always has.
   */
  journalTitleSuffix: string;
  /**
   * Pro: folder definitions for the sidebar Folders tree. Small array,
   * nests to any depth; notes point at an entry via their encrypted
   * `folderId`. Merged across devices by id rather than replaced wholesale,
   * so a device holding an older copy cannot remove a folder another device
   * has - see `mergeFolderTrees` in folders.ts, and `foldersDeleted` below,
   * which is what lets a real deletion still travel.
   */
  folders: FolderDef[];
  /**
   * Folders the user deleted, as tombstones. Separate from `folders` on
   * purpose: every surface that draws the tree reads `folders` and would
   * otherwise each need its own filter, and one that forgot would show a
   * folder its owner deleted. Pruned in `validateFolderTombstones`.
   */
  foldersDeleted: FolderTombstone[];
  /**
   * How the folder tree orders siblings. Synced, unlike the tag sort and
   * unlike which folders are open: 'custom' displays the order the user
   * dragged the folders into, that order lives in `FolderDef.order` above
   * and therefore syncs, and a device that did not know to ask for Custom
   * would show an alphabetical list instead of the arrangement its owner
   * built. Spec: ops/docs/design-decisions.md (folders sort by Custom)
   */
  folderSort: { field: FolderSortField; dir: FolderSortDir };
  /**
   * Which axis the sidebar browse section shows: the tag list or the
   * Pro folder tree. Synced like viewMode. Free accounts are pinned
   * to 'tags' in the UI but the value is preserved so it re-applies
   * on upgrade.
   */
  sidebarBrowse: 'tags' | 'folders';
  /**
   * How many items the user created IN the app, all pillars (every
   * pillar is a note internally). createNote() is the only writer;
   * the importer writes rows directly (import/apply.ts), so a mass
   * import never advances this number. That is the point: milestone
   * thresholds read this counter, never stats.totalNotes, so an
   * imported archive cannot fire them on day one. Monotonic - merges
   * take the larger value, and saveLocalSettings refuses to regress
   * it (React state can hold a copy older than the last bump).
   * Spec: ops/docs/plans/rating-prompt-handoff.md (step 2)
   */
  notesCreated: number;
  /**
   * Milestone keys already celebrated for this account, e.g. `notes:25`.
   * SYNCED, not per-device: the free plan allows two devices, and while
   * this lived in localStorage every milestone re-fired the first time
   * someone opened the app on their second device - the rating ask
   * included. Union-merged, so it can only ever grow.
   * Spec: ops/docs/plans/rating-prompt-handoff.md (step 1)
   */
  milestonesSeen: string[];
  /**
   * When this account first ran the app, ISO timestamp. Stamped on first
   * run when absent, so accounts that predate the field get stamped the
   * next time they open the app rather than reading as ancient.
   *
   * This is NOT stats.ageDays, which derives from the oldest note and so
   * reports ~2400 days for a one-day-old account that imported a 2019
   * archive. Merges keep the OLDER value (mirror image of notesCreated):
   * two devices stamping independently must settle on the first one.
   * Spec: ops/docs/plans/rating-prompt-handoff.md (step 3)
   */
  firstSeenAt: string | null;
  /**
   * Whether the user ever opened a link from the rating modal. Once true
   * the app never asks again - they did the thing we asked for, and a
   * second ask reads as nagging. Never flipped back to false.
   */
  ratingDone: boolean;
  /**
   * Freshness counter, and the one field the server cannot forge. It lives
   * INSIDE the encrypted blob, so a server that keeps an old ciphertext and
   * restamps its `updated_at` cannot raise it: rewriting the number means
   * encrypting, and it holds no key. Every local save increases it, and a
   * pulled blob whose number is LOWER than the one this device already holds
   * is a rollback and is refused.
   *
   * Equality is accepted, deliberately. A client that shipped before this
   * field round-trips it without increasing it (hydrate copies unknown keys
   * through, which is what makes this need no migration), so refusing equality
   * would make every save from such a client invisible. Once the release floor
   * has passed the last client that does not increase it, equality could be
   * refused too, and until then a rollback of exactly one step is what this
   * does not catch.
   *
   * Spec: ops/docs/plans/security-residuals-handoff.md (section 3)
   */
  settingsRev: number;
  /**
   * The two app-wide image switches. Space saver fits a new image inside
   * the ceiling in imageProcessing.ts and re-encodes it; metadata removal
   * drops EXIF and every other metadata block. Both apply to new images
   * only: nothing rewrites a blob that is already stored.
   * Spec: ops/docs/plans/image-quality-handoff.md (section 3)
   */
  imageSpaceSaver: ImageSwitch;
  imageStripMetadata: ImageSwitch;
  /**
   * Keep contact photos small: a contact photo fits inside the ceiling in
   * imageProcessing.ts whatever the two switches above say. Off, it follows
   * them like any other image. Read by the contacts photo path.
   * Spec: ops/docs/plans/image-quality-handoff.md (section 7)
   */
  imageContactCeiling: ImageSwitch;
  /**
   * Password generator preferences: length, character set toggles,
   * and exact counts for numbers/symbols. Synced so the user's
   * preferred password shape follows them across devices.
   */
  pwGen: {
    length: number;
    lowercase: boolean;
    uppercase: boolean;
    numbers: boolean;
    symbols: boolean;
    exactNumbers: number;
    exactSymbols: number;
    /** The passphrase half. `mode` is the tab the generator opens on; a
     *  free account always opens on the password tab whatever is stored. */
    mode: 'password' | 'passphrase';
    words: number;
    separator: '-' | '.' | '_' | ' ';
    capitalize: boolean;
    addNumber: boolean;
    addSymbol: boolean;
  };
};

function defaultSettings(): UserSettings {
  return {
    favoriteTags: [],
    dismissedAnnouncements: [],
    welcomeNoteSeeded: false,
    importHintDismissed: false,
    pinTimeoutMinutes: 5,
    appLockTimeoutMinutes: 5,
    listPrefs: DEFAULT_LIST_PREFS_STORE,
    tasksView: 'hybrid',
    tasksShowDone: false,
    autoProtectLogins: false,
    pinSalt: null,
    pinHash: null,
    pinIterations: null,
    medications: [],
    trackerSettings: defaultTrackerSettings(),
    autoDeleteTrashDays: 30,
    biometricEnabled: false,
    appLockEnabled: false,
    pinWrapSalt: null,
    pinWrapIV: null,
    pinWrapCiphertext: null,
    pinWrapIterations: null,
    colorTheme: 'default',
    viewMode: 'list', // Spec: ops/specs/grid-view.md (default view mode)
    hiddenViews: [],
    hiddenInAll: [],
    startView: 'home', // Spec: ops/docs/plans/start-view.md (All is the default)
    editorMode: 'formatted', // Spec: ops/specs/editor-mode-toggle.md (default editor mode)
    // Spec: ops/docs/design-decisions.md (journal entry titles)
    journalTitleFormat: 'long',
    journalTitleSuffix: '',
    folders: [],
    foldersDeleted: [],
    folderSort: { field: 'name', dir: 'asc' },
    sidebarBrowse: 'tags', // Spec: ops/specs/folders.md (sidebarBrowse default)
    // Spec: ops/docs/plans/image-quality-handoff.md (section 3, both default on)
    imageSpaceSaver: 'on',
    imageStripMetadata: 'on',
    imageContactCeiling: 'on',
    notesCreated: 0,
    milestonesSeen: [],
    firstSeenAt: null,
    ratingDone: false,
    settingsRev: 0,
    pwGen: {
      length: 20,
      lowercase: true,
      uppercase: true,
      numbers: true,
      symbols: true,
      exactNumbers: 1,
      exactSymbols: 1,
      mode: 'password',
      words: 5,
      separator: '-',
      capitalize: true,
      addNumber: true,
      addSymbol: false,
    },
  };
}

/**
 * Flip one view's membership in one of the two hidden lists.
 *
 * Two surfaces write these: the rail's own menus (the eye on the Content
 * caption, the funnel on the All row) and the Sidebar table in Appearance.
 * Same field, shown twice, so the flip lives here rather than in either one.
 * Spec: ops/docs/plans/sidebar-views.md (single toggle shared by every write surface, never duplicated)
 */
export function toggleHiddenView(
  prev: UserSettings,
  field: 'hiddenViews' | 'hiddenInAll',
  key: View,
): UserSettings {
  const list = prev[field];
  return {
    ...prev,
    [field]: list.includes(key) ? list.filter((v) => v !== key) : [...list, key],
  };
}

/**
 * The fields the security surfaces write: the PIN hash, the PIN wrap of the
 * phrase and the two lock switches. Those surfaces hand back a whole settings
 * object built from the copy they were rendered with, which can be older than
 * the cache by the time a PIN derivation or an OS prompt finishes. So the
 * surface also hands back that copy, and the caller applies only the
 * credential keys that DIFFER between the two: those are the surface's own
 * changes. Everything else, including a credential another device set in the
 * meantime, comes from the cache. Taking all nine keys from the result was
 * not enough: a PIN set on another device during a biometric prompt here was
 * overwritten by this device's stale nulls.
 */
const CREDENTIAL_FIELDS = [
  'pinSalt',
  'pinHash',
  'pinIterations',
  'pinWrapSalt',
  'pinWrapIV',
  'pinWrapCiphertext',
  'pinWrapIterations',
  'appLockEnabled',
  'biometricEnabled',
] as const;

export function withCredentialChanges(
  prev: UserSettings,
  base: UserSettings,
  next: UserSettings,
): UserSettings {
  const picked: Partial<UserSettings> = {};
  for (const key of CREDENTIAL_FIELDS) {
    if (next[key] !== base[key]) {
      (picked as Record<string, unknown>)[key] = next[key];
    }
  }
  return { ...prev, ...picked };
}

/** Merge a partial/legacy blob into a fully-populated settings object. */
function hydrate(raw: unknown): UserSettings {
  const base = defaultSettings();
  if (!raw || typeof raw !== 'object') return base;
  const obj = raw as Partial<UserSettings>;
  // Preserve fields this client does not know about. Without this, an
  // older client that hydrates a newer blob and then pushes it strips
  // every field added after it shipped (that is how a stale client can
  // silently wipe e.g. the folders array). Copying unknown keys through
  // makes settings round-trip safely across mixed client versions.
  // Known keys are validated field-by-field below as before.
  for (const key of Object.keys(raw)) {
    if (!(key in base)) {
      (base as Record<string, unknown>)[key] = (raw as Record<string, unknown>)[key];
    }
  }
  if (Array.isArray(obj.favoriteTags)) {
    base.favoriteTags = obj.favoriteTags.filter((t): t is string => typeof t === 'string');
  }
  if (Array.isArray(obj.dismissedAnnouncements)) {
    base.dismissedAnnouncements = obj.dismissedAnnouncements.filter(
      (t): t is string => typeof t === 'string'
    );
  }
  if (typeof obj.welcomeNoteSeeded === 'boolean') {
    base.welcomeNoteSeeded = obj.welcomeNoteSeeded;
  }
  if (typeof obj.importHintDismissed === 'boolean') {
    base.importHintDismissed = obj.importHintDismissed;
  }
  if (typeof obj.pinTimeoutMinutes === 'number' && Number.isFinite(obj.pinTimeoutMinutes)) {
    // "Immediately" (0) was removed - it re-prompted every render on
    // PIN-protected notes. Coerce any legacy 0 to the default 5.
    base.pinTimeoutMinutes = obj.pinTimeoutMinutes === 0 ? 5 : obj.pinTimeoutMinutes;
  }
  // A blob with no window of its own for the app lock inherits the PIN one
  // rather than the default, so a device set to lock after a minute cannot
  // come back sitting at five. Runs after the field above, which it reads.
  if (
    typeof obj.appLockTimeoutMinutes === 'number' &&
    Number.isFinite(obj.appLockTimeoutMinutes)
  ) {
    base.appLockTimeoutMinutes =
      obj.appLockTimeoutMinutes === 0 ? 5 : obj.appLockTimeoutMinutes;
  } else {
    base.appLockTimeoutMinutes = base.pinTimeoutMinutes;
  }
  if (obj.listPrefs !== undefined) {
    base.listPrefs = hydrateListPrefsStore(obj.listPrefs);
  }
  if (
    obj.tasksView === 'hybrid' ||
    obj.tasksView === 'aggregated' ||
    obj.tasksView === 'list'
  ) {
    base.tasksView = obj.tasksView;
  }
  if (typeof obj.tasksShowDone === 'boolean') {
    base.tasksShowDone = obj.tasksShowDone;
  }
  if (typeof obj.autoProtectLogins === 'boolean') {
    base.autoProtectLogins = obj.autoProtectLogins;
  }
  if (typeof obj.pinSalt === 'string') {
    base.pinSalt = obj.pinSalt;
  }
  if (typeof obj.pinHash === 'string') {
    base.pinHash = obj.pinHash;
  }
  if (typeof obj.pinIterations === 'number' && Number.isFinite(obj.pinIterations)) {
    base.pinIterations = obj.pinIterations;
  }
  if (Array.isArray(obj.medications)) {
    base.medications = obj.medications;
  }
  if (obj.trackerSettings && typeof obj.trackerSettings === 'object') {
    const ts = obj.trackerSettings as Partial<TrackerSettings>;
    const dts = defaultTrackerSettings();
    base.trackerSettings = {
      activeBuiltins: Array.isArray(ts.activeBuiltins) ? ts.activeBuiltins : dts.activeBuiltins,
      customTrackers: Array.isArray(ts.customTrackers) ? ts.customTrackers : dts.customTrackers,
      archivedMedications: Array.isArray(ts.archivedMedications) ? ts.archivedMedications : dts.archivedMedications,
      weightUnit: WEIGHT_UNITS.includes(ts.weightUnit as WeightUnit) ? (ts.weightUnit as WeightUnit) : dts.weightUnit,
    };
  }
  if (typeof obj.autoDeleteTrashDays === 'number' && Number.isFinite(obj.autoDeleteTrashDays) && obj.autoDeleteTrashDays >= 0) {
    base.autoDeleteTrashDays = obj.autoDeleteTrashDays;
  }
  if (typeof obj.biometricEnabled === 'boolean') {
    base.biometricEnabled = obj.biometricEnabled;
  }
  if (typeof obj.appLockEnabled === 'boolean') {
    base.appLockEnabled = obj.appLockEnabled;
  }
  if (typeof obj.pinWrapSalt === 'string') {
    base.pinWrapSalt = obj.pinWrapSalt;
  }
  if (typeof obj.pinWrapIV === 'string') {
    base.pinWrapIV = obj.pinWrapIV;
  }
  if (typeof obj.pinWrapCiphertext === 'string') {
    base.pinWrapCiphertext = obj.pinWrapCiphertext;
  }
  if (typeof obj.pinWrapIterations === 'number') {
    base.pinWrapIterations = obj.pinWrapIterations;
  }
  if (isColorTheme(obj.colorTheme)) {
    base.colorTheme = obj.colorTheme;
  } else if ((obj as Record<string, unknown>).colorTheme === 'cool-white') {
    // Legacy migration: cool-white was replaced by slate in v0.132.10.
    base.colorTheme = 'slate';
  }
  if (obj.viewMode === 'auto' || obj.viewMode === 'list' || obj.viewMode === 'grid') {
    base.viewMode = obj.viewMode;
  }
  // Members are NOT validated against the View union on purpose. An older
  // client that dropped a value it did not recognise would silently un-hide
  // a newer client's row on its next write; unknown members are ignored at
  // render instead. Same shape as favoriteTags above.
  if (Array.isArray(obj.hiddenViews)) {
    base.hiddenViews = obj.hiddenViews.filter((v) => typeof v === 'string') as View[];
  }
  if (Array.isArray(obj.hiddenInAll)) {
    base.hiddenInAll = obj.hiddenInAll.filter((v) => typeof v === 'string') as View[];
  }
  // Not validated against the View union, for the reason above: an older
  // client that refused a value it did not recognise and wrote the blob back
  // would reset a newer client's choice. resolveStartView filters at read.
  if (typeof obj.startView === 'string') {
    base.startView = obj.startView as View;
  }
  if (obj.editorMode === 'formatted' || obj.editorMode === 'markdown') {
    base.editorMode = obj.editorMode;
  }
  if (isJournalTitleFormat(obj.journalTitleFormat)) {
    base.journalTitleFormat = obj.journalTitleFormat;
  }
  if (typeof obj.journalTitleSuffix === 'string') {
    base.journalTitleSuffix = obj.journalTitleSuffix.slice(0, JOURNAL_SUFFIX_MAX);
  }
  if (obj.folders !== undefined) {
    base.folders = validateFolders(obj.folders);
  }
  if (obj.foldersDeleted !== undefined) {
    base.foldersDeleted = validateFolderTombstones(obj.foldersDeleted);
  }
  // A folder cannot be both live and deleted. The tombstone wins, so a
  // client that predates the field and writes the array wholesale cannot
  // undo a deletion just by carrying its own older copy of the tree.
  if (base.foldersDeleted.length > 0 && base.folders.length > 0) {
    const gone = new Set(base.foldersDeleted.map((d) => d.id));
    if (base.folders.some((f) => gone.has(f.id))) {
      base.folders = validateFolders(base.folders.filter((f) => !gone.has(f.id)));
    }
  }
  if (obj.folderSort && typeof obj.folderSort === 'object') {
    const raw = obj.folderSort as { field?: unknown; dir?: unknown };
    base.folderSort = {
      field: isFolderSortField(raw.field) ? raw.field : 'name',
      dir: raw.dir === 'desc' ? 'desc' : 'asc',
    };
  }
  if (obj.sidebarBrowse === 'tags' || obj.sidebarBrowse === 'folders') {
    base.sidebarBrowse = obj.sidebarBrowse;
  }
  if (obj.imageSpaceSaver === 'on' || obj.imageSpaceSaver === 'off') {
    base.imageSpaceSaver = obj.imageSpaceSaver;
  }
  if (obj.imageStripMetadata === 'on' || obj.imageStripMetadata === 'off') {
    base.imageStripMetadata = obj.imageStripMetadata;
  }
  if (obj.imageContactCeiling === 'on' || obj.imageContactCeiling === 'off') {
    base.imageContactCeiling = obj.imageContactCeiling;
  }
  if (Array.isArray(obj.milestonesSeen)) {
    base.milestonesSeen = obj.milestonesSeen.filter((k): k is string => typeof k === 'string');
  }
  if (typeof obj.firstSeenAt === 'string' && !Number.isNaN(Date.parse(obj.firstSeenAt))) {
    base.firstSeenAt = obj.firstSeenAt;
  }
  if (typeof obj.ratingDone === 'boolean') {
    base.ratingDone = obj.ratingDone;
  }
  // Anything that is not a finite, non-negative number reads as 0, which is
  // the value a blob written before this field existed effectively carries.
  if (typeof obj.settingsRev === 'number' && Number.isFinite(obj.settingsRev) && obj.settingsRev >= 0) {
    base.settingsRev = Math.floor(obj.settingsRev);
  }
  if (
    typeof obj.notesCreated === 'number' &&
    Number.isFinite(obj.notesCreated) &&
    obj.notesCreated >= 0
  ) {
    base.notesCreated = Math.floor(obj.notesCreated);
  }
  if (obj.pwGen && typeof obj.pwGen === 'object') {
    const pg = obj.pwGen as Partial<UserSettings['pwGen']>;
    const dpg = base.pwGen;
    if (typeof pg.length === 'number' && pg.length >= 8 && pg.length <= 64) dpg.length = pg.length;
    if (typeof pg.lowercase === 'boolean') dpg.lowercase = pg.lowercase;
    if (typeof pg.uppercase === 'boolean') dpg.uppercase = pg.uppercase;
    if (typeof pg.numbers === 'boolean') dpg.numbers = pg.numbers;
    if (typeof pg.symbols === 'boolean') dpg.symbols = pg.symbols;
    if (typeof pg.exactNumbers === 'number' && pg.exactNumbers >= 0 && pg.exactNumbers <= 9) dpg.exactNumbers = pg.exactNumbers;
    if (typeof pg.exactSymbols === 'number' && pg.exactSymbols >= 0 && pg.exactSymbols <= 9) dpg.exactSymbols = pg.exactSymbols;
    if (pg.mode === 'password' || pg.mode === 'passphrase') dpg.mode = pg.mode;
    if (typeof pg.words === 'number' && Number.isInteger(pg.words) && pg.words >= 3 && pg.words <= 20) dpg.words = pg.words;
    if (pg.separator === '-' || pg.separator === '.' || pg.separator === '_' || pg.separator === ' ') dpg.separator = pg.separator;
    if (typeof pg.capitalize === 'boolean') dpg.capitalize = pg.capitalize;
    if (typeof pg.addNumber === 'boolean') dpg.addNumber = pg.addNumber;
    if (typeof pg.addSymbol === 'boolean') dpg.addSymbol = pg.addSymbol;
  }
  return base;
}

/** The earlier of two optional ISO stamps; null only when both are null. */
function olderStamp(a: string | null, b: string | null): string | null {
  if (!a) return b;
  if (!b) return a;
  return a < b ? a : b;
}

// ------------------------------------------------------------------
// Local cache (localStorage)
// ------------------------------------------------------------------

// The key (and its demo twin) lives in settingsLocalKey.ts so the
// light notesCreated.ts module can share it - see the comment there.
const localKey = settingsLocalKey;

type LocalCache = {
  settings: UserSettings;
  // ISO timestamp of the last local mutation - used as "client updatedAt"
  // when pushing to the server, so last-write-wins is deterministic.
  updatedAt: string;
  // Whether we have a local change that hasn't been pushed yet. Set on
  // every mutation; cleared after a successful push.
  dirty: boolean;
  // Whether this device has ever SEEN the server's settings row: a pull
  // that decrypted it, a pre-push merge that decrypted it, or a pull that
  // proved no row exists. While false, this device's blob is defaults plus
  // seconds of local history - so a dirty push must take the server row as
  // its base (full mergeSettings), never the ad-hoc local-wins merge. A
  // fresh device that went dirty before its first pull (the v0.450.0
  // firstSeenAt stamp, a pre-pull note create) used to skip the pull AND
  // win the push, overwriting the account's folders, favorite tags, PIN
  // and prefs with defaults. Legacy caches lack the field and default to
  // TRUE: they belong to devices that synced before this field shipped,
  // and treating them as never-pulled would revert their next genuine
  // scalar edit.
  everPulled: boolean;
  // Whether this tab does NOT know the account's PIN wrap. The four wrap
  // fields are a durable copy of the phrase under four digits, so a device
  // the user marked untrusted keeps them out of localStorage the way it
  // keeps the phrase out: the envelope on disk carries them as null there,
  // and the real values live in a sessionStorage side key for as long as
  // the tab does. With no side key the fields are unknown, which is NOT the
  // same as the account holding none: syncPinWrap does nothing with an
  // unknown wrap, and the push takes the four fields from the server row it
  // reads rather than sending nulls over the account's wrap. Never written
  // to disk. Always false on a trusted device, whose envelope is unchanged.
  // Spec: ops/docs/archive/sec-24-untrusted-settings-cache.md
  wrapWithheld: boolean;
  // The account's freshness counter as of the last completed sync: the row
  // this device last adopted or pushed. The restore of unknown wrap fields
  // refuses a server row below it, and it cannot use `settings.settingsRev`
  // for that, because a dirty cache also counts this device's own unpushed
  // saves and an honest row would read as a rollback. Written to disk only
  // on an untrusted device, where the restore can run; a trusted envelope
  // keeps its shape.
  syncedRev: number;
};

type PinWrapFields = Pick<
  UserSettings,
  'pinWrapSalt' | 'pinWrapIV' | 'pinWrapCiphertext' | 'pinWrapIterations'
>;

const NULL_WRAP: PinWrapFields = {
  pinWrapSalt: null,
  pinWrapIV: null,
  pinWrapCiphertext: null,
  pinWrapIterations: null,
};

// Credential-bucketed like the wrap keys biometric.ts writes, so a demo
// session's copy is swept with the rest of the `.demo` bucket.
const wrapSideKey = () => credentialKey('privacynotes.settings.pinWrap');

function pickWrap(s: UserSettings): PinWrapFields {
  return {
    pinWrapSalt: s.pinWrapSalt,
    pinWrapIV: s.pinWrapIV,
    pinWrapCiphertext: s.pinWrapCiphertext,
    pinWrapIterations: s.pinWrapIterations,
  };
}

function readWrapSideKey(): PinWrapFields | null {
  try {
    const raw = sessionStorage.getItem(wrapSideKey());
    if (!raw) return null;
    const p = JSON.parse(raw) as Partial<PinWrapFields>;
    return {
      pinWrapSalt: typeof p.pinWrapSalt === 'string' ? p.pinWrapSalt : null,
      pinWrapIV: typeof p.pinWrapIV === 'string' ? p.pinWrapIV : null,
      pinWrapCiphertext: typeof p.pinWrapCiphertext === 'string' ? p.pinWrapCiphertext : null,
      pinWrapIterations: typeof p.pinWrapIterations === 'number' ? p.pinWrapIterations : null,
    };
  } catch {
    return null;
  }
}

/**
 * The untrusted view of a parsed envelope. An envelope that still carries a
 * wrap was written before the cache withheld it: keep the values and rewrite
 * it once, so the ciphertext leaves the disk on the first read. Otherwise the
 * side key says what this tab knows, present or known absent, and no side
 * key means unknown.
 */
function untrustedView(cache: LocalCache): LocalCache {
  if (hasPinWrap(cache.settings)) {
    const known = { ...cache, wrapWithheld: false };
    writeLocal(known);
    return known;
  }
  const side = readWrapSideKey();
  if (side) {
    return { ...cache, settings: { ...cache.settings, ...side }, wrapWithheld: false };
  }
  return { ...cache, settings: { ...cache.settings, ...NULL_WRAP }, wrapWithheld: true };
}

const EPOCH = '1970-01-01T00:00:00.000Z';

function readLocal(): LocalCache {
  const trusted = isTrustedDevice();
  try {
    const raw = localStorage.getItem(localKey());
    if (!raw) {
      return { settings: defaultSettings(), updatedAt: EPOCH, dirty: false, everPulled: false, wrapWithheld: !trusted, syncedRev: 0 };
    }
    const parsed = JSON.parse(raw) as Partial<LocalCache>;
    const settings = hydrate(parsed.settings);
    const cache: LocalCache = {
      settings,
      updatedAt: typeof parsed.updatedAt === 'string' ? parsed.updatedAt : EPOCH,
      dirty: parsed.dirty === true,
      // Legacy caches (no field): a CLEAN one belongs to a device whose
      // last pass completed, so it has pulled; a DIRTY one is ambiguous -
      // it can be a healthy device with a pending offline edit, or a
      // pre-fix fresh sign-in whose default blob never pushed (the wipe,
      // one pass from completing). Treat dirty-legacy as never-pulled:
      // the worst case for the healthy device is one server-base merge
      // that reverts its pending scalar edit, while the worst case of
      // the opposite guess is the full account wipe. One completed pass
      // writes the field explicitly and retires this heuristic.
      everPulled:
        parsed.everPulled === undefined
          ? parsed.dirty !== true
          : parsed.everPulled === true,
      wrapWithheld: false,
      // An envelope without the field predates it, or was written by a
      // trusted device: treating every local increment as synced is the
      // conservative reading, and the legacy scrub below hands such a cache
      // its wrap anyway, so the restore never needs the number there.
      syncedRev:
        typeof parsed.syncedRev === 'number' && Number.isFinite(parsed.syncedRev) && parsed.syncedRev >= 0
          ? Math.floor(parsed.syncedRev)
          : settings.settingsRev,
    };
    if (!trusted) return untrustedView(cache);
    // A trusted reader of an envelope an untrusted session wrote: the four
    // nulls are that session's withholding, not the account's state, and
    // the side key it kept them in belongs to a tab that is gone. Unknown,
    // until a pass reads the row and writes the trusted shape back.
    if (parsed.wrapWithheld === true) {
      return { ...cache, settings: { ...cache.settings, ...NULL_WRAP }, wrapWithheld: true };
    }
    return cache;
  } catch {
    return { settings: defaultSettings(), updatedAt: EPOCH, dirty: false, everPulled: false, wrapWithheld: !trusted, syncedRev: 0 };
  }
}

function writeLocal(cache: LocalCache): void {
  const { wrapWithheld, syncedRev, ...stored } = cache;
  const trusted = isTrustedDevice();
  // A trusted device that knows its wrap writes exactly the shape it always
  // had. Every other write carries the four fields as null plus a marker
  // saying so, because the trust flag can change under the same envelope: a
  // sign-in that ticks "trust this device" after an untrusted session must
  // not read that session's nulls as the account having no wrap. The
  // marker outlives the flag; a pass that reads the row clears it.
  if (trusted && !wrapWithheld) {
    try {
      localStorage.setItem(localKey(), JSON.stringify(stored));
    } catch {
      /* storage full / disabled - we fall back to in-memory only */
    }
    return;
  }
  try {
    localStorage.setItem(
      localKey(),
      JSON.stringify({
        ...stored,
        settings: { ...stored.settings, ...NULL_WRAP },
        syncedRev,
        wrapWithheld: true,
      }),
    );
  } catch {
    /* storage full / disabled - we fall back to in-memory only */
  }
  // The side key belongs to an untrusted tab that knows the wrap. An absent
  // side key is the record that the fields are unknown here, and writing
  // four nulls over it would turn "not read yet" into "removed".
  if (trusted || wrapWithheld) return;
  try {
    sessionStorage.setItem(wrapSideKey(), JSON.stringify(pickWrap(cache.settings)));
  } catch {
    // A dropped side key reads as unknown on the next read, which is the
    // safe side: the device then sends nothing for these fields until a
    // pass has read them from the server.
  }
}

/**
 * Load the locally-cached settings. Returns defaults if nothing is
 * cached. Does NOT hit the network - use `syncUserSettings` for that.
 */
export function loadLocalSettings(): UserSettings {
  return readLocal().settings;
}

/**
 * Write a new settings blob locally and mark it dirty. The caller
 * should then schedule a sync (debounced in practice). Returns the
 * updated settings so the caller can use them as the next React
 * state value.
 */
export function saveLocalSettings(next: UserSettings): UserSettings {
  // Four fields are write-once-forward and must survive a stale save:
  // callers hand us whole settings objects out of React state, and that
  // state can predate a write another code path made in the meantime
  // (createNote bumps the counter outside React entirely). Roll-back
  // here would re-arm a spent milestone, so each merges rather than
  // overwrites - exactly the rules syncUserSettings applies remotely.
  const current = readLocal();
  const stored = current.settings;
  if (stored.notesCreated > next.notesCreated) {
    next = { ...next, notesCreated: stored.notesCreated };
  }
  if (stored.milestonesSeen.some((k) => !next.milestonesSeen.includes(k))) {
    next = {
      ...next,
      milestonesSeen: [...new Set([...stored.milestonesSeen, ...next.milestonesSeen])],
    };
  }
  const firstSeen = olderStamp(stored.firstSeenAt, next.firstSeenAt);
  if (firstSeen !== next.firstSeenAt) {
    next = { ...next, firstSeenAt: firstSeen };
  }
  if (stored.ratingDone && !next.ratingDone) {
    next = { ...next, ratingDone: true };
  }
  // The freshness counter is derived here rather than trusted from the caller,
  // which hands us whole settings objects out of React state that can predate
  // another write. It only ever moves up.
  next = { ...next, settingsRev: Math.max(stored.settingsRev, next.settingsRev) + 1 };
  const cache: LocalCache = {
    settings: next,
    updatedAt: new Date().toISOString(),
    dirty: true,
    everPulled: current.everPulled,
    // A save that carries a wrap can only have come from a tab that knows
    // it. One that leaves the fields alone leaves them as unknown as they
    // were, and clearPin's nulls over a known wrap are known absent, which
    // is what lets the removal travel.
    wrapWithheld: current.wrapWithheld && !hasPinWrap(next),
    syncedRev: current.syncedRev,
  };
  writeLocal(cache);
  return next;
}

/**
 * Apply a change to the settings the cache holds right now, then save.
 *
 * Every settings write from the UI comes through here rather than through a
 * whole object taken out of React state. That copy can predate the first
 * pull: on a fresh device the state starts as defaults, the pull lands in
 * the cache first, and a change built from the defaults would put an empty
 * folder tree back over the account's real one, which the pulled cache then
 * pushes as its own. The cache is the freshest local truth, so the updater
 * runs against it and the caller's copy is never trusted for the fields it
 * did not change. The stale-pass guard in useSyncOrchestrator stays with the
 * caller.
 *
 * An updater that returns its input unchanged saves nothing: no dirty flag,
 * no counter step, no push.
 */
export function updateLocalSettings(
  updater: (prev: UserSettings) => UserSettings,
): UserSettings {
  const prev = readLocal().settings;
  const next = updater(prev);
  return next === prev ? prev : saveLocalSettings(next);
}

/**
 * Whether this device's settings cache has ever seen the server row
 * (see the everPulled field doc on LocalCache). useSyncOrchestrator
 * gates the one-time firstSeenAt stamp on it, so the stamp can never
 * be the write that arms a defaults-over-server push.
 */
export function hasSettingsPulled(): boolean {
  return readLocal().everPulled;
}

/** Clear any locally cached settings. Called on sign-out, and on a
 *  fresh demo session (where it clears only the demo bucket). */
export function clearLocalSettings(): void {
  try {
    localStorage.removeItem(localKey());
  } catch {
    /* ignore */
  }
  try {
    sessionStorage.removeItem(wrapSideKey());
  } catch {
    /* ignore */
  }
}

/**
 * True while this tab does not know the account's PIN wrap: the cache
 * withholds it on an untrusted device and no pass has read it yet. The
 * settings then carry four nulls that mean "not read", never "removed", and
 * syncPinWrap must not act on them. Pinned by tests/pinRecovery.test.ts and
 * tests/settingsSync.test.ts.
 */
export function isPinWrapWithheld(): boolean {
  return readLocal().wrapWithheld;
}

// ------------------------------------------------------------------
// Remote sync
// ------------------------------------------------------------------

type RemoteRow = {
  user_pubkey: string;
  ciphertext: string;
  nonce: string;
  updated_at: string;
};

/**
 * Union-merge two template arrays by ID with tombstone semantics.
 *
 * Rules:
 * - Every ID present on either side appears in the result.
 * - If both sides have the same ID: tombstoned copy wins (deletion is
 *   permanent). If neither is tombstoned, local copy wins (intentional edit).
 * - Result is never smaller than either input - safe for pull AND push.
 *
 * Medications and custom trackers share this because they share a shape:
 * a template in settings that per-day values in the journal notes point
 * at by id. Dropping one does not merely hide a pill, it orphans every
 * value ever logged against it. Medications got this protection after the
 * first round of loss reports; custom trackers were still taking the
 * wholesale path until they were routed through here too.
 */
type Template = { id: string; deletedAt?: string; updatedAt?: string };

/**
 * Which side wins when both hold an ACTIVE copy of the same id and
 * neither carries an edit stamp.
 *
 * This is not a preference, it is a fact about the caller. On the PULL
 * the local cache is clean by definition (`remoteWins` requires it), so
 * it cannot be hiding an unpushed edit and the server is simply newer.
 * On a PUSH the local cache is dirty, so it may hold the only copy of an
 * edit that has never left this device. Getting this backwards on the
 * pull is what stopped a dosage corrected on one device from ever
 * reaching the others.
 */
type Winner = 'local' | 'remote';

function mergeTemplates<T extends Template>(
  local: T[],
  remote: T[],
  unstampedWinner: Winner = 'local'
): T[] {
  const map = new Map<string, T>();
  for (const m of remote) map.set(m.id, m);
  for (const m of local) {
    const existing = map.get(m.id);
    if (!existing) {
      map.set(m.id, m);
    } else if (m.deletedAt && !existing.deletedAt) {
      // Local has tombstone, remote doesn't - tombstone wins.
      map.set(m.id, m);
    } else if (!m.deletedAt && existing.deletedAt) {
      // Remote has tombstone - keep it (already in map).
    } else if (m.updatedAt || existing.updatedAt) {
      // At least one side carries an edit stamp: the newer edit wins, and
      // a stamped copy beats an unstamped one (it was written by a client
      // that records edits, so it is the later write).
      const localNewer = (m.updatedAt ?? '') > (existing.updatedAt ?? '');
      if (localNewer) map.set(m.id, m);
    } else if (unstampedWinner === 'local') {
      map.set(m.id, m);
    }
  }
  return [...map.values()];
}

function mergeMedications(
  local: MedicationTemplate[],
  remote: MedicationTemplate[],
  unstampedWinner: Winner = 'local'
): MedicationTemplate[] {
  return mergeTemplates(local, remote, unstampedWinner);
}

/** Merge the whole tracker-config object: templates union, the rest
 *  follows whichever side the caller passed as the base. */
function mergeTrackerSettings(
  base: TrackerSettings,
  local: TrackerSettings,
  remote: TrackerSettings,
  unstampedWinner: Winner = 'local'
): TrackerSettings {
  return {
    ...base,
    customTrackers: mergeTemplates<CustomTrackerTemplate>(
      local.customTrackers,
      remote.customTrackers,
      unstampedWinner
    ),
    archivedMedications: mergeTemplates<MedicationTemplate>(
      local.archivedMedications,
      remote.archivedMedications,
      unstampedWinner
    ),
  };
}

/**
 * Merge local and remote settings when a push conflict is detected.
 *
 * General strategy: server wins for scalar prefs (it's newer). For
 * medications: tombstone-aware union by ID so neither side can silently
 * wipe the other's templates, and deletions propagate correctly.
 */
function mergeSettings(
  local: UserSettings,
  remote: UserSettings,
  foldersUnstampedWinner: Winner = 'local',
): UserSettings {
  // Start from remote (newer) as the base for all scalar fields.
  const merged = { ...remote };

  // Folders are not a scalar and must not follow the base. Whichever side is
  // newer, the other one can hold a folder it has never seen, and taking the
  // base wholesale is what let one device's copy stand in for the account's.
  const tree = mergeFolderTrees(
    { folders: local.folders, deleted: local.foldersDeleted },
    { folders: remote.folders, deleted: remote.foldersDeleted },
    foldersUnstampedWinner,
  );
  merged.folders = tree.folders;
  merged.foldersDeleted = tree.deleted;

  // Medications: tombstone-aware union merge.
  merged.medications = mergeMedications(local.medications, remote.medications);

  // Tracker config: scalars follow remote (the base), templates union so
  // neither side can wipe the other's.
  merged.trackerSettings = mergeTrackerSettings(
    remote.trackerSettings,
    local.trackerSettings,
    remote.trackerSettings
  );

  // Favorite tags: union (order doesn't matter much, dedupe).
  const tagSet = new Set([...remote.favoriteTags, ...local.favoriteTags]);
  merged.favoriteTags = [...tagSet];

  // Dismissed announcements: union. A dismiss on either device is spent.
  merged.dismissedAnnouncements = [
    ...new Set([...remote.dismissedAnnouncements, ...local.dismissedAnnouncements]),
  ];

  // Boolean flags that should never regress from true → false.
  if (local.welcomeNoteSeeded) merged.welcomeNoteSeeded = true;
  if (local.importHintDismissed) merged.importHintDismissed = true;

  // Monotonic counter: the larger side has seen more creates.
  merged.notesCreated = Math.max(local.notesCreated, remote.notesCreated);

  // Milestones: union. A celebration shown on either device is spent.
  merged.milestonesSeen = [...new Set([...remote.milestonesSeen, ...local.milestonesSeen])];

  // First seen: the OLDER stamp wins - the account is as old as its
  // earliest sighting, whichever device recorded it.
  merged.firstSeenAt = olderStamp(local.firstSeenAt, remote.firstSeenAt);

  if (local.ratingDone) merged.ratingDone = true;

  // Monotonic, like notesCreated: a merged blob must never push a number
  // lower than one either side has already seen, or its own push reads as a
  // rollback on the next device to pull it.
  merged.settingsRev = Math.max(local.settingsRev, remote.settingsRev);

  return merged;
}

/**
 * A pulled blob carrying a freshness counter lower than the one this device
 * already holds. Thrown rather than returned so it lands in the same place
 * the decrypt failure does, where the local copy is what stands.
 */
class SettingsRollbackError extends Error {
  constructor() {
    super('settings rollback refused');
    this.name = 'SettingsRollbackError';
  }
}

/** Logged once per run of skipped passes, like the notes gate in sync.ts. */
let claimGateLogged = false;

/**
 * Pull-then-push sync for the settings blob.
 *
 * Return value: the post-sync settings (either the remote copy if it
 * won, the local copy if it won, or the default if both were empty).
 * Callers should feed this back into their React state so the UI
 * reflects any remote changes.
 */
export async function syncUserSettings(
  supabase: SupabaseClient,
  pubkey: string,
  encryptionKey: Uint8Array
): Promise<UserSettings> {
  // Demo mode never syncs settings to the server - return local only.
  if (isDemoMode()) return readLocal().settings;
  // Below the release floor server writes pause (see sync.ts). Local settings
  // keep working; the dirty flag survives, so they push after the update.
  if (isServerWriteBlocked()) return readLocal().settings;
  // The session must carry THIS vault's pubkey claim before any read. Under
  // a missing or foreign claim the row policies raise nothing: they filter
  // the select to no rows, which is exactly what "no row exists" looks like
  // from here, and that reading marks the device as pulled and lets its next
  // push carry its default blob over the account's real settings. The notes
  // pass has the same gate for the same reason (sync.ts). A skipped pass
  // reads and writes nothing; the dirty flag waits for one that runs.
  const { data: sessionData } = await supabase.auth.getSession();
  const claim = sessionData?.session?.user?.app_metadata?.pubkey as string | undefined;
  if (claim !== pubkey) {
    if (!claimGateLogged) {
      claimGateLogged = true;
      logAuthEvent('settings:claim-gate-skipped', {
        hasSession: sessionData?.session != null,
        sessionPk: claim?.slice(0, 8) ?? null,
        expectedPk: pubkey.slice(0, 8),
      });
    }
    return readLocal().settings;
  }
  claimGateLogged = false;
  // Private copy of the key for this pass: signOut zeroes the caller's
  // Uint8Array in place once sign-out begins, and a pass still in flight
  // at that moment used to encrypt/decrypt with the zeroed buffer -
  // pushing permanently undecryptable ciphertext over a good server row,
  // then clearing the dirty flag. Same pattern as sync.ts.
  const passKey = new Uint8Array(encryptionKey);
  if (passKey.every((b) => b === 0)) {
    passKey.fill(0);
    console.warn('[settings] sign-out in progress - sync deferred');
    return readLocal().settings;
  }
  const local = readLocal();

  try {
  // ── 1. PULL ────────────────────────────────────────────────────
  const { data: remoteRow, error: pullErr } = await supabase
    .from('user_settings')
    .select('*')
    .eq('user_pubkey', pubkey)
    .maybeSingle();

  let effective: LocalCache = local;

  if (pullErr) {
    console.error('[settings] pull failed:', pullErr);
  } else if (remoteRow) {
    const row = remoteRow as RemoteRow;
    // Remote wins iff it is strictly newer than our local copy AND we
    // don't have a pending local edit (mirrors notes sync behavior:
    // never clobber dirty local edits).
    // A cache that does not know the account's wrap is not as fresh as the
    // row whatever its stamp says: adopting the row is what puts the wrap
    // back into memory for this tab.
    const remoteWins =
      !local.dirty && (row.updated_at > local.updatedAt || local.wrapWithheld);
    if (remoteWins) {
      try {
        const remoteSettings = hydrate(
          decryptJson(
            base64ToBytes(row.ciphertext),
            base64ToBytes(row.nonce),
            passKey
          )
        );
        // Rollback refusal. `updated_at` is a column the server writes, so a
        // server that serves an OLD ciphertext with a NEW stamp passes the
        // freshness test above and this device adopts a settings blob it has
        // already moved past. That is how a credential can be deleted by a
        // genuine old copy: the wrap fields are settings like any other. The
        // counter inside the blob is the answer, because raising it means
        // encrypting and the server holds no key.
        //
        // Strictly lower only. See the settingsRev field doc for why equality
        // is accepted, and for what that leaves uncovered.
        if (remoteSettings.settingsRev < local.settings.settingsRev) {
          logAuthEvent('settings:rollback-refused');
          console.warn('[settings] refused a remote blob older than this device holds');
          throw new SettingsRollbackError();
        }
        // Remote is authoritative for scalars, but medications use
        // tombstone-based union-merge so no device can ever silently
        // wipe another's templates. Deletions are represented as
        // { ...med, deletedAt: timestamp } - not absence from array.
        // 'remote': this branch runs only when the local cache is CLEAN
        // and the server row is strictly newer, so a template both sides
        // hold cannot be carrying a local edit the server has not seen.
        remoteSettings.medications = mergeMedications(
          local.settings.medications,
          remoteSettings.medications,
          'remote'
        );
        remoteSettings.trackerSettings = mergeTrackerSettings(
          remoteSettings.trackerSettings,
          local.settings.trackerSettings,
          remoteSettings.trackerSettings,
          'remote'
        );

        // Boolean flags that must never regress true -> false.
        if (local.settings.welcomeNoteSeeded) {
          remoteSettings.welcomeNoteSeeded = true;
        }
        if (local.settings.importHintDismissed) {
          remoteSettings.importHintDismissed = true;
        }
        if (local.settings.notesCreated > remoteSettings.notesCreated) {
          remoteSettings.notesCreated = local.settings.notesCreated;
        }
        remoteSettings.milestonesSeen = [
          ...new Set([...remoteSettings.milestonesSeen, ...local.settings.milestonesSeen]),
        ];
        remoteSettings.firstSeenAt = olderStamp(
          local.settings.firstSeenAt,
          remoteSettings.firstSeenAt
        );
        if (local.settings.ratingDone) remoteSettings.ratingDone = true;
        // Folders merge on the way in as well as on the way out. The server
        // copy is newer, but newer is not the same as complete: it can have
        // been written by a device that never knew about a folder this one
        // holds, or by a client too old to merge at all. Whatever the merge
        // adds back has to be pushed, or this device alone would hold the
        // repaired tree, so a merge that changed anything re-arms the dirty
        // flag. 'remote' settles a tie because a clean local cache cannot be
        // hiding an edit that never left the device.
        const pulledTree = mergeFolderTrees(
          { folders: local.settings.folders, deleted: local.settings.foldersDeleted },
          { folders: remoteSettings.folders, deleted: remoteSettings.foldersDeleted },
          'remote',
        );
        const treeRepaired = !folderTreesEqual(pulledTree, {
          folders: remoteSettings.folders,
          deleted: remoteSettings.foldersDeleted,
        });
        remoteSettings.folders = pulledTree.folders;
        remoteSettings.foldersDeleted = pulledTree.deleted;
        if (treeRepaired) {
          logAuthEvent('settings:folders-repaired', {
            folders: pulledTree.folders.length,
          });
        }
        // A repair has to carry a NEW stamp. Keeping the server row's own
        // would push the repaired tree back under the timestamp it already
        // has, so every other device's freshness test would say it had
        // already seen this row and none of them would ever pull the repair.
        effective = {
          settings: remoteSettings,
          updatedAt: treeRepaired ? new Date().toISOString() : row.updated_at,
          dirty: treeRepaired,
          everPulled: true,
          // The row is the account's, wrap fields included.
          wrapWithheld: false,
          syncedRev: remoteSettings.settingsRev,
        };
        // A settings write that landed while the pull was in flight is newer
        // than anything this pass read, so it stands and the pass leaves the
        // cache alone. Without the check the pull silently erased it, dirty
        // flag included, and the change never reached the server.
        const current = readLocal();
        if (current.updatedAt > local.updatedAt) {
          // The cache is what stands, so it is also what this pass carries
          // forward: the push below reads `effective`, and the caller sets
          // React state from what is returned. Handing back the discarded
          // remote blob here would push its scalars over the write that just
          // landed and show the user the settings they had just changed away.
          console.warn('[settings] local write landed mid-pull - keeping it');
          effective = current;
        } else {
          writeLocal(effective);
        }
      } catch (err) {
        // A refused rollback is not a decrypt failure and must not read as
        // one: the local copy stands and the pass continues to the push,
        // which is what puts this device's newer blob back on the server.
        if (err instanceof SettingsRollbackError) {
          effective = { ...local, dirty: true };
          writeLocal(effective);
        } else {
          console.error('[settings] decrypt failed:', err);
        }
      }
    }
  } else {
    // Pull succeeded and no row exists: the server holds nothing this
    // device could destroy, so its first push may safely proceed as an
    // insert. Recording that also unlocks the firstSeenAt stamp (see
    // hasSettingsPulled).
    if (!local.everPulled) {
      // No row means the account holds no wrap either, so four nulls are
      // the truth here rather than an unknown.
      effective = { ...local, everPulled: true, wrapWithheld: false, syncedRev: 0 };
      writeLocal(effective);
    }
  }

  // ── 2. PUSH (conflict-aware) ────────────────────────────────────
  if (effective.dirty) {
    const snapshotUpdatedAt = effective.updatedAt;

    // Medications (and archived medications) must never be blind-overwritten
    // by the fast update path below. When local is dirty the PULL above is
    // skipped, so this device can hold stale templates - e.g. a freshly-
    // signed-in device that edited settings before its first pull landed.
    // The fast path's conditional update succeeds whenever this device's
    // timestamp is newer, which would silently wipe another device's meds.
    // Re-read the server row and union-merge the array fields first so the
    // outgoing blob can only ever grow the medication set, never shrink it.
    // Scalar prefs follow local ONLY on a device that has pulled at least
    // once (this device is the newest writer of choices it actually made);
    // a never-pulled device takes the server row as its base instead - see
    // the everPulled branch below and the field doc on LocalCache.
    let outgoing = effective.settings;
    const { data: preRow, error: preErr } = await supabase
      .from('user_settings')
      .select('ciphertext, nonce')
      .eq('user_pubkey', pubkey)
      .maybeSingle();
    // A never-pulled device may only push over a row it has actually
    // READ. On a failed read, preRow is null exactly like "no row
    // exists", and proceeding would push the near-default blob over the
    // account's real row - the wipe, back through the error path. Defer:
    // dirty stays set, everPulled stays false, the next pass retries.
    // A device that HAS pulled keeps the old behavior (its local-wins
    // push is legitimate; the med union just misses one pass).
    // Deferred for EVERY device, not only a never-pulled one. The folder tree
    // and the template lists are merged against the server row on the way
    // out, so a push that could not read that row is a push that would write
    // this device's copy of them wholesale - which is the shape of write that
    // cost two accounts their folders. Deferring costs one pass; the dirty
    // flag stays set and the next pass does the whole thing.
    if (preErr) {
      console.error('[settings] pre-push read failed - push deferred:', preErr);
      return effective.settings;
    }
    if (preRow) {
      try {
        const serverSettings = hydrate(
          decryptJson(
            base64ToBytes((preRow as RemoteRow).ciphertext),
            base64ToBytes((preRow as RemoteRow).nonce),
            passKey
          )
        );
        if (!effective.everPulled) {
          // This device has NEVER seen the server blob, and the row it is
          // about to overwrite is the account's real settings (folders,
          // favorite tags, PIN, theme, prefs). Server wins via the full
          // conflict merge; the union fields keep their rules. Deliberate
          // cost: scalar edits made on this device BEFORE its first pull
          // (usually seconds of history; hours if it signed in offline)
          // revert to the account's values, including a locally set PIN.
          // That is the right bias - the alternative was this device
          // wiping every other one.
          // Folders are the exception to that bias, because they are not a
          // preference: a folder this device made before its first pull is
          // real work, and the server's tree is the account's. The merge
          // keeps both, and 'remote' settles a shared id, which matters for
          // the starter folders, whose ids are fixed rather than fresh.
          outgoing = mergeSettings(effective.settings, serverSettings, 'remote');
        } else {
          // Same rule as the medication templates below, and the one that
          // matters most: this device's tree can be stale, and writing it
          // whole removes every folder another device made in the meantime.
          const pushTree = mergeFolderTrees(
            { folders: effective.settings.folders, deleted: effective.settings.foldersDeleted },
            { folders: serverSettings.folders, deleted: serverSettings.foldersDeleted },
            'local',
          );
          outgoing = {
            ...effective.settings,
            folders: pushTree.folders,
            foldersDeleted: pushTree.deleted,
            medications: mergeMedications(
              effective.settings.medications,
              serverSettings.medications
            ),
            // Same reason as medications: this device can hold a stale
            // template list, and a blind overwrite deletes a custom
            // tracker another device just created - orphaning every value
            // already logged against it.
            trackerSettings: mergeTrackerSettings(
              effective.settings.trackerSettings,
              effective.settings.trackerSettings,
              serverSettings.trackerSettings
            ),
            notesCreated: Math.max(
              effective.settings.notesCreated,
              serverSettings.notesCreated
            ),
            milestonesSeen: [
              ...new Set([
                ...effective.settings.milestonesSeen,
                ...serverSettings.milestonesSeen,
              ]),
            ],
            firstSeenAt: olderStamp(
              effective.settings.firstSeenAt,
              serverSettings.firstSeenAt
            ),
            ratingDone: effective.settings.ratingDone || serverSettings.ratingDone,
          };
          // The cache withheld the wrap and no pass has read it in this tab,
          // so the four nulls in `effective.settings` mean "unknown", and
          // pushing them would clear the account's wrap from a device that
          // never held it. The row this pass just read is the source, under
          // the same rollback rule as the pull: an older row is not one, and
          // the push waits for a pass that reads a current row.
          if (effective.wrapWithheld) {
            if (serverSettings.settingsRev < effective.syncedRev) {
              console.warn('[settings] wrap unknown here and the server row is older - push deferred');
              return effective.settings;
            }
            outgoing = { ...outgoing, ...pickWrap(serverSettings) };
          }
        }
      } catch (err) {
        console.error('[settings] pre-push merge decrypt failed:', err);
        // Same rule as the failed read above: a never-pulled device must
        // not blind-overwrite a row it could not merge with, and neither
        // may a device whose wrap fields are unknown, because its push
        // would carry four nulls over a row it could not read. (For a
        // pulled device that knows its wrap this stays a warning: same key
        // means same phrase, so an undecryptable row is corrupt and
        // overwriting it is the recovery.)
        if (!effective.everPulled || effective.wrapWithheld) {
          return effective.settings;
        }
      }
    }

    const { ciphertext, nonce } = encryptJson(outgoing, passKey);
    const payload = {
      user_pubkey: pubkey,
      ciphertext: bytesToBase64(ciphertext),
      nonce: bytesToBase64(nonce),
      updated_at: effective.updatedAt,
    };

    // Try a conditional update: only succeed if server row isn't newer.
    const { data: updated, error: updateErr } = await supabase
      .from('user_settings')
      .update({
        ciphertext: payload.ciphertext,
        nonce: payload.nonce,
        updated_at: payload.updated_at,
      })
      .eq('user_pubkey', pubkey)
      .lte('updated_at', effective.updatedAt)
      .select('user_pubkey');

    if (updateErr) {
      console.error('[settings] push failed:', updateErr);
    } else if (!updated || updated.length === 0) {
      // Two possibilities: server has a newer row (conflict), or no
      // row exists yet (first-time user). Check which.
      const { data: existing } = await supabase
        .from('user_settings')
        .select('ciphertext, nonce, updated_at')
        .eq('user_pubkey', pubkey)
        .maybeSingle();

      if (!existing) {
        // No row - first-time insert.
        const { error: insertErr } = await supabase
          .from('user_settings')
          .insert(payload);
        if (insertErr) {
          console.error('[settings] insert failed:', insertErr);
        } else {
          const current = readLocal();
          if (current.updatedAt === snapshotUpdatedAt) {
            // The insert proves the server held no row - nothing existed
            // for this device to have missed.
            const cleaned: LocalCache = { ...current, dirty: false, everPulled: true, wrapWithheld: false, syncedRev: current.settings.settingsRev };
            writeLocal(cleaned);
            effective = cleaned;
          }
        }
      } else {
        // Conflict: server is newer. Merge and re-push. The local side is
        // `outgoing`, not the raw cache: outgoing already carries the unions
        // this pass took against the row it read - the folder tree, the
        // medications and the tracker templates - and re-merging from the
        // raw cache would throw all of that away and start again from a copy
        // that has seen less.
        console.warn('[settings] conflict detected - merging');
        try {
          const serverSettings = hydrate(
            decryptJson(
              base64ToBytes(existing.ciphertext),
              base64ToBytes(existing.nonce),
              passKey
            )
          );
          // The rollback rule belongs here as well as on the pull, and this is
          // the door the plan for it did not name. This branch adopts the
          // server's scalars, so a stale row that beat the conditional update
          // would come straight back in through the merge - including the
          // credential fields - after the pull had just refused it. A device
          // that has never pulled is exempt: it holds no history to be rolled
          // back to, and taking the server as its base is what stops it wiping
          // every other device.
          const rolledBack =
            effective.everPulled && serverSettings.settingsRev < outgoing.settingsRev;
          if (rolledBack) {
            logAuthEvent('settings:rollback-refused');
            console.warn('[settings] conflict row is older than this device holds - keeping ours');
          }
          // A refused rollback keeps this device's blob, and even then the
          // folders merge: refusing the server's SCALARS is not a reason to
          // drop a folder the server holds and this device has not seen.
          const merged = rolledBack
            ? {
                ...outgoing,
                ...(() => {
                  const tree = mergeFolderTrees(
                    { folders: outgoing.folders, deleted: outgoing.foldersDeleted },
                    { folders: serverSettings.folders, deleted: serverSettings.foldersDeleted },
                    'local',
                  );
                  return { folders: tree.folders, foldersDeleted: tree.deleted };
                })(),
              }
            : mergeSettings(outgoing, serverSettings, effective.everPulled ? 'local' : 'remote');
          const mergedAt = new Date().toISOString();
          const enc = encryptJson(merged, passKey);
          const { error: mergeErr } = await supabase
            .from('user_settings')
            .update({
              ciphertext: bytesToBase64(enc.ciphertext),
              nonce: bytesToBase64(enc.nonce),
              updated_at: mergedAt,
            })
            .eq('user_pubkey', pubkey);
          if (mergeErr) {
            console.error('[settings] merge push failed:', mergeErr);
          } else {
            effective = { settings: merged, updatedAt: mergedAt, dirty: false, everPulled: true, wrapWithheld: false, syncedRev: merged.settingsRev };
            writeLocal(effective);
          }
        } catch (err) {
          console.error('[settings] merge decrypt failed:', err);
        }
      }
    } else {
      // Update succeeded - clear dirty and persist the merged blob so this
      // device's local cache reflects the union (it won't pull again until
      // the server row is strictly newer). Guarded so a local mutation that
      // landed mid-push is not clobbered.
      const current = readLocal();
      if (current.updatedAt === snapshotUpdatedAt) {
        // Either the pre-push merge above decrypted the server row, or no
        // row existed - both count as having seen the server.
        const cleaned: LocalCache = { settings: outgoing, updatedAt: current.updatedAt, dirty: false, everPulled: true, wrapWithheld: false, syncedRev: outgoing.settingsRev };
        writeLocal(cleaned);
        effective = cleaned;
      }
    }
  }

  return effective.settings;
  } finally {
    passKey.fill(0);
  }
}
