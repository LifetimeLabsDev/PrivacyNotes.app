import { DEFAULT_STORE as DEFAULT_LIST_PREFS_STORE, type ListPrefsStore } from './listPrefs';
import { defaultTrackerSettings, type TrackerSettings, type MedicationTemplate } from './trackerTypes';
import type { ColorTheme, LineSpacing } from './theme';
import type { JournalTitleFormat } from './notesViewUtils';
import type { Clock, DateOrder } from './intlFormat';
import type { View } from './views';
import type { FolderDef, FolderSortDir, FolderSortField, FolderTombstone } from './folders';
import type { ItemStyles, NoteColorStyle } from './itemStyles';
import type { DeviceLabels } from './deviceLabels';
import type { CustomThemes } from './customThemes';
import type { FormatBarSetting } from './formatBar';

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
export type CalendarSettings = {
  alertTimed: number | null;
  alertAllDay: { days: number; at: string } | null;
  alertBirthday: { days: number; at: string } | null;
  weekNumbers: boolean;
  hourStart: string;
  hourEnd: string;
  reminderTitles: boolean;
};

/** Settings › Date & Time › Calendar as it starts: 10 minutes before a timed item, 09:00 on
 *  the day of an all-day one, 09:00 the day before a birthday, no week
 *  numbers, the hours 07:00 to 22:00, titles shown.
 *  Spec: ops/docs/plans/calendar-pillar-spec.md (decision 11) */
export function defaultCalendarSettings(): CalendarSettings {
  return {
    alertTimed: 10,
    alertAllDay: { days: 0, at: '09:00' },
    alertBirthday: { days: 1, at: '09:00' },
    weekNumbers: false,
    hourStart: '07:00',
    hourEnd: '22:00',
    reminderTitles: true,
  };
}

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
   * Whether the Tasks view shows completed task items. Synced so
   * toggling on one device carries to the others - matches the
   * sync-everything design rule.
   */
  tasksShowDone: boolean;
  /**
   * Whether a task moves below the open tasks of its list when it is ticked,
   * in the editor and in the Tasks view alike. On by default.
   */
  sinkCheckedTasks: boolean;
  /**
   * Whether the Personal and Work spaces are on (Pro). On by default; off
   * shows every item and hides the switch. Spec: ops/docs/plans/spaces.md
   */
  spaces: boolean;
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
   * narrow). Global across every view. The pick itself is stored per
   * device (`viewMode.ts`), because a phone and a desktop want different
   * layouts; this synced value is only read as the start value for a
   * device that never picked, and nothing in the app writes it.
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
   * Whether the All list, and the tag and folder views built on it, also
   * hold archived items. The one All switch stored as ON rather than as a
   * removal: archived items are out of All by default, and a removal list
   * could only express the opposite default.
   * Spec: ops/issues/archive/0388.md (archived items in All, off by default)
   */
  archivedInAll: boolean;
  /**
   * Whether an open folder lists the items of its subfolders too. One switch
   * for every folder and every section, because the folder filter scopes all
   * of them at once. Off lists the direct members only.
   * Spec: ops/docs/plans/folder-subfolders.md (D1, D2)
   */
  includeSubfolders: boolean;
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
   * The gap between two paragraphs in a note body: 'compact' (none, so
   * Enter costs the same line as Shift+Enter), 'tight' (no gap and closer
   * lines) or 'normal'. Synced like
   * editorMode, because it describes how somebody writes rather than the
   * screen they write on, and a note typed on a phone is read on a
   * laptop. A blob with no value means compact, so every account lands
   * there until somebody changes it.
   * GitHub #255. Spec: ops/docs/design-decisions.md (editor paragraph rhythm)
   */
  lineSpacing: LineSpacing;
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
   * The order of day, month and year in every date the app shows: 'auto'
   * follows the app language plus the device region, so it resolves on each
   * device. Synced, as a top-level key of its own, so an older client copies
   * it through. Anything else reads as 'auto'. GitHub #251.
   * Spec: ops/docs/plans/dates.md (section 3.3)
   */
  dateOrder: DateOrder;
  /** 24-hour or 12-hour clock; 'auto' follows the device, as `dateOrder` does. */
  clock: Clock;
  /**
   * A custom pattern for new journal titles, from Day.js token names
   * (`formatPattern` in intlFormat.ts). Empty by default. A non-empty pattern
   * is the active choice over the preset and takes no suffix; picking a preset
   * clears it. A new key rather than a new `journalTitleFormat` value, which
   * an older client would revert. GitHub #200.
   * Spec: ops/docs/plans/dates.md (section 3.5)
   */
  journalTitlePattern: string;
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
   * Pro: the look of each folder and tag, an icon and a color, keyed
   * `f:<folder id>` or `t:<tag>`. A map of registers that merges per value at
   * every sync point, beside the folder tree rather than inside it - see
   * itemStyles.ts for why.
   * Spec: ops/docs/plans/folder-tag-icons.md (section 5)
   */
  itemStyles: ItemStyles;
  /**
   * The names a person gave their registered devices, by device id. Merged
   * per device at every sync point, like the looks - see deviceLabels.ts.
   * Spec: ops/docs/design-decisions.md (device labels live in the settings blob)
   */
  deviceLabels: DeviceLabels;
  /**
   * Pro: the color themes a person made, one theme code per id. Merged per
   * theme at every sync point; which theme a device shows stays on the
   * device. See customThemes.ts.
   * Spec: ops/docs/color-themes.md (section 6)
   */
  customThemes: CustomThemes;
  /**
   * Pro: the format bar a person arranged, as one stamped register, merged at
   * every sync point like the looks. Empty or reset is the stock bar.
   * Spec: ops/docs/plans/format-bar.md (section 8)
   */
  formatBar: FormatBarSetting;
  /**
   * Whether a note takes its folder or tag color as its background: the open
   * note, its list row and its grid tile. One switch for all notes, synced
   * like the theme.
   * Spec: ops/docs/plans/folder-tag-icons.md (section 4.6)
   */
  tintNotes: boolean;
  /**
   * How strongly a note shows its color: as a background, or only on its
   * icon. A field of its own beside `tintNotes`, which keeps its meaning for
   * older clients; the Appearance control writes both.
   * Spec: ops/docs/plans/note-color-style.md (section 4)
   */
  noteColorStyle: NoteColorStyle;
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
   * Whether the user closed the import offer that the list panes show. One
   * dismissal hides it in every pillar and on every device, and it never
   * comes back. Spec: ops/docs/design-decisions.md (the import offer lives in the list)
   */
  importPromptDismissed: boolean;
  /**
   * Settings › Date & Time › Calendar: the alert a new alert list starts with for a timed
   * item (minutes before), an all-day item and a birthday (days before, at a
   * time), null for none; the week numbers column; the hours the hour grid
   * opens on; and whether a reminder shows the item's title.
   * Spec: ops/docs/plans/calendar-pillar-spec.md (decisions 11 and 15)
   */
  calendar: CalendarSettings;
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

export function defaultSettings(): UserSettings {
  return {
    favoriteTags: [],
    dismissedAnnouncements: [],
    welcomeNoteSeeded: false,
    importHintDismissed: false,
    pinTimeoutMinutes: 5,
    appLockTimeoutMinutes: 5,
    listPrefs: DEFAULT_LIST_PREFS_STORE,
    tasksShowDone: false,
    sinkCheckedTasks: true,
    spaces: true,
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
    archivedInAll: false,
    includeSubfolders: false,
    startView: 'home', // Spec: ops/docs/plans/start-view.md (All is the default)
    editorMode: 'formatted', // Spec: ops/specs/editor-mode-toggle.md (default editor mode)
    // Spec: ops/docs/design-decisions.md (editor paragraph rhythm)
    lineSpacing: 'compact',
    // Spec: ops/docs/design-decisions.md (journal entry titles)
    journalTitleFormat: 'long',
    journalTitleSuffix: '',
    dateOrder: 'auto',
    clock: 'auto',
    journalTitlePattern: '',
    folders: [],
    foldersDeleted: [],
    itemStyles: {},
    deviceLabels: {},
    customThemes: {},
    formatBar: {},
    // Spec: ops/docs/plans/folder-tag-icons.md (decision D10, on)
    tintNotes: true,
    // Spec: ops/docs/plans/note-color-style.md (decision N5, accent)
    noteColorStyle: 'accent',
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
    importPromptDismissed: false,
    // Spec: ops/docs/plans/calendar-pillar-spec.md (decision 11)
    calendar: defaultCalendarSettings(),
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
  // Archive's All switch is its own field; see archivedInAll.
  if (field === 'hiddenInAll' && key === 'archive') {
    return { ...prev, archivedInAll: !prev.archivedInAll };
  }
  const list = prev[field];
  return {
    ...prev,
    [field]: list.includes(key) ? list.filter((v) => v !== key) : [...list, key],
  };
}

/** Whether the All list holds a view's items: the checkbox state. */
export function isShownInAll(s: Pick<UserSettings, 'hiddenInAll' | 'archivedInAll'>, key: View): boolean {
  return key === 'archive' ? s.archivedInAll : !s.hiddenInAll.includes(key);
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
export const CREDENTIAL_FIELDS = [
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
