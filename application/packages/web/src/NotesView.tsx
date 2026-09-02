import { useEffect, useLayoutEffect, useRef, useState, useCallback, useMemo, useDeferredValue, type CSSProperties } from 'react';
import { useTranslation, Trans } from 'react-i18next';
import { CaretRight, Folder, Fire } from './icons';
import { useAuth, type AuthState } from './auth';
import type { SupabaseClient } from '@notes/shared';
import {
  getNote,
  createNote,
  updateNote,
  trashNote,
  restoreNote,
  permanentlyDelete,
  emptyTrash,
  setStarred,
  setLocked,
  setPinProtected,
  duplicateNote,
  countUnsyncedNotes,
} from './notesRepo';
import { runAtRestSweep } from './localSweep';
import { parseMarkdownFile } from './import/markdown';
import { FolderPicker } from './FolderPicker';
import { BookmarksList, type BookmarkDraft } from './BookmarksList';
import { openExternal } from './openExternal';
import { noteLinkKey } from './noteLinks';
import { parseLinkBody, buildLinkBody, buildLinkKeyMap } from './linkBody';
import { canDeleteFolder, UNFILED_ID } from './folders';
import { FolderNamesContext } from './folderNames';
import { db, reopenDb, type LocalNote } from './db';
import { ConflictModal } from './ConflictModal';
import { fetchQuotaUsage, heartbeat, recalculateQuota, type QuotaUsage } from './devices';
import { type EditorHandle } from './Editor';
import { readToolbarPref, writeToolbarPref } from './editorPrefs';
import { DemoBanner } from './DemoBanner';
import { AnnouncementBanner } from './AnnouncementBanner';
import { MoveBanner, MovedBookmarkHint } from './MoveBanner';
import { setWikiLinkNavigator } from './NoteLink';
import { setWikiLinkNoteTitles } from './NoteLinkSuggestion';
import { type TagInputHandle } from './TagInput';

import { LogoIcon } from './LogoIcon';
import { TypewriterLine } from './LoadingScreen';
import { toggleHiddenView,
  loadLocalSettings,
  saveLocalSettings,
  type UserSettings,
} from './userSettings';
import { SettingsShell } from './SettingsShell';
import { iconSignOut } from './icons';
import { activeLocale } from './languages';
import { UpgradeModal } from './UpgradeModal';
import { PinGateModal } from './ProtectedNoteGate';
import { shouldPromptForPin, markPinUnlocked, hasPin, syncPinCache } from './pin';
import { syncPinWrap } from './pinRecovery';
import { startPinKeepAlive } from './pinKeepAlive';
import { hasBiometricCredential, unlockWithBiometric } from './biometric';
import { rememberOpenNote, takeReopenNote } from './appReLock';
import { createNoteVersion } from './noteVersions';
import { HoverLabel } from './HoverLabel';
import { useNoteEditing } from './useNoteEditing';
import { useSyncOrchestrator } from './useSyncOrchestrator';
import { useTheme, FREE_THEMES } from './theme';
import { searchNotes } from './search';
import { useSearchIndexSync } from './searchIndexSync';
import type { NewMilestone } from './milestones';
import { pendingRatingMilestones } from './ratingPrompt';
import { DonationModal } from './DonationModal';
import { MilestoneToast } from './MilestoneToast';
import { FeedbackModal } from './FeedbackModal';
import { RateModal } from './RateModal';
import { AppearanceSheet } from './AppearanceSheet';
import { UploadProgressModal } from './UploadProgressModal';
import { ExportProgressModal } from './ExportProgressModal';
import { useKeyboardShortcuts } from './useKeyboardShortcuts';
import { useMultiSelect } from './useMultiSelect';
import {
  ContextMenu,
  useContextMenu,
  isEditableTarget,
  shouldUseBrowserDefault,
  isTouchContextMenu,
  optsOutOfAppMenu,
  type ContextMenuItem,
} from './ContextMenu';
import { computeStats } from './stats';
import { countWords } from './wordCountUtils';
import { isDemoMode, proUnlocked } from './demo';
import { recordAdminEvent } from './adminEvents';
import { createBurnLink, prepareBurnPayload } from './burnShare';
import { ImageStore, readImageSizes, listImageSizes } from './imageStore';
import { EmptyTrashModal } from './EmptyTrashModal';
import { DeleteNoteModal } from './DeleteNoteModal';
import { ConfirmModal } from './ConfirmModal';
import { setImageStore, setImageUploadContext } from './EncryptedImage';
import { AttachmentStore } from './attachmentStore';
import { setAttachmentStore, setAttachmentUploadContext } from './EncryptedAttachment';
import { gcOnNoteDelete, gcOnNotesDelete } from './imageGC';
import {
  extractAllTasks,
  selectTaskNotes,
  setTaskCheckedInBody,
  appendTaskToBody,
  INBOX_TITLE,
  type TaskItem,
} from './tasks';
import { useIsMobile } from './useIsMobile';
import { isSoftKeyboardDevice, suppressSoftKeyboard, createLongPressGuard } from './softKeyboard';
import { useKeyboardOpen } from './useKeyboardOpen';
import { useEscapeToClose, closeTopOverlay, hasOpenOverlay } from './useEscapeToClose';
import { useEdgeSwipe, EDGE_START_PX } from './useEdgeSwipe';
import {
  usePaneResize,
  SIDEBAR_WIDTH_DEFAULT, SIDEBAR_WIDTH_MIN, SIDEBAR_WIDTH_MAX,
  LIST_WIDTH_DEFAULT, LIST_WIDTH_MIN, LIST_WIDTH_MAX,
  SIDEBAR_VIEWPORT_CAP, LIST_VIEWPORT_CAP,
  EDITOR_DOCK_DEFAULT, EDITOR_DOCK_MIN, EDITOR_DOCK_STORE_MAX, GRID_DOCK_MIN,
  STRIPS_W,
} from './usePaneResize';

// Derived reserves for the docked-grid clamp system (see usePaneResize.ts
// constants comment). DOCK_SIDEBAR_RESERVE caps the sidebar (strips + full
// grid floor + editor min); DOCK_GRID_RESERVE is what the grid-floor
// formula subtracts (sidebar min + strips + editor min).
// Spec: ops/docs/design-decisions.md (pane resize clamps)
const DOCK_SIDEBAR_RESERVE = STRIPS_W + GRID_DOCK_MIN + EDITOR_DOCK_MIN;
const DOCK_GRID_RESERVE = SIDEBAR_WIDTH_MIN + STRIPS_W + EDITOR_DOCK_MIN;
import { setAndroidBackHandler } from './androidBack';
import { TagsRail } from './TagsRail';
import type { FolderSortDir, FolderSortField } from './folders';
import { VIEW_NOTE_TYPES, type View } from './views';
import { CollapsedSidebar } from './CollapsedSidebar';
import { FilesList, extractFileItems, type FileType } from './FilesList';
import { FILE_ACCEPT } from './attachmentValidation';
import {
  type ListPrefs,
  type ListPrefsStore,
  resolvePrefs,
  viewToPillar,
} from './listPrefs';
import {
  compareNotes,
  deriveDisplayTitle,
  noteLinkName,
  deriveExcerpt,
  formatModified,
  isWeekJournal,
  getMondayIso,
  journalTitle,
  toLocalIso,
  hotkeyLabel,
  VAULT_EMPTY_BODIES,
} from './notesViewUtils';
import type { JournalTrackerData } from './trackerTypes';
import { BurnShareModal } from './notesView/BurnShareModal';
import { FullFooter, MiniFooter } from './notesView/AppFooter';
import { useTagActions } from './notesView/useTagActions';
import { useFolderActions } from './notesView/useFolderActions';
import { useFilesUpload } from './notesView/useFilesUpload';
import {
  buildSettingsCategories,
  StatsModal,
  AboutModal,
  SecurityModal,
  SyncOptionsModal,
  NoteHistoryModal,
  ImportModal,
} from './notesView/settingsCategories';
import { ProActivationPendingBanner } from './notesView/ProActivationPendingBanner';
import { SnapshotForbiddenBanner } from './notesView/SnapshotForbiddenBanner';
import { StoragePastDueBanner } from './notesView/StoragePastDueBanner';
import { useExports } from './notesView/useExports';
import { createContextMenuBuilders } from './notesView/contextMenus';
import { MobileDrawer } from './notesView/MobileDrawer';
import { NoteEditorPane } from './notesView/NoteEditorPane';
import type { QuickActionsTier } from './notesView/NoteQuickActions';
import { QuotaExceededBanner } from './notesView/QuotaExceededBanner';
import { isStorageConfigured } from './paddle';
import { SyncErrorBanner } from './notesView/SyncErrorBanner';
import { SessionExpiredModal } from './notesView/SessionExpiredModal';
import { SignOutConfirmModal } from './notesView/SignOutConfirmModal';
import { NotesList } from './NotesList';
// Static, NOT lazy. Making these four lazy is the obvious way to keep the
// pillar out of the boot chunk, and it crashes the app: a Suspense boundary
// anywhere above `MarkdownFilePane` lets React disconnect and reconnect the
// subtree, TipTap's `useEditor` destroys the editor on the disconnect and does
// not rebuild it, and the reconnected effects then reach through a destroyed
// instance (`editor.commands` throws inside TipTap's own getter, where the
// `if (!editor)` guard cannot see it - a destroyed editor is still truthy).
// The cost of keeping them static is recorded in the two budgets in
// vite.config.ts. Spec: ops/docs/bundle-size.md (chunk gzip budgets raised to cover these four staying static)
import { MarkdownListPane } from './markdownFolder/MarkdownListPane';
import { MarkdownFilePane } from './markdownFolder/MarkdownFilePane';
import type { OpenedMarkdownFile, OpenedMarkdownDir } from './markdownFolder/types';
import { MarkdownRail } from './markdownFolder/MarkdownRail';
import { MarkdownExplainer, MarkdownPitch } from './markdownFolder/MarkdownExplainer';
import { MarkdownDefaultAppCard } from './markdownFolder/MarkdownDefaultApp';
import { markdownDefaultAppSupported } from './markdownFolder/defaultApp';
import { useTagIndex } from './markdownFolder/useTagIndex';
import { usePendingFileOpens } from './markdownFolder/usePendingFileOpens';
import { useFolderRestore } from './markdownFolder/useFolderRestore';
import { useFolderRefresh } from './markdownFolder/useFolderRefresh';
import TasksList from './TasksList';

/** Does a plain note created from this pillar land somewhere the user can see
 *  it? A pillar that answers `false` renders something other than the notes
 *  list, so the note is made silently in the background and the click looks
 *  like it did nothing - `handleNew` bounces to 'all' first (#46b). Written as
 *  a total Record rather than an `if` on one view name so that adding a pillar
 *  to `View` fails to compile until it answers here: the Files-only condition
 *  shipped the identical bug a second time when the Markdown pillar arrived.
 *  Journal, tasks, starred and vault answer `true` - each creates its own type
 *  and shows it in place - and trash hides its "New Note" button entirely. */
const NEW_NOTE_IS_VISIBLE: Record<View, boolean> = {
  all: true,
  home: true,
  journal: true,
  starred: true,
  trash: true,
  tasks: true,
  vault: true,
  files: false,
  markdown: false,
  bookmarks: false,
};

type Authed = Extract<AuthState, { status: 'authenticated' }>;

/**
 * How long after an app open the rating ask may appear. Long enough that
 * the app has painted and the first sync has had its say, short enough
 * that the user is still in the same sitting.
 * Spec: ops/docs/plans/rating-prompt-handoff.md
 */
const RATING_ASK_DELAY_MS = 4000;

/**
 * Editor header widths, measured on the header row itself rather than the
 * viewport, because the sidebar and the notes list are drag-resizable and a
 * wide window says nothing about how wide the editor pane is. Above the
 * first and second, the quick-action pill appears in its two tiers.
 *
 * Both numbers are lower than a window width would suggest, because this row
 * does not grow with the window: it wears `.pn-content-col`, so at the
 * default reading column it stops at 896px however wide the pane gets. A
 * threshold above that is unreachable for everyone who never changes the
 * column.
 *
 * Both were set from what is left for the TITLE, which is the row's first
 * claim and the thing every other number is spent against. They are also
 * deliberately ABOVE the 896px the default reading column caps this row at,
 * so the common case shows the short row rather than a dozen icons: the
 * extra groups arrive only on a genuinely wide pane, or once the reader
 * picks the wide or full column themselves. At 896 that leaves the title
 * 583px.
 *
 * Nothing else in this row hides by width. The back/forward pair is the only
 * way to retrace a step on a phone, where the notes list is not on screen at
 * all; share is the action people reach for, so it holds its place at every
 * width; and burn, pin and trash live in the "..." menu, which never hides.
 * Spec: ops/docs/ui-patterns.md (section 80)
 */
const QUICK_ACTIONS_CORE_PX = 960;
const QUICK_ACTIONS_ALL_PX = 1280;
/**
 * How far a note has to run past its scroller before the editor's find pill
 * appears. One comfortable line, so a note hovering on the boundary does not
 * flicker the pill while somebody types.
 * Spec: ops/docs/design-decisions.md (the editor corner holds only controls that can hide themselves)
 */
const NOTE_OVERFLOW_SLACK_PX = 40;

export function NotesView() {
  const { auth, supabase, signOut, forceSignOut, refreshProStatus, revalidationExpired } = useAuth();
  if (auth.status !== 'authenticated') return null;
  return (
    <AuthenticatedView
      auth={auth}
      supabase={supabase}
      signOut={signOut}
      forceSignOut={forceSignOut}
      refreshProStatus={refreshProStatus}
      revalidationExpired={revalidationExpired}
    />
  );
}

function AuthenticatedView({
  auth,
  supabase,
  signOut,
  forceSignOut,
  refreshProStatus,
  revalidationExpired,
}: {
  auth: Authed;
  supabase: SupabaseClient;
  signOut: (opts?: { keepUnsyncedNotes?: boolean }) => Promise<void>;
  forceSignOut: (reason?: string) => Promise<void>;
  refreshProStatus: () => Promise<void>;
  /** Boot revalidation hit a definitive CAPTCHA rejection - session is
   *  dead, show SessionExpiredModal. See auth.tsx, backlog #118. */
  revalidationExpired: boolean;
}) {
  const { t } = useTranslation('notes');

  const isMobile = useIsMobile();
  const keyboardOpen = useKeyboardOpen();
  const mobileTabIndex = isMobile ? -1 : undefined;
  const [notes, setNotes] = useState<LocalNote[]>([]);
  // The at-rest sweep: one idle-delayed pass per session converts any
  // plaintext backlog. Module-scoped and deliberately not cancelled on
  // unmount - a re-lock keeps keys in memory and the sweep continues.
  // Spec: ops/docs/plans/local-at-rest.md (section 5.3)
  useEffect(() => {
    const timer = window.setTimeout(() => void runAtRestSweep(), 4000);
    return () => window.clearTimeout(timer);
  }, []);
  // The full-text index follows this state - see searchIndexSync.ts.
  // The version feeds the displayNotes memo so a search recomputes
  // right after the index catches up with a state change.
  const searchIndexVersion = useSearchIndexSync(notes);
  // True when the local IndexedDB read failed even after a reopen+retry.
  // Drives a fallback UI so a dead DB never leaves a silent blank screen
  // (iOS standalone resume bug, #112).
  const [loadError, setLoadError] = useState(false);
  // An app-lock re-lock unmounts this view, so the note that was open comes
  // back through appReLock rather than through any state React kept. Null on
  // every other mount, including a cold start. Spec: ops/docs/biometric-unlock.md (section 3.3)
  const [selectedId, setSelectedId] = useState<string | null>(() => takeReopenNote());
  /** The note a `[[note-link]]` click just jumped to, held until the list
   *  catches up. `navigateToNoteByTitle` drops the filters that hide its
   *  target, but the list does not always widen in the same render: the
   *  search runs through `useDeferredValue`, so `displayNotes` still holds
   *  the old, narrow result set when the auto-select effect fires. Without
   *  this the effect read a fresh jump as a stale selection and replaced it,
   *  which is what made a note-link look dead under a filter.
   *
   *  A note restored after a re-lock needs the identical protection for the
   *  identical reason, one render earlier: the list is still empty while it
   *  loads from IndexedDB, and the auto-select effect would read the restored
   *  note as a stale selection and clear it before it ever appeared. */
  const linkTargetRef = useRef<string | null>(selectedId);
  /** Set once when an RLS-rejected snapshot insert is detected (Pro
   *  lapsed mid-edit). Banner is dismissible; the flag persists for
   *  the rest of the session so we don't re-prompt on every edit.
   *  See gap #6. */
  const [snapshotForbidden, setSnapshotForbidden] = useState(false);
  const [snapshotBannerDismissed, setSnapshotBannerDismissed] = useState(false);
  /** Set when `refreshProStatus` exhausts its 18 s poll without seeing
   *  Pro flip on. The user paid but nothing visibly changed - surface
   *  a friendly banner so they know to wait or contact support, not
   *  double-purchase. See gap #23. */
  const [proActivationPending, setProActivationPending] = useState(false);
  // `search` updates once per typing pause, not per keystroke - the
  // input itself echoes from local state inside ListSearchInput (#130).
  // The deferred wrapper lets the input's last echo paint before the
  // expensive query render (MiniSearch + re-sort, ~400 ms at 5k items)
  // commits.
  const [search, setSearch] = useState('');
  const deferredSearch = useDeferredValue(search);
  const [showStats, setShowStats] = useState(false);
  const [showAbout, setShowAbout] = useState<false | { tab?: 'about' | 'changelog' | 'hotkeys' }>(false);
  const [showFeedback, setShowFeedback] = useState(false);
  const [showRate, setShowRate] = useState(false);
  const [showSyncOptions, setShowSyncOptions] = useState(false);
  const [showAppearance, setShowAppearance] = useState(false);
  // SecurityModal replaces the old Phrase+PinPrompt pair. `null` =
  // closed; the object tells the modal which tab to open on.
  const [showSecurity, setShowSecurity] = useState<
    null | { tab: 'pin' | 'phrase' | 'biometric'; reason?: 'protect' }
  >(null);
  // UpgradeModal opens from Settings and from any Pro-gated action.
  // The optional trigger biases the intro copy so the user knows
  // what they just tried to do.
  const [showUpgrade, setShowUpgrade] = useState<
    | null
    | { trigger: 'lock' | 'protect' | 'history' | 'devices' | 'zen' | 'theme' | 'storage' | 'callout' | 'fileSize' | 'folders' | 'totp' | null }
  >(null);
  const [exportProgress, setExportProgress] = useState<{ status: string; done: boolean; error?: string } | null>(null);
  // Note-options "..." menu state. `null` = closed.
  const [showNoteOptions, setShowNoteOptions] = useState(false);
  const noteOptionsButtonRef = useRef<HTMLButtonElement | null>(null);
  // PIN verification overlay - stores a callback to run on success.
  // The note whose gate is open only so its protection can come off. Both
  // menus set it; the gate clears it once the user removes or backs out.
  const [removeProtectionFor, setRemoveProtectionFor] = useState<string | null>(null);
  /**
    * Take the protection off a note, behind the same check that opens it.
    *
    * The fingerprint is asked for HERE, inside the click, because a browser
    * raises the OS prompt only under a user gesture - a prompt fired from an
    * effect one tick later can be refused, and refused silently. A pass takes
    * the lock off with no screen change at all. Anything else falls through to
    * the note's gate, which offers the finger again and the PIN beside it.
    */
  async function requestRemoveProtection(id: string) {
    setSelectedId(id);
    // The screen changes FIRST. The OS sheet is drawn over whatever is already
    // there, so prompting before this left the user confirming a disable while
    // looking at the unlock screen, and a pass then took the lock off with
    // nothing on screen having acknowledged the request.
    setRemoveProtectionFor(id);
    if (!hasBiometricCredential()) return;
    // Still inside the click, ahead of the first await, which is what lets the
    // browser raise the prompt at all.
    const phrase = await unlockWithBiometric(
      t('security:lockScreen.unlockWithBiometrics'),
      t('common:actions.cancel'),
    );
    // A refusal leaves the disable screen standing, where the same finger and
    // the PIN are both one press away.
    if (!phrase) return;
    setRemoveProtectionFor(null);
    void handleSetPinProtected(id, false);
  }
  // Note history modal - open for a specific note id. Pro only.
  const [historyForNoteId, setHistoryForNoteId] = useState<string | null>(null);
  // Bump this to force re-evaluation of shouldPromptForPin - React
  // doesn't know sessionStorage has changed otherwise. We bump on
  // successful unlock and on a slow poll so expired timeouts re-lock
  // any currently-open protected note.
  const [pinUnlockVersion, setPinUnlockVersion] = useState(0);
  // Notes protected since the last unlock. Protecting a note gates it at
  // once instead of at the end of the unlock window, so the switch has a
  // visible effect: the pane shows the gate and the row drops its preview.
  // Cleared by markUnlocked, after which the shared timer governs again.
  const [justProtectedIds, setJustProtectedIds] = useState<ReadonlySet<string>>(new Set());

  /** Everything an unlock does: refresh the shared timer, tell React the
   *  timer moved, and drop the instant gate a fresh protect put on. */
  function markUnlocked() {
    markPinUnlocked();
    setPinUnlockVersion((v) => v + 1);
    setJustProtectedIds(new Set());
  }
  const [importExportModal, setImportExportModal] = useState<
    { open: false } | { open: true; tab: 'import' | 'export' | 'restore' | 'vault' }
  >({ open: false });
  const [showShareMenu, setShowShareMenu] = useState(false);
  const [showSettings, setShowSettings] = useState(false);
  // Deep-link target for SettingsShell (e.g. the storage banner opens it
  // straight to the Storage pane). Undefined = land on the default category.
  const [settingsCategory, setSettingsCategory] = useState<string | undefined>(undefined);
  // Clear the deep-link target whenever Settings closes, so a later open
  // from the gear / shortcut lands on the default category. Closing can
  // happen from many embedded panes, so reset here rather than per-site.
  // Set when the user arrived by clicking the sync status, so the
  // ID & Sync pane runs the verification without a second click. Cleared
  // with the deep-link target below.
  const [settingsAutoVerify, setSettingsAutoVerify] = useState(false);
  useEffect(() => {
    if (!showSettings) {
      setSettingsCategory(undefined);
      setSettingsAutoVerify(false);
    }
  }, [showSettings]);
  /** "Synced" is a claim; this is how the user gets it checked. */
  const openSyncVerify = useCallback(() => {
    setSettingsCategory('me');
    setSettingsAutoVerify(true);
    setShowSettings(true);
  }, []);
  const [importToast, setImportToast] = useState<string | null>(null);
  /** Show a transient toast and clear it again. The Markdown pillar reports
   *  every one of its disk failures this way, and hand-rolling the pair at each
   *  call site is how one of them ends up without the clear. */
  function flashToast(message: string) {
    setImportToast(message);
    window.setTimeout(() => setImportToast(null), 3000);
  }
  const [burnShareUrl, setBurnShareUrl] = useState<string | null>(null);
  const [burnCopied, setBurnCopied] = useState(false);
  const [burnError, setBurnError] = useState<string | null>(null);
  const [burnImagesStripped, setBurnImagesStripped] = useState(false);
  const [view, setView] = useState<View>('home');
  /** Vault sub-filter: narrow by item type within the vault view. */
  type VaultFilter = 'all' | 'login' | 'card' | 'ssh-key';
  const [vaultFilter, setVaultFilter] = useState<VaultFilter>('all');
  /** The Markdown pillar's open file. Lives here rather than inside the pane
   *  because both columns need it: the list column shows its name and tags, the
   *  editor column shows its contents. Session-only and never persisted - it is
   *  a handle on a file the user picked, not app data. */
  const [markdownFile, setMarkdownFile] = useState<OpenedMarkdownFile | null>(null);
  /** The Markdown pillar's open folder and its scanned entries. Session-only
   *  and never persisted: on the web these are handles the browser will not let
   *  us re-acquire without another user gesture, so remembering them across a
   *  reload would promise something we cannot deliver. */
  const [markdownDir, setMarkdownDir] = useState<OpenedMarkdownDir | null>(null);
  /** Rail filters for the Markdown pillar. Both narrow the same list; neither
   *  touches note state, so they live here purely because the rail and the list
   *  are rendered from two different places in this shell. */
  const [markdownDirFilter, setMarkdownDirFilter] = useState<string | null>(null);
  const [markdownTagFilter, setMarkdownTagFilter] = useState<string | null>(null);
  /** The Markdown reference card, opened by the `?` on the folder row. Was also
   *  a first-run gate in front of the picker until 2026-08-14; that mode went
   *  when the empty state started carrying the same pitch.
   *  Spec: ops/docs/plans/markdown-folder.md (section 12) */
  const [markdownExplain, setMarkdownExplain] = useState(false);
  const [markdownDelete, setMarkdownDelete] = useState<OpenedMarkdownFile | null>(null);
  const [markdownDeleteMany, setMarkdownDeleteMany] = useState<string[] | null>(null);

  /**
   * Bodies already sitting in the encrypted notes, for "have I saved this file
   * before?".
   *
   * The file's whole raw text IS the note body - `handleImportMarkdown` passes
   * `raw` straight through - so an exact body match is a precise answer to that
   * question rather than a heuristic. Two notes with byte-identical bodies are
   * the same note by any definition a user would recognise.
   *
   * Matching on content and not on the source path is a deliberate choice, not a
   * shortcut. A path would need a new field on `LocalNote`, which is a synced
   * shape, so every note in every account would start carrying a filesystem path
   * from whichever machine touched it last - a sync-protocol change and a pile of
   * local path metadata crossing between devices, to answer a question the
   * content already answers.
   *
   * Trashed notes deliberately do not count: someone who threw the note away and
   * saves again means it.
   */
  function savedNoteBodies(): Set<string> {
    const bodies = new Set<string>();
    for (const n of notes) {
      if (n.trashed === 0 && n.type === 'note') bodies.add(n.body);
    }
    return bodies;
  }

  /** Copy a plaintext file into the encrypted notes. One-way on purpose: the
   *  original file is left exactly where it is, so nobody loses a copy they
   *  still rely on in another editor.
   *  Spec: ops/docs/plans/markdown-folder.md (section 10) */
  async function handleImportMarkdown(filename: string, raw: string) {
    // Converted the way a DROPPED .md is converted: front matter becomes the
    // title, the tags and the trackers, and the body arrives without it. It
    // used to be the raw file text, so the same file became two different
    // notes depending on whether it was dropped on the app or saved from the
    // folder view - and the saved one showed its YAML as a heading.
    const parsed = parseMarkdownFile(filename, raw);
    // Saving the same unchanged file twice used to make a second note, every
    // time, with nothing on screen to say the first one existed. Open the one
    // that is already there instead, which is what the second click was for.
    //
    // Matched against BOTH shapes: a note saved before the conversion above
    // holds the file's raw text, so comparing only the converted body would
    // read every one of them as new and duplicate it on the next click.
    const already = notes.find(
      (n) => n.trashed === 0 && (n.body === parsed.body || n.body === raw),
    );
    if (already) {
      setView('all');
      setSelectedId(already.id);
      flashToast(t('shell:markdown.alreadySavedToast', { title: parsed.title }));
      return;
    }
    const created = await createNote(
      parsed.title,
      parsed.body,
      parsed.tags,
      false,
      parsed.type ?? 'note',
    );
    // Trackers have no `createNote` parameter, and a journal file that lost
    // them would look identical and silently be a different note.
    const withTrackers = parsed.trackers
      ? ((await updateNote(created.id, { trackers: parsed.trackers })) ?? created)
      : created;
    setNotes((prev) => [withTrackers, ...prev]);
    setView('all');
    setSelectedId(created.id);
    flashToast(t('shell:markdown.importedToast', { title: parsed.title }));
  }

  /** Copy several plaintext files into the encrypted notes at once. Reads run
   *  in sequence rather than in parallel: each one is a note write plus a state
   *  update, and a burst of them starves the editor for no gain. */
  async function handleImportMarkdownMany(paths: string[]) {
    if (!markdownDir) return;
    const byPath = new Map(markdownDir.entries.map((e) => [e.relPath, e.ref]));
    // Seeded from what is already saved and then added to as we go, so the skip
    // covers both "saved on an earlier run" and two identical files inside THIS
    // selection. `notes` cannot do the second job on its own: `setNotes` has not
    // applied yet by the time the next file is read.
    const seen = savedNoteBodies();
    let done = 0;
    let skipped = 0;
    for (const path of paths) {
      const ref = byPath.get(path);
      if (!ref) continue;
      try {
        const raw = await ref.read();
        // Same conversion and the same both-shapes check as the single save
        // above, for the same two reasons.
        const parsed = parseMarkdownFile(ref.name, raw);
        if (seen.has(parsed.body) || seen.has(raw)) { skipped++; continue; }
        seen.add(parsed.body);
        const created = await createNote(
          parsed.title,
          parsed.body,
          parsed.tags,
          false,
          parsed.type ?? 'note',
        );
        if (parsed.trackers) await updateNote(created.id, { trackers: parsed.trackers });
        setNotes((prev) => [created, ...prev]);
        done++;
      } catch { /* one unreadable file must not abort the rest */ }
    }
    // Bulk gets a count, never a prompt: a modal per already-saved file in a
    // fifty-file selection is worse than the duplicates were.
    flashToast(
      skipped > 0
        ? t('shell:markdown.importedManySkippedToast', { saved: done, skipped })
        : t('shell:markdown.importedManyToast', { count: done }),
    );
  }

  /** Move several files to `.trash/`, then rescan once at the end. */
  async function handleMarkdownDeleteMany(paths: string[]) {
    setMarkdownDeleteMany(null);
    if (!markdownDir) return;
    // One unwritable file must not abort the rest, but it must not pass in
    // silence either: the rescan below simply leaves that row in place, which
    // on its own reads as the delete never having been asked for.
    let failed = 0;
    for (const path of paths) {
      try { await markdownDir.ref.trashFile(path); } catch { failed++; }
    }
    setMarkdownFile(null);
    setMarkdownDir({ ref: markdownDir.ref, entries: await markdownDir.ref.scan() });
    if (failed > 0) flashToast(t('shell:markdown.deleteFailed'));
  }

  /** Move a plaintext file to `.trash/` inside the user's own folder - never an
   *  unlink, so a regretted delete is recoverable in their file manager. */
  async function handleMarkdownDelete(file: OpenedMarkdownFile) {
    setMarkdownDelete(null);
    if (!markdownDir) return;
    try {
      await markdownDir.ref.trashFile(file.ref.location);
      setMarkdownFile(null);
      setMarkdownDir({ ref: markdownDir.ref, entries: await markdownDir.ref.scan() });
    } catch {
      flashToast(t('shell:markdown.deleteFailed'));
    }
  }
  // Tags live inside files, so they need a read of every one - a background
  // pass, deliberately not part of the scan, so the list is usable immediately.
  const markdownTags = useTagIndex(markdownDir?.entries ?? null);
  // Restored at app start rather than when the pillar is first opened, so the
  // sidebar's file count is there on launch instead of only after a visit.
  const markdownRestore = useFolderRestore(markdownDir, setMarkdownDir);
  // Nothing watches the folder, so this is what notices a file added or removed
  // by Obsidian, git or Finder while the app was in the background. Straight to
  // `setMarkdownDir` and not through the list's `onDir`, which also clears the
  // rail filters: the user did not change folder, and having their subfolder
  // selection dropped by a background refresh would be its own bug.
  useFolderRefresh(markdownDir, setMarkdownDir);
  // A double-click in Finder or Explorer lands here, once auth and the app lock
  // are behind us. Switching the view is part of honouring it: opening a file
  // into a pillar the user cannot see would look like nothing happened.
  usePendingFileOpens(
    (file) => {
      setMarkdownFile(file);
      setView('markdown');
    },
    // The window came forward because the user double-clicked something. Saying
    // nothing at that point is indistinguishable from the app ignoring them.
    () => flashToast(t('shell:markdown.openFailed')),
  );
  /** Files pillar type filter - lifted here so it survives FilesList
   *  unmount/remount when the ternary swaps component types. */
  const [fileFilter, setFileFilter] = useState<FileType>('all');
  const [selectedTag, setSelectedTag] = useState<string | null>(null);
  /** Pro folders: active folder filter - the sibling of selectedTag.
   *  Ephemeral navigation state (per-session, like tag selection). */
  const [selectedFolder, setSelectedFolder] = useState<string | null>(null);
  const [toast, setToast] = useState<NewMilestone | null>(null);
  const [donationReason, setDonationReason] = useState<string | null>(null);
  const [drawerOpen, setDrawerOpen] = useState(false);
  const [showSignOutConfirm, setShowSignOutConfirm] = useState(false);
  // Covers the sign-out gap with a full-screen notice: signOut() awaits a
  // final sync + device revoke + local wipe before the view flips, which
  // otherwise looks like a frozen app for a second or two.
  const [signingOut, setSigningOut] = useState(false);
  const [signOutDontRemind, setSignOutDontRemind] = useState(false);
  /** dirty=1 rows counted when the sign-out confirm opens - drives the
   *  unsynced-notes warning in SignOutConfirmModal. */
  const [unsyncedCount, setUnsyncedCount] = useState(0);
  // Hydrated from localStorage; remote sync overwrites on mount if newer.
  const [userSettings, setUserSettings] = useState<UserSettings>(() => {
    const loaded = loadLocalSettings();
    // NOTE: the legacy per-device PIN migration that ran here was
    // removed. Its source keys are the same localStorage keys
    // syncPinCache writes, so on a shared browser it adopted the
    // PREVIOUS account's PIN into a brand-new account's synced
    // settings (foreign PIN prompt on the phrase tab, PIN hash leaked
    // across accounts). syncPinCache also clears the stale cache when
    // the loaded settings carry no PIN.
    //
    // Skip entirely in demo: ?demo=1 runs on the SAME origin as a real
    // install, but the PIN cache and wrapped-phrase keys are NOT
    // demo-bucketed. Calling syncPinCache with the demo blob (pinHash
    // null) would wipe the real account's PIN cache off this origin.
    if (!isDemoMode()) {
      syncPinCache(loaded);
      // The wrap follows the cached settings the same way the hash cache
      // above does, in both directions.
      syncPinWrap(loaded);
    }
    return loaded;
  });
  // Tag sort control (persisted). Field = what to sort by, dir = asc/desc.
  // 'entries' sorts by number of notes carrying the tag.
  type TagSortField = 'name' | 'modified' | 'entries';
  type TagSortDir = 'asc' | 'desc';
  // Default is 'entries' descending: the most-used tags float to the
  // top where they're easiest to click. Anyone who prefers alphabetical
  // can switch and we'll remember it.
  const [tagSortField, setTagSortField] = useState<TagSortField>(() => {
    const v = typeof window !== 'undefined'
      ? window.localStorage.getItem('privacynotes.tagSort.field')
      : null;
    return v === 'name' || v === 'modified' || v === 'entries' ? v : 'entries';
  });
  const [tagSortDir, setTagSortDir] = useState<TagSortDir>(() => {
    const v = typeof window !== 'undefined'
      ? window.localStorage.getItem('privacynotes.tagSort.dir')
      : null;
    return v === 'asc' ? 'asc' : 'desc';
  });

  // ESC-to-close for overlays that don't have their own modal component
  // (the mobile drawer registers its own inside MobileDrawer)
  useEscapeToClose(() => setShowShareMenu(false), showShareMenu);

  useEffect(() => {
    window.localStorage.setItem('privacynotes.tagSort.field', tagSortField);
  }, [tagSortField]);
  useEffect(() => {
    window.localStorage.setItem('privacynotes.tagSort.dir', tagSortDir);
  }, [tagSortDir]);

  // Live prefs - resolve per-pillar so each view can own its own copy
  // (bookmarks, files, journal, vault). Falls back to global, plus that
  // pillar's starting delta, when no copy exists.
  //
  // Memoized because `resolvePrefs` returns a FRESH object for any pillar
  // carrying a delta, and this value is a dependency of the list's sort and
  // filter memo below. Unmemoized it re-sorted the whole library on every
  // render.
  const listPrefs: ListPrefs = useMemo(
    () => resolvePrefs(userSettings.listPrefs, viewToPillar(view as any)),
    [userSettings.listPrefs, view]
  );

  function handleListPrefsChange(nextStore: ListPrefsStore) {
    mutateSettings((prev) => ({ ...prev, listPrefs: nextStore }));
  }

  function handleTasksViewChange(nextView: UserSettings['tasksView']) {
    const next = { ...userSettings, tasksView: nextView };
    setUserSettings(next);
    saveLocalSettings(next);
  }

  // Mirror showDoneTasks onto synced settings. Local alias keeps all
  // the existing render sites untouched while the source of truth
  // lives on `userSettings.tasksShowDone`.
  const showDoneTasks = userSettings.tasksShowDone;
  function setShowDoneTasks(updater: boolean | ((v: boolean) => boolean)) {
    const nextVal =
      typeof updater === 'function' ? updater(showDoneTasks) : updater;
    const next = { ...userSettings, tasksShowDone: nextVal };
    setUserSettings(next);
    saveLocalSettings(next);
  }

  /**
   * Whether a note is currently gated behind the PIN. True iff the user
   * marked it PIN-protected, AND either it was protected since the last
   * unlock, or `shouldPromptForPin` says we're outside the unlock window.
   *
   * React re-renders on every `setPinUnlockVersion` bump (the poll
   * interval + unlock handler both call it), which is how the UI
   * stays in sync with the sessionStorage unlock timestamp - the
   * state value itself is never read, only its "something changed"
   * signal.
   */
  function isNoteLocked(n: LocalNote): boolean {
    if (n.pinProtected !== 1) return false;
    if (justProtectedIds.has(n.id)) return true;
    // No PIN set yet? Still gate the note. The bootstrap branch of
    // ProtectedNoteGate walks the user through setting one.
    if (!hasPin()) return true;
    return shouldPromptForPin(userSettings.pinTimeoutMinutes);
  }
  // Poll sessionStorage so an expired timeout re-locks an already-open
  // note without requiring interaction. 30s granularity is fine - a
  // 5-minute timeout with up to 30s of drift is well within UX norms.
  useEffect(() => {
    if (userSettings.pinTimeoutMinutes === -1) return;
    const t = setInterval(() => {
      setPinUnlockVersion((v) => v + 1);
    }, 30_000);
    return () => clearInterval(t);
  }, [userSettings.pinTimeoutMinutes]);

  // ── UI layout collapse state (persisted per-device) ──────────────
  // All UI chrome collapse state is per-device, not synced: someone on
  // a 13" laptop wants a narrower shell than on a 27" desktop. Stored
  // as flat localStorage keys so there's no migration drift.
  const readUiBool = (key: string, fallback: boolean): boolean => {
    if (typeof window === 'undefined') return fallback;
    const v = window.localStorage.getItem(key);
    if (v === '1' || v === 'true') return true;
    if (v === '0' || v === 'false') return false;
    return fallback;
  };
  const writeUiBool = (key: string, value: boolean) => {
    try {
      window.localStorage.setItem(key, value ? '1' : '0');
    } catch { /* quota / disabled - fall back to in-memory */ }
  };
  const readUiPx = (key: string, fallback: number, min: number, max: number): number => {
    if (typeof window === 'undefined') return fallback;
    const v = parseInt(window.localStorage.getItem(key) ?? '', 10);
    if (Number.isNaN(v)) return fallback;
    return Math.max(min, Math.min(max, v));
  };
  const writeUiPx = (key: string, value: number) => {
    try {
      window.localStorage.setItem(key, String(Math.round(value)));
    } catch { /* quota / disabled - fall back to in-memory */ }
  };
  // Sidebar rests expanded at xl+ (1280) and as the icon rail in the
  // lg-xl band, where the full 240px rail crowds the list + editor.
  // Manual expand (rail buttons, handles, context menu) stays available
  // below xl as a session override; crossing the xl line resets the
  // sidebar to its width default, so the choice is deliberately NOT
  // persisted anymore.
  // Spec: ops/docs/ui-patterns.md section 40 (canonical breakpoints)
  const [xlScreen, setXlScreen] = useState<boolean>(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 1280px)').matches,
  );
  const [sidebarCollapsed, setSidebarCollapsed] = useState<boolean>(() => !xlScreen);
  // The list collapse is a MULTI-PANE affordance: both of its strips are
  // md+ only, and below that line the list is the whole screen. Honouring
  // the stored flag there unmounts the only pane, leaves no handle to
  // bring it back, and persists - a blank app that a restart cannot cure.
  // A phone reaches the strips at all because landscape is wider than md,
  // so dropping out of the md band forgets the collapse, the same session
  // reseed the sidebar does at the xl line above. The mount read is gated
  // too, so a device that is already stuck heals on its next launch
  // instead of painting one blank frame first.
  // Spec: ops/docs/ui-patterns.md section 56 (pane resize strips)
  const [mdScreen, setMdScreen] = useState<boolean>(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 768px)').matches,
  );
  const [notesListCollapsed, setNotesListCollapsed] = useState<boolean>(
    () => mdScreen && readUiBool('privacynotes.ui.notesListCollapsed', false)
  );
  const [viewsCollapsed, setViewsCollapsed] = useState<boolean>(
    () => readUiBool('privacynotes.ui.viewsCollapsed', false)
  );
  // Pane widths (GitHub #211) are per-device like the collapse state above.
  // Width and collapse are independent axes: resizing never writes a
  // collapse boolean, collapsing never rewrites a width, and the stored
  // width simply applies whenever the pane is expanded (so it survives
  // the sidebar's session-only xl reseed below).
  // Spec: ops/docs/design-decisions.md (pane resize)
  const [sidebarWidth, setSidebarWidth] = useState<number>(
    () => readUiPx('privacynotes.ui.sidebarWidth', SIDEBAR_WIDTH_DEFAULT, SIDEBAR_WIDTH_MIN, SIDEBAR_WIDTH_MAX)
  );
  const [notesListWidth, setNotesListWidth] = useState<number>(
    () => readUiPx('privacynotes.ui.notesListWidth', LIST_WIDTH_DEFAULT, LIST_WIDTH_MIN, LIST_WIDTH_MAX)
  );
  // Docked-grid editor column width (>=1400px grid mode with a note open).
  const [editorDockWidth, setEditorDockWidth] = useState<number>(
    () => readUiPx('privacynotes.ui.editorDockWidth', EDITOR_DOCK_DEFAULT, EDITOR_DOCK_MIN, EDITOR_DOCK_STORE_MAX)
  );
  // Zen mode is intentionally NOT persisted: it's a "get out of my way
  // right now" gesture, not a layout preference. Reloads exit it so the
  // user isn't stuck wondering where the UI went.
  const [zenMode, setZenMode] = useState(false);
  // Demo conversion banner, dismissable for the session. Owned here rather
  // than in App because it is the first child of this component's h-dvh flex
  // column, so the shell below has to reflow when it closes.
  // Spec: ops/docs/ui-patterns.md section 39 (persistent chrome sits in the flow, never floating)
  const [demoBannerDismissed, setDemoBannerDismissed] = useState(false);
  const showDemoBanner = isDemoMode() && !demoBannerDismissed;
  // Formatting toolbar visibility while in Zen. Separate from the persisted
  // `toolbarVisible` so entering Zen starts with a clean surface and the
  // in-Zen markdown toggle flips it without touching the normal pref.
  const [zenToolbar, setZenToolbar] = useState(false);
  // The public demo unlocks every client-side Pro gate so visitors can
  // try the whole app before signing up; the Pro rocket badges stay as
  // teasers because they key off isPro. See proUnlocked() in demo.ts.
  const zenUnlocked = proUnlocked(auth.isPro);
  const foldersUnlocked = proUnlocked(auth.isPro);
  // Tease zen mode behind the upgrade modal: when the modal opens with
  // trigger='zen', temporarily activate zen so the user sees the clean
  // writing surface through the semi-transparent backdrop.
  useEffect(() => {
    if (showUpgrade?.trigger === 'zen' && !auth.isPro) setZenMode(true);
  }, [showUpgrade, auth.isPro]);
  // Listen for the "still not Pro after 18s of polling" signal from
  // auth.tsx::refreshProStatus. See gap #23.
  useEffect(() => {
    const onPending = () => setProActivationPending(true);
    window.addEventListener('privacynotes:pro-activation-pending', onPending);
    return () => {
      window.removeEventListener('privacynotes:pro-activation-pending', onPending);
    };
  }, []);
  // The update toasts (rendered at App level) ask us to open the changelog
  // tab via this event, since the About modal state lives here in NotesView.
  useEffect(() => {
    const onOpenChangelog = () => setShowAbout({ tab: 'changelog' });
    window.addEventListener('privacynotes:open-changelog', onOpenChangelog);
    return () => {
      window.removeEventListener('privacynotes:open-changelog', onOpenChangelog);
    };
  }, []);
  // If Pro flips to true after the banner showed (e.g. webhook lands
  // late), clear the banner automatically.
  useEffect(() => {
    if (auth.status === 'authenticated' && auth.isPro && proActivationPending) {
      setProActivationPending(false);
    }
  }, [auth, proActivationPending]);
  // Auto-clear snapshotForbidden when Pro is restored. See gap #41.
  useEffect(() => {
    if (auth.status === 'authenticated' && auth.isPro) {
      setSnapshotForbidden(false);
      setSnapshotBannerDismissed(false);
    }
  }, [auth]);

  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(min-width: 1280px)');
    const on = () => setXlScreen(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(min-width: 768px)');
    const on = () => setMdScreen(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);
  useEffect(() => { setSidebarCollapsed(!xlScreen); }, [xlScreen]);
  useEffect(() => { if (!mdScreen) setNotesListCollapsed(false); }, [mdScreen]);
  useEffect(() => { writeUiBool('privacynotes.ui.notesListCollapsed', notesListCollapsed); }, [notesListCollapsed]);
  useEffect(() => { writeUiBool('privacynotes.ui.viewsCollapsed', viewsCollapsed); }, [viewsCollapsed]);
  useEffect(() => { writeUiPx('privacynotes.ui.sidebarWidth', sidebarWidth); }, [sidebarWidth]);
  useEffect(() => { writeUiPx('privacynotes.ui.notesListWidth', notesListWidth); }, [notesListWidth]);
  useEffect(() => { writeUiPx('privacynotes.ui.editorDockWidth', editorDockWidth); }, [editorDockWidth]);

  // Drag-to-resize wiring for the four collapse strips. The refs are
  // shared: the root div carries the CSS vars, the badge is the floating
  // live-width readout. See usePaneResize.ts for the full contract.
  const shellRootRef = useRef<HTMLDivElement | null>(null);
  const dragBadgeRef = useRef<HTMLDivElement | null>(null);
  const sidebarResize = usePaneResize({
    rootRef: shellRootRef,
    badgeRef: dragBadgeRef,
    cssVar: '--pn-sidebar-w',
    min: SIDEBAR_WIDTH_MIN,
    getMax: () => Math.round(Math.min(SIDEBAR_WIDTH_MAX, SIDEBAR_VIEWPORT_CAP * window.innerWidth)),
    width: sidebarWidth,
    onCommitWidth: setSidebarWidth,
    onCollapse: () => setSidebarCollapsed(true),
  });
  const listResize = usePaneResize({
    rootRef: shellRootRef,
    badgeRef: dragBadgeRef,
    cssVar: '--pn-list-w',
    min: LIST_WIDTH_MIN,
    getMax: () => Math.round(Math.min(LIST_WIDTH_MAX, LIST_VIEWPORT_CAP * window.innerWidth)),
    width: notesListWidth,
    onCommitWidth: setNotesListWidth,
    onCollapse: () => setNotesListCollapsed(true),
  });
  // Docked-grid divider (between grid and editor): drag sizes the editor
  // column (invert - the pane sits RIGHT of its strip), click collapses
  // the grid so the editor takes the full width. The cap mirrors
  // --pn-editor-render-dock: viewport minus strips, the grid floor
  // formula, and the sidebar's actual rendered width.
  const editorResize = usePaneResize({
    rootRef: shellRootRef,
    badgeRef: dragBadgeRef,
    cssVar: '--pn-editor-w',
    min: EDITOR_DOCK_MIN,
    getMax: () => {
      const vw = window.innerWidth;
      const gridFloor = Math.min(GRID_DOCK_MIN, vw - DOCK_GRID_RESERVE);
      const sb = sidebarCollapsed
        ? 52
        : Math.max(SIDEBAR_WIDTH_MIN, Math.min(sidebarWidth, Math.min(SIDEBAR_WIDTH_MAX, vw - DOCK_SIDEBAR_RESERVE)));
      return Math.max(EDITOR_DOCK_MIN, Math.round(vw - STRIPS_W - gridFloor - sb));
    },
    invert: true,
    width: editorDockWidth,
    onCommitWidth: setEditorDockWidth,
    onCollapse: () => setNotesListCollapsed(true),
  });

  // Inline "+ Create Tag" flow: the button swaps to an input field in
  // place, user types a tag name, Enter creates a new pre-tagged note
  // so the tag materializes in the sidebar immediately. Escape cancels.
  // No new storage concept - tags are still just strings on notes.
  const [creatingTag, setCreatingTag] = useState(false);
  const [newTagDraft, setNewTagDraft] = useState('');

  const { toggle: toggleTheme, colorTheme, setColorTheme, spellcheck, invisibles, setInvisibles } = useTheme();
  const ctxMenu = useContextMenu();
  // List rows (notes, tasks, files) answer right-click with the row menu.
  // On touch the same event is a long-press, which is how multi-select
  // starts - swallow it so neither this menu nor the WebView's own text
  // selection fires while the row is being selected. Spec: issue #208.
  const openRowMenu = (e: React.MouseEvent, items: ContextMenuItem[]) => {
    if (isTouchContextMenu(e)) {
      e.preventDefault();
      return;
    }
    ctxMenu.open(e, items);
  };
  const saveTimer = useRef<number | null>(null);
  const lastSyncAt = useRef<number>(0);
  // Stable ref for flushEditingBody - breaks the circular dependency
  // between runSync (defined early, calls flush) and useNoteEditing
  // (defined later, returns flush but takes runSync as input).
  const flushEditingBodyRef = useRef<() => void>(() => {});
  // Refs for tab order: title input → tags input → editor body.
  const titleInputRef = useRef<HTMLTextAreaElement | null>(null);
  const tagInputRef = useRef<TagInputHandle | null>(null);
  const editorRef = useRef<EditorHandle | null>(null);
  // Jump-to-file: set when a file row is clicked in the Files pillar; once
  // the target note's editor is mounted, scroll to the attachment/image and
  // flash it (GitHub #167). State (not a ref) so the effect below re-runs
  // when a new target is set while the same note is already open.
  const [pendingFileScroll, setPendingFileScroll] = useState<{ noteId: string; uuid: string } | null>(null);
  useEffect(() => {
    if (!pendingFileScroll) return;
    // User moved on to a different note - drop the stale target.
    if (selectedId !== pendingFileScroll.noteId) {
      setPendingFileScroll(null);
      return;
    }
    // Editor not mounted yet (PIN gate showing, or mid note-switch). Keep
    // the target; pinUnlockVersion bumps re-run this effect after unlock.
    const handle = editorRef.current;
    if (!handle) return;
    handle.scrollToFile(pendingFileScroll.uuid);
    setPendingFileScroll(null);
  }, [pendingFileScroll, selectedId, pinUnlockVersion]);
  const [editorFocused, setEditorFocused] = useState(false);
  // Ref mirror for the sync orchestrator's idle check (#142): runSync fires
  // from a poller whose closure would hold stale state, so it reads focus
  // through this ref instead.
  const editorFocusedRef = useRef(false);
  useEffect(() => { editorFocusedRef.current = editorFocused; }, [editorFocused]);
  const [titleFocused, setTitleFocused] = useState(false);
  // True when the editor header is too narrow to fit the pin/share/trash
  // shortcut icons without crowding the title; they collapse into the "..."
  // menu so the title keeps priority. Measured on the header row (below).
  // How much of the quick-action pill the header row can carry: nothing, the
  // three note-behavior icons, or all seven. The pill is a shortcut into the
  // "..." menu, which keeps every one of these rows at every width.
  const [quickActionsTier, setQuickActionsTier] = useState<QuickActionsTier>(0);

  // Pin the tag row (which hosts undo/redo + the Hide/Show toggle) to the top
  // and push the editor's own sticky toolbar down by the tag row's height so
  // the two control bars stack instead of overlapping. Measured live via a
  // callback ref + ResizeObserver because tags wrap to a variable height; the
  // result is written to a --pn-tagrow-h CSS var on the content column, which
  // the toolbar reads for its sticky `top`.
  const tagRowObserverRef = useRef<ResizeObserver | null>(null);
  const tagRowColRef = useRef<HTMLElement | null>(null);
  /**
   * Whether the open note runs past its own scroller. The editor's find pill
   * floats over the note text, so it draws itself only when the note is long
   * enough to have somewhere to scroll to; on a note that fits, the corner is
   * empty. Nothing else keys off this.
   *
   * The gap is a hysteresis band, not a rounding guard. A note sitting on the
   * boundary grows and shrinks by a line as the caret wraps, and a bare
   * `scrollHeight > clientHeight` test makes the pill blink on and off while
   * somebody types. One comfortable line of slack costs nothing: a note that
   * only just overflows has nothing worth finding in it either.
   * Spec: ops/docs/ui-patterns.md (section 80)
   */
  const [bodyOverflows, setBodyOverflows] = useState(false);
  const scrollerObserverRef = useRef<ResizeObserver | null>(null);
  const scrollerNodeRef = useRef<HTMLDivElement | null>(null);
  /**
   * Read the open note's height against its scroller, and make sure we are
   * watching whatever is currently inside it.
   *
   * The column is re-resolved on every pass rather than captured once. The
   * scroller survives a note switch, so the callback ref fires only on the
   * first note; a column captured then can be replaced underneath us, and a
   * ResizeObserver holding the old one reports a note that never changes
   * size. `observe` on an element already watched is a no-op, so re-asking
   * costs nothing and self-heals after a swap.
   */
  const measureBodyOverflow = useCallback(() => {
    const node = scrollerNodeRef.current;
    const ro = scrollerObserverRef.current;
    if (!node || !ro) return;
    const col = node.querySelector('[data-content-col]');
    if (col) ro.observe(col);
    setBodyOverflows(node.scrollHeight - node.clientHeight > NOTE_OVERFLOW_SLACK_PX);
  }, []);
  const setNoteScroller = useCallback((node: HTMLDivElement | null) => {
    scrollerObserverRef.current?.disconnect();
    scrollerObserverRef.current = null;
    scrollerNodeRef.current = node;
    if (!node) { setBodyOverflows(false); return; }
    // The scroller's own box stops changing once the pane is sized, so the
    // column inside it is what reports a note crossing the line as it is
    // written. Both are watched: the scroller for a pane resize, the column
    // for the text.
    const ro = new ResizeObserver(() => measureBodyOverflow());
    ro.observe(node);
    scrollerObserverRef.current = ro;
    measureBodyOverflow();
  }, [measureBodyOverflow]);
  const setStickyTagRow = useCallback((node: HTMLDivElement | null) => {
    tagRowObserverRef.current?.disconnect();
    if (!node) {
      tagRowColRef.current?.style.removeProperty('--pn-tagrow-h');
      tagRowColRef.current = null;
      return;
    }
    const col = node.closest('[data-content-col]') as HTMLElement | null;
    tagRowColRef.current = col;
    const apply = () => col?.style.setProperty('--pn-tagrow-h', `${node.offsetHeight}px`);
    apply();
    const ro = new ResizeObserver(apply);
    ro.observe(node);
    tagRowObserverRef.current = ro;
  }, []);
  // Formatting-toolbar visibility lives here (not in Editor) so the Hide/Show
  // toggle can render inline on the tag row instead of overlapping the note.
  const [toolbarVisible, setToolbarVisible] = useState<boolean>(() => readToolbarPref());
  const toggleToolbar = useCallback(() => {
    setToolbarVisible((v) => {
      const next = !v;
      writeToolbarPref(next);
      return next;
    });
  }, []);
  // Zen force-hides the formatting toolbar for a clean writing surface; to use
  // markdown formatting the user exits zen. No in-zen toggle by design.
  /** True when the body editor is focused on mobile - collapses tracker pills. */
  const mobileEditing = isMobile && editorFocused;
  /** True when any on-screen keyboard is up on mobile - hides footer/header. */
  const mobileKeyboard = isMobile && keyboardOpen;
  // When handleNew creates a note, we want the title field to receive
  // focus on the very next render so the user can start typing
  // immediately. We can't call `.focus()` synchronously because the
  // input only mounts after React re-renders with the new selectedId.
  const pendingTitleFocus = useRef(false);
  // Toggle the editor into task-list mode on next render (used when
  // creating a new note from the Tasks view so it starts with a checkbox).
  const pendingTaskList = useRef(false);
  // Focus the Tasks quick-add input next render (used when "New Task" is
  // picked from the right-click menu - we swap the view and want the
  // cursor to land in the input so the user can just start typing).
  const pendingTaskInputFocus = useRef(false);
  const taskInputRef = useRef<HTMLInputElement | null>(null);

  const imageStoreRef = useRef<ImageStore | null>(null);
  const attachmentStoreRef = useRef<AttachmentStore | null>(null);

  const {
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
  } = useSyncOrchestrator({
    auth,
    supabase,
    forceSignOut,
    setUserSettings,
    setNotes,
    flushEditingBodyRef,
    imageStoreRef,
    attachmentStoreRef,
    selectedId,
    editingBodyRef: { get current() { return editingBodyRef.current; } },
    setEditorRevision: (value) => setEditorRevision(value),
    editorFocusedRef,
  });

  // The announcement banner stays hidden for the whole session that
  // created the vault: the fresh-vault notice marks that session, and a
  // banner over the first-run seed is noise the new user did not ask for.
  // Spec: ops/docs/backlog.md (#175, "never during onboarding or the first-run seed")
  const freshVaultSessionRef = useRef(false);
  if (freshVaultNotice) freshVaultSessionRef.current = true;

  useEffect(() => {
    (async () => {
      try {
        await refresh();
        setLoadError(false);
      } catch (err) {
        // listNotes already tried a reopen+retry; if it still failed the
        // local DB is unreachable. Show the fallback instead of a blank
        // screen, then still attempt sync. (#112)
        console.error('[load] initial notes read failed:', err);
        setLoadError(true);
      }
      await runSync().catch((err) =>
        console.error('[load] initial sync failed:', err)
      );
    })();
  }, [refresh, runSync]);

  // iOS standalone web apps can have their IndexedDB connection severed
  // while backgrounded; on resume the content area would otherwise stay
  // blank (a soft reload reuses the dead connection - only a full app
  // kill recovers). Re-read on foreground so the list repopulates;
  // listNotes reopens the DB on failure. (#112)
  useEffect(() => {
    const revalidate = (e: Event) => {
      if (document.hidden) return;
      // pageshow also fires on every NORMAL page load, right after the
      // mount effect above already ran the initial refresh - that made
      // every boot pay a redundant full listNotes + index rebuild (#140).
      // The iOS dead-DB resume this effect exists for (#112) arrives as a
      // bfcache restore (persisted: true) or as visibilitychange.
      if (e.type === 'pageshow' && !(e as PageTransitionEvent).persisted) return;
      refresh()
        .then(() => setLoadError(false))
        .catch((err) => {
          console.error('[resume] notes re-read failed:', err);
          setLoadError(true);
        });
    };
    document.addEventListener('visibilitychange', revalidate);
    window.addEventListener('pageshow', revalidate);
    return () => {
      document.removeEventListener('visibilitychange', revalidate);
      window.removeEventListener('pageshow', revalidate);
    };
  }, [refresh]);

  // Manual recovery for the fallback UI: force a fresh connection, then
  // reload notes and kick a sync. (#112)
  const handleDbReload = useCallback(async () => {
    try {
      await reopenDb();
      await refresh();
      setLoadError(false);
      void runSync();
    } catch (err) {
      console.error('[reload] manual DB recovery failed:', err);
      setLoadError(true);
    }
  }, [refresh, runSync]);

  // Initialize the image store + upload context for the encrypted image
  // editor extension. Runs once on mount (auth is stable for the session).
  useEffect(() => {
    const store = new ImageStore(supabase, auth.encryptionKey, auth.pubkey);
    store.onBackgroundError = (error) => {
      setImportToast(t('toast.imageUploadFailed', { error }));
      window.setTimeout(() => setImportToast(null), 8000);
    };
    imageStoreRef.current = store;
    setImageStore(store);
    // Retry any blobs that were cached locally but never made it to the server.
    store.processPendingUploads().catch((err) =>
      console.warn('[imageStore] processPendingUploads failed:', err),
    );

    // Images carry no per-file tier limit (only the shared storage
    // quota), so this context has no Pro flag - unlike the attachment
    // one below, whose isPro picks the 5/50/100 MB per-file cap.
    setImageUploadContext({
      imageStore: store,
      onQuotaExceeded: () => {
        setQuotaExceeded(true);
        setShowSyncOptions(true);
      },
      getQuota: () => quotaRef.current,
      onError: (msg) => {
        setImportToast(t('toast.imageError', { error: msg }));
        window.setTimeout(() => setImportToast(null), 6000);
      },
    });

    // Attachment store - same pattern, same bucket, same quota.
    const attachStore = new AttachmentStore(supabase, auth.encryptionKey, auth.pubkey);
    attachStore.onBackgroundError = (filename, error) => {
      setImportToast(t('toast.uploadFailedFor', { filename, error }));
      window.setTimeout(() => setImportToast(null), 8000);
    };
    attachmentStoreRef.current = attachStore;
    setAttachmentStore(attachStore);
    attachStore.processPendingUploads().catch((err) =>
      console.warn('[attachmentStore] processPendingUploads failed:', err),
    );
    setAttachmentUploadContext({
      // Drives the per-file size cap only (5 MB free / 50 MB Pro), so the
      // demo gets the Pro cap like every other client-side gate.
      isPro: proUnlocked(auth.isPro),
      attachmentStore: attachStore,
      onQuotaExceeded: () => {
        setQuotaExceeded(true);
        setShowSyncOptions(true);
      },
      getQuota: () => quotaRef.current,
    });

    return () => {
      setImageStore(null);
      setImageUploadContext(null);
      imageStoreRef.current = null;
      attachmentStoreRef.current = null;
      setAttachmentStore(null);
      setAttachmentUploadContext(null);
    };
  }, [supabase, auth.encryptionKey, auth.pubkey, auth.isPro]);

  // Periodic revocation check - catches idle devices that aren't syncing.
  // Runs every 30s on a timer + on visibilitychange (tab/app foregrounded).
  // The timer uses the default throttled heartbeat; visibilitychange forces
  // an immediate server check so revoked devices sign out the instant the
  // user switches to the tab - no 60s throttle delay. Fix: GitHub #32.
  // Ticks are skipped while hidden, same as the sync poll above: the Android
  // app left foreground with the screen off keeps webview timers running, and
  // an unguarded tick fired a device_heartbeat RPC (radio wakeup) every minute
  // all night (GitHub #189). Revocation is still caught the moment the app is
  // foregrounded again via the forced visibilitychange check below.
  useEffect(() => {
    const check = async (force = false) => {
      if (!navigator.onLine) return;
      const ok = await heartbeat(supabase, auth.deviceId, force);
      if (!ok) await forceSignOut('device revoked');
    };
    const interval = setInterval(() => {
      if (!document.hidden) void check();
    }, 30_000);
    const onVisibility = () => {
      if (!document.hidden) void check(true);
    };
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      clearInterval(interval);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, [supabase, auth.deviceId, forceSignOut]);

  // Mutate + persist user settings locally. The next regular runSync
  // pass picks up the dirty flag and pushes to the server - no need
  // for a separate debounced push, which was the source of the toggle
  // flicker bug (GitHub #71).
  const mutateSettings = useCallback(
    (updater: (prev: UserSettings) => UserSettings) => {
      settingsGenRef.current += 1;
      setUserSettings((prev) => {
        const next = updater(prev);
        queueMicrotask(() => saveLocalSettings(next));
        return next;
      });
    },
    []
  );

  // Folder sort control - SYNCED, unlike the tag sort above it. 'entries' =
  // direct note count, 'custom' = the order the user dragged the folders
  // into (FolderDef.order, which syncs too, so the choice has to follow it
  // or a second device shows an alphabetical list instead of the
  // arrangement its owner built).
  const folderSortField = userSettings.folderSort.field;
  const folderSortDir = userSettings.folderSort.dir;
  const setFolderSortField = useCallback(
    (field: FolderSortField) =>
      mutateSettings((prev) => ({ ...prev, folderSort: { ...prev.folderSort, field } })),
    [mutateSettings],
  );
  const setFolderSortDir = useCallback(
    (update: (prev: FolderSortDir) => FolderSortDir) =>
      mutateSettings((prev) => ({
        ...prev,
        folderSort: { ...prev.folderSort, dir: update(prev.folderSort.dir) },
      })),
    [mutateSettings],
  );

  // One-shot migration off the per-device keys this setting used to live in,
  // so a user who had already chosen "Entries" on this device keeps it
  // instead of being reset to Name the day the choice started syncing. The
  // keys are removed after, so a later device change cannot re-apply an old
  // local value over a newer synced one.
  useEffect(() => {
    const field = window.localStorage.getItem('privacynotes.folderSort.field');
    const dir = window.localStorage.getItem('privacynotes.folderSort.dir');
    if (!field && !dir) return;
    window.localStorage.removeItem('privacynotes.folderSort.field');
    window.localStorage.removeItem('privacynotes.folderSort.dir');
    mutateSettings((prev) => ({
      ...prev,
      folderSort: {
        field: field === 'entries' || field === 'custom' || field === 'name' ? field : prev.folderSort.field,
        dir: dir === 'desc' || dir === 'asc' ? dir : prev.folderSort.dir,
      },
    }));
  }, [mutateSettings]);

  const {
    exportSingleMarkdown,
    exportSingleHtml,
    exportAllMarkdownZip,
    exportAllHtmlZip,
    exportAllJson,
    exportEncryptedBackup,
    exportEncryptedFullBackup,
    decryptFullBackup,
    exportVault,
    exportBookmarks,
    printNote,
    importEncryptedBackup,
  } = useExports({
    supabase,
    auth,
    userSettings,
    mutateSettings,
    imageStoreRef,
    attachmentStoreRef,
    setExportProgress,
  });

  // After handleNew mounts the new note, the title input appears on the
  // next render - we then focus it so the user can start typing the
  // title immediately. Consumes the pending flag so regular
  // selection changes don't steal focus from the editor.
  // Mirror of pendingTitleFocus for the Tasks quick-add input. Fires
  // after the view swap to 'tasks' renders so the input is already in
  // the DOM by the time we call .focus().
  useEffect(() => {
    if (!pendingTaskInputFocus.current) return;
    if (view !== 'tasks') return;
    pendingTaskInputFocus.current = false;
    requestAnimationFrame(() => {
      taskInputRef.current?.focus();
    });
  }, [view]);

  useEffect(() => {
    if (!pendingTitleFocus.current) return;
    if (!selectedId) return;
    pendingTitleFocus.current = false;
    // rAF guarantees the input has been committed to the DOM.
    requestAnimationFrame(() => {
      titleInputRef.current?.focus();
      // If created from Tasks view, toggle the editor into task-list
      // mode so the first line is an empty checkbox - this makes the
      // note immediately visible in the Tasks view.
      if (pendingTaskList.current) {
        pendingTaskList.current = false;
        // Double-rAF: the editor mounts after the title input, so we
        // need one more frame for TipTap to initialize.
        requestAnimationFrame(() => {
          editorRef.current?.toggleTaskList();
        });
      }
    });
  }, [selectedId]);

  // Hand the open note to the app lock, which unmounts this whole view when it
  // re-locks and gives the note back on the way in.
  useEffect(() => {
    rememberOpenNote(selectedId);
  }, [selectedId]);

  // Commit-on-blur: when the user navigates away from a note (selects
  // another, creates a new one, switches view, trashes, logs out - all
  // of which change or clear selectedId), persist the derived title if
  // the user never set one. This closes the gap where the list card
  // showed a derived title but the editor's title field stayed empty.
  //
  // Only fires when the stored title is empty. An explicit title, even
  // the literal word "Untitled", is respected. If the user later clears
  // the title and navigates away, derivation kicks back in - that's the
  // symmetric behavior we want.
  //
  // We read fresh from Dexie rather than closing over `notes` so the
  // check reflects the current state, not whatever was in memory when
  // selectedId was last set. Cleanup fires before the next effect runs,
  // so the captured id is the outgoing note, not the incoming one.
  useEffect(() => {
    const id = selectedId;
    return () => {
      if (!id) return;
      void (async () => {
        const n = await getNote(id);
        if (!n) return;
        if ((n.title ?? '').trim()) return;
        const derived = deriveDisplayTitle(n);
        if (!derived || derived === 'Untitled') return;
        // Use existing updatedAt - committing a derived title shouldn't
        // re-sort the note to the top of the list.
        const ts = n.updatedAt ?? new Date().toISOString();
        patchLocal(id, { title: derived }, ts);
        await updateNote(id, { title: derived }, ts);
        scheduleSync();
      })();
    };
  }, [selectedId]);

  // Quota for the storage bars (Files view + Trash view).
  const [viewQuota, setViewQuota] = useState<QuotaUsage | null>(null);
  /** Recompute blob bytes from Storage ground truth, then re-read the
   *  counters into the bar. The recalc is what makes a drifted image_bytes
   *  self-heal on view; it excludes blobs still sitting in the deferred-GC
   *  queue (migration 0066), so a delete the user just made shows as freed
   *  rather than being re-added by the ground-truth recount. Best-effort -
   *  recalculateQuota handles its own errors. Declared up here because every
   *  destructive path below chains off it. */
  const refreshStorage = useCallback(() => {
    return recalculateQuota(supabase)
      .then(() => fetchQuotaUsage(supabase, auth.isPro ?? false))
      .then((q) => {
        // One source of truth: the upload gates read quotaRef, the pane
        // hints read viewQuota - feed both from the same server read so
        // they can never disagree (backlog #131).
        quotaRef.current = { usedBytes: q.totalBytes + q.imageBytes, maxBytes: q.maxTotalBytes };
        setViewQuota(q);
      });
  }, [supabase, auth.isPro]);

  // Only non-trashed notes count toward sidebar tag totals + All count.
  const activeNotes = useMemo(
    () => notes.filter((n) => n.trashed === 0),
    [notes]
  );
  const trashedNotes = useMemo(
    () => notes.filter((n) => n.trashed === 1),
    [notes]
  );

  /* Every bookmark URL the account holds, built ONCE here and handed to both
     surfaces that can write one - the quick-add bar and the editor's URL
     field. Neither may derive its own: a guard built from a rendered list
     misses the copy the current filter hides. */
  const bookmarkKeys = useMemo(() => buildLinkKeyMap(activeNotes), [activeNotes]);

  // Auto-purge trashed notes older than N days (client-side, runs once
  // on mount after notes are loaded). Server can't do this - trashed
  // status is inside the encrypted payload.
  // updatedAt is the age signal here, which relies on every writer of
  // trashed=1 stamping it at trash time (trashNote, trashNotesWithTag,
  // applyImport). Anything that sets trashed=1 while keeping an older
  // updatedAt is permanently deleted on the next mount, with no undo.
  const autoDeleteRanRef = useRef(false);
  useEffect(() => {
    if (autoDeleteRanRef.current) return;
    if (trashedNotes.length === 0) return;
    const days = userSettings.autoDeleteTrashDays;
    if (days <= 0) return;
    autoDeleteRanRef.current = true;
    const cutoff = Date.now() - days * 86_400_000;
    const expired = trashedNotes.filter(
      (n) => new Date(n.updatedAt).getTime() < cutoff
    );
    if (expired.length === 0) return;
    (async () => {
      if (imageStoreRef.current) {
        void gcOnNotesDelete(
          imageStoreRef.current,
          expired.map((n) => ({ id: n.id, body: n.body })),
          attachmentStoreRef.current,
        );
      }
      for (const n of expired) {
        await permanentlyDelete(n.id);
      }
      await refresh();
      // Sync deletes to server, then refresh quota so the storage bar updates.
      runSync().then(refreshStorage);
    })();
  }, [trashedNotes, userSettings.autoDeleteTrashDays, refresh, runSync, refreshStorage]);

  /**
   * The rating ask.
   *
   * Runs ONCE per app open, never on reaching the threshold itself: an
   * ask that interrupts the sentence someone is typing is the version of
   * this feature everyone hates. Crossing 25 notes at 11pm means the
   * modal greets them at their next app open instead, which is also the
   * one moment in a session when nothing has failed yet (suppression
   * rule 6 - never ask right after the app let someone down).
   *
   * The first-run firstSeenAt stamp is NOT minted here anymore: it moved
   * to useSyncOrchestrator, behind the first successful settings pull.
   * Stamping at mount marked the settings blob dirty BEFORE that pull,
   * which made a fresh device push its default blob over the account's
   * real settings (the folder-wipe bug). The once-per-open ref still
   * latches BEFORE the null-stamp check, on purpose: a session that
   * boots without a stamp never asks, even after the pull brings an old
   * account's real one - so an existing user signing in on a fresh
   * device (the domain move) is not greeted by the rating modal minutes
   * into their first session there. That is exactly the timing the
   * stamp-first version of this effect enforced.
   *
   * `notesCreated` is read from storage rather than React state because
   * createNote bumps it outside React entirely.
   *
   * Every other reason not to ask lives in ratingPrompt.ts.
   * Spec: ops/docs/plans/rating-prompt-handoff.md (every met milestone is spent on one ask, never back to back)
   */
  const ratingCheckedRef = useRef(false);
  useEffect(() => {
    if (ratingCheckedRef.current) return;
    if (auth.status !== 'authenticated') return;
    ratingCheckedRef.current = true;
    if (!userSettings.firstSeenAt) return;
    const timer = window.setTimeout(() => {
      const fresh = loadLocalSettings();
      const earned = pendingRatingMilestones(fresh, auth.isPro);
      if (earned.length === 0) return;
      // Spend every earned key, not just the one that opened the modal:
      // otherwise crossing both thresholds asks twice in a row.
      mutateSettings((prev) => ({
        ...prev,
        milestonesSeen: [...new Set([...prev.milestonesSeen, ...earned])],
      }));
      setShowRate(true);
    }, RATING_ASK_DELAY_MS);
    return () => window.clearTimeout(timer);
  }, [auth.status, auth.isPro, userSettings.firstSeenAt, mutateSettings]);

  const starredCount = useMemo(
    () => activeNotes.filter((n) => n.starred === 1).length,
    [activeNotes]
  );

  // Plain-notes count for sidebar badge (type === 'note' only).
  const plainNotesCount = useMemo(
    () => activeNotes.filter((n) => n.type === 'note').length,
    [activeNotes]
  );

  // Tasks view - derived from the same `activeNotes` list. Every
  // `- [ ] …` / `- [x] …` line across non-trashed notes is a task. No
  // new storage, no new entity: the body of each note IS the task list.
  // Re-runs whenever any note body changes, which is fine - parsing a
  // few thousand lines of markdown is instant.
  const allTasks = useMemo(() => extractAllTasks(activeNotes), [activeNotes]);
  const openTaskCount = useMemo(
    () => allTasks.reduce((n, t) => n + (t.checked ? 0 : 1), 0),
    [allTasks]
  );
  // Quick-add buffer: controlled input at the top of the Tasks view.
  // Enter appends a new `- [ ] …` line to the Reminders note (auto-created
  // on first use). Empty input is a no-op.
  const [taskDraft, setTaskDraft] = useState('');
  // Bumped after each quick-add so the editor remounts and picks up
  // the appended task line (same note ID → key must change).
  const [editorRevision, setEditorRevision] = useState(0);

  // Per-note editor mode override, session-scoped and never synced. The
  // "Show markdown" link flips only the selected note; userSettings.editorMode
  // stays the default every note opens in. Cleared on reload by design.
  // Spec: ops/specs/editor-mode-toggle.md (persisting this override is deferred, would need a new note field)
  const [editorModeOverrides, setEditorModeOverrides] = useState<Record<string, 'formatted' | 'markdown'>>({});

  const {
    toggleFavoriteTag,
    openTagMenu,
    setOpenTagMenu,
    openTagActionMenu,
    renamingTag,
    setRenamingTag,
    renameBuffer,
    setRenameBuffer,
    commitRenameTag,
    handleDeleteTag,
    handleDeleteTagAndNotes,
    handleCreateTag,
    tagConfirm,
    setTagConfirm,
  } = useTagActions({
    activeNotes,
    selectedId,
    setSelectedId,
    selectedTag,
    setSelectedTag,
    setSelectedFolder,
    setView,
    setDrawerOpen,
    setCreatingTag,
    setNewTagDraft,
    pendingTitleFocus,
    discardIfEmpty,
    mutateSettings,
    refresh,
    runSync,
  });

  // Journal count - derived before tagCounts so the sidebar badge stays live.
  const journalCount = useMemo(
    () => activeNotes.filter((n) => n.type === 'journal').length,
    [activeNotes]
  );

  // Vault count - structured types only (logins, cards, ssh keys).
  const vaultCount = useMemo(
    () => activeNotes.filter((n) => n.type === 'login' || n.type === 'card' || n.type === 'ssh-key').length,
    [activeNotes]
  );

  /** Every live bookmark, unscoped - the pillar count and the duplicate
   *  guard's reference set (folder/tag scope must not hide a duplicate). */
  const allLinkNotes = useMemo(
    () => activeNotes.filter((n) => n.type === 'link'),
    [activeNotes]
  );
  const bookmarksCount = allLinkNotes.length;

  // Files view - extract all image + attachment references from note bodies.
  const rawFileItems = useMemo(
    () => extractFileItems(activeNotes),
    [activeNotes]
  );

  // Enrich image items with sizes - local cache first, then Supabase Storage.
  const [fileItems, setFileItems] = useState(rawFileItems);
  /** Blob uuids a full listing did not find, held for this session only. */
  const absentBlobs = useRef<Set<string>>(new Set());
  useEffect(() => {
    const zeroSize = rawFileItems.filter((f) => f.kind === 'image' && f.size === 0);
    if (zeroSize.length === 0) { setFileItems(rawFileItems); return; }
    const uuids = zeroSize.map((f) => f.uuid);
    let cancelled = false;
    void (async () => {
      const sizeMap = new Map<string, number>();
      // 1. Local imageDedup cache (fast, no network). It is keyed by the
      //    content hash, so only the device that uploaded the image has a row.
      const local = await db.imageDedup.where('uuid').anyOf(uuids).toArray();
      for (const r of local) if (r.encryptedSize) sizeMap.set(r.uuid, r.encryptedSize);
      // 2. Sizes an earlier listing already resolved. This is the cache every
      //    other device reads: a new phone or a fresh browser holds no hash.
      const remembered = await readImageSizes();
      for (const u of uuids) {
        if (sizeMap.has(u)) continue;
        const sz = remembered[u];
        if (sz) sizeMap.set(u, sz);
      }
      // 3. Storage listing for whatever is still unknown. It pages, and the
      //    Files view is the only surface that renders a byte size, so no
      //    other view pays for the scan.
      //    Skipped in demo mode, which makes zero server calls - nothing was
      //    ever uploaded, so there is nothing for the server to know about.
      const missing = uuids.filter(
        (u) => !sizeMap.has(u) && !absentBlobs.current.has(u),
      );
      if (missing.length > 0 && view === 'files' && !isDemoMode()) {
        try {
          const { sizes, absent } = await listImageSizes(supabase, auth.pubkey, missing);
          for (const [uuid, sz] of sizes) sizeMap.set(uuid, sz);
          // A uuid a full listing walked past is not in the bucket, which is
          // what a note referencing a removed blob leaves behind. Holding it
          // for the session is what stops paging from re-running on every
          // render; a reload asks again, so a blob that a second device
          // uploads later is still picked up.
          for (const uuid of absent) absentBlobs.current.add(uuid);
          if (cancelled) return;
          // imageDedup keeps carrying the size where a row exists, which
          // leaves the quota accounting reading one number.
          for (const uuid of missing) {
            const sz = sizeMap.get(uuid);
            if (!sz) continue;
            const rec = await db.imageDedup.where('uuid').equals(uuid).first();
            if (rec) await db.imageDedup.put({ ...rec, encryptedSize: sz });
          }
        } catch { /* offline - sizes will fill in next time */ }
      }
      if (cancelled) return;
      setFileItems(sizeMap.size > 0
        ? rawFileItems.map((f) => { const sz = sizeMap.get(f.uuid); return sz ? { ...f, size: sz } : f; })
        : rawFileItems);
    })();
    return () => { cancelled = true; };
  }, [rawFileItems, supabase, auth.pubkey, view]);

  useEffect(() => {
    if (view !== 'files' && view !== 'trash') return;
    refreshStorage();
  }, [view, refreshStorage]);

  const tagCounts = useMemo(() => {
    const counts = new Map<string, number>();
    // Track the most recent updatedAt for any note that carries a
    // given tag so we can sort by "Modified". Uses numeric ms
    // timestamps because local notes use "...Z" format while
    // server-synced notes may use "...+00:00" - string comparison
    // across those formats gives wrong results.
    const lastModified = new Map<string, number>();
    let untagged = 0;
    for (const n of activeNotes) {
      if (n.tags.length === 0) untagged++;
      for (const t of n.tags) {
        counts.set(t, (counts.get(t) ?? 0) + 1);
        const modTs = Date.parse(n.updatedAt) || 0;
        const prevMod = lastModified.get(t) ?? 0;
        if (modTs > prevMod) lastModified.set(t, modTs);
      }
    }
    const entries = [...counts.entries()];
    entries.sort((a, b) => {
      let cmp = 0;
      if (tagSortField === 'name') {
        cmp = a[0].localeCompare(b[0]);
      } else if (tagSortField === 'modified') {
        const av = lastModified.get(a[0]) ?? 0;
        const bv = lastModified.get(b[0]) ?? 0;
        cmp = av - bv;
        if (cmp === 0) cmp = a[0].localeCompare(b[0]);
      } else {
        // entries - sort by note count, tie-break on name.
        cmp = a[1] - b[1];
        if (cmp === 0) cmp = a[0].localeCompare(b[0]);
      }
      return tagSortDir === 'asc' ? cmp : -cmp;
    });
    return { tags: entries, untagged };
  }, [activeNotes, tagSortField, tagSortDir]);

  // Unfiled count - the folder sibling of tagCounts.untagged. Drives the
  // muted "Unfiled" row under the folder tree (GitHub #235).
  const unfiledCount = useMemo(
    () => activeNotes.filter((n) => !n.folderId).length,
    [activeNotes]
  );

  // Split the sorted tag list into Favorites + Regular, based on the
  // synced user settings. Favorites appear in a dedicated group above
  // the Tags header. A favorite tag that no longer exists in the user's
  // vault (e.g. the user deleted all notes with it) is quietly dropped
  // from the Favorites list but kept in userSettings so that if the
  // tag gets recreated later the favorite flag comes back automatically.
  const favoriteTagsList = useMemo(() => {
    const tagCountMap = new Map(tagCounts.tags);
    return userSettings.favoriteTags
      .filter((t) => tagCountMap.has(t))
      .map((t) => [t, tagCountMap.get(t) ?? 0] as [string, number]);
  }, [tagCounts.tags, userSettings.favoriteTags]);
  const nonFavoriteTagsList = useMemo(() => {
    const favSet = new Set(userSettings.favoriteTags);
    return tagCounts.tags.filter(([t]) => !favSet.has(t));
  }, [tagCounts.tags, userSettings.favoriteTags]);

  // If the user is filtering by "Untagged" and that bucket drops to 0
  // (either because they tagged the last one, or restored the last one
  // from trash), the sidebar button disappears - so bounce the selection
  // back to "All notes" instead of leaving them staring at an empty
  // list that's filtered by a view that no longer exists in the UI.
  useEffect(() => {
    if (selectedTag === '__untagged__' && tagCounts.untagged === 0) {
      setSelectedTag(null);
    }
  }, [selectedTag, tagCounts.untagged]);

  // Same bounce for folders: if the active folder disappears (deleted
  // on another device, arriving via settings sync), fall back to All
  // items instead of a stranded empty filter. The Unfiled sentinel is
  // not a real folder, so it is exempt here and gets its own zero-count
  // bounce below (mirroring Untagged).
  useEffect(() => {
    if (selectedFolder && selectedFolder !== UNFILED_ID && !userSettings.folders.some((f) => f.id === selectedFolder)) {
      setSelectedFolder(null);
    }
  }, [selectedFolder, userSettings.folders]);
  useEffect(() => {
    if (selectedFolder === UNFILED_ID && unfiledCount === 0) {
      setSelectedFolder(null);
    }
  }, [selectedFolder, unfiledCount]);

  // Note types the user switched off in the All options menu (the funnel in
  // the sidebar's All row). Empty for everyone who never opened that menu, so
  // the filter below costs one `.size` check in the common case.
  // Spec: ops/docs/plans/sidebar-views.md (All row funnel: which note types the All list holds)
  const hiddenTypesInAll = useMemo(
    () => new Set(userSettings.hiddenInAll.flatMap((v) => VIEW_NOTE_TYPES[v] ?? [])),
    [userSettings.hiddenInAll],
  );

  /**
   * The tag + folder scope as one predicate.
   *
   * Shared by the notes list and by the id set that scopes the Tasks and
   * Files feeds, so the two can never disagree about what a filter means.
   * Folders match direct members only - no recursive rollup.
   */
  const inScope = useCallback((n: LocalNote) => {
    if (selectedTag === '__untagged__') {
      if (n.tags.length > 0) return false;
    } else if (selectedTag && !n.tags.includes(selectedTag)) {
      return false;
    }
    if (selectedFolder === UNFILED_ID) return !n.folderId;
    if (selectedFolder) return n.folderId === selectedFolder;
    return true;
  }, [selectedTag, selectedFolder]);

  const displayNotes = useMemo(() => {
    // Tasks view is not a notes list - the middle column renders its
    // own UI. Return an empty list so the auto-select effect below
    // clears any stale selection.
    if (view === 'tasks') return [];
    if (view === 'files') return [];
    // The Markdown pillar reads from the user's disk, never from the encrypted
    // store. Falling through would compute the whole Notes list for a pane that
    // cannot display it, and worse, would put encrypted notes one wiring
    // mistake away from a plaintext surface.
    if (view === 'markdown') return [];
    let list: LocalNote[];
    if (view === 'trash') {
      list = trashedNotes;
    } else if (view === 'home') {
      // All Items - every active type except the ones switched off in the All
      // options menu. Deliberately only this branch: a single-type pillar must
      // never filter itself (the Vault list would hide the vault), Trash is
      // exempt like the two filters further down so nothing is marooned there,
      // and Pinned answers to the pin, not to this. The tag and folder views
      // come along for free - a tag click sets view to 'home'.
      list = hiddenTypesInAll.size
        ? activeNotes.filter((n) => !hiddenTypesInAll.has(n.type))
        : activeNotes;
    } else if (view === 'starred') {
      list = activeNotes.filter((n) => n.starred === 1);
    } else if (view === 'journal') {
      list = activeNotes.filter((n) => n.type === 'journal');
    } else if (view === 'vault') {
      list = activeNotes.filter((n) =>
        (n.type === 'login' || n.type === 'card' || n.type === 'ssh-key') && (vaultFilter === 'all' || n.type === vaultFilter)
      );
    } else if (view === 'bookmarks') {
      list = activeNotes.filter((n) => n.type === 'link');
    } else {
      // Notes pillar - only plain notes (excludes journals, files, vault types).
      list = activeNotes.filter((n) => n.type === 'note');
    }
    // Tag + folder scope. Both apply in every view, and to each other.
    if (selectedTag || selectedFolder) list = list.filter(inScope);
    // Hide locked / protected notes per the user's "Other" toggles.
    // Trash bypasses both filters so nothing gets marooned there.
    if (view !== 'trash') {
      if (!listPrefs.showLocked) list = list.filter((n) => n.locked !== 1);
      if (!listPrefs.showProtected) list = list.filter((n) => n.pinProtected !== 1);
    }
    if (deferredSearch.trim()) {
      // When the user is actively searching, prioritise relevance:
      // MiniSearch returns hits best-match-first, so we replay that
      // ordering on the filtered set and skip the user's sort pref
      // entirely. The pref re-applies as soon as the search box is
      // cleared.
      const hitIds = searchNotes(deferredSearch);
      const byId = new Map(list.map((n) => [n.id, n] as const));
      const ordered: LocalNote[] = [];
      for (const id of hitIds) {
        const hit = byId.get(id);
        if (hit) ordered.push(hit);
      }
      return ordered;
    }
    // No search active - apply the user's sort pref. Copy the array
    // because the upstream lists are memoised; mutating would cause
    // stale equality checks elsewhere.
    const sorted = list.slice();
    sorted.sort((a, b) => compareNotes(a, b, listPrefs));
    return sorted;
  // searchIndexVersion: searchNotes reads a module-level index that
  // updates AFTER the render a state change triggers - the version bump
  // is what re-runs this memo against the fresh index.
  }, [activeNotes, trashedNotes, deferredSearch, inScope, selectedTag, selectedFolder, view, listPrefs, vaultFilter, hiddenTypesInAll, searchIndexVersion]);

  // Tag + folder + view compose: when either filter is active, the Tasks and
  // Files pillars (which render from their own data feeds, not displayNotes)
  // get scoped copies. Sidebar counts intentionally stay global.
  const scopeNoteIds = useMemo(
    () => (selectedTag || selectedFolder
      ? new Set(activeNotes.filter(inScope).map((n) => n.id))
      : null),
    [activeNotes, inScope, selectedTag, selectedFolder]
  );
  const scopedAllTasks = useMemo(
    () => (scopeNoteIds ? allTasks.filter((t) => scopeNoteIds.has(t.noteId)) : allTasks),
    [allTasks, scopeNoteIds]
  );
  const scopedActiveNotes = useMemo(
    () => (scopeNoteIds ? activeNotes.filter((n) => scopeNoteIds.has(n.id)) : activeNotes),
    [activeNotes, scopeNoteIds]
  );
  const scopedFileItems = useMemo(
    () => (scopeNoteIds ? fileItems.filter((f) => scopeNoteIds.has(f.noteId)) : fileItems),
    [fileItems, scopeNoteIds]
  );

  // The Tasks pillar's note list, derived from the exact inputs TasksList
  // renders from. It feeds displayNotesRef, so anything this list and the
  // rendered one disagree on - a filter, the folder scope, the order -
  // lets multi-select address rows the user cannot see.
  const taskContainingNotes = useMemo(
    () => selectTaskNotes(scopedActiveNotes, scopedAllTasks, deferredSearch, listPrefs),
    [scopedActiveNotes, scopedAllTasks, deferredSearch, listPrefs]
  );

  // Mirror displayNotes into a ref so the multi-select callbacks
  // (declared above) can read the current filtered list without
  // capturing it in their useCallback deps.
  useEffect(() => {
    displayNotesRef.current =
      view === 'tasks' ? taskContainingNotes : displayNotes;
  }, [displayNotes, view, taskContainingNotes]);

  // Global view mode. 'auto' resolves to grid on wide screens (>=1400px)
  // and list otherwise, so a wide window fills the space with tiles instead
  // of a narrow list beside an empty editor. An explicit List/Grid choice
  // from any toggle pins it. Spec: ops/specs/grid-view.md (default viewMode is 'list', not 'auto', despite this resolver).
  const [wideScreen, setWideScreen] = useState<boolean>(
    () => typeof window !== 'undefined' && window.matchMedia('(min-width: 1400px)').matches,
  );
  useEffect(() => {
    if (typeof window === 'undefined') return;
    const mq = window.matchMedia('(min-width: 1400px)');
    const on = () => setWideScreen(mq.matches);
    mq.addEventListener('change', on);
    return () => mq.removeEventListener('change', on);
  }, []);
  const effectiveViewMode: 'list' | 'grid' =
    userSettings.viewMode === 'list' || userSettings.viewMode === 'grid'
      ? userSettings.viewMode
      : wideScreen
        ? 'grid'
        : 'list';

  // Grid layout applies to the standard notes lists only. Tasks and Files
  // render their own specialized components, so they stay list-shaped.
  const gridMode = effectiveViewMode === 'grid';


  // Auto-select the first visible note whenever the filtered list changes,
  // so the editor pane is never empty while notes exist. Fires on tag
  // click, view switch, search, rename, trash, restore - anything that
  // re-derives `displayNotes`. Exceptions:
  //   - Empty list (trash folder empty, brand-new user, no search matches):
  //     clear selection so the empty-state message shows.
  //   - Mobile (<md): don't auto-open a note because the list and editor
  //     are mutually exclusive on small screens; tapping a tag should show
  //     the list, not punch straight through into an editor. We still
  //     clear a stale selection if the selected note left the list.
  useEffect(() => {
    // Tasks view owns its own selection rules: clicking a task opens
    // the source note in the editor while keeping the tasks UI in the
    // middle column. displayNotes is empty for Tasks by design, so
    // this effect would clobber that selection if it ran.
    if (view === 'tasks' || view === 'files') return;
    const isDesktop =
      typeof window !== 'undefined' &&
      window.matchMedia('(min-width: 768px)').matches;
    const selectionInList =
      selectedId != null && displayNotes.some((n) => n.id === selectedId);
    // A note-link jump outranks this effect until the list catches up with
    // it. Any other selection retires the jump, and so does the target
    // arriving in the list. See `linkTargetRef`.
    if (linkTargetRef.current !== null) {
      if (selectedId === linkTargetRef.current && !selectionInList) return;
      linkTargetRef.current = null;
    }
    if (!isDesktop) {
      if (selectedId && !selectionInList) setSelectedId(null);
      return;
    }
    // Grid mode: the grid is the primary surface, so never auto-open a note.
    // Only clear a selection that has left the list (e.g. after delete).
    if (gridMode) {
      if (selectedId && !selectionInList) setSelectedId(null);
      return;
    }
    if (displayNotes.length === 0) {
      if (selectedId) setSelectedId(null);
      return;
    }
    if (!selectionInList) {
      const first = displayNotes[0];
      if (first) setSelectedId(first.id);
    }
  }, [displayNotes, selectedId, view, gridMode]);

  // Pop the Security → Phrase tab once for new OAuth users so they
  // see their recovery phrase and can write it down. The flag is set
  // by hydrateFromOAuthSession in auth.tsx on first OAuth signup.
  // We previously suppressed this reveal as "too confusing," but that
  // reasoning assumed the server could re-derive the phrase if the
  // user lost their device. Post oauth-zk-fix the phrase is the only
  // way back - surfacing it once on signup is the right trade.
  // See ops/docs/oauth-zk-fix.md.
  useEffect(() => {
    let flag: string | null = null;
    try {
      flag = window.localStorage.getItem('privacynotes.oauth.showPhraseOnce');
    } catch {
      /* ignore */
    }
    if (flag === '1') {
      try {
        window.localStorage.removeItem('privacynotes.oauth.showPhraseOnce');
      } catch {
        /* ignore */
      }
      setShowSecurity({ tab: 'phrase' });
    }
  }, []);

  const selected = notes.find((n) => n.id === selectedId) ?? null;

  // A note the user is working in must not lock under them, so while a
  // protected note is the open one, input carries the unlock window forward.
  // The watch ends when that note stops being the open one, which is when the
  // window starts running out again (issue #254).
  const selectedIsProtected = selected?.pinProtected === 1;
  useEffect(() => {
    if (!selectedIsProtected) return;
    return startPinKeepAlive(userSettings.pinTimeoutMinutes);
  }, [selectedIsProtected, selectedId, userSettings.pinTimeoutMinutes]);

  /**
   * Previous and next note IN THE LIST, for the editor header's two
   * chevrons and their shortcuts (GitHub #246).
   *
   * "The list" is whatever the list pane is showing, filters and sort
   * included, which is also what the grid renders - both read
   * `displayNotes`, so the arrows follow either without knowing which is
   * on screen. The tasks pillar is the one view with a list of its own.
   *
   * A bookmark row is skipped rather than landed on: selecting one opens
   * its URL instead of the editor (see handleSelectNote), and an arrow
   * that opens a browser tab is not a navigation control. Nothing to step
   * to leaves the arrow disabled, so it never promises a move it will not
   * make - which is why one helper answers both questions.
   */
  const neighbourNoteId = useCallback((step: -1 | 1) => {
    // The same list the effect above mirrors into displayNotesRef, read
    // directly because that ref is created further down, by useMultiSelect.
    const list = view === 'tasks' ? taskContainingNotes : displayNotes;
    const from = selectedId ? list.findIndex((n) => n.id === selectedId) : -1;
    if (from < 0) return null;
    for (let i = from + step; i >= 0 && i < list.length; i += step) {
      const n = list[i];
      if (!n) continue;
      if (n.type === 'link' && n.trashed !== 1) continue;
      return n.id;
    }
    return null;
  }, [view, taskContainingNotes, displayNotes, selectedId]);
  const navigateList = useCallback((direction: 'prev' | 'next') => {
    const id = neighbourNoteId(direction === 'prev' ? -1 : 1);
    if (id) void handleSelectNote(id);
  }, [neighbourNoteId]);

  /**
   * Whether the wide pane currently holds something.
   *
   * The two-pane layout below is written around `selected`, which is a NOTE.
   * The Markdown pillar never selects a note - what it opens lives in
   * `markdownFile` - so `selected` is null there even with a file open, and the
   * layout drew the wrong conclusion twice: below `md` the list kept the full
   * width and the file pane stayed hidden, so opening a file looked like
   * nothing happened; in grid mode the file pane was hidden at EVERY width.
   */
  const [bookmarkFocusSignal, setBookmarkFocusSignal] = useState(0);
  const paneOccupied = selected != null || (view === 'markdown' && markdownFile != null);

  /**
   * The Markdown pillar before anything is open: no folder, no single file.
   *
   * There is no list in that state, only the entry card, and the 320px list
   * column is the wrong place for it - the pitch, its four chips and the two
   * pickers each wrapped onto three lines while the whole wide pane sat empty
   * next to it saying "Open a Markdown file to read it here". So the list
   * column and its resize strips are not rendered at all here and
   * `markdownPane` moves into the wide pane, keeping its own h-14 title row,
   * which is what carries the pillar switcher and the mobile drawer button.
   * The moment a folder or a file opens this goes false and the column snaps
   * back into place.
   */
  const markdownEntry = view === 'markdown' && markdownDir == null && markdownFile == null;


  /** True when either app footer is on screen. Both footers gate on this, and
   *  so does the editor column's bottom padding: with a footer below, the
   *  column only needs the small gap that seats the word-count row on the
   *  footer's divider; without one the column IS the bottom of the screen and
   *  has to clear the home indicator itself. */
  const footerVisible = !mobileKeyboard && !(zenMode && selected);

  // The selected note's editor mode: its session override if the user hit
  // "Show markdown" on this note, otherwise the synced default.
  // Spec: ops/specs/editor-mode-toggle.md (precedence: per-note override beats the synced global default)
  const selectedEditorMode: 'formatted' | 'markdown' =
    (selected ? editorModeOverrides[selected.id] : undefined) ?? userSettings.editorMode;

  /**
   * Re-measure the open note whenever the note under the scroller changes.
   * The ResizeObserver covers a note GROWING as it is typed. It cannot cover
   * a SWAP: the scroller keeps its own box while its contents are replaced,
   * and the column is exchanged rather than resized, so the observer is left
   * holding a detached element that will never report again.
   *
   * A LAYOUT effect, not a plain one, and this is the whole reason. The first
   * build read the DOM inside `requestAnimationFrame` and measured the note
   * that was on its way out: the callback beat React's commit, re-observed
   * the OLD column, and the pill then stayed on a short note forever, because
   * nothing was watching the new one either. A layout effect runs after the
   * commit, so the column it finds is the one on screen. The frame after is a
   * second pass for whatever settles later, an image being the usual one.
   */
  useLayoutEffect(() => {
    measureBodyOverflow();
    const a = requestAnimationFrame(measureBodyOverflow);
    return () => cancelAnimationFrame(a);
  }, [selectedId, selectedEditorMode, editorRevision, measureBodyOverflow]);

  // Which of the editor header's icon groups fit, measured on the header
  // row itself rather than the viewport: the sidebar and the notes list are
  // drag-resizable, so a narrow editor pane under a wide window has to
  // collapse them too. That is the macOS case where the two left columns
  // squeeze the editor while the window stays wide.
  //
  // A CALLBACK ref, not an effect over a ref object. The header row is a
  // different DOM node after a remount, and an observer opened in an effect
  // keyed on `selectedId` went on watching the OLD node: the row visibly
  // changed width and no group ever appeared or left until the next reload.
  // A callback ref is handed the node every time it changes, which is the
  // only signal that cannot go stale. Same pattern as setStickyTagRow above.
  const headerObserverRef = useRef<ResizeObserver | null>(null);
  const measureHeaderRef = useRef<() => void>(() => {});
  const setHeaderRow = useCallback((node: HTMLDivElement | null) => {
    headerObserverRef.current?.disconnect();
    headerObserverRef.current = null;
    if (!node) return;
    const measure = () => {
      const w = node.clientWidth;
      setQuickActionsTier(w >= QUICK_ACTIONS_ALL_PX ? 2 : w >= QUICK_ACTIONS_CORE_PX ? 1 : 0);
    };
    measureHeaderRef.current = measure;
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(node);
    headerObserverRef.current = ro;
  }, []);
  // The observer alone is not reliable on a window resize in WKWebView (the
  // macOS app), so the window event drives the same measurement.
  useEffect(() => {
    const onResize = () => requestAnimationFrame(() => measureHeaderRef.current());
    window.addEventListener('resize', onResize);
    return () => window.removeEventListener('resize', onResize);
  }, []);

  // Lightweight stats used in the footer's clickable stats chip. We only
  // need the total note count and word count here; the full heatmap +
  // streaks still live inside StatsModal (opened by clicking the chip).
  // Derived from `displayNotes` so the chip matches the current view.
  // Tasks/files views return an empty displayNotes - fall back to all
  // active notes so the chip isn't blank.
  const footerStats = useMemo(() => {
    // The Markdown pillar counts FILES ON DISK, not notes. Its displayNotes is
    // empty by design (nothing encrypted belongs to it), so falling through
    // would have shown "0 Notes" over a folder of 85 files.
    //
    // Words are a true total, summed from full bodies the tag index already
    // read. It climbs as that background pass lands, which is honest: it is the
    // count of what has been read so far, never a truncated count presented as
    // a whole one.
    if (view === 'markdown') {
      const words = [...markdownTags.byPath.values()]
        .reduce((sum, m) => sum + m.words, 0);
      return {
        notes: markdownDir?.entries.length ?? 0,
        words,
        label: t('shell:markdown.footerFiles'),
      };
    }
    const pool = (view === 'tasks' || view === 'files') ? activeNotes : displayNotes;
    const s = computeStats(pool);
    const label =
      view === 'journal' ? t('footerStats.journals')
      : view === 'vault' ? t('footerStats.items')
      : view === 'bookmarks' ? t('footerStats.bookmarks')
      : view === 'trash' ? t('footerStats.trashed')
      : t('footerStats.notes');
    return { notes: s.totalNotes, words: s.totalWords, label };
    // t in the deps: its identity changes on language switch and on lazy
    // catalog load, or the label stays cached in the boot language forever.
  }, [view, activeNotes, displayNotes, markdownDir, markdownTags, t]);

  /**
   * "Empty" = no title, no body, no tags. Used to decide whether a
   * draft should be discarded when the user navigates away instead of
   * lingering as clutter in the list and on the server. A note with a
   * single space of body or a single tag is NOT empty - that's real
   * user intent and we respect it.
   *
   * Task and journal notes get system-generated titles on creation
   * ("Tasks for Friday, May 15, 2026" / "Friday, May 15, 2026"), so
   * for those types the title alone doesn't prove user intent. It
   * doesn't disprove it either: someone who renames a journal entry
   * and writes no body meant to keep it, and we used to hard-delete
   * that on the next tap (#122). What tells the two apart is whether
   * the note was ever written to - createNote sets createdAt equal to
   * updatedAt, and every edit (title included) bumps updatedAt - so
   * an untouched draft is the only thing we discard.
   *
   * Vault items (login/card/ssh-key) get template JSON bodies on
   * creation. The Save button blocks empty saves (v0.135.8), but
   * navigating away without saving bypasses that - the template body
   * looks non-empty to a plain trim check. We treat template-matching
   * bodies as empty so discardIfEmpty catches them.
   */
  function isNoteEmpty(note: LocalNote | undefined): boolean {
    if (!note) return false;
    const body = (note.body ?? '').trim();
    const hasTags = (note.tags ?? []).length > 0;
    const hasTitle = (note.title ?? '').trim() !== '';
    // Vault items: template JSON body = empty.
    const vaultTemplate = VAULT_EMPTY_BODIES[note.type];
    const hasBody = vaultTemplate ? body !== '' && body !== vaultTemplate : body !== '';
    // Task & journal titles are auto-generated - body is the real
    // signal, but only while the draft is still untouched (#122).
    if (note.type === 'task' || note.type === 'journal') {
      return !hasBody && !hasTags && note.createdAt === note.updatedAt;
    }
    if (hasTitle) return false;
    if (hasBody) return false;
    if (hasTags) return false;
    return true;
  }

  /**
   * Called from every code path that moves selection away from a note
   * that might be an empty draft. Trashes it (trashed=1 + dirty=1) so
   * the next sync push carries the flag to every device. Safe to call
   * with any id - non-empty notes are left alone.
   *
   * Why trash instead of hard-delete: this is a GUESS about intent,
   * and it is the only thing in the app that disposes of a note nobody
   * asked it to. It used to hard-delete, on the reasoning that trash
   * "would just move clutter from the main list to the trash list -
   * they'd still have to empty it later". That stopped being true when
   * autoDeleteTrashDays shipped: it defaults to 30 and the purge effect
   * above sweeps expired notes on mount, so trash is self-cleaning and
   * costs the user nothing. A wrong guess is now a row in Trash for 30
   * days instead of a tombstone synced to every device, which is the
   * only failure direction a zero-knowledge app can afford. (#122)
   */
  async function discardIfEmpty(id: string | null): Promise<boolean> {
    if (!id) return false;
    const note = await getNote(id);
    // Never auto-delete a note the user already filed away. The desktop
    // auto-select effect makes displayNotes[0] the selection without a
    // click, Trash included, so browsing the trash could turn a
    // recoverable note into a synced tombstone. The deleted check also
    // makes a second discard pass on the same id a no-op instead of
    // re-stamping updatedAt (contextMenus fires two in one tick). (#122)
    if (note?.trashed === 1 || note?.deleted === 1) return false;
    if (!isNoteEmpty(note)) return false;
    // No blob GC here: the note still exists and can be restored, so its
    // images/attachments must stay. The trash purge above GCs them when
    // it permanently deletes the note 30 days from now.
    await trashNote(id);
    return true;
  }

  /**
   * Close the editor and drop the draft if it was never touched.
   *
   * The six navigate-away paths (new note, select note/tag/view/folder)
   * each call discardIfEmpty, but closing the editor in place did not:
   * Escape, the mobile back arrow, the grid close X, and the Android
   * back button all cleared selection directly, so an untouched draft
   * survived and piled up in the list. Every close path routes through
   * here now. (#182)
   */
  async function handleCloseEditor() {
    const previousId = selectedId;
    setSelectedId(null);
    const discarded = await discardIfEmpty(previousId);
    if (discarded) {
      await refresh();
      void runSync();
    }
  }

  // ── Wiki-link navigation ──────────────────────────────────────────
  // Find a note by title and select it. If no match exists, prompt
  // before creating - a stale link whose target was renamed should not
  // silently spawn a phantom note. Called from the WikiLink TipTap
  // extension when the user clicks a [[link]].
  const navigateToNoteByTitle = useCallback(
    async (target: string) => {
      const lower = target.toLowerCase();
      const match =
        activeNotes.find((n) => noteLinkName(n).toLowerCase() === lower) ??
        // Fallback for a target the [[...]] syntax could not hold verbatim.
        // A title with a pipe or a bracket in it ("Recipes | 2024") is written
        // into a link with those characters replaced, so it can never match
        // the title exactly. Comparing both sides through the same rule is
        // what makes those links - including ones already imported by older
        // versions - resolve. Spec: packages/web/src/noteLinks.ts
        (() => {
          const key = noteLinkKey(target);
          return key ? activeNotes.find((n) => noteLinkKey(noteLinkName(n)) === key) : undefined;
        })();
      if (match) {
        // A bookmark is a URL, not an editor document: selecting it would
        // land on an empty Notes pane, which is what #238 reported. Open
        // the URL instead - the same rule a bookmark row click follows.
        const bookmarkUrl =
          match.type === 'link' ? parseLinkBody(match.body).url : '';
        if (bookmarkUrl) {
          openExternal(bookmarkUrl);
          setDrawerOpen(false);
          return;
        }
        // Switch pillar so the auto-select effect doesn't snap back.
        const targetView: View =
          match.type === 'journal' ? 'journal' :
          match.type === 'task' ? 'tasks' :
          match.type === 'file' ? 'files' :
          match.type === 'login' || match.type === 'card' || match.type === 'ssh-key' ? 'vault' :
          // Only reached by a bookmark whose URL is missing or unparseable:
          // show it in its own pillar so the user can repair it.
          match.type === 'link' ? 'bookmarks' :
          'all';
        setView(targetView);
        // The pillar alone is not enough. A tag, a folder, a search and the
        // Vault type filter each scope the LIST, and the auto-select effect
        // above replaces any selection the list does not hold - so a link
        // into a note the active filter hides opened it and was bounced
        // straight back, either to the first note the filter did leave or to
        // nothing at all. The link looked dead. Clear whatever hides the
        // target; a filter the target passes is the user's context and stays.
        if (!inScope(match)) {
          setSelectedTag(null);
          setSelectedFolder(null);
        }
        // Search is left behind either way: the results list is the thing the
        // reader just navigated out of, and testing membership costs a second
        // index query to keep a box that is now stale.
        if (search) setSearch('');
        if (vaultFilter !== 'all' && vaultFilter !== match.type) setVaultFilter('all');
        linkTargetRef.current = match.id;
        setSelectedId(match.id);
        setDrawerOpen(false);
        return;
      }
      // No match - ask before creating so a dangling link doesn't make junk.
      setWikiLinkCreatePending(target);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [activeNotes, inScope, search, vaultFilter]
  );

  // Confirmed via the modal: create the note for a dangling wiki-link
  // and navigate to it.
  const createNoteFromWikiLink = useCallback(
    async (target: string) => {
      const note = await createNote(target);
      await refresh();
      setView('all');
      // Same trap as the jump above, one click later: a note born from a link
      // carries no tag and no folder, so an active filter hides it and the
      // auto-select effect bounced the editor back to whatever the filter did
      // leave. The note was created and then went missing. It does NOT
      // inherit the filter the way "+ New Note" does - the link named a
      // target, not a place to file it - so the filter is what gives way.
      if (!inScope(note)) {
        setSelectedTag(null);
        setSelectedFolder(null);
      }
      if (search) setSearch('');
      linkTargetRef.current = note.id;
      setSelectedId(note.id);
      setDrawerOpen(false);
    },
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [refresh, inScope, search]
  );

  // Wire the navigator + autocomplete titles into the editor whenever
  // it mounts (the editor is keyed by note id, so it remounts on switch).
  const noteTitles = useMemo(
    // `noteLinkName`, not `n.title`: an unnamed bookmark stores an empty title
    // and shows its domain, so reading the raw title left it out of the menu
    // while the app called it "github.com" everywhere else.
    () => activeNotes
      .map((n) => ({ id: n.id, title: noteLinkName(n) }))
      .filter((e) => e.title),
    [activeNotes]
  );

  useEffect(() => {
    const tiptap = editorRef.current?.getEditor?.();
    if (!tiptap) return;
    setWikiLinkNavigator(tiptap, navigateToNoteByTitle);
    setWikiLinkNoteTitles(tiptap, noteTitles);
  });

  async function handleNew(vaultType?: 'login' | 'card' | 'ssh-key', overrideView?: View, overrideFolderId?: string | null, overrideStarred?: boolean) {
    // overrideView: when the context menu "New X" fires from a different
    // pillar, the React closure's `view` is stale (re-render hasn't
    // happened yet). The caller passes the intended target so we create
    // the right type regardless. Fix: ops/docs/backlog.md #94.
    const effectiveView = overrideView ?? view;
    // Folders method A - create in context: a new note files into the
    // selected folder. The folder menu's "New note here" passes an
    // explicit override for the same stale-closure reason as overrideView.
    // The Unfiled sentinel is a filter, not a folder - a new note under it
    // stays unfiled (folderId null), which also keeps it visible there.
    const inheritFolderId = overrideFolderId ?? (selectedFolder === UNFILED_ID ? null : selectedFolder);

    // ── Bug fix #46a: reuse current empty note instead of creating duplicates ──
    // If the user is already looking at an empty untouched note (type='note'),
    // just keep them there. Prevents Alt+Shift+N spam from creating duplicates.
    // Only reuse when the new item would ALSO be a plain note. When the caller
    // asked for a different type (task, journal, or a vault item - e.g. from
    // the All-view "New" type picker or the global menu), fall through and
    // create that type instead; the empty draft is discarded below (#190).
    const reuseEmptyDraft =
      effectiveView !== 'vault' && effectiveView !== 'tasks' && effectiveView !== 'journal';
    if (selectedId && reuseEmptyDraft) {
      const current = await getNote(selectedId);
      if (current && isNoteEmpty(current) && current.type === 'note') {
        // File the reused draft where the user is now looking, so "New
        // note here" on a folder never leaves the draft unfiled.
        if ((current.folderId ?? null) !== inheritFolderId) {
          await updateNote(selectedId, { folderId: inheritFolderId });
          await refresh();
        }
        pendingTitleFocus.current = true;
        return;
      }
    }

    // ── Bug fix #46b: navigate to 'all' from non-note views ──
    // Files and Markdown both render something other than the notes list, so
    // the shortcut creates the note silently in the background and the user
    // sees nothing happen. Switch to 'all' so it is actually visible. Which
    // pillars need the bounce - and why journal, tasks, starred and vault do
    // not - is answered by NEW_NOTE_IS_VISIBLE at the top of this file.
    if (!NEW_NOTE_IS_VISIBLE[effectiveView]) {
      setView('all');
      setSelectedTag(null);
    }
    // Empty title on purpose - the placeholder below reads
    // "Untitled (click to edit or let it autogenerate)" and the list view
    // derives a title from the first body line if nothing is set.
    //
    // Discard any empty draft the user had open before creating a new
    // one, so rapidly clicking "+ New Note" multiple times doesn't
    // leave a trail of empties. No runSync() here: the new note
    // starts dirty but we don't push until there's content, so users
    // who bail never touch the network.
    //
    // Inherit the active filter so the new note actually shows up in
    // the list the user is currently looking at. Without this, hitting
    // "+ New Note" from the Starred view or a specific tag filter
    // creates a note that's invisible in the current view - it exists
    // in the DB, the editor opens, but the list looks unchanged and
    // the user thinks nothing happened. Rules:
    //   - Starred view   → starred=1
    //   - Tag filter X   → tags=[X] (X is the real tag name, not the
    //                       __untagged__ sentinel)
    //   - Untagged filter, All, everything else → plain empty note
    // Trash view has its "+ New Note" button hidden elsewhere, so we
    // don't need to special-case it.
    // overrideStarred lets a caller force the starred flag regardless of the
    // pillar being created into - the Pinned view's "New" picker sets it so a
    // new task/journal/login stays visible in that (starred-only) list (#190).
    const inheritStarred = overrideStarred ?? (effectiveView === 'starred');
    // Journal view: auto-title with today's date, auto-tag 'journal'.
    const isJournal = effectiveView === 'journal';
    // Tasks view: pre-fill with today's date title + one empty checkbox
    // so the note is immediately recognized as a task and stays visible
    // in the Tasks view. The auto-select effect already guards against
    // clobbering (returns early for tasks view), so we don't need to
    // bounce to 'all'.
    const isTasks = effectiveView === 'tasks';
    // Vault view: create structured items (login, card, ssh-key).
    const isVault = effectiveView === 'vault';
    const inheritTags = selectedTag && selectedTag !== '__untagged__'
      ? [selectedTag]
      : undefined;
    // Titles are written in the app's language, never a hardcoded en-US:
    // a German account creating today's entry gets a German date. The
    // journal shape is the user's setting (GitHub #200); tasks keep the
    // long date so the two pillars stay recognisably related.
    const today = new Date();
    const locale = activeLocale();
    const inheritTitle = isTasks
      ? t('tasks.newTitle', {
          date: journalTitle(today, 'long', '', locale),
        })
      : isJournal
        ? journalTitle(
            today,
            userSettings.journalTitleFormat,
            userSettings.journalTitleSuffix,
            locale,
          )
        : '';
    const effectiveVaultType = isVault ? (vaultType ?? 'login') : null;
    const inheritBody = effectiveVaultType ? (VAULT_EMPTY_BODIES[effectiveVaultType] ?? '') : '';
    // Vault filter mismatch: if the active filter doesn't include the
    // new item type, switch to "all" so the new item is visible.
    // e.g. creating a Credit Card while the "Logins" filter is active.
    if (isVault && effectiveVaultType && vaultFilter !== 'all' && vaultFilter !== effectiveVaultType) {
      setVaultFilter('all');
    }
    // Trash view: bounce to All so the new note is visible. Tasks view
    // stays put (type='task' keeps it in the task list).
    if (effectiveView === 'trash') {
      setView('all');
      setSelectedTag(null);
    }
    const previousId = selectedId;
    const note = await createNote(
      inheritTitle, inheritBody, inheritTags, inheritStarred,
      effectiveVaultType ?? (isJournal ? 'journal' : isTasks ? 'task' : 'note'),
      inheritFolderId,
    );
    // Stamp the calendar date on journal entries. This, not the title,
    // is what the Week in Review card matches on - titles are the user's
    // to rename and their shape is a setting. See notesViewUtils.ts.
    // Pass the birth timestamp so the stamp doesn't read as a user edit
    // and defeat the untouched-draft check in isNoteEmpty (#122).
    if (isJournal) {
      await updateNote(note.id, { trackers: { journalDate: toLocalIso(today) } }, note.updatedAt);
    }
    // PIN-protect is always off on creation. Users toggle per-item
    // in the form if they want it.
    const discarded = await discardIfEmpty(previousId);
    if (discarded) await refresh();
    else await refresh();
    pendingTitleFocus.current = true;
    if (isTasks) pendingTaskList.current = true;
    setSelectedId(note.id);
    setDrawerOpen(false);
  }

  /**
   * Imported or restored blobs sit in the local cache with pendingUpload=1
   * until a pass picks them up. Shared by the import modal and the Files
   * pillar's drag-and-drop, which both land blobs the same way. A function
   * DECLARATION on purpose: it is hoisted, so the useFilesUpload call below
   * can pass it before this line is reached.
   */
  function handleBlobsRestored() {
    imageStoreRef.current?.processPendingUploads().catch((err) =>
      console.warn('[imageStore] post-restore processPendingUploads failed:', err),
    );
    attachmentStoreRef.current?.processPendingUploads().catch((err) =>
      console.warn('[attachmentStore] post-restore processPendingUploads failed:', err),
    );
  }

  const {
    uploadEntries,
    setUploadEntries,
    pendingImportableFiles,
    setPendingImportableFiles,
    filesUploadRef,
    handleFilesUpload,
    handleFilesSelected,
    handleImportFromFiles,
    handleAttachFromFiles,
  } = useFilesUpload({
    auth,
    supabase,
    attachmentStoreRef,
    quotaRef,
    refresh,
    runSync,
    refreshStorage,
    setSelectedId,
    setView,
    setImportToast,
    // `mergeImportedFolders` is declared below (useFolderActions). The arrow
    // only RUNS on a drop, long after this render assigns it.
    onImportFolders: (folders) => mergeImportedFolders(folders),
    onBlobsRestored: handleBlobsRestored,
  });

  /**
   * Create a new journal entry for a recent date. Always creates - no
   * dedup, because two entries for one day is a choice the user is
   * allowed to make (a morning page and an evening page).
   */
  /**
   * Persist the weekly reflection onto this week's Monday journal entry,
   * creating that entry when the user has not journalled on a Monday.
   *
   * Two bugs met here. The write went straight to Dexie with no React
   * state update, and the textarea is CONTROLLED by a value derived from
   * `notes` - so its value prop never moved and every keystroke was
   * discarded, making the field impossible to type in. And when no Monday
   * entry existed the write was skipped entirely by an `if (entry)` with
   * no else, so the text went nowhere and said nothing about it.
   */
  async function saveWeekReflection(text: string) {
    const existing = notes.find(
      (n) => n.deleted === 0 && n.trashed === 0 && n.type === 'journal' && isWeekJournal(n)
    );
    if (existing) {
      const trackers = {
        ...((existing.trackers as Record<string, unknown> | undefined) ?? {}),
        weekReflection: text,
      };
      // handleTrackersChange, not updateNote: it patches React state and
      // schedules the sync, which is what makes the field typeable.
      await handleTrackersChange(existing.id, trackers as JournalTrackerData);
      return;
    }
    const monday = getMondayIso();
    const note = await createNote(
      journalTitle(
        new Date(monday + 'T12:00:00'),
        userSettings.journalTitleFormat,
        userSettings.journalTitleSuffix,
        activeLocale(),
      ),
      '',
      undefined,
      undefined,
      'journal',
    );
    await updateNote(note.id, { trackers: { journalDate: monday } }, note.updatedAt);
    await refresh();
    await handleTrackersChange(note.id, { journalDate: monday, weekReflection: text });
  }

  async function handleBackfillDate(isoDate: string) {
    // Noon avoids the DST edge where midnight local does not exist.
    const date = new Date(isoDate + 'T12:00:00');
    const title = journalTitle(
      date,
      userSettings.journalTitleFormat,
      userSettings.journalTitleSuffix,
      activeLocale(),
    );
    const note = await createNote(title, '', undefined, undefined, 'journal');
    const todayLocal = toLocalIso(new Date());
    // Birth timestamp again, same reason as handleNew: the stamp is ours,
    // not the user's, so it must not read as an edit. Leaving it to bump
    // would make the discard check a race between two new Date() calls
    // that can land in the same millisecond. (#122)
    await updateNote(note.id, {
      trackers: {
        ...(note.trackers as Record<string, unknown> | undefined),
        journalDate: isoDate,
        ...(isoDate < todayLocal ? { backfilled: true } : {}),
      },
    }, note.updatedAt);
    await refresh();
    setSelectedId(note.id);
    setDrawerOpen(false);
  }

  async function handleSelectNote(id: string) {
    // Search-to-file jump: when the active search matches an attachment
    // filename in the clicked note, scroll to that chip on open (GitHub
    // #167). Mirrors the Files-pillar jump for All Items / Notes results.
    // Runs before the same-note early return so re-clicking a result
    // re-jumps.
    const q = search.trim().toLowerCase();
    if (q) {
      const note = notes.find((n) => n.id === id);
      const hit = note
        ? extractFileItems([note]).find(
            (f) => f.kind === 'attachment' && f.name.toLowerCase().includes(q),
          )
        : undefined;
      if (hit) setPendingFileScroll({ noteId: id, uuid: hit.uuid });
    }
    // Bookmarks open their URL instead of becoming an editor selection -
    // everywhere except Trash, where selecting is how you inspect and
    // restore. Spec: ops/docs/plans/bookmarks-pillar.md (row click opens).
    const clicked = notes.find((n) => n.id === id);
    if (clicked?.type === 'link' && clicked.trashed !== 1) {
      openExternal(parseLinkBody(clicked.body).url);
      setDrawerOpen(false);
      return;
    }
    if (id === selectedId) {
      setDrawerOpen(false);
      return;
    }
    const previousId = selectedId;
    setSelectedId(id);
    setDrawerOpen(false);
    const discarded = await discardIfEmpty(previousId);
    if (discarded) {
      await refresh();
      void runSync();
    }
  }

  async function handleSelectTag(tag: string | null) {
    const previousId = selectedId;
    setSelectedTag(tag);
    // The current view and any active folder are kept: a tag, a folder and a
    // pillar compose into one combined filter ("tasks tagged #work inside
    // Stories"), and the list pane names every active one as a chip so none
    // of them can be forgotten. Two views cannot take a tag and so drop back
    // to All items, the landing handleSelectFolder uses: Trash, for the
    // reason handleSelectView spells out, and Markdown, which reads plain
    // files off the user's disk and has a tag filter of its own. Without the
    // bounce, a tag click from either is a click that does nothing.
    if (view === 'trash' || view === 'markdown') setView('home');
    setSelectedId(null);
    setDrawerOpen(false);
    const discarded = await discardIfEmpty(previousId);
    if (discarded) {
      await refresh();
      void runSync();
    }
  }

  async function handleSelectView(next: View) {
    const previousId = selectedId;
    setView(next);
    // Both filters intentionally survive view switches: a tag, a folder and
    // a view compose ("Tasks inside Stories tagged #work"). The sidebar
    // shows all of them as active and the list pane draws a chip per filter.
    // Trash is the one view that cannot compose with either: it lists
    // deleted notes while every tag and folder count speaks for active
    // ones, so the pair reads as two live filters and shows a folder badge
    // of 1 above an empty list. It is exclusive - handleSelectTag and
    // handleSelectFolder both drop out of trash on the way back.
    if (next === 'trash') {
      setSelectedFolder(null);
      setSelectedTag(null);
    }
    setSelectedId(null);
    setDrawerOpen(false);
    const discarded = await discardIfEmpty(previousId);
    if (discarded) {
      await refresh();
      void runSync();
    }
  }

  /**
   * Flip one view's membership in a hidden list, for BOTH surfaces that
   * offer it: the rail's own menus and the Sidebar table in Appearance.
   *
   * Switching off the view you are standing in also leaves it, for All.
   * A hidden row still draws while it IS the open view (see isViewShown),
   * so without this a deliberate hide answers with a box that ticks off
   * beside a row that stays put, and the control reads as broken - which
   * is how it was reported for Bookmarks. The exemption itself stays: it
   * exists for the views the app opens by itself (an upload opens Files,
   * a search hit opens its pillar), where the user chose no such thing.
   * Unhiding is left alone, so ticking the open view back on does not
   * throw the user out of it.
   * Spec: ops/docs/plans/sidebar-views.md (hiding the open view bounces to home, an app-opened view stays put)
   */
  function handleToggleHiddenView(field: 'hiddenViews' | 'hiddenInAll', key: View) {
    const hiding = field === 'hiddenViews' && !userSettings.hiddenViews.includes(key);
    mutateSettings((prev) => toggleHiddenView(prev, field, key));
    if (hiding && key === view) void handleSelectView('home');
  }

  /**
   * Pick the next note to select after `id` is removed from the visible
   * list. Prefers the note immediately after the deleted one, falls
   * back to the one before it, returns null if the list empties out.
   * Used by both trash + permanent delete so the editor never sits on
   * an empty pane after a delete.
   */
  function pickNextSelection(id: string): string | null {
    const idx = displayNotes.findIndex((n) => n.id === id);
    if (idx < 0) return null;
    const next = displayNotes[idx + 1];
    if (next) return next.id;
    const prev = displayNotes[idx - 1];
    if (prev) return prev.id;
    return null;
  }

  // ── PIN gate for destructive actions on protected notes ────────
  const [pendingProtectedAction, setPendingProtectedAction] = useState<(() => Promise<void>) | null>(null);

  /** Move to trash (from the 'all' or 'starred' view). */
  async function handleTrash(id: string) {
    const note = notes.find((n) => n.id === id);
    if (note?.pinProtected === 1 && isNoteLocked(note)) {
      setPendingProtectedAction(() => async () => {
        markUnlocked();
        const nextId = selectedId === id ? pickNextSelection(id) : selectedId;
        await trashNote(id);
        if (selectedId === id) setSelectedId(nextId);
        await refresh();
        void runSync();
      });
      return;
    }
    const nextId = selectedId === id ? pickNextSelection(id) : selectedId;
    await trashNote(id);
    if (selectedId === id) setSelectedId(nextId);
    await refresh();
    void runSync();
  }

  /** Restore a note from trash. */
  async function handleRestore(id: string) {
    await restoreNote(id);
    await refresh();
    void runSync();
  }

  /** Permanently delete a single note from the trash. Callers should
      gate this behind DeleteNoteModal - don't call directly from UI. */
  async function handlePermanentlyDelete(id: string) {
    const nextId = selectedId === id ? pickNextSelection(id) : selectedId;
    // GC image/attachment blobs before deleting the note.
    const note = notes.find((n) => n.id === id);
    if (note && imageStoreRef.current) {
      void gcOnNoteDelete(imageStoreRef.current, note.body, id, attachmentStoreRef.current);
    }
    await permanentlyDelete(id);
    if (selectedId === id) setSelectedId(nextId);
    await refresh();
    // Sync deletes to server, recalculate stale counters, then refresh quota.
    runSync().then(refreshStorage);
  }

  // ── Multi-select ─────────────────────────────────────────────────
  const {
    selectionMode,
    selectedIds,
    selectionAllStarred,
    displayNotesRef,
    clearSelection,
    deselectAll,
    toggleSelected,
    rangeSelect,
    selectAllVisible,
    handleRowClick,
    beginLongPress,
    cancelLongPress,
    bulkTrashPending,
    requestBulkTrash,
    executeBulkTrash,
    dismissBulkTrash,
    handleBulkRestore,
    bulkDeletePending,
    requestBulkDelete,
    executeBulkDelete,
    dismissBulkDelete,
    handleBulkFavorite,
    handleBulkExport,
    handleBulkAddTag,
  } = useMultiSelect({
    notes,
    selectedId,
    setSelectedId,
    view,
    selectedTag,
    imageStoreRef,
    attachmentStoreRef,
    refresh,
    runSync,
    refreshStorage,
    handleSelectNote,
    exportAllMarkdownZip,
    isNoteLocked,
    requestPinGate: (action) => setPendingProtectedAction(() => async () => {
      markUnlocked();
      await action();
    }),
  });

  const {
    mergeImportedFolders,
    folderPicker,
    setFolderPicker,
    folderDeleteConfirm,
    setFolderDeleteConfirm,
    handleSelectFolder,
    effectiveBrowseMode,
    handleBrowseChange,
    openFoldersUpsell,
    handleCreateFolder,
    handleRenameFolder,
    handleMoveFolder,
    handleReorderFolders,
    handleDeleteFolder,
    handleMoveNotesToFolder,
    folderCounts,
    folderChipFor,
    handleBulkMoveToFolder,
  } = useFolderActions({
    userSettings,
    mutateSettings,
    notes,
    activeNotes,
    selectedIds,
    refresh,
    runSync,
    foldersUnlocked,
    isPro: auth.isPro,
    setShowUpgrade,
    discardIfEmpty,
    selectedId,
    setSelectedId,
    setDrawerOpen,
    selectedFolder,
    setSelectedFolder,
    view,
    setView,
  });

  // ── Android back button (#174) ─────────────────────────────────────
  // MainActivity.kt routes hardware/gesture back presses here via
  // androidBack.ts. Each press dismisses the topmost layer, mirroring
  // the desktop Escape cascade in useKeyboardShortcuts; returning
  // false lets the native side background the app (moveTaskToBack).
  // Ref-per-render so the registered handler always sees fresh state.
  const androidBackRef = useRef<() => boolean>(() => false);
  androidBackRef.current = () => {
    // Context menu keeps its own dismiss listeners (not on the Escape
    // stack), so it is checked explicitly first.
    if (ctxMenu.state) {
      ctxMenu.close();
      return true;
    }
    // Topmost modal / popover / sheet / drawer via the shared LIFO stack.
    if (closeTopOverlay()) return true;
    if (selectionMode) {
      clearSelection();
      return true;
    }
    if (zenMode) {
      setZenMode(false);
      return true;
    }
    // Fullscreen editor on a phone: back to the list (same action as the
    // md:hidden back arrow). Gated on the md boundary, NOT isMobile
    // (<1024): at 768-1023px the list and editor render side by side and
    // the auto-select effect would instantly re-select the first note,
    // turning back into a consumed no-op that can never background the
    // app.
    if (selectedId && window.matchMedia('(max-width: 767px)').matches) {
      void handleCloseEditor();
      return true;
    }
    // Any list other than the home screen - a pillar, Starred/Trash, or a
    // tag/folder scope - returns to All Items first, and only the next
    // press backgrounds the app (#213). Android's start-destination
    // convention: Back walks the way you came in before it leaves.
    if (view !== 'home' || selectedTag || selectedFolder) {
      void handleSelectView('home');
      // handleSelectView deliberately keeps both filters (a tag, a folder
      // and a view compose), but a Back that lands on a still-filtered list
      // is not home, so this one caller clears them too.
      setSelectedFolder(null);
      setSelectedTag(null);
      return true;
    }
    return false;
  };
  useEffect(() => {
    setAndroidBackHandler(() => androidBackRef.current());
    return () => setAndroidBackHandler(null);
  }, []);

  // ── Swipe-right opens the mobile drawer (#173) ─────────────────────
  // Two eligible start zones: (1) the left edge, unconditional - the
  // only zone with a note open fullscreen, and inert on gesture-nav
  // Android / iOS Safari where the OS owns the edge; (2) anywhere
  // inside the notes list pane (data-drawer-swipe) - the zone every
  // user gets without changing system settings. Zone 2 skips touches
  // starting on text inputs (search, inline tag create) so swipes
  // never fight text selection there; the editor pane never carries
  // the attribute for the same reason.
  useEdgeSwipe(
    () => {
      // Fire-time guards for layers that don't re-render this component:
      // never pull the drawer over an open overlay or context menu.
      if (hasOpenOverlay() || ctxMenu.state) return;
      setDrawerOpen(true);
    },
    isMobile && !zenMode && !drawerOpen && !mobileKeyboard,
    (t) => {
      if (t.clientX <= EDGE_START_PX) return true;
      const el = t.target instanceof Element ? t.target : null;
      if (!el || el.closest('input, textarea, [contenteditable="true"]')) return false;
      return !!el.closest('[data-drawer-swipe]');
    }
  );

  // Ref on the sidebar search input so the ⌘K / ⌘F shortcut can focus it
  // regardless of where focus currently lives.
  const searchInputRef = useRef<HTMLInputElement | null>(null);

  /** Empty the entire trash. */
  const [showEmptyTrashModal, setShowEmptyTrashModal] = useState(false);

  /** Single-note permanent delete confirmation. */
  const [deleteConfirm, setDeleteConfirm] = useState<{ id: string; title: string } | null>(null);

  // Holds the target title of a clicked [[wiki-link]] that matched no
  // existing note. Set instead of silently creating, so a stale link
  // (e.g. left dangling after its target was renamed) prompts before
  // spawning a phantom note. null = no prompt open.
  const [wikiLinkCreatePending, setWikiLinkCreatePending] = useState<string | null>(null);

  function handleEmptyTrash() {
    if (trashedNotes.length === 0) return;
    setShowEmptyTrashModal(true);
  }

  async function confirmEmptyTrash() {
    // GC blobs for all trashed notes before wiping them - one batch call,
    // so a blob shared by two trashed notes cannot hide behind its
    // batch-mate in the reference check.
    if (imageStoreRef.current) {
      void gcOnNotesDelete(
        imageStoreRef.current,
        trashedNotes.map((n) => ({ id: n.id, body: n.body })),
        attachmentStoreRef.current,
      );
    }
    await emptyTrash();
    setSelectedId(null);
    await refresh();
    // Sync deletes to server, recalculate stale counters, then refresh quota.
    runSync().then(refreshStorage);
  }

  /**
   * Find the user's Reminders note - the destination for quick-added tasks.
   * Matches on exact title. Creates one on demand if none exists.
   * Returns the note id. The Inbox is a regular note and the user can
   * rename, edit, or trash it like anything else; if they do, the next
   * quick-add just creates a new one.
   */
  async function getOrCreateInboxNote(): Promise<string> {
    const existing = activeNotes.find(
      (n) => (n.title ?? '').trim() === INBOX_TITLE
    );
    if (existing) return existing.id;
    const note = await createNote(INBOX_TITLE, '', [], false, 'task');
    await refresh();
    return note.id;
  }

  /** Flip a single task's checkbox by rewriting the parent note body. */
  async function handleToggleTask(task: TaskItem, checked: boolean) {
    const note = await getNote(task.noteId);
    if (!note) return;
    const nextBody = setTaskCheckedInBody(note.body, task.lineIdx, checked);
    if (nextBody == null) {
      // Line shifted out from under us (parallel edit). Rebuild and bail.
      await refresh();
      return;
    }
    const now = new Date().toISOString();
    patchLocal(note.id, { body: nextBody }, now);
    await updateNote(note.id, { body: nextBody });
    // If this note is open in the editor, force remount so the checkbox
    // state is reflected immediately. Clear the editing body ref so the
    // stale buffered body doesn't overwrite the toggled version.
    if (selectedId === task.noteId) {
      editingBodyRef.current.delete(task.noteId);
      setEditorRevision((r) => r + 1);
    }
    scheduleSync();
  }

  /**
   * Append a new unchecked task to the Reminders note. Used by both the
   * quick-add input at the top of the Tasks view and the "New Task"
   * right-click menu item. The Tasks view re-derives on next render
   * via `allTasks`, so the new item shows up immediately.
   */
  async function handleAddQuickTask(text: string) {
    const clean = text.trim();
    if (!clean) return;
    const id = await getOrCreateInboxNote();
    const note = await getNote(id);
    if (!note) return;
    const nextBody = appendTaskToBody(note.body, clean);
    const now = new Date().toISOString();
    patchLocal(id, { body: nextBody }, now);
    await updateNote(id, { body: nextBody });
    await refresh();
    setSelectedId(id);
    setEditorRevision((r) => r + 1);
    scheduleSync();
  }

  /**
   * Jump from a task row to the source line inside its parent note.
   * We don't have line-level selection in the editor yet, so this
   * just selects the note and switches to the All view - good enough
   * to show the user "here's where this task lives".
   */
  async function handleOpenTaskSource(task: TaskItem) {
    // Stay in the Tasks view - middle column keeps showing the task
    // list, editor pane opens the source note on the right. Previous
    // behaviour kicked users back to the All-Notes view, which felt
    // jarring because their context (the task list) disappeared.
    setSelectedId(task.noteId);
    setDrawerOpen(false);
  }

  /** Intercept sign-out to show the phrase-reminder modal, unless the
      user opted out with "never remind me again" or their phrase is
      stored server-side (custodial). Fires for both phrase and OAuth
      sessions - OAuth re-signin alone no longer recovers the phrase
      (see ops/docs/oauth-zk-fix.md). */
  function handleSignOutClick() {
    // Demo has no real account to sign out of; signing out drops the app into
    // the real onboarding/Turnstile flow it can never complete (and strands
    // the tab). Disable it entirely in demo. See demo.ts.
    if (isDemoMode()) return;
    void (async () => {
      // With unsynced rows at stake the confirm ALWAYS shows: custodial
      // accounts and "don't remind me again" skip only the phrase
      // reminder - neither is consent to data loss. Same principle as
      // the forced-sign-out guard (#121).
      const unsynced = await countUnsyncedNotes();
      setUnsyncedCount(unsynced);
      if (unsynced === 0) {
        // Custodial users don't need the phrase reminder - the server
        // stores their key for 1-click re-sign-in.
        if (auth.isCustodial) {
          setSigningOut(true);
          void signOut();
          return;
        }
        const skip = window.localStorage.getItem('privacynotes.signOut.skipReminder');
        if (skip === '1') {
          setSigningOut(true);
          void signOut();
          return;
        }
      }
      setSignOutDontRemind(false);
      setShowSignOutConfirm(true);
    })();
  }

  async function confirmSignOut() {
    if (signOutDontRemind) {
      window.localStorage.setItem('privacynotes.signOut.skipReminder', '1');
    }
    setShowSignOutConfirm(false);
    setSigningOut(true);
    // When this confirm was reached through SessionExpiredModal the
    // sign-out is forced, not chosen: the dead session means the final
    // flush cannot reach the server, so unsynced rows must survive the
    // wipe. They push after the next same-pubkey sign-in.
    await signOut({ keepUnsyncedNotes: sessionExpired || revalidationExpired });
  }

  /** Pro: toggle lock on a note. Caller checks isPro first. */
  async function handleSetLocked(id: string, locked: boolean) {
    await setLocked(id, locked);
    await refresh();
    scheduleSync();
  }

  /** Pro: toggle PIN-protect on a note. Caller checks isPro first. */
  async function handleSetPinProtected(id: string, pinProtected: boolean) {
    setJustProtectedIds((cur) => {
      const next = new Set(cur);
      if (pinProtected) next.add(id); else next.delete(id);
      return next;
    });
    await setPinProtected(id, pinProtected);
    await refresh();
    scheduleSync();
  }

  /** Duplicate a note: same body/tags/star, new id, "(copy)" suffix. */
  async function handleDuplicate(id: string) {
    const copy = await duplicateNote(id);
    if (!copy) return;
    await refresh();
    setSelectedId(copy.id);
    scheduleSync();
  }

  /** Toggle the starred flag on a note. */
  async function handleToggleStar(id: string, starred: boolean) {
    await setStarred(id, starred);
    await refresh();
    scheduleSync();
  }

  /** Generate a Share & Burn After Reading link for a note. Desktop: modal. Mobile: native share sheet. */
  async function handleBurnShare(n: LocalNote) {
    // What travels is decided in one place, so the "..." menu can dim the
    // Burn button on exactly the notes this refuses. Spec: burnShare.ts.
    const payload = prepareBurnPayload(n);
    if (!payload) {
      setBurnError(t('burn.mediaOnly'));
      setTimeout(() => setBurnError(null), 5000);
      return;
    }
    const { body, stripped } = payload;
    const result = await createBurnLink(n.title, body, payload.fields);
    if (!result.ok) {
      setBurnError(result.error);
      setTimeout(() => setBurnError(null), 5000);
      return;
    }
    recordAdminEvent(supabase, 'export', 'burn');
    // Mobile - use native share sheet. Desktop gets the burn modal even if
    // the browser supports navigator.share (Chrome/Safari on macOS do, but
    // the native macOS share sheet is unhelpful for a one-time URL).
    if (isMobile && typeof navigator.share === 'function') {
      try {
        await navigator.share({ title: n.title || t('burn.shareTitle'), url: result.url });
      } catch (e: unknown) {
        // User cancelled the share sheet - not an error.
        if (e instanceof DOMException && e.name === 'AbortError') return;
        // Fallback: copy to clipboard.
        try { await navigator.clipboard.writeText(result.url); } catch { /* ignore */ }
      }
      return;
    }
    // Desktop - show the burn share modal.
    setBurnShareUrl(result.url);
    setBurnCopied(false);
    setBurnImagesStripped(stripped);
  }

  /** Copy the burn URL to clipboard from the modal. */
  async function handleBurnCopy() {
    if (!burnShareUrl) return;
    try {
      await navigator.clipboard.writeText(burnShareUrl);
      setBurnCopied(true);
    } catch { /* clipboard blocked - url is still selectable */ }
  }

  // ── Keyboard shortcuts (extracted to useKeyboardShortcuts.ts) ──
  useKeyboardShortcuts({
    zenMode,
    setZenMode,
    zenUnlocked,
    onOpenUpgrade: (trigger: string) => setShowUpgrade({ trigger: trigger as 'zen' }),
    // In Bookmarks the new-item shortcut focuses the quick-add bar - a
    // background note from a pillar that cannot show it helps nobody.
    handleNew: () => {
      if (view === 'bookmarks') { handleNewBookmark(); return; }
      void handleNew();
    },
    searchInputRef,
    setSidebarCollapsed,
    toggleTheme,
    setShowSettings,
    selectedId,
    view,
    handleTrash,
    closeEditor: () => void handleCloseEditor(),
    search,
    setSearch,
    showAbout,
    setShowAbout,
    displayNotesRef,
    handleSelectNote,
    navigateList,
    selectionMode,
    clearSelection,
    selectAllVisible,
  });

  // --- Right-click context menu builders ------------------------------
  // Kept together so the menu concept stays inspectable in one place.
  // Icons live in ./icons.tsx (no emoji per house rules).

  /** Global / background menu. Fires on right-click anywhere in the app
   *  chrome that isn't an editable surface or a list row. */
  // Context-menu builders (Global / Text / per-Note) live in
  // ./notesView/contextMenus. Re-derive on every render so the closures
  // see fresh state - same behaviour as the inline versions they replaced.
  const { buildGlobalMenu, buildNoteMenu } =
    createContextMenuBuilders({
      view,
      handleSelectView,
      isPro: auth.isPro ?? false,
      zenUnlocked,
      foldersUnlocked,
      onOpenUpgrade: (trigger: string) => setShowUpgrade({ trigger: trigger as 'zen' }),
      zenMode,
      setZenMode,
      sidebarCollapsed,
      setSidebarCollapsed,
      notesListCollapsed,
      setNotesListCollapsed,
      onResetPaneWidths: () => {
        setSidebarWidth(SIDEBAR_WIDTH_DEFAULT);
        setNotesListWidth(LIST_WIDTH_DEFAULT);
        setEditorDockWidth(EDITOR_DOCK_DEFAULT);
      },
      handleNew,
      onNewFile: () => {
        void handleSelectView('files');
        filesUploadRef.current?.click();
      },
      onNewBookmark: handleNewBookmark,
      onOpenBookmark: (n) => openExternal(parseLinkBody(n.body).url),
      onCopyBookmarkUrl: (n) => {
        void navigator.clipboard.writeText(parseLinkBody(n.body).url).then(() => {
          setImportToast(t('shell:bookmarks.copiedUrl'));
        }).catch(() => { /* denied write: no toast is the honest signal */ });
      },
      onEditBookmark: (n) => {
        void handleSelectView('bookmarks').then(() => selectBookmarkForEdit(n.id));
      },
      setShowSettings,
      handleSignOutClick,
      selectedIds,
      onToggleSelected: toggleSelected,
      handleRestore,
      handlePermanentlyDelete,
      requestDeleteConfirm: (id: string, title: string) => setDeleteConfirm({ id, title }),
      handleToggleStar,
      handleSetLocked,
      handleSetPinProtected,
      requestRemoveProtection: (id: string) => void requestRemoveProtection(id),
      onSetPin: () => setShowSecurity({ tab: 'pin', reason: 'protect' }),
      handleDuplicate,
      handleTrash,
      onMoveToFolder: (id: string) => {
        const n = notes.find((x) => x.id === id);
        setFolderPicker({ mode: 'note', noteIds: [id], currentFolderId: n?.folderId ?? null });
      },
      handleBurnShare,
      exportSingleMarkdown,
      exportSingleHtml,
      printNote,
      imageStoreRef,
    });

  /**
   * The title's own long-press guard, twin of the editor body's. Pasting into
   * the title is exactly how #222's reporter kept clobbering it, so it is the
   * one field where long-press-to-paste is the common case rather than the
   * rare one - and the keyboard is never wanted for it.
   * Fix: GitHub #223 (avoid opening keyboard for a long press)
   */
  const titleLongPress = useMemo(createLongPressGuard, []);
  useEffect(() => titleLongPress.cancel, [titleLongPress]);

  /**
   * Undo/redo for the note header buttons, routed to whichever field the user
   * is actually in. The title is a plain textarea and lives outside TipTap's
   * history, so the editor's undo could never touch it - pressing the button
   * with the title focused silently undid a body edit instead, and yanked the
   * caret into the body doing it. `execCommand` drives the textarea's own
   * native undo stack, which already holds the title edits (a paste restores
   * in a single step; typing unwinds a character at a time, which is the
   * browser's granularity, not ours).
   *
   * Both branches suppress the keyboard first, because both raise it on touch
   * and NEITHER does so by focusing - skipping `.focus()` is necessary and not
   * sufficient here, same as at the checklist checkbox. Whichever field holds
   * focus gets an edit applied to it, and Android re-asserts the IME for a
   * focused editable that changes underneath it. Suppressing is safe even
   * mid-typing: `inputmode` never closes a keyboard that is already up, it
   * only stops one being raised.
   * Fix: GitHub #222 (undo/redo on note title, and undo/redo opening the keyboard)
   */
  const handleHistory = useCallback((action: 'undo' | 'redo') => {
    // Any focused textarea, not just the title: the markdown source view is
    // one too, and it lives outside TipTap's history for the same reason the
    // title does.
    const active = document.activeElement;
    if (active instanceof HTMLTextAreaElement) {
      suppressSoftKeyboard(active);
      document.execCommand(action);
      return;
    }
    const editor = editorRef.current?.getEditor();
    if (!editor) {
      // Markdown source view with focus elsewhere. execCommand acts on the
      // focused editable, so the field has to be focused first - the rich
      // branch below does the same thing through `chain.focus()`.
      const source = document.querySelector<HTMLTextAreaElement>('textarea[data-pn-source]');
      if (!source) return;
      suppressSoftKeyboard(source);
      source.focus();
      document.execCommand(action);
      return;
    }
    suppressSoftKeyboard(editor.view.dom as HTMLElement);
    const chain = editor.chain();
    if (!isSoftKeyboardDevice()) chain.focus();
    if (action === 'undo') chain.undo().run();
    else chain.redo().run();
  }, []);

  const {
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
  } = useNoteEditing({
    auth,
    supabase,
    notes,
    setNotes,
    saveTimer,
    lastSyncAt,
    runSync,
    imageStoreRef,
    attachmentStoreRef,
    onSnapshotForbidden: () => setSnapshotForbidden(true),
  });
  flushEditingBodyRef.current = flushEditingBody;

  /** Title field blur: commit the rename, and say how many note-links
   *  followed it. Silence when none did - a rename usually breaks nothing. */
  function handleTitleBlurCommit(id: string) {
    void handleTitleBlur(id).then((count) => {
      if (count > 0) flashToast(t('shell:noteLinks.retargetedToast', { count }));
    });
  }

  // The global editor-mode setting swaps the open note's editors exactly
  // like the per-note "Show markdown" link, so it needs the same pre-swap
  // flush - the replacement editor mounts from selected.body, which body
  // edits do not update per keystroke. See the toggle onClick in
  // NoteEditorPane.tsx. Shared by both AppearanceSheet mounts.
  const handleEditorModeChange = useCallback((m: 'formatted' | 'markdown') => {
    editorRef.current?.flushPendingSave();
    flushEditingBody();
    mutateSettings((prev) => ({ ...prev, editorMode: m }));
  }, [flushEditingBody, mutateSettings]);

  // Flush pending body edits into React state when the user switches notes.
  // This keeps the notes array current without triggering re-renders on
  // every keystroke while actively typing. Perf fix for #58, #64, #66.
  const prevSelectedId = useRef(selectedId);
  // Lightweight word-count body: updated on each editor onChange (300ms
  // debounced by Editor) so WordCount sees the latest text. This triggers
  // a NotesView re-render, but displayNotes is useMemo'd and NoteRow is
  // React.memo'd, so the cost is negligible. Perf fix for #58.
  const [wcBody, setWcBody] = useState('');
  useEffect(() => {
    if (prevSelectedId.current !== selectedId) {
      flushEditingBody();
      setWcBody('');
      prevSelectedId.current = selectedId;
    }
  }, [selectedId, flushEditingBody]);

  // Tags rail - extracted to TagsRail.tsx. The variable is still used in
  // the JSX below (desktop sidebar + mobile drawer).

  const tagsRail = (
    <TagsRail
      markdownCount={markdownDir?.entries.length}
      markdownRail={view === 'markdown' && markdownDir ? (
        <MarkdownRail
          entries={markdownDir.entries}
          tags={markdownTags.counts}
          selectedDir={markdownDirFilter}
          onSelectDir={setMarkdownDirFilter}
          selectedTag={markdownTagFilter}
          onSelectTag={setMarkdownTagFilter}
        />
      ) : undefined}
      view={view}
      selectedTag={selectedTag}
      handleSelectView={handleSelectView}
      handleSelectTag={handleSelectTag}
      setDrawerOpen={setDrawerOpen}
      setShowAbout={setShowAbout}
      onFeedback={() => setShowFeedback(true)}
      onRate={() => setShowRate(true)}
      viewsCollapsed={viewsCollapsed}
      setViewsCollapsed={setViewsCollapsed}
      activeNotesCount={plainNotesCount}
      openTaskCount={openTaskCount}
      vaultCount={vaultCount}
      bookmarksCount={bookmarksCount}
      filesCount={fileItems.length}
      journalCount={journalCount}
      starredCount={starredCount}
      trashedCount={trashedNotes.length}
      tagCounts={tagCounts}
      favoriteTagsList={favoriteTagsList}
      nonFavoriteTagsList={nonFavoriteTagsList}
      browseMode={effectiveBrowseMode}
      onBrowseChange={handleBrowseChange}
      isPro={auth.isPro ?? false}
      folders={userSettings.folders}
      folderCounts={folderCounts}
      unfiledCount={unfiledCount}
      selectedFolder={selectedFolder}
      onSelectFolder={(id) => void handleSelectFolder(id)}
      onCreateFolder={(name, parentId) => void handleCreateFolder(name, parentId)}
      onRenameFolder={handleRenameFolder}
      onReorderFolders={(id, parentId, orderedIds) => {
        handleReorderFolders(id, parentId, orderedIds);
        // The drop only survives if this device stops overruling it.
        setFolderSortField('custom');
      }}
      onRequestMoveFolder={(id) => {
        if (!foldersUnlocked) { openFoldersUpsell(); return; }
        setFolderPicker({ mode: 'folder', folderId: id });
      }}
      onRequestDeleteFolder={(id) => {
        if (!canDeleteFolder(id, foldersUnlocked)) { openFoldersUpsell(); return; }
        const f = userSettings.folders.find((x) => x.id === id);
        if (f) setFolderDeleteConfirm({ id, name: f.name });
      }}
      foldersLocked={!foldersUnlocked}
      onFoldersLockedAction={openFoldersUpsell}
      folderSortField={folderSortField}
      setFolderSortField={setFolderSortField}
      folderSortDir={folderSortDir}
      setFolderSortDir={setFolderSortDir}
      tagSortField={tagSortField}
      setTagSortField={setTagSortField}
      tagSortDir={tagSortDir}
      setTagSortDir={setTagSortDir}
      creatingTag={creatingTag}
      setCreatingTag={setCreatingTag}
      newTagDraft={newTagDraft}
      setNewTagDraft={setNewTagDraft}
      handleCreateTag={handleCreateTag}
      renamingTag={renamingTag}
      setRenamingTag={setRenamingTag}
      renameBuffer={renameBuffer}
      setRenameBuffer={setRenameBuffer}
      commitRenameTag={commitRenameTag}
      openTagMenu={openTagMenu}
      setOpenTagMenu={setOpenTagMenu}
      openTagActionMenu={openTagActionMenu}
      toggleFavoriteTag={toggleFavoriteTag}
      handleDeleteTag={handleDeleteTag}
      handleDeleteTagAndNotes={handleDeleteTagAndNotes}
      userSettings={userSettings}
      mutateSettings={mutateSettings}
      onToggleHidden={handleToggleHiddenView}
      setImportExportModal={setImportExportModal}
      mobileTabIndex={mobileTabIndex}
    />
  );

  // Trash view header renders as a red trash icon (no word) - see the
  // notesList block below. All other views use a plain text label.
  // The active folder is NOT part of the label: it renders as a
  // dismissable chip under the title row (NotesList), so the view name
  // and a long folder name never compete for one truncating line.
  // Folder id -> name for the chip each row and tile draws beside its tags.
  // Memoized on the folder array so a keystroke in the search box does not
  // hand every visible chip a new context value.
  const folderNames = useMemo(
    () => new Map(userSettings.folders.map((f) => [f.id, f.name])),
    [userSettings.folders],
  );
  const activeFolderName = selectedFolder
    ? selectedFolder === UNFILED_ID
      ? t('shell:folders.unfiled')
      : userSettings.folders.find((f) => f.id === selectedFolder)?.name ?? null
    : null;
  // The title names the open pillar and nothing else. The tag used to take
  // it over, which is why a tag could not compose with a view: two filters
  // cannot share one truncating line. Both now ride the chip row instead.
  const listHeaderLabel =
    view === 'home'
      ? t('headerLabel.allItems')
      : view === 'journal'
        ? t('headerLabel.journals')
        : view === 'vault'
          ? t('headerLabel.vault')
          : view === 'starred'
            ? t('headerLabel.pinned')
            : t('headerLabel.notes');

  const tasksList = (
    <TasksList
      onSelectView={handleSelectView}
      hiddenViews={userSettings.hiddenViews}
      onOpenDrawer={() => setDrawerOpen(true)}
      allTasks={scopedAllTasks}
      activeNotes={scopedActiveNotes}
      selectedId={selectedId}
      activeFolderName={activeFolderName}
      onClearFolder={() => setSelectedFolder(null)}
      onClearTag={() => setSelectedTag(null)}
      activeTag={selectedTag}
      listPrefs={listPrefs}
      listPrefsStore={userSettings.listPrefs}
      onListPrefsChange={handleListPrefsChange}
      viewMode={effectiveViewMode}
      tasksView={userSettings.tasksView}
      showDoneTasks={showDoneTasks}
      search={search}
      setSearch={setSearch}
      taskDraft={taskDraft}
      taskInputRef={taskInputRef}
      searchInputRef={searchInputRef as React.RefObject<HTMLInputElement>}
      mobileTabIndex={mobileTabIndex}
      hotkeyLabel={hotkeyLabel}
      isNoteLocked={isNoteLocked}
      onTasksViewChange={handleTasksViewChange}
      onSetShowDoneTasks={setShowDoneTasks}
      onSetTaskDraft={setTaskDraft}
      onToggleTask={handleToggleTask}
      onOpenTaskSource={handleOpenTaskSource}
      onAddQuickTask={handleAddQuickTask}
      onNew={handleNew}
      onOpenImport={() => setImportExportModal({ open: true, tab: 'import' })}
      onSelectNote={(id) => {
        setSelectedId(id);
        setDrawerOpen(false);
      }}
      onContextMenu={openRowMenu}
      buildNoteMenu={buildNoteMenu}
      selectionMode={selectionMode}
      selectedIds={selectedIds}
      selectionAllStarred={selectionAllStarred}
      onRowClick={handleRowClick}
      onToggleSelected={toggleSelected}
      onRangeSelect={rangeSelect}
      onLongPressStart={beginLongPress}
      onLongPressEnd={cancelLongPress}
      onClearSelection={clearSelection}
      onSelectAllVisible={selectAllVisible}
      onBulkFavorite={() => void handleBulkFavorite()}
      onBulkTag={(tag) => {
        void handleBulkAddTag(tag).then((count) => {
          setImportToast(t('toast.addedTag', { tag, count }));
          window.setTimeout(() => setImportToast(null), 3000);
        });
      }}
      onBulkMoveToFolder={handleBulkMoveToFolder}
      foldersUnlocked={foldersUnlocked}
      onBulkExport={() => void handleBulkExport()}
      onBulkTrash={requestBulkTrash}
      allTags={tagCounts.tags}
    />
  );

  const filesList = (
    <FilesList
      onSelectView={handleSelectView}
      hiddenViews={userSettings.hiddenViews}
      onOpenDrawer={() => setDrawerOpen(true)}
      fileItems={scopedFileItems}
      filesCount={scopedFileItems.length}
      activeFolderName={activeFolderName}
      onClearFolder={() => setSelectedFolder(null)}
      onClearTag={() => setSelectedTag(null)}
      activeTag={selectedTag}
      currentNoteId={selectedId}
      filter={fileFilter}
      onFilterChange={setFileFilter}
      onOpenNote={(noteId, fileUuid) => {
        setSelectedId(noteId);
        setDrawerOpen(false);
        if (fileUuid) setPendingFileScroll({ noteId, uuid: fileUuid });
      }}
      onUploadFiles={handleFilesUpload}
      mobileTabIndex={mobileTabIndex}
      quotaUsedBytes={viewQuota ? viewQuota.totalBytes + viewQuota.imageBytes : 0}
      quotaMaxBytes={viewQuota?.maxTotalBytes ?? 0}
      onRefreshStorage={refreshStorage}
      search={search}
      setSearch={setSearch}
      searchInputRef={searchInputRef as React.RefObject<HTMLInputElement>}
      isPro={auth.isPro ?? false}
      onOpenUpgrade={() => setShowUpgrade({ trigger: 'storage' })}
      hasStorageSub={(viewQuota?.maxTotalBytes ?? 0) > 500 * 1000 * 1000}
      onManageStorage={() => { setSettingsCategory('storage'); setShowSettings(true); }}
      listPrefs={listPrefs}
      viewMode={effectiveViewMode}
      listPrefsStore={userSettings.listPrefs}
      onListPrefsChange={handleListPrefsChange}
      selectionMode={selectionMode}
      selectedIds={selectedIds}
      selectionAllStarred={selectionAllStarred}
      onRowClick={handleRowClick}
      onToggleSelected={toggleSelected}
      onRangeSelect={rangeSelect}
      onLongPressStart={beginLongPress}
      onLongPressEnd={cancelLongPress}
      onClearSelection={clearSelection}
      onDeselectAll={deselectAll}
      onSelectAllVisible={selectAllVisible}
      onBulkFavorite={() => void handleBulkFavorite()}
      onBulkMoveToFolder={handleBulkMoveToFolder}
      foldersUnlocked={foldersUnlocked}
      onBulkExport={() => void handleBulkExport()}
      onBulkTrash={requestBulkTrash}
      onContextMenu={openRowMenu}
      onToggleStar={(id, starred) => void handleToggleStar(id, starred)}
      onTrash={(id) => void handleTrash(id)}
      isNoteStarred={(id) => notes.find((n) => n.id === id)?.starred === 1}
      allTags={tagCounts.tags}
      onBulkTag={(tag) => {
        void handleBulkAddTag(tag).then((count) => {
          setImportToast(t('toast.addedTag', { tag, count }));
          window.setTimeout(() => setImportToast(null), 3000);
        });
      }}
    />
  );

  const markdownPane = (
    <MarkdownListPane
      onSelectView={handleSelectView}
      hiddenViews={userSettings.hiddenViews}
      onOpenDrawer={() => setDrawerOpen(true)}
      dir={markdownDir}
      onDir={(next) => { setMarkdownDir(next); setMarkdownDirFilter(null); setMarkdownTagFilter(null); }}
      dirFilter={markdownDirFilter}
      tagFilter={markdownTagFilter}
      tagsByPath={markdownTags.byPath}
      tagsScanned={markdownTags.done}
      listPrefs={listPrefs}
      listPrefsStore={userSettings.listPrefs}
      onListPrefsChange={handleListPrefsChange}
      onExplain={() => setMarkdownExplain(true)}
      reopenName={markdownRestore.reopen?.name ?? null}
      // The remembered folder can be gone, renamed, or on an unmounted volume
      // by the time the user accepts the prompt, and the rejection is the only
      // signal that the reopen did not happen.
      onReopen={() => void markdownRestore.acceptReopen().catch(() => flashToast(t('shell:markdown.openFailed')))}
      onContextMenu={openRowMenu}
      onImportToNotes={(filename, raw) => void handleImportMarkdown(filename, raw)}
      onRequestDelete={setMarkdownDelete}
      onImportManyToNotes={handleImportMarkdownMany}
      onRequestDeleteMany={setMarkdownDeleteMany}
      opened={markdownFile}
      onOpened={setMarkdownFile}
      viewMode={effectiveViewMode}
    />
  );

  // Bookmarks pillar wiring. Creation and editing live inside the list
  // (quick-add bar + in-place expansion); these signals let the "New
  // Bookmark" entry points and the context menu reach them.
  function handleNewBookmark() {
    void handleSelectView('bookmarks');
    setBookmarkFocusSignal((x) => x + 1);
  }

  /** Select a bookmark INTO the standard editor (pencil, context-menu
   *  Edit, quick-add create). handleSelectNote cannot do it - a plain
   *  click there opens the URL by design. */
  async function selectBookmarkForEdit(id: string) {
    const previousId = selectedId;
    setSelectedId(id);
    setDrawerOpen(false);
    const discarded = await discardIfEmpty(previousId);
    if (discarded) {
      await refresh();
      void runSync();
    }
  }

  const bookmarksList = (
    <BookmarksList
      bookmarks={displayNotes}
      bookmarkKeys={bookmarkKeys}
      /* Scoped, not raw: the derived "links from notes" rows answer to the
         active tag and folder like every other row in this pane. Left raw,
         they kept quoting notes the filter had excluded, and their presence
         also kept the pane from ever reading as empty - so the filter hint
         never appeared however narrow the filter was. */
      scanNotes={scopedActiveNotes}
      listPrefs={listPrefs}
      listPrefsStore={userSettings.listPrefs}
      onListPrefsChange={handleListPrefsChange}
      onSelectView={handleSelectView}
      hiddenViews={userSettings.hiddenViews}
      onOpenDrawer={() => setDrawerOpen(true)}
      search={search}
      setSearch={setSearch}
      searchInputRef={searchInputRef}
      activeFolderName={activeFolderName}
      onClearFolder={() => setSelectedFolder(null)}
      onClearTag={() => setSelectedTag(null)}
      activeTag={selectedTag}
      mobileTabIndex={mobileTabIndex}
      allTags={tagCounts.tags}
      foldersUnlocked={foldersUnlocked}
      viewMode={effectiveViewMode}
      onRequestAdd={(url) => {
        void (async () => {
          const created = await createNote('', buildLinkBody(url), [], false, 'link');
          await refresh();
          // Set BEFORE selecting: the focus effect consumes the flag on the
          // selection's render pass - the same choreography handleNew runs.
          pendingTitleFocus.current = true;
          await selectBookmarkForEdit(created.id);
          void runSync();
        })();
      }}
      onRequestEdit={(note) => void selectBookmarkForEdit(note.id)}
      editingNoteId={view === 'bookmarks' ? selectedId : null}
      onSaveDerived={(d: BookmarkDraft) => {
        void (async () => {
          await createNote(d.name, buildLinkBody(d.url), d.tags, false, 'link', d.folderId);
          await refresh();
          void runSync();
        })();
      }}
      selectionMode={selectionMode}
      selectedIds={selectedIds}
      selectionAllStarred={selectionAllStarred}
      onRowClick={handleRowClick}
      onToggleSelected={toggleSelected}
      onRangeSelect={rangeSelect}
      onLongPressStart={beginLongPress}
      onLongPressEnd={cancelLongPress}
      onClearSelection={clearSelection}
      onDeselectAll={deselectAll}
      onSelectAllVisible={selectAllVisible}
      onBulkFavorite={() => void handleBulkFavorite()}
      onBulkTag={(tag) => {
        void handleBulkAddTag(tag).then((count) => {
          setImportToast(t('toast.addedTag', { tag, count }));
          window.setTimeout(() => setImportToast(null), 3000);
        });
      }}
      onBulkMoveToFolder={handleBulkMoveToFolder}
      onBulkExport={() => void handleBulkExport()}
      onBulkTrash={requestBulkTrash}
      onOpen={(url) => openExternal(url)}
      onOpenNote={(noteId) => {
        setView('home');
        void handleSelectNote(noteId);
      }}
      onTrash={(note) => void handleTrash(note.id)}
      onRowContextMenu={(note, e) => openRowMenu(e, buildNoteMenu(note))}
      onOpenImport={() => setImportExportModal({ open: true, tab: 'import' })}
      focusSignal={bookmarkFocusSignal}
    />
  );

  const notesList = (
    <NotesList
      onSelectView={handleSelectView}
      hiddenViews={userSettings.hiddenViews}
      onOpenDrawer={() => setDrawerOpen(true)}
      view={view}
      displayNotes={displayNotes}
      selectedId={selectedId}
      selectedTag={selectedTag}
      activeFolderName={activeFolderName}
      onClearFolder={() => setSelectedFolder(null)}
      onClearTag={() => setSelectedTag(null)}
      /* The same two actions the row menu offers, and the same landing:
         editing a bookmark happens in the Bookmarks pillar, so the edit
         button goes there and selects it. */
      onEditBookmark={(n) => { void handleSelectView('bookmarks').then(() => selectBookmarkForEdit(n.id)); }}
      onTrashBookmark={(n) => void handleTrash(n.id)}
      listHeaderLabel={listHeaderLabel}
      search={search}
      setSearch={setSearch}
      searchInputRef={searchInputRef}
      mobileTabIndex={mobileTabIndex}
      listPrefs={listPrefs}
      viewMode={effectiveViewMode}
      listPrefsStore={userSettings.listPrefs}
      onListPrefsChange={handleListPrefsChange}
      selectionMode={selectionMode}
      selectedIds={selectedIds}
      selectionAllStarred={selectionAllStarred}
      onClearSelection={clearSelection}
      onDeselectAll={deselectAll}
      onSelectAllVisible={selectAllVisible}
      onToggleSelected={toggleSelected}
      onRangeSelect={rangeSelect}
      onBulkFavorite={() => void handleBulkFavorite()}
      onBulkTag={(tag) => {
        void handleBulkAddTag(tag).then((count) => {
          setImportToast(t('toast.addedTag', { tag, count }));
          window.setTimeout(() => setImportToast(null), 3000);
        });
      }}
      onBulkMoveToFolder={handleBulkMoveToFolder}
      foldersUnlocked={foldersUnlocked}
      onBulkExport={() => void handleBulkExport()}
      onBulkTrash={requestBulkTrash}
      onBulkRestore={() => void handleBulkRestore()}
      onBulkDeleteForever={requestBulkDelete}
      allTags={tagCounts.tags}
      onRowClick={handleRowClick}
      onContextMenu={openRowMenu}
      buildNoteMenu={buildNoteMenu}
      onLongPressStart={beginLongPress}
      onLongPressEnd={cancelLongPress}
      isNoteLocked={isNoteLocked}
      onNew={(vaultType, overrideView) => void handleNew(vaultType, overrideView, undefined, view === 'starred')}
      onNewBookmark={handleNewBookmark}
      onOpenImport={(tab) => setImportExportModal({ open: true, tab })}
      onNewFile={() => {
        void handleSelectView('files');
        filesUploadRef.current?.click();
      }}
      onBackfillDate={(d) => void handleBackfillDate(d)}
      onEmptyTrash={handleEmptyTrash}
      trashedNotesLength={trashedNotes.length}
      hotkeyLabel={hotkeyLabel}
      vaultFilter={vaultFilter}
      onVaultFilterChange={setVaultFilter}
      quotaUsedBytes={viewQuota ? viewQuota.totalBytes + viewQuota.imageBytes : undefined}
      quotaMaxBytes={viewQuota?.maxTotalBytes}
      onRefreshStorage={refreshStorage}
      autoDeleteTrashDays={userSettings.autoDeleteTrashDays}
      onAutoDeleteTrashDaysChange={(days) => mutateSettings((prev) => ({ ...prev, autoDeleteTrashDays: days }))}
    />
  );

  return (
    <div
      // Status-bar safe area, applied ONCE at the root. It used to hang off
      // the mobile wordmark bar, but that bar is gone (its drawer button and
      // pillar switcher now live in each list pane's title row, ListNav), and
      // below lg the topmost element is no longer fixed - it is whichever of
      // the banners, the list pane, or the editor renders first. The root is
      // the one ancestor of all three. env() is 0 on Android (the system
      // already insets the WebView) and the real notch inset on iOS.
      // Spec: ops/docs/ui-patterns.md section 54 (the safe-area inset lives on the root, not per pane)
      ref={shellRootRef}
      // No `lg:pt-0` here, deliberately. It used to zero the safe-area padding at
      // the lg breakpoint on the assumption that lg means desktop, where there is
      // no status bar to avoid. iPad breaks that assumption: a 13" iPad is 1032
      // points wide in portrait and 1376 in landscape, both past lg, so the app
      // header rendered underneath the iOS status bar and collided with the clock.
      // Dropping the override costs desktop nothing, because env(safe-area-inset-top)
      // already resolves to 0 there. Found on an iPad Pro 13" simulator 2026-08-16,
      // during App Store submission.
      className="h-dvh flex flex-col bg-surface-0 text-pn overflow-hidden pt-[env(safe-area-inset-top)]"
      // Single source of truth for the pane widths. The raw --pn-*-w vars
      // carry the stored preferences; the --pn-*-render vars carry the
      // declarative clamp formulas (viewport caps, the docked-grid closed
      // system) so every consumer - the sidebar aside, the notes-list
      // aside, the docked editor, the grid floor, and the footer settings
      // zone that must stay pixel-aligned with the sidebar edge - renders
      // from one definition, and window shrink never rewrites a stored
      // value. Spec: ops/docs/design-decisions.md (pane resize clamps)
      style={{
        '--pn-sidebar-w': `${sidebarWidth}px`,
        '--pn-list-w': `${notesListWidth}px`,
        '--pn-editor-w': `${editorDockWidth}px`,
        '--pn-sidebar-render': sidebarCollapsed
          ? '52px'
          : `min(var(--pn-sidebar-w), ${SIDEBAR_WIDTH_MAX}px, ${SIDEBAR_VIEWPORT_CAP * 100}vw)`,
        '--pn-sidebar-render-dock': sidebarCollapsed
          ? '52px'
          : `clamp(${SIDEBAR_WIDTH_MIN}px, var(--pn-sidebar-w), min(${SIDEBAR_WIDTH_MAX}px, calc(100vw - ${DOCK_SIDEBAR_RESERVE}px)))`,
        '--pn-list-render': `min(var(--pn-list-w), ${LIST_WIDTH_MAX}px, ${LIST_VIEWPORT_CAP * 100}vw)`,
        '--pn-grid-min': `min(${GRID_DOCK_MIN}px, calc(100vw - ${DOCK_GRID_RESERVE}px))`,
        '--pn-editor-render-dock': `clamp(${EDITOR_DOCK_MIN}px, var(--pn-editor-w), calc(100vw - ${STRIPS_W}px - var(--pn-grid-min) - var(--pn-sidebar-render-dock)))`,
      } as CSSProperties}
      onContextMenu={(e) => {
        // Strategy B - partial suppression. App menu wins in chrome and
        // on list rows; the browser's native menu wins on editable text
        // (paste, spellcheck), images (Save image as…), and links (Open
        // in new tab, Copy link). Spec: ops/docs/backlog.md #74 (named 'Strategy B - Partial' in the approved menu design).
        if (shouldUseBrowserDefault(e.target)) return;
        // A touch long-press is how you select and copy text on mobile.
        // Leave it to the platform instead of answering it with a menu
        // of app actions. Spec: issue #208.
        if (isTouchContextMenu(e)) return;
        // Overlays opt out of the app menu: "New note / Sign out" is
        // meaningless on top of Settings. The right-click falls through to
        // the platform's own menu, which is what a screen of prose and
        // copyable text wants. Spec: issue #208.
        if (optsOutOfAppMenu(e.target)) return;
        ctxMenu.open(e, buildGlobalMenu());
      }}
    >
      <MoveBanner onConflict={enqueueConflict} />
      <MovedBookmarkHint />
      {showDemoBanner && <DemoBanner onDismiss={() => setDemoBannerDismissed(true)} />}
      {!isDemoMode() && !freshVaultSessionRef.current && (
        <AnnouncementBanner
          surface="app"
          dismissedIds={userSettings.dismissedAnnouncements}
          onDismiss={(id) =>
            mutateSettings((prev) =>
              prev.dismissedAnnouncements.includes(id)
                ? prev
                : { ...prev, dismissedAnnouncements: [...prev.dismissedAnnouncements, id] }
            )
          }
        />
      )}
      {/* Fallback when the local database is unreachable (iOS standalone
          resume bug, #112). Without this the content area is silently
          blank with no way to recover short of force-quitting the app. */}
      {loadError && (
        <div className="fixed inset-0 z-[100] flex flex-col items-center justify-center gap-4 bg-surface-0 text-pn px-6 text-center">
          <p className="text-[15px] max-w-sm opacity-80">
            {t('loadError.message')}
          </p>
          <button
            type="button"
            onClick={() => void handleDbReload()}
            className="bg-accent text-white text-[15px] font-medium px-5 py-2 rounded-full shadow-lg"
          >
            {t('loadError.reload')}
          </button>
        </div>
      )}
      {/* Hidden file input for the Files view upload button. */}
      <input
        ref={filesUploadRef}
        type="file"
        multiple
        accept={FILE_ACCEPT}
        className="hidden"
        onChange={handleFilesSelected}
      />

      {quotaExceeded && (
        <QuotaExceededBanner
          quotaExceededSince={quotaExceededSince}
          storageConfigured={isStorageConfigured()}
          onManageStorage={() => { setSettingsCategory('storage'); setShowSettings(true); }}
          onDismiss={() => { setQuotaExceeded(false); setQuotaExceededSince(null); }}
        />
      )}

      {pushErrors && pushErrors.count > 0 && pushErrorsDismissedKey.current !== `${pushErrors.count}:${pushErrors.lastMessage}` && (
        <SyncErrorBanner
          count={pushErrors.count}
          lastMessage={pushErrors.lastMessage}
          onDismiss={() => {
            pushErrorsDismissedKey.current = `${pushErrors.count}:${pushErrors.lastMessage}`;
            setPushErrors(null);
          }}
        />
      )}

      {proActivationPending && (
        <ProActivationPendingBanner
          onDismiss={() => setProActivationPending(false)}
        />
      )}

      {snapshotForbidden && !snapshotBannerDismissed && (
        <SnapshotForbiddenBanner
          onRestorePro={() => setShowUpgrade({ trigger: 'history' })}
          onDismiss={() => setSnapshotBannerDismissed(true)}
        />
      )}

      {storagePastDue && !storagePastDueDismissed && (
        <StoragePastDueBanner
          onDismiss={() => setStoragePastDueDismissed(true)}
        />
      )}

      <div className="flex flex-1 min-h-0">
        {/* Tags rail - visible lg+ only. Hidden in zen mode or when
            sidebarCollapsed is true; in the collapsed case a slim expand
            handle appears flush against the left edge so the rail is
            one click away. Width picks the RESTING state (collapsed in
            the lg-xl band, expanded at xl+, see xlScreen), but the
            collapse handle renders at every lg+ width - width chooses
            the default, never the capability.
            Spec: ops/docs/ui-patterns.md section 40 (canonical breakpoints) */}
        {!zenMode && !sidebarCollapsed && (
          // Width formulas live in the --pn-sidebar-render vars on the root
          // div; the dock variant tightens the cap in docked-grid so the
          // grid keeps its floor. Spec: ops/docs/design-decisions.md (pane resize clamps)
          <aside className={`hidden lg:flex w-[var(--pn-sidebar-render)] ${gridMode && selected ? 'min-[1400px]:w-[var(--pn-sidebar-render-dock)] ' : ''}flex-col shrink-0 bg-surface-0`}>
            {tagsRail}
          </aside>
        )}
        {!zenMode && !sidebarCollapsed && (
          <HoverLabel label={t('paneResize.hintCollapse')} position="end" className="hidden lg:flex h-full">
            <button
              type="button"
              role="separator"
              aria-orientation="vertical"
              aria-label={t('sidebar.collapse')}
              aria-valuenow={sidebarWidth}
              aria-valuemin={SIDEBAR_WIDTH_MIN}
              aria-valuemax={SIDEBAR_WIDTH_MAX}
              {...sidebarResize.stripProps}
              className="pn-strip flex w-3 border-s border-e border-divider bg-surface-0 hover:bg-surface-1 shrink-0 items-center justify-center text-pn-muted hover:text-accent transition h-full"
            >
              <span className="pn-strip-dots" />
            </button>
          </HoverLabel>
        )}
        {!zenMode && sidebarCollapsed && (
          <aside className="hidden lg:flex w-[52px] flex-col shrink-0 bg-surface-0 border-e border-divider">
            <CollapsedSidebar
              view={view}
              markdownCount={markdownDir?.entries.length}
              selectedTag={selectedTag}
              handleSelectView={handleSelectView}
              handleSelectTag={handleSelectTag}
              onNew={() => void handleNew()}
              onExpand={() => setSidebarCollapsed(false)}
              onExpandToTags={() => {
                setSidebarCollapsed(false);
                if (effectiveBrowseMode !== 'tags') handleBrowseChange('tags');
              }}
              onExpandToFolders={() => {
                setSidebarCollapsed(false);
                if (effectiveBrowseMode !== 'folders') handleBrowseChange('folders');
              }}
              isPro={auth.isPro ?? false}
              selectedFolder={selectedFolder}
              starredCount={starredCount}
              activeNotesCount={plainNotesCount}
              openTaskCount={openTaskCount}
              vaultCount={vaultCount}
      bookmarksCount={bookmarksCount}
              filesCount={fileItems.length}
              journalCount={journalCount}
              trashedCount={trashedNotes.length}
              viewMode={userSettings.viewMode}
              hiddenViews={userSettings.hiddenViews}
              onToggleViewMode={() => mutateSettings((prev) => ({ ...prev, viewMode: prev.viewMode === 'auto' ? 'list' : prev.viewMode === 'list' ? 'grid' : 'auto' }))}
            />
          </aside>
        )}
        {!zenMode && sidebarCollapsed && (
          // Collapsed strips stay plain click-to-expand buttons: a drag here
          // would act on an unmounted pane with no feedback, so no resize
          // affordance is advertised (design call, GitHub #211).
          <HoverLabel label={t('sidebar.expand')} position="end" className="hidden lg:flex h-full">
            <button
              type="button"
              onClick={() => setSidebarCollapsed(false)}
              aria-label={t('sidebar.expand')}
              className="flex w-3 border-e border-divider bg-surface-0 hover:bg-surface-1 shrink-0 items-center justify-center text-pn-muted hover:text-accent transition h-full"
            >
              <CaretRight size={12} className="shrink-0" />
            </button>
          </HoverLabel>
        )}

        {/* Notes list - md+ always visible, <md only when no note selected.
            In zen mode this stays visible while no note is open (the grid/list
            is the focus) and hides only once a note is opened. Also hidden when
            notesListCollapsed; an expand handle mirrors the sidebar one. */}
        {!markdownEntry && (!zenMode || !paneOccupied) && (!notesListCollapsed || (gridMode && !paneOccupied)) && (
          <aside
            // Swipe-right anywhere in this pane opens the mobile drawer
            // (the useEdgeSwipe eligibility guard keys off this attribute).
            data-drawer-swipe
            // Width formulas live in the --pn-* render vars on the root div.
            // Grid mode keeps the inverted model (grid is the fluid pane,
            // editor docks at --pn-editor-render-dock); the docked grid gets
            // the --pn-grid-min floor so a wide sidebar or editor can never
            // crush the tiles. notesListCollapsed now applies in docked grid
            // too (collapse = editor full width); without a note open the
            // grid is the only content, so collapse is ignored there.
            // Spec: ops/docs/design-decisions.md (pane resize clamps)
            className={`pn-list-panel ${
              gridMode
                ? `${paneOccupied ? 'hidden min-[1400px]:flex min-[1400px]:min-w-[var(--pn-grid-min)]' : 'flex'} flex-1 min-w-0 flex-col bg-surface-1`
                : `${paneOccupied ? 'hidden md:flex' : 'flex'} w-full md:w-[var(--pn-list-render)] flex-col shrink-0 bg-surface-1`
            }`}
          >
            {/* Every list pane in one provider: the folder chip on a row or a
                tile is drawn by TagChips, far below any of these panes. */}
            <FolderNamesContext.Provider value={folderNames}>
              {view === 'tasks' ? tasksList : view === 'files' ? filesList : view === 'markdown' ? markdownPane : view === 'bookmarks' ? bookmarksList : notesList}
            </FolderNamesContext.Provider>
          </aside>
        )}
        {/* Both strips act on the list column, so neither exists while the
            Markdown entry state has replaced it. */}
        {!markdownEntry && !zenMode && !gridMode && !notesListCollapsed && (
          <HoverLabel label={t('paneResize.hintCollapse')} position="end" className="hidden md:flex h-full">
            <button
              type="button"
              role="separator"
              aria-orientation="vertical"
              aria-label={t('notesList.collapse')}
              aria-valuenow={notesListWidth}
              aria-valuemin={LIST_WIDTH_MIN}
              aria-valuemax={LIST_WIDTH_MAX}
              {...listResize.stripProps}
              className="pn-strip flex w-3 border-s border-e border-divider bg-surface-1 hover:bg-surface-2 shrink-0 items-center justify-center text-pn-muted hover:text-accent transition h-full"
            >
              <span className="pn-strip-dots" />
            </button>
          </HoverLabel>
        )}
        {!markdownEntry && !zenMode && !gridMode && notesListCollapsed && (
          // Plain click-to-expand, no resize affordance - see the sidebar
          // expand strip above.
          <HoverLabel label={t('notesList.expand')} position="end" className="hidden md:flex h-full">
            <button
              type="button"
              onClick={() => setNotesListCollapsed(false)}
              aria-label={t('notesList.expand')}
              className="flex w-3 border-e border-divider bg-surface-1 hover:bg-surface-2 shrink-0 items-center justify-center text-pn-muted hover:text-accent transition h-full"
            >
              <CaretRight size={12} className="shrink-0" />
            </button>
          </HoverLabel>
        )}

        {/* Docked-grid divider (>=1400px, note open): click collapses the
            grid so the editor takes the full width, drag sizes the editor
            column via --pn-editor-w. Same strip anatomy as list mode. */}
        {!zenMode && gridMode && paneOccupied && !notesListCollapsed && (
          <HoverLabel label={t('paneResize.hintCollapse')} position="end" className="hidden min-[1400px]:flex h-full">
            <button
              type="button"
              role="separator"
              aria-orientation="vertical"
              aria-label={t('notesList.collapse')}
              aria-valuenow={editorDockWidth}
              aria-valuemin={EDITOR_DOCK_MIN}
              aria-valuemax={EDITOR_DOCK_STORE_MAX}
              {...editorResize.stripProps}
              className="pn-strip flex w-3 border-s border-e border-divider bg-surface-1 hover:bg-surface-2 shrink-0 items-center justify-center text-pn-muted hover:text-accent transition h-full"
            >
              <span className="pn-strip-dots" />
            </button>
          </HoverLabel>
        )}
        {!zenMode && gridMode && paneOccupied && notesListCollapsed && (
          <HoverLabel label={t('notesList.expand')} position="end" className="hidden min-[1400px]:flex h-full">
            <button
              type="button"
              onClick={() => setNotesListCollapsed(false)}
              aria-label={t('notesList.expand')}
              className="flex w-3 border-e border-divider bg-surface-1 hover:bg-surface-2 shrink-0 items-center justify-center text-pn-muted hover:text-accent transition h-full"
            >
              <CaretRight size={12} className="shrink-0" />
            </button>
          </HoverLabel>
        )}

        {/* Editor - md+ always visible, <md only when a note is selected.
            In docked grid the width comes from --pn-editor-render-dock;
            with the grid collapsed it stays flex-1 (full width). */}
        <main
          className={
            // The entry state is the only thing on screen, at every width and
            // in both modes, so it takes the pane whole: no `hidden` below md
            // (there is no list to fall back to) and no docked width in grid
            // mode (there is no grid beside it to dock against).
            markdownEntry
              ? 'pn-editor-pane flex flex-1 flex-col min-w-0 bg-surface-2 relative'
              : gridMode
                ? `pn-editor-pane ${paneOccupied ? 'flex' : 'hidden'} flex-1 ${zenMode || notesListCollapsed ? '' : 'min-[1400px]:flex-none min-[1400px]:w-[var(--pn-editor-render-dock)]'} flex-col min-w-0 bg-surface-2 relative`
                : `pn-editor-pane ${paneOccupied ? 'flex' : 'hidden md:flex'} flex-1 flex-col min-w-0 bg-surface-2 relative`
          }
        >
          {/* Markdown owns this pane outright: its files are read from disk and
              never become notes, so `selected` is always null here and the
              note-shaped empty state below would be nonsense. The wide pane is
              where a file's contents belong - the list column is resizable down
              to a rail, which is fine for filenames and hopeless for prose. */}
          {!selected && view === 'markdown' ? (
            markdownFile ? (
              <MarkdownFilePane
                opened={markdownFile}
                onUpdated={setMarkdownFile}
                dir={markdownDir}
                onDelete={markdownDir ? () => setMarkdownDelete(markdownFile) : null}
                onImportToNotes={(filename, raw) => void handleImportMarkdown(filename, raw)}
                onClose={() => setMarkdownFile(null)}
                gridMode={gridMode}
              />
            ) : markdownDir ? (
              // A folder is open and no file is picked yet. The prompt alone
              // left the widest pane in the app holding one grey sentence, so
              // something sits under it. Centred as a block with `my-auto` so it
              // scrolls from the top instead of losing its head on a short
              // window.
              //
              // WHAT sits under it differs by platform, and deliberately so. In
              // the desktop app it is the default-Markdown-app card: a reader who
              // has a folder open has already been past the pitch, and "you can
              // double-click a .md in Finder" is the one thing left that they
              // cannot discover from anywhere else on this screen. Everywhere
              // else that card renders nothing, so the pitch stays rather than
              // handing the widest pane in the app back its one grey sentence.
              // The pitch is still one click away either way, on the `?` in the
              // folder row.
              // Spec: ops/docs/plans/markdown-folder.md (section 11)
              <div className="flex-1 overflow-y-auto flex flex-col px-6 py-10">
                <div className="w-full max-w-md mx-auto my-auto">
                  <p className="text-[15px] text-neutral-500 dark:text-neutral-600 text-center mb-5">
                    {t('emptyEditor.selectMarkdown')}
                  </p>
                  {markdownDefaultAppSupported() ? <MarkdownDefaultAppCard /> : <MarkdownPitch />}
                </div>
              </div>
            ) : (
              // No folder: the same pane, holding the entry state instead of a
              // placeholder pointing at a list that is not there. See
              // `markdownEntry`.
              markdownPane
            )
          ) : !selected ? (
            <div className="flex-1 flex flex-col items-center justify-center px-6 text-center">
              {view === 'files' ? (
                <>
                  <div className="w-16 h-16 rounded-full bg-neutral-100 dark:bg-neutral-800 flex items-center justify-center mb-4">
                    <Folder size={28} className="text-neutral-400 dark:text-neutral-600" />
                  </div>
                  <p className="text-sm font-medium text-neutral-600 dark:text-neutral-300 mb-1">{t('emptyEditor.selectFile')}</p>
                  <p className="text-xs text-neutral-400 dark:text-neutral-600 max-w-[240px]">
                    {t('emptyEditor.uploadFiles')}
                  </p>
                </>
              ) : (
                <span className="text-[15px] text-neutral-500 dark:text-neutral-600">
                  {t('emptyEditor.selectNote')}
                </span>
              )}
            </div>
          ) : (
            <NoteEditorPane
              selected={selected}
              view={view}
              notes={notes}
              bookmarkKeys={bookmarkKeys}
              auth={auth}
              gridMode={gridMode}
              zenMode={zenMode}
              setZenMode={setZenMode}
              zenToolbar={zenToolbar}
              setZenToolbar={setZenToolbar}
              quickActionsTier={quickActionsTier}
              canGoPrev={neighbourNoteId(-1) !== null}
              canGoNext={neighbourNoteId(1) !== null}
              onNavigateList={navigateList}
              isMobile={isMobile}
              mobileTabIndex={mobileTabIndex}
              mobileEditing={mobileEditing}
              footerVisible={footerVisible}
              spellcheck={spellcheck}
              invisibles={invisibles}
              setInvisibles={setInvisibles}
              toolbarVisible={toolbarVisible}
              toggleToolbar={toggleToolbar}
              selectedEditorMode={selectedEditorMode}
              setEditorModeOverrides={setEditorModeOverrides}
              flushEditingBody={flushEditingBody}
              titleFocused={titleFocused}
              setTitleFocused={setTitleFocused}
              setEditorFocused={setEditorFocused}
              titleLongPress={titleLongPress}
              titleInputRef={titleInputRef}
              tagInputRef={tagInputRef}
              editorRef={editorRef}
              setHeaderRow={setHeaderRow}
              setNoteScroller={setNoteScroller}
              bodyOverflows={bodyOverflows}
              noteOptionsButtonRef={noteOptionsButtonRef}
              setStickyTagRow={setStickyTagRow}
              editorRevision={editorRevision}
              wcBody={wcBody}
              setWcBody={setWcBody}
              userSettings={userSettings}
              mutateSettings={mutateSettings}
              tagCounts={tagCounts}
              isNoteLocked={isNoteLocked}
              folderChipFor={folderChipFor}
              refresh={refresh}
              handleTitleChange={handleTitleChange}
              handleTitleFocus={handleTitleFocus}
              handleTitleBlur={handleTitleBlurCommit}
              handleBodyChange={handleBodyChange}
              handleTagsChange={handleTagsChange}
              handleTrackersChange={handleTrackersChange}
              handleCloseEditor={handleCloseEditor}
              handleHistory={handleHistory}
              handleToggleStar={handleToggleStar}
              handleTrash={handleTrash}
              handleRestore={handleRestore}
              handleDuplicate={handleDuplicate}
              handleSetLocked={handleSetLocked}
              handleSetPinProtected={handleSetPinProtected}
              handleBurnShare={handleBurnShare}
              showShareMenu={showShareMenu}
              setShowShareMenu={setShowShareMenu}
              exportSingleMarkdown={exportSingleMarkdown}
              exportSingleHtml={exportSingleHtml}
              printNote={printNote}
              showNoteOptions={showNoteOptions}
              setShowNoteOptions={setShowNoteOptions}
              setSelectedId={setSelectedId}
              setDeleteConfirm={setDeleteConfirm}
              onRequestRemoveProtection={(id) => void requestRemoveProtection(id)}
              removeProtectionFor={removeProtectionFor}
              setRemoveProtectionFor={setRemoveProtectionFor}
              setHistoryForNoteId={setHistoryForNoteId}
              setShowUpgrade={setShowUpgrade}
              setShowSecurity={setShowSecurity}
              onPinUnlocked={markUnlocked}
              setFolderPicker={setFolderPicker}
            />
          )}
        </main>
      </div>

      {/* Full footer (md+): Settings + Sync in a sidebar-width left zone
          (lg+ only - the sidebar doesn't exist below lg, so the md band
          shows Settings + Sync inline instead), hotkey hint + stats +
          controls on the right. The left zone matches the sidebar width
          (the --pn-sidebar-w clamp expanded, w-[52px] collapsed) so the
          vertical border aligns with the sidebar edge even after a resize. Visible at md+ AND above the short tier
          (>500px height) - short viewports swap to the mini footer below,
          crushed (<=320px) hides both.
          Density ladder within md+, lowest priority dies first (priority:
          settings > sync > zen > theme > sign out > shortcut > stats):
          below wide (1400) the spelled-out hotkey hint goes; below xl the
          controls go icon-only (HoverLabels carry the words), the hotkey
          chips merge into one, and the stats drop their unit words; below
          lg the stats go entirely.
          Spec: ops/docs/ui-patterns.md section 40 (canonical breakpoints) */}
      {footerVisible && (
        <FullFooter
          zenMode={zenMode}
          setZenMode={setZenMode}
          zenUnlocked={zenUnlocked}
          sidebarCollapsed={sidebarCollapsed}
          gridMode={gridMode}
          selected={selected}
          openSyncVerify={openSyncVerify}
          footerStats={footerStats}
          auth={auth}
          setShowSettings={setShowSettings}
          setShowStats={setShowStats}
          setShowAbout={setShowAbout}
          setShowAppearance={setShowAppearance}
          setShowUpgrade={setShowUpgrade}
          handleSignOutClick={handleSignOutClick}
        />
      )}

      {/* Mini footer: settings, sync, zen - hidden when any on-screen
          keyboard is up to reclaim vertical space. Phone safe-area bottom
          padding applies below md only; md+ (short desktop windows) gets
          regular padding + the stats readout for density.
          Shows everywhere the full footer doesn't: below md, AND at md+
          on short viewports (<=500px height). Crushed (<=320px) hides it.
          Bottom padding is the safe-area inset with the same 6px floor as the
          top, so the bar is only as tall as its row. The old 1.5rem floor was
          added in v0.227.0 to clear the Android gesture bar; v0.234.1 then made
          MainActivity pad the decor view and CONSUME the insets, so the webview
          no longer draws under the system bars and env() reads 0 there - the
          floor became 24px of dead space on Android (GitHub #205). iOS still
          reports a real inset and still clears the home indicator.
          Spec: ops/docs/ui-patterns.md section 40 (canonical breakpoints) */}
      {footerVisible && (
        <MiniFooter
          zenMode={zenMode}
          setZenMode={setZenMode}
          zenUnlocked={zenUnlocked}
          selected={selected}
          openSyncVerify={openSyncVerify}
          footerStats={footerStats}
          auth={auth}
          setShowSettings={setShowSettings}
          setShowStats={setShowStats}
          setShowAppearance={setShowAppearance}
          setShowUpgrade={setShowUpgrade}
        />
      )}

      {/* Mobile drawer - contains tags rail only (notes list is native md+).
          MobileDrawer owns the slide animation, Escape, backdrop tap, and
          swipe-left-to-close; edge-swipe-to-open is wired above. */}
      <MobileDrawer open={drawerOpen} onClose={() => setDrawerOpen(false)}>
        {tagsRail}
      </MobileDrawer>

      <ContextMenu state={ctxMenu.state} onClose={ctxMenu.close} />
      {/* Live width readout while dragging a pane strip; positioned and
          filled imperatively by usePaneResize so drags never re-render. */}
      <div ref={dragBadgeRef} className="pn-drag-badge" aria-hidden="true" />

      {showSettings && (
        <SettingsShell
          onClose={() => setShowSettings(false)}
          initialCategory={settingsCategory}
          defaultCategory="stats"
          footer={
            <button
              type="button"
              onClick={() => { setShowSettings(false); handleSignOutClick(); }}
              className="w-full rounded-md border border-neutral-300 dark:border-neutral-800 hover:bg-surface-1 px-4 py-2 text-sm transition text-neutral-600 dark:text-neutral-400 inline-flex items-center justify-center gap-1.5"
            >
              {iconSignOut()}
              {t('footer.signOut')}
            </button>
          }
          categories={buildSettingsCategories({
            t,
            notes,
            userSettings,
            mutateSettings,
            onEditorModeChange: handleEditorModeChange,
            onToggleHiddenView: handleToggleHiddenView,
            auth,
            settingsAutoVerify,
            setShowSettings,
            setShowUpgrade,
            setImportToast,
            handleSignOutClick,
            mergeImportedFolders,
            exportAllMarkdownZip,
            exportAllHtmlZip,
            exportAllJson,
            exportEncryptedBackup,
            exportEncryptedFullBackup,
            decryptFullBackup,
            exportVault,
            exportBookmarks,
            importEncryptedBackup,
            imageStoreRef,
            attachmentStoreRef,
            refresh,
            runSync,
            saveWeekReflection,
          })}
        />
      )}

      {showStats && (
        <StatsModal
          notes={notes}
          // Deleted medications included on purpose: their log entries
          // already count toward adherence, and without the template
          // nothing can resolve the id back into a name.
          medications={userSettings.medications}
          isPro={auth.isPro}
          onOpenUpgrade={() => { setShowStats(false); setShowUpgrade({ trigger: null }); }}
          onClose={() => setShowStats(false)}
          weekReflection={(() => {
            const entry = notes.find((n) => n.deleted === 0 && n.trashed === 0 && n.type === 'journal' && isWeekJournal(n));
            const trackers = entry?.trackers as Record<string, unknown> | undefined;
            return (trackers?.weekReflection as string) ?? '';
          })()}
          onWeekReflectionChange={(text) => void saveWeekReflection(text)}
        />
      )}
      {showAbout && (
        <AboutModal onClose={() => setShowAbout(false)} initialTab={showAbout.tab} />
      )}
      {showFeedback && (
        <FeedbackModal onClose={() => setShowFeedback(false)} />
      )}
      {showRate && (
        <RateModal
          onClose={() => setShowRate(false)}
          // They went and did it - the app never asks again, on any device.
          onRated={() => mutateSettings((prev) => ({ ...prev, ratingDone: true }))}
        />
      )}
      {exportProgress && (
        <ExportProgressModal
          status={exportProgress.status}
          done={exportProgress.done}
          error={exportProgress.error}
          onClose={() => setExportProgress(null)}
        />
      )}
      {uploadEntries && (
        <UploadProgressModal
          entries={uploadEntries}
          isPro={auth.isPro ?? false}
          hasStorageSub={(viewQuota?.maxTotalBytes ?? 0) > 500 * 1000 * 1000}
          onOpenUpgrade={() => { setUploadEntries(null); setShowUpgrade({ trigger: 'fileSize' }); }}
          onManageStorage={() => { setUploadEntries(null); setSettingsCategory('storage'); setShowSettings(true); }}
          onClose={() => setUploadEntries(null)}
        />
      )}
      {pendingImportableFiles && (() => {
        // Snapshot files so the closure is stable even if state resets.
        const files = pendingImportableFiles;
        return (
          <ConfirmModal
            title={t('importStore.title')}
            confirmLabel={t('importStore.confirm')}
            cancelLabel={t('importStore.cancel')}
            variant="info"
            onConfirm={() => void handleImportFromFiles(files)}
            onCancel={() => void handleAttachFromFiles(files)}
            onClose={() => setPendingImportableFiles(null)}
          >
            {files.length === 1
              ? <Trans i18nKey="notes:importStore.bodySingle" values={{ filename: files[0]!.name }} components={{ strong: <strong /> }} />
              : t('importStore.bodyMulti', { count: files.length })
            }
          </ConfirmModal>
        );
      })()}
      {showSyncOptions && (
        <SyncOptionsModal
          onClose={() => setShowSyncOptions(false)}
          onSyncNow={runSync}
          onOpenUpgrade={() => {
            setShowSyncOptions(false);
            setShowUpgrade({ trigger: null });
          }}
          onSignOut={handleSignOutClick}
        />
      )}
      {showAppearance && (
        <AppearanceSheet
          isPro={auth.isPro ?? false}
          viewMode={userSettings.viewMode}
          onViewModeChange={(m) => mutateSettings((prev) => ({ ...prev, viewMode: m }))}
          editorMode={userSettings.editorMode}
          onEditorModeChange={handleEditorModeChange}
          hiddenViews={userSettings.hiddenViews}
          hiddenInAll={userSettings.hiddenInAll}
          onToggleHidden={handleToggleHiddenView}
          onOpenUpgrade={() => {
            setShowAppearance(false);
            setShowUpgrade({ trigger: 'theme' });
          }}
          onClose={() => setShowAppearance(false)}
        />
      )}
      {showSecurity && (
        <SecurityModal
          phrase={auth.phrase}
          defaultTab={showSecurity.tab}
          reason={showSecurity.reason}
          pinTimeoutMinutes={userSettings.pinTimeoutMinutes}
          onPinTimeoutChange={(minutes) => {
            mutateSettings((prev) => ({ ...prev, pinTimeoutMinutes: minutes }));
          }}
          userSettings={userSettings}
          onSettingsChange={(next) => {
            mutateSettings(() => next);
          }}
          onClose={() => setShowSecurity(null)}
          pubkey={auth.pubkey}
        />
      )}
      {showUpgrade && (
        <UpgradeModal
          trigger={showUpgrade.trigger}
          pubkey={auth.pubkey}
          onCheckoutComplete={refreshProStatus}
          onClose={() => {
            // If we were teasing zen mode behind the modal, revert it
            // (unless they just upgraded and are now pro).
            if (showUpgrade.trigger === 'zen' && !auth.isPro) setZenMode(false);
            // If a pro theme was being previewed, revert to default.
            if (showUpgrade.trigger === 'theme' && !proUnlocked(auth.isPro) && !FREE_THEMES.has(colorTheme)) {
              setColorTheme('default');
            }
            setShowUpgrade(null);
          }}
        />
      )}
      {historyForNoteId && (
        <NoteHistoryModal
          noteId={historyForNoteId}
          supabase={supabase}
          encryptionKey={auth.encryptionKey}
          onClose={() => setHistoryForNoteId(null)}
          onRestore={async (v) => {
            // Force-snapshot the current (pre-restore) state BEFORE
            // overwriting. We bypass the usual 60s rate limit on
            // purpose: if the user had unsnapshotted in-flight edits
            // (typed within the last 60s), a plain
            // scheduleVersionSnapshot call below would be rate-
            // limited and lose those edits permanently.
            const current = await getNote(historyForNoteId);
            if (current && proUnlocked(auth.isPro)) {
              const h = await contentHash(current);
              // Only snapshot if the current state differs from the
              // most recent version we've already recorded in this
              // session - avoids duplicating a version that's
              // already on the server.
              if (lastVersionHashRef.current.get(historyForNoteId) !== h) {
                lastVersionHashRef.current.set(historyForNoteId, h);
                lastVersionAtRef.current.set(historyForNoteId, Date.now());
                await createNoteVersion(
                  supabase,
                  auth.pubkey,
                  auth.encryptionKey,
                  current
                );
              }
            }

            // Apply the version's content to the live note.
            const now = new Date().toISOString();
            patchLocal(
              historyForNoteId,
              { title: v.title, body: v.body, tags: v.tags },
              now
            );
            await updateNote(historyForNoteId, {
              title: v.title,
              body: v.body,
              tags: v.tags,
            });
            // Remount the open editor so TipTap re-parses the restored
            // body. Without this the live note's data updates but the
            // editor keeps showing the pre-restore content until the user
            // switches to another note and back. Same key-bump pattern as
            // the task quick-add and convert-to-task paths. Clear any
            // buffered in-flight body first so flushEditingBody can't
            // clobber the restored text on the next flush.
            if (selectedId === historyForNoteId) {
              editingBodyRef.current.delete(historyForNoteId);
              setEditorRevision((r) => r + 1);
            }
            scheduleSync();
          }}
        />
      )}
      {donationReason && (
        <DonationModal
          reason={donationReason}
          onClose={() => setDonationReason(null)}
        />
      )}
      {pendingProtectedAction && (
        <PinGateModal
          onUnlock={() => {
            const action = pendingProtectedAction;
            setPendingProtectedAction(null);
            void action();
          }}
          onCancel={() => setPendingProtectedAction(null)}
        />
      )}
      {showEmptyTrashModal && (
        <EmptyTrashModal
          noteCount={trashedNotes.length}
          onConfirm={() => void confirmEmptyTrash()}
          onClose={() => setShowEmptyTrashModal(false)}
        />
      )}
      {deleteConfirm && (
        <DeleteNoteModal
          noteTitle={deleteConfirm.title}
          onConfirm={() => void handlePermanentlyDelete(deleteConfirm.id)}
          onClose={() => setDeleteConfirm(null)}
        />
      )}
      {folderPicker && (
        <FolderPicker
          folders={userSettings.folders}
          mode={folderPicker.mode}
          currentFolderId={folderPicker.mode === 'note' ? folderPicker.currentFolderId : undefined}
          movingFolderId={folderPicker.mode === 'folder' ? folderPicker.folderId : undefined}
          counts={folderCounts}
          sortField={folderSortField}
          sortDir={folderSortDir}
          onPick={(target) => {
            const p = folderPicker;
            setFolderPicker(null);
            if (p.mode === 'note') void handleMoveNotesToFolder(p.noteIds, target);
            else handleMoveFolder(p.folderId, target);
          }}
          onCreateFolder={(name, parentId) => handleCreateFolder(name, parentId)}
          onRenameFolder={handleRenameFolder}
          onReorderFolders={(id, parentId, orderedIds) => {
            handleReorderFolders(id, parentId, orderedIds);
            // The drop only survives if this device stops overruling it.
            setFolderSortField('custom');
          }}
          onClose={() => setFolderPicker(null)}
        />
      )}
      {folderDeleteConfirm && (() => {
        const target = userSettings.folders.find((f) => f.id === folderDeleteConfirm.id);
        const parent = target?.parentId
          ? userSettings.folders.find((f) => f.id === target.parentId)
          : undefined;
        return (
          <ConfirmModal
            title={t('shell:folders.deleteConfirmTitle')}
            confirmLabel={t('shell:folders.delete')}
            variant="danger"
            onConfirm={() => {
              const id = folderDeleteConfirm.id;
              setFolderDeleteConfirm(null);
              void handleDeleteFolder(id);
            }}
            onClose={() => setFolderDeleteConfirm(null)}
          >
            {parent
              ? t('shell:folders.deleteConfirmBodyNested', { folder: folderDeleteConfirm.name, parent: parent.name })
              : t('shell:folders.deleteConfirmBodyRoot', { folder: folderDeleteConfirm.name })}
          </ConfirmModal>
        );
      })()}
      {bulkTrashPending && (
        <ConfirmModal
          title={t('bulkTrash.title')}
          confirmLabel={t('bulkTrash.title')}
          variant="warning"
          onConfirm={() => void executeBulkTrash()}
          onClose={dismissBulkTrash}
        >
          <Trans
            i18nKey="notes:bulkTrash.body"
            count={bulkTrashPending.length}
            values={{ count: bulkTrashPending.length }}
            components={{ highlight: <span className="font-medium text-pn" /> }}
          />
        </ConfirmModal>
      )}
      {bulkDeletePending && (
        <ConfirmModal
          title={t('editor.deleteForever')}
          confirmLabel={t('editor.deleteForever')}
          variant="danger"
          onConfirm={() => void executeBulkDelete()}
          onClose={dismissBulkDelete}
        >
          <Trans
            i18nKey="notes:bulkDelete.body"
            count={bulkDeletePending.length}
            values={{ count: bulkDeletePending.length }}
            components={{ highlight: <span className="font-medium text-pn" /> }}
          />
        </ConfirmModal>
      )}
      {tagConfirm && (
        <ConfirmModal
          title={
            tagConfirm.type === 'merge' ? t('tagConfirm.mergeTitle')
            : tagConfirm.type === 'delete' ? t('tagConfirm.deleteTitle')
            : t('tagConfirm.deleteWithNotesTitle')
          }
          confirmLabel={
            tagConfirm.type === 'merge' ? t('tagConfirm.mergeConfirm')
            : tagConfirm.type === 'delete' ? t('tagConfirm.deleteConfirm')
            : t('tagConfirm.moveToTrash')
          }
          variant={tagConfirm.type === 'delete-with-notes' ? 'danger' : 'warning'}
          onConfirm={tagConfirm.onConfirm}
          onClose={() => setTagConfirm(null)}
        >
          {tagConfirm.type === 'merge' && (
            <Trans
              i18nKey="notes:tagConfirm.mergeBody"
              count={tagConfirm.count}
              values={{ targetTag: tagConfirm.targetTag, tag: tagConfirm.tag, count: tagConfirm.count }}
              components={{ highlight: <span className="font-medium text-pn" /> }}
            />
          )}
          {tagConfirm.type === 'delete' && (
            <Trans
              i18nKey="notes:tagConfirm.deleteBody"
              count={tagConfirm.count}
              values={{ tag: tagConfirm.tag, count: tagConfirm.count }}
              components={{ highlight: <span className="font-medium text-pn" /> }}
            />
          )}
          {tagConfirm.type === 'delete-with-notes' && (
            <Trans
              i18nKey="notes:tagConfirm.deleteWithNotesBody"
              count={tagConfirm.count}
              values={{ tag: tagConfirm.tag, count: tagConfirm.count }}
              components={{ highlight: <span className="font-medium text-pn" /> }}
            />
          )}
        </ConfirmModal>
      )}
      {wikiLinkCreatePending !== null && (
        <ConfirmModal
          title={t('createNote.title')}
          confirmLabel={t('createNote.confirm')}
          variant="info"
          onConfirm={() => void createNoteFromWikiLink(wikiLinkCreatePending)}
          onClose={() => setWikiLinkCreatePending(null)}
        >
          <Trans
            i18nKey="notes:createNote.body"
            values={{ title: wikiLinkCreatePending }}
            components={{ highlight: <span className="font-medium text-pn" /> }}
          />
        </ConfirmModal>
      )}
      {toast && (
        <MilestoneToast milestone={toast} onDismiss={() => setToast(null)} />
      )}
      {markdownExplain && <MarkdownExplainer onClose={() => setMarkdownExplain(false)} />}
      {markdownDelete && (
        <ConfirmModal
          title={t('shell:markdown.deleteTitle')}
          confirmLabel={t('shell:markdown.deleteConfirm')}
          onConfirm={() => void handleMarkdownDelete(markdownDelete)}
          onClose={() => setMarkdownDelete(null)}
        >
          {t('shell:markdown.deleteBody', { name: markdownDelete.adapted.title })}
        </ConfirmModal>
      )}
      {markdownDeleteMany && (
        <ConfirmModal
          title={t('shell:markdown.deleteManyTitle', { count: markdownDeleteMany.length })}
          confirmLabel={t('shell:markdown.deleteConfirm')}
          onConfirm={() => void handleMarkdownDeleteMany(markdownDeleteMany)}
          onClose={() => setMarkdownDeleteMany(null)}
        >
          {t('shell:markdown.deleteManyBody')}
        </ConfirmModal>
      )}
      {freshVaultNotice && (
        <ConfirmModal
          title={t('freshVault.title')}
          confirmLabel={t('freshVault.confirm')}
          cancelLabel={null}
          variant="info"
          onConfirm={() => setFreshVaultNotice(false)}
          onClose={() => setFreshVaultNotice(false)}
        >
          {t('freshVault.body')}
        </ConfirmModal>
      )}
      {importExportModal.open && (
        <ImportModal
          onClose={() => setImportExportModal({ open: false })}
          initialTab={importExportModal.tab}
          notes={notes}
          onImportFolders={mergeImportedFolders}
          onExportAllMdZip={(ns) => void exportAllMarkdownZip(ns)}
          onExportAllHtmlZip={(ns) => void exportAllHtmlZip(ns)}
          onExportAllJson={exportAllJson}
          onExportEncrypted={exportEncryptedBackup}
          onExportEncryptedZip={(ns) => void exportEncryptedFullBackup(ns)}
          decryptFullBackup={decryptFullBackup}
          onExportVault={exportVault}
          onExportBookmarks={exportBookmarks}
          onImportEncrypted={importEncryptedBackup}
          onBlobsRestored={handleBlobsRestored}
          onImported={async (count, skippedDuplicates) => {
            setImportToast(
              skippedDuplicates
                ? `${t('toast.importedSyncing', { count })} ${t('shell:bookmarks.importSkipped', { count: skippedDuplicates })}`
                : t('toast.importedSyncing', { count })
            );
            // Mission accomplished - kill the sidenav hint so it doesn't
            // keep nagging a user who already used the import feature.
            mutateSettings((prev) =>
              prev.importHintDismissed ? prev : { ...prev, importHintDismissed: true }
            );
            await refresh();
            void runSync();
            // Clear the toast after a few seconds - the sync success is
            // already communicated by the header's "Synced" indicator.
            window.setTimeout(() => setImportToast(null), 4000);
          }}
        />
      )}
      {importToast && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 bg-accent text-white text-[15px] font-medium px-4 py-2 rounded-full shadow-lg">
          {importToast}
        </div>
      )}
      {burnError && (
        <div className="fixed bottom-6 left-1/2 -translate-x-1/2 z-50 bg-orange-500 text-white text-[15px] font-medium px-4 py-2 rounded-full shadow-lg flex items-center gap-2">
          <Fire size={16} />
          {burnError}
        </div>
      )}
      {burnShareUrl && (
        <BurnShareModal
          url={burnShareUrl}
          copied={burnCopied}
          imagesStripped={burnImagesStripped}
          onCopy={() => void handleBurnCopy()}
          onClose={() => setBurnShareUrl(null)}
        />
      )}
      {conflictQueue.length > 0 && conflictQueue[0] != null && (
        <ConflictModal
          conflict={conflictQueue[0]}
          onResolve={(resolution) => void resolveConflict(conflictQueue[0]!, resolution)}
          onClose={() => {
            // Dismiss = server wins (safest default - server has the newer timestamp).
            void resolveConflict(conflictQueue[0]!, 'server');
          }}
        />
      )}
      {/* Hidden while the confirm or Security is open so the phrase
          escape hatch is actually visible - this modal sits at z-[70],
          above both. It returns when they close. */}
      {(sessionExpired || revalidationExpired) && !showSignOutConfirm && !showSecurity && (
        <SessionExpiredModal
          onSignOut={() => {
            // Never wipe blind. This sign-out is forced by the server,
            // not chosen, so the phrase-backup guard runs even for
            // users who ticked "don't remind me again" on a voluntary
            // sign-out - they consented to skipping a reminder they
            // asked for, not to losing a vault they did not. #121
            setSignOutDontRemind(false);
            // Fill in the unsynced-notes warning; the count lands a
            // beat after the modal opens, which is fine.
            void countUnsyncedNotes().then(setUnsyncedCount);
            setShowSignOutConfirm(true);
          }}
        />
      )}
      {signingOut && (
        <div className="fixed inset-0 z-[100] flex items-center justify-center bg-surface-0">
          <TypewriterLine text={t('footer.signingOut')} />
        </div>
      )}
      {showSignOutConfirm && (
        <SignOutConfirmModal
          dontRemind={signOutDontRemind}
          onDontRemindChange={setSignOutDontRemind}
          unsyncedCount={unsyncedCount}
          unsyncedKept={sessionExpired || revalidationExpired}
          onShowPhrase={() => {
            // "Don't remind me again" is intentionally NOT honoured on
            // this path - the user explicitly asked to see the phrase,
            // not to suppress the reminder.
            setShowSignOutConfirm(false);
            setShowSecurity({ tab: 'phrase' });
          }}
          onConfirmSignOut={() => void confirmSignOut()}
        />
      )}
    </div>
  );
}

