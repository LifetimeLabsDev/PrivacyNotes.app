import type { Space } from '../spaces';
import type { TrackerSetupTab } from '../TrackerConfig';
import type { SpaceMove } from '../NoteOptionsMenu';
import { useCallback, useContext, useDeferredValue, useEffect, useLayoutEffect, useMemo, useRef, useState } from 'react';
import type { UpgradeTrigger } from '../UpgradeModal';
import type { Dispatch, ReactNode, RefObject, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowUUpLeft as Undo2Icon, ArrowUUpRight as Redo2Icon, X, ArrowLeft, ArrowCounterClockwise, Trash, DotsThreeOutlineVertical, CaretLeft, CaretRight, PencilSimpleSlash, MarkdownLogo, TextAa, ArticleMedium, Paragraph, MagnifyingGlass, FrameCorners, ArrowCircleUp, ArrowCircleDown, CalendarDots, CalendarPlus } from '../icons';
import type { AuthState } from '../auth';
import { captureAnchor, followAnchor, type ViewAnchor } from '../viewSwitchAnchor';
import { noteAnchor, rememberNoteAnchor } from './listPlace';
import type { LocalNote } from '../db';
import { updateNote } from '../notesRepo';
import { Editor, type EditorHandle } from '../Editor';
import { FormatBarContext } from '../formatBarContext';
import { MarkdownSourceEditor, type MarkdownSourceHandle } from '../MarkdownSourceEditor';
import { TagInput, type TagInputHandle } from '../TagInput';
import { withCredentialChanges, type UserSettings } from '../userSettings';
import { NoteOptionsMenu, type NoteColorInfo, type NoteOptionsView } from '../NoteOptionsMenu';
import { EventCard, type ScheduleRow } from '../EventCard';
import { convertPatch, type ConvertTarget } from '../noteTypes';
import type { NoteOwnColor } from '../itemStyles';
import { ProtectedNoteGate } from '../ProtectedNoteGate';
import { parseLinkBody, linkDomain } from '../linkBody';
import { BookmarkItem, type BookmarkClip } from '../BookmarkItem';
import { ContactItem } from '../ContactItem';
import { HoverLabel } from '../HoverLabel';
import type { NoteJump } from './AppFooter';
import { EditorSlotPill } from '../EditorSlotPill';
import { useTheme, type ContentWidth } from '../theme';
import { TITLE_MAX_LENGTH, newEditorKey } from '../useNoteEditing';
import { proUnlocked } from '../demo';
import { usePushFailure } from '../pushFailures';
import { VaultItem } from '../VaultItem';
import { entryDayOf, hasStructuredBody, isKnownNoteType, isWeekJournal, noteLinkName, shareSurface, toLocalIso } from '../notesViewUtils';
import { buildLinkIndex } from '../connectionsIndex';
import { ConnectionsPill } from '../ConnectionsPill';
import { scheduleOf } from '../schedule';
import { formatDay } from '../intlFormat';
import { timeLabel } from '../JournalCalendar';
import { typeGlyph } from '../NoteRow';
import type { View } from '../views';
import { WordCount } from '../WordCount';
import { storedNoteBytes } from '../sync';
import { TrackerPills } from '../TrackerPills';
import { APP_KEYS, keyText, matchesKey } from '../shortcutMatch';
import { editorCommands, registerEditorCommand } from '../editorCommands';
import type { JournalTrackerData } from '../trackerTypes';
import { ShareMenu } from './ShareMenu';
import { NoteQuickActions, HeaderDivider, type QuickActionsTier } from './NoteQuickActions';
import type { NoteActionGuardDeps } from '../noteActionGuards';
import { WeekInReview } from './WeekInReview';
import { isImeComposing } from '../imeComposing';
import type { JournalDays } from '../notesViewUtils';
import type { ScheduleEdit } from '../schedule';

type Authed = Extract<AuthState, { status: 'authenticated' }>;

/**
 * The one box every button in the editor header wears: a 32px square with
 * an 18px glyph. Row 1 (note actions), row 2 (the tag row's controls) and
 * the formatting toolbar all use this size, so the three rows read as one
 * instrument rather than three. Colour is left to mean state - accent for
 * on, amber for burn, red for destructive - and grouping is carried by the
 * hairline in `HeaderDivider`, never by a filled container.
 * Spec: ops/docs/archive/ui-patterns.md (section 80)
 */
const HEADER_BTN_BASE =
  'shrink-0 flex items-center justify-center h-8 rounded-md transition disabled:opacity-30 disabled:cursor-not-allowed';
const HEADER_BTN_REST =
  'text-pn-soft enabled:active:scale-95 enabled:[@media(hover:hover)]:hover:text-accent enabled:[@media(hover:hover)]:hover:bg-pn/10';
const HEADER_BTN = `${HEADER_BTN_BASE} w-8 ${HEADER_BTN_REST}`;
/**
 * The same button, 24px wide instead of 32. For a PAIR that reads as one
 * control - previous and next - where two full squares plus the gap between
 * them cost more room than the pair is worth, and the title pays for it.
 * The 32px height keeps the touch target.
 */
const HEADER_BTN_NARROW = `${HEADER_BTN_BASE} w-6 ${HEADER_BTN_REST}`;
/** Glyph size for every icon in the editor header. */
const HEADER_ICON = 18;
/**
 * The same 32px square, in zen's clothes. Zen strips the page down to the
 * note, so the few controls left have to look like controls: borderless
 * among bordered reads as a stray glyph, and every one of them matches the
 * Exit Zen button beside it. `ZEN_BTN_ON` is the pressed state for the
 * toggles that have one.
 */
const ZEN_BTN_BOX =
  'shrink-0 inline-flex h-8 w-8 items-center justify-center rounded-md border transition';
const ZEN_BTN_REST = `${ZEN_BTN_BOX} border-divider bg-surface-2 text-pn-soft hover:text-accent hover:border-accent/50`;
const ZEN_BTN_ON = `${ZEN_BTN_BOX} border-accent/50 bg-accent/10 text-accent-strong`;

/**
 * Cycles the editor's reading column: default, wide, full. The cap itself
 * lives in one place (`.pn-content-col` in index.css); this only steps the
 * `data-content-width` attribute the CSS reads.
 * Spec: ops/docs/design-decisions.md (editor content column max-width)
 */
/**
 * The reading-width cycle, and zen is its only home in the editor: zen
 * strips the page down and takes the settings sheet away with it, so the one
 * taste that changes how the stripped page reads has to stay reachable.
 * Everywhere else Settings > Editor carries the same axis, at every
 * width, which the tag-row copy never did - it needed a pane past 56rem to
 * appear at all. It wears zen's bordered box, like its two neighbours.
 */
function ContentWidthButton({
  contentWidth,
  onCycle,
}: {
  contentWidth: ContentWidth;
  onCycle: () => void;
}) {
  const { t } = useTranslation('notes');
  // The tip names what the click DOES, like the markdown toggle beside it,
  // so it reads as an action rather than a status readout.
  const nextLabel =
    contentWidth === 'default'
      ? t('editor.widthWide')
      : contentWidth === 'wide'
        ? t('editor.widthFull')
        : t('editor.widthDefault');
  const on = contentWidth !== 'default';
  return (
    <HoverLabel label={nextLabel} position="below-end">
      <button
        type="button"
        onMouseDown={(e) => e.preventDefault()}
        onClick={onCycle}
        aria-label={nextLabel}
        className={on ? ZEN_BTN_ON : ZEN_BTN_REST}
      >
        <FrameCorners size={HEADER_ICON} aria-hidden="true" />
      </button>
    </HoverLabel>
  );
}

/** Where the pane sits: phone or desktop, grid, footer. */
interface NoteEditorLayout {
  gridMode: boolean;
  isMobile: boolean;
  mobileTabIndex: number | undefined;
  mobileEditing: boolean;
  footerVisible: boolean;
  /** The on-screen keyboard is up on a phone. */
  keyboardUp: boolean;
  /** The jump a long note offers (see NoteJump); drawn here on screens with
   *  the desktop footer, in the phone bar elsewhere. */
  noteJump?: NoteJump;
}

/** Zen mode and the formatting toolbar it shows on demand. */
interface NoteEditorZen {
  zenMode: boolean;
  setZenMode: Dispatch<SetStateAction<boolean>>;
  zenToolbar: boolean;
  setZenToolbar: Dispatch<SetStateAction<boolean>>;
}

/** How much of the header row fits, and the previous/next arrows. */
interface NoteEditorHeaderNav {
  /** How many quick-action groups the header row fits. Measured in NotesView. */
  quickActionsTier: QuickActionsTier;
  /** The header row is phone-narrow: previous/next and share leave it, and
   *  share moves into the "..." menu. Measured in NotesView. */
  headerCompact: boolean;
  /** Previous/next note in the list (GitHub #246). Hidden on a compact header. */
  /** The arrows step through the open tabs rather than the list. */
  navTabs: boolean;
  canGoPrev: boolean;
  canGoNext: boolean;
  onNavigateList: (direction: 'prev' | 'next') => void;
}

/** The elements NotesView measures and focuses. */
interface NoteEditorPaneRefs {
  titleInputRef: RefObject<HTMLTextAreaElement | null>;
  tagInputRef: RefObject<TagInputHandle | null>;
  editorRef: RefObject<EditorHandle | null>;
  /** Callback ref for the header row. NotesView measures it to pick which
   *  icon groups fit; a callback cannot go stale across a remount. */
  setHeaderRow: (node: HTMLDivElement | null) => void;
  noteOptionsButtonRef: RefObject<HTMLButtonElement | null>;
  setStickyTagRow: (node: HTMLDivElement | null) => void;
  /** Callback ref for the editor's scroll container, so NotesView can watch
   *  the note grow past it. Same shape as setStickyTagRow above. */
  setNoteScroller: (node: HTMLDivElement | null) => void;
}

/** What an edit to the open item writes (useNoteEditing). */
interface NoteEditorEditing {
  handleTitleChange: (id: string, title: string) => Promise<void>;
  /** Focus/blur on the title field bracket a rename, so note-links into
   *  this note can follow it. See useNoteEditing.handleTitleBlur (#238). */
  handleTitleFocus: (id: string) => void;
  handleTitleBlur: (id: string) => void;
  handleBodyChange: (id: string, body: string, editorKey?: string) => Promise<void>;
  /** See useNoteEditing.registerEditorBody (#497). */
  registerEditorBody: (editorKey: string, body: string) => void;
  handleTagsChange: (id: string, tags: string[]) => Promise<void>;
  handleTrackersChange: (id: string, trackers: JournalTrackerData) => Promise<void>;
  handleVaultSave: (id: string, body: string, trackers?: Record<string, unknown>) => Promise<boolean>;
}

/** The actions of the "..." menu and the header that change the item itself. The
 *  exports, history and the lock predicate stay top-level props: the lock gate
 *  wiring test reads them off the JSX. */
interface NoteEditorMenuActions {
  /** The note menu's color row: the note's own pick and the color it takes
   *  without one. */
  noteColor: NoteColorInfo | null;
  /** Set or clear the note's own color; null takes its tag's or folder's. */
  onSetNoteColor: (noteId: string, color: NoteOwnColor | null) => void;
  /** Opens Settings at the "Folder and tag colors" row. */
  onOpenColorSettings: () => void;
  /** Opens the icon picker on a note (Pro). */
  onPickNoteIcon: (noteId: string) => void;
  handleToggleStar: (id: string, starred: boolean) => Promise<void>;
  handleToggleArchive: (id: string, archived: boolean) => Promise<void>;
  /** Move a journal entry to another day (`YYYY-MM-DD`). */
  setJournalDate: (id: string, day: string) => Promise<void>;
  /** Attach a note or a task list to a day (`YYYY-MM-DD`), or take it away (null). */
  setNoteDate: (id: string, day: string | null) => Promise<void>;
  /** The days that hold a journal entry, for the Entry date calendar. */
  journalDays: JournalDays;
  /** Trash the open note through the shared confirm modal. */
  requestTrash: (ids: string[]) => void;
  handleRestore: (id: string) => Promise<void>;
  handleDuplicate: (id: string) => Promise<void>;
  /** "Split note" beside the sync-limit line; null where a note cannot split. */
  splitNote: ((n: LocalNote) => void) | null;
  /** The editor's measure found the open note over the 1 MB sync limit. */
  onOverSyncLimit: (id: string) => void;
  /** True when the note has more than one task and at least one is checked. */
  canUncheckAllTasks: (n: LocalNote) => boolean;
  handleUncheckAllTasks: (n: LocalNote) => Promise<void>;
  canDeleteCheckedTasks: (n: LocalNote) => boolean;
  handleDeleteCheckedTasks: (n: LocalNote) => void;
  canSortTasksByStatus: (n: LocalNote) => boolean;
  handleSortTasksByStatus: (n: LocalNote) => Promise<void>;
  handleSetLocked: (id: string, locked: boolean) => Promise<void>;
  handleSetPinProtected: (id: string, pinProtected: boolean) => Promise<void>;
  onCopyShortcut: (n: LocalNote) => void;
  onCopyNoteLink: ((n: LocalNote) => void) | null;
  /** "Move to Work" or "Move to Personal" in the "..." menu, while spaces are on. */
  spaceMove?: SpaceMove;
  /** The Schedule view: the open occurrence, and the edit, which asks on a
   *  repeating event. */
  schedule: {
    occurrence: string | null;
    edit: (id: string, occurrence: string | null, edit: ScheduleEdit) => void;
    /** A calendar menu's "Schedule": opens the Schedule view on this item. */
    ask?: { id: string; n: number } | null;
  };
}

export interface NoteEditorPaneProps {
  selected: LocalNote;
  view: View;
  notes: LocalNote[];
  /** Every saved bookmark URL in the account (buildLinkKeyMap), for the
   *  bookmark body's duplicate guard. Owned by NotesView so the editor and
   *  the quick-add bar can never guard against different sets. */
  bookmarkKeys: Map<string, string>;
  /** Save as note for the open bookmark (useClipper). */
  bookmarkClip: (bookmark: LocalNote) => BookmarkClip;
  auth: Authed;
  /** Opens Settings › Wellness, the one tracker setup. */
  onOpenTrackerSettings: (tab: TrackerSetupTab) => void;

  spellcheck: boolean;
  invisibles: boolean;
  setInvisibles: (next: boolean) => void;
  toolbarVisible: boolean;
  toggleToolbar: () => void;
  selectedEditorMode: 'formatted' | 'markdown';
  setEditorModeOverrides: Dispatch<SetStateAction<Record<string, 'formatted' | 'markdown'>>>;
  /** Push buffered body edits into React state. The mode toggle must call
   *  this before it swaps editors - the replacement mounts from
   *  selected.body, which body edits do not update per keystroke. */
  flushEditingBody: () => void;

  titleFocused: boolean;
  setTitleFocused: Dispatch<SetStateAction<boolean>>;
  setEditorFocused: Dispatch<SetStateAction<boolean>>;
  titleLongPress: {
    start: (el: HTMLElement | null | undefined, touch?: { clientX: number; clientY: number }) => void;
    cancel: () => void;
  };

  /** True once the open note runs past its scroller. Drives the find pill,
   *  and nothing else. */
  bodyOverflows: boolean;

  editorRevision: number;
  wcBody: string;
  setWcBody: Dispatch<SetStateAction<string>>;

  userSettings: UserSettings;
  mutateSettings: (updater: (prev: UserSettings) => UserSettings) => void;

  tagCounts: { tags: [string, number][]; untagged: number };
  isNoteLocked: (n: LocalNote) => boolean;
  folderChipFor: (note: LocalNote) => ReactNode;
  refresh: () => Promise<LocalNote[]>;
  /** Open a note in the pillar that lists it, clearing a filter that hides it. */
  onRevealNote: (note: LocalNote) => void;

  handleSelectTag: (tag: string | null) => Promise<void>;

  handleCloseEditor: () => Promise<void>;
  handleHistory: (action: 'undo' | 'redo') => void;
  handleBurnShare: (n: LocalNote) => Promise<void>;

  showShareMenu: boolean;
  setShowShareMenu: Dispatch<SetStateAction<boolean>>;
  exportSingleMarkdown: (n: LocalNote) => Promise<void> | void;
  exportSingleHtml: (n: LocalNote) => Promise<void> | void;
  printNote: (n: LocalNote, titleOnly?: boolean) => Promise<void> | void;

  showNoteOptions: boolean;
  setShowNoteOptions: Dispatch<SetStateAction<boolean>>;

  setSelectedId: Dispatch<SetStateAction<string | null>>;
  setDeleteConfirm: Dispatch<SetStateAction<{ id: string; title: string } | null>>;
  /** Ask to take a note's protection off. Owns the biometric shortcut, so the
   *  prompt is raised inside the click that asked for it. */
  onRequestRemoveProtection: (id: string) => void;
  /** The note whose gate is open purely to take its protection off, if any.
   *  Set by the two menus; cleared here when the gate is done with it. */
  removeProtectionFor: string | null;
  setRemoveProtectionFor: Dispatch<SetStateAction<string | null>>;
  /** Open a note's version history. NotesView asks for the PIN first when
   *  the note is gated, so no version is listed past the gate. */
  openHistory: (n: LocalNote) => void;
  setShowUpgrade: Dispatch<SetStateAction<null | { trigger: UpgradeTrigger }>>;
  setShowSecurity: Dispatch<SetStateAction<null | { tab: 'pin' | 'phrase' | 'biometric'; reason?: 'protect' }>>;
  onPinUnlocked: () => void;
  setFolderPicker: Dispatch<SetStateAction<
    | { mode: 'note'; noteIds: string[]; currentFolderId: string | null | undefined; space?: Space }
    | { mode: 'folder'; folderId: string }
    | null
  >>;

  layout: NoteEditorLayout;
  zen: NoteEditorZen;
  headerNav: NoteEditorHeaderNav;
  paneRefs: NoteEditorPaneRefs;
  editing: NoteEditorEditing;
  noteMenu: NoteEditorMenuActions;
}

export function NoteEditorPane(props: NoteEditorPaneProps) {
  const { t } = useTranslation('notes');
  const { position: barPosition } = useContext(FormatBarContext);
  const [barSlot, setBarSlot] = useState<HTMLDivElement | null>(null);
  /** The name the contact form's draft spells, while it is still being typed.
   *  The title field shows it in grey below, so a new contact wears its name at
   *  the top before it has a title to wear. Nothing writes it: the form buffers
   *  its draft and Cancel drops it, so a title stored from a keystroke would
   *  outlive the edit that spelled it. */
  const [contactDraftName, setContactDraftName] = useState('');
  // The last sync pass could not push this note (pushFailures.ts).
  const pushFailure = usePushFailure(props.selected.id);
  const { contentWidth, cycleContentWidth } = useTheme();
  const {
    selected,
    view,
    notes,
    bookmarkKeys,
    bookmarkClip,
    auth,
    onOpenTrackerSettings,
    spellcheck,
    invisibles,
    setInvisibles,
    toolbarVisible,
    toggleToolbar,
    selectedEditorMode,
    setEditorModeOverrides,
    flushEditingBody,
    titleFocused,
    setTitleFocused,
    setEditorFocused,
    titleLongPress,
    bodyOverflows,
    editorRevision,
    wcBody,
    setWcBody,
    userSettings,
    mutateSettings,
    tagCounts,
    isNoteLocked,
    folderChipFor,
    refresh,
    onRevealNote,
    handleSelectTag,
    handleCloseEditor,
    handleHistory,
    handleBurnShare,
    showShareMenu,
    setShowShareMenu,
    exportSingleMarkdown,
    exportSingleHtml,
    printNote,
    showNoteOptions,
    setShowNoteOptions,
    setSelectedId,
    setDeleteConfirm,
    onRequestRemoveProtection,
    removeProtectionFor,
    setRemoveProtectionFor,
    openHistory,
    setShowUpgrade,
    setShowSecurity,
    onPinUnlocked,
    setFolderPicker,
    layout: { gridMode, isMobile, mobileTabIndex, mobileEditing, footerVisible, keyboardUp, noteJump },
    zen: { zenMode, setZenMode, zenToolbar, setZenToolbar },
    headerNav: { quickActionsTier, headerCompact, navTabs, canGoPrev, canGoNext, onNavigateList },
    paneRefs: {
      titleInputRef, tagInputRef, editorRef, setHeaderRow, noteOptionsButtonRef,
      setStickyTagRow, setNoteScroller,
    },
    editing: {
      handleTitleChange, handleTitleFocus, handleTitleBlur, handleBodyChange, registerEditorBody,
      handleTagsChange, handleTrackersChange, handleVaultSave,
    },
    noteMenu: {
      noteColor, onSetNoteColor, onOpenColorSettings, onPickNoteIcon, handleToggleStar, handleToggleArchive, setJournalDate, setNoteDate,
      journalDays, requestTrash, handleRestore, handleDuplicate, splitNote, onOverSyncLimit, canUncheckAllTasks,
      handleUncheckAllTasks, canDeleteCheckedTasks, handleDeleteCheckedTasks,
      canSortTasksByStatus, handleSortTasksByStatus, handleSetLocked, handleSetPinProtected,
      onCopyShortcut, onCopyNoteLink, spaceMove, schedule,
    },
  } = props;
  // True while a menu has asked to take this note's protection off. The gate
  // does the asking, so an open note gets the same two checks as a locked one.
  const removingProtection = removeProtectionFor === selected.id;
  /** A type a newer build added. This build cannot read its body, so the item
   *  is read-only here and the body area holds a notice instead of an editor. */
  const knownType = isKnownNoteType(selected.type);
  const structuredBody = hasStructuredBody(selected.type);
  /**
   * True when the markdown editor is the thing under the header, so Zen's
   * markdown toggle has a toolbar to switch. Two states fail that test.
   * Bookmarks, contacts and vault items replace the editor with a structured
   * form, which has no toolbar at any width, and a type this build does not
   * know replaces it with a notice. A PIN-protected note replaces it with the
   * unlock gate until the user enters the PIN. In both the toggle shows and
   * switches a bar that is not on screen.
   */
  const markdownBody = !structuredBody && !isNoteLocked(selected);
  /**
   * Each markdown editor mount saves under a key of its own, and records the
   * body it mounted with, so a save from an editor whose row was rewritten
   * under it is refused (#497). A new key comes with every new mount: another
   * note, a remount, the other editor mode, or the editor coming back from
   * behind the PIN gate, the one that takes the protection off included. The
   * body is read at the mount only: later bodies reach the record through the
   * editor's own saves.
   */
  const editorShown = markdownBody && knownType && !removingProtection;
  const mountOf = `${selected.id}|${editorRevision}|${selectedEditorMode}|${editorShown}`;
  const editorMountRef = useRef<{ of: string; key: string } | null>(null);
  if (editorMountRef.current?.of !== mountOf) editorMountRef.current = { of: mountOf, key: newEditorKey(selected.id) };
  const editorKey = editorMountRef.current.key;
  useLayoutEffect(() => {
    if (editorShown) registerEditorBody(editorKey, selected.body);
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editorKey]);
  /**
   * Flip THIS note between the rich editor and the markdown source.
   *
   * Both editors are uncontrolled and mount from selected.body, but body
   * edits only reach React state on a note switch or before a sync. Flush
   * both stashes NOW, in the same event, so the batched re-render swaps the
   * editors with the current body: first the rich editor's pending debounce
   * (its unmount flush runs after the replacement already rendered), then
   * the keystroke buffer into state. Skipping this showed the last-synced
   * body, and one keystroke in the fresh editor persisted it over the real
   * one.
   *
   * Session-only and per-note: it never writes userSettings.editorMode.
   * Spec: ops/specs/editor-mode-toggle.md (a reload clears it back to the global default)
   */
  const toggleEditorMode = () => {
    editorRef.current?.flushPendingSave();
    flushEditingBody();
    viewAnchorRef.current = scrollerRef.current ? captureAnchor(scrollerRef.current) : null;
    setEditorModeOverrides((prev) => ({
      ...prev,
      [selected.id]: selectedEditorMode === 'markdown' ? 'formatted' : 'markdown',
    }));
  };
  /**
   * The markdown row shows in the "..." menu on exactly the notes whose
   * word-count link shows it: a real markdown body, not read-only, not in
   * the trash. Two entry points, one condition.
   */
  const canSwitchEditorMode = markdownBody && view !== 'trash' && selected.locked !== 1;
  // The reading position across a switch: read before the swap, put back
  // once the other view has drawn its text, and again a frame later, when
  // its height has settled. Spec: ops/issues/0493.md (Reading position)
  const scrollerRef = useRef<HTMLDivElement | null>(null);
  const viewAnchorRef = useRef<ViewAnchor | null>(null);
  const [paneEl, setPaneEl] = useState<HTMLDivElement | null>(null);
  const setScroller = useCallback((node: HTMLDivElement | null) => {
    scrollerRef.current = node;
    setNoteScroller(node);
    setPaneEl(node);
  }, [setNoteScroller]);
  useEffect(() => {
    const anchor = viewAnchorRef.current;
    const pane = scrollerRef.current;
    viewAnchorRef.current = null;
    if (!anchor || !pane) return;
    return followAnchor(pane, anchor);
  }, [selectedEditorMode]);
  // Each note opens at the line it was left at this session, on any way in:
  // a row, a tab, a view switch and back. The line is read when a scroll
  // settles, and only for the note it was read in: the swap to another note
  // scrolls the pane too. Memory only, it holds words of the text.
  // Spec: ops/docs/archive/keep-my-place.md (section 2.3)
  const placeNoteRef = useRef(selected.id);
  useEffect(() => {
    const pane = paneEl;
    const id = selected.id;
    placeNoteRef.current = id;
    if (!pane) return;
    let timer: ReturnType<typeof setTimeout> | undefined;
    let ready = false;
    const anchor = noteAnchor(id);
    const stopFollow = anchor ? followAnchor(pane, anchor) : undefined;
    // The swap's own scroll events land before this; listen from the next frame.
    const frame = requestAnimationFrame(() => { ready = true; });
    const onScroll = () => {
      if (!ready) return;
      clearTimeout(timer);
      timer = setTimeout(() => {
        if (placeNoteRef.current === id) rememberNoteAnchor(id, captureAnchor(pane));
      }, 200);
    };
    pane.addEventListener('scroll', onScroll, { passive: true });
    return () => {
      stopFollow?.();
      cancelAnimationFrame(frame);
      clearTimeout(timer);
      pane.removeEventListener('scroll', onScroll);
    };
  }, [selected.id, paneEl]);
  // Tab from the title or the tag field lands in whichever body is mounted.
  // False when none is, so the caller lets the browser's own Tab run.
  const sourceRef = useRef<MarkdownSourceHandle | null>(null);
  const focusBody = () =>
    (selectedEditorMode === 'markdown' ? sourceRef.current?.focus() : editorRef.current?.focus()) ?? false;
  // A contact, bookmark or vault item has fields instead of a body: Tab goes
  // to the first text field after the tag row, past the photo button. With
  // no field open (a vault item in view mode) the browser's own Tab runs.
  const structuredColRef = useRef<HTMLDivElement | null>(null);
  const focusFirstField = () => {
    const from = document.activeElement;
    const field = [...(structuredColRef.current?.querySelectorAll<HTMLElement>(
      'input:not([type=file]):not([type=hidden]):not([type=checkbox]):not([type=radio]):not([disabled]), textarea:not([disabled])',
    ) ?? [])].find((el) => !!from && !!(from.compareDocumentPosition(el) & Node.DOCUMENT_POSITION_FOLLOWING));
    field?.focus();
    return !!field;
  };
  // Mod+Shift+M flips the open note between the two views, wherever the focus
  // is, on the notes that offer the switch (GitHub #260).
  const markdownKeyRef = useRef<(() => void) | null>(null);
  markdownKeyRef.current = canSwitchEditorMode ? toggleEditorMode : null;
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!markdownKeyRef.current || !matchesKey(e, APP_KEYS.markdownView)) return;
      e.preventDefault();
      markdownKeyRef.current();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);
  useEffect(
    () => (canSwitchEditorMode ? registerEditorCommand('markdownView', () => markdownKeyRef.current?.()) : undefined),
    [canSwitchEditorMode],
  );
  // Typed text waits in the keystroke buffer, and its "last edited" stamp
  // with it, so the "..." menu would read both as they were. Opening the menu
  // writes the pending save and empties the buffer: Details shows the stamp
  // the row holds, and the write that lands after it brings the new one.
  useEffect(() => {
    if (!showNoteOptions) return;
    editorRef.current?.flushPendingSave();
    flushEditingBody();
  }, [showNoteOptions]); // eslint-disable-line react-hooks/exhaustive-deps
  /** Where Share sits for this note: nowhere while it is gated (shareSurface). */
  const share = shareSurface(isNoteLocked(selected), zenMode || headerCompact);
  // The view the "..." menu opens on: the header's convert button opens it
  // straight on the type list, the "..." button on the main view.
  const [optionsStartView, setOptionsStartView] = useState<NoteOptionsView>('main');
  // The Schedule row the event card asked for (Repeat, Alert, Ends).
  const [scheduleSub, setScheduleSub] = useState<'ends' | 'repeat' | 'alerts' | undefined>(undefined);
  const openScheduleAt = (row: ScheduleRow) => {
    setScheduleSub(row === 'main' ? undefined : row);
    setOptionsStartView('schedule');
    setShowNoteOptions(true);
  };
  // A calendar menu asked for the Schedule view of this item.
  useEffect(() => {
    if (!schedule.ask || schedule.ask.id !== selected?.id) return;
    setScheduleSub(undefined);
    setOptionsStartView('schedule');
    setShowNoteOptions(true);
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [schedule.ask?.n, selected?.id]);
  /**
   * Give this item another of the note-like types, then follow it to the
   * pillar that lists it. Only `type` changes, and no field is removed: a
   * journal entry that becomes a task keeps its date and tracker values, so
   * converting it back restores the entry unchanged.
   *
   * Spec: ops/docs/archive/convert-type.md
   */
  const convertNoteType = async (target: ConvertTarget) => {
    if (target === selected.type) return;
    const trackers = selected.trackers as Record<string, unknown> | undefined;
    await updateNote(selected.id, convertPatch(trackers, target, toLocalIso(new Date())));
    const fresh = (await refresh()).find((n) => n.id === selected.id);
    if (fresh) onRevealNote(fresh);
  };
  /**
   * The wiring behind the four gated per-note actions, shared by the "..."
   * menu and the header's quick-action pill so the two cannot drift. The
   * gates themselves live in noteActionGuards.ts.
   */
  const noteGuards: NoteActionGuardDeps = {
    note: selected,
    isPro: auth.isPro,
    onClose: () => setShowNoteOptions(false),
    onSetLocked: (locked) => void handleSetLocked(selected.id, locked),
    onSetPinProtected: (p) => void handleSetPinProtected(selected.id, p),
    onRequestRemoveProtection: () => {
      setShowNoteOptions(false);
      onRequestRemoveProtection(selected.id);
    },
    onOpenUpgrade: (trigger) => {
      setShowNoteOptions(false);
      setShowUpgrade({ trigger });
    },
    onOpenHistory: () => {
      setShowNoteOptions(false);
      openHistory(selected);
    },
    onSetPin: () => setShowSecurity({ tab: 'pin', reason: 'protect' }),
    onMoveToFolder: () => {
      setShowNoteOptions(false);
      setFolderPicker({ mode: 'note', noteIds: [selected.id], currentFolderId: selected.folderId ?? null });
    },
  };
  /**
   * The only control left in the editor's top-right slot, beside the
   * collapsed outline pill.
   *
   * The slot floats over the note's own text, so a control earns a place in
   * it by being able to take itself away again. The outline draws nothing on
   * a note without headings; find draws nothing on a note that fits the
   * screen, because there is nothing to scroll past and looking for a word
   * you can already see is not a thing anyone does. On a note short enough,
   * the corner is empty.
   *
   * Two controls that used to sit here have permanent homes elsewhere and
   * left. The markdown switch is the first row of the "..." menu and the
   * link under the word count. Invisible characters is a row in Settings >
   * Appearance and the toggle beside the word count. Neither could hide
   * itself, and three opaque boxes over the first line of every note is what
   * GitHub #265 reported.
   *
   * Find drives the rich editor's own search plugin through editorRef, so it
   * has nothing to act on over the markdown textarea and stays away there.
   * Spec: ops/docs/archive/ui-patterns.md (section 80)
   */
  const findPill = selectedEditorMode !== 'markdown' && bodyOverflows ? (
    <EditorSlotPill
      label={t('editor.findInNote')}
      keys={keyText('find')}
      onClick={() => editorRef.current?.toggleFind()}
      tabIndex={isMobile ? -1 : undefined}
    >
      <MagnifyingGlass size={17} />
    </EditorSlotPill>
  ) : null;

  // Which items link to which, for the Connections pill. A locked note
  // answers to its gated name, so the set of locked notes keys the memo too.
  // Spec: ops/issues/0351.md (Spec)
  const lockedKey = notes.filter(isNoteLocked).map((n) => n.id).join(' ');
  // Deferred: the scan reads every body, and a save must not wait for it.
  const deferredNotes = useDeferredValue(notes);
  const liveNotes = useMemo(() => deferredNotes.filter((n) => n.trashed === 0), [deferredNotes]);
  const linkIndex = useMemo(
    () => buildLinkIndex(liveNotes, {
      nameOf: (n) => noteLinkName(n, isNoteLocked(n)),
      isSource: (n) => !hasStructuredBody(n.type),
    }),
    // eslint-disable-next-line react-hooks/exhaustive-deps
    [liveNotes, lockedKey],
  );
  const bodyControls = findPill;
  const connections = (open: boolean, onOpenChange: (open: boolean) => void) => (
    <ConnectionsPill
      note={selected}
      notes={liveNotes}
      index={linkIndex}
      isNoteLocked={isNoteLocked}
      onOpen={onRevealNote}
      open={open}
      onOpenChange={onOpenChange}
      tabIndex={isMobile ? -1 : undefined}
    />
  );

  // With the bar at the bottom, the pane keeps a row for it under the
  // scrolling column (see Editor's toolbarSlot).
  const sourceSearch = {
    isPro: auth.isPro ?? false,
    onOpenUpgrade: (trigger: 'replace') => setShowUpgrade({ trigger }),
  };

  const barBelow = barPosition === 'bottom' && (zenMode ? zenToolbar : toolbarVisible)
    && view !== 'trash' && selected.locked !== 1;

  return (
    <>
      {/* Editor header - fixed h-14 so its bottom border lines up
          with the sidebar brand row and the notes list header across
          all three columns. The title is a single line (it truncates
          with a soft fade rather than wrapping) so the header height
          never changes and the dividers stay aligned. In Zen the
          per-note actions collapse into the "..." menu and the
          markdown-toolbar + Exit Zen toggles sit at the row's end. */}
      <div className={`flex justify-center min-h-11 sm:min-h-14 py-1.5 sm:py-0 sm:h-14 border-b border-divider shrink-0`}>
        <div
          ref={setHeaderRow}
          // min-w-0 is load-bearing twice over. A flex item defaults to
          // min-width:auto, which floors it at its own min-content width -
          // and every icon here is shrink-0, so that floor is the whole icon
          // set. The row then refused to go below ~748px inside a 618px pane:
          // it overflowed the window at both ends (it is centred), AND the
          // width NotesView measures was the row's own minimum rather than
          // the space available, so no group ever dropped. More icons made
          // the floor higher, which is the wrong way round.
          className="flex items-center gap-2 px-4 sm:px-6 pn-content-col min-w-0"
        >
        <button
          onClick={() => void handleCloseEditor()}
          aria-label={t('editor.backToList')}
          className={`${gridMode ? 'hidden' : 'md:hidden'} ${HEADER_BTN} -ms-1`}
        >
          <ArrowLeft size={HEADER_ICON} />
        </button>
        {gridMode && (
          <HoverLabel label={t('editor.backToGrid')} keys={keyText('closeTab')} position="below-start">
            <button
              onClick={() => void handleCloseEditor()}
              aria-label={t('editor.backToGrid')}
              className={`${HEADER_BTN} -ms-1`}
            >
              <X size={HEADER_ICON} />
            </button>
          </HoverLabel>
        )}
        {/* Previous and next note in the list, in the browser's own place
            and order (GitHub #246); while tabs are open, the previous and
            next tab, as a browser's arrows move within its pages. A compact header drops the pair and the
            divider after it: on a phone they cost the title more than they
            save, and the back arrow is the way to the list there. Chevrons,
            never the curved arrows the tag row uses for undo - two
            identical pairs one row apart would read as one control drawn
            twice - and never plain arrows, because the mobile back-to-list
            arrow sits right beside them. */}
        {!headerCompact && (
          <>
            <div className="shrink-0 flex items-center">
              <HoverLabel label={t(navTabs ? 'editor.navPrevTab' : 'editor.navPrev')} keys={keyText(navTabs ? 'previousTab' : 'previousInList')} position="below-start">
                <button
                  type="button"
                  tabIndex={mobileTabIndex}
                  onClick={() => onNavigateList('prev')}
                  disabled={!canGoPrev}
                  aria-label={t(navTabs ? 'editor.navPrevTab' : 'editor.navPrev')}
                  className={HEADER_BTN_NARROW}
                >
                  <CaretLeft size={HEADER_ICON} />
                </button>
              </HoverLabel>
              <HoverLabel label={t(navTabs ? 'editor.navNextTab' : 'editor.navNext')} keys={keyText(navTabs ? 'nextTab' : 'nextInList')} position="below-start">
                <button
                  type="button"
                  tabIndex={mobileTabIndex}
                  onClick={() => onNavigateList('next')}
                  disabled={!canGoNext}
                  aria-label={t(navTabs ? 'editor.navNextTab' : 'editor.navNext')}
                  className={HEADER_BTN_NARROW}
                >
                  <CaretRight size={HEADER_ICON} />
                </button>
              </HoverLabel>
            </div>
            <HeaderDivider />
          </>
        )}
        <textarea
          ref={titleInputRef}
          dir="auto"
          tabIndex={mobileTabIndex}
          value={selected.title}
          onChange={(e) => {
            // Strip newlines - title is single-concept, just visually wrapping.
            const clean = e.target.value.replace(/\n/g, '');
            handleTitleChange(selected.id, clean);
          }}
          onKeyDown={(e) => {
            if (isImeComposing(e)) return;
            // Block Enter - no newlines in titles.
            if (e.key === 'Enter') { e.preventDefault(); return; }
            // Tab from title → tag input (skipping the star/trash
            // buttons so the flow is title → tags → body).
            if (e.key === 'Tab' && !e.shiftKey) {
              if (tagInputRef.current) tagInputRef.current.focus();
              else if (!focusBody()) return;
              e.preventDefault();
            }
          }}
          onFocus={() => { setTitleFocused(true); handleTitleFocus(selected.id); }}
          onBlur={() => { setTitleFocused(false); handleTitleBlur(selected.id); }}
          onTouchStart={(e) => titleLongPress.start(titleInputRef.current, e.touches[0])}
          onTouchEnd={titleLongPress.cancel}
          onTouchMove={titleLongPress.cancel}
          onTouchCancel={titleLongPress.cancel}
          maxLength={TITLE_MAX_LENGTH}
          rows={1}
          wrap="off"
          spellCheck={spellcheck ? undefined : false}
          placeholder={
            selected.type === 'link' ? (linkDomain(parseLinkBody(selected.body).url) || t('editor.titlePlaceholderLink'))
            : selected.type === 'contact' ? (contactDraftName || t('editor.titlePlaceholderContact'))
            : selected.type === 'login' ? t('editor.titlePlaceholderLogin')
            : selected.type === 'card' ? t('editor.titlePlaceholderCard')
            : selected.type === 'ssh-key' ? t('editor.titlePlaceholderSshKey')
            : t('editor.titlePlaceholder')
          }
          disabled={view === 'trash' || selected.locked === 1 || !knownType}
          readOnly={selected.locked === 1 || !knownType}
          // Single line (wrap="off"): the header stays a fixed height so
          // the column dividers line up. A too-long title scrolls and is
          // softly faded at the right edge (not hard-clipped) as a "more
          // text" cue; the fade is dropped while editing so typing at the
          // end stays legible.
          style={
            !titleFocused
              ? {
                  maskImage:
                    'linear-gradient(to right, #000 90%, transparent)',
                  WebkitMaskImage:
                    'linear-gradient(to right, #000 90%, transparent)',
                }
              : undefined
          }
          // Placeholder inherits the title's font-size/line-height on
          // purpose: under Tailwind 4, placeholder:text-* sets BOTH
          // font-size and line-height on ::placeholder, and a smaller
          // placeholder line box top-anchors inside the title's taller
          // strut instead of centering (visibly off-center at every
          // breakpoint). Matching metrics is the only fix that holds
          // across the responsive title sizes; font-normal + muted
          // color keep it visually quiet.
          className="pn-note-title flex-1 min-w-0 bg-transparent text-base sm:text-xl lg:text-2xl font-semibold tracking-tight focus:outline-none placeholder:text-pn-muted placeholder:font-normal disabled:opacity-60 resize-none overflow-hidden leading-tight whitespace-nowrap [&::-webkit-scrollbar]:hidden"
        />
        {/* Shortcuts into the "..." menu, which keeps every one of these
            rows at every width. They appear only on a header row wide
            enough to hold them without crowding the title, in two tiers.
            Trash gets none: that view's menu carries Restore and Delete
            forever and nothing else. */}
        {view !== 'trash' && !zenMode && (
          <NoteQuickActions
            note={selected}
            isPro={auth.isPro}
            tier={quickActionsTier}
            guards={noteGuards}
            onDuplicate={() => void handleDuplicate(selected.id)}
            onConvertType={() => { setOptionsStartView('convert'); setShowNoteOptions(true); }}
          />
        )}
        {/* Burn, pin and trash are not here. All three are rare, all three
            already had a permanent row in the "..." menu, and the header was
            carrying up to thirteen icons beside a title it kept truncating.
            Share is the one that stayed, because it is the one people reach
            for. It leaves in zen and on a compact header, where the "..."
            strip carries it instead.
            Spec: ops/docs/design-decisions.md (share holds the header) */}
        {view === 'trash' ? (
          <>
            {/* Trash actions - labeled so "Restore" vs "Delete
                forever" is unambiguous. Both carry the same glyph
                and the same colour as the right-click menu on a
                trashed row and as the "..." menu beside them, so
                the three surfaces read as one action each. */}
            <HoverLabel label={t('editor.restore')} position="below">
              <button
                onClick={() => void handleRestore(selected.id)}
                aria-label={t('editor.restore')}
                className="ms-2 inline-flex items-center gap-1.5 rounded-md px-2.5 py-2 text-sm font-medium text-success hover:text-emerald-500 hover:bg-emerald-500/10 transition shrink-0"
              >
              <ArrowCounterClockwise size={18} />
              <span className="hidden sm:inline">{t('editor.restore')}</span>
              </button>
            </HoverLabel>
            <HoverLabel label={t('editor.deleteForever')} position="below">
              <button
                onClick={() => setDeleteConfirm({ id: selected.id, title: selected.title || '' })}
                aria-label={t('editor.deleteForever')}
                className="ms-1 inline-flex items-center gap-1.5 rounded-md px-2.5 py-2 text-sm font-medium text-danger hover:text-red-500 hover:bg-red-500/10 transition shrink-0"
              >
                <Trash size={18} />
                <span className="hidden sm:inline">{t('editor.deleteForever')}</span>
              </button>
            </HoverLabel>
          </>
        ) : share === 'none' ? null : (
          <>
          <ShareMenu
            open={showShareMenu}
            onClose={() => setShowShareMenu(false)}
            onToggle={() => setShowShareMenu((v) => !v)}
            triggerHidden={share === 'menu'}
            fallbackAnchorRef={noteOptionsButtonRef}
            selected={selected}
            exportSingleMarkdown={exportSingleMarkdown}
            exportSingleHtml={exportSingleHtml}
            printNote={printNote}
            handleBurnShare={handleBurnShare}
            onCopyShortcut={onCopyShortcut}
            onCopyNoteLink={onCopyNoteLink}
          />
          </>
        )}
        {/* The calendar's door on every dated type: "Add to calendar" while
            the item has no day, its day and time once it has one. It opens
            the Schedule view of the "..." menu, the one place a schedule is
            edited. Spec: ops/docs/archive/calendar-pillar-spec.md (step 8) */}
        {view !== 'trash' && !zenMode && (selected.type === 'note' || selected.type === 'task' || selected.type === 'event' || selected.type === 'journal') && (() => {
          const s = scheduleOf(selected.trackers as Record<string, unknown> | undefined, selected.type, selected.type === 'journal' ? entryDayOf(selected) : undefined);
          const day = s ? (schedule.occurrence && s.repeat ? schedule.occurrence : s.day) : null;
          const label = day
            ? [formatDay(day, 'weekdayDate'), s?.time ? timeLabel(day, s.time) : ''].filter(Boolean).join(' · ')
            : t('shell:calendar.addToCalendar');
          // An event draws its schedule in the card above the body instead.
          if (day && selected.type === 'event') return null;
          const openSchedule = () => openScheduleAt('main');
          // One name per type wherever the view opens: a journal entry's date is the entry's own.
          const scheduleName = t(selected.type === 'journal' ? 'shell:noteOptionsMenu.entryDate' : 'shell:noteOptionsMenu.schedule');
          return day && !headerCompact ? (
            <HoverLabel label={scheduleName} position="below">
              <button type="button" onClick={openSchedule} aria-label={`${scheduleName}: ${label}`} className={`${HEADER_BTN_BASE} gap-1.5 px-2 ${HEADER_BTN_REST} text-[13px] tabular-nums whitespace-nowrap`}>
                <CalendarDots size={16} aria-hidden="true" className={typeGlyph('event').color} />
                {label}
              </button>
            </HoverLabel>
          ) : (
            <HoverLabel label={label} position="below">
              <button type="button" onClick={openSchedule} aria-label={label} className={HEADER_BTN}>
                {day ? <CalendarDots size={HEADER_ICON} aria-hidden="true" /> : <CalendarPlus size={HEADER_ICON} aria-hidden="true" />}
              </button>
            </HoverLabel>
          );
        })()}
        {/* The toolbar toggle holds this place in both views: the Markdown
            view has a bar of its own, which ends with the way back to
            formatted text. Spec: ops/specs/editor-mode-toggle.md */}
        {zenMode && markdownBody && (
          // Zen's only formatting affordance, and testers kept missing
          // it: borderless with a 16px glyph it read as a label beside
          // the bordered Exit Zen button. MarkdownLogo's viewBox is
          // square but its ink is roughly 2:1.25, so it needs a larger
          // `size` than a solid icon to carry the same weight - hence
          // 20 against Exit Zen's X at 16. Box matches Exit Zen exactly
          // (h-8 w-8, same border and surface) so the two read as one
          // pair of controls.
          <HoverLabel label={zenToolbar ? t('editor.hideToolbar') : t('editor.showToolbar')} position="below-end">
            <button
              type="button"
              onClick={() => setZenToolbar((v) => !v)}
              aria-label={zenToolbar ? t('editor.hideToolbar') : t('editor.showToolbar')}
              aria-pressed={zenToolbar}
              className={zenToolbar ? ZEN_BTN_ON : ZEN_BTN_REST}
            >
              <MarkdownLogo size={20} aria-hidden="true" />
            </button>
          </HoverLabel>
        )}
        {zenMode && (
          <ContentWidthButton contentWidth={contentWidth} onCycle={cycleContentWidth} />
        )}
        {/* Note options - the complete per-note surface, and the only
            control that never hides. Burn, pin and trash live in its strip
            and nowhere else; it adds the Pro toggles, folders, history and
            the note-info block. It renders in the trash view too, where it
            carries Restore and Delete forever, and in zen, where the
            vertical three-dot glyph is narrow enough not to compete with
            the page.

            Last in the row after the zen controls, so in zen it sits beside
            Exit Zen rather than in front of the pair of toggles: the two
            that end the row are the two that leave the note, and a menu
            wedged before them splits controls that belong together. Outside
            zen those three render nothing, so this is still the row's last
            item there. Anchored relative so the popover opens under the
            button. */}
        <div className="relative shrink-0">
          <HoverLabel label={t('editor.noteOptions')} position="below-end">
            <button
              ref={noteOptionsButtonRef}
              onClick={() => { setOptionsStartView('main'); setScheduleSub(undefined); setShowNoteOptions((v) => !v); }}
              aria-label={t('editor.noteOptions')}
              aria-expanded={showNoteOptions}
              // In zen it takes the bordered box its neighbours wear.
              className={
                zenMode
                  ? (showNoteOptions ? ZEN_BTN_ON : ZEN_BTN_REST)
                  : `${HEADER_BTN_BASE} w-8 ${showNoteOptions ? 'text-accent-strong bg-accent/15' : HEADER_BTN_REST}`
              }
          >
            <DotsThreeOutlineVertical size={HEADER_ICON} aria-hidden="true" />
            </button>
          </HoverLabel>
          {showNoteOptions && (
            <NoteOptionsMenu
              {...noteGuards}
              spaceMove={spaceMove}
              isTrash={view === 'trash'}
              onRestore={() => void handleRestore(selected.id)}
              onDeleteForever={() => setDeleteConfirm({ id: selected.id, title: selected.title || '' })}
              onBurn={() => void handleBurnShare(selected)}
              anchorRef={noteOptionsButtonRef}
              onDuplicate={() => void handleDuplicate(selected.id)}
              onToggleStar={() =>
                void handleToggleStar(selected.id, selected.starred !== 1)
              }
              onToggleArchive={() => void handleToggleArchive(selected.id, selected.archived !== 1)}
              // Share is the one strip cell that comes and goes, because it
              // is the one action still in the header: two copies at one
              // width would read as the same control drawn twice. Zen and a
              // compact header hide the header's copy, so those are where
              // the cell earns its place.
              {...(share === 'menu' ? { onShare: () => setShowShareMenu(true) } : {})}
              onTrash={() => requestTrash([selected.id])}
              initialView={optionsStartView}
              onConvertType={(target) => void convertNoteType(target)}
              {...(selected.type === 'journal' && view !== 'trash'
                ? { onSetJournalDate: (day: string) => void setJournalDate(selected.id, day), journalDays }
                : {})}
              {...((selected.type === 'note' || selected.type === 'task' || selected.type === 'event') && view !== 'trash'
                ? { onSetNoteDate: (day: string | null) => void setNoteDate(selected.id, day) }
                : {})}
              schedule={{
                occurrence: schedule.occurrence,
                onEdit: (edit) => schedule.edit(selected.id, schedule.occurrence, edit),
                sub: scheduleSub,
              }}
              {...(noteColor
                ? {
                    color: noteColor,
                    onSetColor: (c: NoteOwnColor | null) => onSetNoteColor(selected.id, c),
                    onOpenColorSettings,
                    onPickIcon: () => onPickNoteIcon(selected.id),
                  }
                : {})}
              {...(canSwitchEditorMode
                ? { editorMode: selectedEditorMode, onToggleEditorMode: toggleEditorMode }
                : {})}
              // Each view has its own replace bar, and the Pro gate sits
              // inside each toggle, shared with the shortcut.
              {...(canSwitchEditorMode
                ? {
                    onFindReplace: selectedEditorMode === 'markdown'
                      ? () => editorCommands.findReplace?.()
                      : () => editorRef.current?.toggleReplace(),
                  }
                : {})}
              // Same notes as the editor-mode row: an editable markdown body.
              {...(canSwitchEditorMode && canUncheckAllTasks(selected)
                ? { onUncheckAllTasks: () => void handleUncheckAllTasks(selected) }
                : {})}
              {...(canSwitchEditorMode && canDeleteCheckedTasks(selected)
                ? { onDeleteCheckedTasks: () => handleDeleteCheckedTasks(selected) }
                : {})}
              {...(canSwitchEditorMode && canSortTasksByStatus(selected)
                ? { onSortTasksByStatus: () => void handleSortTasksByStatus(selected) }
                : {})}
            />
          )}
        </div>
        {zenMode && (
          // Last control in the row and hard against the window's
          // right edge, so the centered tip was cut by the viewport
          // (nothing in this chain clips - see ui-patterns 18a step 4):
          // `below-end` opens it below, end-aligned, growing inward.
          // It stays beside the button's own "Exit Zen" label, because
          // it carries the key.
          <HoverLabel label={t('zen.exitHover')} keys={keyText('escape')} position="below-end">
            <button
              type="button"
              onClick={() => setZenMode(false)}
              aria-label={t('zen.exitHover')}
              className="ms-1 shrink-0 inline-flex items-center justify-center gap-1.5 h-8 w-8 sm:w-auto sm:px-3 rounded-md border border-divider bg-surface-2 text-sm font-medium text-pn-soft hover:text-accent hover:border-accent/50 transition"
            >
              <X size={16} />
              <span className="hidden sm:inline">{t('zen.exit')}</span>
            </button>
          </HoverLabel>
        )}
        </div>
      </div>
      {/* Not backed up: the server refused this note on the last pass. Sits
          under the header so the header keeps its fixed height, and has no
          dismiss - the only thing that clears it is a pass that pushes the
          note. Spec: ops/docs/archive/ui-patterns.md (the not-backed-up state) */}
      {pushFailure && (
        <div
          role="status"
          className="shrink-0 border-b border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30 px-4 sm:px-6 py-2 text-sm text-amber-800 dark:text-amber-300"
        >
          {pushFailure.reason === 'too_large'
            ? t('editor.notBackedUpTooLarge')
            : t('editor.notBackedUpFailed', { message: pushFailure.message })}
        </div>
      )}
      {/* PIN-protect gate - covers the editor until the user
          unlocks. Unlocking here sets the shared session
          timer, so any other protected notes also become
          accessible for the configured duration.
          It also stands in for a modal when a menu asks to take the
          protection off an open note: same two checks, one screen. */}
      {isNoteLocked(selected) || removingProtection ? (
        <div className="flex-1 overflow-y-auto px-4 sm:px-6 pt-0 pb-6">
          <ProtectedNoteGate
            phrase={auth.phrase}
            onUnlock={onPinUnlocked}
            initialIntent={removingProtection ? 'remove' : 'unlock'}
            onExitRemove={() => setRemoveProtectionFor(null)}
            onRemoveProtection={() => {
              setRemoveProtectionFor(null);
              void handleSetPinProtected(selected.id, false);
            }}
            onCancel={() => setSelectedId(null)}
            userSettings={userSettings}
            onSettingsChange={(next, base) => {
              mutateSettings((prev) => withCredentialChanges(prev, base, next));
            }}
          />
        </div>
      ) : !knownType ? (
        /* Neither the editor nor a form: either would read the body as
           something it is not, and a keystroke in the editor writes markdown
           over it. The title above is read-only and the tag row stays out;
           the menus still pin, protect, move and trash the item like any
           other. */
        <div className="flex-1 flex flex-col items-center justify-center px-6 text-center">
          <p className="max-w-sm text-[15px] text-pn-muted">
            {t('editor.unknownType')}
          </p>
        </div>
      ) : structuredBody ? (
        /* The same centered reading column the notes editor uses - the
           header row wears pn-content-col already, so a left-hugging body
           under a centered title read as two different layouts on wide
           screens (2026-08-22 review). */
        <div className="flex-1 overflow-y-auto">
        <div ref={structuredColRef} className="pn-content-col flex min-h-full flex-col">
          {!zenMode && view !== 'trash' && selected.locked !== 1 && (
            <TagInput
              key={`tags-${selected.id}`}
              ref={tagInputRef}
              tags={selected.tags}
              allTags={tagCounts.tags}
              onChange={(tags) => handleTagsChange(selected.id, tags)}
              onSelectTag={(tag) => void handleSelectTag(tag)}
              onTabOut={focusFirstField}
              leading={folderChipFor(selected)}
            />
          )}
          {selected.locked === 1 && view !== 'trash' && (
            /* The same read-only hint the markdown editor shows - vault
               items and bookmarks were silently uneditable without it. */
            <div className="px-6 pt-3 flex items-center gap-2 text-[13px] text-warning">
              <PencilSimpleSlash size={13} className="shrink-0" aria-hidden="true" />
              <span className="truncate">{t('editor.readOnlyToggle')}</span>
              <span className="inline-flex items-center gap-1 shrink-0">
                <DotsThreeOutlineVertical size={13} aria-hidden="true" />
                {t('editor.menu')}
              </span>
            </div>
          )}
          {selected.type === 'contact' ? (
            <ContactItem
              key={selected.id}
              note={selected}
              isTrash={view === 'trash'}
              onDraftName={setContactDraftName}
              onTitleChange={handleTitleChange}
              onBodyChange={(id, body) => void handleBodyChange(id, body)}
              onPinProtectedChange={handleSetPinProtected}
            />
          ) : selected.type === 'link' ? (
            <BookmarkItem
              key={selected.id}
              note={selected}
              bookmarkKeys={bookmarkKeys}
              isTrash={view === 'trash'}
              clip={view === 'trash' ? undefined : bookmarkClip(selected)}
              onBodyChange={(id, body) => void handleBodyChange(id, body)}
              onPinProtectedChange={handleSetPinProtected}
            />
          ) : (
          <VaultItem
            key={`${selected.id}-${editorRevision}`}
            note={selected}
            isTrash={view === 'trash'}
            onTitleChange={handleTitleChange}
            onSave={handleVaultSave}
            onPinProtectedChange={handleSetPinProtected}
            isPro={auth.isPro}
            onOpenUpgrade={(trigger) => setShowUpgrade({ trigger })}
          />
          )}
        </div>
        </div>
      ) : (
        <>
        <div ref={setScroller} className={`flex-1 overflow-y-auto overflow-x-hidden pt-0 ${footerVisible ? 'pb-2' : 'pb-[max(0.5rem,env(safe-area-inset-bottom))]'}`}>
          {/* Tags + tracker pills + week-in-review scroll with the
              editor so they don't permanently eat vertical space
              on mobile. The toolbar inside Editor is sticky.
              overflow-x-hidden keeps the sticky toolbar pinned
              when content (e.g. wide tables) overflows - the
              editor wrapper below handles horizontal scroll.
              pn-content-col caps the reading width so nothing
              stretches edge-to-edge on ultrawide displays. */}
          <div className="pn-content-col flex min-h-full flex-col" data-content-col>
          {!zenMode && view !== 'trash' && selected.locked !== 1 && (selected.type === 'note' || selected.type === 'journal' || selected.type === 'file' || selected.type === 'task') && (
            <div ref={setStickyTagRow} className="pn-tagrow sticky top-0 z-20 bg-surface-1/95 backdrop-blur">
            <TagInput
              key={`tags-${selected.id}`}
              ref={tagInputRef}
              tags={selected.tags}
              allTags={tagCounts.tags}
              onChange={(tags) => handleTagsChange(selected.id, tags)}
              onSelectTag={(tag) => void handleSelectTag(tag)}
              onTabOut={focusBody}
              leading={folderChipFor(selected)}
              trailing={
                // Undo/redo and the toolbar toggle are all TipTap
                // controls: they go through editorRef, and the
                // formatting bar itself renders inside Editor.
                //
                // The cluster used to be hidden entirely in markdown mode,
                // back when everything in it drove TipTap. Only the
                // formatting-bar toggle still does: undo and redo fall
                // through to the textarea's own native history (see
                // handleHistory in NotesView.tsx), and the reading width is
                // a CSS variable on the content column, which the source
                // view wears too. So the one dead control gives its slot to
                // the way back to formatted text, and the rest stay.
                // Spec: ops/specs/editor-mode-toggle.md
                (
                <div className="ml-auto flex items-center gap-1.5 shrink-0">
                  {/* What is left in this row acts on the two rows around
                      it, not on the note body: undo and redo, then the
                      toggle for the formatting bar directly below and the
                      reading width the bar sits across. Everything that
                      acts on the BODY moved into the slot above it (see
                      bodyControls further down). */}
                  {/* Undo and redo are for the devices with no keyboard to
                      press. On a pointer device Ctrl+Z and Ctrl+Shift+Z do
                      the same job without spending a place in the row, and
                      the pair was the only thing left in this cluster that a
                      shortcut already covered. The hover query is the test
                      because it answers what the device HAS, where a width
                      breakpoint only guesses.
                      Spec: ops/docs/design-decisions.md (share holds the header) */}
                  <div className="flex items-center gap-0.5 [@media(hover:hover)_and_(pointer:fine)]:hidden">
                    <HoverLabel label={t('editor.undo')} keys={keyText('undo')} position="below">
                      <button
                        type="button"
                        tabIndex={isMobile ? -1 : undefined}
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={() => handleHistory('undo')}
                        aria-label={t('editor.undo')}
                        className={HEADER_BTN}
                      >
                        <Undo2Icon size={HEADER_ICON} />
                      </button>
                    </HoverLabel>
                    <HoverLabel label={t('editor.redo')} keys={keyText('redo')} position="below">
                      <button
                        type="button"
                        tabIndex={isMobile ? -1 : undefined}
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={() => handleHistory('redo')}
                        aria-label={t('editor.redo')}
                        className={HEADER_BTN}
                      >
                        <Redo2Icon size={HEADER_ICON} />
                      </button>
                    </HoverLabel>
                  </div>
                  <div className="[@media(hover:hover)_and_(pointer:fine)]:hidden">
                    <HeaderDivider />
                  </div>
                  <div className="flex items-center gap-0.5">
                    {/* The formatting-bar toggle, in both views: the Markdown
                        view has a bar of its own, and the way between the two
                        views sits at the end of each bar. The slot never
                        changes its control (GitHub #493).
                        Spec: ops/specs/editor-mode-toggle.md */}
                    <HoverLabel label={toolbarVisible ? t('editor.hideToolbar') : t('editor.showToolbar')} position="below-end">
                      <button
                        type="button"
                        tabIndex={isMobile ? -1 : undefined}
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={toggleToolbar}
                        aria-label={toolbarVisible ? t('editor.hideToolbar') : t('editor.showToolbar')}
                        aria-pressed={toolbarVisible}
                        className={`${HEADER_BTN_BASE} w-8 ${toolbarVisible ? 'text-accent-strong bg-accent/15' : HEADER_BTN_REST}`}
                      >
                        {/* 20, not the row's 18: the markdown mark's ink is
                            roughly 2:1.25 inside a square viewBox, so at the
                            shared size it reads visibly lighter than the
                            solid glyphs beside it. */}
                        <MarkdownLogo size={20} aria-hidden="true" />
                      </button>
                    </HoverLabel>
                    {/* The reading width is not here. It only ever appeared
                        past a 56rem pane, it is a taste somebody sets once,
                        and Settings > Editor carries the same axis at
                        every width. Zen keeps its own copy, because zen has
                        no settings sheet to reach. */}
                  </div>
                </div>
                )
              }
            />
            </div>
          )}
          {!zenMode && view !== 'trash' && selected.type === 'event' && (() => {
            const s = scheduleOf(selected.trackers as Record<string, unknown> | undefined, 'event');
            if (!s) return null;
            return (
              <EventCard
                key={selected.id}
                schedule={s}
                day={schedule.occurrence && s.repeat ? schedule.occurrence : s.day}
                fold={mobileEditing || (wcBody || selected.body).trim() !== ''}
                alertsUnlocked={proUnlocked(auth.isPro)}
                showPro={!auth.isPro}
                onOpen={openScheduleAt}
                onUpgrade={() => setShowUpgrade({ trigger: 'alerts' })}
              />
            );
          })()}
          {!zenMode && selected.type === 'journal' && (
            <TrackerPills
              data={(selected.trackers as JournalTrackerData) ?? {}}
              onChange={(next) => handleTrackersChange(selected.id, next)}
              trackerSettings={userSettings.trackerSettings}
              onSettingsChange={(ts) => mutateSettings((prev) => ({ ...prev, trackerSettings: ts }))}
              medications={userSettings.medications}
              factors={userSettings.factors}
              readOnly={view === 'trash' || selected.locked === 1}
              isPro={auth.isPro}
              onOpenUpgrade={() => setShowUpgrade({ trigger: null })}
              collapsed={mobileEditing}
              onOpenSetup={onOpenTrackerSettings}
            />
          )}
          {proUnlocked(auth.isPro) && selected.type === 'journal' && isWeekJournal(selected) && (
            <WeekInReview notes={notes} medications={userSettings.medications} isNoteLocked={isNoteLocked} />
          )}
          {selected.locked === 1 && view !== 'trash' && (
            <div className="mx-4 sm:mx-6 mt-1 mb-3 flex items-center gap-2 text-[13px] text-warning">
              <PencilSimpleSlash size={13} className="shrink-0" aria-hidden="true" />
              <span className="truncate">
                {t('editor.readOnlyToggle')}
              </span>
              <span className="inline-flex items-center gap-1 shrink-0">
                <DotsThreeOutlineVertical size={13} aria-hidden="true" />
                {t('editor.menu')}
              </span>
            </div>
          )}
          <div className="px-4 sm:px-6 flex flex-1 flex-col min-w-0">
            {selectedEditorMode === 'markdown' ? (
              /* No corner pills here. Find and replace come from the keys
                 and the "..." menu and open in the view's own bar; the
                 outline has no headings to read off a plain textarea. The
                 way back to formatted text is the end of the view's own
                 toolbar, the first row of the "..." menu, and the link under
                 the word count. */
              <MarkdownSourceEditor
                key={`${selected.id}-${editorRevision}`}
                ref={sourceRef}
                value={selected.body}
                onChange={(body) => { handleBodyChange(selected.id, body, editorKey); setWcBody(body); }}
                readOnly={view === 'trash' || selected.locked === 1}
                search={sourceSearch}
                toolbar={(zenMode ? zenToolbar : toolbarVisible) ? {
                  onShowFormatted: toggleEditorMode,
                  atBottom: barPosition === 'bottom',
                  slot: barSlot,
                  mobileTabIndex: isMobile ? -1 : undefined,
                } : undefined}
              />
            ) : (
              <Editor
                key={`${selected.id}-${editorRevision}`}
                ref={editorRef}
                noteId={selected.id}
                value={selected.body}
                onChange={(body) => { handleBodyChange(selected.id, body, editorKey); setWcBody(body); }}
                readOnly={view === 'trash' || selected.locked === 1}
                onFocusChange={setEditorFocused}
                toolbarVisible={zenMode ? zenToolbar : toolbarVisible}
                isPro={auth.isPro ?? false}
                onOpenUpgrade={(trigger) => setShowUpgrade({ trigger })}
                // A note created from a single uploaded file carries that
                // file's name as its title too, so a rename in the chip
                // takes the title with it. The other direction is left
                // alone: a note title is free text everywhere else, and
                // rewriting the body from a text field on every keystroke
                // is the wrong trade.
                onRenameFile={selected.type === 'file'
                  ? (name) => { void handleTitleChange(selected.id, name); }
                  : undefined}
                fileNote={selected.type === 'file'}
                bodyControls={bodyControls}
                connections={connections}
                toolbarSlot={barSlot}
                onShowMarkdown={canSwitchEditorMode ? toggleEditorMode : undefined}
                sinkCheckedTasks={userSettings.sinkCheckedTasks}
                placeholder={selected.type === 'event' ? t('editor:eventPlaceholder') : undefined}
              />
            )}
            {/* 2-col footer: word/char counts left, editor-mode link right.
                This is the last row in the scroll column, so the
                container's bottom padding (pb-2) is the only gap between
                it and the app footer's divider - it reads as sitting ON
                that line rather than floating in a void (GitHub #205).
                Hidden in zen mode: it is metadata plus a control, and
                zen already drops the app footer (and with it the global
                word count), the tag row and the header actions. Exit zen
                to reach the mode toggle again.
                Spec: ops/specs/editor-mode-toggle.md */}
            {/* The jump a long note offers, on screens with the desktop footer:
                the pill of find and the outline, on the same right edge as they
                are (the text's), in a zero-height sticky strip at the column's
                foot. It rides above the pane's bottom edge while the note
                scrolls and rests above the word count at the end. It shows only
                while the note moves and fades two seconds after, so it takes no
                width from the text and covers its edge only for a moment; the
                pointer on it holds it. Hidden, it is inert, so it never catches
                a click meant for the text. Phones carry the arrow in the bottom
                bar instead. */}
            {noteJump && (
              <div
                inert={!noteJump.scrolling}
                onMouseEnter={() => noteJump.keepShown(true)}
                onMouseLeave={() => noteJump.keepShown(false)}
                className={`sticky bottom-3 z-[5] mt-auto hidden [@media(min-width:768px)_and_(min-height:501px)]:flex h-0 items-end justify-end overflow-visible pointer-events-none transition-opacity duration-200 motion-reduce:transition-none ${noteJump.scrolling ? 'opacity-100' : 'opacity-0'}`}
              >
                <EditorSlotPill
                  label={t(noteJump.toTop ? 'footer.goToTop' : 'footer.goToEnd')}
                  onClick={() => noteJump.go(noteJump.toTop ? 'top' : 'end')}
                >
                  {noteJump.toTop ? <ArrowCircleUp size={18} /> : <ArrowCircleDown size={18} />}
                </EditorSlotPill>
              </div>
            )}
            {!zenMode && (
              <div className="mt-auto pt-4 shrink-0 flex items-start justify-between gap-3">
                <div className="min-w-0 flex items-start gap-1.5">
                  {/* Invisible characters toggle. Only meaningful over the
                      rich-text editor - the markdown source view is a plain
                      textarea with nothing to decorate. The tip opens away
                      from this edge: position="end" maps to `start-full`
                      under the hood, which is the side the tip grows
                      toward, not where it sits (see the header comment in
                      HoverLabel.tsx) - and it mirrors under RTL by design.
                      It has to open outward because this is the first
                      element in the row. */}
                  {selectedEditorMode !== 'markdown' && (
                    <HoverLabel
                      label={invisibles ? t('editor.invisiblesHide') : t('editor.invisiblesShow')}
                      keys={keyText('invisibles')}
                      position="end"
                    >
                      {/* h-4 matches the text-xs line box next to it, so the
                          icon centers on the counter's first line instead of
                          hanging off the top of it - `items-start` on the row
                          aligns boxes, and a bare SVG is a shorter box than a
                          16px line. Size 14 is the 12px text beside it plus
                          2px; duotone keeps the extra size from reading as
                          heavier than the counter. */}
                      <button
                        type="button"
                        onClick={() => setInvisibles(!invisibles)}
                        aria-pressed={invisibles}
                        aria-label={invisibles ? t('editor.invisiblesHide') : t('editor.invisiblesShow')}
                        className={`shrink-0 h-4 flex items-center text-accent transition ${
                          invisibles ? '' : 'opacity-70 hover:opacity-100'
                        }`}
                      >
                        {/* Accent in both states - the control is the one
                            colored thing in a row of grey metadata, so it
                            reads as a control rather than as a stray glyph.
                            On/off is carried by weight (fill vs duotone),
                            the same active convention the rest of the app
                            uses, plus a slight opacity lift on hover. */}
                        <Paragraph size={14} weight={invisibles ? 'fill' : 'duotone'} />
                      </button>
                    </HoverLabel>
                  )}
                  <WordCount
                    body={wcBody || selected.body}
                    sizeOf={(body) => storedNoteBytes({ ...selected, body })}
                    onSplit={splitNote && view !== 'trash' ? () => splitNote(selected) : undefined}
                    onOverLimit={() => onOverSyncLimit(selected.id)}
                  />
                </div>
                {view !== 'trash' && selected.locked !== 1 && (
                  <button
                    type="button"
                    onClick={toggleEditorMode}
                    className="shrink-0 select-none inline-flex items-center gap-1.5 text-xs text-pn-muted hover:text-pn-soft transition group/mode"
                  >
                    {/* The same two glyphs the note options menu shows for this
                        toggle, and the same state decides which: one control in
                        two places must not be learned twice. Accent, like the
                        invisible-characters glyph at the other end of this
                        footer, and after its label rather than before it, so
                        both glyphs sit on the footer's outer edges and the two
                        blocks of text face each other. The underline moves onto
                        the label alone, so the glyph is not dragged into it. */}
                    <span className="group-hover/mode:underline">
                      {selectedEditorMode === 'markdown' ? t('editor.showFormatted') : t('editor.showMarkdown')}
                    </span>
                    {selectedEditorMode === 'markdown'
                      ? <TextAa size={14} className="text-accent shrink-0" aria-hidden="true" />
                      : <ArticleMedium size={14} className="text-accent shrink-0" aria-hidden="true" />}
                  </button>
                )}
              </div>
            )}
          </div>
          </div>
        </div>
        {/* The format bar's row when it sits at the bottom: outside the
            scrolling column, so the note scrolls and bounces under it and
            the bar never moves. It keeps clear of the home indicator only
            when it is the last thing on the screen: over the keyboard there
            is none, and iOS still reports the inset there (GitHub #533). */}
        {barBelow && (
          <div className={`shrink-0 border-t border-divider bg-surface-2 ${footerVisible || keyboardUp ? '' : 'pb-[env(safe-area-inset-bottom)]'}`}>
            <div ref={setBarSlot} className="pn-content-col" />
          </div>
        )}
        </>
      )}
    </>
  );
}
