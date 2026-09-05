import type { Dispatch, ReactNode, RefObject, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowUUpLeft as Undo2Icon, ArrowUUpRight as Redo2Icon, X, ArrowLeft, ArrowCounterClockwise, Trash, DotsThreeOutlineVertical, CaretLeft, CaretRight, PencilSimpleSlash, MarkdownLogo, TextAa, Paragraph, MagnifyingGlass, FrameCorners } from '../icons';
import type { AuthState } from '../auth';
import type { LocalNote } from '../db';
import { updateNote } from '../notesRepo';
import { Editor, type EditorHandle } from '../Editor';
import { MarkdownSourceEditor } from '../MarkdownSourceEditor';
import { TagInput, type TagInputHandle } from '../TagInput';
import type { UserSettings } from '../userSettings';
import { NoteOptionsMenu } from '../NoteOptionsMenu';
import { ProtectedNoteGate } from '../ProtectedNoteGate';
import { parseLinkBody, linkDomain } from '../linkBody';
import { BookmarkItem } from '../BookmarkItem';
import { HoverLabel } from '../HoverLabel';
import { EditorSlotPill } from '../EditorSlotPill';
import { useTheme, type ContentWidth } from '../theme';
import { TITLE_MAX_LENGTH } from '../useNoteEditing';
import { proUnlocked } from '../demo';
import { usePushFailure } from '../pushFailures';
import { VaultItem } from '../VaultItem';
import { isWeekJournal, toLocalIso } from '../notesViewUtils';
import type { View } from '../views';
import { WordCount } from '../WordCount';
import { TrackerPills } from '../TrackerPills';
import type { JournalTrackerData } from '../trackerTypes';
import { ShareMenu } from './ShareMenu';
import { NoteQuickActions, HeaderDivider, type QuickActionsTier } from './NoteQuickActions';
import type { NoteActionGuardDeps } from '../noteActionGuards';
import { WeekInReview } from './WeekInReview';

type Authed = Extract<AuthState, { status: 'authenticated' }>;

/**
 * The one box every button in the editor header wears: a 32px square with
 * an 18px glyph. Row 1 (note actions), row 2 (the tag row's controls) and
 * the formatting toolbar all use this size, so the three rows read as one
 * instrument rather than three. Colour is left to mean state - accent for
 * on, amber for burn, red for destructive - and grouping is carried by the
 * hairline in `HeaderDivider`, never by a filled container.
 * Spec: ops/docs/ui-patterns.md (section 80)
 */
const HEADER_BTN_BASE =
  'shrink-0 flex items-center justify-center h-8 rounded-md transition disabled:opacity-30 disabled:cursor-not-allowed';
const HEADER_BTN_REST =
  'text-neutral-600 dark:text-neutral-300 enabled:active:scale-95 enabled:[@media(hover:hover)]:hover:text-accent enabled:[@media(hover:hover)]:hover:bg-neutral-200 enabled:[@media(hover:hover)]:dark:hover:bg-neutral-800';
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
const ZEN_BTN_REST = `${ZEN_BTN_BOX} border-divider bg-surface-2 text-neutral-600 dark:text-neutral-300 hover:text-accent hover:border-accent/50`;
const ZEN_BTN_ON = `${ZEN_BTN_BOX} border-accent/50 bg-accent/10 text-accent`;

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
 * Everywhere else Settings > Appearance carries the same axis, at every
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

export interface NoteEditorPaneProps {
  selected: LocalNote;
  view: View;
  notes: LocalNote[];
  /** Every saved bookmark URL in the account (buildLinkKeyMap), for the
   *  bookmark body's duplicate guard. Owned by NotesView so the editor and
   *  the quick-add bar can never guard against different sets. */
  bookmarkKeys: Map<string, string>;
  auth: Authed;
  gridMode: boolean;

  zenMode: boolean;
  setZenMode: Dispatch<SetStateAction<boolean>>;
  zenToolbar: boolean;
  setZenToolbar: Dispatch<SetStateAction<boolean>>;

  /** How many quick-action groups the header row fits. Measured in NotesView. */
  quickActionsTier: QuickActionsTier;
  /** Previous/next note in the list (GitHub #246). Never hides. */
  canGoPrev: boolean;
  canGoNext: boolean;
  onNavigateList: (direction: 'prev' | 'next') => void;
  isMobile: boolean;
  mobileTabIndex: number | undefined;
  mobileEditing: boolean;
  footerVisible: boolean;

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

  handleTitleChange: (id: string, title: string) => Promise<void>;
  /** Focus/blur on the title field bracket a rename, so note-links into
   *  this note can follow it. See useNoteEditing.handleTitleBlur (#238). */
  handleTitleFocus: (id: string) => void;
  handleTitleBlur: (id: string) => void;
  handleBodyChange: (id: string, body: string) => Promise<void>;
  handleTagsChange: (id: string, tags: string[]) => Promise<void>;
  handleTrackersChange: (id: string, trackers: JournalTrackerData) => Promise<void>;

  handleCloseEditor: () => Promise<void>;
  handleHistory: (action: 'undo' | 'redo') => void;
  handleToggleStar: (id: string, starred: boolean) => Promise<void>;
  handleTrash: (id: string) => Promise<void>;
  handleRestore: (id: string) => Promise<void>;
  handleDuplicate: (id: string) => Promise<void>;
  handleSetLocked: (id: string, locked: boolean) => Promise<void>;
  handleSetPinProtected: (id: string, pinProtected: boolean) => Promise<void>;
  handleBurnShare: (n: LocalNote) => Promise<void>;

  showShareMenu: boolean;
  setShowShareMenu: Dispatch<SetStateAction<boolean>>;
  exportSingleMarkdown: (n: LocalNote) => Promise<void> | void;
  exportSingleHtml: (n: LocalNote) => Promise<void> | void;
  printNote: (n: LocalNote) => Promise<void> | void;

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
  setHistoryForNoteId: Dispatch<SetStateAction<string | null>>;
  setShowUpgrade: Dispatch<SetStateAction<null | { trigger: 'lock' | 'protect' | 'history' | 'devices' | 'zen' | 'theme' | 'storage' | 'callout' | 'fileSize' | 'folders' | 'totp' | null }>>;
  setShowSecurity: Dispatch<SetStateAction<null | { tab: 'pin' | 'phrase' | 'biometric'; reason?: 'protect' }>>;
  onPinUnlocked: () => void;
  setFolderPicker: Dispatch<SetStateAction<
    | { mode: 'note'; noteIds: string[]; currentFolderId: string | null | undefined }
    | { mode: 'folder'; folderId: string }
    | null
  >>;
}

export function NoteEditorPane(props: NoteEditorPaneProps) {
  const { t } = useTranslation('notes');
  // The last sync pass could not push this note (pushFailures.ts).
  const pushFailure = usePushFailure(props.selected.id);
  const { contentWidth, cycleContentWidth } = useTheme();
  const {
    selected,
    view,
    notes,
    bookmarkKeys,
    auth,
    gridMode,
    zenMode,
    setZenMode,
    zenToolbar,
    setZenToolbar,
    quickActionsTier,
    canGoPrev,
    canGoNext,
    onNavigateList,
    isMobile,
    mobileTabIndex,
    mobileEditing,
    footerVisible,
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
    titleInputRef,
    tagInputRef,
    editorRef,
    setHeaderRow,
    noteOptionsButtonRef,
    setStickyTagRow,
    setNoteScroller,
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
    handleTitleChange,
    handleTitleFocus,
    handleTitleBlur,
    handleBodyChange,
    handleTagsChange,
    handleTrackersChange,
    handleCloseEditor,
    handleHistory,
    handleToggleStar,
    handleTrash,
    handleRestore,
    handleDuplicate,
    handleSetLocked,
    handleSetPinProtected,
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
    setHistoryForNoteId,
    setShowUpgrade,
    setShowSecurity,
    onPinUnlocked,
    setFolderPicker,
  } = props;
  // True while a menu has asked to take this note's protection off. The gate
  // does the asking, so an open note gets the same two checks as a locked one.
  const removingProtection = removeProtectionFor === selected.id;
  const structuredBody =
    selected.type === 'login' || selected.type === 'card' ||
    selected.type === 'ssh-key' || selected.type === 'link';
  /**
   * True when the markdown editor is the thing under the header, so Zen's
   * markdown toggle has a toolbar to switch. Two states fail that test.
   * Bookmarks and vault items replace the editor with a structured form,
   * which has no toolbar at any width. A PIN-protected note replaces it with
   * the unlock gate until the user enters the PIN. In both the toggle shows
   * and switches a bar that is not on screen.
   */
  const markdownBody = !structuredBody && !isNoteLocked(selected);
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
  /**
   * Flip this note between the note and journal types.
   *
   * A journal entry without `trackers.journalDate` falls back to the UTC
   * day of createdAt, so every tracker value logged on a converted note is
   * filed under the day the NOTE was made, months ago for an old one.
   * Stamp the day it becomes a journal, the way the create and backfill
   * paths do.
   */
  const convertNoteType = async () => {
    const newType = selected.type === 'journal' ? 'note' as const : 'journal' as const;
    const existing = (selected.trackers as Record<string, unknown> | undefined) ?? {};
    const patch =
      newType === 'journal' && typeof existing.journalDate !== 'string'
        ? { type: newType, trackers: { ...existing, journalDate: toLocalIso(new Date()) } }
        : { type: newType };
    await updateNote(selected.id, patch);
    await refresh();
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
      setHistoryForNoteId(selected.id);
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
   * Spec: ops/docs/ui-patterns.md (section 80)
   */
  const bodyControls = selectedEditorMode !== 'markdown' && bodyOverflows ? (
    <EditorSlotPill
      label={t('editor.findInNote')}
      onClick={() => editorRef.current?.toggleFind()}
      tabIndex={isMobile ? -1 : undefined}
    >
      <MagnifyingGlass size={17} />
    </EditorSlotPill>
  ) : null;

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
          <HoverLabel label={t('editor.backToGrid')} position="below-start">
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
            and order (GitHub #246). They never hide, not even in zen or
            under 560px: on a phone the list is not on screen at all, which
            is exactly where stepping through it without going back and
            forth matters most. Chevrons, never the curved arrows the tag
            row uses for undo - two identical pairs one row apart would
            read as one control drawn twice - and never plain arrows,
            because the mobile back-to-list arrow sits right beside
            them. */}
        <div className="shrink-0 flex items-center">
          <HoverLabel label={t('editor.navPrev')} position="below-start">
            <button
              type="button"
              tabIndex={mobileTabIndex}
              onClick={() => onNavigateList('prev')}
              disabled={!canGoPrev}
              aria-label={t('editor.navPrev')}
              className={HEADER_BTN_NARROW}
            >
              <CaretLeft size={HEADER_ICON} />
            </button>
          </HoverLabel>
          <HoverLabel label={t('editor.navNext')} position="below-start">
            <button
              type="button"
              tabIndex={mobileTabIndex}
              onClick={() => onNavigateList('next')}
              disabled={!canGoNext}
              aria-label={t('editor.navNext')}
              className={HEADER_BTN_NARROW}
            >
              <CaretRight size={HEADER_ICON} />
            </button>
          </HoverLabel>
        </div>
        <HeaderDivider />
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
            // Block Enter - no newlines in titles.
            if (e.key === 'Enter') { e.preventDefault(); return; }
            // Tab from title → tag input (skipping the star/trash
            // buttons so the flow is title → tags → body).
            if (e.key === 'Tab' && !e.shiftKey) {
              e.preventDefault();
              tagInputRef.current?.focus();
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
            : selected.type === 'login' ? t('editor.titlePlaceholderLogin')
            : selected.type === 'card' ? t('editor.titlePlaceholderCard')
            : selected.type === 'ssh-key' ? t('editor.titlePlaceholderSshKey')
            : t('editor.titlePlaceholder')
          }
          disabled={view === 'trash' || selected.locked === 1}
          readOnly={selected.locked === 1}
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
          className="pn-note-title flex-1 min-w-0 bg-transparent text-base sm:text-xl lg:text-2xl font-semibold tracking-tight focus:outline-none placeholder:text-neutral-400 dark:placeholder:text-neutral-700 placeholder:font-normal disabled:opacity-60 resize-none overflow-hidden leading-tight whitespace-nowrap [&::-webkit-scrollbar]:hidden"
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
            onConvertType={() => void convertNoteType()}
          />
        )}
        {/* Burn, pin and trash are not here. All three are rare, all three
            already had a permanent row in the "..." menu, and the header was
            carrying up to thirteen icons beside a title it kept truncating.
            Share is the one that stayed, because it is the one people reach
            for, and it now holds its place at every width instead of
            dropping out on a narrow pane.
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
                className="ms-2 inline-flex items-center gap-1.5 rounded-md px-2.5 py-2 text-sm font-medium text-emerald-600 dark:text-emerald-400 hover:text-emerald-500 hover:bg-emerald-500/10 transition shrink-0"
              >
              <ArrowCounterClockwise size={18} />
              <span className="hidden sm:inline">{t('editor.restore')}</span>
              </button>
            </HoverLabel>
            <HoverLabel label={t('editor.deleteForever')} position="below">
              <button
                onClick={() => setDeleteConfirm({ id: selected.id, title: selected.title || '' })}
                aria-label={t('editor.deleteForever')}
                className="ms-1 inline-flex items-center gap-1.5 rounded-md px-2.5 py-2 text-sm font-medium text-red-600 dark:text-red-400 hover:text-red-500 hover:bg-red-500/10 transition shrink-0"
              >
                <Trash size={18} />
                <span className="hidden sm:inline">{t('editor.deleteForever')}</span>
              </button>
            </HoverLabel>
          </>
        ) : (
          <>
          <ShareMenu
            open={showShareMenu}
            onClose={() => setShowShareMenu(false)}
            onToggle={() => setShowShareMenu((v) => !v)}
            zenMode={zenMode}
            selected={selected}
            exportSingleMarkdown={exportSingleMarkdown}
            exportSingleHtml={exportSingleHtml}
            printNote={printNote}
            handleBurnShare={handleBurnShare}
          />
          </>
        )}
        {/* One slot, one control per editor mode, exactly as the tag row
            does it outside zen. The formatting bar drives TipTap, which the
            source view unmounts, so in markdown mode this box carries the
            way back to formatted text instead of a toggle that reads as
            live and does nothing. Icon only, because Exit Zen is the one
            label zen affords and a second one would compete with it.
            Spec: ops/specs/editor-mode-toggle.md */}
        {zenMode && canSwitchEditorMode && selectedEditorMode === 'markdown' && (
          <HoverLabel label={t('editor.showFormatted')} position="below">
            <button
              type="button"
              onClick={toggleEditorMode}
              aria-label={t('editor.showFormatted')}
              className={ZEN_BTN_REST}
            >
              <TextAa size={HEADER_ICON} aria-hidden="true" />
            </button>
          </HoverLabel>
        )}
        {zenMode && markdownBody && selectedEditorMode !== 'markdown' && (
          // Zen's only formatting affordance, and testers kept missing
          // it: borderless with a 16px glyph it read as a label beside
          // the bordered Exit Zen button. MarkdownLogo's viewBox is
          // square but its ink is roughly 2:1.25, so it needs a larger
          // `size` than a solid icon to carry the same weight - hence
          // 20 against Exit Zen's X at 16. Box matches Exit Zen exactly
          // (h-8 w-8, same border and surface) so the two read as one
          // pair of controls.
          <HoverLabel label={zenToolbar ? t('editor.hideToolbar') : t('editor.showToolbar')} position="below">
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
              onClick={() => setShowNoteOptions((v) => !v)}
              aria-label={t('editor.noteOptions')}
              aria-expanded={showNoteOptions}
              // In zen it takes the bordered box its neighbours wear.
              className={
                zenMode
                  ? (showNoteOptions ? ZEN_BTN_ON : ZEN_BTN_REST)
                  : `${HEADER_BTN_BASE} w-8 ${showNoteOptions ? 'text-accent bg-accent/15' : HEADER_BTN_REST}`
              }
          >
            <DotsThreeOutlineVertical size={HEADER_ICON} aria-hidden="true" />
            </button>
          </HoverLabel>
          {showNoteOptions && (
            <NoteOptionsMenu
              {...noteGuards}
              isTrash={view === 'trash'}
              onRestore={() => void handleRestore(selected.id)}
              onDeleteForever={() => setDeleteConfirm({ id: selected.id, title: selected.title || '' })}
              onBurn={() => void handleBurnShare(selected)}
              anchorRef={noteOptionsButtonRef}
              onDuplicate={() => void handleDuplicate(selected.id)}
              onToggleStar={() =>
                void handleToggleStar(selected.id, selected.starred !== 1)
              }
              // Share is the one strip cell that comes and goes, because it
              // is the one action still in the header: two copies at one
              // width would read as the same control drawn twice. Zen hides
              // the header's copy, so zen is where the cell earns its place.
              {...(zenMode ? { onShare: () => setShowShareMenu(true) } : {})}
              onTrash={() => void handleTrash(selected.id)}
              onConvertType={() => void convertNoteType()}
              {...(canSwitchEditorMode
                ? { editorMode: selectedEditorMode, onToggleEditorMode: toggleEditorMode }
                : {})}
            />
          )}
        </div>
        {zenMode && (
          // Last control in the row and hard against the window's
          // right edge, so the centered tip was cut by the viewport
          // (nothing in this chain clips - see ui-patterns 18a step 4):
          // `bottom-left` opens it below, right-aligned, growing
          // inward. `hiddenAtSm` then drops it at the width the button
          // grows its own "Exit Zen" label, leaving the tip to do its
          // job only while the button is the bare X.
          <HoverLabel hiddenAtSm label={t('zen.exitHover')} position="below-end">
            <button
              type="button"
              onClick={() => setZenMode(false)}
              aria-label={t('zen.exitHover')}
              className="ms-1 shrink-0 inline-flex items-center justify-center gap-1.5 h-8 w-8 sm:w-auto sm:px-3 rounded-md border border-divider bg-surface-2 text-sm font-medium text-neutral-600 dark:text-neutral-300 hover:text-accent hover:border-accent/50 transition"
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
          note. Spec: ops/docs/ui-patterns.md (the not-backed-up state) */}
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
            onSettingsChange={(next) => {
              mutateSettings(() => next);
            }}
          />
        </div>
      ) : structuredBody ? (
        /* The same centered reading column the notes editor uses - the
           header row wears pn-content-col already, so a left-hugging body
           under a centered title read as two different layouts on wide
           screens (2026-08-22 review). */
        <div className="flex-1 overflow-y-auto">
        <div className="pn-content-col flex min-h-full flex-col">
          {!zenMode && view !== 'trash' && selected.locked !== 1 && (
            <TagInput
              key={`tags-${selected.id}`}
              ref={tagInputRef}
              tags={selected.tags}
              allTags={tagCounts.tags}
              onChange={(tags) => handleTagsChange(selected.id, tags)}
              onTabOut={() => {}}
              leading={folderChipFor(selected)}
            />
          )}
          {selected.locked === 1 && view !== 'trash' && (
            /* The same read-only hint the markdown editor shows - vault
               items and bookmarks were silently uneditable without it. */
            <div className="px-6 pt-3 flex items-center gap-2 text-[13px] text-amber-600 dark:text-amber-500">
              <PencilSimpleSlash size={13} className="shrink-0" aria-hidden="true" />
              <span className="truncate">{t('editor.readOnlyToggle')}</span>
              <span className="inline-flex items-center gap-1 shrink-0">
                <DotsThreeOutlineVertical size={13} aria-hidden="true" />
                {t('editor.menu')}
              </span>
            </div>
          )}
          {selected.type === 'link' ? (
            <BookmarkItem
              key={selected.id}
              note={selected}
              bookmarkKeys={bookmarkKeys}
              isTrash={view === 'trash'}
              onBodyChange={(id, body) => void handleBodyChange(id, body)}
              onPinProtectedChange={handleSetPinProtected}
            />
          ) : (
          <VaultItem
            key={selected.id}
            note={selected}
            isTrash={view === 'trash'}
            onTitleChange={handleTitleChange}
            onBodyChange={handleBodyChange}
            onPinProtectedChange={handleSetPinProtected}
            isPro={auth.isPro}
            onOpenUpgrade={() => setShowUpgrade({ trigger: 'totp' })}
          />
          )}
        </div>
        </div>
      ) : (
        <div ref={setNoteScroller} className={`flex-1 overflow-y-auto overflow-x-hidden pt-0 ${footerVisible ? 'pb-2' : 'pb-[max(0.5rem,env(safe-area-inset-bottom))]'}`}>
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
            <div ref={setStickyTagRow} className="sticky top-0 z-20 bg-surface-1/95 backdrop-blur">
            <TagInput
              key={`tags-${selected.id}`}
              ref={tagInputRef}
              tags={selected.tags}
              allTags={tagCounts.tags}
              onChange={(tags) => handleTagsChange(selected.id, tags)}
              onTabOut={() => editorRef.current?.focus()}
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
                    <HoverLabel label={t('editor.undo')} position="below">
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
                    <HoverLabel label={t('editor.redo')} position="below">
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
                    {/* The way back out of the source view, in the slot the
                        formatting-bar toggle holds the rest of the time.
                        Both controls act on the shape of the editor rather
                        than on the note body, so one place carries both and
                        neither is ever drawn twice. The glyph names the
                        DESTINATION, matching the "..." menu's row for the
                        same flip; the label spells it out where the row has
                        room, and under `sm` the glyph stands alone in the
                        row's own 32px square, which is where the tag row is
                        tightest. The label is a second copy of the
                        accessible name, so there is no hover tip on top of
                        it.
                        Spec: ops/specs/editor-mode-toggle.md */}
                    {selectedEditorMode === 'markdown' && canSwitchEditorMode && (
                      <button
                        type="button"
                        tabIndex={isMobile ? -1 : undefined}
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={toggleEditorMode}
                        aria-label={t('editor.showFormatted')}
                        className={`${HEADER_BTN_BASE} ${HEADER_BTN_REST} w-8 sm:w-auto sm:gap-1.5 sm:px-2 text-xs font-medium`}
                      >
                        <TextAa size={HEADER_ICON} aria-hidden="true" />
                        <span className="hidden sm:inline">{t('editor.showFormatted')}</span>
                      </button>
                    )}
                    {selectedEditorMode !== 'markdown' && (
                    <HoverLabel label={toolbarVisible ? t('editor.hideToolbar') : t('editor.showToolbar')} position="below">
                      <button
                        type="button"
                        tabIndex={isMobile ? -1 : undefined}
                        onMouseDown={(e) => e.preventDefault()}
                        onClick={toggleToolbar}
                        aria-label={toolbarVisible ? t('editor.hideToolbar') : t('editor.showToolbar')}
                        aria-pressed={toolbarVisible}
                        className={`${HEADER_BTN_BASE} w-8 ${toolbarVisible ? 'text-accent bg-accent/15' : HEADER_BTN_REST}`}
                      >
                        {/* 20, not the row's 18: the markdown mark's ink is
                            roughly 2:1.25 inside a square viewBox, so at the
                            shared size it reads visibly lighter than the
                            solid glyphs beside it. */}
                        <MarkdownLogo size={20} aria-hidden="true" />
                      </button>
                    </HoverLabel>
                    )}
                    {/* The reading width is not here. It only ever appeared
                        past a 56rem pane, it is a taste somebody sets once,
                        and Settings > Appearance carries the same axis at
                        every width. Zen keeps its own copy, because zen has
                        no settings sheet to reach. */}
                  </div>
                </div>
                )
              }
            />
            </div>
          )}
          {!zenMode && selected.type === 'journal' && (
            <TrackerPills
              data={(selected.trackers as JournalTrackerData) ?? {}}
              onChange={(next) => handleTrackersChange(selected.id, next)}
              trackerSettings={userSettings.trackerSettings}
              onSettingsChange={(ts) => mutateSettings((prev) => ({ ...prev, trackerSettings: ts }))}
              medications={userSettings.medications}
              onMedicationsChange={(meds) => mutateSettings((prev) => ({ ...prev, medications: meds }))}
              readOnly={view === 'trash' || selected.locked === 1}
              isPro={auth.isPro}
              onOpenUpgrade={() => setShowUpgrade({ trigger: null })}
              collapsed={mobileEditing}
            />
          )}
          {proUnlocked(auth.isPro) && selected.type === 'journal' && isWeekJournal(selected) && (
            <WeekInReview notes={notes} medications={userSettings.medications} />
          )}
          {selected.locked === 1 && view !== 'trash' && (
            <div className="mx-4 sm:mx-6 mt-1 mb-3 flex items-center gap-2 text-[13px] text-amber-600 dark:text-amber-500">
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
              /* No corner here, and nothing to put in one. Find drives the
                 rich editor, which is unmounted in this view, and the outline
                 has no headings to read off a plain textarea. The way back to
                 formatted text is the tag row's button, the first row of the
                 "..." menu, and the link under the word count. */
              <MarkdownSourceEditor
                key={`${selected.id}-${editorRevision}`}
                value={selected.body}
                onChange={(body) => { handleBodyChange(selected.id, body); setWcBody(body); }}
                readOnly={view === 'trash' || selected.locked === 1}
              />
            ) : (
              <Editor
                key={`${selected.id}-${editorRevision}`}
                ref={editorRef}
                noteId={selected.id}
                value={selected.body}
                onChange={(body) => { handleBodyChange(selected.id, body); setWcBody(body); }}
                readOnly={view === 'trash' || selected.locked === 1}
                onFocusChange={setEditorFocused}
                toolbarVisible={zenMode ? zenToolbar : toolbarVisible}
                isPro={auth.isPro ?? false}
                onOpenUpgrade={() => setShowUpgrade({ trigger: 'callout' })}
                bodyControls={bodyControls}
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
                  <WordCount body={wcBody || selected.body} />
                </div>
                {view !== 'trash' && selected.locked !== 1 && (
                  <button
                    type="button"
                    onClick={toggleEditorMode}
                    className="shrink-0 select-none text-xs text-neutral-400 dark:text-neutral-600 hover:text-neutral-600 dark:hover:text-neutral-400 hover:underline transition"
                  >
                    {selectedEditorMode === 'markdown' ? t('editor.showFormatted') : t('editor.showMarkdown')}
                  </button>
                )}
              </div>
            )}
          </div>
          </div>
        </div>
      )}
    </>
  );
}
