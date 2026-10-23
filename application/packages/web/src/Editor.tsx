import {
  forwardRef,
  useCallback,
  useContext,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { FormatBarContext } from './formatBarContext';
import { useEditor, EditorContent, type Editor as TipTapEditor, type JSONContent } from '@tiptap/react';
import { readDocCache, writeDocCache, DOC_CACHE_MIN_BYTES } from './editorDocCache';
import { perfSpan } from './perf';
import StarterKit from '@tiptap/starter-kit';
import Placeholder from '@tiptap/extension-placeholder';
import Link from '@tiptap/extension-link';
import { LinkAddressPill } from './LinkAddressPill';
import { findHeadingPos, headingPosByCode } from './noteHeadings';
import TableRow from '@tiptap/extension-table-row';
import TableCell from '@tiptap/extension-table-cell';
import TableHeader from '@tiptap/extension-table-header';
import Underline from '@tiptap/extension-underline';
import Superscript from '@tiptap/extension-superscript';
import Subscript from '@tiptap/extension-subscript';
import 'katex/dist/katex.min.css';

import { Color } from '@tiptap/extension-color';
import { FontSize } from '@tiptap/extension-text-style/font-size';
import { FontFamily } from '@tiptap/extension-text-style/font-family';
import { TextSelection, type EditorState } from '@tiptap/pm/state';
import { Fragment, type Node as ProseMirrorNode } from '@tiptap/pm/model';
import { splitIndex } from './noteSplit';
import { Markdown, type MarkdownStorage } from 'tiptap-markdown';

// TipTap 3 types editor.storage as an empty augmentable interface instead of a
// permissive record, so the markdown storage tiptap-markdown registers has to
// be declared once. Both tiptap-markdown 0.8 and 0.9 export MarkdownStorage,
// so this compiles on either side of the TipTap 3 migration.
declare module '@tiptap/core' {
  interface Storage {
    markdown: MarkdownStorage;
  }
}
import { invisibleCharacterBuilders, LazyInvisibleCharacters } from './editorInvisibles';
import { FaviconChips, refreshFavicons } from './editorFavicons';
import { EncryptedImage, isPictureSelection, sanitizePastedHtml } from './EncryptedImage';
import { ClipboardSpacing, copySelectionAs } from './clipboardSpacing';
import { EncryptedAttachment, holdsOneFile, requestAttachmentRename } from './EncryptedAttachment';
import { WikiLink } from './NoteLink';
import { AudioRecordingBanner, type AudioRecordingState } from './AudioRecorder';
import { LinkSheet } from './LinkSheet';
import { Callout, CalloutTitle } from './Callout';
import { proUnlocked } from './demo';
import { stepKanban } from './kanban';
import { Footnotes, carriedSection } from './footnotes';
import { useIsMobile } from './useIsMobile';
import { ContextMenu, useContextMenu, isTouchContextMenu, isLongPressEcho, type ContextMenuItem } from './ContextMenu';
import {
  iconCopy, iconEditPencil, iconExternal, iconTrash,
  ClipboardText, Code, FileMd, Highlighter, Link as LinkGlyph, Plus, Scissors, SortAscending, SortDescending, TextB, TextItalic, TextStrikethrough,
} from './icons';
import { Spoiler } from './editorSpoiler';
import { InlineCodeCopy, inlineCodeHint } from './editorCodeCopy';
import { AddLineBetweenBlocks } from './editorAddLine';
import { LinkModifierOpen, MarkdownLinkTyping, SelfLinkTyping, linkHrefAt, linkSelectionIfUrl, openLinkHref } from './editorLinks';
import { createLongPressGuard } from './softKeyboard';
import { planLineSort } from './sortLines';
import { activeLocale } from './i18n';
import { readColorPref } from './editorPrefs';
import { DEFAULT_HIGHLIGHT, HIGHLIGHT_COLORS } from './editorColors';
import { useTheme, readLineSpacing, readCopyFormat } from './theme';
import { SearchHighlight, setSearchQuery, getSearchInfo, clearSearch } from './editorSearch';
import { FindBar } from './FindBar';
import { ReplaceBar } from './ReplaceBar';
import { OutlinePanel } from './OutlinePanel';
import { TableControls } from './TableControls';
import { Toolbar } from './EditorToolbar';
import { useEditorPanels } from './useEditorPanels';
import { NodeViewMount } from './editorNodeViewMount';
import { APP_KEYS, matchesKey } from './shortcutMatch';
import { useDebouncedMarkdownSave } from './useDebouncedMarkdownSave';
import {
  TextStyleMarkdown,
  TaskListInputRule,
  TaskListWithMarkdown,
  TaskItemMobileSafe,
  fixEmptyTaskItems,
  collapseMediaGaps,
  cleanEmptyTaskItems,
  CodeBlockPlainCopy,
  lowlight,
  CodeBlockWithCopy,
  InlineMathWithMarkdown,
  BlockMathWithMarkdown,
  HighlightWithMarkdown,
  COPY_BOX_LANGUAGE,
  TrailingParagraph,
  PlainEscape,
  MediaGapCleaner,
  TextAlignOurLeft,
  ParagraphWithMarkdown,
  HeadingWithMarkdown,
  HardBreakWithMarkdown,
  TextWithMarkdown,
  TableWithMarkdown,
  stepTableCell,
  indentListItem,
  indentText,
  NbspParagraphCleaner,
  MixedListSplitter,
  clipboardRenderer,
  markdownForClipboard,
  replaceBodyUndoably,
} from './editorExtensions';

type Props = {
  /** Initial markdown content. Only read on mount - use a `key` prop to force reload. */
  value: string;
  /** Called with the latest markdown, debounced by 300ms of idle typing. */
  onChange: (markdown: string) => void;
  /** Id of the note being edited - enables the synchronous close-flush
   *  stash (flushStash.ts) so a tab closed mid-debounce loses nothing. */
  noteId?: string;
  /** When true, nothing edits the note: no toolbar, no "Add a line at
   *  the top" zone, no replace. Find and the outline stay, because they only read it. */
  readOnly?: boolean;
  /**
   * A static rendering: the note history preview. Read-only, and without the
   * corner, the bars or their shortcuts. The note editor stays mounted
   * behind that modal, so a second editor claiming Cmd/Ctrl+F would open a
   * second bar.
   */
  preview?: boolean;
  /** Called when the editor gains or loses focus. */
  onFocusChange?: (focused: boolean) => void;
  /**
   * Whether the formatting toolbar is shown. Controlled by NotesView so the
   * Hide/Show toggle can live on the tag row. Defaults to visible.
   */
  toolbarVisible?: boolean;
  /** Whether the user has Pro. Gates the replace bar. */
  isPro?: boolean;
  /** Opens the upgrade modal when a free account asks for the replace bar. */
  onOpenUpgrade?: (trigger: 'replace' | null) => void;
  /** Hides the encrypted image / attachment / audio group - see Toolbar. */
  hideEncryptedMedia?: boolean;
  /** Takes the picture and file buttons' files when that group is hidden - see Toolbar. */
  onInsertFiles?: (files: File[]) => void;
  /**
   * Controls for the BODY, rendered in the top-right slot beside the
   * collapsed outline pill: find, the rich/markdown switch, invisible
   * characters. They are built by NoteEditorPane, which owns their state,
   * and land here because this is the corner they act on. Hidden while a
   * find or replace bar is up - the bar owns the corner then, and closes
   * itself.
   */
  bodyControls?: ReactNode;
  /**
   * The Connections pill and panel, drawn between the other pills and the
   * outline. Its open state lives here with the outline's, so the corner
   * shows one panel at a time.
   */
  connections?: (open: boolean, onOpenChange: (open: boolean) => void) => ReactNode;
  /**
   * Where the format bar goes when it sits at the bottom: a row the pane
   * keeps under its scrolling column. Nothing is drawn until it exists.
   */
  toolbarSlot?: HTMLElement | null;
  /** The format bar's "Show markdown"; absent where the note has no Markdown view. */
  onShowMarkdown?: () => void;
  /**
   * Called when a file chip in this note is renamed and that note's name
   * lives outside the document too. Only fires for a note holding exactly
   * one file - see the wiring below.
   */
  onRenameFile?: (name: string) => void;
  /**
   * The note is one the Files pillar made. While it holds one file, a picture
   * or a PDF in it renders as a card showing the file rather than as a chip;
   * a note of several files keeps its chips.
   */
  fileNote?: boolean;
  /** Whether a ticked task moves below the open ones (the synced
   *  `sinkCheckedTasks` setting). Defaults to on. */
  sinkCheckedTasks?: boolean;
  /** The empty body's hint, when the item type has its own ("Add an agenda..." on an event). */
  placeholder?: string;
  /** Called once with the editor after it is created. The history
   *  comparison adds its decorations through it. */
  onReady?: (editor: TipTapEditor) => void;
};

/**
 * TipTap-based live inline markdown editor.
 *
 * Type `# heading`, `**bold**`, `- list`, etc. and they render in place.
 * The parent passes a unique `key` (the note id) so switching notes
 * remounts the editor with fresh content.
 *
 * The toolbar above the editor is for beginners who aren't fluent in
 * markdown syntax - clicking a button just inserts the same markdown
 * they could type by hand.
 */
export type EditorHandle = {
  /** Focus the body. False when there is no editor to focus yet. */
  focus: () => boolean;
  /** Open the find-in-note bar, or close it if it is already open. The
   *  corner magnifier and Cmd/Ctrl+F share this one action. */
  toggleFind: () => void;
  /** Open the find-and-replace bar, or close it if it is already open. The
   *  "..." menu row and Option/Alt+Cmd/Ctrl+F share this one action, and the
   *  Pro gate sits behind it (useEditorPanels.ts). */
  toggleReplace: () => void;
  /** Scroll to the attachment chip / image whose pn:file/pn:img URI contains
   *  `uuid` and flash-highlight it (jump-to-file from the Files pillar). */
  scrollToFile: (uuid: string) => void;
  /** Jump to the attachment chip holding `uuid` and open its rename field.
   *  The Files pillar's Rename row, once the note is open. */
  startRenameFile: (uuid: string) => void;
  /** Scroll the heading a note-link names to the top and flash it, with the
   *  caret at its start. `onMissing` runs when the note holds no such heading. */
  scrollToHeading: (heading: string, onMissing?: () => void) => void;
  /** The same for a shortcut's heading code. A code that matches no heading
   *  leaves the note at its top, without a message. */
  scrollToHeadingCode: (itemId: string, code: string) => void;
  /** Open the find bar on the first of `candidates` the text holds, hits
   *  marked: the list search following into the open note (GitHub #288). A
   *  no-op in the history preview, which has no bar, and when the text as
   *  written holds none of them. */
  highlightSearch: (candidates: string[]) => void;
  /** Close the find bar if the search opened it; a bar the reader opened
   *  stays. Runs when the list search is emptied. */
  clearSearchHighlight: () => void;
  /** Raw TipTap editor instance - used by NotesView to wire wiki-link navigation. */
  getEditor: () => TipTapEditor | null;
  /** Put a rewritten body in as one undoable step (replaceBodyUndoably).
   *  False when this editor cannot take it, the history preview included. */
  replaceBody: (md: string) => boolean;
  /** The note as two Markdown halves for "Split note", cut at `splitIndex`
   *  (noteSplit.ts) from the cursor. Null when the note cannot be divided. */
  splitParts: () => { head: string; tail: string } | null;
  /** Serialize and save any pending debounced edit NOW, synchronously.
   *  The editor-mode toggle calls this before it swaps editors: the
   *  unmount flush runs after the replacement has already rendered, so
   *  without this the last debounce window of typing is not in the body
   *  the replacement mounts with. */
  flushPendingSave: () => void;
};

/** Room under a touch selection for the drag handles Android hangs below it. */
const TOUCH_HANDLE_HEIGHT = 32;

const EditorInner = forwardRef<EditorHandle, Props & { cachedDoc?: JSONContent }>(function EditorInner(
  { value, onChange, readOnly = false, onFocusChange, toolbarVisible = true, isPro = false, onOpenUpgrade, noteId, cachedDoc, hideEncryptedMedia, onInsertFiles, bodyControls, connections, toolbarSlot, onShowMarkdown, onRenameFile, fileNote = false, preview = false, sinkCheckedTasks = true, placeholder, onReady },
  ref
) {
  const { t } = useTranslation('editor');
  const { onUpdate, useFlushOnExit, flushNow } = useDebouncedMarkdownSave({ value, onChange, readOnly, noteId });

  /**
   * Back-reference to the editor, for callbacks declared above `useEditor`.
   * The panels hook and the click-to-add-a-line target both need the editor
   * from a callback that is built before it exists, so they read it lazily.
   */
  const editorRef = useRef<TipTapEditor | null>(null);

  /**
   * Stable handle on the rename callback. The extension below captures it
   * once, when the editor is built, so it has to read the current prop
   * rather than the one that existed then.
   */
  const onRenameFileRef = useRef(onRenameFile);
  onRenameFileRef.current = onRenameFile;
  const sinkCheckedRef = useRef(sinkCheckedTasks);
  sinkCheckedRef.current = sinkCheckedTasks;
  const placeholderRef = useRef(placeholder);
  placeholderRef.current = placeholder;
  // Read by a Kanban board's Add column, which is Pro.
  const isProRef = useRef(isPro);
  isProRef.current = isPro;
  const onOpenUpgradeRef = useRef(onOpenUpgrade);
  onOpenUpgradeRef.current = onOpenUpgrade;

  const isMobile = useIsMobile();
  const { spellcheck, invisibles, favicons } = useTheme();
  const barAtBottom = useContext(FormatBarContext).position === 'bottom';
  const rootRef = useRef<HTMLDivElement>(null);
  // Long-press keyboard guard for the body. See the handleDOMEvents block in
  // editorProps; the note title owns a second one in NotesView.
  const longPress = useMemo(createLongPressGuard, []);
  useEffect(() => longPress.cancel, [longPress]);
  const [linkPopoverOpen, setLinkPopoverOpen] = useState(false);
  const linkBtnRef = useRef<HTMLButtonElement | null>(null);
  const linkFallbackRef = useRef<HTMLDivElement | null>(null);
  // The link panel lines up under the toolbar's link button. That button is
  // absent in two states the shortcut still reaches - the toolbar is hidden,
  // or the button has folded into the collapsed overflow row - so the anchor
  // resolves on every measurement instead of being captured once, and falls
  // back to a zero-height marker at the top of the editor pane.
  const linkAnchorRef = useMemo(
    () => ({ get current() { return (linkBtnRef.current ?? linkFallbackRef.current) as HTMLElement | null; } }),
    [],
  );
  /**
   * The link button and its shortcut, in one place because they answer the
   * same question and must answer it the same way.
   *
   * A selection that is already an address is linked on the spot: the
   * reader has said where it goes, so the panel would only ask them to
   * type what they already selected. Everything else opens the panel.
   */
  const askForLink = useCallback(() => {
    const ed = editorRef.current;
    if (ed && linkSelectionIfUrl(ed)) return;
    setLinkPopoverOpen(true);
  }, []);

  const linkMenu = useContextMenu();

  /**
   * The editor state as it stood before the pointer went down. On macOS a
   * right click on a word selects that word before `contextmenu` fires, so
   * only this tells a selection the reader made from a click on a
   * misspelled word, which keeps the browser menu and its suggestions.
   */
  const preClickRef = useRef<EditorState | null>(null);
  const notePreClickState = () => {
    preClickRef.current = editorRef.current?.state ?? null;
  };

  /**
   * The menu for a right click inside a selection: the clipboard, the marks
   * of the toolbar, a link, and Sort when the selection is two or more lines
   * of one kind. Cut and Copy go through the browser so the editor's own
   * copy path writes the clipboard. "Copy as plain text" and "Copy as Markdown"
   * write that text alone, so every app pastes what the label says. Highlight applies the colour the
   * toolbar remembers, or removes a highlight that is already there.
   */
  const selectionMenuItems = (ed: TipTapEditor): ContextMenuItem[] => {
    const remembered = readColorPref('highlight');
    const highlight = HIGHLIGHT_COLORS.find((c) => c.name.toLowerCase() === remembered) ?? DEFAULT_HIGHLIGHT;
    const toggleHighlight = () => {
      const chain = ed.chain().focus();
      if (ed.isActive('highlight')) chain.unsetHighlight().run();
      else (highlight.value ? chain.setHighlight({ color: highlight.value }) : chain.setHighlight()).run();
    };
    const items: ContextMenuItem[] = [
      { label: t('bodyMenu.cut'), icon: <Scissors size={14} />, onSelect: () => { ed.commands.focus(); document.execCommand('cut'); } },
      { label: t('common:actions.copy'), icon: iconCopy(), onSelect: () => { ed.commands.focus(); document.execCommand('copy'); } },
      { label: t('bodyMenu.copyAsPlain'), icon: <ClipboardText size={14} />, onSelect: () => copySelectionAs(ed, 'plain') },
      { label: t('bodyMenu.copyAsMarkdown'), icon: <FileMd size={14} />, onSelect: () => copySelectionAs(ed, 'markdown') },
      { type: 'separator' },
      { label: t('toolbar.bold'), icon: <TextB size={14} />, checked: ed.isActive('bold'), onSelect: () => ed.chain().focus().toggleBold().run() },
      { label: t('toolbar.italic'), icon: <TextItalic size={14} />, checked: ed.isActive('italic'), onSelect: () => ed.chain().focus().toggleItalic().run() },
      { label: t('toolbar.strikethrough'), icon: <TextStrikethrough size={14} />, checked: ed.isActive('strike'), onSelect: () => ed.chain().focus().toggleStrike().run() },
      { label: t('toolbar.highlight'), icon: <Highlighter size={14} />, checked: ed.isActive('highlight'), onSelect: toggleHighlight },
      { label: t('toolbar.inlineCode'), icon: <Code size={14} />, checked: ed.isActive('code'), onSelect: () => ed.chain().focus().toggleCode().run() },
      { label: t('link.popoverLabel'), icon: <LinkGlyph size={14} />, onSelect: askForLink },
    ];
    const sort = planLineSort(ed.state, activeLocale(), sinkCheckedRef.current);
    if (sort) {
      const doc = ed.state.doc;
      items.push({ type: 'separator' }, {
        label: t(sort.direction === 'asc' ? 'bodyMenu.sortAsc' : 'bodyMenu.sortDesc'),
        icon: sort.direction === 'asc' ? <SortAscending size={14} /> : <SortDescending size={14} />,
        onSelect: () => {
          // The plan holds positions in the document it was made for.
          if (ed.state.doc !== doc) return;
          ed.view.dispatch(sort.apply(ed.state.tr));
          ed.commands.focus();
        },
      });
    }
    return items;
  };

  /**
   * Right-click on a URL link: Open, Copy, Edit, Remove.
   *
   * This is the one route to a link that does not go through the caret, and
   * every other route does: the toolbar button and Cmd/Ctrl+Shift+K both
   * act on the link the cursor is in, so they answer "Add link" for a
   * cursor anywhere else and offer no Remove at all (GitHub #293).
   *
   * `ContextMenu.tsx` states that a link and editable text keep the
   * browser's own menu, and this is a deliberate exception to both halves,
   * for the same reason `NoteLink.tsx` is one: nothing in the platform menu
   * can take a link off a word. A touch long press on a link opens the
   * same menu, and keeps the word the long press selected (below).
   */
  const touchLinkMenuAt = useRef(0);
  const stopTouchMenuWatch = useRef<(() => void) | null>(null);
  useEffect(() => {
    if (!linkMenu.state) stopTouchMenuWatch.current?.();
  }, [linkMenu.state]);
  const openBodyMenu = (e: React.MouseEvent) => {
    const ed = editorRef.current;
    // Shift + right click always leaves the browser's own menu.
    if (!ed || readOnly || e.shiftKey) return;
    // Android fires the long press twice; only the first carries the finger.
    if (isLongPressEcho(e.nativeEvent)) {
      if (touchLinkMenuAt.current > performance.now() - 1500) e.preventDefault();
      return;
    }
    const touch = isTouchContextMenu(e);
    const at = ed.view.posAtCoords({ left: e.clientX, top: e.clientY });
    if (!at) return;
    const href = linkHrefAt(ed.state, at.pos);
    if (touch && !href) return;
    if (!href) {
      // Only a click inside a selection that existed before it gets the app
      // menu. A caret, an empty line, a word and a selected picture keep the
      // browser menu, with its spelling, Look Up, Paste and Copy image.
      // Spec: ops/issues/archive/0414.md, ops/issues/0488.md
      const before = preClickRef.current;
      const sel = before?.selection;
      if (!before || !sel || sel.empty || before.doc !== ed.state.doc || at.pos < sel.from || at.pos > sel.to) return;
      if (isPictureSelection(sel)) return;
      if (!ed.state.selection.eq(sel)) ed.view.dispatch(ed.state.tr.setSelection(sel));
      linkMenu.open(e, selectionMenuItems(ed));
      return;
    }
    // A right click does not move the caret in every browser, and Edit and
    // Remove both act on the mark the caret is in.
    if (touch) touchLinkMenuAt.current = performance.now();
    else ed.chain().focus().setTextSelection(at.pos).run();
    const items: ContextMenuItem[] = [
      { label: t('link.menuOpen'), onSelect: () => openLinkHref(ed, href), icon: iconExternal() },
      {
        label: t('link.menuCopy'),
        onSelect: () => { void navigator.clipboard.writeText(href).catch(() => { /* denied: no clipboard, no feedback */ }); },
        icon: iconCopy(),
      },
      { label: t('link.menuEdit'), onSelect: () => setLinkPopoverOpen(true), icon: iconEditPencil() },
      {
        label: t('link.menuRemove'),
        onSelect: () => { ed.chain().focus().extendMarkRange('link').unsetLink().run(); },
        destructive: true,
        icon: iconTrash(),
      },
    ];
    if (!touch) {
      linkMenu.open(e, items);
      return;
    }
    // The long press has already selected the word under the finger, and that
    // selection is the start of a drag over more text (issue #454), so it
    // stays. The menu opens clear of the word and the handles that hang below
    // it, and a drag of either handle closes it.
    const word = window.getSelection();
    const band = () => {
      const now = window.getSelection();
      const box = (now && now.rangeCount ? now.getRangeAt(0) : null)?.getBoundingClientRect()
        ?? ed.view.coordsAtPos(at.pos);
      return { top: box.top, bottom: box.bottom + TOUCH_HANDLE_HEIGHT };
    };
    linkMenu.open(e, items, false, band);
    stopTouchMenuWatch.current?.();
    const start = word && word.rangeCount ? word.getRangeAt(0).cloneRange() : null;
    const onChange = () => {
      const now = window.getSelection();
      const r = now && now.rangeCount ? now.getRangeAt(0) : null;
      if (start && r && r.startContainer === start.startContainer && r.startOffset === start.startOffset
        && r.endContainer === start.endContainer && r.endOffset === start.endOffset) return;
      stopTouchMenuWatch.current?.();
      linkMenu.close();
    };
    document.addEventListener('selectionchange', onChange);
    stopTouchMenuWatch.current = () => {
      document.removeEventListener('selectionchange', onChange);
      stopTouchMenuWatch.current = null;
    };
  };

  const [audioState, setAudioState] = useState<AudioRecordingState>('idle');
  const [audioDuration, setAudioDuration] = useState(0);
  const audioStopRef = useRef<(() => void) | null>(null);

  const handleAudioStateChange = useCallback(
    (state: AudioRecordingState, duration: number) => {
      setAudioState(state);
      setAudioDuration(duration);
    },
    [],
  );

  // VITE_PERF span over editor creation - the markdown parse happens
  // synchronously inside the first useEditor render (#150); later renders
  // reuse the instance and the span reads ~0.
  const endEditorCreate = perfSpan('editorCreate');
  const editor = useEditor({
    extensions: [
      StarterKit.configure({
        // Disable StarterKit's codeBlock - we register CodeBlockWithCopy
        // below to get a hover-revealed Copy button.
        codeBlock: false,
        // Inline code copies on a modifier click (editorCodeCopy); the hint
        // says so on hover.
        code: { HTMLAttributes: { title: inlineCodeHint() } },
        // TipTap 3's StarterKit absorbed extensions we already ship our own
        // way. Disable the overlaps so nothing registers twice:
        // - link: our Link.extend below carries the favicon renderHTML and
        //   the non-inclusive mark behavior.
        // - underline: registered standalone right after this block.
        // - trailingNode: our TrailingParagraph implements the same idea
        //   tuned to our media blocks; two trailing-node extensions fight.
        // - listKeymap: new list Backspace/Delete behavior in v3; keep the
        //   v2-equivalent behavior our custom Tab handling was built around,
        //   revisit deliberately if wanted.
        link: false,
        underline: false,
        trailingNode: false,
        listKeymap: false,
        // ParagraphWithMarkdown below carries the empty-paragraph markdown
        // spec; two paragraph extensions must not both register.
        paragraph: false,
        // HeadingWithMarkdown carries the alignment-aware markdown spec, same
        // reasoning as paragraph above.
        heading: false,
        // HardBreakWithMarkdown writes the next line's quote prefix early.
        hardBreak: false,
        // TextWithMarkdown escapes text so it reads back as itself.
        text: false,
        // Footnotes brings a document with room for its section after the body.
        document: false,
        // Drop indicator for dragged text and files. The library default is a
        // 1px BLACK bar, which is the same "where is it going to land" problem
        // the gap cursor had in dark and sepia - invisible against the surface
        // it is drawn on. Match the gap cursor's treatment: accent-colored and
        // thick enough to read as a real insertion point.
        // Spec: ops/docs/design-decisions.md (Drop cursor visibility)
        dropcursor: { color: 'rgb(var(--pn-accent))', width: 2 },
      }),
      ParagraphWithMarkdown,
      HeadingWithMarkdown,
      HardBreakWithMarkdown,
      TextWithMarkdown,
      Underline,
      // TextStyleMarkdown must come before Color: Color sets the `color`
      // attribute on the textStyle mark, so that mark has to exist first.
      TextStyleMarkdown,
      Color.configure({ types: ['textStyle'] }),
      // Both hang off the textStyle mark above and are serialized by
      // textStyleCss - see the warning there before adding a third.
      FontSize,
      FontFamily,
      Placeholder.configure({
        placeholder: ({ node }) =>
          node.type.name !== 'codeBlock'
            ? (placeholderRef.current ?? t('placeholder'))
            : node.attrs['language'] === COPY_BOX_LANGUAGE
              ? t('copyBox.placeholder')
              : t('codeBlock.placeholder'),
      }),
      Link.extend({
        // TipTap defaults inclusive to the value of autolink (true), which
        // means typing at the end of a link extends the mark. We want the
        // opposite: typing after a link should be plain text. Autolink
        // still re-scans on input, so new URLs typed after an existing
        // link still get auto-linked - this only stops the mark from
        // silently bleeding into adjacent text.
        inclusive() { return false; },
      }).configure({
        // Who opens a clicked link is decided in one place, and it is not
        // here: `LinkModifierOpen` reads the pointer, the modifier and
        // whether the note is being edited, then hands the URL to
        // `openExternal`. This option cannot make any of those
        // distinctions - it is fixed when the editor is built, and it
        // opens through window.open, which Android's WebView turns into an
        // in-place navigation that replaces the app with the web page
        // (#241) while WKWebView merely swallows the call.
        openOnClick: false,
        autolink: true,
        linkOnPaste: true,
        // protocols omitted - http, https, mailto are defaults.
        // Passing them explicitly triggers linkifyjs "already initialized"
        // warnings because registerCustomProtocol runs after first parse.
        HTMLAttributes: {
          rel: 'noopener noreferrer nofollow',
          target: '_blank',
          class: 'text-accent hover:text-accent-hover cursor-pointer',
        },
      }),
      LinkModifierOpen,
      SelfLinkTyping,
      MarkdownLinkTyping,
      TaskListWithMarkdown.configure({
        HTMLAttributes: {
          class: 'task-list',
        },
      }),
      TaskItemMobileSafe.configure({
        nested: true,
        HTMLAttributes: {
          class: 'task-item',
        },
        sinkChecked: () => sinkCheckedRef.current,
      }),
      TaskListInputRule,
      TableWithMarkdown.configure({
        resizable: false,
        HTMLAttributes: {
          class: 'pn-table',
        },
        formulasUnlocked: () => proUnlocked(isProRef.current),
      }),
      TableRow,
      TableCell,
      TableHeader,
      // ALWAYS registered, including when `hideEncryptedMedia` is set. It is
      // tempting to drop these two for the Markdown pillar so no event route
      // can reach the encrypted blob stores, and it silently destroys files:
      // `EncryptedImage` is the only thing that defines the `image` NODE TYPE,
      // so without it `![](path.png)` has nothing to parse into, every image in
      // the document is dropped on load, and the next keystroke writes the file
      // back to disk with its images gone. `hideEncryptedMedia` therefore stays
      // what its name says - a toolbar affordance - and the plaintext boundary
      // is held where it can be held without breaking the document model: the
      // Markdown pane's own paste and drop capture handlers.
      // Spec: ops/docs/archive/markdown-folder.md (section 5, isolation)
      // The paste guard on the upload itself rides on the same flag:
      // ops/docs/archive/paste-pictures.md (section 3.3)
      EncryptedImage.configure({ plaintextOnly: !!hideEncryptedMedia }),
      EncryptedAttachment.configure({
        onRename: (name: string) => {
          // A note whose name lives in its title as well holds exactly one
          // file: that is how the Files pillar creates it. A note holding
          // several, or a file pasted into a written note, has a title of
          // its own that a single chip must not overwrite.
          const ed = editorRef.current;
          if (!ed || !holdsOneFile(ed.state.doc)) return;
          onRenameFileRef.current?.(name);
        },
        // Read once: the editor is keyed by note, so a note changing type
        // remounts it with the new value. Whether the note holds one file is
        // the chip's own question, asked again after every edit.
        filePreview: fileNote,
      }),
      WikiLink,
      CalloutTitle,
      Callout.configure({
        kanbanUnlocked: () => proUnlocked(isProRef.current),
        onUpgrade: () => onOpenUpgradeRef.current?.(null),
      }),
      Footnotes,
      TrailingParagraph,
      PlainEscape,
      MediaGapCleaner,
      NbspParagraphCleaner,
      MixedListSplitter,
      ClipboardSpacing,
      // defaultLanguage 'plaintext': an untagged fence stays plain instead
      // of lowlight auto-guessing a grammar and tinting random words.
      CodeBlockWithCopy.configure({ lowlight, defaultLanguage: 'plaintext' }),
      CodeBlockPlainCopy,
      SearchHighlight,
      // ==highlight== mark; input + paste rules ship with the extension.
      // multicolor lets the toolbar's palette set a `color` attribute; a
      // plain highlight still stores as ==text== (Obsidian syntax) and a
      // colored one as inline <mark style>, per HighlightWithMarkdown.
      HighlightWithMarkdown.configure({ multicolor: true }),
      // ||spoiler|| mark, blurred until the caret or a click shows it.
      Spoiler,
      InlineCodeCopy,
      AddLineBetweenBlocks,
      // <sup>/<sub> marks (Mod+. / Mod+,). Same inline-HTML round-trip.
      Superscript,
      // Subscript keeps its toolbar button but loses its default Mod-,
      // shortcut: Cmd+, is the app-wide "open settings" key, and both fired
      // at once (subscript toggled AND settings opened). The toolbar hint
      // for subscript is already null for the same reason.
      Subscript.extend({
        addKeyboardShortcuts() {
          return {};
        },
      }),
      InlineMathWithMarkdown.configure({ katexOptions: { throwOnError: false } }),
      BlockMathWithMarkdown.configure({ katexOptions: { throwOnError: false } }),
      // Alignment on the two block types that can carry prose, plus images.
      // Prose is stored as an inline-styled <p>/<h*> by ParagraphWithMarkdown
      // / HeadingWithMarkdown, the same HTML round-trip our colored text uses;
      // an image keeps plain markdown and carries the value in its own
      // attribute suffix instead (`![](src){width=50 align=center}`), which is
      // why `image` belongs here rather than getting its own command.
      TextAlignOurLeft.configure({ types: ['heading', 'paragraph', 'image'] }),
      // Proofreading overlay: pilcrows, space dots, line-break arrows. Purely
      // decorations - it never touches the document. `visible` is seeded from
      // the persisted preference; the footer toggle drives it after mount.
      // `builders` is the stock list with our space builder swapped in, so a
      // space dot inside a link stops splitting the <a> - see editorInvisibles.
      // The Lazy variant defers ALL decoration work until the toggle is on -
      // upstream built the whole-document set at creation even while hidden,
      // which was ~600 ms of every huge-note open (#150). injectCSS is dead
      // in the lazy plugin; the base rules are vendored in index.css.
      LazyInvisibleCharacters.configure({ visible: invisibles, builders: invisibleCharacterBuilders(), injectCSS: false }),
      // Website icons on links. Decorations only, and only for icons that
      // actually downloaded - see editorFavicons.
      FaviconChips,
      // One draw of the note on mount instead of two - see editorNodeViewMount.
      NodeViewMount,
      Markdown.configure({
        html: true,
        breaks: true,
        transformPastedText: true,
        transformCopiedText: true,
      }),
    ],
    // A cached parsed doc skips the markdown parse entirely (#150) - the
    // JSON was produced from THIS exact body string by a previous mount,
    // so the two forms are interchangeable. The markdown branch keeps the
    // load half of the round-trip sandwich (collapseMediaGaps +
    // fixEmptyTaskItems) byte-identical to before.
    content: cachedDoc ?? collapseMediaGaps(fixEmptyTaskItems(value)),
    onCreate: ({ editor: created }) => {
      // Populate the cache on a miss so the NEXT open of this big note
      // mounts from JSON. On a hit there is nothing new to write.
      if (!cachedDoc && noteId && value.length >= DOC_CACHE_MIN_BYTES) {
        void writeDocCache(noteId, value, created.getJSON());
      }
    },
    editable: !readOnly,
    editorProps: {
      attributes: {
        class:
          'prose prose-pn max-w-none focus:outline-none min-h-[40vh] sm:min-h-[60vh] text-[length:var(--pn-editor-body)] prose-p:text-[length:var(--pn-editor-body)] prose-li:text-[length:var(--pn-editor-body)] prose-blockquote:text-[length:var(--pn-editor-body)]',
        // On mobile, remove the editor from the tab order so iOS Safari
        // doesn't show the prev/next form-assistant toolbar above the
        // keyboard. Users still tap to focus - only the automatic chain
        // is broken.
        ...(isMobile ? { tabindex: '-1' } : {}),
        // spellcheck is inherited, so one attribute on the contenteditable
        // root covers headings, tables, callouts, code blocks and task items
        // alike. Emitted ONLY in the off case: with spell check on we leave
        // the engine's own default alone, so an Android WebView that ships
        // it off is never switched on by someone who just installed an
        // update. Spec: ops/docs/design-decisions.md (Spell check is the
        // engine's, not ours)
        ...(spellcheck ? {} : { spellcheck: 'false' }),
      },
      // Copying to another app: lines of unformatted text as they show, and
      // anything else as the note's markdown, with its line breaks written as
      // two trailing spaces instead of a backslash and only the escapes its
      // text needs (editorClipboard.ts). tiptap-markdown
      // supplies this prop too, and editorProps is consulted before any
      // plugin, so this wins; an empty string falls back to its version, which
      // is what the first paint before the editor lands would get.
      clipboardTextSerializer: (slice) => {
        // `serializer` and `parser` are real but missing from tiptap-markdown's published
        // types, which declare getMarkdown() alone - and getMarkdown() is no
        // use here, because it serializes the whole note rather than the
        // selection. Hence the cast.
        const md = editorRef.current?.storage.markdown as
          | {
              serializer?: { serialize(content: Fragment): string };
              parser?: Parameters<typeof clipboardRenderer>[0];
            }
          | undefined;
        const ser = md?.serializer;
        if (!ser) return '';
        // A copied footnote marker brings its definition along.
        const footnotes = editorRef.current ? carriedSection(slice.content, editorRef.current.schema) : null;
        return markdownForClipboard(
          footnotes ? slice.content.append(Fragment.from(footnotes)) : slice.content,
          (fragment) => ser.serialize(fragment),
          readLineSpacing() !== 'normal',
          readCopyFormat(),
          md.parser ? clipboardRenderer(md.parser) : undefined,
        );
      },
      // Sort the pictures of pasted HTML: ours stay, the ones whose bytes the
      // device holds become pending pictures, the rest go, so no broken image
      // node is ever made. A Markdown folder note stores none of them.
      // Spec: GitHub #67, ops/docs/archive/paste-pictures.md (section 3.2)
      transformPastedHTML: (html) => sanitizePastedHtml(html, { store: !hideEncryptedMedia, report: true }),
      // Long-press-to-paste shouldn't drag the keyboard up with it: the user
      // is reaching for the Cut/Copy/Paste bubble, not for the keys, and an
      // accidental long press shouldn't cost them the screen either. The
      // selection handles and the bubble are unaffected by inputmode.
      // Fix: GitHub #223 (avoid opening keyboard for a long press)
      handleDOMEvents: {
        // Gboard's clipboard panel does not paste - it commits the whole clip
        // through the IME as ordinary typed text. No paste event fires, so
        // none of the paste handling above runs: not transformPastedHTML, and
        // not tiptap-markdown's text parser. The browser then applies the
        // newlines literally, and the blank line between two paragraphs
        // becomes a real empty paragraph, which the note stores as `&nbsp;`
        // (see ParagraphWithMarkdown). That is the extra blank line in #204,
        // and why the same clip is clean through long-press > Paste and dirty
        // through the keyboard's clipboard chip.
        //
        // `beforeinput` is the only place the clip is still whole: it carries
        // the entire string, newlines intact, while the `input` events that
        // follow are already split into per-line insertions. Handing it to
        // pasteText() puts it back on the paste path, where the markdown
        // parser reads `\n\n` as one paragraph break instead of two splits -
        // so a clip whose paragraphs are separated by a blank line lands as
        // paragraphs, the same way that clip does through long-press > Paste.
        // Ordinary typing carries no newline and never reaches the second
        // line of this handler.
        //
        // The two gestures still disagree on a SINGLE newline, and not in
        // this handler's favour to fix: a real paste of "a\nb" currently
        // joins the lines into "ab" (the newline is swallowed on the paste
        // path), while this lands them as two paragraphs. Two paragraphs is
        // the better answer of the two, so it stays; the swallowing is a
        // separate, older defect and belongs in its own change.
        // Fix: GitHub #204 (extra blank line pasting from the keyboard clipboard)
        beforeinput: (view, event) => {
          const input = event as InputEvent;
          if (!view.editable || input.inputType !== 'insertText' || !input.data?.includes('\n')) return false;
          // Drop the blank lines the selection happened to start and end on.
          // They are an artifact of how the text was picked up, not content
          // anyone asked for, and on this path a blank line is a real empty
          // paragraph (#101) - so a clip ending in one newline too many adds
          // an `&nbsp;` line under the paste. The paste menu never showed it
          // because the browser hands that gesture text/html as well, where
          // boundary whitespace is discarded before we ever see it. Only
          // whole blank lines go: indentation on the first real line is
          // content and survives.
          const clip = input.data
            .replace(/^(?:[ \t]*\r?\n)+/, '')
            .replace(/(?:\r?\n[ \t]*)+$/, '');
          if (!clip) return false;
          input.preventDefault();
          return view.pasteText(clip);
        },
        touchstart: (view, event) => { longPress.start(view.dom as HTMLElement, event.touches[0]); return false; },
        touchend: () => { longPress.cancel(); return false; },
        touchmove: () => { longPress.cancel(); return false; },
        touchcancel: () => { longPress.cancel(); return false; },
      },
      // Mod+Shift+9 toggles a task list. StarterKit already uses Mod+Shift+7
      // (numbered) and Mod+Shift+8 (bulleted); 9 extends the sequence for
      // the third list type we ship. Matches Bear / Notion conventions.
      handleKeyDown: (_view, event) => {
        if (matchesKey(event, APP_KEYS.taskList)) {
          event.preventDefault();
          editor?.chain().focus().toggleTaskList().run();
          return true;
        }
        // Cmd/Ctrl+Shift+K asks for a link. It was plain ⌘K until
        // 2026-08-21; ⌘K now focuses search everywhere (the modern search
        // convention won over the link convention), so link took the
        // shifted variant. Plain ⌘K must NOT be handled here - returning
        // false lets it bubble to the window search listener. Works with
        // or without a selection; LinkSheet handles all three states.
        if (matchesKey(event, APP_KEYS.insertLink)) {
          event.preventDefault();
          askForLink();
          return true;
        }
        // Tab inside the editor body must NEVER escape focus to the next
        // form field. On iOS Safari, letting Tab do its default focus-
        // escape is what puts the browser into "form chaining" mode -
        // that's what caused the stuck-zoom when dismissing the keyboard
        // (reported v0.28.1). Inside lists we still want Tab to sink/lift
        // list items (standard behavior). Everywhere else we swallow it
        // so the editor keeps focus and iOS stays out of form mode.
        if (event.key === 'Tab') {
          event.preventDefault();
          if (!editor) return true;
          // Inside a table, Tab/Shift+Tab moves between cells. Use our own
          // cell-stepper (stepTableCell) instead of prosemirror-tables'
          // goToNextCell, which gets stuck on image-only cells. See #145.
          if (editor.isActive('table')) {
            stepTableCell(editor, event.shiftKey ? -1 : 1);
            return true;
          }
          // Inside a Kanban board, Tab steps through titles and cards.
          if (stepKanban(editor.state, editor.view.dispatch, event.shiftKey ? -1 : 1)) return true;
          // Indent / outdent the item, checkbox lists included - this
          // handler runs BEFORE every plugin keymap, so TaskItem's own Tab
          // shortcut never gets a turn and the type has to be resolved
          // here. Outside a list, a paragraph or a code block takes spaces
          // (indentText), never a tab character, which Markdown would read
          // as the start of a code block.
          if (!indentListItem(editor, event.shiftKey ? -1 : 1)) indentText(editor, event.shiftKey ? -1 : 1);
          return true;
        }
        return false;
      },
    },
    onUpdate,
    onFocus: () => onFocusChange?.(true),
    onBlur: () => onFocusChange?.(false),
  });
  endEditorCreate();

  useEffect(() => {
    if (editor && onReady) onReady(editor);
    // Once per editor instance; a new callback identity is not a new editor.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [editor]);

  // Sync readOnly prop to TipTap's editable state. The editor is keyed by
  // note id so it doesn't remount when `locked` toggles - this effect
  // makes prevent-editing take effect immediately.
  useEffect(() => {
    if (editor) editor.setEditable(!readOnly);
  }, [editor, readOnly]);

  // Feed the back-reference declared above (see editorRef).
  useEffect(() => {
    editorRef.current = editor ?? null;
  }, [editor]);

  // Sync the persisted invisible-characters preference to the extension. The
  // `visible` option only seeds the plugin at construction time, so the footer
  // toggle has to drive the command; the editor is keyed by note id, and this
  // effect is what carries the choice across a note switch.
  useEffect(() => {
    if (!editor) return;
    if (invisibles) editor.commands.showInvisibleCharacters();
    else editor.commands.hideInvisibleCharacters();
  }, [editor, invisibles]);

  // Same story for website icons: the plugin reads the preference when it
  // builds its decorations, so flipping the toggle has to ask for a rebuild.
  useEffect(() => {
    refreshFavicons(editor ?? null);
  }, [editor, favicons]);

  useFlushOnExit(editor);

  // Force tabindex=-1 on the ProseMirror contenteditable on mobile.
  // TipTap may override the attribute set via editorProps, so we apply
  // it directly on the DOM element after mount. This removes the editor
  // from iOS Safari's form-assistant prev/next chain.
  useEffect(() => {
    if (!editor) return;
    const el = editor.view.dom;
    if (isMobile) {
      el.setAttribute('tabindex', '-1');
    } else {
      // Let TipTap manage its own default (usually 0).
      el.removeAttribute('tabindex');
    }
  }, [isMobile, editor]);

  const {
    bar,
    setBar,
    barFocusTick,
    outlineOpen,
    setOutlineOpen,
    connectionsOpen,
    setConnectionsOpen,
    setPillsEl,
    findSeed,
    openFindWith,
    closeSeededFind,
    closeBar,
    toggleFind,
    toggleReplace,
    swapBar,
    swapTerm,
  } = useEditorPanels({ rootRef, editorRef, editor, readOnly, preview, toolbarVisible, isPro, onOpenUpgrade });

  /**
   * Put a new empty line above everything else in the note and the caret on
   * it - the action behind the "Add a line at the top" zone above the body.
   *
   * A note that starts with an image, a table, a quote or a list has no line
   * to click above its first block, and the keyboard way in (ArrowUp into a
   * gap cursor) is neither discoverable nor, since TipTap 3, available above
   * a quote. A note that starts with a paragraph or a heading needs no help,
   * so the zone only shows for the others (needsTopLine).
   */
  const [needsTopLine, setNeedsTopLine] = useState(false);
  useEffect(() => {
    if (!editor) return;
    const check = () => {
      const first = editor.state.doc.firstChild?.type.name;
      setNeedsTopLine(first !== undefined && first !== 'paragraph' && first !== 'heading');
    };
    check();
    editor.on('update', check);
    return () => { editor.off('update', check); };
  }, [editor]);

  // The zone needs more room than the body's 16px top gap to hold its label
  // clear of the line above (pn-top-line-pad in index.css).
  const showTopLine = !readOnly && !preview && needsTopLine;

  const addLineAtTop = useCallback(() => {
    const ed = editorRef.current;
    if (!ed || !ed.isEditable) return;
    const { state, view } = ed;
    const paragraph = state.schema.nodes['paragraph']?.create();
    if (!paragraph) return;
    const tr = state.tr.insert(0, paragraph);
    tr.setSelection(TextSelection.create(tr.doc, 1));
    view.dispatch(tr.scrollIntoView());
    view.focus();
  }, []);

  /**
   * Bring the node at the position `find` returns into view and flash it.
   * Shared by the jump to a file from the Files pillar, the rename that
   * pillar asks for, and a note-link to a heading. Best effort by nature: it
   * runs on animation frames, which a hidden or throttled tab never
   * delivers, so no caller may depend on it having finished.
   */
  const revealNode = useCallback((
    find: () => number,
    block: ScrollLogicalPosition,
    onMissing?: () => void,
  ) => {
    if (!editor) return;
    // Defer a frame before resolving the position: NodeView portals may
    // not be in the DOM yet, and the post-parse normalization plugins
    // (TrailingParagraph, MediaGapCleaner) can shift positions right
    // after mount, so a position captured now goes stale.
    requestAnimationFrame(() => {
      if (editor.isDestroyed) return;
      const found = find();
      if (found < 0) { onMissing?.(); return; }
      const dom = editor.view.nodeDOM(found);
      if (!(dom instanceof HTMLElement)) return;
      // Keep the target centered until layout settles: on a freshly
      // mounted note the NodeView chips hydrate asynchronously, so a
      // single scrollIntoView lands correctly and is then pushed away
      // as the content above the target grows. Re-center every frame
      // until the target's position is stable, then flash.
      const start = performance.now();
      let lastTop = Number.NaN;
      let stableFrames = 0;
      const step = () => {
        if (editor.isDestroyed || !dom.isConnected) return;
        const top = dom.getBoundingClientRect().top;
        if (Math.abs(top - lastTop) < 1) stableFrames++;
        else stableFrames = 0;
        lastTop = top;
        dom.scrollIntoView({ block, inline: 'nearest' });
        if (stableFrames >= 5 || performance.now() - start > 1200) {
          // Remove + reflow so a repeat jump to the same file re-flashes.
          dom.classList.remove('pn-file-flash');
          void dom.offsetWidth;
          dom.classList.add('pn-file-flash');
          window.setTimeout(() => dom.classList.remove('pn-file-flash'), 1700);
          return;
        }
        requestAnimationFrame(step);
      };
      step();
    });
  }, [editor]);

  /** Centre the attachment chip or image whose `pn:file/` or `pn:img/` ref
   *  holds `uuid` and flash it. */
  const revealFileNode = useCallback((uuid: string) => {
    if (!editor) return;
    revealNode(() => {
      let found = -1;
      editor.state.doc.descendants((node, pos) => {
        if (found >= 0) return false;
        if (node.type.name !== 'attachment' && node.type.name !== 'image') return true;
        const src = node.attrs['src'] as string | null;
        if (src && src.includes(uuid)) {
          found = pos;
          return false;
        }
        return true;
      });
      return found;
    }, 'center');
  }, [editor, revealNode]);

  useImperativeHandle(
    ref,
    () => ({
      focus: () => editor?.commands.focus() ?? false,
      toggleFind,
      toggleReplace,
      scrollToFile: (uuid: string) => {
        revealFileNode(uuid);
      },
      scrollToHeading: (heading: string, onMissing?: () => void) => {
        if (!editor) return;
        revealNode(() => {
          const pos = findHeadingPos(editor.state.doc, heading);
          // The caret goes to the heading's start, so typing continues there
          // and not wherever the note was last left.
          if (pos >= 0) editor.commands.setTextSelection(pos + 1);
          return pos;
        }, 'start', onMissing);
      },
      scrollToHeadingCode: (itemId: string, code: string) => {
        if (!editor) return;
        revealNode(() => {
          const pos = headingPosByCode(editor.state.doc, itemId, code);
          if (pos >= 0) editor.commands.setTextSelection(pos + 1);
          return pos;
        }, 'start');
      },
      startRenameFile: (uuid: string) => {
        // The name is written by the chip inside the live editor, never by
        // rewriting the note body from a list. Centring the chip is a
        // separate, best-effort courtesy: it runs on animation frames, which
        // a hidden or throttled tab never delivers, and the field must open
        // either way. The field autofocuses, which brings it into view on
        // its own.
        revealFileNode(uuid);
        requestAttachmentRename(uuid);
      },
      highlightSearch: (candidates: string[]) => {
        if (!editor || preview || editor.isDestroyed) return;
        // Synchronous, unlike scrollToFile: the match list is computed from
        // the ProseMirror document, which is complete once the editor exists,
        // and the bar scrolls to the current hit itself. A deferred frame
        // would also never fire in a hidden tab.
        for (const candidate of candidates) {
          setSearchQuery(editor.view, candidate);
          if (getSearchInfo(editor.view).total > 0) {
            openFindWith(candidate);
            return;
          }
        }
        // The index folds what the editor does not (Arabic diacritics, for
        // one), so a word it matched can be absent from the text as written.
        // No bar beats a bar that opens on a red 0/0.
        clearSearch(editor.view);
      },
      clearSearchHighlight: closeSeededFind,
      getEditor: () => editor,
      replaceBody: (md: string) => !preview && replaceBodyUndoably(editor, md),
      splitParts: () => {
        if (!editor || preview || readOnly) return null;
        const { doc } = editor.state;
        const index = splitIndex(doc, editor.state.selection.head);
        if (index === null) return null;
        let cut = 0;
        for (let i = 0; i < index; i++) cut += doc.child(i).nodeSize;
        const ser = (editor.storage.markdown as { serializer?: { serialize(content: ProseMirrorNode): string } }).serializer;
        if (!ser) return null;
        const md = (node: ProseMirrorNode) => collapseMediaGaps(cleanEmptyTaskItems(ser.serialize(node)));
        return { head: md(doc.cut(0, cut)), tail: md(doc.cut(cut)) };
      },
      flushPendingSave: () => {
        if (editor) flushNow(editor);
      },
    }),
    [editor, preview, readOnly, openFindWith, closeSeededFind]
  );

  return (
    <div
      ref={rootRef}
      // pn-editor-topgapped marks a note editor (not the history preview).
      className={`relative flex flex-col min-h-0${preview ? '' : ' pn-editor-topgapped'}${showTopLine ? ' pn-top-line-pad' : ''}`}
      onMouseDownCapture={notePreClickState}
      onContextMenu={openBodyMenu}
    >
      {/* Toolbar must be a direct child of the Editor root - wrapping it
          in a short-height div kills sticky (the toolbar can only stick
          within its parent's bounds). */}
      {/* Toolbar visibility is controlled by the parent (NotesView) so the
          Hide/Show toggle can live on the tag row instead of overlapping
          the note body. */}
      {!readOnly && toolbarVisible && barAtBottom && toolbarSlot && createPortal(
        // At the bottom the bar lives outside the scrolling column, so it
        // never moves with the note: a sticky bar inside the column is left
        // behind by a trackpad bounce (Firefox) and by the page shift iOS
        // makes for the keyboard.
        <Toolbar
          editor={editor}
          mobileTabIndex={isMobile ? -1 : undefined}
          onOpenLinkPopover={askForLink}
          linkBtnRef={linkBtnRef}
          onAudioStateChange={handleAudioStateChange}
          audioStopRef={audioStopRef}
          hideEncryptedMedia={hideEncryptedMedia}
          onInsertFiles={onInsertFiles}
          onShowMarkdown={onShowMarkdown}
        />,
        toolbarSlot,
      )}
      {!readOnly && toolbarVisible && !barAtBottom && (
        <Toolbar
          editor={editor}
          mobileTabIndex={isMobile ? -1 : undefined}
          onOpenLinkPopover={askForLink}
          linkBtnRef={linkBtnRef}
          onAudioStateChange={handleAudioStateChange}
          audioStopRef={audioStopRef}
          hideEncryptedMedia={hideEncryptedMedia}
          onInsertFiles={onInsertFiles}
          onShowMarkdown={onShowMarkdown}
        />
      )}
      {/* Where the link panel falls back to when the link button is not on
          screen. Zero height, so it marks the top of the note body when the
          toolbar is hidden and the line under the toolbar when it is not. */}
      <div ref={linkFallbackRef} aria-hidden="true" />
      {editor && !readOnly && linkPopoverOpen && !isMobile && (
        <LinkSheet
          editor={editor}
          isMobile={false}
          anchorRef={linkAnchorRef}
          onClose={() => setLinkPopoverOpen(false)}
        />
      )}
      {/* Find or replace bar, pinned top-right just under the toolbar. The
          zero-height sticky wrapper keeps it floating over the note content
          (no reserved row) and pinned on scroll; the inner bar handles
          pointer events. Sticky top = tag row + measured toolbar height. */}
      {bar !== 'none' && !preview && editor && (
        <div
          className="sticky z-[5] flex h-0 items-start justify-end overflow-visible pointer-events-none"
          style={{ top: 'calc(var(--pn-tagrow-h, 0px) + var(--pn-editor-toolbar-h, 0px))' }}
        >
          {bar === 'find' ? (
            <FindBar
              key={findSeed ? `seed-${findSeed.tick}` : 'find'}
              editor={editor}
              focusTick={barFocusTick}
              initialQuery={findSeed?.term}
              startQuery={swapTerm}
              onSwap={readOnly ? undefined : swapBar}
              swapPro={!isPro}
              onClose={closeBar}
            />
          ) : (
            <ReplaceBar editor={editor} focusTick={barFocusTick} startQuery={swapTerm} onSwap={swapBar} swapPro={!isPro} onClose={closeBar} />
          )}
        </div>
      )}
      {/* Outline panel, same top-right sticky slot as the bars. Hidden while
          a bar is open so the two never share the corner; the panel
          renders nothing when the note has no headings. Also hidden while a
          recording is running: the floating pill sits exactly on the
          banner's Stop button otherwise (reported during the TipTap 3
          verification pass). */}
      {bar === 'none' && !preview && editor && audioState === 'idle' && (
        <div
          className="sticky z-[5] flex h-0 items-start justify-end gap-1.5 overflow-visible pointer-events-none"
          style={{ top: 'calc(var(--pn-tagrow-h, 0px) + var(--pn-editor-toolbar-h, 0px))' }}
        >
          {/* Measured, so the first lines of the note wrap beside the
              pills instead of under them. */}
          <div ref={setPillsEl} className="flex items-start gap-1.5">
            {bodyControls}
            {connections?.(connectionsOpen, setConnectionsOpen)}
            <OutlinePanel
              editor={editor}
              open={outlineOpen}
              onOpenChange={(v) => {
                setOutlineOpen(v);
                if (v) setBar('none');
              }}
            />
          </div>
        </div>
      )}
      {audioState !== 'idle' && (
        <AudioRecordingBanner
          state={audioState}
          duration={audioDuration}
          onStop={() => audioStopRef.current?.()}
        />
      )}
      {/* The "Add a line at the top" zone: it covers the body's top padding,
          only on a note whose first block has no line to click above it,
          and shows its label on hover. Zero height in the flow, so a hover
          moves nothing. onMouseDown is
          swallowed so focus never leaves the editor - the handler puts the
          caret where it belongs itself. */}
      {showTopLine && (
        <div className="relative h-0">
          <button
            type="button"
            tabIndex={isMobile ? -1 : undefined}
            onMouseDown={(e) => e.preventDefault()}
            onClick={addLineAtTop}
            className="pn-top-line group absolute inset-x-0 top-0 z-[1] h-8 cursor-text outline-none"
          >
            <span className="pointer-events-none absolute inset-x-0 top-1/2 flex -translate-y-1/2 items-center gap-1.5 opacity-0 transition-opacity [@media(hover:hover)]:group-hover:opacity-100 [@media(hover:hover)]:group-hover:delay-150 group-focus-visible:opacity-100">
              <span className="flex items-center gap-1 text-xs leading-none text-pn-muted">
                <Plus size={14} aria-hidden="true" />
                {t('topRow.add')}
              </span>
              {/* Ends where the corner pills begin. */}
              <span className="flex-1 border-t border-dashed border-pn-muted/40" style={{ marginInlineEnd: 'var(--pn-outline-fw, 0px)' }} />
            </span>
          </button>
        </div>
      )}
      <EditorContent editor={editor} />
      <LinkAddressPill rootRef={rootRef} />
      {/* Always mounted, hidden by itself until the caret is in a table: a
          gate read here would only be as fresh as the last render of this
          component, which a transaction does not cause. */}
      {editor && !readOnly && (
        <TableControls editor={editor} formulasUnlocked={proUnlocked(isPro)} onUpgrade={() => onOpenUpgradeRef.current?.(null)} />
      )}
      {editor && !readOnly && linkPopoverOpen && isMobile && (
        <LinkSheet editor={editor} isMobile={true} anchorRef={linkAnchorRef} onClose={() => setLinkPopoverOpen(false)} />
      )}
      <ContextMenu state={linkMenu.state} onClose={linkMenu.close} />
    </div>
  );
});

/**
 * Public Editor: for big notes, resolve the parsed-doc cache BEFORE the
 * editor exists - useEditor parses `content` synchronously in its first
 * render, which at huge sizes is the multi-second open freeze (#150). A
 * cache hit mounts from JSON in milliseconds; either way the one async hop
 * paints a skeleton frame first, so a big note visibly opens instead of
 * the app hanging on the click. Small notes (and mounts without a noteId,
 * e.g. history previews) take the synchronous path exactly as before.
 */
export const Editor = forwardRef<EditorHandle, Props>(function Editor(props, ref) {
  const big = !!props.noteId && props.value.length >= DOC_CACHE_MIN_BYTES;
  const [resolved, setResolved] = useState<{ doc: JSONContent | undefined } | null>(
    big ? null : { doc: undefined },
  );
  useEffect(() => {
    if (resolved) return;
    let live = true;
    readDocCache(props.noteId as string, props.value).then(
      (doc) => { if (live) setResolved({ doc }); },
      () => { if (live) setResolved({ doc: undefined }); },
    );
    return () => { live = false; };
  }, [resolved, props.noteId, props.value]);
  if (!resolved) {
    // Textless skeleton (no copy, so no locale surface): visible for one
    // frame on a cache hit, for the parse duration on a miss.
    return (
      <div className="animate-pulse space-y-4 py-6" aria-hidden="true">
        <div className="h-4 w-3/4 rounded bg-pn/10" />
        <div className="h-4 w-full rounded bg-pn/10" />
        <div className="h-4 w-5/6 rounded bg-pn/10" />
        <div className="h-4 w-2/3 rounded bg-pn/10" />
      </div>
    );
  }
  return <EditorInner {...props} cachedDoc={resolved.doc} ref={ref} />;
});
