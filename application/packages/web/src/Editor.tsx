import {
  forwardRef,
  useCallback,
  useEffect,
  useImperativeHandle,
  useMemo,
  useRef,
  useState,
  type ReactNode,
} from 'react';
import { useTranslation } from 'react-i18next';
import { useEditor, EditorContent, type Editor as TipTapEditor, type JSONContent } from '@tiptap/react';
import { readDocCache, writeDocCache, DOC_CACHE_MIN_BYTES } from './editorDocCache';
import { perfSpan } from './perf';
import StarterKit from '@tiptap/starter-kit';
import Placeholder from '@tiptap/extension-placeholder';
import Link from '@tiptap/extension-link';
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
import { TextSelection } from '@tiptap/pm/state';
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
import { EncryptedImage, sanitizePastedHtml } from './EncryptedImage';
import { EncryptedAttachment } from './EncryptedAttachment';
import { WikiLink } from './NoteLink';
import { AudioRecordingBanner, type AudioRecordingState } from './AudioRecorder';
import { LinkSheet } from './LinkSheet';
import { Callout, CalloutTitle } from './Callout';
import { useIsMobile } from './useIsMobile';
import { createLongPressGuard } from './softKeyboard';
import { useTheme } from './theme';
import { SearchHighlight } from './editorSearch';
import { mathSourceEdit } from './editorMath';
import { FindBar } from './FindBar';
import { ReplaceBar } from './ReplaceBar';
import { OutlinePanel } from './OutlinePanel';
import { TableControls } from './TableControls';
import { Toolbar } from './EditorToolbar';
import { useEditorPanels, EDITOR_TOP_GAP_PX } from './useEditorPanels';
import { useDebouncedMarkdownSave } from './useDebouncedMarkdownSave';
import {
  TextStyleMarkdown,
  TaskListInputRule,
  TaskListWithMarkdown,
  TaskItemMobileSafe,
  fixEmptyTaskItems,
  collapseMediaGaps,
  CodeBlockPlainCopy,
  lowlight,
  CodeBlockWithCopy,
  InlineMathWithMarkdown,
  BlockMathWithMarkdown,
  HighlightWithMarkdown,
  TrailingParagraph,
  MediaGapCleaner,
  TextAlignOurLeft,
  ParagraphWithMarkdown,
  HeadingWithMarkdown,
  TableWithMarkdown,
  goToAdjacentCell,
  indentListItem,
  NbspParagraphCleaner,
  MixedListSplitter,
} from './editorExtensions';
import { detectPlatform } from './devices';

const IS_DESKTOP = detectPlatform() !== 'web';

type Props = {
  /** Initial markdown content. Only read on mount - use a `key` prop to force reload. */
  value: string;
  /** Called with the latest markdown, debounced by 300ms of idle typing. */
  onChange: (markdown: string) => void;
  /** Id of the note being edited - enables the synchronous close-flush
   *  stash (flushStash.ts) so a tab closed mid-debounce loses nothing. */
  noteId?: string;
  /** When true, the editor and toolbar are non-interactive (trash view). */
  readOnly?: boolean;
  /** Called when the editor gains or loses focus. */
  onFocusChange?: (focused: boolean) => void;
  /**
   * Whether the formatting toolbar is shown. Controlled by NotesView so the
   * Hide/Show toggle can live on the tag row. Defaults to visible.
   */
  toolbarVisible?: boolean;
  /** Whether the user has Pro. Gates the Pro-only callout types. */
  isPro?: boolean;
  /** Opens the upgrade modal when a locked Pro callout type is picked, or
   *  when a free account asks for the replace bar. */
  onOpenUpgrade?: (trigger: 'callout' | 'replace') => void;
  /** Hides the encrypted image / attachment / audio group - see Toolbar. */
  hideEncryptedMedia?: boolean;
  /**
   * Controls for the BODY, rendered in the top-right slot beside the
   * collapsed outline pill: find, the rich/markdown switch, invisible
   * characters. They are built by NoteEditorPane, which owns their state,
   * and land here because this is the corner they act on. Hidden while a
   * find or replace bar is up - the bar owns the corner then, and closes
   * itself.
   */
  bodyControls?: ReactNode;
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
  focus: () => void;
  toggleTaskList: () => void;
  /** Open the find-in-note bar, or close it if it is already open. The
   *  tag-row magnifier and Cmd/Ctrl+F share this one action. */
  toggleFind: () => void;
  /** Open the find-and-replace bar, or close it if it is already open. The
   *  "..." menu row and Option/Alt+Cmd/Ctrl+F share this one action, and the
   *  Pro gate sits behind it (useEditorPanels.ts). */
  toggleReplace: () => void;
  /** Scroll to the attachment chip / image whose pn:file/pn:img URI contains
   *  `uuid` and flash-highlight it (jump-to-file from the Files pillar). */
  scrollToFile: (uuid: string) => void;
  /** Raw TipTap editor instance - used by NotesView to wire wiki-link navigation. */
  getEditor: () => TipTapEditor | null;
  /** Serialize and save any pending debounced edit NOW, synchronously.
   *  The editor-mode toggle calls this before it swaps editors: the
   *  unmount flush runs after the replacement has already rendered, so
   *  without this the last debounce window of typing is not in the body
   *  the replacement mounts with. */
  flushPendingSave: () => void;
};

const EditorInner = forwardRef<EditorHandle, Props & { cachedDoc?: JSONContent }>(function EditorInner(
  { value, onChange, readOnly = false, onFocusChange, toolbarVisible = true, isPro = false, onOpenUpgrade, noteId, cachedDoc, hideEncryptedMedia, bodyControls },
  ref
) {
  const { t } = useTranslation('editor');
  const { onUpdate, useFlushOnExit, flushNow } = useDebouncedMarkdownSave({ value, onChange, readOnly, noteId });

  /**
   * Back-reference to the editor for extension option callbacks.
   *
   * The math extensions' `onClick` is configured inside the `extensions` array
   * that `useEditor` itself consumes, so the editor does not exist yet at that
   * point and the callback signature is `(node, pos)` with no editor argument.
   * This ref is assigned right after and read lazily at click time.
   */
  const editorRef = useRef<TipTapEditor | null>(null);

  /**
   * Turn a math node back into its own LaTeX source so it can be edited.
   *
   * The nodes are atoms - KaTeX output is not editable text, so before this
   * there was no way to fix a typo in a formula short of deleting it and
   * retyping from scratch. Clicking now swaps the rendered node for the
   * `$latex$` / `$$latex$$` that produced it, with the caret in it; finishing
   * the closing delimiter re-triggers the input rule and it renders again.
   *
   * Leaving it as raw text is a safe resting state, not a broken one: that is
   * exactly the form our markdown-it rules read back, so a note abandoned
   * mid-edit still renders correctly on the next load.
   */
  const editMathSource = useCallback((node: { attrs: { latex?: string } ; nodeSize: number }, pos: number, block: boolean) => {
    const ed = editorRef.current;
    if (!ed || !ed.isEditable) return;
    const { state } = ed.view;
    const { schema } = state;
    const { source, caret } = mathSourceEdit(node.attrs.latex ?? '', pos, block);

    // Build the replacement by hand rather than handing `insertContentAt` a
    // string. That helper PARSES the string as content, which for a block math
    // node means it decides on a paragraph wrapper itself - and the resulting
    // off-by-one put the caret past the end of the new text and into the block
    // BELOW. Constructing the node here makes the wrapper explicit, which is
    // what mathSourceEdit's offset is calculated against.
    const text = schema.text(source);
    const replacement = block ? schema.nodes['paragraph']?.createAndFill(null, text) : text;
    if (!replacement) return;

    const tr = state.tr.replaceWith(pos, pos + node.nodeSize, replacement);
    // Clamp: appendTransaction plugins (TrailingParagraph, MediaGapCleaner)
    // can still resize the doc around us on the same tick.
    tr.setSelection(TextSelection.create(tr.doc, Math.min(caret, tr.doc.content.size)));
    tr.scrollIntoView();
    ed.view.dispatch(tr);
    ed.view.focus();
  }, []);
  const isMobile = useIsMobile();
  const { spellcheck, invisibles, favicons } = useTheme();
  const rootRef = useRef<HTMLDivElement>(null);
  // Long-press keyboard guard for the body. See the handleDOMEvents block in
  // editorProps; the note title owns a second one in NotesView.
  const longPress = useMemo(createLongPressGuard, []);
  useEffect(() => longPress.cancel, [longPress]);
  const [linkPopoverOpen, setLinkPopoverOpen] = useState(false);
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
        placeholder: t('placeholder'),
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
        // Clicking a link in the editor opens it in a new tab (web only).
        // The `target: '_blank'` + `rel: noopener noreferrer` in
        // HTMLAttributes keep it safe. Meta/Ctrl-click still opens in a
        // background tab. In the native wrappers this must stay OFF: the
        // extension opens via window.open, which Android's WebView turns
        // into an in-place navigation that replaces the app with the web
        // page (#241) - WKWebView merely swallows the call. The anchor
        // interceptor in App.tsx already opens every external link through
        // the opener plugin on native, so the click still works.
        openOnClick: !IS_DESKTOP,
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
      }),
      TaskListInputRule,
      TableWithMarkdown.configure({
        resizable: false,
        HTMLAttributes: {
          class: 'pn-table',
        },
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
      // Spec: ops/docs/plans/markdown-folder.md (section 5, isolation)
      EncryptedImage,
      EncryptedAttachment,
      WikiLink,
      CalloutTitle,
      Callout,
      TrailingParagraph,
      MediaGapCleaner,
      NbspParagraphCleaner,
      MixedListSplitter,
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
      // <sup>/<sub> marks (Mod+. / Mod+,). Same inline-HTML round-trip.
      Superscript,
      // Subscript keeps its toolbar button but loses its default Mod-,
      // shortcut: Cmd+, is the app-wide "open settings" key, and both fired
      // at once (subscript toggled AND settings opened, caught by the
      // 2026-08-21 hotkey audit). The toolbar hint for subscript is already
      // null for the same reason.
      Subscript.extend({
        addKeyboardShortcuts() {
          return {};
        },
      }),
      InlineMathWithMarkdown.configure({
        katexOptions: { throwOnError: false },
        onClick: (node, pos) => editMathSource(node, pos, false),
      }),
      BlockMathWithMarkdown.configure({
        katexOptions: { throwOnError: false },
        onClick: (node, pos) => editMathSource(node, pos, true),
      }),
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
          'prose prose-neutral dark:prose-invert max-w-none focus:outline-none min-h-[40vh] sm:min-h-[60vh] text-[length:var(--pn-editor-body)] prose-p:text-[length:var(--pn-editor-body)] prose-li:text-[length:var(--pn-editor-body)] prose-blockquote:text-[length:var(--pn-editor-body)]',
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
      // Strip <img> tags with external/blob sources from pasted HTML so
      // they don't create broken image nodes. The paste plugin in
      // EncryptedImage.tsx tries to recover the actual image data first;
      // this is the safety net for URLs we can't fetch (cross-origin
      // blob: URLs from WhatsApp, Telegram, etc.).
      // Spec: GitHub #67 (images pasted from WhatsApp show broken previews)
      transformPastedHTML: sanitizePastedHtml,
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
          if (input.inputType !== 'insertText' || !input.data?.includes('\n')) return false;
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
        const mod = event.metaKey || event.ctrlKey;
        if (mod && event.shiftKey && (event.code === 'Digit9' || event.key === '9')) {
          event.preventDefault();
          editor?.chain().focus().toggleTaskList().run();
          return true;
        }
        // Cmd/Ctrl+Shift+K opens the link popover. It was plain ⌘K until
        // 2026-08-21; ⌘K now focuses search everywhere (the modern search
        // convention won over the link convention), so link took the
        // shifted variant. Plain ⌘K must NOT be handled here - returning
        // false lets it bubble to the window search listener. Works with
        // or without a selection; LinkPopover handles all three states.
        if (mod && event.shiftKey && !event.altKey && (event.code === 'KeyK' || event.key === 'k' || event.key === 'K')) {
          event.preventDefault();
          setLinkPopoverOpen(true);
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
          // cell-stepper (goToAdjacentCell) instead of prosemirror-tables'
          // goToNextCell, which gets stuck on image-only cells. See #145.
          if (editor.isActive('table')) {
            goToAdjacentCell(editor, event.shiftKey ? -1 : 1);
            return true;
          }
          // Indent / outdent the item, checkbox lists included - this
          // handler runs BEFORE every plugin keymap, so TaskItem's own Tab
          // shortcut never gets a turn and the type has to be resolved
          // here. Outside a list it is a no-op: we deliberately do NOT
          // insert a literal tab character, plain prose does not want tabs,
          // and the goal here is just "don't jump focus".
          indentListItem(editor, event.shiftKey ? -1 : 1);
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

  // Sync readOnly prop to TipTap's editable state. The editor is keyed by
  // note id so it doesn't remount when `locked` toggles - this effect
  // makes prevent-editing take effect immediately.
  useEffect(() => {
    if (editor) editor.setEditable(!readOnly);
  }, [editor, readOnly]);

  // Feed the back-reference the math onClick handlers read (see editorRef).
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
    setOutlineReserve,
    closeBar,
    toggleFind,
    toggleReplace,
  } = useEditorPanels({ rootRef, editorRef, editor, isMobile, readOnly, toolbarVisible, isPro, onOpenUpgrade });

  /**
   * Put the caret on a line above everything else in the note - the action
   * behind the click row that sits above the body.
   *
   * The row exists because the first block is the one place a note can become
   * unreachable: a leading image, table or quote leaves no line to click, and
   * the keyboard escape (ArrowUp into a gap cursor) is neither discoverable
   * nor, since TipTap 3, available above a quote. A row that is always there
   * answers that for every note without the editor having to guess which
   * documents need a paragraph inserted into them.
   *
   * Nothing is inserted when the note already starts with an empty paragraph
   * (the common case) - we just go there, so repeated clicks can't stack blank
   * lines.
   */
  const addLineAtTop = useCallback(() => {
    const ed = editorRef.current;
    if (!ed || !ed.isEditable) return;
    const { state, view } = ed;
    const first = state.doc.firstChild;
    if (first?.type.name === 'paragraph' && first.content.size === 0) {
      view.dispatch(state.tr.setSelection(TextSelection.create(state.doc, 1)).scrollIntoView());
      view.focus();
      return;
    }
    const paragraph = state.schema.nodes['paragraph']?.create();
    if (!paragraph) return;
    const tr = state.tr.insert(0, paragraph);
    tr.setSelection(TextSelection.create(tr.doc, 1));
    view.dispatch(tr.scrollIntoView());
    view.focus();
  }, []);

  useImperativeHandle(
    ref,
    () => ({
      focus: () => editor?.commands.focus(),
      toggleTaskList: () => {
        editor?.commands.focus();
        editor?.commands.toggleTaskList();
      },
      toggleFind,
      toggleReplace,
      scrollToFile: (uuid: string) => {
        if (!editor) return;
        // Defer a frame before resolving the position: NodeView portals may
        // not be in the DOM yet, and the post-parse normalization plugins
        // (TrailingParagraph, MediaGapCleaner) can shift positions right
        // after mount, so a position captured now goes stale.
        requestAnimationFrame(() => {
          if (editor.isDestroyed) return;
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
          if (found < 0) return;
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
            dom.scrollIntoView({ block: 'center', inline: 'nearest' });
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
      },
      getEditor: () => editor,
      flushPendingSave: () => {
        if (editor) flushNow(editor);
      },
    }),
    [editor]
  );

  return (
    <div
      ref={rootRef}
      // pn-editor-topgapped hands the "start of note" gap to the click row
      // below, so the body's own top padding doesn't stack on top of it.
      className={`relative flex flex-col min-h-0${readOnly ? '' : ' pn-editor-topgapped'}`}
    >
      {/* Toolbar must be a direct child of the Editor root - wrapping it
          in a short-height div kills sticky (the toolbar can only stick
          within its parent's bounds). The desktop LinkSheet needs a
          positioned ancestor for its absolute positioning, so it gets its
          own relative wrapper that does NOT contain the toolbar. */}
      {/* Toolbar visibility is controlled by the parent (NotesView) so the
          Hide/Show toggle can live on the tag row instead of overlapping
          the note body. */}
      {!readOnly && toolbarVisible && (
        <>
          <Toolbar
            editor={editor}
            mobileTabIndex={isMobile ? -1 : undefined}
            onOpenLinkPopover={() => setLinkPopoverOpen(true)}
            onAudioStateChange={handleAudioStateChange}
            audioStopRef={audioStopRef}
            isPro={isPro}
            onOpenUpgrade={onOpenUpgrade}
            hideEncryptedMedia={hideEncryptedMedia}
          />
          {editor && linkPopoverOpen && !isMobile && (
            <div className="relative">
              <LinkSheet editor={editor} isMobile={false} onClose={() => setLinkPopoverOpen(false)} />
            </div>
          )}
        </>
      )}
      {/* Find or replace bar, pinned top-right just under the toolbar. The
          zero-height sticky wrapper keeps it floating over the note content
          (no reserved row) and pinned on scroll; the inner bar handles
          pointer events. Sticky top = tag row + measured toolbar height. */}
      {bar !== 'none' && !readOnly && editor && (
        <div
          className="sticky z-[5] flex h-0 items-start justify-end overflow-visible pointer-events-none"
          style={{ top: 'calc(var(--pn-tagrow-h, 0px) + var(--pn-editor-toolbar-h, 0px))' }}
        >
          {bar === 'find' ? (
            <FindBar editor={editor} focusTick={barFocusTick} onClose={closeBar} />
          ) : (
            <ReplaceBar editor={editor} focusTick={barFocusTick} onClose={closeBar} />
          )}
        </div>
      )}
      {/* Outline panel, same top-right sticky slot as the bars. Hidden while
          a bar is open so the two never share the corner; the panel
          renders nothing when the note has no headings. Also hidden while a
          recording is running: the floating pill sits exactly on the
          banner's Stop button otherwise (reported during the TipTap 3
          verification pass). */}
      {bar === 'none' && !readOnly && editor && audioState === 'idle' && (
        <div
          className="sticky z-[5] flex h-0 items-start justify-end gap-1.5 overflow-visible pointer-events-none"
          style={{ top: 'calc(var(--pn-tagrow-h, 0px) + var(--pn-editor-toolbar-h, 0px))' }}
        >
          {bodyControls}
          <OutlinePanel
            editor={editor}
            open={outlineOpen}
            onOpenChange={(v) => {
              setOutlineOpen(v);
              if (v) setBar('none');
            }}
            onReserve={setOutlineReserve}
          />
        </div>
      )}
      {audioState !== 'idle' && (
        <AudioRecordingBanner
          state={audioState}
          duration={audioDuration}
          onStop={() => audioStopRef.current?.()}
        />
      )}
      {/* The click row above the body. Always rendered, on every note: it is
          both the guaranteed way in above a first block you can't type in
          front of (image, table, quote) and the collapsed outline pill's own
          row, which is what stops the pill sitting on the note's first lines.
          onMouseDown is swallowed so focus never leaves the editor - the
          handler puts the caret where it belongs itself. */}
      {!readOnly && (
        <button
          type="button"
          tabIndex={isMobile ? -1 : undefined}
          onMouseDown={(e) => e.preventDefault()}
          onClick={addLineAtTop}
          aria-label={t('topRow.add')}
          style={{ height: EDITOR_TOP_GAP_PX }}
          className="shrink-0 w-full cursor-text rounded-md transition-colors [@media(hover:hover)]:hover:bg-neutral-500/[0.06]"
        />
      )}
      <EditorContent editor={editor} />
      {/* Always mounted, hidden by itself until the caret is in a table: a
          gate read here would only be as fresh as the last render of this
          component, which a transaction does not cause. */}
      {editor && !readOnly && <TableControls editor={editor} />}
      {editor && !readOnly && linkPopoverOpen && isMobile && (
        <LinkSheet editor={editor} isMobile={true} onClose={() => setLinkPopoverOpen(false)} />
      )}
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
        <div className="h-4 w-3/4 rounded bg-neutral-200 dark:bg-neutral-800" />
        <div className="h-4 w-full rounded bg-neutral-200 dark:bg-neutral-800" />
        <div className="h-4 w-5/6 rounded bg-neutral-200 dark:bg-neutral-800" />
        <div className="h-4 w-2/3 rounded bg-neutral-200 dark:bg-neutral-800" />
      </div>
    );
  }
  return <EditorInner {...props} cachedDoc={resolved.doc} ref={ref} />;
});
