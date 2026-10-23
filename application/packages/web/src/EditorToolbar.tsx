import {
  Fragment,
  useCallback,
  useContext,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ChangeEvent,
  type PointerEvent as ReactPointerEvent,
  type MutableRefObject,
  type ReactElement,
  type RefObject,
} from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import {
  TextB as BoldIcon,
  TextItalic as ItalicIcon,
  TextUnderline as UnderlineIcon,
  TextStrikethrough as StrikethroughIcon,
  TextAUnderline as TextColorIcon,
  TextH,
  TextHOne,
  TextHTwo,
  TextHThree,
  TextHFour,
  TextHFive,
  TextHSix,
  TextT as FontIcon,
  CaretDown as ChevronDownIcon,
  CaretLineDown as HideKeyboardIcon,
  ListChecks as ListChecksIcon,
  Link as LinkIcon,
  BracketsSquare as BracketsIcon,
  DotsThree as MoreIcon,
  Plus as PlusIcon,
  Highlighter as HighlighterIcon,
  TextAlignLeft as TextAlignLeftIcon,
  TextAlignCenter as TextAlignCenterIcon,
  TextAlignRight as TextAlignRightIcon,
  TextAlignJustify as TextAlignJustifyIcon,
  Megaphone as MegaphoneIcon,
} from './icons';
import { useEditorState, type Editor as TipTapEditor } from '@tiptap/react';
import { triggerAttachmentUpload } from './EncryptedAttachment';
import { insertFootnote } from './footnotes';
import { copySelectionAs } from './clipboardSpacing';
import { openPicturePicker } from './mediaRefs';
import { HoverLabel } from './HoverLabel';
import { AudioRecorder, type AudioRecordingState } from './AudioRecorder';
import { isLinuxNative } from './devices';
import { TEXT_COLORS, HIGHLIGHT_COLORS, DEFAULT_HIGHLIGHT } from './editorColors';
import { usePopoverPosition } from './usePopoverPosition';
import { suppressSoftKeyboard } from './softKeyboard';
import { readColorPref } from './editorPrefs';
import { toggleCodeBlockSmart, ALIGNMENT_VALUES, COPY_BOX_LANGUAGE } from './editorExtensions';
import { useEscapeToClose } from './useEscapeToClose';
import { keyText } from './shortcutMatch';
import { insertDateText } from './editorCommands';
import { insertKanbanBoard } from './KanbanBoard';
import { FormatBarContext } from './formatBarContext';
import { formatBarItem } from './formatBar';
import { FORMAT_BAR_LOOK } from './formatBarItems';

const AttachIcon = FORMAT_BAR_LOOK.attachMenu!.Icon;
import { useIsMobile, useIsTouchDevice } from './useIsMobile';
import { useKeyboardOpen } from './useKeyboardOpen';
import {
  ColorBar,
  MORE_TOGGLE_W,
  TB_BTN_ACTIVE,
  TB_BTN_BASE,
  TB_BTN_REST,
  TB_CARET,
  TB_ICON,
  TB_SPLIT_CARET,
  TB_SPLIT_MAIN,
  TipSideContext,
  ToolbarBtn,
  endComposition,
  normalizeCssColor,
  runOnCaretWord,
  useToolbarPopover,
} from './editorToolbarParts';
import { AlignPanel, CalloutPanel, FontPanel, HeadingPanel, HighlightPanel, TextColorPanel } from './editorToolbarPopovers';

// ------------------------------------------------------------------
// Toolbar
// ------------------------------------------------------------------

type ToolbarProps = {
  editor: TipTapEditor | null;
  /** Pass -1 on mobile to remove toolbar buttons from iOS form-assistant chain. */
  mobileTabIndex?: number;
  /** Opens the URL link popover (chain icon / Cmd+K). */
  onOpenLinkPopover: () => void;
  /**
   * Anchor for that popover. The link button is the only toolbar control a
   * popover outside this file has to line up with, so the ref comes in rather
   * than the panel guessing at a position.
   */
  linkBtnRef?: RefObject<HTMLButtonElement | null>;
  onAudioStateChange?: (state: AudioRecordingState, duration: number) => void;
  /**
   * Hides the image / attachment / audio group.
   *
   * Those three write an ENCRYPTED blob and insert a `pn:img/` or `pn:file/`
   * reference, which is correct for a note and meaningless inside somebody's
   * Markdown folder - the file would be unreadable in Obsidian, in git, and in
   * the folder itself. The Markdown pillar writes real files next to the note
   * instead, so it turns this group off rather than letting it corrupt a vault.
   * Spec: ops/docs/archive/markdown-folder.md (section 8, media)
   */
  hideEncryptedMedia?: boolean;
  /**
   * Where the picture and file buttons hand their files when the encrypted
   * group is hidden. The Markdown pillar writes them as real files next to
   * the note; without this prop the two buttons stay hidden too. The
   * recorder and "from Files" stay hidden either way: both only exist as
   * encrypted blobs.
   */
  onInsertFiles?: (files: File[]) => void;
  /** Ref that gets set to the stop function when recording starts. */
  audioStopRef?: MutableRefObject<(() => void) | null>;
  /** Switches the note to its Markdown view; absent where the note has none. */
  onShowMarkdown?: () => void;
};

// The heading button's glyph for the level the caret is in, 0 for body text.
const HEADING_ICONS = [TextH, TextHOne, TextHTwo, TextHThree, TextHFour, TextHFive, TextHSix] as const;

export function Toolbar({ editor, mobileTabIndex, onOpenLinkPopover, linkBtnRef, onAudioStateChange, audioStopRef, hideEncryptedMedia = false, onInsertFiles, onShowMarkdown }: ToolbarProps) {
  const { t } = useTranslation('editor');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const attachmentInputRef = useRef<HTMLInputElement>(null);
  // The person's arrangement of the bar and the + menu, and the gear's door
  // to Settings > Toolbar. Spec: ops/docs/archive/format-bar.md
  const { layout, onCustomize, position } = useContext(FormatBarContext);
  // A touch screen gets one strip that scrolls sideways; a pointer gets the
  // measured row with the ••• overflow. The swipe decides it, not the width.
  const strip = useIsTouchDevice();
  // The iOS app removes the system Done bar above the keyboard (GitHub #533),
  // so the strip carries the only control that closes it. It sits outside
  // the arrangeable items: a person who could hide it could lose the way out.
  const keyboardUp = useKeyboardOpen();
  // The gear needs room the phone bar does not have; there the door is the
  // Settings row.
  const wide = !useIsMobile();
  // The person can put the bar at the bottom of the note (section 7 of the
  // plan): the last item of the editor's column, sticky to the bottom of the
  // scroll view, and on a phone above the keyboard. Its labels then open
  // above it, and the ••• row opens above the main row.
  // bottom-[-0.5rem] reaches past the note view's 0.5rem bottom padding, so no
  // text scrolls into a gap under the bar.
  const atBottom = position === 'bottom';
  const tipSide = atBottom ? 'above' : 'below';
  const [recording, setRecording] = useState(false);

  /**
   * Subscribe the toolbar to the editor state it displays.
   *
   * TipTap 3's `useEditor` defaults `shouldRerenderOnTransaction` to FALSE, so
   * nothing re-renders this component when the caret moves. Every `isActive()`
   * below was therefore computed on the last unrelated React render and then
   * went stale - buttons only caught up when some other state (a popover
   * opening, the overflow row measuring) happened to re-render the tree. It
   * looked worst on alignment, because that is a block property that changes
   * simply by arrowing into a different paragraph, but bold, headings, lists
   * and the rest were all equally stale.
   *
   * Deliberately NOT `shouldRerenderOnTransaction: true` on `useEditor`: that
   * re-renders the whole Editor - EditorContent, node views and all - on every
   * keystroke. Subscribing just this component, with a selector, keeps the
   * re-render scoped to the toolbar AND skips it entirely while the states are
   * unchanged (useEditorState compares with deepEqual by default), so ordinary
   * typing inside one paragraph costs nothing.
   */
  useEditorState({
    editor,
    selector: ({ editor: e }) => !e ? null : ({
      bold: e.isActive('bold'),
      italic: e.isActive('italic'),
      underline: e.isActive('underline'),
      strike: e.isActive('strike'),
      code: e.isActive('code'),
      codeBlock: e.isActive('codeBlock'),
      highlight: e.isActive('highlight'),
      link: e.isActive('link'),
      superscript: e.isActive('superscript'),
      subscript: e.isActive('subscript'),
      spoiler: e.isActive('spoiler'),
      blockquote: e.isActive('blockquote'),
      bulletList: e.isActive('bulletList'),
      orderedList: e.isActive('orderedList'),
      taskList: e.isActive('taskList'),
      table: e.isActive('table'),
      callout: e.isActive('callout'),
      heading: e.isActive('heading') ? (e.getAttributes('heading').level ?? 0) : 0,
      // The three attribute-driven controls. textAlign is why this exists.
      textAlign: ALIGNMENT_VALUES.find((v) => e.isActive({ textAlign: v })) ?? null,
      fontFamily: e.getAttributes('textStyle').fontFamily ?? null,
      fontSize: e.getAttributes('textStyle').fontSize ?? null,
      color: e.getAttributes('textStyle').color ?? null,
      highlightColor: e.getAttributes('highlight').color ?? null,
    }),
  });

  const handleImagePick = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files?.length || !editor) return;
    // Never the encrypted upload where that store is off limits.
    if (hideEncryptedMedia) {
      onInsertFiles?.(Array.from(files));
      e.target.value = '';
      return;
    }
    // On mobile, file.type is often empty even for valid images picked
    // from the gallery. Since the input already has accept="image/*",
    // trust that the OS only offered image files - don't filter on MIME.
    const pos = editor.state.selection.from;
    const view = editor.view;
    for (const file of Array.from(files)) {
      import('./EncryptedImage').then(({ triggerImageUpload }) => {
        void triggerImageUpload(file, view, pos);
      });
    }
    // Reset so the same file can be picked again.
    e.target.value = '';
  }, [editor, hideEncryptedMedia, onInsertFiles]);

  const handleAttachmentPick = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files?.length || !editor) return;
    if (hideEncryptedMedia) {
      onInsertFiles?.(Array.from(files));
      e.target.value = '';
      return;
    }
    const view = editor.view;
    // Everything from the attachment picker goes through the attachment
    // pipeline - even images. The dedicated image button exists for
    // inline image rendering. The paperclip always creates file chips.
    for (const file of Array.from(files)) {
      void triggerAttachmentUpload(file, view);
    }
    e.target.value = '';
  }, [editor, hideEncryptedMedia, onInsertFiles]);

  if (!editor) return null;

  const isActive = (name: string, attrs?: Record<string, unknown>) =>
    editor.isActive(name, attrs);

  /**
   * How a popover trigger in the row acts. Under a mouse it acts on
   * pointerdown, which keeps the outside-pointerdown close of the open
   * popover from fighting the toggle. In a touch strip a swipe can start on
   * any button, so the trigger acts on the click the browser fires after a
   * tap and never after a scroll; pointerdown still keeps the focus in the
   * note. A press on the open trigger lands inside its wrapper, so the
   * outside check lets it through and the click closes it.
   *
   * Android raises a closed keyboard for a tap that leaves a focused note
   * focused, and the page then shrinks under the popover the tap opened, so
   * the strip arms the keyboard guard as the tap starts (GitHub #490).
   *
   * Every press first ends a keyboard composition, so a command that
   * redraws the block never makes the keyboard type its word twice.
   */
  const press = (act: () => void) => strip
    ? {
        onPointerDown: (e: ReactPointerEvent) => {
          e.preventDefault();
          endComposition(editor);
          suppressSoftKeyboard(editor.view.dom);
        },
        onClick: act,
      }
    : { onPointerDown: (e: ReactPointerEvent) => { e.preventDefault(); endComposition(editor); act(); } };

  const { open: headingOpen, setOpen: setHeadingOpen, wrapRef: headingRef, btnRef: headingBtnRef, popoverRef: headingDropdownRef, pos: headingDropdownPos } =
    useToolbarPopover('button');

  // Text color swatch popover. Same portal + outside-click pattern as the
  // heading dropdown so it escapes the toolbar's overflow clipping.
  //
  // The wrapper is the popover's anchor rather than a button, because the
  // trigger is a two-part control: the popover lines up with the whole
  // thing, not with the caret half that opens it.
  const { open: colorOpen, setOpen: setColorOpen, wrapRef: colorWrapRef, popoverRef: colorPopoverRef, pos: colorPos } =
    useToolbarPopover('wrap');

  const currentColor = (editor.getAttributes('textStyle').color as string | undefined) || undefined;

  // The swatch picked here last, so the button's main half can apply it
  // again in one press. Held in React state beside localStorage so the
  // bar of the glyph repaints the moment a swatch is picked.
  const [textMemory, setTextMemory] = useState<string | null>(() => readColorPref('text'));
  const rememberedTextColor =
    TEXT_COLORS.find((c) => c.name.toLowerCase() === textMemory)?.value ?? null;

  // Highlight swatch popover. Twin of the text color one above, down to the
  // two-ref outside-click check, and it reuses the same `color.names.*`
  // strings - HIGHLIGHT_COLORS carries the same nine names.
  const { open: highlightOpen, setOpen: setHighlightOpen, wrapRef: highlightWrapRef, popoverRef: highlightPopoverRef, pos: highlightPos } =
    useToolbarPopover('wrap');

  // The color attribute is absent on a plain highlight, which is the
  // palette's first entry rather than "nothing selected" - so the two
  // states the swatches distinguish are (highlighted, which color) and
  // (not highlighted at all).
  const highlightOn = isActive('highlight');
  const currentHighlight = (editor.getAttributes('highlight').color as string | undefined) || undefined;

  // Twin of the text memory above, with one difference: this palette HAS a
  // default, so an untrained button still applies something on its first
  // press rather than falling through to the popover.
  const [highlightMemory, setHighlightMemory] = useState<string | null>(() => readColorPref('highlight'));
  const rememberedHighlight =
    HIGHLIGHT_COLORS.find((c) => c.name.toLowerCase() === highlightMemory) ?? DEFAULT_HIGHLIGHT;

  /**
   * Apply the remembered colour, or strip it when the run already carries
   * exactly that. The second half is what makes removal a single press;
   * a run in some OTHER colour is recoloured rather than cleared, because
   * that is what pressing a colour button asks for.
   */
  const applyRememberedTextColor = () => {
    // The text palette has no default entry the way the highlight one does:
    // unstyled body text is not a swatch. So an untrained button has nothing
    // to apply and opens the palette, which is all it ever did.
    if (!rememberedTextColor) {
      setColorOpen(true);
      return;
    }
    const same = normalizeCssColor(currentColor) === normalizeCssColor(rememberedTextColor);
    runOnCaretWord(editor, (chain) => (same ? chain.unsetColor() : chain.setColor(rememberedTextColor)));
  };

  const applyRememberedHighlight = () => {
    const same =
      highlightOn &&
      normalizeCssColor(currentHighlight) === normalizeCssColor(rememberedHighlight.value ?? undefined);
    // setHighlight MERGES onto an active mark, so the default entry has to
    // clear the old colour rather than omit one - the same trap the popover
    // swatches work around.
    runOnCaretWord(editor, (chain) => {
      if (same) return chain.unsetHighlight();
      return rememberedHighlight.value
        ? chain.setHighlight({ color: rememberedHighlight.value })
        : chain.unsetHighlight().setHighlight();
    });
  };

  // Font family + size share ONE popover and one toolbar button. Two reasons:
  // the format row is measured and clipped, so every button added pushes a
  // writing toggle into the ••• row; and the natural icon for a font-family
  // control is a letterform, which is already spoken for by the text-color
  // button (TextAa). One "Font" entry on TextT avoids both problems.
  const { open: fontOpen, setOpen: setFontOpen, wrapRef: fontWrapRef, btnRef: fontBtnRef, popoverRef: fontPopoverRef, pos: fontPos } =
    useToolbarPopover('button');

  // Undefined means the run carries no font attribute, the same
  // no-value-is-not-a-default distinction the alignment control makes.
  const currentFontFamily = (editor.getAttributes('textStyle').fontFamily as string | undefined) || undefined;
  const currentFontSize = (editor.getAttributes('textStyle').fontSize as string | undefined) || undefined;

  // Text alignment. A popover rather than four toolbar buttons: the format row
  // is already measured-and-clipped, and four more always-on buttons would push
  // the writing toggles people actually use into the ••• row. Same shape as the
  // color picker above it.
  const { open: alignOpen, setOpen: setAlignOpen, wrapRef: alignWrapRef, btnRef: alignBtnRef, popoverRef: alignPopoverRef, pos: alignPos } =
    useToolbarPopover('button');

  // The attach menu behind the paperclip: the picture, file and recording
  // items a person put there. Spec: ops/issues/0534.md
  const { open: attachOpen, setOpen: setAttachOpen, wrapRef: attachWrapRef, btnRef: attachBtnRef, popoverRef: attachPopoverRef, pos: attachPos } =
    useToolbarPopover('button');
  // Starts a recording from the attach menu, where no recorder button shows.
  const audioStartRef = useRef<(() => void) | null>(null);

  // The '+' menu's wrapper, read by the menu's own outside-click check below.
  const insertWrapRef = useRef<HTMLDivElement>(null);

  // Callout type picker. Same portal + outside-click pattern as the color
  // swatch so it escapes the toolbar's overflow clipping.
  //
  // The trigger belongs in this row, inside calloutWrapRef and beside the panel
  // it opens. A popover whose trigger sits in a menu that closes on the same
  // pointerdown cannot survive its own opening press: the menu unmounts the
  // pressed row, the event reaches this listener carrying a target that is no
  // longer in the document, no wrapper contains it, and the check reads an
  // outside click. The link popover has the same requirement.
  const { open: calloutOpen, setOpen: setCalloutOpen, wrapRef: calloutWrapRef, btnRef: calloutBtnRef, popoverRef: calloutPopoverRef, pos: calloutPos } =
    useToolbarPopover('button');

  // '+' insert menu: the newer marks (highlight, superscript, subscript)
  // and math live in a labeled dropdown instead of growing the format
  // row. Same portal + outside-click pattern as the pickers above.
  const [insertOpen, setInsertOpen] = useState(false);
  const insertMenuRef = useRef<HTMLDivElement>(null);

  useEffect(() => {
    if (!insertOpen) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (
        insertWrapRef.current?.contains(target) ||
        insertMenuRef.current?.contains(target)
      ) return;
      setInsertOpen(false);
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [insertOpen]);

  // Escape closes whichever popover is open. Six of the seven register
  // through useToolbarPopover; the '+' menu, anchored to the whole right
  // cluster, registers here.
  //
  // They each had an outside-pointerdown check and nothing else, so the one
  // key every other overlay in the app answers to did nothing here. The hook
  // is the documented route (ui-patterns.md): it keeps a LIFO stack and only
  // the topmost entry acts, and `enabled` gated on the open flag means a
  // CLOSED popover registers no listener at all - which is what keeps this
  // from touching any other Escape behaviour in the app.
  //
  // It also settles the one collision worth checking. useEditorPanels swallows
  // Escape while find-in-note is open, from a capture-phase listener on
  // `document`; this hook's is capture-phase on `window`, and capture runs
  // window before document, so an open popover wins and closes, and the find
  // bar stays up. With every popover closed the hook is not listening, so that
  // swallow and the global Esc cascade behave exactly as they did before.
  //
  // Registering here also hands these popovers to the Android back button,
  // which walks the same stack via closeTopOverlay().
  useEscapeToClose(() => setInsertOpen(false), insertOpen);

  // Overflow expand/collapse. Collapsed (default), the format buttons fill
  // row 1 and any that don't fit are clipped; the ••• toggle reveals them by
  // letting the bar wrap to more rows. On a wide editor everything fits, so
  // collapsing hides nothing - we only hide the tail when there's no space.
  const [formatExpanded, setFormatExpanded] = useState(false);
  // Responsive fill: row 1 shows as many priority buttons as fit at the
  // current width; the rest overflow into a full-width row 2 revealed by •••.
  // visibleCount is measured. When everything fits, hasOverflow is false and
  // the ••• toggle is hidden (nothing to reveal).
  const [visibleCount, setVisibleCount] = useState(99);
  const [hasOverflow, setHasOverflow] = useState(false);
  const formatRowRef = useRef<HTMLDivElement>(null);
  const rightClusterRef = useRef<HTMLDivElement>(null);
  // The insert menu is anchored to the whole right cluster, not to its own
  // '+' button, and end-aligned: the menu is wider than the cluster, so this
  // lines its right edge up with the media cluster (and the toolbar's right
  // padding) instead of leaving it a few px short of the buttons above it.
  const insertPos = usePopoverPosition(insertOpen, rightClusterRef, insertMenuRef, { align: 'end', shrink: true });
  const itemWidthsRef = useRef<number[]>([]);
  const overflowRef = useRef(false);
  const recomputeFitRef = useRef<() => void>(() => {});
  // The widths cache is indexed by position, so a new arrangement starts it
  // over: position 3 now names another button. The fit measures the buttons
  // in the row, so until it has measured this arrangement every button is
  // drawn; otherwise a button that was behind the ••• before the change
  // would never be measured and never shown.
  const barSig = layout.bar.join(',');
  const [measuredSig, setMeasuredSig] = useState<string | null>(null);
  useLayoutEffect(() => {
    const row = formatRowRef.current;
    const flexRow = row?.parentElement;
    if (!row || !flexRow) return;
    itemWidthsRef.current = [];
    overflowRef.current = false;
    if (strip) {
      // Every button renders and the row scrolls; a fade on the edge that has
      // more to show says so. Logical edges: in RTL the start is on the right
      // and scrollLeft counts down from 0.
      recomputeFitRef.current = () => {};
      setVisibleCount(99);
      setHasOverflow(false);
      setFormatExpanded(false);
      const fade = () => {
        const max = row.scrollWidth - row.clientWidth;
        const pos = Math.abs(row.scrollLeft);
        const start = pos > 1;
        const end = pos < max - 1;
        row.dataset.fade = start && end ? 'both' : start ? 'start' : end ? 'end' : '';
      };
      fade();
      row.addEventListener('scroll', fade, { passive: true });
      const ro = new ResizeObserver(fade);
      ro.observe(row);
      return () => { row.removeEventListener('scroll', fade); ro.disconnect(); };
    }
    delete row.dataset.fade;
    const recompute = () => {
      const kids = Array.from(row.children) as HTMLElement[];
      // Every button's width, captured while all of them are still in row 1.
      // Later passes see only the ones that fit, so they refresh that prefix
      // in place, and each entry keeps the WIDEST width it has been measured
      // at. The heading button is why: its glyph reads H in body copy and H1
      // to H6 inside a heading, so it grows by a digit as the caret moves.
      // Reserving the wider spelling is what stops the row dropping a button
      // the moment somebody puts the caret in a title.
      if (kids.length > itemWidthsRef.current.length) {
        itemWidthsRef.current = kids.map((k) => k.getBoundingClientRect().width);
      } else {
        kids.forEach((k, i) => {
          itemWidthsRef.current[i] = Math.max(itemWidthsRef.current[i] ?? 0, k.getBoundingClientRect().width);
        });
      }
      const widths = itemWidthsRef.current;
      const total = widths.length;
      if (!total) return;
      // A button width is fractional - the heading button's glyph decides its
      // own - while the row's box is whole pixels, so a button whose last
      // fraction of a pixel lands outside still reads as fitting: the clip
      // takes a sliver of a rounded corner nobody can see. Hold that slack
      // open, because a 0.8px overhang otherwise costs a whole button.
      const SUBPIXEL = 1;
      const fit = (cap: number) => {
        let used = 0;
        let n = 0;
        for (; n < total; n++) {
          used += widths[n]! + (n ? 2 : 0);
          if (used - cap > SUBPIXEL) break;
        }
        return n;
      };
      // The row's own box is the width flexbox allotted it, and it already
      // accounts for the right cluster, including ••• when that is present.
      // The 6px gap to the cluster is part of the layout, so nothing is held
      // back for it here: a margin on top of that gap buys no space a reader
      // can see and costs the last button its place.
      const avail = row.getBoundingClientRect().width;
      let n = fit(avail);
      const overflow = n < total;
      // On the transition into overflow the ••• isn't in the cluster yet, so
      // reserve its width now - otherwise a button would clip for one frame
      // before the observer re-measures the (now wider) cluster.
      if (overflow && !overflowRef.current) n = Math.max(1, fit(avail - MORE_TOGGLE_W));
      overflowRef.current = overflow;
      setVisibleCount(overflow ? n : total);
      setHasOverflow(overflow);
      setMeasuredSig(barSig);
    };
    recomputeFitRef.current = recompute;
    recompute();
    const ro = new ResizeObserver(recompute);
    ro.observe(flexRow);
    if (rightClusterRef.current) ro.observe(rightClusterRef.current);
    return () => ro.disconnect();
  }, [strip, barSig]);

  // All six levels, menu and detection alike. The schema always allowed
  // every level (imports and ###### markdown produce H6) and detection
  // always read all six so the button never showed a bare "H"; the menu
  // stopped at 5 until the H1-H6 ladder in index.css gave H6 a size of its
  // own, above body copy, that made it worth offering.
  const activeHeading = isActive('heading', { level: 1 }) ? 1
    : isActive('heading', { level: 2 }) ? 2
    : isActive('heading', { level: 3 }) ? 3
    : isActive('heading', { level: 4 }) ? 4
    : isActive('heading', { level: 5 }) ? 5
    : isActive('heading', { level: 6 }) ? 6
    : 0;
  const HeadingIcon = HEADING_ICONS[activeHeading];

  // Format buttons in priority order. They fill the bar; whatever doesn't
  // fit wraps below and is clipped (max-h) until ••• expands it.
  const bold = (
    <ToolbarBtn key="bold" onClick={() => editor.chain().focus().toggleBold().run()} active={isActive('bold')} label={t('toolbar.bold')} keys={keyText('bold')} tabIndex={mobileTabIndex}>
      <BoldIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  const italic = (
    <ToolbarBtn key="italic" onClick={() => editor.chain().focus().toggleItalic().run()} active={isActive('italic')} label={t('toolbar.italic')} keys={keyText('italic')} tabIndex={mobileTabIndex}>
      <ItalicIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  // Underline sits in the B/I/U triad rather than beside strikethrough: it is
  // where every other editor puts it, and priority order is also clipping
  // order, so parking it at the end would drop it into the ••• row first.
  const underline = (
    <ToolbarBtn key="underline" onClick={() => editor.chain().focus().toggleUnderline().run()} active={isActive('underline')} label={t('toolbar.underline')} keys={keyText('underline')} tabIndex={mobileTabIndex}>
      <UnderlineIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  const heading = (
    <div key="heading" ref={headingRef} className="relative shrink-0">
      <HoverLabel label={t('toolbar.heading')} position={tipSide}>
        <button
          ref={headingBtnRef}
          type="button"
          tabIndex={mobileTabIndex}
          {...press(() => setHeadingOpen((prev) => !prev))}
          aria-label={t('toolbar.heading')}
          className={`${TB_BTN_BASE} ${activeHeading ? TB_BTN_ACTIVE : TB_BTN_REST}`}
        >
          {/* A plain button box with no caret: its one press opens the level
              list, as alignment, font and callout do. The glyph names the
              level the caret is in, so the box never changes width.
              Spec: ops/docs/archive/ui-patterns.md (section 23 - editor toolbar fit) */}
          <HeadingIcon size={TB_ICON} />
        </button>
      </HoverLabel>
      {headingOpen && (
        <HeadingPanel
          popoverRef={headingDropdownRef}
          pos={headingDropdownPos}
          onClose={() => setHeadingOpen(false)}
          editor={editor}
          activeHeading={activeHeading}
        />
      )}
    </div>
  );
  const tasks = (
    <ToolbarBtn key="tasks" onClick={() => editor.chain().focus().toggleTaskList().run()} active={isActive('taskList')} label={t('toolbar.taskList')} keys={keyText('taskList')} tabIndex={mobileTabIndex}>
      <ListChecksIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  const link = (
    <ToolbarBtn key="link" onClick={onOpenLinkPopover} active={isActive('link')} label={t('toolbar.addLink')} keys={keyText('insertLink')} tabIndex={mobileTabIndex} btnRef={linkBtnRef}>
      <LinkIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  // The two kinds of link are one pair and sit together: the chain reaches a
  // site, the brackets reach another note. This one only types "[[" and leaves
  // the rest to the suggestion plugin, so it could live in the '+' menu as
  // well - it sits in the row because its twin has to, and a pair split across
  // two homes reads as two unrelated controls.
  const noteLink = (
    <ToolbarBtn key="notelink" onClick={() => { editor.chain().focus().insertContent('[[').run(); }} label={t('toolbar.noteLink')} tabIndex={mobileTabIndex}>
      <BracketsIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  // Split control: the wide half applies the remembered colour, the caret
  // opens the palette. Both halves paint the same rest state so the pair
  // reads as one button, and the bar of the A shows either the colour of
  // the run the caret sits in or the one a press would apply.
  const colorApplyLabel = rememberedTextColor
    ? t('toolbar.textColorApply', { color: t(`color.names.${textMemory}`) })
    : t('toolbar.textColor');
  const color = (
    <div key="color" ref={colorWrapRef} className="relative shrink-0 flex items-stretch">
      <HoverLabel label={colorApplyLabel} position={tipSide}>
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          {...press(applyRememberedTextColor)}
          aria-label={colorApplyLabel}
          className={`${TB_SPLIT_MAIN} ${TB_BTN_REST}`}
        >
          <TextColorIcon size={TB_ICON} />
          <ColorBar place="underline" color={currentColor ?? rememberedTextColor} />
        </button>
      </HoverLabel>
      <HoverLabel label={t('toolbar.pickColor')} position={tipSide}>
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          {...press(() => setColorOpen((prev) => !prev))}
          aria-label={t('toolbar.pickColor')}
          aria-expanded={colorOpen}
          className={`${TB_SPLIT_CARET} ${TB_BTN_REST}`}
        >
          <ChevronDownIcon size={TB_CARET} />
        </button>
      </HoverLabel>
      {colorOpen && (
        <TextColorPanel
          popoverRef={colorPopoverRef}
          pos={colorPos}
          onClose={() => setColorOpen(false)}
          editor={editor}
          currentColor={currentColor}
          setTextMemory={setTextMemory}
        />
      )}
    </div>
  );
  const callout = (
    <div key="callout" ref={calloutWrapRef} className="relative shrink-0">
      <HoverLabel label={t('toolbar.callout')} position={tipSide}>
        <button
          ref={calloutBtnRef}
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          {...press(() => setCalloutOpen((prev) => !prev))}
          aria-label={t('toolbar.callout')}
          className={`${TB_BTN_BASE} ${isActive('callout') ? TB_BTN_ACTIVE : TB_BTN_REST} shrink-0`}
        >
          <MegaphoneIcon size={TB_ICON} />
        </button>
      </HoverLabel>
      {calloutOpen && (
        <CalloutPanel
          popoverRef={calloutPopoverRef}
          pos={calloutPos}
          onClose={() => setCalloutOpen(false)}
          editor={editor}
          isActive={isActive}
        />
      )}
    </div>
  );
  const font = (
    <div key="font" ref={fontWrapRef} className="relative shrink-0">
      <HoverLabel label={t('toolbar.font')} position={tipSide}>
        <button
          ref={fontBtnRef}
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          {...press(() => setFontOpen((prev) => !prev))}
          aria-label={t('toolbar.font')}
          className={`${TB_BTN_BASE} ${currentFontFamily || currentFontSize ? TB_BTN_ACTIVE : TB_BTN_REST} shrink-0`}
        >
          <FontIcon size={TB_ICON} />
        </button>
      </HoverLabel>
      {fontOpen && (
        <FontPanel
          popoverRef={fontPopoverRef}
          pos={fontPos}
          onClose={() => setFontOpen(false)}
          editor={editor}
          currentFontFamily={currentFontFamily}
          currentFontSize={currentFontSize}
        />
      )}
    </div>
  );

  const ALIGN_ICONS = {
    left: TextAlignLeftIcon,
    center: TextAlignCenterIcon,
    right: TextAlignRightIcon,
    justify: TextAlignJustifyIcon,
  } as const;
  const ALIGNMENTS = ALIGNMENT_VALUES.map((value) => ({ value, Icon: ALIGN_ICONS[value] }));
  // NULL means the block carries no textAlign attribute at all, which is a
  // different state from an explicit 'left' and must not be collapsed into it:
  // TextAlign's defaultAlignment is null, so an untouched paragraph matches no
  // alignment. Defaulting this to 'left' lit up the Align-left entry on every
  // unaligned paragraph, and worse, made the unset-on-repick branch below fire
  // on it - so clicking Align left called unsetTextAlign() and explicit left
  // could never be set.
  const currentAlign =
    ALIGNMENTS.find((a) => editor.isActive({ textAlign: a.value }))?.value ?? null;
  // The trigger mirrors the active alignment so the row shows state without
  // opening the popover; unaligned borrows the left glyph but stays in the
  // rest style, which is what "inheriting" looks like.
  const CurrentAlignIcon =
    ALIGNMENTS.find((a) => a.value === currentAlign)?.Icon ?? TextAlignLeftIcon;

  const align = (
    <div key="align" ref={alignWrapRef} className="relative shrink-0">
      <HoverLabel label={t('toolbar.align')} position={tipSide}>
        <button
          ref={alignBtnRef}
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          {...press(() => setAlignOpen((prev) => !prev))}
          aria-label={t('toolbar.align')}
          className={`${TB_BTN_BASE} ${currentAlign === null ? TB_BTN_REST : TB_BTN_ACTIVE} shrink-0`}
        >
          <CurrentAlignIcon size={TB_ICON} />
        </button>
      </HoverLabel>
      {alignOpen && (
        <AlignPanel
          popoverRef={alignPopoverRef}
          pos={alignPos}
          onClose={() => setAlignOpen(false)}
          editor={editor}
          alignments={ALIGNMENTS}
          currentAlign={currentAlign}
        />
      )}
    </div>
  );
  // Twin of the text-colour control above. The active tint paints BOTH
  // halves, because a half-tinted pair would read as two buttons.
  const highlightApplyLabel = t('toolbar.highlightApply', {
    color: t(`color.names.${rememberedHighlight.name.toLowerCase()}`),
  });
  const highlight = (
    <div key="highlight" ref={highlightWrapRef} className="relative shrink-0 flex items-stretch">
      <HoverLabel label={highlightApplyLabel} position={tipSide}>
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          {...press(applyRememberedHighlight)}
          aria-label={highlightApplyLabel}
          className={`${TB_SPLIT_MAIN} ${highlightOn ? TB_BTN_ACTIVE : TB_BTN_REST}`}
        >
          <HighlighterIcon size={TB_ICON} />
          {/* The strip shows the run's own wash while the caret sits inside
              one, and the colour a press would apply everywhere else. */}
          {highlightOn && currentHighlight
            ? <ColorBar place="below" color={currentHighlight} />
            : <ColorBar
                place="below"
                color={rememberedHighlight.value}
                className={rememberedHighlight.value ? '' : 'pn-hl-default'}
              />}
        </button>
      </HoverLabel>
      <HoverLabel label={t('toolbar.pickHighlight')} position={tipSide}>
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          {...press(() => setHighlightOpen((prev) => !prev))}
          aria-label={t('toolbar.pickHighlight')}
          aria-expanded={highlightOpen}
          className={`${TB_SPLIT_CARET} ${highlightOn ? TB_BTN_ACTIVE : TB_BTN_REST}`}
        >
          <ChevronDownIcon size={TB_CARET} />
        </button>
      </HoverLabel>
      {highlightOpen && (
        <HighlightPanel
          popoverRef={highlightPopoverRef}
          pos={highlightPos}
          onClose={() => setHighlightOpen(false)}
          editor={editor}
          highlightOn={highlightOn}
          currentHighlight={currentHighlight}
          setHighlightMemory={setHighlightMemory}
        />
      )}
    </div>
  );
  const strike = (
    <ToolbarBtn key="strike" onClick={() => editor.chain().focus().toggleStrike().run()} active={isActive('strike')} label={t('toolbar.strikethrough')} keys={keyText('strikethrough')} tabIndex={mobileTabIndex}>
      <StrikethroughIcon size={TB_ICON} />
    </ToolbarBtn>
  );

  // What a press does for every item that can sit in the + menu, and for the
  // plain marks a person can move there. The look (icon, label) comes from
  // formatBarItems.tsx; the group from formatBar.ts. `hint` is the Markdown or
  // the key that does the same, which the menu shows beside the label.
  type MenuAction = { hint: string | null; active: boolean; run: () => void };
  const actions: Record<string, MenuAction> = {
    bold: { hint: '**x**', active: isActive('bold'), run: () => editor.chain().focus().toggleBold().run() },
    italic: { hint: '*x*', active: isActive('italic'), run: () => editor.chain().focus().toggleItalic().run() },
    underline: { hint: keyText('underline'), active: isActive('underline'), run: () => editor.chain().focus().toggleUnderline().run() },
    tasks: { hint: '[]', active: isActive('taskList'), run: () => editor.chain().focus().toggleTaskList().run() },
    notelink: { hint: '[[', active: false, run: () => { editor.chain().focus().insertContent('[[').run(); } },
    customize: { hint: null, active: false, run: () => onCustomize?.() },
    markdownView: { hint: keyText('markdownView'), active: false, run: () => onShowMarkdown?.() },
    strike: { hint: '~~x~~', active: isActive('strike'), run: () => editor.chain().focus().toggleStrike().run() },
    // A header row is what a pipe table needs to exist at all: the markdown
    // serializer falls back to raw HTML for a table whose first row is plain
    // cells, so a headerless one is stored as a wall of markup and travels to
    // other apps as markup too. The bar under the table turns it off for
    // anyone who wants a grid instead.
    table: { hint: null, active: isActive('table'), run: () => editor.chain().focus().insertTable({ rows: 2, cols: 2, withHeaderRow: true }).run() },
    hr: { hint: '---', active: false, run: () => editor.chain().focus().setHorizontalRule().run() },
    // The hint column teaches the list prefixes, and the prefix is faster
    // than any button.
    bullets: { hint: '-', active: isActive('bulletList'), run: () => editor.chain().focus().toggleBulletList().run() },
    numbered: { hint: '1.', active: isActive('orderedList'), run: () => editor.chain().focus().toggleOrderedList().run() },
    date: { hint: keyText('insertDate'), active: false, run: () => insertDateText(editor, 'date') },
    dateTime: { hint: keyText('insertDateTime'), active: false, run: () => insertDateText(editor, 'dateTime') },
    quote: { hint: '>', active: isActive('blockquote'), run: () => editor.chain().focus().toggleBlockquote().run() },
    codeblock: {
      hint: '```',
      active: isActive('codeBlock') && !isActive('codeBlock', { language: COPY_BOX_LANGUAGE }),
      run: () => toggleCodeBlockSmart(editor),
    },
    copybox: {
      hint: '```copy',
      active: isActive('codeBlock', { language: COPY_BOX_LANGUAGE }),
      run: () => toggleCodeBlockSmart(editor, COPY_BOX_LANGUAGE),
    },
    kanban: { hint: null, active: false, run: () => insertKanbanBoard(editor, t) },
    inlinecode: { hint: '`x`', active: isActive('code'), run: () => editor.chain().focus().toggleCode().run() },
    // The selected text becomes the formula. The insert commands do not
    // replace a selection, so it is deleted first.
    math: {
      hint: '$x$',
      active: false,
      run: () => {
        const { from, to, empty } = editor.state.selection;
        const latex = empty ? 'x^2' : editor.state.doc.textBetween(from, to, ' ');
        editor.chain().focus().deleteSelection().insertInlineMath({ latex }).run();
      },
    },
    // Block math is its own node in @tiptap/extension-mathematics, so it has
    // its own entry.
    blockmath: {
      hint: '$$x$$',
      active: false,
      run: () => {
        const { from, to, empty } = editor.state.selection;
        const latex = empty ? 'x^2' : editor.state.doc.textBetween(from, to, ' ');
        editor.chain().focus().deleteSelection().insertBlockMath({ latex }).run();
      },
    },
    superscript: { hint: null, active: isActive('superscript'), run: () => editor.chain().focus().toggleSuperscript().run() },
    subscript: { hint: null, active: isActive('subscript'), run: () => editor.chain().focus().toggleSubscript().run() },
    spoiler: { hint: '||x||', active: isActive('spoiler'), run: () => editor.chain().focus().toggleSpoiler().run() },
    footnote: { hint: '[^1]', active: false, run: () => insertFootnote(editor) },
    // The touch home of the selection menu's "Copy as ..." entries (#546).
    copyAsPlain: { hint: null, active: false, run: () => copySelectionAs(editor, 'plain') },
    copyAsMarkdown: { hint: null, active: false, run: () => copySelectionAs(editor, 'markdown') },
  };
  // A picture already in Files, shown without a copy (#330). A modal, so the
  // menu closing under the press cannot close it. Absent where the media
  // buttons are: a Markdown folder cannot hold a reference to our encrypted
  // store.
  // The picture and file pickers run as a command, so they can sit in the
  // menu as well as on the bar.
  if (!hideEncryptedMedia || onInsertFiles) {
    actions.image = { hint: null, active: false, run: () => fileInputRef.current?.click() };
    actions.attach = { hint: null, active: false, run: () => attachmentInputRef.current?.click() };
  }
  if (!hideEncryptedMedia) {
    actions.fromFiles = {
      hint: null,
      active: false,
      run: () => {
        const view = editor.view;
        openPicturePicker({
          onPick: (ref) => {
            void import('./EncryptedImage').then(({ insertPictureRef }) => insertPictureRef(view, ref));
          },
        });
      },
    };
  }

  const lookLabel = (key: string) => t(FORMAT_BAR_LOOK[key]!.label);

  // The recording and "from Files" buttons only make an encrypted blob, which
  // a Markdown folder note cannot hold; the picture and file buttons stay when
  // the folder takes their files (`onInsertFiles`). The Linux app has no
  // recorder (getUserMedia is dead in WebKitGTK; ops/docs/gotchas.md). An item
  // this editor does not offer is left out wherever it was placed.
  const MEDIA = new Set(onInsertFiles ? ['audio', 'fromFiles'] : ['image', 'attach', 'audio', 'fromFiles']);
  // "Customize toolbar" is the door to Settings > Toolbar, where this bar is
  // arranged: an item like the others, so a person can hide it there. Only
  // where there is room for it; on a phone that tab is reached through
  // Settings. No Pro mark on it: the tab says what Pro adds.
  const offered = (key: string) =>
    !(hideEncryptedMedia && MEDIA.has(key)) && !(key === 'audio' && isLinuxNative()) &&
    !(key === 'customize' && !(wide && onCustomize)) &&
    !(key === 'markdownView' && !onShowMarkdown);

  // What the attach menu offers here. Its items count only while the
  // paperclip is on the bar; with one item left, the paperclip gives way to
  // that item's own button.
  const onBarOrEnd = (key: string) => layout.bar.includes(key) || layout.end.includes(key);
  const attachKeys = onBarOrEnd('attachMenu')
    ? layout.attachMenu.filter((k) => offered(k) && (k === 'audio' || actions[k]))
    : [];
  const soloAttach = attachKeys.length === 1 ? attachKeys[0]! : null;
  // The recorder shows its idle button only where the person placed it on
  // the bar. In the attach menu it stays mounted with no button, so a
  // recording started from the menu keeps its stop button on the bar.
  const recorderShown = onBarOrEnd('audio') || soloAttach === 'audio';
  if (attachKeys.includes('audio')) {
    actions.audio = { hint: null, active: false, run: () => audioStartRef.current?.() };
  }

  // A menu item the person moved onto the bar: a plain button whose tip
  // carries the shortcut the menu row showed.
  const promoted = (key: string) => {
    const action = actions[key];
    if (!action) return null;
    const { Icon } = FORMAT_BAR_LOOK[key]!;
    return (
      <ToolbarBtn key={key} onClick={action.run} active={action.active} label={lookLabel(key)} keys={action.hint ?? undefined} tabIndex={mobileTabIndex}>
        <Icon size={TB_ICON} />
      </ToolbarBtn>
    );
  };

  // The bar's own controls. Their stock order, and why each item starts where
  // it does, is in formatBar.ts.
  const recorder = (
    <AudioRecorder
      key="audio"
      editorView={editor.view}
      tabIndex={mobileTabIndex}
      onStateChange={(state, duration) => {
        setRecording(state !== 'idle');
        onAudioStateChange?.(state, duration);
      }}
      stopRef={audioStopRef}
      startRef={audioStartRef}
      idleHidden={!recorderShown}
      tipSide={tipSide}
    />
  );
  const attachMenu = attachKeys.length === 0 ? null
    : soloAttach === 'audio' ? recorder
    : soloAttach ? promoted(soloAttach)
    : (
      <div key="attachMenu" ref={attachWrapRef} className="relative shrink-0">
        <HoverLabel label={lookLabel('attachMenu')} position={tipSide}>
          <button
            ref={attachBtnRef}
            type="button"
            tabIndex={mobileTabIndex}
            onMouseDown={(e) => e.preventDefault()}
            {...press(() => setAttachOpen((prev) => !prev))}
            aria-label={lookLabel('attachMenu')}
            aria-haspopup="menu"
            aria-expanded={attachOpen}
            className={`${TB_BTN_BASE} ${attachOpen ? TB_BTN_ACTIVE : TB_BTN_REST} shrink-0`}
          >
            <AttachIcon size={TB_ICON} />
          </button>
        </HoverLabel>
        {attachOpen && createPortal(
          <div
            ref={attachPopoverRef}
            role="menu"
            aria-label={lookLabel('attachMenu')}
            className="fixed z-50 bg-surface-1 border border-divider rounded-lg shadow-lg py-1 w-48"
            style={{ top: attachPos?.top ?? 0, left: attachPos?.left ?? 0, visibility: attachPos ? 'visible' : 'hidden' }}
          >
            {attachKeys.map((key) => {
              const { Icon } = FORMAT_BAR_LOOK[key]!;
              return (
                <button
                  key={key}
                  type="button"
                  role="menuitem"
                  {...press(() => {
                    setAttachOpen(false);
                    actions[key]!.run();
                  })}
                  className="w-full flex items-center gap-2.5 text-start px-3 py-1.5 text-sm text-pn-soft [@media(hover:hover)]:hover:bg-pn/5 active:bg-pn/5 transition"
                >
                  <Icon size={TB_ICON} />
                  <span className="flex-1">{lookLabel(key)}</span>
                </button>
              );
            })}
          </div>,
          document.body,
        )}
      </div>
    );
  // A thin line the person places between buttons to group them.
  const separatorLine = (key: string) => (
    <span key={key} aria-hidden="true" className="shrink-0 -mx-0.5 h-4 w-px bg-pn-muted/35" />
  );
  const rowControls: Record<string, ReactElement> = {
    bold, italic, underline, heading, tasks, link, notelink: noteLink,
    color, align, font, highlight, callout, strike, audio: recorder,
    separator1: separatorLine('separator1'), separator2: separatorLine('separator2'),
    separator3: separatorLine('separator3'), separator4: separatorLine('separator4'),
  };
  const controls = (keys: string[]) => keys
    .filter(offered)
    .map((key) => (key === 'attachMenu' ? attachMenu : rowControls[key] ?? promoted(key)))
    .filter((el): el is ReactElement => el !== null);
  const formatButtons = controls(layout.bar);
  // The end of the bar, after the '+': it never gives way behind the •••.
  // A hidden or moved-away recorder stays here while it records, so a change
  // to the bar never cuts a recording off. One in the attach menu stays here
  // at rest too, with no button, so the menu can start it.
  const endKeys = !onBarOrEnd('audio') && soloAttach !== 'audio' && (recording || attachKeys.includes('audio'))
    ? [...layout.end, 'audio']
    : layout.end;
  const endButtons = controls(endKeys);
  // A recorder that sits in row 2 keeps row 2 open while it records: closing
  // the ••• would unmount it, and its button with it.
  const audioAt = formatButtons.indexOf(recorder);
  const holdOpen = recording && audioAt >= 0 && measuredSig === barSig && audioAt >= visibleCount;
  const rowTwoOpen = formatExpanded || holdOpen;
  const menuKeys = layout.menu.filter((key) => actions[key] && offered(key));

  return (
    <TipSideContext.Provider value={tipSide}>
    <div className={`pn-editor-toolbar border-divider ${
      atBottom ? 'pn-toolbar-bottom flex flex-col-reverse' : 'sticky z-10 -mx-4 sm:-mx-6 bg-surface-2/90 backdrop-blur [overscroll-behavior:contain] top-[var(--pn-tagrow-h,0px)] border-b'
    }`}>
      <div className="flex items-start gap-1.5 px-4 sm:px-6 py-1">
        {/* Row 1 under a pointer: as many buttons as fit (measured), clipped
            to a single line; the overflow lives in the full-width row 2 below.
            overflow-x-clip (not -hidden) hides transient button spill during
            resize measurement while letting the hover labels, which render
            below the buttons, escape vertically. A label that would hang past
            the clip moves back inside it as it shows (HoverLabel's fitTip).
            On a touch screen it is one strip that scrolls (pn-format-strip in
            index.css); touch shows no hover labels, so nothing needs to
            escape it. */}
        <div ref={formatRowRef} className={`pn-format-row flex-1 min-w-0 flex items-center gap-0.5 ${strip ? 'pn-format-strip' : 'overflow-x-clip'}`}>
          {formatButtons.slice(0, measuredSig === barSig ? visibleCount : formatButtons.length)}
        </div>

        {/* Right cluster: ••• overflow toggle (only when something overflows)
            + accent media cluster (image / attach / audio), always on row 1. */}
        <div ref={rightClusterRef} className="shrink-0 flex items-center gap-1.5">
          {/* The ••• sits next to the row it extends, before the '+'. */}
          {hasOverflow && (
            <ToolbarBtn
              onClick={() => { if (!holdOpen) setFormatExpanded((v) => !v); }}
              active={rowTwoOpen}
              label={rowTwoOpen ? t('toolbar.fewerFormatting') : t('toolbar.moreFormatting')}
              tabIndex={mobileTabIndex}
            >
              <MoreIcon size={TB_ICON} />
            </ToolbarBtn>
          )}
          {/* '+' insert menu: block inserts (table, divider, code block, the
              bullet and numbered lists) plus the rare notation marks (inline
              code, sup/sub, math). Labeled entries with syntax hints - the
              menu teaches while the format row keeps the marks a live
              selection is waiting for. */}
          {/* An empty menu has no button: everything is on the bar or hidden. */}
          {menuKeys.length > 0 && (
          <div ref={insertWrapRef} className="relative shrink-0">
            <HoverLabel label={t('toolbar.insert')} position={tipSide}>
              <button
                type="button"
                tabIndex={mobileTabIndex}
                onMouseDown={(e) => e.preventDefault()}
                // On touch the menu opens on the click after the tap. Opened
                // on pointerdown, a menu placed over the button took the release
                // of the same tap and ran the entry under the finger.
                {...press(() => setInsertOpen((prev) => !prev))}
                aria-label={t('toolbar.insert')}
                className={`${TB_BTN_BASE} ${insertOpen ? TB_BTN_ACTIVE : TB_BTN_REST} shrink-0`}
              >
                <PlusIcon size={TB_ICON} />
              </button>
            </HoverLabel>
            {insertOpen && createPortal(
              <div
                ref={insertMenuRef}
                // An arranged menu can hold every movable item, so it scrolls
                // rather than run off the screen.
                className="fixed z-50 bg-surface-1 border border-divider rounded-lg shadow-lg py-1 w-56 overflow-y-auto overscroll-contain"
                style={{
                  top: insertPos?.top ?? 0,
                  left: insertPos?.left ?? 0,
                  maxHeight: insertPos?.maxHeight ?? `calc(100dvh - ${insertPos?.top ?? 0}px - 8px)`,
                  visibility: insertPos ? 'visible' : 'hidden',
                }}
              >
                {menuKeys.map((key, i, all) => {
                  const item = { key, group: formatBarItem(key)!.group, Icon: FORMAT_BAR_LOOK[key]!.Icon, label: lookLabel(key), ...actions[key]! };
                  return (
                  <Fragment key={item.key}>
                    {/* A header opens each run of entries sharing a group. The
                        arrangement is grouped (resolveFormatBar), so comparing
                        with the previous entry is enough, and a group with no
                        entry left shows no header. */}
                    {(i === 0 || formatBarItem(all[i - 1]!)!.group !== item.group) && (
                      <div className="px-3 pt-2 pb-0.5 text-[11px] uppercase tracking-wide text-pn-muted">
                        {t(`insertGroup.${item.group}`)}
                      </div>
                    )}
                    <button
                      type="button"
                      // On touch a press that becomes a scroll of the menu
                      // must not run an entry.
                      {...press(() => {
                        item.run();
                        setInsertOpen(false);
                      })}
                      className={`w-full flex items-center gap-2.5 text-start px-3 py-1.5 text-sm [@media(hover:hover)]:hover:bg-pn/5 active:bg-pn/5 transition ${
                        item.active ? 'text-accent' : 'text-pn-soft'
                      }`}
                    >
                      <item.Icon size={TB_ICON} />
                      <span className="flex-1">{item.label}</span>
                      {item.hint && (
                        <span className="text-[11px] font-mono text-pn-muted">{item.hint}</span>
                      )}
                    </button>
                  </Fragment>
                  );
                })}
              </div>,
              document.body,
            )}
          </div>
          )}
          {endButtons.length > 0 && (
          <>
          {/* Hairline, not a tinted box. An accent fill here would be the only
              filled container in the editor's three control rows, reading as a
              different kind of control rather than the last group in a row.
              Spec: ops/docs/archive/ui-patterns.md (section 80) */}
          <span aria-hidden="true" className="shrink-0 mx-0.5 h-4 w-px bg-pn-muted/35" />
          <div className="flex items-center gap-0.5">
            {endButtons}
          </div>
          </>
          )}
          {strip && keyboardUp && (
            <>
              <span aria-hidden="true" className="shrink-0 mx-0.5 h-4 w-px bg-pn-muted/35" />
              <ToolbarBtn onClick={() => editor.commands.blur()} label={t('toolbar.hideKeyboard')} tabIndex={mobileTabIndex}>
                <HideKeyboardIcon size={TB_ICON} />
              </ToolbarBtn>
            </>
          )}
        </div>
      </div>

      {/* Row 2: the overflow buttons, full width, revealed by •••. Only once
          the fit has measured this arrangement: before that row 1 draws every
          button, and drawing some of them here as well would mount a control
          twice and leave its popover anchor empty. */}
      {measuredSig === barSig && rowTwoOpen && hasOverflow && (
        <div className={`flex flex-wrap items-center gap-0.5 px-4 sm:px-6 py-1 border-divider ${atBottom ? 'border-b' : 'border-t'}`}>
          {formatButtons.slice(visibleCount)}
        </div>
      )}

      <input
        ref={fileInputRef}
        type="file"
        accept="image/*"
        multiple
        className="hidden"
        onChange={handleImagePick}
      />
      <input
        ref={attachmentInputRef}
        type="file"
        multiple
        className="hidden"
        onChange={handleAttachmentPick}
      />
    </div>
    </TipSideContext.Provider>
  );
}
