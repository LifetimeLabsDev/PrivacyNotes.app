import {
  Fragment,
  useCallback,
  useEffect,
  useLayoutEffect,
  useRef,
  useState,
  type ChangeEvent,
  type MutableRefObject,
} from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import {
  TextB as BoldIcon,
  TextItalic as ItalicIcon,
  TextUnderline as UnderlineIcon,
  TextStrikethrough as StrikethroughIcon,
  Code as CodeIcon,
  TextAa as BaselineIcon,
  TextT as FontIcon,
  CaretDown as ChevronDownIcon,
  ListChecks as ListChecksIcon,
  ListBullets as ListIcon,
  ListNumbers as ListOrderedIcon,
  Quotes as QuoteIcon,
  CodeBlock as SquareCodeIcon,
  GridFour as TableIcon,
  Minus as MinusIcon,
  Link as LinkIcon,
  BracketsSquare as BracketsIcon,
  Image as ImageIcon,
  Paperclip as PaperclipIcon,
  DotsThree as MoreIcon,
  Plus as PlusIcon,
  Highlighter as HighlighterIcon,
  TextSuperscript as SuperscriptIcon,
  TextSubscript as SubscriptIcon,
  MathOperations as MathIcon,
  TextAlignLeft as TextAlignLeftIcon,
  TextAlignCenter as TextAlignCenterIcon,
  TextAlignRight as TextAlignRightIcon,
  TextAlignJustify as TextAlignJustifyIcon,
  Trash as TrashIcon,
  Prohibit as ProhibitIcon,
  Megaphone as MegaphoneIcon,
  RocketLaunch as RocketIcon,
} from './icons';
import { useEditorState, type Editor as TipTapEditor } from '@tiptap/react';
import { triggerAttachmentUpload } from './EncryptedAttachment';
import { HoverLabel } from './HoverLabel';
import { AudioRecorder, type AudioRecordingState } from './AudioRecorder';
import { isLinuxNative } from './devices';
import { TEXT_COLORS, HIGHLIGHT_COLORS, DEFAULT_HIGHLIGHT, FONT_FAMILIES, FONT_SIZES } from './editorColors';
import { CALLOUT_TYPES } from './calloutTypes';
import { proUnlocked } from './demo';
import { usePopoverPosition } from './usePopoverPosition';
import { readColorPref, writeColorPref } from './editorPrefs';
import { toggleCodeBlockSmart, ALIGNMENT_VALUES } from './editorExtensions';
import { useEscapeToClose } from './useEscapeToClose';

/**
 * Compare two CSS colors as the swatch grid needs to: the value we wrote
 * into the mark comes back from the DOM re-spelled (`rgba(64,192,87,.35)`
 * vs `rgba(64, 192, 87, 0.35)`), so a raw === would show no swatch as
 * selected on a note reopened from storage. Whitespace and case are the
 * only differences the browser introduces between two spellings of the
 * same palette entry, which is all this has to absorb.
 */
function normalizeCssColor(value: string | undefined): string {
  return (value ?? '').replace(/\s+/g, '').toLowerCase();
}

/**
 * The colour strip under a split colour button's glyph. It names the colour
 * the button's main half will apply, so a reader can see it without opening
 * the popover. Rendered even when there is nothing to show - transparent -
 * so the glyph above it does not shift when the first colour is picked.
 *
 * `className` carries `pn-hl-default` for the highlight palette's default
 * entry, which has no stored colour and takes its themed pair from CSS.
 */
function ColorBar({ color, className = '' }: { color?: string | null; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`block w-4 h-[3px] rounded-full ${className}`}
      style={color ? { background: color } : undefined}
    />
  );
}
// ------------------------------------------------------------------
// Smart heading toggle - splits hard breaks into separate paragraphs
// before applying heading so only the cursor's line is affected.
// Fixes: H1/H2/H3 applying to entire note when content has hard breaks
// (from paste, Shift+Enter, or imported single-newline text).
// ------------------------------------------------------------------

function smartToggleHeading(editor: TipTapEditor, level: 1 | 2 | 3 | 4 | 5 | 6) {
  const { state } = editor;
  const { $from } = state.selection;
  const parent = $from.parent;

  // Collect hard-break offsets within the parent block
  const hbOffsets: number[] = [];
  parent.forEach((node, offset) => {
    if (node.type.name === 'hardBreak') hbOffsets.push(offset);
  });

  if (hbOffsets.length === 0) {
    // No hard breaks - standard toggle on the current block
    editor.chain().focus().toggleHeading({ level }).run();
    return;
  }

  // Split hard breaks into separate paragraphs (end-to-start for stable positions)
  const blockContentStart = $from.start(); // position right after opening tag
  const tr = state.tr;
  for (let i = hbOffsets.length - 1; i >= 0; i--) {
    const mapped = tr.mapping.map(blockContentStart + hbOffsets[i]!);
    tr.delete(mapped, mapped + 1); // remove the hardBreak node
    tr.split(mapped);              // split into two blocks
  }
  editor.view.dispatch(tr);

  // Now the cursor is in one of the resulting paragraphs - toggle heading
  editor.chain().focus().toggleHeading({ level }).run();
}

// ------------------------------------------------------------------
// Toolbar button & divider - module-level so React identity is stable
// across Toolbar re-renders (prevents CSS :hover flicker on keystrokes).
// ------------------------------------------------------------------

// Chip button system: uniform 36px rounded-square tap target, ghost at
// rest, subtle neutral fill on hover, ACCENT TINT when toggled on - a
// low-opacity accent wash plus an accent-colored icon, not a solid fill.
// Solid fills were too loud: several marks are commonly active at once
// (bold + italic + a list), and a row of saturated chips read as noise
// rather than state. The tint still separates "on" from "hover" - hover
// is neutral, on is colored - while staying quiet at four active chips.
//
// BASE carries LAYOUT ONLY; REST and ACTIVE each own their colors and are
// mutually exclusive. Do not move a color back into BASE: rest and active
// colors then collide at equal specificity inside the same variant, and
// the winner is decided by Tailwind's internal utility order rather than
// by anything in this file. That is not theoretical - the old solid-fill
// active state paired `dark:text-white` against a BASE `dark:text-neutral-300`
// and silently lost, which nobody caught because #d4d4d4 and #fff are
// indistinguishable on a saturated blue chip. On a 15% tint the same loss
// is glaring: the wash appears but the icon stays grey.
const TB_BTN_BASE =
  'flex items-center justify-center w-8 h-8 rounded-md active:scale-95 transition disabled:opacity-40 disabled:cursor-not-allowed outline-none shrink-0';
const TB_BTN_REST =
  'text-neutral-600 dark:text-neutral-300 [@media(hover:hover)]:hover:bg-neutral-200 [@media(hover:hover)]:dark:hover:bg-neutral-800';
const TB_BTN_ACTIVE = 'bg-accent/15 text-accent [@media(hover:hover)]:hover:bg-accent/25';
// The two halves of a colour button. The wide half keeps the standard 32px
// box and glyph, so the row still reads as one instrument; the caret takes
// the extra width. Only the outer corners round, so the pair reads as a
// single control, and the corners are logical, so the caret stays on the
// trailing side under RTL.
//
// The caret is 20px under a mouse and 24px under a finger, and the hairline is
// what makes the pair read as one control rather than as two neighbours.
//
// Both numbers were measured on a Pixel 10 rather than chosen. A 32px caret,
// matching every other button in the row, is the most tappable option and it
// looks broken: the glyph centres in its own box, which leaves 18px between the
// two GLYPHS against 19px between two unrelated buttons. Pushing the glyph to
// the near edge closes that gap and moves the dead space to the far side, where
// it reads as a hole in the row. 24px is the width where the caret carries no
// visible slack on either side, and the hairline then does the grouping that
// spacing alone cannot. Spec: ops/docs/ui-patterns.md (split colour buttons)
const TB_SPLIT_MAIN =
  'flex flex-col items-center justify-center gap-px w-8 h-8 rounded-s-md active:scale-95 transition outline-none shrink-0';
const TB_SPLIT_CARET =
  "relative flex items-center justify-center w-5 [@media(hover:none)]:w-6 h-8 rounded-e-md active:scale-95 transition outline-none shrink-0 " +
  "before:content-[''] before:absolute before:start-0 before:top-2 before:bottom-2 before:w-px before:bg-divider";
// Matches HEADER_ICON in notesView/NoteEditorPane.tsx: the two header rows
// and this toolbar are one instrument, so they share a box and a glyph size.
// Weight comes from the IconDefaults provider.
const TB_ICON = 18;
// What the ••• toggle costs row 1 once it appears: one 32px button box and
// the 6px gap before it. Only the frame that turns overflow on needs this -
// after that the toggle is in the cluster and the row is measured around it.
const MORE_TOGGLE_W = 38;

function ToolbarBtn({
  onClick,
  active,
  label,
  tabIndex,
  children,
}: {
  onClick: () => void;
  active?: boolean;
  label: string;
  tabIndex?: number;
  children: React.ReactNode;
}) {
  return (
    <HoverLabel label={label} position="below">
      <button
        type="button"
        tabIndex={tabIndex}
        onMouseDown={(e) => e.preventDefault()}
        onClick={onClick}
        aria-label={label}
        className={`${TB_BTN_BASE} ${active ? TB_BTN_ACTIVE : TB_BTN_REST} shrink-0`}
      >
        {children}
      </button>
    </HoverLabel>
  );
}

// Groups are separated by whitespace, not vertical rules - cleaner and
// less visual noise than dividers (the bar reads as grouped clusters).
function ToolbarDivider() {
  return <div className="w-2.5 shrink-0" aria-hidden="true" />;
}

// ------------------------------------------------------------------
// Toolbar
// ------------------------------------------------------------------

type ToolbarProps = {
  editor: TipTapEditor | null;
  /** Pass -1 on mobile to remove toolbar buttons from iOS form-assistant chain. */
  mobileTabIndex?: number;
  /** Opens the URL link popover (chain icon / Cmd+K). */
  onOpenLinkPopover: () => void;
  onAudioStateChange?: (state: AudioRecordingState, duration: number) => void;
  /**
   * Hides the image / attachment / audio group.
   *
   * Those three write an ENCRYPTED blob and insert a `pn:img/` or `pn:file/`
   * reference, which is correct for a note and meaningless inside somebody's
   * Markdown folder - the file would be unreadable in Obsidian, in git, and in
   * the folder itself. The Markdown pillar writes real files next to the note
   * instead, so it turns this group off rather than letting it corrupt a vault.
   * Spec: ops/docs/plans/markdown-folder.md (section 8, media)
   */
  hideEncryptedMedia?: boolean;
  /** Ref that gets set to the stop function when recording starts. */
  audioStopRef?: MutableRefObject<(() => void) | null>;
  /** Whether the user has Pro - gates the Pro-only callout types. */
  isPro?: boolean;
  /** Opens the upgrade modal when a locked Pro callout type is picked. */
  onOpenUpgrade?: (trigger: 'callout') => void;
};

export function Toolbar({ editor, mobileTabIndex, onOpenLinkPopover, onAudioStateChange, audioStopRef, isPro = false, onOpenUpgrade, hideEncryptedMedia = false }: ToolbarProps) {
  const { t } = useTranslation('editor');
  const fileInputRef = useRef<HTMLInputElement>(null);
  const attachmentInputRef = useRef<HTMLInputElement>(null);

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
  }, [editor]);

  const handleAttachmentPick = useCallback((e: ChangeEvent<HTMLInputElement>) => {
    const files = e.target.files;
    if (!files?.length || !editor) return;
    const view = editor.view;
    // Everything from the attachment picker goes through the attachment
    // pipeline - even images. The dedicated image button exists for
    // inline image rendering. The paperclip always creates file chips.
    for (const file of Array.from(files)) {
      void triggerAttachmentUpload(file, view);
    }
    e.target.value = '';
  }, [editor]);

  if (!editor) return null;

  const isActive = (name: string, attrs?: Record<string, unknown>) =>
    editor.isActive(name, attrs);

  const [headingOpen, setHeadingOpen] = useState(false);
  const headingRef = useRef<HTMLDivElement>(null);
  const headingBtnRef = useRef<HTMLButtonElement>(null);
  const headingDropdownRef = useRef<HTMLDivElement>(null);
  const headingDropdownPos = usePopoverPosition(headingOpen, headingBtnRef, headingDropdownRef);

  // Close heading dropdown on outside click. The dropdown is portaled
  // to document.body so we check both the trigger and the dropdown.
  useEffect(() => {
    if (!headingOpen) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (
        headingRef.current?.contains(target) ||
        headingDropdownRef.current?.contains(target)
      ) return;
      setHeadingOpen(false);
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [headingOpen]);

  // Text color swatch popover. Same portal + outside-click pattern as the
  // heading dropdown so it escapes the toolbar's overflow clipping.
  //
  // The wrapper is the popover's anchor rather than a button, because the
  // trigger is a two-part control: the popover lines up with the whole
  // thing, not with the caret half that opens it.
  const [colorOpen, setColorOpen] = useState(false);
  const colorWrapRef = useRef<HTMLDivElement>(null);
  const colorPopoverRef = useRef<HTMLDivElement>(null);
  const colorPos = usePopoverPosition(colorOpen, colorWrapRef, colorPopoverRef);

  useEffect(() => {
    if (!colorOpen) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (
        colorWrapRef.current?.contains(target) ||
        colorPopoverRef.current?.contains(target)
      ) return;
      setColorOpen(false);
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [colorOpen]);

  const currentColor = (editor.getAttributes('textStyle').color as string | undefined) || undefined;

  // The swatch picked here last, so the button's main half can apply it
  // again in one press. Held in React state beside localStorage so the
  // strip under the glyph repaints the moment a swatch is picked.
  const [textMemory, setTextMemory] = useState<string | null>(() => readColorPref('text'));
  const rememberedTextColor =
    TEXT_COLORS.find((c) => c.name.toLowerCase() === textMemory)?.value ?? null;

  // Highlight swatch popover. Twin of the text color one above, down to the
  // two-ref outside-click check, and it reuses the same `color.names.*`
  // strings - HIGHLIGHT_COLORS carries the same nine names.
  const [highlightOpen, setHighlightOpen] = useState(false);
  const highlightWrapRef = useRef<HTMLDivElement>(null);
  const highlightPopoverRef = useRef<HTMLDivElement>(null);
  const highlightPos = usePopoverPosition(highlightOpen, highlightWrapRef, highlightPopoverRef);

  useEffect(() => {
    if (!highlightOpen) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (
        highlightWrapRef.current?.contains(target) ||
        highlightPopoverRef.current?.contains(target)
      ) return;
      setHighlightOpen(false);
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [highlightOpen]);

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
    const chain = editor.chain().focus();
    if (normalizeCssColor(currentColor) === normalizeCssColor(rememberedTextColor)) {
      chain.unsetColor().run();
    } else {
      chain.setColor(rememberedTextColor).run();
    }
  };

  const applyRememberedHighlight = () => {
    const chain = editor.chain().focus();
    const same =
      highlightOn &&
      normalizeCssColor(currentHighlight) === normalizeCssColor(rememberedHighlight.value ?? undefined);
    if (same) {
      chain.unsetHighlight().run();
      return;
    }
    // setHighlight MERGES onto an active mark, so the default entry has to
    // clear the old colour rather than omit one - the same trap the popover
    // swatches work around.
    (rememberedHighlight.value
      ? chain.setHighlight({ color: rememberedHighlight.value })
      : chain.unsetHighlight().setHighlight()
    ).run();
  };

  // Font family + size share ONE popover and one toolbar button. Two reasons:
  // the format row is measured and clipped, so every button added pushes a
  // writing toggle into the ••• row; and the natural icon for a font-family
  // control is a letterform, which is already spoken for by the text-color
  // button (TextAa). One "Font" entry on TextT avoids both problems.
  const [fontOpen, setFontOpen] = useState(false);
  const fontWrapRef = useRef<HTMLDivElement>(null);
  const fontBtnRef = useRef<HTMLButtonElement>(null);
  const fontPopoverRef = useRef<HTMLDivElement>(null);
  const fontPos = usePopoverPosition(fontOpen, fontBtnRef, fontPopoverRef);

  useEffect(() => {
    if (!fontOpen) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (
        fontWrapRef.current?.contains(target) ||
        fontPopoverRef.current?.contains(target)
      ) return;
      setFontOpen(false);
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [fontOpen]);

  // Undefined means the run carries no font attribute, the same
  // no-value-is-not-a-default distinction the alignment control makes.
  const currentFontFamily = (editor.getAttributes('textStyle').fontFamily as string | undefined) || undefined;
  const currentFontSize = (editor.getAttributes('textStyle').fontSize as string | undefined) || undefined;

  // Text alignment. A popover rather than four toolbar buttons: the format row
  // is already measured-and-clipped, and four more always-on buttons would push
  // the writing toggles people actually use into the ••• row. Same shape as the
  // color picker above it.
  const [alignOpen, setAlignOpen] = useState(false);
  const alignWrapRef = useRef<HTMLDivElement>(null);
  const alignBtnRef = useRef<HTMLButtonElement>(null);
  const alignPopoverRef = useRef<HTMLDivElement>(null);
  const alignPos = usePopoverPosition(alignOpen, alignBtnRef, alignPopoverRef);

  useEffect(() => {
    if (!alignOpen) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (
        alignWrapRef.current?.contains(target) ||
        alignPopoverRef.current?.contains(target)
      ) return;
      setAlignOpen(false);
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [alignOpen]);

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
  const [calloutOpen, setCalloutOpen] = useState(false);
  const calloutWrapRef = useRef<HTMLDivElement>(null);
  const calloutBtnRef = useRef<HTMLButtonElement>(null);
  const calloutPopoverRef = useRef<HTMLDivElement>(null);
  const calloutPos = usePopoverPosition(calloutOpen, calloutBtnRef, calloutPopoverRef);

  useEffect(() => {
    if (!calloutOpen) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (
        calloutWrapRef.current?.contains(target) ||
        calloutPopoverRef.current?.contains(target)
      ) return;
      setCalloutOpen(false);
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [calloutOpen]);

  // Demo unlocks every callout type as a teaser, same as Zen. Spec: ops/docs/callouts.md
  const calloutUnlocked = proUnlocked(isPro);

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

  // Escape closes whichever popover is open, for all seven at once.
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
  useEscapeToClose(() => setHeadingOpen(false), headingOpen);
  useEscapeToClose(() => setColorOpen(false), colorOpen);
  useEscapeToClose(() => setHighlightOpen(false), highlightOpen);
  useEscapeToClose(() => setFontOpen(false), fontOpen);
  useEscapeToClose(() => setAlignOpen(false), alignOpen);
  useEscapeToClose(() => setCalloutOpen(false), calloutOpen);
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
  const insertPos = usePopoverPosition(insertOpen, rightClusterRef, insertMenuRef, { align: 'end' });
  const itemWidthsRef = useRef<number[]>([]);
  const overflowRef = useRef(false);
  const recomputeFitRef = useRef<() => void>(() => {});
  useLayoutEffect(() => {
    const row = formatRowRef.current;
    const flexRow = row?.parentElement;
    if (!row || !flexRow) return;
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
    };
    recomputeFitRef.current = recompute;
    recompute();
    const ro = new ResizeObserver(recompute);
    ro.observe(flexRow);
    if (rightClusterRef.current) ro.observe(rightClusterRef.current);
    return () => ro.disconnect();
  }, []);

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
  // Re-fit when the heading button's glyph changes, which is the one width in
  // the row that moves on its own. This is what teaches the widths cache the
  // wider spelling the first time a caret lands in a heading.
  useLayoutEffect(() => { recomputeFitRef.current(); }, [activeHeading]);

  // Format buttons in priority order. They fill the bar; whatever doesn't
  // fit wraps below and is clipped (max-h) until ••• expands it.
  const bold = (
    <ToolbarBtn key="bold" onClick={() => editor.chain().focus().toggleBold().run()} active={isActive('bold')} label={t('toolbar.bold')} tabIndex={mobileTabIndex}>
      <BoldIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  const italic = (
    <ToolbarBtn key="italic" onClick={() => editor.chain().focus().toggleItalic().run()} active={isActive('italic')} label={t('toolbar.italic')} tabIndex={mobileTabIndex}>
      <ItalicIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  // Underline sits in the B/I/U triad rather than beside strikethrough: it is
  // where every other editor puts it, and priority order is also clipping
  // order, so parking it at the end would drop it into the ••• row first.
  const underline = (
    <ToolbarBtn key="underline" onClick={() => editor.chain().focus().toggleUnderline().run()} active={isActive('underline')} label={t('toolbar.underline')} tabIndex={mobileTabIndex}>
      <UnderlineIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  const heading = (
    <div key="heading" ref={headingRef} className="relative shrink-0">
      <HoverLabel label={t('toolbar.heading')} position="below">
        <button
          ref={headingBtnRef}
          type="button"
          tabIndex={mobileTabIndex}
          onPointerDown={(e) => {
            e.preventDefault();
            setHeadingOpen((prev) => !prev);
          }}
          aria-label={t('toolbar.heading')}
          className={`flex items-center justify-center gap-0.5 h-9 w-auto px-1.5 rounded-lg active:scale-95 transition outline-none shrink-0 ${activeHeading ? TB_BTN_ACTIVE : TB_BTN_REST}`}
        >
          {/* No padding around the glyph, and a tighter box than a plain icon
              button needs. The letter and the caret already read as one word,
              and the 8px this frees is a whole button's place in a phone-width
              row - the difference between the checklist toggle sitting in the
              row and sitting behind the ••• .
              Spec: ops/docs/ui-patterns.md (section 23 - editor toolbar fit) */}
          <span className="font-bold text-sm">H{activeHeading || ''}</span>
          <ChevronDownIcon size={12} />
        </button>
      </HoverLabel>
      {headingOpen && createPortal(
        <div
          ref={headingDropdownRef}
          className="fixed z-50 bg-surface-1 border border-divider rounded-lg shadow-lg py-1 w-40"
          style={{
            top: headingDropdownPos?.top ?? 0,
            left: headingDropdownPos?.left ?? 0,
            visibility: headingDropdownPos ? 'visible' : 'hidden',
          }}
        >
          <button
            type="button"
            onPointerDown={(e) => {
              e.preventDefault();
              editor.chain().focus().setParagraph().run();
              setHeadingOpen(false);
            }}
            className={`w-full text-start px-3 py-1.5 text-sm [@media(hover:hover)]:hover:bg-neutral-100 [@media(hover:hover)]:dark:hover:bg-neutral-800 active:bg-neutral-100 dark:active:bg-neutral-800 transition ${
              activeHeading === 0 ? 'text-accent' : 'text-neutral-700 dark:text-neutral-200'
            }`}
          >
            {t('heading.normalText')}
          </button>
          {([1, 2, 3, 4, 5, 6] as const).map((level) => (
            <button
              key={level}
              type="button"
              onPointerDown={(e) => {
                e.preventDefault();
                smartToggleHeading(editor, level);
                setHeadingOpen(false);
              }}
              className={`w-full text-start px-3 py-1.5 text-sm [@media(hover:hover)]:hover:bg-neutral-100 [@media(hover:hover)]:dark:hover:bg-neutral-800 active:bg-neutral-100 dark:active:bg-neutral-800 transition ${
                activeHeading === level ? 'text-accent' : 'text-neutral-700 dark:text-neutral-200'
              }`}
            >
              {t('heading.level', { level })}
            </button>
          ))}
        </div>,
        document.body,
      )}
    </div>
  );
  const tasks = (
    <ToolbarBtn key="tasks" onClick={() => editor.chain().focus().toggleTaskList().run()} active={isActive('taskList')} label={t('toolbar.taskList')} tabIndex={mobileTabIndex}>
      <ListChecksIcon size={TB_ICON} />
    </ToolbarBtn>
  );
  const link = (
    <ToolbarBtn key="link" onClick={onOpenLinkPopover} active={isActive('link')} label={t('toolbar.addLink')} tabIndex={mobileTabIndex}>
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
  // reads as one button, and the strip under the glyph shows either the
  // colour of the run the caret sits in or the one a press would apply.
  const colorApplyLabel = rememberedTextColor
    ? t('toolbar.textColorApply', { color: t(`color.names.${textMemory}`) })
    : t('toolbar.textColor');
  const color = (
    <div key="color" ref={colorWrapRef} className="relative shrink-0 flex items-stretch">
      <HoverLabel label={colorApplyLabel} position="below">
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          onPointerDown={(e) => {
            e.preventDefault();
            applyRememberedTextColor();
          }}
          aria-label={colorApplyLabel}
          className={`${TB_SPLIT_MAIN} ${TB_BTN_REST}`}
        >
          <BaselineIcon size={TB_ICON} />
          <ColorBar color={currentColor ?? rememberedTextColor} />
        </button>
      </HoverLabel>
      <HoverLabel label={t('toolbar.pickColor')} position="below">
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          onPointerDown={(e) => {
            e.preventDefault();
            setColorOpen((prev) => !prev);
          }}
          aria-label={t('toolbar.pickColor')}
          aria-expanded={colorOpen}
          className={`${TB_SPLIT_CARET} ${TB_BTN_REST}`}
        >
          <ChevronDownIcon size={11} />
        </button>
      </HoverLabel>
      {colorOpen && createPortal(
        <div
          ref={colorPopoverRef}
          className="fixed z-50 bg-surface-1 border border-divider rounded-lg shadow-lg p-2 w-[168px]"
          style={{
            top: colorPos?.top ?? 0,
            left: colorPos?.left ?? 0,
            visibility: colorPos ? 'visible' : 'hidden',
          }}
        >
          <div className="grid grid-cols-5 gap-1.5">
            {TEXT_COLORS.map((c) => {
              const selected = currentColor?.toLowerCase() === c.value.toLowerCase();
              const colorName = t(`color.names.${c.name.toLowerCase()}`);
              return (
                <HoverLabel key={c.value} label={colorName} position="above">
                  <button
                    type="button"
                    aria-label={colorName}
                    onPointerDown={(e) => {
                      e.preventDefault();
                      editor.chain().focus().setColor(c.value).run();
                      // Every pick trains the button. Remove does not: it is
                      // not a choice of colour.
                      setTextMemory(c.name.toLowerCase());
                      writeColorPref('text', c.name.toLowerCase());
                      setColorOpen(false);
                    }}
                    className={`block w-6 h-6 rounded-full transition [@media(hover:hover)]:hover:scale-110 ${
                      selected ? 'ring-2 ring-offset-1 ring-accent ring-offset-surface-1' : 'border border-divider'
                    }`}
                    style={{ background: c.value }}
                  />
                </HoverLabel>
              );
            })}
            <HoverLabel label={t('color.remove')} position="above">
              <button
                type="button"
                aria-label={t('color.remove')}
                onPointerDown={(e) => {
                  e.preventDefault();
                  editor.chain().focus().unsetColor().run();
                  setColorOpen(false);
                }}
                className={`w-6 h-6 rounded-full flex items-center justify-center text-neutral-500 dark:text-neutral-400 transition [@media(hover:hover)]:hover:scale-110 ${
                  currentColor ? 'border border-divider' : 'ring-2 ring-offset-1 ring-accent ring-offset-surface-1 border border-divider'
                }`}
              >
                <ProhibitIcon size={13} />
              </button>
            </HoverLabel>
          </div>
        </div>,
        document.body,
      )}
    </div>
  );
  const callout = (
    <div key="callout" ref={calloutWrapRef} className="relative shrink-0">
      <HoverLabel label={t('toolbar.callout')} position="below">
        <button
          ref={calloutBtnRef}
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          onPointerDown={(e) => {
            e.preventDefault();
            setCalloutOpen((prev) => !prev);
          }}
          aria-label={t('toolbar.callout')}
          className={`${TB_BTN_BASE} ${isActive('callout') ? TB_BTN_ACTIVE : TB_BTN_REST} shrink-0`}
        >
          <MegaphoneIcon size={TB_ICON} />
        </button>
      </HoverLabel>
      {calloutOpen && createPortal(
        <div
          ref={calloutPopoverRef}
          role="menu"
          aria-label={t('callout.pickerLabel')}
          className="fixed z-50 bg-surface-1 border border-divider rounded-lg shadow-lg p-2 w-[224px]"
          style={{
            top: calloutPos?.top ?? 0,
            left: calloutPos?.left ?? 0,
            visibility: calloutPos ? 'visible' : 'hidden',
          }}
        >
          <div className="grid grid-cols-3 gap-1">
            {CALLOUT_TYPES.map((c) => {
              const locked = c.pro && !calloutUnlocked;
              const CalloutIcon = c.icon;
              return (
                <button
                  key={c.type}
                  type="button"
                  onPointerDown={(e) => {
                    e.preventDefault();
                    setCalloutOpen(false);
                    if (locked) { onOpenUpgrade?.('callout'); return; }
                    if (editor.isActive('callout')) {
                      editor.chain().focus().setCalloutType(c.type).run();
                    } else {
                      editor.chain().focus().insertCallout(c.type).run();
                    }
                  }}
                  className="relative flex flex-col items-center gap-1 rounded-md px-1 py-2 text-neutral-700 dark:text-neutral-200 [@media(hover:hover)]:hover:bg-neutral-100 [@media(hover:hover)]:dark:hover:bg-neutral-800 transition"
                >
                  <CalloutIcon size={18} weight="bold" color={c.color} />
                  <span className="text-[11px] leading-none">{t(`callout.types.${c.type}`)}</span>
                  {locked && (
                    <RocketIcon size={11} weight="fill" className="text-pro absolute top-1 end-1" />
                  )}
                </button>
              );
            })}
          </div>
          {/* When the cursor is inside a callout, offer an explicit way to remove
              it - the picker is where users look to change or undo a callout, and
              this covers touch platforms with no Backspace-at-start gesture. */}
          {isActive('callout') && (
            <div className="mt-1.5 pt-1.5 border-t border-divider">
              <button
                type="button"
                onPointerDown={(e) => {
                  e.preventDefault();
                  setCalloutOpen(false);
                  editor.chain().focus().removeCallout().run();
                }}
                className="flex w-full items-center justify-center gap-2 rounded-md px-2 py-2 text-[13px] text-neutral-700 dark:text-neutral-200 [@media(hover:hover)]:hover:bg-neutral-100 [@media(hover:hover)]:dark:hover:bg-neutral-800 transition"
              >
                <TrashIcon size={16} className="text-red-500 dark:text-red-400" />
                <span>{t('callout.remove')}</span>
              </button>
            </div>
          )}
        </div>,
        document.body,
      )}
    </div>
  );
  const font = (
    <div key="font" ref={fontWrapRef} className="relative shrink-0">
      <HoverLabel label={t('toolbar.font')} position="below">
        <button
          ref={fontBtnRef}
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          onPointerDown={(e) => {
            e.preventDefault();
            setFontOpen((prev) => !prev);
          }}
          aria-label={t('toolbar.font')}
          className={`${TB_BTN_BASE} ${currentFontFamily || currentFontSize ? TB_BTN_ACTIVE : TB_BTN_REST} shrink-0`}
        >
          <FontIcon size={TB_ICON} />
        </button>
      </HoverLabel>
      {fontOpen && createPortal(
        <div
          ref={fontPopoverRef}
          className="fixed z-50 bg-surface-1 border border-divider rounded-lg shadow-lg py-1 w-44"
          style={{
            top: fontPos?.top ?? 0,
            left: fontPos?.left ?? 0,
            visibility: fontPos ? 'visible' : 'hidden',
          }}
        >
          {FONT_FAMILIES.map((f) => {
            const selected = currentFontFamily === f.value;
            return (
              <button
                key={f.value}
                type="button"
                aria-pressed={selected}
                onPointerDown={(e) => {
                  e.preventDefault();
                  if (selected) editor.chain().focus().unsetFontFamily().run();
                  else editor.chain().focus().setFontFamily(f.value).run();
                  setFontOpen(false);
                }}
                className={`w-full flex items-center justify-between text-start px-3 py-1.5 text-sm [@media(hover:hover)]:hover:bg-neutral-100 [@media(hover:hover)]:dark:hover:bg-neutral-800 active:bg-neutral-100 dark:active:bg-neutral-800 transition ${
                  selected ? 'text-accent' : 'text-neutral-700 dark:text-neutral-200'
                }`}
                style={{ fontFamily: f.value }}
              >
                {t(`font.families.${f.name.toLowerCase()}`)}
              </button>
            );
          })}
          <div className="my-1 h-px bg-divider" aria-hidden="true" />
          {FONT_SIZES.map((s) => {
            const selected = currentFontSize === s.value;
            return (
              <button
                key={s.value}
                type="button"
                aria-pressed={selected}
                onPointerDown={(e) => {
                  e.preventDefault();
                  if (selected) editor.chain().focus().unsetFontSize().run();
                  else editor.chain().focus().setFontSize(s.value).run();
                  setFontOpen(false);
                }}
                className={`w-full flex items-center justify-between text-start px-3 py-1.5 [@media(hover:hover)]:hover:bg-neutral-100 [@media(hover:hover)]:dark:hover:bg-neutral-800 active:bg-neutral-100 dark:active:bg-neutral-800 transition ${
                  selected ? 'text-accent' : 'text-neutral-700 dark:text-neutral-200'
                }`}
                style={{ fontSize: `calc(0.875rem * ${parseFloat(s.value)})` }}
              >
                {t(`font.sizes.${s.name.toLowerCase()}`)}
              </button>
            );
          })}
          {/* One reset for both axes - the two "unset" paths above only clear
              the entry you re-picked, and a run can carry either or both. */}
          {(currentFontFamily || currentFontSize) && (
            <>
              <div className="my-1 h-px bg-divider" aria-hidden="true" />
              <button
                type="button"
                onPointerDown={(e) => {
                  e.preventDefault();
                  editor.chain().focus().unsetFontFamily().unsetFontSize().run();
                  setFontOpen(false);
                }}
                className="w-full text-start px-3 py-1.5 text-sm text-neutral-700 dark:text-neutral-200 [@media(hover:hover)]:hover:bg-neutral-100 [@media(hover:hover)]:dark:hover:bg-neutral-800 active:bg-neutral-100 dark:active:bg-neutral-800 transition"
              >
                {t('font.reset')}
              </button>
            </>
          )}
        </div>,
        document.body,
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
      <HoverLabel label={t('toolbar.align')} position="below">
        <button
          ref={alignBtnRef}
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          onPointerDown={(e) => {
            e.preventDefault();
            setAlignOpen((prev) => !prev);
          }}
          aria-label={t('toolbar.align')}
          className={`${TB_BTN_BASE} ${currentAlign === null ? TB_BTN_REST : TB_BTN_ACTIVE} shrink-0`}
        >
          <CurrentAlignIcon size={TB_ICON} />
        </button>
      </HoverLabel>
      {alignOpen && createPortal(
        <div
          ref={alignPopoverRef}
          className="fixed z-50 bg-surface-1 border border-divider rounded-lg shadow-lg p-1 flex items-center gap-0.5"
          style={{
            top: alignPos?.top ?? 0,
            left: alignPos?.left ?? 0,
            visibility: alignPos ? 'visible' : 'hidden',
          }}
        >
          {ALIGNMENTS.map(({ value, Icon }) => (
            <HoverLabel key={value} label={t(`align.${value}`)} position="above">
              <button
                type="button"
                aria-label={t(`align.${value}`)}
                aria-pressed={currentAlign === value}
                onPointerDown={(e) => {
                  e.preventDefault();
                  // 'left' unsets rather than sets - it is the unstyled default,
                  // and storing it would only add an HTML blob to the markdown
                  // source. Re-picking the active alignment also clears it, so
                  // the block goes back to inheriting.
                  if (value === 'left' || currentAlign === value) {
                    editor.chain().focus().unsetTextAlign().run();
                  } else {
                    editor.chain().focus().setTextAlign(value).run();
                  }
                  setAlignOpen(false);
                }}
                className={`${TB_BTN_BASE} ${currentAlign === value ? TB_BTN_ACTIVE : TB_BTN_REST}`}
              >
                <Icon size={TB_ICON} />
              </button>
            </HoverLabel>
          ))}
        </div>,
        document.body,
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
      <HoverLabel label={highlightApplyLabel} position="below">
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          onPointerDown={(e) => {
            e.preventDefault();
            applyRememberedHighlight();
          }}
          aria-label={highlightApplyLabel}
          className={`${TB_SPLIT_MAIN} ${highlightOn ? TB_BTN_ACTIVE : TB_BTN_REST}`}
        >
          <HighlighterIcon size={TB_ICON} />
          {/* The strip shows the run's own wash while the caret sits inside
              one, and the colour a press would apply everywhere else. */}
          {highlightOn && currentHighlight
            ? <ColorBar color={currentHighlight} />
            : <ColorBar
                color={rememberedHighlight.value}
                className={rememberedHighlight.value ? '' : 'pn-hl-default'}
              />}
        </button>
      </HoverLabel>
      <HoverLabel label={t('toolbar.pickHighlight')} position="below">
        <button
          type="button"
          tabIndex={mobileTabIndex}
          onMouseDown={(e) => e.preventDefault()}
          onPointerDown={(e) => {
            e.preventDefault();
            setHighlightOpen((prev) => !prev);
          }}
          aria-label={t('toolbar.pickHighlight')}
          aria-expanded={highlightOpen}
          className={`${TB_SPLIT_CARET} ${highlightOn ? TB_BTN_ACTIVE : TB_BTN_REST}`}
        >
          <ChevronDownIcon size={11} />
        </button>
      </HoverLabel>
      {highlightOpen && createPortal(
        <div
          ref={highlightPopoverRef}
          className="fixed z-50 bg-surface-1 border border-divider rounded-lg shadow-lg p-2 w-[168px]"
          style={{
            top: highlightPos?.top ?? 0,
            left: highlightPos?.left ?? 0,
            visibility: highlightPos ? 'visible' : 'hidden',
          }}
        >
          <div className="grid grid-cols-5 gap-1.5">
            {HIGHLIGHT_COLORS.map((c) => {
              // A swatch is selected only when the run is actually
              // highlighted: without that check the palette's first entry
              // (color === null) would read as selected on unhighlighted text.
              const selected = highlightOn && normalizeCssColor(currentHighlight) === normalizeCssColor(c.value ?? undefined);
              const colorName = t(`color.names.${c.name.toLowerCase()}`);
              return (
                <HoverLabel key={c.name} label={colorName} position="above">
                  <button
                    type="button"
                    aria-label={colorName}
                    onPointerDown={(e) => {
                      e.preventDefault();
                      // setHighlight MERGES attributes onto an active mark, so
                      // the default entry has to clear the old color rather
                      // than omit one: picking Yellow over a green run would
                      // otherwise leave it green.
                      const chain = editor.chain().focus();
                      (c.value
                        ? chain.setHighlight({ color: c.value })
                        : chain.unsetHighlight().setHighlight()
                      ).run();
                      setHighlightMemory(c.name.toLowerCase());
                      writeColorPref('highlight', c.name.toLowerCase());
                      setHighlightOpen(false);
                    }}
                    className={`block w-6 h-6 rounded-full transition [@media(hover:hover)]:hover:scale-110 ${
                      c.value ? '' : 'pn-hl-default '
                    }${
                      selected ? 'ring-2 ring-offset-1 ring-accent ring-offset-surface-1' : 'border border-divider'
                    }`}
                    // The wash is translucent by design, so the swatch shows
                    // it over the popover's own surface - which is the same
                    // light-or-dark ground it will sit on in the note. The
                    // default entry has no stored color and takes its themed
                    // pair from the .pn-hl-default class instead.
                    style={c.value ? { background: c.value } : undefined}
                  />
                </HoverLabel>
              );
            })}
            <HoverLabel label={t('color.removeHighlight')} position="above">
              <button
                type="button"
                aria-label={t('color.removeHighlight')}
                onPointerDown={(e) => {
                  e.preventDefault();
                  editor.chain().focus().unsetHighlight().run();
                  setHighlightOpen(false);
                }}
                className={`w-6 h-6 rounded-full flex items-center justify-center text-neutral-500 dark:text-neutral-400 transition [@media(hover:hover)]:hover:scale-110 ${
                  highlightOn ? 'border border-divider' : 'ring-2 ring-offset-1 ring-accent ring-offset-surface-1 border border-divider'
                }`}
              >
                <ProhibitIcon size={13} />
              </button>
            </HoverLabel>
          </div>
        </div>,
        document.body,
      )}
    </div>
  );
  const strike = (
    <ToolbarBtn key="strike" onClick={() => editor.chain().focus().toggleStrike().run()} active={isActive('strike')} label={t('toolbar.strikethrough')} tabIndex={mobileTabIndex}>
      <StrikethroughIcon size={TB_ICON} />
    </ToolbarBtn>
  );

  // Priority order (1 = first to show, last to be clipped). The row holds the
  // toggles reached while writing a sentence. What a person goes LOOKING for
  // lives in the '+' menu instead: the block inserts, the rare notation marks
  // and the quote. Highlight sits beside text color (paint family), and the
  // note link beside the chain (link family).
  //
  // The bullet and numbered lists are in the menu rather than the row, even
  // though both are common: a person who wants one types "- " or "1. " and the
  // list opens under the caret, so the button is the slower way to reach a
  // thing the keyboard already does. The checklist keeps its button because
  // "[] " is the one list prefix nobody guesses. Two buttons back is a whole
  // button's place at phone width.
  //
  // Link and callout stay in the row because both open a React popover, and a
  // popover cannot be opened from a menu that closes on the same press - see
  // the callout picker's own note above. Every '+' entry either runs a command
  // outright or hands the caret to a ProseMirror plugin, which survives the
  // menu closing under it.
  const formatButtons = [
    bold, italic, underline, heading, tasks, link, noteLink,
    // Text-styling trio, kept adjacent and in this order: color, alignment,
    // font. They are the three attribute-driven popovers and read as one group.
    color, align, font,
    highlight, callout, strike,
  ];

  return (
    <div className="pn-editor-toolbar sticky top-[var(--pn-tagrow-h,0px)] z-10 -mx-4 sm:-mx-6 border-b border-divider bg-surface-2/90 backdrop-blur [overscroll-behavior:contain]">
      <div className="flex items-start gap-1.5 px-4 sm:px-6 py-1">
        {/* Row 1: as many priority buttons as fit (measured). Clipped to a
            single line; the overflow lives in the full-width row 2 below. */}
        {/* overflow-x-clip (not -hidden) hides transient button spill during
            resize measurement while letting the hover labels, which render
            below the buttons, escape vertically. That same clip cuts the
            horizontal overhang of the end buttons' centered hover labels, so
            pn-format-row edge-aligns those two tips in index.css - the last
            button changes with width, so it can't be a per-button prop. */}
        <div ref={formatRowRef} className="pn-format-row flex-1 min-w-0 flex items-center gap-0.5 overflow-x-clip">
          {formatButtons.slice(0, visibleCount)}
        </div>

        {/* Right cluster: ••• overflow toggle (only when something overflows)
            + accent media cluster (image / attach / audio), always on row 1. */}
        <div ref={rightClusterRef} className="shrink-0 flex items-center gap-1.5">
          {/* '+' insert menu: block inserts (table, divider, code block, the
              bullet and numbered lists) plus the rare notation marks (inline
              code, sup/sub, math). Labeled entries with syntax hints - the
              menu teaches while the format row keeps the marks a live
              selection is waiting for. */}
          <div ref={insertWrapRef} className="relative shrink-0">
            <HoverLabel label={t('toolbar.insert')} position="below">
              <button
                type="button"
                tabIndex={mobileTabIndex}
                onMouseDown={(e) => e.preventDefault()}
                onPointerDown={(e) => {
                  e.preventDefault();
                  setInsertOpen((prev) => !prev);
                }}
                aria-label={t('toolbar.insert')}
                className={`${TB_BTN_BASE} ${insertOpen ? TB_BTN_ACTIVE : TB_BTN_REST} shrink-0`}
              >
                <PlusIcon size={TB_ICON} />
              </button>
            </HoverLabel>
            {insertOpen && createPortal(
              <div
                ref={insertMenuRef}
                className="fixed z-50 bg-surface-1 border border-divider rounded-lg shadow-lg py-1 w-56"
                style={{
                  top: insertPos?.top ?? 0,
                  left: insertPos?.left ?? 0,
                  visibility: insertPos ? 'visible' : 'hidden',
                }}
              >
                {[
                  {
                    key: 'table',
                    group: 'insert',
                    Icon: TableIcon,
                    label: t('toolbar.table'),
                    hint: null,
                    active: isActive('table'),
                    run: () => editor.chain().focus().insertTable({ rows: 2, cols: 2, withHeaderRow: false }).run(),
                  },
                  {
                    key: 'hr',
                    group: 'insert',
                    Icon: MinusIcon,
                    label: t('toolbar.divider'),
                    hint: '---',
                    active: false,
                    run: () => editor.chain().focus().setHorizontalRule().run(),
                  },
                  {
                    // The two lists whose markdown prefix a person already
                    // knows. The hint column is the point of moving them here:
                    // it teaches the prefix, and the prefix is faster than the
                    // menu it is written in.
                    key: 'bullets',
                    group: 'insert',
                    Icon: ListIcon,
                    label: t('toolbar.bulletList'),
                    hint: '-',
                    active: isActive('bulletList'),
                    run: () => editor.chain().focus().toggleBulletList().run(),
                  },
                  {
                    key: 'numbered',
                    group: 'insert',
                    Icon: ListOrderedIcon,
                    label: t('toolbar.numberedList'),
                    hint: '1.',
                    active: isActive('orderedList'),
                    run: () => editor.chain().focus().toggleOrderedList().run(),
                  },
                  {
                    key: 'quote',
                    group: 'blocks',
                    Icon: QuoteIcon,
                    label: t('toolbar.quote'),
                    hint: '>',
                    active: isActive('blockquote'),
                    run: () => editor.chain().focus().toggleBlockquote().run(),
                  },
                  {
                    key: 'codeblock',
                    group: 'blocks',
                    Icon: SquareCodeIcon,
                    label: t('toolbar.codeBlock'),
                    hint: '```',
                    active: isActive('codeBlock'),
                    run: () => toggleCodeBlockSmart(editor),
                  },
                  {
                    key: 'inlinecode',
                    group: 'notation',
                    Icon: CodeIcon,
                    label: t('toolbar.inlineCode'),
                    hint: '`x`',
                    active: isActive('code'),
                    run: () => editor.chain().focus().toggleCode().run(),
                  },
                  {
                    key: 'math',
                    group: 'notation',
                    Icon: MathIcon,
                    label: t('toolbar.math'),
                    hint: '$x$',
                    active: false,
                    run: () => {
                      const { from, to, empty } = editor.state.selection;
                      const latex = empty
                        ? 'x^2'
                        : editor.state.doc.textBetween(from, to, ' ');
                      editor.chain().focus().insertInlineMath({ latex }).run();
                    },
                  },
                  {
                    // Block math is its own node since the move to
                    // @tiptap/extension-mathematics, so it needs its own entry -
                    // the inline one above can no longer reach it via a display
                    // attribute the way the old extension did.
                    key: 'blockmath',
                    group: 'notation',
                    Icon: MathIcon,
                    label: t('toolbar.blockMath'),
                    hint: '$$x$$',
                    active: false,
                    run: () => {
                      const { from, to, empty } = editor.state.selection;
                      const latex = empty
                        ? 'x^2'
                        : editor.state.doc.textBetween(from, to, ' ');
                      editor.chain().focus().insertBlockMath({ latex }).run();
                    },
                  },
                  {
                    key: 'superscript',
                    group: 'notation',
                    Icon: SuperscriptIcon,
                    label: t('toolbar.superscript'),
                    hint: null,
                    active: isActive('superscript'),
                    run: () => editor.chain().focus().toggleSuperscript().run(),
                  },
                  {
                    key: 'subscript',
                    group: 'notation',
                    Icon: SubscriptIcon,
                    label: t('toolbar.subscript'),
                    hint: null,
                    active: isActive('subscript'),
                    run: () => editor.chain().focus().toggleSubscript().run(),
                  },
                ].map((item, i, all) => (
                  <Fragment key={item.key}>
                    {/* A header opens each run of entries sharing a group. The
                        list is authored in group order, so comparing with the
                        previous entry is enough and no second array can fall
                        out of step with this one. */}
                    {(i === 0 || all[i - 1]?.group !== item.group) && (
                      <div className="px-3 pt-2 pb-0.5 text-[11px] uppercase tracking-wide text-neutral-400 dark:text-neutral-500">
                        {t(`insertGroup.${item.group}`)}
                      </div>
                    )}
                    <button
                      type="button"
                      onPointerDown={(e) => {
                        e.preventDefault();
                        item.run();
                        setInsertOpen(false);
                      }}
                      className={`w-full flex items-center gap-2.5 text-start px-3 py-1.5 text-sm [@media(hover:hover)]:hover:bg-neutral-100 [@media(hover:hover)]:dark:hover:bg-neutral-800 active:bg-neutral-100 dark:active:bg-neutral-800 transition ${
                        item.active ? 'text-accent' : 'text-neutral-700 dark:text-neutral-200'
                      }`}
                    >
                      <item.Icon size={TB_ICON} />
                      <span className="flex-1">{item.label}</span>
                      {item.hint && (
                        <span className="text-[11px] font-mono text-neutral-400 dark:text-neutral-500">{item.hint}</span>
                      )}
                    </button>
                  </Fragment>
                ))}
              </div>,
              document.body,
            )}
          </div>
          {hasOverflow && (
            <ToolbarBtn
              onClick={() => setFormatExpanded((v) => !v)}
              active={formatExpanded}
              label={formatExpanded ? t('toolbar.fewerFormatting') : t('toolbar.moreFormatting')}
              tabIndex={mobileTabIndex}
            >
              <MoreIcon size={TB_ICON} />
            </ToolbarBtn>
          )}
          {!hideEncryptedMedia && (
          <>
          {/* Hairline, not a tinted box. An accent fill here would be the only
              filled container in the editor's three control rows, reading as a
              different kind of control rather than the last group in a row.
              Spec: ops/docs/ui-patterns.md (section 80) */}
          <span aria-hidden="true" className="shrink-0 mx-0.5 h-4 w-px bg-neutral-300 dark:bg-neutral-700" />
          <div className="flex items-center gap-0.5">
            <ToolbarBtn onClick={() => fileInputRef.current?.click()} label={t('toolbar.image')} tabIndex={mobileTabIndex}>
              <ImageIcon size={TB_ICON} />
            </ToolbarBtn>
            <ToolbarBtn onClick={() => attachmentInputRef.current?.click()} label={t('toolbar.attachFile')} tabIndex={mobileTabIndex}>
              <PaperclipIcon size={TB_ICON} />
            </ToolbarBtn>
            {/* Camera/mic getUserMedia is dead in the Linux (WebKitGTK) app with no fallback, so hide the recorder there. See ops/docs/gotchas.md. */}
            {!isLinuxNative() && (
              <AudioRecorder editorView={editor.view} tabIndex={mobileTabIndex} onStateChange={onAudioStateChange} stopRef={audioStopRef} />
            )}
          </div>
          </>
          )}
        </div>
      </div>

      {/* Row 2: the overflow buttons, full width, revealed by •••. */}
      {formatExpanded && hasOverflow && (
        <div className="flex flex-wrap items-center gap-0.5 px-4 sm:px-6 py-1 border-t border-divider">
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
  );
}
