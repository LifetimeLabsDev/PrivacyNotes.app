import { createContext, useContext, useEffect, useRef, useState, type RefObject } from 'react';
import type { ChainedCommands, Editor as TipTapEditor } from '@tiptap/react';
import { HoverLabel } from './HoverLabel';
import { usePopoverPosition } from './usePopoverPosition';
import { useEscapeToClose } from './useEscapeToClose';

// The editor toolbar's building blocks: its button system, the colour strip,
// the heading toggle and the popover hook. Toolbar (EditorToolbar.tsx)
// composes them.

/**
 * Compare two CSS colors as the swatch grid needs to: the value we wrote
 * into the mark comes back from the DOM re-spelled (`rgba(64,192,87,.35)`
 * vs `rgba(64, 192, 87, 0.35)`), so a raw === would show no swatch as
 * selected on a note reopened from storage. Whitespace and case are the
 * only differences the browser introduces between two spellings of the
 * same palette entry, which is all this has to absorb.
 */
export function normalizeCssColor(value: string | undefined): string {
  return (value ?? '').replace(/\s+/g, '').toLowerCase();
}

/**
 * The colour strip of a split colour button. It names the colour the button's
 * main half will apply, so a reader can see it without opening the popover.
 * It is positioned, never in the flow, so the glyph stays centred in its box
 * at the same height as every other glyph in the row.
 *
 * `underline` lies over the bar of the `TextAUnderline` glyph (18px glyph in
 * the 32px box): with no colour it is transparent and the glyph's own bar
 * shows. `below` sits under a glyph that has no bar of its own.
 *
 * `className` carries `pn-hl-default` for the highlight palette's default
 * entry, which has no stored colour and takes its themed pair from CSS.
 */
export function ColorBar({ color, place, className = '' }: { color?: string | null; place: 'underline' | 'below'; className?: string }) {
  const at = place === 'underline' ? 'start-[9px] top-[20.5px] w-3.5' : 'start-2 bottom-[3px] w-4';
  return (
    <span
      aria-hidden="true"
      className={`absolute ${at} h-[3px] rounded-full pointer-events-none ${className}`}
      style={color ? { background: color } : undefined}
    />
  );
}

/**
 * Make the keyboard commit the word it is still composing. Gboard keeps the
 * last typed word open until the next space; a toolbar command that redraws
 * that block (a heading) takes away the node the composition lives in, and
 * the commit then types the word a second time. A blur and refocus makes the
 * browser end the composition while the node is still there.
 */
export function endComposition(editor: TipTapEditor): void {
  const { view } = editor;
  if (!view.composing) return;
  view.dom.blur();
  view.focus();
}

const WORD_CHAR = /[\p{L}\p{N}\p{M}]/u;

/**
 * Run a colour or highlight command the way a word processor does: a bare
 * caret inside a word colours that word and the caret stays where it was.
 * A caret between words, or at either edge of one, keeps the stored mark,
 * so the next typed text takes the colour.
 */
export function runOnCaretWord(editor: TipTapEditor, apply: (chain: ChainedCommands) => ChainedCommands): void {
  const { selection } = editor.state;
  let chain = editor.chain().focus();
  if (!selection.empty) {
    apply(chain).run();
    return;
  }
  const { $from } = selection;
  const block = $from.parent;
  // One character per position: every inline leaf stands in as one char.
  const text = block.textBetween(0, block.content.size, undefined, '￼');
  const at = $from.parentOffset;
  if (!WORD_CHAR.test(text[at - 1] ?? '') || !WORD_CHAR.test(text[at] ?? '')) {
    apply(chain).run();
    return;
  }
  let start = at;
  while (start > 0 && WORD_CHAR.test(text[start - 1]!)) start--;
  let end = at;
  while (end < text.length && WORD_CHAR.test(text[end]!)) end++;
  const base = $from.start();
  chain = chain.setTextSelection({ from: base + start, to: base + end });
  apply(chain).setTextSelection(selection.from).run();
}

// ------------------------------------------------------------------
// Smart heading toggle - splits hard breaks into separate paragraphs
// before applying heading so only the cursor's line is affected.
// Fixes: H1/H2/H3 applying to entire note when content has hard breaks
// (from paste, Shift+Enter, or imported single-newline text).
// ------------------------------------------------------------------

export function smartToggleHeading(editor: TipTapEditor, level: 1 | 2 | 3 | 4 | 5 | 6) {
  endComposition(editor);
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
export const TB_BTN_BASE =
  'flex items-center justify-center w-8 h-8 rounded-md active:scale-95 transition disabled:opacity-40 disabled:cursor-not-allowed outline-none shrink-0';
export const TB_BTN_REST =
  'text-pn-soft [@media(hover:hover)]:hover:bg-pn/10';
export const TB_BTN_ACTIVE = 'bg-accent/15 text-accent-strong [@media(hover:hover)]:hover:bg-accent/25';
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
export const TB_SPLIT_MAIN =
  'relative flex items-center justify-center w-8 h-8 rounded-s-md active:scale-95 transition outline-none shrink-0';
export const TB_SPLIT_CARET =
  "relative flex items-center justify-center w-5 [@media(hover:none)]:w-6 h-8 rounded-e-md active:scale-95 transition outline-none shrink-0 " +
  "before:content-[''] before:absolute before:start-0 before:top-2 before:bottom-2 before:w-px before:bg-divider";
// Matches HEADER_ICON in notesView/NoteEditorPane.tsx: the two header rows
// and this toolbar are one instrument, so they share a box and a glyph size.
// Weight comes from the IconDefaults provider.
export const TB_ICON = 18;
// The caret of a split button. Only a split button carries one: a button whose
// one press opens a list (heading, alignment, font, callout) shows no caret.
export const TB_CARET = 11;
// What the ••• toggle costs row 1 once it appears: one 32px button box and
// the 6px gap before it. Only the frame that turns overflow on needs this -
// after that the toggle is in the cluster and the row is measured around it.
export const MORE_TOGGLE_W = 38;

/**
 * Which side of the bar its hover labels open on: below the bar at the top of
 * the note, above it when the person put the bar at the bottom, where a label
 * below would fall out of the view.
 */
export const TipSideContext = createContext<'below' | 'above'>('below');

export function ToolbarBtn({
  onClick,
  active,
  label,
  tabIndex,
  btnRef,
  children,
}: {
  onClick: () => void;
  active?: boolean;
  label: string;
  tabIndex?: number;
  /** Set on buttons a popover anchors to, so it can measure the real box. */
  btnRef?: RefObject<HTMLButtonElement | null>;
  children: React.ReactNode;
}) {
  const side = useContext(TipSideContext);
  return (
    <HoverLabel label={label} position={side}>
      <button
        ref={btnRef}
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


/**
 * One of the toolbar's portaled popovers: its open flag, the wrapper it lines
 * up with or the button inside it, the panel, and the two ways it closes. A
 * pointerdown outside both the wrapper and the panel closes it (the panel is
 * portaled to document.body, so the wrapper alone cannot tell), and so does
 * Escape, through the shared overlay stack, which also hands it to the Android
 * back button. A closed popover registers no listener at all.
 */
export function useToolbarPopover(anchor: 'wrap' | 'button') {
  const [open, setOpen] = useState(false);
  const wrapRef = useRef<HTMLDivElement>(null);
  const btnRef = useRef<HTMLButtonElement>(null);
  const popoverRef = useRef<HTMLDivElement>(null);
  const anchorRef: RefObject<HTMLElement | null> = anchor === 'wrap' ? wrapRef : btnRef;
  const pos = usePopoverPosition(open, anchorRef, popoverRef);
  useEffect(() => {
    if (!open) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node;
      if (wrapRef.current?.contains(target) || popoverRef.current?.contains(target)) return;
      setOpen(false);
    }
    document.addEventListener('pointerdown', handler);
    return () => document.removeEventListener('pointerdown', handler);
  }, [open]);
  useEscapeToClose(() => setOpen(false), open);
  return { open, setOpen, wrapRef, btnRef, popoverRef, pos };
}
