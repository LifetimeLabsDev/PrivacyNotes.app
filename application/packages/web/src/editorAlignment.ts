import { TextAlign } from '@tiptap/extension-text-align';
import { getHTMLFromFragment } from '@tiptap/core';
import { Fragment, type Node as ProseMirrorNode } from '@tiptap/pm/model';
import { TextSelection } from '@tiptap/pm/state';

/**
 * Alignments the toolbar offers, in display order.
 *
 * 'left' is pickable but never STORED: choosing it unsets the attribute rather
 * than setting it, and serializeAlignedBlock ignores it if one arrives from
 * imported HTML anyway. Left is what unstyled text already does, so writing
 * `<p style="text-align: left">` would swap a clean paragraph for an HTML blob
 * in the markdown source and change nothing on screen. The accepted trade is
 * that explicit-left is not a state the toolbar can show as active.
 */
export const ALIGNMENT_VALUES = ['left', 'center', 'right', 'justify'] as const;

/**
 * TextAlign with its Mod-Shift-L binding REMOVED.
 *
 * The extension ships four silent shortcuts (Mod-Shift-L/E/R/J) and the L one
 * collides head-on with our own ⌘⇧L, which toggles light/dark mode and has
 * been documented in the hotkeys modal far longer than this extension has
 * existed. The collision is not a race that one side wins: our theme handler
 * is a `window` keydown listener with no editing guard, and ProseMirror's
 * keymap calls preventDefault WITHOUT stopPropagation, so the event ran both -
 * one keypress flipped the theme AND changed the block's alignment.
 *
 * Upstream's binding also set an explicit `left`, which our serializer drops
 * anyway (see ALIGNMENT_VALUES), so the shortcut was writing a state that
 * could not survive a save. Dropping it costs nothing: the popover still
 * offers left, and left means "unset" there.
 *
 * E / R / J are kept exactly as upstream defines them - they collide with
 * nothing of ours, and the browser-level conflicts (hard reload, devtools)
 * were reviewed and accepted, since they only bind while the editor has focus.
 */
/**
 * Selection span (in ProseMirror positions, roughly characters) past which
 * setTextAlign switches to the single-step path below. The stock command
 * dispatches one attr-update step per block; on a select-all over a huge
 * note that bookkeeping dominated - measured 5.5 s for 4,201 blocks where
 * one ReplaceStep over the same blocks dispatches in ~0.95 s (#150).
 */
const BIG_ALIGN_SELECTION_SPAN = 50_000;

export const TextAlignOurLeft = TextAlign.extend({
  addKeyboardShortcuts() {
    // Toggle, never set (upstream only sets): pressing the active
    // alignment's combo again returns the block to the left default, so
    // keyboard-only users can un-align. Mod-Shift-l stays removed - it
    // collides with the app's theme toggle. Decided 2026-08-21 with the
    // hotkey audit; "align left" is these three keys pressed twice.
    return {
      'Mod-Shift-e': () => this.editor.commands.toggleTextAlign('center'),
      'Mod-Shift-r': () => this.editor.commands.toggleTextAlign('right'),
      'Mod-Shift-j': () => this.editor.commands.toggleTextAlign('justify'),
    };
  },
  addCommands() {
    return {
      ...this.parent?.(),
      setTextAlign: (alignment: string) => ({ state, dispatch, commands }: any) => {
        if (!this.options.alignments.includes(alignment)) return false;
        const { from, to } = state.selection;
        // Ordinary selections: one updateAttributes per aligned type, which
        // is upstream's own body - map over the types, reduce with `some`.
        //
        // Copy it EXACTLY when touching this. v0.305.3 added this override
        // for the big-selection path below and wrote `every` here while its
        // comment claimed the small path was stock behavior bit-for-bit. It
        // was not: updateAttributes reports whether it FOUND a node of that
        // type, so with types ['heading', 'paragraph'] any selection without
        // a heading in it - a task item, a bullet, an ordinary paragraph -
        // short-circuited at `heading` and never reached the paragraph.
        // Aligning anything but a heading silently did nothing for three
        // versions. `some` also reports the honest answer: did anything move.
        if (to - from < BIG_ALIGN_SELECTION_SPAN) {
          return this.options.types
            .map((type: string) => commands.updateAttributes(type, { textAlign: alignment }))
            .some(Boolean);
        }
        // Huge selections: rebuild the covered blocks in ONE pass and
        // dispatch a single ReplaceStep. Untouched nodes are returned by
        // identity, so ProseMirror's view diff reuses their DOM instead of
        // redrawing them; overlap semantics mirror nodesBetween (any node
        // intersecting [from, to] of an aligned type gets the attr).
        if (dispatch) {
          const types = new Set<string>(this.options.types);
          const rebuild = (node: ProseMirrorNode, pos: number): ProseMirrorNode => {
            if (node.isText) return node;
            const overlaps = pos + node.nodeSize > from && pos < to;
            if (!overlaps) return node;
            let changed = false;
            const children: ProseMirrorNode[] = [];
            let childPos = pos + 1;
            node.content.forEach((child) => {
              const next = rebuild(child, childPos);
              if (next !== child) changed = true;
              children.push(next);
              childPos += child.nodeSize;
            });
            const aligns = types.has(node.type.name) && node.attrs['textAlign'] !== alignment;
            if (!aligns && !changed) return node;
            const attrs = aligns ? { ...node.attrs, textAlign: alignment } : node.attrs;
            return node.type.create(attrs, changed ? Fragment.from(children) : node.content, node.marks);
          };
          const replacement: ProseMirrorNode[] = [];
          state.doc.forEach((node: ProseMirrorNode, offset: number) => {
            replacement.push(rebuild(node, offset));
          });
          const tr = state.tr.replaceWith(0, state.doc.content.size, replacement);
          // Attr-only changes keep every size, so the original offsets are
          // still valid in the new doc.
          tr.setSelection(TextSelection.create(tr.doc, from, to));
          dispatch(tr);
        }
        return true;
      },
    };
  },
});

/**
 * Serialize a text-aligned block as raw HTML, returning true when it did.
 *
 * Alignment has no markdown representation, and the trick our colored text
 * uses does not transfer: a `<span style>` is INLINE html, which markdown-it
 * passes through while still parsing the markdown around it, but a `<p style>`
 * is a BLOCK html token, and markdown-it stops parsing markdown inside one. So
 * emitting `<p style="text-align: center">**bold**</p>` would round-trip the
 * alignment and lose the bold.
 *
 * Rendering the whole node to HTML instead keeps both: marks come back as
 * `<strong>`/`<a>` tags that the DOM parser reads on load, and TextAlign's own
 * parseHTML picks the alignment back off `element.style.textAlign`. This is
 * the same escape hatch serializeTableToMarkdown already takes for tables that
 * cannot be expressed as a pipe table - the cost is that an aligned block
 * shows as HTML in the markdown source view, which is honest about what it is.
 */
export function serializeAlignedBlock(state: any, node: any): boolean {
  const align = node.attrs?.textAlign;
  if (!align || align === 'left') return false;
  state.write(getHTMLFromFragment(Fragment.from(node), node.type.schema));
  state.closeBlock(node);
  return true;
}

/** An alignment that has to be written out. Left is what plain text already does. */
export function isStoredAlignment(align: unknown): boolean {
  return typeof align === 'string' && align !== '' && align !== 'left';
}
