/**
 * TipTap block node for Obsidian-style callouts.
 *
 * A callout is a colored, collapsible box with a rich title and block body:
 *
 *   > [!warning]+ Heads up
 *   > This can't be undone.
 *
 * The marker after the type sets the fold state on serialize: `+` expanded,
 * `-` folded, none = expanded. Every callout is foldable in the editor via a
 * chevron; we always write `+`/`-`. This is Obsidian-native, so notes import
 * and export 1:1 (see ops/docs/callouts.md).
 *
 * Structure: a `callout` node holds a `calloutTitle` (inline) followed by the
 * body (`block+`). The title is real editor content, so bold/links/note-links
 * work in it and round-trip through markdown.
 *
 * Parse: a markdown-it block rule (registered via tiptap-markdown's
 * parse.setup) turns `> [!type] ...` blockquotes into
 * `<div data-callout><div data-callout-title>..</div>..body..</div>` HTML,
 * which parseHTML rebuilds. Registering at the markdown-it level means load,
 * import, AND paste all go through it. Non-callout blockquotes fall through to
 * StarterKit's blockquote untouched.
 */

import { Node, mergeAttributes, InputRule } from '@tiptap/core';
import { ReactNodeViewRenderer, NodeViewWrapper, NodeViewContent } from '@tiptap/react';
import { Fragment, type Node as ProseMirrorNode } from '@tiptap/pm/model';
import { TextSelection, type EditorState } from '@tiptap/pm/state';
import type { EditorView } from '@tiptap/pm/view';
import { GapCursor } from '@tiptap/pm/gapcursor';
import { useTranslation } from 'react-i18next';
import { ArrowsOutSimple, ArrowsInSimple } from './icons';
import { CALLOUT_BY_TYPE, canonicalCalloutType, type CalloutType } from './calloutTypes';

declare module '@tiptap/core' {
  interface Commands<ReturnType> {
    callout: {
      /** Insert a fresh callout of the given type (or change the current one). */
      insertCallout: (type?: CalloutType) => ReturnType;
      /** Change the type of the callout the selection is inside. */
      setCalloutType: (type: CalloutType) => ReturnType;
      /** Remove the callout the selection is inside, keeping its content as plain blocks. */
      removeCallout: () => ReturnType;
    };
  }
}

/* ------------------------------------------------------------------ */
/* Leading-node escape                                                */
/* ------------------------------------------------------------------ */

/**
 * Place a gap cursor just before a callout so content can be added above it,
 * even when the callout is the first node in the document (the classic
 * leading-block trap where there is no line to click into). This is the
 * tiptap-native fix: nothing permanent is added to the document. It only falls
 * back to inserting an empty paragraph if a gap cursor is not valid there.
 * `requireStart` limits ArrowLeft to the very start of the title; ArrowUp fires
 * from anywhere on the title's top visual line.
 */
function escapeAboveCallout(state: EditorState, view: EditorView, requireStart: boolean): boolean {
  const sel = state.selection;
  if (!sel.empty) return false;
  const $from = sel.$from;
  if ($from.parent.type.name !== 'calloutTitle') return false;
  if (requireStart ? $from.parentOffset !== 0 : !view.endOfTextblock('up')) return false;
  const calloutDepth = $from.depth - 1;
  const callout = $from.node(calloutDepth);
  if (!callout || callout.type.name !== 'callout') return false;
  const before = $from.before(calloutDepth);
  const nodeBefore = state.doc.resolve(before).nodeBefore;
  // If a normal typeable block sits above, let the default arrow move into it.
  if (nodeBefore && nodeBefore.isTextblock) return false;
  const $pos = state.doc.resolve(before);
  const parent = $pos.parent;
  const deflt = parent.contentMatchAt($pos.index()).defaultType;
  // A gap cursor is valid here when the parent can hold a textblock at this
  // index (mirrors prosemirror-gapcursor's own check, which is not exported).
  const gapCursorOk =
    !parent.isTextblock &&
    parent.type.spec.allowGapCursor !== false &&
    !!deflt &&
    deflt.isTextblock;
  if (gapCursorOk) {
    view.dispatch(state.tr.setSelection(new GapCursor($pos)).scrollIntoView());
    return true;
  }
  const paragraph = state.schema.nodes.paragraph?.createAndFill();
  if (!paragraph) return false;
  const tr = state.tr.insert(before, paragraph);
  tr.setSelection(TextSelection.create(tr.doc, before + 1));
  view.dispatch(tr.scrollIntoView());
  return true;
}

/* ------------------------------------------------------------------ */
/* Node view                                                          */
/* ------------------------------------------------------------------ */

function CalloutView({
  node,
  updateAttributes,
}: {
  node: {
    attrs: { type: CalloutType; folded: boolean };
    childCount: number;
    firstChild: { type: { name: string }; content: { size: number } } | null;
  };
  updateAttributes: (attrs: Record<string, unknown>) => void;
}) {
  const { t } = useTranslation('editor');
  const type = node.attrs.type;
  const folded = node.attrs.folded;
  const def = CALLOUT_BY_TYPE[type] ?? CALLOUT_BY_TYPE.info;
  const Icon = def.icon;

  // Show the type name as a placeholder while the title is empty (Obsidian
  // shows the type as the default title). The title is the first child.
  const titleEmpty =
    node.firstChild?.type.name === 'calloutTitle' && node.firstChild.content.size === 0;
  const label = t(`callout.types.${type}`);

  return (
    <NodeViewWrapper
      as="div"
      className={`pn-callout pn-callout-${type}${folded ? ' pn-callout-folded' : ''}`}
      data-callout=""
      data-type={type}
      style={{ ['--cc' as string]: def.rgb, ['--cs' as string]: def.color } as React.CSSProperties}
    >
      <span className="pn-callout-icon" contentEditable={false}>
        <Icon size={18} weight="bold" />
      </span>
      <button
        type="button"
        className="pn-callout-fold"
        contentEditable={false}
        onMouseDown={(e) => e.preventDefault()}
        onClick={() => updateAttributes({ folded: !folded })}
        aria-label={folded ? t('callout.expand') : t('callout.collapse')}
      >
        {folded ? <ArrowsOutSimple size={15} weight="bold" /> : <ArrowsInSimple size={15} weight="bold" />}
      </button>
      {titleEmpty && (
        <span className="pn-callout-placeholder" contentEditable={false} aria-hidden="true">
          {label}
        </span>
      )}
      <NodeViewContent className="pn-callout-content" />
    </NodeViewWrapper>
  );
}

/* ------------------------------------------------------------------ */
/* markdown-it block rule: > [!type] ... -> callout HTML               */
/* ------------------------------------------------------------------ */

// Loose typing for the slice of markdown-it's block state we touch.
interface MdBlockState {
  src: string;
  bMarks: number[];
  eMarks: number[];
  tShift: number[];
  sCount: number[];
  blkIndent: number;
  line: number;
  env: unknown;
  tokens: unknown[];
  md: {
    block: { parse: (src: string, md: unknown, env: unknown, out: unknown[]) => void };
  };
  push: (type: string, tag: string, nesting: number) => {
    attrs: [string, string][] | null;
    map: number[] | null;
    content: string;
    children: unknown[] | null;
    block: boolean;
  };
}

function calloutBlockRule(state: MdBlockState, startLine: number, endLine: number, silent: boolean): boolean {
  // Not while inside indented code.
  if (state.sCount[startLine]! - state.blkIndent >= 4) return false;

  const start = state.bMarks[startLine]! + state.tShift[startLine]!;
  const max = state.eMarks[startLine]!;
  if (state.src.charCodeAt(start) !== 0x3e /* > */) return false;

  const firstLine = state.src.slice(start, max);
  const m = firstLine.match(/^>\s?\[!(\w+)\]([+-]?)\s?(.*)$/);
  if (!m) return false;
  if (silent) return true;

  // Consume consecutive blockquote lines (every callout line is `>`-prefixed
  // in both Obsidian and our serializer). A non-`>` line ends the callout.
  let nextLine = startLine + 1;
  const bodyLines: string[] = [];
  for (; nextLine < endLine; nextLine++) {
    const pos = state.bMarks[nextLine]! + state.tShift[nextLine]!;
    if (state.src.charCodeAt(pos) !== 0x3e /* > */) break;
    const text = state.src.slice(pos, state.eMarks[nextLine]!);
    bodyLines.push(text.replace(/^>\s?/, ''));
  }

  const type = canonicalCalloutType(m[1]!);
  const folded = m[2] === '-';
  const title = m[3] ?? '';

  const open = state.push('callout_open', 'div', 1);
  open.block = true;
  open.map = [startLine, nextLine];
  open.attrs = [
    ['data-callout', ''],
    ['data-type', type],
    ['data-folded', String(folded)],
    ['class', 'pn-callout'],
  ];

  const titleOpen = state.push('callout_title_open', 'div', 1);
  titleOpen.attrs = [['data-callout-title', '']];
  const inline = state.push('inline', '', 0);
  inline.content = title;
  inline.map = [startLine, startLine + 1];
  inline.children = [];
  state.push('callout_title_close', 'div', -1);

  const bodyStr = bodyLines.join('\n');
  if (bodyStr.trim() !== '') {
    // Re-tokenize the de-prefixed body as normal markdown. Nested callouts
    // (`> > [!x]`) fall out for free since this same rule runs on the body.
    state.md.block.parse(bodyStr, state.md, state.env, state.tokens);
  }

  state.push('callout_close', 'div', -1);

  state.line = nextLine;
  return true;
}

interface MdInstance {
  block: { ruler: { before: (ref: string, name: string, fn: typeof calloutBlockRule) => void } };
  renderer: { rules: Record<string, (tokens: { attrGet: (n: string) => string | null }[], idx: number) => string> };
}

function registerCalloutMarkdown(md: MdInstance) {
  md.block.ruler.before('blockquote', 'pn_callout', calloutBlockRule);
  md.renderer.rules.callout_open = (tokens, idx) => {
    const type = tokens[idx]!.attrGet('data-type') || 'info';
    const folded = tokens[idx]!.attrGet('data-folded') || 'false';
    return `<div data-callout data-type="${type}" data-folded="${folded}" class="pn-callout">`;
  };
  md.renderer.rules.callout_close = () => '</div>';
  md.renderer.rules.callout_title_open = () => '<div data-callout-title>';
  md.renderer.rules.callout_title_close = () => '</div>';
}

/* ------------------------------------------------------------------ */
/* Callout title node                                                 */
/* ------------------------------------------------------------------ */

export const CalloutTitle = Node.create({
  name: 'calloutTitle',
  content: 'inline*',
  defining: true,
  selectable: false,

  parseHTML() {
    return [{ tag: 'div[data-callout-title]' }];
  },

  renderHTML({ HTMLAttributes }) {
    return ['div', mergeAttributes(HTMLAttributes, { 'data-callout-title': '', class: 'pn-callout-title' }), 0];
  },

  addStorage() {
    return {
      markdown: {
        // Never reached in the normal path (the callout serializer renders the
        // title inline). Defensive: render inline if invoked standalone.
        serialize(state: { renderInline: (n: unknown) => void }, node: unknown) {
          state.renderInline(node);
        },
        parse: {},
      },
    };
  },
});

/* ------------------------------------------------------------------ */
/* Callout node                                                       */
/* ------------------------------------------------------------------ */

export const Callout = Node.create({
  name: 'callout',
  group: 'block',
  content: 'calloutTitle block+',
  defining: true,

  addAttributes() {
    return {
      type: {
        default: 'info',
        parseHTML: (el) => canonicalCalloutType(el.getAttribute('data-type') || 'info'),
        renderHTML: (attrs) => ({ 'data-type': attrs.type }),
      },
      folded: {
        default: false,
        parseHTML: (el) => el.getAttribute('data-folded') === 'true',
        renderHTML: (attrs) => ({ 'data-folded': attrs.folded ? 'true' : 'false' }),
      },
    };
  },

  parseHTML() {
    return [{ tag: 'div[data-callout]' }];
  },

  renderHTML({ HTMLAttributes }) {
    return ['div', mergeAttributes(HTMLAttributes, { 'data-callout': '', class: 'pn-callout' }), 0];
  },

  addNodeView() {
    return ReactNodeViewRenderer(CalloutView as never, {
      // Android froze the app the moment a callout was inserted. Three
      // behaviours upstream of us combine into a runaway loop:
      //
      //   1. React renders this node view through a portal, so the callout's
      //      own DOM appears AFTER ProseMirror's write window - which means
      //      ProseMirror's DOMObserver sees it as a foreign mutation instead
      //      of one of its own.
      //   2. tiptap's default ignoreMutation has an Android carve-out that
      //      reports such a mutation whenever every added node is
      //      contentEditable - exactly what React mounting the content div is.
      //   3. prosemirror-view's readDOMChange treats a foreign mutation that
      //      added a block element as the user having pressed Enter, and
      //      synthesizes the keydown for it.
      //
      // So inserting a callout looked like Enter, the resulting block split
      // re-rendered the node view, that looked like Enter again, and the
      // document grew forever at 100% CPU with the UI wedged.
      //
      // ignoreMutation is only consulted for mutations whose nearest view desc
      // is this node view - the wrapper and the content container, both of
      // which are React's to write. Text inside the title and body belongs to
      // their own descs, so reading real edits (and IME input) is untouched.
      // Spec: ops/docs/callouts.md (any future React node view with editable content needs this too)
      ignoreMutation: ({ mutation }) => mutation.type !== 'selection',
    });
  },

  addCommands() {
    return {
      insertCallout:
        (type: CalloutType = 'info') =>
        ({ state, dispatch, tr }) => {
          const { schema } = state;
          const titleType = schema.nodes.calloutTitle;
          const paragraph = schema.nodes.paragraph;
          if (!titleType || !paragraph) return false;
          const title = titleType.createAndFill();
          const body = paragraph.createAndFill();
          if (!title || !body) return false;
          const callout = this.type.create({ type, folded: false }, Fragment.fromArray([title, body]));
          // Selected text becomes the callout's body instead of being thrown
          // away - dropping an EMPTY box over the selection would read as
          // data loss. Grabbed from `state` because the transaction below
          // deletes the selection before we can use it.
          const wrapped = state.selection.empty ? null : state.selection.content();
          if (dispatch) {
            const from = tr.selection.from;
            if (wrapped) {
              // replaceRange, not replaceSelectionWith: a selection that
              // covers a whole block leaves that block behind EMPTY under
              // replaceSelectionWith, so wrapping a heading left a blank
              // heading above the new callout. replaceRange drops a parent
              // the selection fully covered, which is the WYSIWYG answer.
              tr.replaceRangeWith(from, tr.selection.to, callout);
            } else {
              tr.replaceSelectionWith(callout);
            }
            // Drop the cursor into the new callout's title. Search for the
            // calloutTitle near the insertion instead of doing position
            // arithmetic, which breaks when the insert splits the
            // surrounding block (offsetting everything after it). The start
            // is mapped because replaceRange can widen the replaced range
            // backwards, putting the callout BEFORE the old `from`.
            const start = tr.mapping.map(from, -1);
            let titlePos = -1;
            tr.doc.nodesBetween(start, Math.min(tr.doc.content.size, start + callout.nodeSize + 4), (node, pos) => {
              if (titlePos === -1 && node.type.name === 'calloutTitle') { titlePos = pos + 1; return false; }
              return true;
            });
            if (titlePos >= 0 && wrapped) {
              // Re-insert the slice through replaceSelection rather than
              // building the body node by hand: that is the same fitter the
              // paste path uses, so a selection that cuts across list items
              // or spans several blocks lands re-wrapped instead of throwing
              // on `block+`. The caret sits in the empty body paragraph, and
              // replaceRange drops that paragraph when block content arrives.
              const $title = tr.doc.resolve(titlePos);
              tr.setSelection(TextSelection.create(tr.doc, $title.after($title.depth) + 1));
              tr.replaceSelection(wrapped);
            }
            // Title last: it sits before the body, so the paste above never
            // moves it, and the user lands where the name goes.
            if (titlePos >= 0) tr.setSelection(TextSelection.create(tr.doc, titlePos));
            tr.scrollIntoView();
            dispatch(tr);
          }
          return true;
        },
      setCalloutType:
        (type: CalloutType) =>
        ({ commands }) =>
          commands.updateAttributes(this.name, { type }),
      // Unwrap the callout the selection is in: the title becomes a normal
      // paragraph and the body blocks are lifted out, so removing the box
      // never loses the text. This is the single "get rid of it" path shared
      // by the toolbar Remove button and Backspace at the start of the title.
      removeCallout:
        () =>
        ({ state, dispatch, tr }) => {
          const { $from } = state.selection;
          let depth = $from.depth;
          while (depth > 0 && $from.node(depth).type.name !== this.name) depth--;
          if (depth < 1 || $from.node(depth).type.name !== this.name) return false;
          const callout = $from.node(depth);
          const start = $from.before(depth);
          const end = $from.after(depth);
          const paragraph = state.schema.nodes.paragraph;
          if (!paragraph) return false;
          const replacement: ProseMirrorNode[] = [];
          callout.forEach((child, _offset, index) => {
            if (index === 0) {
              // Title -> paragraph, but only when it has content, so an empty
              // title does not leave a stray blank line above the body.
              if (child.content.size > 0) replacement.push(paragraph.create(null, child.content));
            } else {
              replacement.push(child);
            }
          });
          // Body is `block+`, so there is normally a block to keep; guard the
          // all-empty case so we never replace the callout with nothing.
          if (replacement.length === 0) {
            const empty = paragraph.createAndFill();
            if (empty) replacement.push(empty);
          }
          if (dispatch) {
            tr.replaceWith(start, end, Fragment.fromArray(replacement));
            tr.setSelection(TextSelection.create(tr.doc, start + 1));
            dispatch(tr.scrollIntoView());
          }
          return true;
        },
    };
  },

  addInputRules() {
    // Typing `[!type] ` (optionally `+`/`-`) at the start of a paragraph turns
    // it into a callout of that type.
    return [
      new InputRule({
        find: /^\[!(\w+)\]([+-]?)\s$/,
        handler: ({ state, range, match, chain }) => {
          const type = canonicalCalloutType(match[1] || 'info');
          const folded = match[2] === '-';
          chain()
            .deleteRange(range)
            .insertCallout(type)
            .command(({ commands }) => (folded ? commands.updateAttributes(this.name, { folded: true }) : true))
            .run();
        },
      }),
    ];
  },

  addKeyboardShortcuts() {
    return {
      // Enter in the title jumps to the body instead of trying to split the
      // (single, required) title node.
      Enter: ({ editor }) => {
        const { state } = editor;
        const { $from, empty } = state.selection;
        if (!empty) return false;
        if ($from.parent.type.name !== 'calloutTitle') return false;
        // Move to the start of the first body block (the title's next sibling).
        const after = $from.after($from.depth);
        const $after = state.doc.resolve(after);
        return editor.chain().setTextSelection($after.pos + 1).run();
      },
      // Backspace at the very start of the title removes the callout, unwrapping
      // its content back to plain blocks - the natural "get rid of it" gesture
      // (there is also a Remove button in the toolbar picker). Spec: ops/docs/callouts.md (two removal paths by design, the toolbar one requested in GitHub #170)
      Backspace: ({ editor }) => {
        const { $from, empty } = editor.state.selection;
        if (!empty) return false;
        if ($from.parent.type.name !== 'calloutTitle') return false;
        if ($from.parentOffset !== 0) return false;
        return editor.commands.removeCallout();
      },
      // Escape above a leading callout: ArrowUp from the title's top line, or
      // ArrowLeft from its very start, drops a gap cursor before the callout so
      // content can be added in front of it. Spec: ops/docs/callouts.md (uses tiptap's gap cursor, only falls back to a paragraph if invalid)
      ArrowUp: ({ editor }) => escapeAboveCallout(editor.state, editor.view, false),
      ArrowLeft: ({ editor }) => escapeAboveCallout(editor.state, editor.view, true),
    };
  },

  addStorage() {
    return {
      markdown: {
        serialize(
          state: {
            wrapBlock: (delim: string, first: string | null, node: unknown, f: () => void) => void;
            write: (s: string) => void;
            ensureNewLine: () => void;
            renderInline: (n: unknown) => void;
            render: (n: unknown, parent: unknown, i: number) => void;
          },
          node: {
            attrs: { type: string; folded: boolean };
            firstChild: { type: { name: string }; content: { size: number } } | null;
            forEach: (f: (child: unknown, offset: number, index: number) => void) => void;
          },
        ) {
          const type = node.attrs.type || 'info';
          const marker = node.attrs.folded ? '-' : '+';
          state.wrapBlock('> ', null, node, () => {
            state.write(`[!${type}]${marker}`);
            const title = node.firstChild;
            if (title && title.type.name === 'calloutTitle' && title.content.size > 0) {
              state.write(' ');
              state.renderInline(title);
            }
            state.ensureNewLine();
            node.forEach((child, _offset, index) => {
              if (index === 0) return; // title handled above
              state.render(child, node, index);
            });
          });
        },
        parse: {
          setup(md: MdInstance) {
            registerCalloutMarkdown(md);
          },
        },
      },
    };
  },
});
