/**
 * TipTap inline-node extension for [[wiki-links]].
 *
 * Stores two attributes:
 *   - `target`: the note title being linked to
 *   - `label`:  optional display text (for [[target|label]] syntax)
 *
 * Renders as a clickable pill in the editor. Clicking navigates to
 * the target note (by title match). If no match is found, the click
 * creates a new note with that title.
 *
 * Markdown round-trip: stored as `[[target]]` or `[[target|label]]`.
 * The tiptap-markdown integration uses addStorage().markdown for
 * serialization, and an inputRule + pasteRule handle the parse side
 * (markdown-it doesn't know wiki-link syntax natively).
 */

import { InputRule, mergeAttributes, Node } from '@tiptap/core';
import { NodeViewWrapper, ReactNodeViewRenderer } from '@tiptap/react';
import { Fragment, Slice, type Node as PMNode } from '@tiptap/pm/model';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import { wikiLinkSuggestion } from './NoteLinkSuggestion';
import { HoverLabel } from './HoverLabel';

/* ------------------------------------------------------------------ */
/* Navigation callback - set by the host (NotesView) via extension    */
/* storage so the node view can navigate without prop-drilling.       */
/* ------------------------------------------------------------------ */

type WikiLinkNavigator = (target: string) => void;

const NAVIGATE_KEY = '__wikiLinkNavigate';

/** Call from NotesView to wire up the navigation callback. */
export function setWikiLinkNavigator(
  // `storage: unknown` rather than a Record: TipTap 3 types editor.storage as
  // an interface without an index signature, which no longer matches a Record
  // parameter structurally. The runtime shape is unchanged.
  editor: { storage: unknown } | null,
  fn: WikiLinkNavigator
) {
  if (!editor) return;
  const store = (editor.storage as Record<string, Record<string, unknown>>).wikiLink;
  if (store) store[NAVIGATE_KEY] = fn;
}

/* ------------------------------------------------------------------ */
/* Inline node view                                                   */
/* ------------------------------------------------------------------ */

function WikiLinkView({
  node,
  editor,
}: {
  node: { attrs: { target: string; label: string | null } };
  editor: { storage: Record<string, Record<string, unknown>>; isEditable: boolean };
}) {
  const { target, label } = node.attrs;
  const display = label || target;
  const wlStore = editor.storage.wikiLink as Record<string, unknown> | undefined;
  // Read the navigator out of the storage box AT CLICK TIME, never at render
  // time. NotesView rewrites the box on every render, and the navigator it
  // writes closes over the live filters and note list. A node view renders
  // once and then sits there across every one of those renders, so a captured
  // copy is the state of the app when the link happened to be drawn - or
  // `null`, for a node drawn before NotesView first wired the box, whose click
  // then does nothing at all.
  const go = () => {
    const navigate = wlStore?.[NAVIGATE_KEY] as WikiLinkNavigator | undefined;
    if (navigate) navigate(target);
  };

  const span = (
    <span
      role="link"
      tabIndex={0}
      onClick={(e) => {
        e.preventDefault();
        e.stopPropagation();
        go();
      }}
      onKeyDown={(e) => {
        if (e.key === 'Enter') {
          e.preventDefault();
          go();
        }
      }}
      className="text-accent hover:text-accent-hover underline underline-offset-2 cursor-pointer rounded px-0.5 -mx-0.5 hover:bg-accent/10 transition"
      aria-label={target !== display ? target : undefined}
    >
      {display}
    </span>
  );

  return (
    <NodeViewWrapper as="span" className="inline">
      {target !== display
        ? <HoverLabel label={target} position="above" inline>{span}</HoverLabel>
        : span}
    </NodeViewWrapper>
  );
}

/* ------------------------------------------------------------------ */
/* markdown-it inline rule for [[wiki-links]]                        */
/* ------------------------------------------------------------------ */

/** Minimal typing for the markdown-it inline state we touch. */
interface WikiLinkParseState {
  src: string;
  pos: number;
  posMax: number;
  push: (type: string, tag: string, nesting: number) => {
    attrSet: (k: string, v: string) => void;
    content: string;
  };
}

function wikiLinkRule(state: WikiLinkParseState): boolean {
  const { src, pos, posMax } = state;
  // Must start with [[
  if (src.charCodeAt(pos) !== 0x5B || src.charCodeAt(pos + 1) !== 0x5B) {
    return false;
  }
  // `![[target]]` is Obsidian's EMBED, a different thing from a note-link, and
  // it is what a vault writes for an inline image. markdown-it's image rule
  // does not recognise that shape, so without this guard the `!` is left
  // stranded as literal text and the rest becomes a note-link - which is both
  // wrong on screen and, once serialized back, a rewrite of the user's file.
  // Spec: ops/docs/plans/markdown-folder.md (section 8, media)
  if (pos > 0 && src.charCodeAt(pos - 1) === 0x21) {
    return false;
  }
  // Find closing ]]
  const closeIdx = src.indexOf(']]', pos + 2);
  if (closeIdx < 0 || closeIdx > posMax) return false;

  const inner = src.slice(pos + 2, closeIdx);
  if (!inner.trim()) return false;

  // Split on | for optional display text
  const pipeIdx = inner.indexOf('|');
  const target = pipeIdx >= 0 ? inner.slice(0, pipeIdx).trim() : inner.trim();
  const label = pipeIdx >= 0 ? inner.slice(pipeIdx + 1).trim() : null;

  if (!target) return false;

  // Emit an HTML token that parseHTML will pick up.
  // Escape quotes in attrs to prevent injection.
  const esc = (s: string) => s.replace(/&/g, '&amp;').replace(/"/g, '&quot;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const escText = (s: string) => s.replace(/&/g, '&amp;').replace(/</g, '&lt;').replace(/>/g, '&gt;');
  const tokenOpen = state.push('html_inline', '', 0);
  const labelAttr = label ? ` data-label="${esc(label)}"` : '';
  tokenOpen.content = `<span data-wiki-link data-target="${esc(target)}"${labelAttr}>${escText(label || target)}</span>`;

  state.pos = closeIdx + 2;
  return true;
}

/* ------------------------------------------------------------------ */
/* Extension                                                          */
/* ------------------------------------------------------------------ */

export const WikiLink = Node.create({
  name: 'wikiLink',
  group: 'inline',
  inline: true,
  atom: true,

  addAttributes() {
    return {
      target: { default: '' },
      label: { default: null },
    };
  },

  parseHTML() {
    return [
      {
        tag: 'span[data-wiki-link]',
        getAttrs: (el) => {
          const dom = el as HTMLElement;
          return {
            target: dom.getAttribute('data-target') || '',
            label: dom.getAttribute('data-label') || null,
          };
        },
      },
    ];
  },

  renderHTML({ HTMLAttributes }) {
    // `target` and `label` are NODE attributes, not HTML ones, so they are
    // taken out before the merge. Spreading them straight onto the tag wrote a
    // second, meaningless `target="Some note"` beside the `data-target` that
    // actually carries it. It is not cosmetic: a block that cannot be written
    // as markdown - an aligned paragraph, a table that is not a pipe table -
    // falls back to this HTML, so the junk attribute was stored in the user's
    // own note and shown in the markdown source view.
    const { target, label, ...rest } = HTMLAttributes;
    return [
      'span',
      mergeAttributes(rest, {
        'data-wiki-link': '',
        'data-target': target,
        'data-label': label || undefined,
      }),
      label || target,
    ];
  },

  addNodeView() {
    return ReactNodeViewRenderer(WikiLinkView as never);
  },

  addKeyboardShortcuts() {
    // A note-link is one uneditable pill, and with no handler here the
    // browser is the one that decides what deleting next to it does.
    // prosemirror-view carries a workaround for that deletion failing on
    // Chrome and Firefox for Android, and the workaround only runs when the
    // browser left the DOM untouched, so the outcome there is a race: the
    // pill goes, or it stays, or the text around it moves. Claiming both keys
    // makes the removal one plain transaction on every platform.
    const removeAdjacent = (before: boolean) => () =>
      this.editor.commands.command(({ tr, state }) => {
        const { empty, $anchor } = state.selection;
        if (!empty) return false;
        const node = before ? $anchor.nodeBefore : $anchor.nodeAfter;
        if (!node || node.type !== this.type) return false;
        const from = before ? $anchor.pos - node.nodeSize : $anchor.pos;
        tr.delete(from, from + node.nodeSize);
        return true;
      });

    return {
      Backspace: removeAdjacent(true),
      Delete: removeAdjacent(false),
    };
  },

  addInputRules() {
    // Type [[ and the closing ]] to create a wiki-link inline.
    // Matches: [[target]] or [[target|label]]
    const type = this.type;
    return [
      new InputRule({
        find: /\[\[([^\]|]+?)(?:\|([^\]]+?))?\]\]$/,
        handler: ({ state, range, match }) => {
          const target = match[1]?.trim() ?? '';
          const label = match[2]?.trim() || null;
          if (!target) return;
          const node = type.create({ target, label });
          state.tr.replaceWith(range.from, range.to, node);
        },
      }),
    ];
  },

  addProseMirrorPlugins() {
    const type = this.type;
    return [
      // Autocomplete dropdown when user types [[
      wikiLinkSuggestion(this.editor),
      // Paste rule: convert [[...]] in pasted text to wiki-link nodes.
      new Plugin({
        key: new PluginKey('wikiLinkPaste'),
        props: {
          transformPasted(slice) {
            const wikiRe = /\[\[([^\]|]+?)(?:\|([^\]]+?))?\]\]/g;

            function walkFragment(fragment: Fragment): Fragment {
              const newNodes: PMNode[] = [];
              fragment.forEach((node) => {
                if (node.isText && node.text) {
                  const text = node.text;
                  let lastIdx = 0;
                  let m: RegExpExecArray | null;
                  wikiRe.lastIndex = 0;
                  while ((m = wikiRe.exec(text)) !== null) {
                    if (m.index > lastIdx) {
                      newNodes.push(
                        node.type.schema.text(text.slice(lastIdx, m.index), node.marks)
                      );
                    }
                    newNodes.push(
                      type.create({
                        target: m[1]?.trim() ?? '',
                        label: m[2]?.trim() || null,
                      })
                    );
                    lastIdx = m.index + m[0].length;
                  }
                  if (lastIdx === 0) {
                    // No wiki-link matched - keep the original node as-is.
                    // (Pushing the cloned slice AND the original here used
                    // to duplicate every plain-text paste.)
                    newNodes.push(node);
                  } else if (lastIdx < text.length) {
                    // Trailing text after the final match.
                    newNodes.push(
                      node.type.schema.text(text.slice(lastIdx), node.marks)
                    );
                  }
                } else if (node.content.size > 0) {
                  newNodes.push(node.copy(walkFragment(node.content)));
                } else {
                  newNodes.push(node);
                }
              });
              return Fragment.fromArray(newNodes);
            }

            return new Slice(
              walkFragment(slice.content),
              slice.openStart,
              slice.openEnd
            );
          },
        },
      }),
    ];
  },

  addStorage() {
    return {
      [NAVIGATE_KEY]: null as WikiLinkNavigator | null,
      markdown: {
        serialize(
          state: { write: (s: string) => void; esc: (s: string) => string },
          node: { attrs: { target: string; label: string | null } }
        ) {
          const t = node.attrs.target;
          const l = node.attrs.label;
          if (l && l !== t) {
            state.write(`[[${t}|${l}]]`);
          } else {
            state.write(`[[${t}]]`);
          }
        },
        parse: {
          setup(md: { inline: { ruler: { push: (name: string, fn: (state: WikiLinkParseState) => boolean) => void } } }) {
            // Register a markdown-it inline rule that converts [[...]]
            // tokens into <span data-wiki-link> elements that parseHTML
            // picks up.
            md.inline.ruler.push('wiki_link', wikiLinkRule);
          },
          updateDOM(_el: HTMLElement) {
            // nothing to patch
          },
        },
      },
    };
  },
});
