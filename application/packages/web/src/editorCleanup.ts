import type { Editor as TipTapEditor } from '@tiptap/react';
import { Extension } from '@tiptap/core';
import type { Node as ProseMirrorNode } from '@tiptap/pm/model';
import { Plugin, PluginKey } from '@tiptap/pm/state';
import { markPlainEscape } from './plainEscape';
import { fixEmptyTaskItems } from './editorTasks';

/**
 * Collapse runs of 3+ newlines between consecutive media lines (images
 * and attachments) down to exactly 2 (one blank line). Prevents empty-
 * paragraph accumulation across save/load cycles.
 *
 * The root cause: markdown-it wraps `![alt](src)` in <p> tags, and
 * TipTap extracts our block-level image node, leaving the now-empty
 * paragraph behind. Each round-trip adds more empty paragraphs that
 * serialize as extra blank lines.
 *
 * Fix: GitHub #68 (empty spaces between attachments after navigating back)
 */
export function collapseMediaGaps(md: string): string {
  // Media line patterns:
  //   Image:      ![...](pn:img/...){width=N align=X} (optional attr suffix),
  //               or pn:file/... for a picture placed from Files
  //   Attachment:  [...|...|...](pn:file/...)
  const mediaLine =
    '(?:!\\[.*?\\]\\(pn:(?:img|file)\\/[^)]+\\)(?:\\{[^}\\n]*\\})?|\\[.*?\\|.*?\\|.*?\\]\\(pn:file\\/[^)]+\\))';
  return md.replace(
    new RegExp(`(${mediaLine})\\n{3,}(?=${mediaLine})`, 'g'),
    '$1\n\n',
  );
}

/**
 * Put a rewritten body into the open editor as one step of its history,
 * through the transforms the editor's own load applies, so Undo brings the
 * old body back. False when there is no editor or it takes no edits; the
 * caller then writes the row and remounts the editor itself.
 */
export function replaceBodyUndoably(editor: TipTapEditor | null | undefined, md: string): boolean {
  if (!editor || editor.isDestroyed || !editor.isEditable) return false;
  return editor.commands.setContent(collapseMediaGaps(fixEmptyTaskItems(md)));
}

/**
 * Ensures the document always ends with an empty paragraph so the user
 * can click/tap below block nodes (images, code blocks, tables) to
 * continue typing. Without this, a terminal image swallows the full
 * width and there's no insertion point after it.
 */
/**
 * Marks an Escape that reached the end of the editor's key handlers unused, so
 * the app's Escape cascade can close the note (plainEscape.ts). The lowest
 * priority puts it after every plugin that may use Escape, the note-link menu
 * among them, and it never consumes the key.
 */
export const PlainEscape = Extension.create({
  name: 'plainEscape',
  priority: 1,
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('plainEscape'),
        props: {
          handleKeyDown(_view, event) {
            if (event.key === 'Escape' && !event.isComposing) markPlainEscape(event);
            return false;
          },
        },
      }),
    ];
  },
});

export const TrailingParagraph = Extension.create({
  name: 'trailingParagraph',
  addProseMirrorPlugins() {
    return [
      new Plugin({
        key: new PluginKey('trailingParagraph'),
        appendTransaction(_transactions, _oldState, newState) {
          const { doc, schema } = newState;
          const lastNode = doc.lastChild;
          // The footnote section is always last, so the line goes in front of it.
          if (lastNode?.type.name === 'footnotes') {
            const before = doc.child(doc.childCount - 2);
            if (before.type.name === 'paragraph') return null;
            return newState.tr.insert(doc.content.size - lastNode.nodeSize, schema.nodes['paragraph']!.create());
          }
          if (lastNode && lastNode.type.name !== 'paragraph') {
            return newState.tr.insert(
              doc.content.size,
              schema.nodes['paragraph']!.create(),
            );
          }
          return null;
        },
      }),
    ];
  },
});

/*
 * There is deliberately no leading-edge mirror of TrailingParagraph.
 *
 * One existed (`LeadingParagraph`): it forced an empty paragraph in front of a
 * note whose first block was an image, table or quote, because none of those
 * leaves a line to click above. The cost was that it EDITED the note to fix a
 * UI problem - an empty paragraph serializes as `&nbsp;` (see
 * ParagraphWithMarkdown), so the first line of the user's markdown became a
 * blank one they never typed, which is also why callouts were excluded from it
 * (it would have broken the 1:1 Obsidian round-trip on every `> [!type]` note).
 *
 * Editor.tsx instead draws an "Add a line at the top" zone above any note
 * whose first block leaves no line to click, and the document is only touched
 * when the user actually asks for a line.
 */

/**
 * Removes the empty space markdown parsing leaves around media block nodes
 * (images and attachments) on initial document load.
 *
 * Root cause: markdown-it wraps `![alt](src)` in <p> tags. When
 * TipTap extracts the block-level image node, the now-empty <p>
 * wrapper remains as an empty paragraph. Each save/load cycle
 * accumulates more of these ghost paragraphs.
 *
 * This plugin fires once per editor instance (on the first
 * transaction after initial content parse) and strips empty
 * paragraphs that are sandwiched between media block nodes.
 * It preserves empty paragraphs at the start/end of the doc and
 * between non-media nodes so users can still type between content.
 *
 * It also heals notes written before media blocks closed their markdown block
 * properly (see the closeBlock call in EncryptedAttachment.tsx): those hold a
 * <br> after every media node, either alone in its own two-line-tall paragraph
 * or glued to the front of the text that followed. Only a break directly after
 * media is touched, so a break the user typed anywhere else survives.
 *
 * Fix: GitHub #68 (empty spaces between attachments after navigating back)
 */
const MEDIA_NODE_NAMES = new Set(['image', 'attachment']);

/**
 * A paragraph that carries no visible content: truly empty, or nothing but
 * hard breaks.
 *
 * The hard-break case is the residue of the serializer bug fixed in
 * EncryptedAttachment/EncryptedImage (a media block wrote a bare "\n" instead
 * of closing its block, so markdown-it's breaks:true turned the next line's
 * softbreak into a <br> and ProseMirror left it behind in its own paragraph).
 * Notes saved before that fix still hold one between every pair of media
 * blocks, two lines tall; without this they would keep it until something else
 * edited the note.
 */
function isBlankParagraph(node: ProseMirrorNode): boolean {
  if (node.type.name !== 'paragraph') return false;
  if (node.content.size === 0) return true;
  let blank = true;
  node.content.forEach((child) => {
    if (child.type.name !== 'hardBreak') blank = false;
  });
  return blank;
}

export const MediaGapCleaner = Extension.create({
  name: 'mediaGapCleaner',
  addProseMirrorPlugins() {
    let cleaned = false;
    return [
      new Plugin({
        key: new PluginKey('mediaGapCleaner'),
        appendTransaction(_transactions, _oldState, newState) {
          if (cleaned) return null;
          cleaned = true;

          const { doc, tr } = newState;
          const childCount = doc.childCount;
          if (childCount < 2) return null; // need at least media + something

          // Nearest sibling in either direction that isn't a blank paragraph.
          const mediaBefore = (i: number) => {
            for (let p = i - 1; p >= 0; p--) {
              const prev = doc.child(p);
              if (isBlankParagraph(prev)) continue;
              return MEDIA_NODE_NAMES.has(prev.type.name);
            }
            return false;
          };
          const mediaAfter = (i: number) => {
            for (let n = i + 1; n < childCount; n++) {
              const next = doc.child(n);
              if (isBlankParagraph(next)) continue;
              return MEDIA_NODE_NAMES.has(next.type.name);
            }
            return false;
          };

          // Collect positions of empty paragraphs between media blocks.
          // Walk children, identify runs of [media, empty_p+, media].
          const toDelete: { from: number; to: number }[] = [];
          let offset = 0;
          for (let i = 0; i < childCount; i++) {
            const node = doc.child(i);
            const leadingBreak = node.firstChild?.type.name === 'hardBreak';
            if (isBlankParagraph(node)) {
              if (mediaBefore(i) && mediaAfter(i)) {
                toDelete.push({ from: offset, to: offset + node.nodeSize });
              } else if (leadingBreak && mediaBefore(i)) {
                // A blank paragraph that only media precedes: keep the
                // paragraph (it's the one the user types into after the last
                // chip), drop the break that made it two lines tall.
                toDelete.push({ from: offset + 1, to: offset + 1 + node.firstChild!.nodeSize });
              }
            } else if (
              leadingBreak &&
              node.type.name === 'paragraph' &&
              mediaBefore(i)
            ) {
              // Same pre-fix residue, one block further on: text that followed
              // a media block was glued onto its line, so it came back with a
              // leading <br> instead of a paragraph split. Drop just the
              // break - the text is the user's.
              toDelete.push({ from: offset + 1, to: offset + 1 + node.firstChild!.nodeSize });
            }
            offset += node.nodeSize;
          }

          if (toDelete.length === 0) return null;

          // Delete in reverse order to keep earlier positions valid.
          for (let i = toDelete.length - 1; i >= 0; i--) {
            tr.delete(toDelete[i]!.from, toDelete[i]!.to);
          }
          return tr;
        },
      }),
    ];
  },
});

/**
 * Strip non-breaking spaces from paragraphs that contain only NBSP: the
 * top-level ones, the blank lines of a callout or a quote, and the empty line
 * of an empty checkbox.
 * These markers are added by EmptyParagraphSerializer on save to
 * survive the markdown round-trip. On load, we clean them so the
 * user gets truly empty paragraphs (no invisible characters that
 * interfere with typing).
 *
 * Fires once per editor instance on initial content parse. The
 * mountedRef guard in onUpdate suppresses the resulting onChange,
 * so this cleanup doesn't trigger a re-save.
 *
 * Fix: GitHub #101 (empty line spacing removed after reopening notes)
 */
export const NbspParagraphCleaner = Extension.create({
  name: 'nbspParagraphCleaner',
  addProseMirrorPlugins() {
    let cleaned = false;
    return [
      new Plugin({
        key: new PluginKey('nbspParagraphCleaner'),
        appendTransaction(_transactions, _oldState, newState) {
          if (cleaned) return null;
          cleaned = true;

          const { doc, tr } = newState;
          const toClean: { from: number; to: number }[] = [];
          let offset = 0;
          for (let i = 0; i < doc.childCount; i++) {
            const node = doc.child(i);
            // Only strip paragraphs whose entire content is NBSP text.
            // An inline atom (e.g. a wiki-link) has content.size > 0 but
            // empty textContent, so the old textContent-only check matched
            // a link-only paragraph and deleted the link. Require every
            // child to be a text node made up solely of NBSP.
            if (node.type.name === 'paragraph' && node.content.size > 0) {
              let onlyNbsp = true;
              node.content.forEach((child) => {
                if (!child.isText || child.text!.replace(/\u00a0/g, '').length !== 0) {
                  onlyNbsp = false;
                }
              });
              if (onlyNbsp) {
                toClean.push({ from: offset + 1, to: offset + 1 + node.content.size });
              }
            }
            offset += node.nodeSize;
          }

          // The same marker holds the empty line of an empty checkbox, which
          // sits inside its task item rather than at the top level. Left in,
          // it is a hidden character next to whatever the person types there.
          // A blank line inside a callout or a quote carries it too.
          doc.descendants((node, pos, parent) => {
            if (
              node.type.name === 'paragraph' &&
              (parent?.type.name === 'callout' || parent?.type.name === 'blockquote') &&
              node.content.size > 0
            ) {
              let onlyNbsp = true;
              node.content.forEach((child) => {
                if (!child.isText || child.text!.replace(/ /g, '').length !== 0) onlyNbsp = false;
              });
              if (onlyNbsp) toClean.push({ from: pos + 1, to: pos + 1 + node.content.size });
              return false;
            }
            if (node.type.name !== 'taskItem') return true;
            const first = node.firstChild;
            if (first?.type.name === 'paragraph' && first.content.size > 0) {
              let onlyNbsp = true;
              first.content.forEach((child) => {
                if (!child.isText || child.text!.replace(/\u00a0/g, '').length !== 0) onlyNbsp = false;
              });
              if (onlyNbsp) toClean.push({ from: pos + 2, to: pos + 2 + first.content.size });
            }
            return true;
          });

          if (toClean.length === 0) return null;
          toClean.sort((a, b) => a.from - b.from);

          // Delete in reverse order to keep earlier positions valid.
          for (let i = toClean.length - 1; i >= 0; i--) {
            tr.delete(toClean[i]!.from, toClean[i]!.to);
          }
          return tr;
        },
      }),
    ];
  },
});

/**
 * Split mixed bullet/task lists in the parsed markdown DOM before ProseMirror
 * sees them.
 *
 * CommonMark treats list items separated by blank lines as ONE loose list, so
 * markdown like "- plain item / blank line / - [ ] task item" reaches
 * markdown-it as a single <ul>. markdown-it-task-lists then marks the whole
 * list contains-task-list, tiptap-markdown maps it to a taskList node, and the
 * plain <li>s are invalid taskList children (content spec is taskItem+).
 * ProseMirror recovers by pushing them out into a bulletList and fills the
 * now-childless taskList's required content with one empty taskItem: a phantom
 * unchecked checkbox appears above the list, and a later save would persist it
 * as a bare "- [ ] " line. Reachable through imports and hand-written markdown;
 * found via a deliberately pathological note during the markdown-it 14.3.0
 * verification (v0.251.4).
 *
 * The fix runs in tiptap-markdown's parse.updateDOM hook, the same mechanism
 * the library itself uses to tag task lists: partition each mixed <ul> into
 * runs of consecutive same-kind items and emit one homogeneous <ul> per run.
 * Task runs inherit the original list's attributes (class and data-type, so
 * ordering relative to the taskList extension's own hook does not matter);
 * plain runs get a bare <ul> that parses as a bulletList. Homogeneous lists,
 * i.e. every normal task list, are left untouched. Serialization writes the
 * split lists adjacently, CommonMark merges them again on the next load, and
 * this hook re-splits them, so the round trip is stable and no phantom is
 * ever created. Detection keys off the markdown-it-task-lists classes rather
 * than data-type attributes for the same ordering reason.
 */
export const MixedListSplitter = Extension.create({
  name: 'mixedListSplitter',
  addStorage() {
    return {
      markdown: {
        parse: {
          updateDOM(element: HTMLElement) {
            element.querySelectorAll('ul.contains-task-list').forEach((list) => {
              const items = Array.from(list.children);
              const isTask = (li: Element) => li.classList.contains('task-list-item');
              if (items.every(isTask)) return;

              const runs: { task: boolean; items: Element[] }[] = [];
              for (const li of items) {
                const task = isTask(li);
                const last = runs[runs.length - 1];
                if (last && last.task === task) last.items.push(li);
                else runs.push({ task, items: [li] });
              }

              const lists = runs.map((run) => {
                const ul = list.ownerDocument.createElement('ul');
                if (run.task) {
                  for (const attr of Array.from(list.attributes)) {
                    ul.setAttribute(attr.name, attr.value);
                  }
                }
                for (const li of run.items) ul.appendChild(li);
                return ul;
              });
              list.replaceWith(...lists);
            });
          },
        },
      },
    };
  },
});
