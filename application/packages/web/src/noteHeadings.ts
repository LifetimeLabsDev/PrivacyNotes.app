import type { Node as PMNode } from '@tiptap/pm/model';
import { noteLinkKey } from './noteLinks';
import type { NoteType } from '@notes/shared';
import { hasStructuredBody, stripToPlainText } from './notesViewUtils';
import { nextFence, type Fence } from './markdownFence';

/**
 * The headings a note-link can point at (`[[Note#Heading]]`), read two ways
 * that must agree: from the open editor's document, and from the markdown
 * body of a note that is not open. A link made from one list is followed
 * with the other, so a heading text that differs between them is a link
 * that opens its note at the top. `tests/noteHeadings.test.ts` holds the two
 * readers to the same answer.
 *
 * A heading inside a callout is not a target, the same rule the outline
 * follows. Neither is a heading inside a quote, because the markdown reader
 * skips quoted lines, where a callout's own lines live too.
 *
 * Spec: ops/docs/plans/note-link-headings.md
 */

export type HeadingEntry = { level: number; text: string };

/** A note's headings, or 'locked' when its lock is closed. */
export type NoteHeadingsAnswer = HeadingEntry[] | 'locked';

/**
 * The headings another note offers a link: none from a form-shaped item,
 * and 'locked' from a note behind a closed lock, because its headings are
 * its content and the `[[` menu must not show them.
 */
export function noteHeadingsFor(note: { type: NoteType; body: string }, locked: boolean): NoteHeadingsAnswer {
  if (locked) return 'locked';
  return hasStructuredBody(note.type) ? [] : headingsFromMarkdown(note.body);
}

/** Containers whose headings the markdown body does not show as heading
 *  lines (a quote, a callout, a list item, a table cell), so neither reader
 *  lists them and a target is one both can find. */
const NO_HEADING_TARGETS = new Set(['callout', 'blockquote', 'listItem', 'taskItem', 'tableCell', 'tableHeader']);

/** Every heading of an editor document, with its position, in order. */
export function headingsFromDoc(doc: PMNode): (HeadingEntry & { pos: number })[] {
  const out: (HeadingEntry & { pos: number })[] = [];
  doc.descendants((node, pos) => {
    if (NO_HEADING_TARGETS.has(node.type.name)) return false;
    if (node.type.name === 'heading') {
      const text = node.textContent.trim();
      if (text) out.push({ pos, level: node.attrs.level ?? 1, text });
      return false;
    }
    return true;
  });
  return out;
}

/** Every ATX heading of a markdown body, outside code fences and quotes. */
export function headingsFromMarkdown(body: string): HeadingEntry[] {
  const out: HeadingEntry[] = [];
  let fence: Fence | null = null;
  for (const line of body.split(/\r?\n/)) {
    const step = nextFence(fence, line);
    fence = step.fence;
    if (step.isFence || fence !== null) continue;
    // A top-level list line that opens with a heading loads as that heading,
    // lifted out of its list, so it reads as one here too.
    const h = /^ {0,3}(?:[-*+][ \t]+)?(#{1,6})[ \t]+(.*)$/.exec(line);
    if (!h) continue;
    const text = stripToPlainText(h[2]!.replace(/[ \t]+#+[ \t]*$/, ''));
    if (text) out.push({ level: h[1]!.length, text });
  }
  return out;
}

/** One row per heading text: a link to the second "Notes" opens the first. */
export function uniqueHeadings<T extends HeadingEntry>(list: readonly T[]): T[] {
  const seen = new Set<string>();
  return list.filter((h) => {
    const key = noteLinkKey(h.text);
    if (seen.has(key)) return false;
    seen.add(key);
    return true;
  });
}

/**
 * The position of the heading a link names, or -1. The first heading in
 * document order wins. Obsidian's nested form `[[Note#Part 1#Step 2]]`
 * falls back to its last part.
 */
export function findHeadingPos(doc: PMNode, heading: string): number {
  const list = headingsFromDoc(doc);
  const find = (name: string) => {
    const key = noteLinkKey(name);
    return key ? list.find((h) => noteLinkKey(h.text) === key)?.pos ?? -1 : -1;
  };
  const pos = find(heading);
  if (pos >= 0 || !heading.includes('#')) return pos;
  return find(heading.slice(heading.lastIndexOf('#') + 1));
}
