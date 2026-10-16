import type { Node as PMNode } from '@tiptap/pm/model';
import { TextSelection, type EditorState, type Transaction } from '@tiptap/pm/state';

/**
 * "Sort lines" in the body's selection menu: reorder the selected sibling
 * list items, or sibling paragraphs, by the text of their own line.
 *
 * It works on document nodes, not on Markdown lines, because a nested list
 * lives inside its parent item: sorting the items carries every child along
 * in its own order, and an ordered list renumbers itself. The order is the
 * platform collator in the reader's language, with the same settings as
 * folders and tags (case and accents ignored, numbers by value).
 *
 * Spec: ops/issues/archive/0391.md
 */

type LineSortDirection = 'asc' | 'desc';

export type LineSort = {
  /** A to Z, unless the lines are already in that order: then Z to A. */
  direction: LineSortDirection;
  apply: (tr: Transaction) => Transaction;
};

const ITEM_TYPES = new Set(['paragraph', 'listItem', 'taskItem']);
const NO_SORT_IN = new Set(['tableCell', 'tableHeader']);

/** The text a line sorts by: an item's own first line, never its children.
 *  A note-link is an atom with no text of its own, so it reads its label. */
function lineText(node: PMNode): string {
  const line = node.type.name === 'paragraph' ? node : node.firstChild;
  if (!line || !line.isTextblock) return '';
  return line
    .textBetween(0, line.content.size, ' ', (leaf) => String(leaf.attrs.label || leaf.attrs.target || ' '))
    .trim();
}

/**
 * The sort the current selection allows, or null when it allows none: an
 * empty selection, one line, a table cell, or lines of different kinds (a
 * heading among paragraphs, items of two lists). A partial selection widens
 * to whole lines; a line the selection only touches at its edge stays out.
 */
export function planLineSort(state: EditorState, locale: string, sinkChecked: boolean): LineSort | null {
  const sel = state.selection;
  // By its JSON type, not instanceof: a table's cell selection must not pass.
  const kind = (sel.toJSON() as { type: string }).type;
  if (sel.empty || (kind !== 'text' && kind !== 'all')) return null;
  const { $from, $to } = sel;
  const depth = $from.sharedDepth(sel.to);
  const parent = $from.node(depth);
  if (parent.isTextblock || NO_SORT_IN.has(parent.type.name)) return null;

  const children: { node: PMNode; from: number; to: number }[] = [];
  parent.forEach((node, offset) => {
    const from = $from.start(depth) + offset;
    children.push({ node, from, to: from + node.nodeSize });
  });
  const hasText = (a: number, b: number) => a < b && state.doc.textBetween(a, b, ' ', ' ').trim() !== '';
  let lines = children.slice($from.index(depth), $to.index(depth) + 1);
  while (lines.length > 1 && !hasText(Math.max(sel.from, lines[0]!.from), lines[0]!.to)) lines = lines.slice(1);
  while (lines.length > 1 && !hasText(lines.at(-1)!.from, Math.min(sel.to, lines.at(-1)!.to))) lines = lines.slice(0, -1);
  const [firstLine] = lines;
  const lastLine = lines.at(-1);
  if (!firstLine || !lastLine || lines.length < 2) return null;

  const nodes = lines.map((l) => l.node);
  const type = firstLine.node.type.name;
  if (!ITEM_TYPES.has(type) || nodes.some((n) => n.type.name !== type)) return null;

  const collator = new Intl.Collator(locale, { sensitivity: 'base', numeric: true });
  const keyed = nodes.map((node) => ({ node, key: lineText(node) }));
  // Empty lines go last in both directions. With "move checked items down"
  // on, open and checked tasks sort inside their own group, so the sort
  // never undoes that setting.
  const order = (dir: LineSortDirection) => {
    const cmp = (a: (typeof keyed)[number], b: (typeof keyed)[number]) => {
      if (!a.key || !b.key) return (a.key ? 0 : 1) - (b.key ? 0 : 1);
      const c = collator.compare(a.key, b.key);
      return dir === 'asc' ? c : -c;
    };
    const groups = type === 'taskItem' && sinkChecked
      ? [keyed.filter((k) => !k.node.attrs.checked), keyed.filter((k) => k.node.attrs.checked)]
      : [keyed];
    return groups.flatMap((g) => [...g].sort(cmp));
  };
  const unchanged = (list: typeof keyed) => list.every((k, i) => k === keyed[i]);

  const asc = order('asc');
  const direction: LineSortDirection = unchanged(asc) ? 'desc' : 'asc';
  const sorted = direction === 'asc' ? asc : order('desc');
  if (unchanged(sorted)) return null;

  const { from } = firstLine;
  const { to } = lastLine;
  return {
    direction,
    apply: (tr) => {
      tr.replaceWith(from, to, sorted.map((k) => k.node));
      return tr.setSelection(TextSelection.between(tr.doc.resolve(from), tr.doc.resolve(to)));
    },
  };
}
