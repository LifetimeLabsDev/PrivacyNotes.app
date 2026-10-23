/**
 * Kanban board edits. A board is a callout of type `kanban` whose body is
 * callouts of type `column`; a card is a top-level task of a column. Every
 * edit here is one transaction, so undo takes it back in one step, and no
 * edit ever drops a card: a column that goes moves its content into the
 * column on its left (or on its right, for the first column).
 *
 * Stored form (Obsidian callout syntax, the color in its metadata):
 *
 *   > [!kanban]+ Title
 *   > > [!column|purple]+ To do
 *   > > - [ ] A card
 *
 * Spec: ops/issues/0270.md (Spec)
 */

import type { Node as PMNode, Schema } from '@tiptap/pm/model';
import { DEFAULT_COLORS } from './kanbanLayout';
import { Plugin, PluginKey, Selection, TextSelection, type EditorState, type Transaction } from '@tiptap/pm/state';

/** Event a tap on a card's grip sends to its board (kanbanDrag.ts). */
export const CARD_MENU_EVENT = 'pn-kanban-card-menu';
export type CardMenuDetail = { pos: number; column: number; x: number; y: number };

/** The fewest and the most columns a board keeps. */
export const MIN_COLUMNS = 2;
export const MAX_COLUMNS = 6;


export function isBoard(node: PMNode | null | undefined): boolean {
  return !!node && node.type.name === 'callout' && node.attrs.type === 'kanban';
}

export function isColumn(node: PMNode | null | undefined): boolean {
  return !!node && node.type.name === 'callout' && node.attrs.type === 'column';
}

/** The columns of a board, in order. */
export function columnsOf(board: PMNode): PMNode[] {
  const out: PMNode[] = [];
  board.forEach((child) => {
    if (isColumn(child)) out.push(child);
  });
  return out;
}

/** The body of a callout: its children after the title. */
function bodyOf(node: PMNode): PMNode[] {
  const out: PMNode[] = [];
  node.forEach((child, _offset, index) => {
    if (!(index === 0 && child.type.name === 'calloutTitle')) out.push(child);
  });
  return out;
}

function titleOf(node: PMNode): PMNode | null {
  const first = node.firstChild;
  return first && first.type.name === 'calloutTitle' ? first : null;
}

/** Joins task lists that sit next to each other, so cards moved into a
 *  column land in its list instead of in a second list under it. */
function joinTaskLists(blocks: PMNode[]): PMNode[] {
  const out: PMNode[] = [];
  for (const block of blocks) {
    const prev = out[out.length - 1];
    if (prev && prev.type.name === 'taskList' && block.type.name === 'taskList') {
      out[out.length - 1] = prev.type.create(prev.attrs, prev.content.append(block.content));
    } else {
      out.push(block);
    }
  }
  return out;
}

function isBlank(node: PMNode): boolean {
  if (node.type.name !== 'paragraph') return false;
  let blank = true;
  node.forEach((child) => {
    if (!child.isText || child.text!.replace(/\u00a0/g, '').trim() !== '') blank = false;
  });
  return blank;
}

/** A column with `blocks` as its body; an empty body gets one empty task,
 *  the line a new card is typed on. */
function columnWithBody(schema: Schema, column: PMNode, blocks: PMNode[]): PMNode {
  const body = joinTaskLists(blocks.filter((b, i, all) => !(isBlank(b) && all.length > 1)));
  const content = [titleOf(column) ?? schema.nodes.calloutTitle!.create(), ...(body.length && !(body.length === 1 && isBlank(body[0]!)) ? body : [emptyTaskList(schema)])];
  return column.type.create(column.attrs, content);
}

/** A task with one empty paragraph: the line a new card is typed on. A task
 *  holding only a note-link or another inline atom has empty text and is a
 *  card all the same, so the test is the paragraph, not the text. */
export function isPlaceholderTask(node: PMNode): boolean {
  return node.childCount === 1 && node.firstChild!.type.name === 'paragraph' && node.firstChild!.content.size === 0;
}

/** A task list holding one empty task. */
function isPlaceholderList(node: PMNode): boolean {
  return node.type.name === 'taskList' && node.childCount === 1 && isPlaceholderTask(node.firstChild!);
}

/** The columns of a board with every block that sits between columns moved
 *  to the end of the column before it (the first column for a block before
 *  them all), the rule the normalizer applies. A board loaded from a file
 *  can hold such blocks, and a board edit rebuilds the board from its
 *  columns, so they are folded in first and never dropped. */
function foldedColumns(board: PMNode): PMNode[] {
  const schema = board.type.schema;
  const cols: PMNode[] = [];
  const extra: PMNode[][] = [];
  const before: PMNode[] = [];
  board.forEach((child, _o, i) => {
    if (isColumn(child)) {
      cols.push(child);
      extra.push([]);
    } else if (i > 0 || child.type.name !== 'calloutTitle') {
      (cols.length ? extra[cols.length - 1]! : before).push(child);
    }
  });
  // A board with no columns yet keeps its content in a first column, so the
  // edit that adds columns never drops it.
  if (cols.length === 0) {
    if (before.length === 0) return [];
    return [schema.nodes.callout!.create({ type: 'column', folded: false, keyword: null, meta: null }, [schema.nodes.calloutTitle!.create(), ...before])];
  }
  // Blocks before every column come first, the order the normalizer leaves.
  if (before.length) extra[0]!.unshift(...before);
  // The body keeps its blocks as they are, so a position read from the
  // document still finds its block in the folded column.
  return cols.map((col, i) =>
    extra[i]!.length ? col.type.create(col.attrs, [titleOf(col) ?? schema.nodes.calloutTitle!.create(), ...bodyOf(col), ...extra[i]!]) : col,
  );
}

function emptyTaskList(schema: Schema): PMNode {
  const { taskList, taskItem, paragraph } = schema.nodes;
  return taskList!.create(null, taskItem!.create({ checked: false }, paragraph!.create()));
}

function makeColumn(schema: Schema, name: string, color: string | null): PMNode {
  const title = schema.nodes.calloutTitle!.create(null, name ? schema.text(name) : undefined);
  return schema.nodes.callout!.create(
    { type: 'column', folded: false, keyword: null, meta: color },
    [title, emptyTaskList(schema)],
  );
}

export function makeBoard(schema: Schema, names: string[], colors: (string | null)[]): PMNode {
  const columns = names.map((name, i) => makeColumn(schema, name, colors[i] ?? null));
  return schema.nodes.callout!.create(
    { type: 'kanban', folded: false, keyword: null, meta: null },
    [schema.nodes.calloutTitle!.create(), ...columns],
  );
}

/** Replaces the board at `pos` with the same board holding `columns`. */
function replaceColumns(tr: Transaction, pos: number, board: PMNode, columns: PMNode[]): Transaction {
  const title = titleOf(board) ?? board.type.schema.nodes.calloutTitle!.create();
  const next = board.type.create(board.attrs, [title, ...columns]);
  return tr.replaceWith(pos, pos + board.nodeSize, next);
}

function boardAt(tr: Transaction, pos: number): PMNode | null {
  const node = tr.doc.nodeAt(pos);
  return node && isBoard(node) ? node : null;
}

export function setColumnColor(tr: Transaction, boardPos: number, index: number, color: string | null): boolean {
  const board = boardAt(tr, boardPos);
  if (!board) return false;
  let offset = boardPos + 1;
  let seen = -1;
  let done = false;
  board.forEach((child) => {
    if (!done && isColumn(child) && ++seen === index) {
      tr.setNodeMarkup(offset, undefined, { ...child.attrs, meta: color });
      done = true;
    }
    offset += child.nodeSize;
  });
  return done;
}

/** Removes column `index`; its content joins the column on its left, or on
 *  its right for the first column. Refused below the minimum. */
export function deleteColumn(tr: Transaction, boardPos: number, index: number): boolean {
  const board = boardAt(tr, boardPos);
  if (!board) return false;
  const cols = foldedColumns(board);
  if (cols.length <= MIN_COLUMNS || index < 0 || index >= cols.length) return false;
  const schema = board.type.schema;
  const gone = cols[index]!;
  const into = index > 0 ? index - 1 : 1;
  const moved = bodyOf(gone);
  const target = cols[into]!;
  // The empty line a column keeps for a new card is not content: it goes,
  // and columnWithBody puts one back when nothing else is left.
  const merged = (index > 0 ? [...bodyOf(target), ...moved] : [...moved, ...bodyOf(target)]).filter(
    (b) => !isBlank(b) && !isPlaceholderList(b),
  );
  const next = cols.map((c, i) => (i === into ? columnWithBody(schema, target, merged) : c)).filter((_, i) => i !== index);
  replaceColumns(tr, boardPos, board, next);
  return true;
}

export function moveColumn(tr: Transaction, boardPos: number, index: number, dir: -1 | 1): boolean {
  const board = boardAt(tr, boardPos);
  if (!board) return false;
  const cols = foldedColumns(board);
  const to = index + dir;
  if (index < 0 || index >= cols.length || to < 0 || to >= cols.length) return false;
  const next = cols.slice();
  [next[index], next[to]] = [next[to]!, next[index]!];
  replaceColumns(tr, boardPos, board, next);
  return true;
}

export function addColumn(tr: Transaction, boardPos: number, name: string, color: string | null): boolean {
  const board = boardAt(tr, boardPos);
  if (!board) return false;
  const cols = foldedColumns(board);
  if (cols.length >= MAX_COLUMNS) return false;
  replaceColumns(tr, boardPos, board, [...cols, makeColumn(board.type.schema, name, color)]);
  return true;
}

/**
 * Sets the number of columns. Going down removes the column before the last
 * one, again and again, with its content joining the column on its left.
 * Going up adds columns before the last one, named and colored as that slot
 * of the default layout. Names the reader typed stay where they are.
 */
export function setColumnCount(
  tr: Transaction,
  boardPos: number,
  count: number,
  slotNames: (count: number, slot: number) => string,
): boolean {
  let board = boardAt(tr, boardPos);
  if (!board) return false;
  let cols = foldedColumns(board);
  if (count === cols.length || count < MIN_COLUMNS || count > MAX_COLUMNS) return false;
  while (cols.length > count) {
    if (!deleteColumn(tr, boardPos, cols.length - 2)) return false;
    board = boardAt(tr, boardPos)!;
    cols = foldedColumns(board);
  }
  if (cols.length < count) {
    const schema = board.type.schema;
    const palette = DEFAULT_COLORS[count as 3 | 4] ?? [];
    const next = cols.slice();
    while (next.length < count) {
      const slot = next.length - 1;
      next.splice(slot, 0, makeColumn(schema, slotNames(count, slot), palette[slot] ?? null));
    }
    replaceColumns(tr, boardPos, board, next);
  }
  return true;
}

/** Turns the board back into plain blocks: each title becomes a paragraph
 *  over its column's content, so no card and no column name is lost. */
export function removeBoard(tr: Transaction, boardPos: number): boolean {
  const board = boardAt(tr, boardPos);
  if (!board) return false;
  const schema = board.type.schema;
  const out: PMNode[] = [];
  const pushTitle = (node: PMNode) => {
    const title = titleOf(node);
    if (title && title.content.size > 0) out.push(schema.nodes.paragraph!.create(null, title.content));
  };
  pushTitle(board);
  for (const child of bodyOf(board)) {
    if (isColumn(child)) {
      pushTitle(child);
      out.push(...bodyOf(child));
    } else {
      out.push(child);
    }
  }
  if (out.length === 0) out.push(schema.nodes.paragraph!.create());
  tr.replaceWith(boardPos, boardPos + board.nodeSize, out);
  tr.setSelection(TextSelection.near(tr.doc.resolve(boardPos)));
  return true;
}

/** Where a card sits: its board, its column and its place in the column's list. */
export interface CardPlace {
  boardPos: number;
  column: number;
}

/** The board and column of the top-level card whose task item starts at `pos`. */
export function cardPlace(doc: PMNode, pos: number): CardPlace | null {
  const $pos = doc.resolve(pos);
  // item inside list (depth d+2) inside column (d+1) inside board (d)
  if ($pos.depth < 3) return null;
  if ($pos.parent.type.name !== 'taskList') return null;
  const column = $pos.node($pos.depth - 1);
  const board = $pos.node($pos.depth - 2);
  if (!isColumn(column) || !isBoard(board)) return null;
  const boardPos = $pos.before($pos.depth - 2);
  const colChild = $pos.index($pos.depth - 2);
  let column_ = -1;
  board.forEach((child, _o, i) => {
    if (i <= colChild && isColumn(child)) column_++;
  });
  return { boardPos, column: column_ };
}

/**
 * Moves the card at `pos` into column `to`, at `index` among that column's
 * cards (its first task list), or last when `index` is left out. A list the
 * card leaves empty goes, and an emptied column keeps one empty line.
 */
export function moveCard(tr: Transaction, pos: number, to: number, index?: number): boolean {
  const place = cardPlace(tr.doc, pos);
  const item = tr.doc.nodeAt(pos);
  if (!place || !item) return false;
  const board = boardAt(tr, place.boardPos)!;
  const cols = foldedColumns(board);
  if (to < 0 || to >= cols.length) return false;
  const schema = board.type.schema;
  const $pos = tr.doc.resolve(pos);
  const list = $pos.parent;
  const itemIndex = $pos.index();
  const listIndexInColumn = $pos.index($pos.depth - 1) - 1;

  const source = cols[place.column]!;
  const sourceBody = bodyOf(source);
  const remaining: PMNode[] = [];
  list.forEach((c, _o, i) => {
    if (i !== itemIndex) remaining.push(c);
  });
  sourceBody.splice(listIndexInColumn, 1, ...(remaining.length ? [list.type.create(list.attrs, remaining)] : []));

  const next = cols.slice();
  next[place.column] = columnWithBody(schema, source, sourceBody);
  const target = next[to]!;
  const targetBody = bodyOf(target);
  const listAt = targetBody.findIndex((b) => b.type.name === 'taskList');
  if (listAt < 0) {
    targetBody.push(list.type.create(list.attrs, item));
  } else {
    const tl = targetBody[listAt]!;
    const kids: PMNode[] = [];
    tl.forEach((c) => kids.push(c));
    // A lone empty task is a placeholder line, not a card: the card takes its place.
    if (kids.length === 1 && isPlaceholderTask(kids[0]!)) kids.length = 0;
    // Without a place, an open card goes last among the open cards, the
    // order a ticked task sinks to.
    let at = index ?? kids.length;
    if (index === undefined && !item.attrs.checked) {
      const firstDone = kids.findIndex((k) => k.attrs.checked);
      if (firstDone >= 0) at = firstDone;
    }
    kids.splice(Math.max(0, Math.min(at, kids.length)), 0, item);
    targetBody[listAt] = tl.type.create(tl.attrs, kids);
  }
  next[to] = columnWithBody(schema, target, targetBody);
  replaceColumns(tr, place.boardPos, board, next);
  return true;
}

/**
 * Keeps a board made of columns. A block that lands between columns (a gap
 * cursor, a paste, a drop) moves into the column before it, or the first
 * column when it lands before them all, with the caret.
 */
function normalizeBoards(state: EditorState): Transaction | null {
  const fixes: { from: number; to: number; into: number }[] = [];
  state.doc.descendants((node, pos) => {
    if (isBoard(node)) {
      const cols = columnsOf(node);
      if (cols.length > 0) {
        let offset = pos + 1;
        let lastColEnd = -1;
        let firstColStart = -1;
        node.forEach((child, _o, i) => {
          const start = offset;
          offset += child.nodeSize;
          if (isColumn(child)) {
            if (firstColStart < 0) firstColStart = start;
            lastColEnd = offset - 1;
            return;
          }
          if (i === 0) return;
          fixes.push({ from: start, to: offset, into: lastColEnd >= 0 ? lastColEnd : -1 });
        });
        // A block before every column joins the first column, at its end.
        for (const f of fixes) if (f.into === -1) f.into = firstColStart + columnsOf(node)[0]!.nodeSize - 1;
      }
      return false;
    }
    return node.type.name === 'doc' || node.type.name === 'callout' || node.type.name === 'blockquote' || node.type.name === 'listItem' || node.type.name === 'taskItem' || node.type.name === 'bulletList' || node.type.name === 'orderedList' || node.type.name === 'taskList';
  });
  const tr = state.tr;
  if (fixes.length === 0) return fillEmptyColumns(tr) ? tr : null;
  const head = state.selection.head;
  // The caret in the current document of `tr`, once it sits in a moved block.
  let caret: number | null = null;
  const follow = (from: number) => {
    if (caret !== null) caret = tr.mapping.slice(from).map(caret);
  };
  // Last first, so the earlier positions stay valid.
  for (const f of fixes.slice().reverse()) {
    const content = state.doc.slice(f.from, f.to).content;
    const into = tr.mapping.map(f.into, -1);
    let steps = tr.steps.length;
    tr.insert(into, content);
    follow(steps);
    if (caret === null && head >= f.from && head <= f.to) caret = into + (head - f.from);
    steps = tr.steps.length;
    tr.delete(tr.mapping.map(f.from), tr.mapping.map(f.to));
    follow(steps);
  }
  if (caret !== null) {
    tr.setSelection(TextSelection.near(tr.doc.resolve(Math.min(caret, tr.doc.content.size))));
  }
  fillEmptyColumns(tr);
  return tr;
}

/**
 * A column whose only content is a blank line (its last card deleted, a
 * Delete checked items that took every card) gets its empty card line back,
 * the line a new card is typed on, with the caret in it when it was there.
 * Returns whether it changed anything.
 */
function fillEmptyColumns(tr: Transaction): boolean {
  const blanks: number[] = [];
  tr.doc.descendants((node, pos) => {
    if (isColumn(node)) {
      if (node.childCount === 2 && isBlank(node.child(1)) && isBoard(tr.doc.resolve(pos).parent)) {
        blanks.push(pos + 1 + node.child(0).nodeSize);
      }
      return false;
    }
    return node.type.name === 'doc' || node.type.name === 'callout' || node.type.name === 'blockquote' || node.type.name === 'listItem' || node.type.name === 'taskItem' || node.type.name === 'bulletList' || node.type.name === 'orderedList' || node.type.name === 'taskList';
  });
  if (blanks.length === 0) return false;
  const head = tr.selection.head;
  for (const at of blanks.reverse()) {
    const blank = tr.doc.nodeAt(at)!;
    const inside = head > at && head < at + blank.nodeSize;
    tr.replaceWith(at, at + blank.nodeSize, emptyTaskList(tr.doc.type.schema));
    // taskList, taskItem, paragraph: the caret goes three levels in.
    if (inside) tr.setSelection(TextSelection.create(tr.doc, at + 3));
  }
  return true;
}

/**
 * Tab and Shift+Tab inside a board move the caret from stop to stop, the
 * way Tab moves between table cells: the board title, then each column's
 * title and its cards, in reading order. Tab after the last stop leaves the
 * board for the line below it (made when there is none); Shift+Tab before
 * the first goes to the line above it. Returns false outside a board, so
 * Tab keeps its list and text meaning everywhere else.
 */
export function stepKanban(state: EditorState, dispatch: (tr: Transaction) => void, dir: 1 | -1): boolean {
  const { $from } = state.selection;
  let depth = $from.depth;
  while (depth > 0 && !isBoard($from.node(depth))) depth--;
  if (depth === 0) return false;
  const board = $from.node(depth);
  const boardPos = $from.before(depth);
  // Each stop is a textblock, as the start and end of its content.
  const stops: [number, number][] = [];
  const add = (node: PMNode, pos: number) => {
    stops.push([pos + 1, pos + 1 + node.content.size]);
  };
  board.forEach((child, offset) => {
    const pos = boardPos + 1 + offset;
    if (child.isTextblock) return add(child, pos);
    if (!isColumn(child)) return;
    child.forEach((block, o2) => {
      const bpos = pos + 1 + o2;
      if (block.isTextblock) return add(block, bpos);
      if (block.type.name === 'taskList') {
        block.forEach((item, o3) => {
          const first = item.firstChild;
          if (first?.isTextblock) add(first, bpos + 1 + o3 + 1);
        });
      }
    });
  });
  const head = state.selection.head;
  let at = -1;
  stops.forEach(([start], i) => {
    if (start <= head) at = i;
  });
  const next = at + dir;
  const tr = state.tr;
  if (next >= 0 && next < stops.length) {
    tr.setSelection(TextSelection.create(tr.doc, stops[next]![1]));
  } else if (dir === 1) {
    const after = boardPos + board.nodeSize;
    if (!tr.doc.resolve(after).nodeAfter?.isTextblock) tr.insert(after, state.schema.nodes.paragraph!.create());
    tr.setSelection(TextSelection.create(tr.doc, after + 1));
  } else {
    // The nearest text place before the board, inside a list or a callout too.
    const before = Selection.findFrom(tr.doc.resolve(boardPos), -1, true);
    if (!before) return true;
    tr.setSelection(before);
  }
  dispatch(tr.scrollIntoView());
  return true;
}

const kanbanNormalizeKey = new PluginKey('kanbanNormalize');

export function kanbanNormalizePlugin(): Plugin {
  return new Plugin({
    key: kanbanNormalizeKey,
    appendTransaction(trs, _old, state) {
      if (!trs.some((t) => t.docChanged)) return null;
      return normalizeBoards(state);
    },
  });
}
