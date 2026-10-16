import { mergeAttributes } from '@tiptap/core';
import { TableView } from '@tiptap/extension-table';
import type { DOMOutputSpec, Node as ProseMirrorNode } from '@tiptap/pm/model';
import { Plugin, PluginKey, type EditorState, type Transaction } from '@tiptap/pm/state';
import { TableMap } from '@tiptap/pm/tables';
import { Decoration, DecorationSet, type EditorView } from '@tiptap/pm/view';
import i18n from './i18n';
import { commitWidths, dragColumn, dragTableWidth, dragWidths, effectiveWidths, mirrorEdge, widthsFromTableLines } from './tableColumnWidths';
import { tableWidthFromMarker } from './tableDelimiterRow';

/**
 * Column widths in the editor: reading them out of the markdown, drawing
 * them, and dragging a border to change them. The storage rules live in
 * tableColumnWidths.ts; this file is the part that touches ProseMirror.
 * Spec: ops/docs/plans/table-column-widths.md
 */

/**
 * The stored weight of each column: the first cell from the top that carries
 * one. prosemirror-tables copies a column's width into every cell of it after
 * each change, so the first row normally answers, but a row added above the
 * old first row starts out without one.
 */
function tableColumnWeights(table: ProseMirrorNode): (number | null)[] {
  const map = TableMap.get(table);
  const out: (number | null)[] = [];
  for (let col = 0; col < map.width; col++) {
    let weight: number | null = null;
    for (let row = 0; row < map.height && weight === null; row++) {
      const pos = map.map[row * map.width + col]!;
      const cell = table.nodeAt(pos);
      const value = cell?.attrs['colwidth']?.[col - map.colCount(pos)];
      if (typeof value === 'number' && value > 0) weight = value;
    }
    out.push(weight);
  }
  return out;
}

/** The column percentages a table shows, or null when its columns are equal. */
export function tableWidths(table: ProseMirrorNode): number[] | null {
  return effectiveWidths(tableColumnWeights(table));
}

/** The `<colgroup>` for a table: a percentage per column, or bare cols for equal ones. */
function colSpecs(table: ProseMirrorNode): DOMOutputSpec[] {
  const widths = tableWidths(table);
  const count = TableMap.get(table).width;
  return Array.from({ length: count }, (_, i) => (widths ? ['col', { style: `width: ${widths[i]}%` }] : ['col', {}]));
}

/**
 * `renderHTML` for the table: the same percentages the node view draws, and
 * never a pixel width on the table. This is the output of `getHTML`, of the
 * clipboard, and of the HTML the serializer writes for a table that cannot be
 * a pipe table.
 */
export function renderTableHTML(node: ProseMirrorNode, attrs: Record<string, unknown>): DOMOutputSpec {
  const width = tableWidthOf(node);
  const own = width ? { 'data-table-width': String(width), style: `width: ${width}%` } : {};
  return ['table', mergeAttributes(attrs, own), ['colgroup', {}, ...colSpecs(node)], ['tbody', 0]];
}

/** The table's own width in percent of the note, or null for full width. */
export function tableWidthOf(table: ProseMirrorNode): number | null {
  const width = table.attrs['tableWidth'];
  return typeof width === 'number' && width > 0 && width < 100 ? width : null;
}

function applyColumnWidths(node: ProseMirrorNode, table: HTMLTableElement, colgroup: HTMLElement, cellMinWidth: number): void {
  const count = TableMap.get(node).width;
  while (colgroup.children.length < count) colgroup.appendChild(document.createElement('col'));
  while (colgroup.children.length > count) colgroup.lastElementChild!.remove();
  const widths = tableWidths(node);
  Array.from(colgroup.children).forEach((col, i) => {
    (col as HTMLElement).style.cssText = widths ? `width: ${widths[i]}%` : '';
  });
  const width = tableWidthOf(node);
  table.style.width = width ? `${width}%` : '';
  table.style.minWidth = `${count * cellMinWidth}px`;
}

/**
 * The table node view. TipTap's own view reads `colwidth` as pixels and pins
 * the table to their sum; here it is a share of a table that is always as
 * wide as the note.
 */
export class ColumnWidthTableView extends TableView {
  constructor(node: ProseMirrorNode, cellMinWidth: number, view?: EditorView, HTMLAttributes: Record<string, any> = {}) {
    super(node, cellMinWidth, view, HTMLAttributes);
    applyColumnWidths(node, this.table, this.colgroup, cellMinWidth);
  }

  override update(node: ProseMirrorNode): boolean {
    if (!super.update(node)) return false;
    applyColumnWidths(node, this.table, this.colgroup, this.cellMinWidth);
    return true;
  }
}

/* ------------------------------------------------------------------ */
/* Markdown: the delimiter row becomes `colwidth` on every cell        */
/* ------------------------------------------------------------------ */

interface MdToken {
  type: string;
  attrSet(name: string, value: string): void;
}
interface MdBlockState {
  src: string;
  line: number;
  bMarks: number[];
  tShift: number[];
  eMarks: number[];
  tokens: MdToken[];
}
type MdBlockRule = ((state: MdBlockState, startLine: number, endLine: number, silent: boolean) => boolean) & { pnWidths?: true };
interface MdInstance {
  block: {
    ruler: {
      __find__(name: string): number;
      __rules__: { fn: MdBlockRule; alt: string[] }[];
      at(name: string, fn: MdBlockRule, options: { alt: string[] }): void;
    };
  };
}

function sourceLine(state: MdBlockState, line: number): string {
  return state.src.slice(state.bMarks[line]! + state.tShift[line]!, state.eMarks[line]!);
}

/**
 * Wrap markdown-it's own `table` rule so that each table it recognises gets
 * its widths from the delimiter row, read from the live block state. That
 * state is the only place the row is right inside a callout: the callout
 * rule parses its body again as a separate string, so the line numbers of a
 * table in it do not count lines of the note.
 *
 * tiptap-markdown runs every extension's `setup` on each parse, against one
 * markdown-it instance per editor, so the wrapper marks itself and is added
 * once.
 */
export function registerTableWidthsMarkdown(md: MdInstance): void {
  const index = md.block.ruler.__find__('table');
  const rule = md.block.ruler.__rules__[index];
  if (!rule || rule.fn.pnWidths) return;
  const original = rule.fn;
  const wrapped: MdBlockRule = (state, startLine, endLine, silent) => {
    const first = state.tokens.length;
    const ok = original(state, startLine, endLine, silent);
    if (!ok || silent) return ok;
    const widths = widthsFromTableLines(sourceLine(state, startLine), sourceLine(state, startLine + 1));
    let col = 0;
    for (const token of widths ? state.tokens.slice(first) : []) {
      if (token.type === 'tr_open') col = 0;
      if (token.type === 'th_open' || token.type === 'td_open') {
        const width = widths![col++];
        if (width) token.attrSet('colwidth', String(width));
      }
    }
    // The width marker sits on the line right under the table, where an HTML
    // comment ends the table. It is consumed here so no comment block is left.
    const tableWidth = state.line < endLine ? tableWidthFromMarker(sourceLine(state, state.line)) : null;
    if (tableWidth) {
      state.tokens[first]?.attrSet('data-table-width', String(tableWidth));
      state.line += 1;
    }
    return ok;
  };
  wrapped.pnWidths = true;
  md.block.ruler.at('table', wrapped, { alt: rule.alt });
}

/* ------------------------------------------------------------------ */
/* Drag a border                                                       */
/* ------------------------------------------------------------------ */

/** How close to a border, in CSS pixels, the pointer has to be to grab it. */
const HANDLE_REACH = 5;

interface Handle {
  table: number;
  border: number;
}
interface ResizeState {
  handle: Handle | null;
  dragging: boolean;
}

const resizeKey = new PluginKey<ResizeState>('pnColumnResize');

/** A transaction that stores `widths` (null for equal) on every cell of the table at `tablePos`. */
function setTableWidths(tr: Transaction, tablePos: number, widths: readonly number[] | null): Transaction {
  const table = tr.doc.nodeAt(tablePos);
  if (!table) return tr;
  const map = TableMap.get(table);
  const seen = new Set<number>();
  for (const pos of map.map) {
    if (seen.has(pos)) continue;
    seen.add(pos);
    const cell = table.nodeAt(pos);
    if (!cell) continue;
    const start = map.colCount(pos);
    const colspan: number = cell.attrs['colspan'] ?? 1;
    const colwidth = widths ? Array.from({ length: colspan }, (_, i) => widths[start + i]!) : null;
    tr.setNodeMarkup(tablePos + 1 + pos, null, { ...cell.attrs, colwidth });
  }
  return tr;
}

/** Set the columns of the table at `tablePos` back to equal widths. */
export function clearTableWidths(view: EditorView, tablePos: number): void {
  view.dispatch(setTableWidths(view.state.tr, tablePos, null));
}

/**
 * Turns the hover handle on or off. A click moves the caret in the DOM before
 * the editor reads it, and any transaction in that gap writes the editor's
 * older caret back over the click, so the pending DOM selection is read first.
 * `flush` is ProseMirror's own read of the DOM; it is not in the public types.
 */
function setHandle(view: EditorView, handle: Handle | null): void {
  const current = resizeKey.getState(view.state)?.handle ?? null;
  if (current?.table === handle?.table && current?.border === handle?.border) return;
  (view as unknown as { domObserver: { flush(): void } }).domObserver.flush();
  view.dispatch(view.state.tr.setMeta(resizeKey, { handle }));
}

/** The border under the pointer: the end edge of a cell, or its start edge (the border before it). */
function borderAt(view: EditorView, event: PointerEvent): Handle | null {
  const cellEl = (event.target as Element | null)?.closest?.('td, th');
  if (!cellEl || !view.dom.contains(cellEl)) return null;
  const tableEl = cellEl.closest('table');
  if (!tableEl) return null;
  const rect = cellEl.getBoundingClientRect();
  const rtl = getComputedStyle(tableEl).direction === 'rtl';
  const endEdge = rtl ? rect.left : rect.right;
  const startEdge = rtl ? rect.right : rect.left;

  let $pos;
  try { $pos = view.state.doc.resolve(view.posAtDOM(cellEl, 0)); } catch { return null; }
  for (let depth = $pos.depth; depth > 2; depth--) {
    const role = $pos.node(depth).type.spec['tableRole'];
    if (role !== 'cell' && role !== 'header_cell') continue;
    const tablePos = $pos.before(depth - 2);
    const table = view.state.doc.nodeAt(tablePos);
    if (!table || table.type.spec['tableRole'] !== 'table') return null;
    const map = TableMap.get(table);
    const cellPos = $pos.before(depth) - tablePos - 1;
    const first = map.colCount(cellPos);
    const last = first + ($pos.node(depth).attrs['colspan'] ?? 1) - 1;
    if (Math.abs(event.clientX - endEdge) <= HANDLE_REACH) return { table: tablePos, border: last };
    if (Math.abs(event.clientX - startEdge) <= HANDLE_REACH && first > 0) return { table: tablePos, border: first - 1 };
    return null;
  }
  return null;
}

function handleDecorations(state: EditorState, handle: Handle): DecorationSet {
  const table = state.doc.nodeAt(handle.table);
  if (!table) return DecorationSet.empty;
  const map = TableMap.get(table);
  const decorations: Decoration[] = [];
  for (let row = 0; row < map.height; row++) {
    const index = row * map.width + handle.border;
    const pos = map.map[index]!;
    const edge = handle.border === map.width - 1;
    if (!edge && map.map[index + 1] === pos) continue;
    if (row > 0 && map.map[index - map.width] === pos) continue;
    const cell = table.nodeAt(pos)!;
    const dom = document.createElement('div');
    dom.className = edge ? 'pn-col-resize-handle is-edge' : 'pn-col-resize-handle';
    decorations.push(Decoration.widget(handle.table + 1 + pos + cell.nodeSize - 1, dom));
  }
  return DecorationSet.create(state.doc, decorations);
}

/** What a drag shows: the column percentages and the table's own width (100 is the note's width). */
interface DragLayout {
  widths: readonly number[];
  tableWidth: number;
  /** pair: a border trades width between its two columns; edge: the whole table scales; column: one column and the table edge move. */
  kind: 'pair' | 'edge' | 'column';
  fine: boolean;
}

/** The key hint that follows the pointer during a drag. */
function dragHint(): HTMLElement {
  const hint = document.createElement('div');
  hint.className = 'pn-col-drag-hint';
  // Read at drag time: editorLinks.ts has the same test, but reads the window as it loads.
  const mac = /Mac|iP(hone|[oa]d)/.test(navigator.platform);
  hint.textContent = i18n.t('editor:table.resizeHint', { shift: 'Shift', alt: mac ? 'Option' : 'Alt' });
  document.body.appendChild(hint);
  return hint;
}

/**
 * Drag a border. Each move reads the keys again, so they can be pressed or
 * let go mid-drag:
 * - plain, on a border between columns: the pair trades width (dragWidths);
 * - plain, on the table's outer end edge: the whole table gets narrower or
 *   wider and its columns keep their shares (dragTableWidth);
 * - Shift: only the column before the border changes, and the table edge
 *   moves with it (dragColumn);
 * - Alt (Option on a Mac): whole-percent steps in place of the grid.
 * A table width under 100 is stored as the marker line under the table.
 */
function startDrag(view: EditorView, handle: Handle, event: PointerEvent): void {
  const wrapper = view.nodeDOM(handle.table) as HTMLElement | null;
  const tableEl = wrapper instanceof HTMLTableElement ? wrapper : wrapper?.querySelector('table');
  const table = view.state.doc.nodeAt(handle.table);
  if (!tableEl || !table) return;
  const count = TableMap.get(table).width;
  const edge = handle.border === count - 1;
  // The table's own width is a share of the wrapper, which is as wide as the note.
  const note = wrapper && wrapper !== tableEl ? wrapper : null;
  if (edge && !note) return;
  const cols = Array.from(tableEl.querySelectorAll<HTMLElement>(':scope > colgroup > col'));
  const stored = tableWidths(table);
  const storedTable = tableWidthOf(table);
  const start = stored ?? Array.from({ length: count }, () => 100 / count);
  const startTable = storedTable ?? 100;
  const rtl = getComputedStyle(tableEl).direction === 'rtl';
  const tablePx = tableEl.getBoundingClientRect().width;
  const notePx = note ? note.getBoundingClientRect().width : tablePx;
  const startX = event.clientX;
  let lastX = startX;
  let lastY = event.clientY;
  // A press with no move is not a drag: committing it would snap an untouched table to the grid.
  let moved = false;
  let current: DragLayout = { widths: start, tableWidth: startTable, kind: edge ? 'edge' : 'pair', fine: false };

  // The symmetry guide: a dashed line where this border would mirror its
  // partner across the middle of the table, solid (with the partner border
  // lit) while the border sits on it. Drawn in the wrapper, outside the
  // content the editor owns, and gone when the drag ends. Only a pair drag
  // has one: the others move the table edge, and the guide with it.
  const target = edge ? null : mirrorEdge(start, handle.border);
  const partner = count - 2 - handle.border;
  const partnerEdge = start.slice(0, partner + 1).reduce((a, w) => a + w, 0);
  const guides: HTMLElement[] = [];
  const guideAt = (percent: number, className: string): HTMLElement | null => {
    if (!note) return null;
    const line = document.createElement('div');
    line.className = className;
    const wrapRect = note.getBoundingClientRect();
    const tableRect = tableEl.getBoundingClientRect();
    const fraction = rtl ? 1 - percent / 100 : percent / 100;
    line.style.left = `${tableRect.left - wrapRect.left + note.scrollLeft + fraction * tableRect.width}px`;
    line.style.top = `${tableEl.offsetTop}px`;
    line.style.height = `${tableEl.offsetHeight}px`;
    note.appendChild(line);
    guides.push(line);
    return line;
  };
  const guide = target === null ? null : guideAt(target, 'pn-col-guide');
  const partnerLine = target === null || partner === handle.border ? null : guideAt(partnerEdge, 'pn-col-guide pn-col-guide-partner');
  const hint = dragHint();

  const show = (layout: { widths: readonly number[] | null; tableWidth: number }) => {
    cols.forEach((col, i) => { col.style.cssText = layout.widths ? `width: ${layout.widths[i]}%` : ''; });
    tableEl.style.width = layout.tableWidth < 100 ? `${layout.tableWidth}%` : '';
  };
  const layoutAt = (x: number, keys: { shiftKey: boolean; altKey: boolean }): DragLayout => {
    const dx = (x - startX) * (rtl ? -1 : 1);
    const fine = keys.altKey;
    if (keys.shiftKey && note) {
      const next = dragColumn(start, startTable, handle.border, (dx / notePx) * 100, fine);
      return { ...next, kind: 'column', fine };
    }
    if (edge) return { widths: start, tableWidth: dragTableWidth(startTable, (dx / notePx) * 100, fine) ?? 100, kind: 'edge', fine };
    return { widths: dragWidths(start, handle.border, (dx / tablePx) * 100, target, fine), tableWidth: startTable, kind: 'pair', fine };
  };
  const placeHint = () => {
    hint.style.left = `${Math.max(8, Math.min(lastX + 14, window.innerWidth - hint.offsetWidth - 8))}px`;
    hint.style.top = `${Math.min(lastY + 18, window.innerHeight - hint.offsetHeight - 8)}px`;
  };
  const update = (keys: { shiftKey: boolean; altKey: boolean }) => {
    current = layoutAt(lastX, keys);
    show(current);
    const edgeAt = current.widths.slice(0, handle.border + 1).reduce((a, w) => a + w, 0);
    const matched = current.kind === 'pair' && target !== null && Math.abs(edgeAt - target) < 0.01;
    for (const line of guides) {
      line.style.display = current.kind === 'pair' ? '' : 'none';
      line.classList.toggle('is-matched', matched);
    }
    placeHint();
  };
  const move = (ev: PointerEvent) => {
    lastX = ev.clientX;
    lastY = ev.clientY;
    moved = true;
    update(ev);
  };
  const finish = (commit: boolean) => {
    window.removeEventListener('pointermove', move);
    window.removeEventListener('pointerup', onUp);
    window.removeEventListener('pointercancel', onCancel);
    window.removeEventListener('keydown', onKey, true);
    window.removeEventListener('keyup', onKey, true);
    document.documentElement.classList.remove('pn-col-resizing');
    for (const line of guides) line.remove();
    hint.remove();
    let widths = stored;
    let width = storedTable;
    if (commit && current.kind === 'pair') widths = commitWidths(current.widths, current.fine);
    if (commit && current.kind === 'column') widths = effectiveWidths(current.widths);
    if (commit && current.kind !== 'pair') width = current.tableWidth < 100 ? current.tableWidth : null;
    const tr = view.state.tr.setMeta(resizeKey, { handle: null, dragging: false });
    const widthsChanged = JSON.stringify(widths) !== JSON.stringify(stored);
    if (widthsChanged) setTableWidths(tr, handle.table, widths);
    if (width !== storedTable) tr.setNodeMarkup(handle.table, null, { ...tr.doc.nodeAt(handle.table)!.attrs, tableWidth: width });
    if (!widthsChanged && width === storedTable) show({ widths: stored, tableWidth: startTable });
    view.dispatch(tr);
  };
  const onUp = () => finish(moved);
  const onCancel = () => finish(false);
  const onKey = (ev: KeyboardEvent) => {
    if (ev.key === 'Escape' && ev.type === 'keydown') {
      ev.preventDefault();
      ev.stopPropagation();
      finish(false);
      return;
    }
    if (ev.key !== 'Shift' && ev.key !== 'Alt') return;
    // A lone Alt press would otherwise move the focus to a browser's menu bar on Windows.
    ev.preventDefault();
    update(ev);
  };

  document.documentElement.classList.add('pn-col-resizing');
  window.addEventListener('pointermove', move);
  window.addEventListener('pointerup', onUp);
  window.addEventListener('pointercancel', onCancel);
  window.addEventListener('keydown', onKey, true);
  window.addEventListener('keyup', onKey, true);
  placeHint();
  view.dispatch(view.state.tr.setMeta(resizeKey, { handle, dragging: true }));
}

/**
 * Drag a column border or the table's end edge (startDrag says what each key
 * does). Mouse and pen only; touch has no hover
 * to find a border with, and a finger drag in the editor scrolls. The drag
 * shows on the cols directly and writes one transaction on release, so it
 * is one undo step and one save.
 */
export function columnResizePlugin(): Plugin<ResizeState> {
  return new Plugin<ResizeState>({
    key: resizeKey,
    state: {
      init: () => ({ handle: null, dragging: false }),
      apply(tr, prev) {
        const meta = tr.getMeta(resizeKey) as Partial<ResizeState> | undefined;
        if (meta) return { ...prev, ...meta };
        if (tr.docChanged && prev.handle && !prev.dragging) return { handle: null, dragging: false };
        return prev;
      },
    },
    props: {
      attributes(state): Record<string, string> {
        return resizeKey.getState(state)?.handle ? { class: 'pn-col-resize-cursor' } : {};
      },
      decorations(state) {
        const handle = resizeKey.getState(state)?.handle;
        return handle ? handleDecorations(state, handle) : null;
      },
      handleDOMEvents: {
        pointermove(view, event) {
          if (!view.editable || event.pointerType === 'touch' || resizeKey.getState(view.state)?.dragging) return false;
          setHandle(view, borderAt(view, event));
          return false;
        },
        pointerleave(view) {
          if (!resizeKey.getState(view.state)?.dragging) setHandle(view, null);
          return false;
        },
        pointerdown(view, event) {
          const state = resizeKey.getState(view.state);
          if (!view.editable || event.pointerType === 'touch' || event.button !== 0 || !state?.handle || state.dragging) return false;
          event.preventDefault();
          startDrag(view, state.handle, event);
          return true;
        },
        mousedown(view, event) {
          const state = resizeKey.getState(view.state);
          if (!state?.handle && !state?.dragging) return false;
          event.preventDefault();
          return true;
        },
      },
    },
  });
}
