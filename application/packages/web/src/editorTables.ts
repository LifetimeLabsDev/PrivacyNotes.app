import type { Editor as TipTapEditor } from '@tiptap/react';
import { Table, type TableOptions } from '@tiptap/extension-table';
import { getHTMLFromFragment } from '@tiptap/core';
import { Fragment } from '@tiptap/pm/model';
import { Selection } from '@tiptap/pm/state';
import { selectionCell } from '@tiptap/pm/tables';
import { TABLE_MIN_WIDTH, delimiterRow } from './tableColumnWidths';
import { tableWidthMarker } from './tableDelimiterRow';
import { ColumnWidthTableView, columnResizePlugin, registerTableWidthsMarkdown, renderTableHTML, tableWidthOf, tableWidths } from './tableColumnResize';
import { isStoredAlignment } from './editorAlignment';
import { tableFormulaPlugin } from './editorTableFormula';
import { formulaSuggestion } from './FormulaSuggestion';
import { isFormulaText } from './tableFormula';

/**
 * A cell holding nothing but a formula, as one unmarked run of text.
 *
 * Such a cell is written to the file VERBATIM rather than through the inline
 * serializer, because the escaper cannot know it is looking at a formula and
 * escapes the `*` of `=B2*C2` so it cannot be read as emphasis. That escape
 * is correct markdown and round-trips cleanly, but "Show markdown" is a raw
 * view, and `=B2\*C2` reads as broken to the person who wrote `=B2*C2`.
 *
 * Writing it raw is safe because a formula's alphabet is closed: letters,
 * digits, and `. , : ( ) + - * / =`. None of them starts a block inside a
 * pipe cell, and `|` cannot appear at all, so `escapeCellPipes` has nothing
 * to do afterwards either.
 */
function plainFormulaCell(cell: any): string | null {
  if (cell.type.name !== 'paragraph' || cell.childCount !== 1) return null;
  const text = cell.firstChild;
  if (!text?.isText || text.marks.length) return null;
  return isFormulaText(text.text ?? '') ? (text.text as string) : null;
}

/**
 * Added to the table's options so Editor.tsx can hand over the Pro state.
 *
 * It gates the insert MENU and nothing else. Formulas are computed for every
 * account, because the formula lives in the person's own file and the export
 * renderer has no account to ask. See the note on `tableFormulaPlugin`.
 */
type TableFormulaOptions = { formulasUnlocked: () => boolean };

/**
 * Override the table markdown serializer so the contents of a table cell
 * survive the markdown round-trip.
 *
 * tiptap-markdown's default table serializer renders each cell with
 * `state.renderInline(cell.firstChild)` but guards it behind
 * `cell.firstChild.textContent.trim()`. An image is an atom block node
 * with no textContent, so an image-only cell serializes as blank - the
 * `pn:img/<uuid>` reference is dropped at save time and the image never
 * appears in HTML / PDF / print export (or after reopening the note).
 *
 * Fix: detect an image cell and emit its `![alt](src){width=N}` markdown
 * directly, and ask `cellHasContent` rather than `textContent` for every
 * other cell. Everything else (text cells, the pipe-vs-HTML structural
 * decision) matches tiptap-markdown's default behavior exactly, so
 * unaffected tables serialize identically to before.
 *
 * Spec: GitHub #105 (image added to table not visible in print/pdf/html export)
 */
function cellHasSpan(cell: any): boolean {
  return cell.attrs.colspan > 1 || cell.attrs.rowspan > 1;
}

function cellsOf(row: any): any[] {
  const cells: any[] = [];
  row.forEach((cell: any) => cells.push(cell));
  return cells;
}

/**
 * Whether a cell holds anything worth writing.
 *
 * `textContent` alone is the wrong question, and it is what tiptap-markdown
 * asks. An inline ATOM carries its content in attributes and reports an empty
 * string, so a cell holding nothing but a note-link or an inline formula
 * measured as empty and was written out as blank: the column emptied itself
 * the first time the note round-tripped through markdown. Same defect as the
 * image case above, one node type further in.
 */
function cellHasContent(cell: any): boolean {
  if (cell.textContent.trim()) return true;
  let found = false;
  cell.descendants((child: any) => {
    if (found) return false;
    if (!child.isText) found = true;
    return !found;
  });
  return found;
}

/**
 * Escape every `|` the cell just wrote, from `from` to the end of the output.
 *
 * An unescaped pipe ENDS the cell, so anything carrying one split the row
 * into an extra column on the way back in: a note-link with a display label
 * (`[[target|label]]`) and a plain text pipe alike. Nothing upstream can do
 * this - prosemirror-markdown's `esc()` does not know it is inside a table,
 * and the node's own serializer does not know either. markdown-it un-escapes
 * `\|` inside a cell before any inline rule runs, so the round trip is stable.
 */
function escapeCellPipes(state: any, from: number): void {
  const written: string = state.out.slice(from);
  if (!written.includes('|')) return;
  state.out = state.out.slice(0, from) + written.replace(/\|/g, '\\|');
  // tiptap-markdown remembers where each mark opened and closed, as offsets
  // into `out`, and trims the run after the next node renders. Each inserted
  // backslash moves the text after it, so the offsets move with it and a
  // delimiter written in this cell is the escaped one. Left stale, the trim
  // read a one-letter spoiler as an empty mark and deleted the letter.
  const shift = (pos: number) =>
    pos < from ? pos : pos + (written.slice(0, pos - from).match(/\|/g)?.length ?? 0);
  for (const inline of (state.inlines ?? []) as { start?: number; end?: number; delimiter?: unknown }[]) {
    if (typeof inline.start === 'number' && inline.start >= from && typeof inline.delimiter === 'string') {
      inline.delimiter = inline.delimiter.replace(/\|/g, '\\|');
    }
    if (typeof inline.start === 'number') inline.start = shift(inline.start);
    if (typeof inline.end === 'number') inline.end = shift(inline.end);
  }
}

/**
 * A pipe row holds one line of inline content per cell. A cell of more than
 * one block, or of one block that is not a paragraph or an image (a list, a
 * heading, a code block, a quote), cannot be written there: it broke the row
 * and spilled out under the table on reload. Nor can a paragraph aligned on
 * its own, since a pipe table aligns whole columns only.
 */
const PIPE_CELL_BLOCKS = new Set(['paragraph', 'image']);

function cellIsPipeSafe(cell: any): boolean {
  const first = cell.firstChild;
  if (cellHasSpan(cell) || cell.childCount > 1) return false;
  if (!first) return true;
  return PIPE_CELL_BLOCKS.has(first.type.name) && !(first.type.name === 'paragraph' && isStoredAlignment(first.attrs.textAlign));
}

/** tiptap-markdown's isMarkdownSerializable, plus the cell rule above. */
function tableIsPipeSerializable(node: any): boolean {
  const rows: any[] = [];
  node.forEach((row: any) => rows.push(row));
  const firstRow = rows[0];
  if (!firstRow) return false;
  if (cellsOf(firstRow).some((cell) => cell.type.name !== 'tableHeader' || !cellIsPipeSafe(cell))) {
    return false;
  }
  if (rows.slice(1).some((row) => cellsOf(row).some((cell) => cell.type.name === 'tableHeader' || !cellIsPipeSafe(cell)))) {
    return false;
  }
  return true;
}

function serializeTableToMarkdown(this: any, state: any, node: any, _parent: any): void {
  // Tables with spans or multi-block cells aren't representable as a GFM
  // pipe table - fall back to HTML, identical to tiptap-markdown's default.
  if (!tableIsPipeSerializable(node)) {
    if (this?.editor?.storage?.markdown?.options?.html ?? true) {
      // `text` rather than `write`: a code block in a cell carries newlines,
      // and each line needs the quote or list prefix the table sits under.
      state.text(getHTMLFromFragment(Fragment.from(node), node.type.schema), false);
    }
    if (node.isBlock) state.closeBlock(node);
    return;
  }

  state.inTable = true;
  const widths = tableWidths(node);
  node.forEach((row: any, _p: number, i: number) => {
    const rowStart: number = state.out.length;
    state.write('| ');
    row.forEach((col: any, _p2: number, j: number) => {
      if (j) state.write(' | ');
      const cell = col.firstChild;
      const cellStart: number = state.out.length;
      if (cell?.type.name === 'image') {
        const alt = state.esc(cell.attrs.alt || '');
        const widthSuffix =
          cell.attrs.width && cell.attrs.width !== 100 ? `{width=${cell.attrs.width}}` : '';
        state.write(`![${alt}](${cell.attrs.src || ''})${widthSuffix}`);
      } else if (cell && plainFormulaCell(cell)) {
        state.text(plainFormulaCell(cell)!, false);
      } else if (cell && cellHasContent(cell)) {
        state.renderInline(cell);
      }
      escapeCellPipes(state, cellStart);
    });
    state.write(' |');
    const written: string = state.out.slice(rowStart);
    state.ensureNewLine();
    if (!i) {
      // The delimiter row is the only place a pipe table can say how its
      // columns align (the cell's `align` attr, which the tiptap table cell
      // parses off the `text-align` markdown-it writes for `:---:`) and how
      // wide they are (dash counts, see tableColumnWidths.ts). A bare `---`
      // here would drop both on the first edit after an import.
      const aligns = cellsOf(row).map((col) => col.attrs?.['align']);
      state.write(delimiterRow(written.slice(written.indexOf('|')), widths, aligns));
      state.ensureNewLine();
    }
  });
  const tableWidth = tableWidthOf(node);
  if (tableWidth) {
    state.write(tableWidthMarker(tableWidth));
    state.ensureNewLine();
  }
  state.closeBlock(node);
  state.inTable = false;
}

/**
 * Table with our serializer declared in addStorage, replacing the pre-TipTap-3
 * onCreate monkey-patch that died silently when v3 made extension.storage a
 * per-access rebuild (see ParagraphWithMarkdown's HISTORY note; this one was
 * caught the same day when tables started saving as raw HTML instead of pipe
 * tables). tiptap-markdown's getMarkdownSpec merges this over its default
 * table spec, whose `parse` is empty; ours reads the column widths.
 *
 * Column widths: `colwidth` holds a relative weight, so the node view and
 * `renderHTML` are replaced (TipTap's read it as pixels), and a plugin drags
 * a border. `resizable` stays false, which keeps prosemirror-tables' own
 * pixel resizer out. Spec: ops/docs/archive/table-column-widths.md
 */
export const TableWithMarkdown = Table.extend<TableOptions & TableFormulaOptions>({
  addOptions() {
    // `formulasUnlocked` is a callback, not a flag: Editor.tsx reads the Pro
    // state through a ref, so an upgrade mid-session opens the menu without
    // rebuilding the extension set.
    return { ...this.parent!(), View: ColumnWidthTableView, formulasUnlocked: () => false };
  },
  addAttributes() {
    return {
      ...this.parent?.(),
      // The table's width in percent of the note, null for full width.
      // Written as a marker line under a pipe table, as data-table-width on
      // the HTML one; renderTableHTML draws it.
      tableWidth: {
        default: null,
        parseHTML: (element: HTMLElement) => {
          const width = Number(element.getAttribute('data-table-width'));
          return width >= TABLE_MIN_WIDTH && width < 100 ? width : null;
        },
        renderHTML: () => ({}),
      },
    };
  },
  renderHTML({ node, HTMLAttributes }) {
    return renderTableHTML(node, { ...this.options.HTMLAttributes, ...HTMLAttributes });
  },
  addProseMirrorPlugins() {
    return [
      ...(this.parent?.() ?? []),
      columnResizePlugin(),
      tableFormulaPlugin(),
      formulaSuggestion(this.editor, this.options.formulasUnlocked),
    ];
  },
  addStorage() {
    return {
      markdown: {
        serialize: serializeTableToMarkdown,
        parse: {
          setup: registerTableWidthsMarkdown,
        },
      },
    };
  },
});

/**
 * Move the selection to the next/previous table cell on Tab/Shift+Tab.
 *
 * Replaces prosemirror-tables' `goToNextCell`, which is broken for cells
 * whose only content is an atom block (an image or attachment). Its landing
 * step uses `TextSelection.between`, which does a text-ONLY search for a
 * caret position; an image-only cell has none, so the search snaps back to
 * the previous text cell and the caret never advances. The command still
 * reports success, so Tab silently appears dead.
 *
 * Here we compute the adjacent cell ourselves (the same map-walk
 * prosemirror-tables uses internally) and land with `Selection.near`, which
 * resolves to a NodeSelection on the atom when the cell holds no text. This
 * makes Tab step onto, and off of, image cells like any other cell.
 *
 * Returns false when there is no adjacent cell (first/last cell of the
 * table), leaving the selection untouched.
 *
 * Spec: GitHub #145 (Tab does not move to next cell when a cell holds an image)
 */
function findAdjacentCellPos($cell: any, dir: number): number | null {
  if (dir < 0) {
    const before = $cell.nodeBefore;
    if (before) return $cell.pos - before.nodeSize;
    for (let row = $cell.index(-1) - 1, rowEnd = $cell.before(); row >= 0; row--) {
      const rowNode = $cell.node(-1).child(row);
      const lastChild = rowNode.lastChild;
      if (lastChild) return rowEnd - 1 - lastChild.nodeSize;
      rowEnd -= rowNode.nodeSize;
    }
    return null;
  }
  if ($cell.index() < $cell.parent.childCount - 1) {
    return $cell.pos + $cell.nodeAfter.nodeSize;
  }
  const table = $cell.node(-1);
  for (let row = $cell.indexAfter(-1), rowStart = $cell.after(); row < table.childCount; row++) {
    const rowNode = table.child(row);
    if (rowNode.childCount) return rowStart + 1;
    rowStart += rowNode.nodeSize;
  }
  return null;
}

function goToAdjacentCell(editor: TipTapEditor, dir: number): boolean {
  const { state, dispatch } = editor.view;
  let $cell: any;
  try {
    $cell = selectionCell(state);
  } catch {
    return false; // not inside a table cell
  }
  const cellPos = findAdjacentCellPos($cell, dir);
  if (cellPos == null) return false;
  // +1 steps inside the cell; Selection.near lands on the first child -
  // a caret in a paragraph, or a NodeSelection on an atom (image).
  const sel = Selection.near(state.doc.resolve(cellPos + 1), 1);
  dispatch(state.tr.setSelection(sel).scrollIntoView());
  editor.view.focus();
  return true;
}

/**
 * What Tab (dir 1) and Shift+Tab (dir -1) do inside a table: step to the
 * adjacent cell, and from the last cell add a row and step into it. Shift+Tab
 * in the first cell stays put.
 */
export function stepTableCell(editor: TipTapEditor, dir: number): void {
  if (goToAdjacentCell(editor, dir) || dir !== 1 || !editor.can().addRowAfter()) return;
  editor.chain().addRowAfter().run();
  goToAdjacentCell(editor, 1);
}
