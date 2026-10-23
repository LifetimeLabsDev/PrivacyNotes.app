import type { EditorState } from '@tiptap/pm/state';
import { TableMap } from '@tiptap/pm/tables';
import type { Node as ProseMirrorNode } from '@tiptap/pm/model';
import { FORMULA_NAMES, cellNumber, evaluateTable } from './tableFormula';

/**
 * What the insert menu offers, and what it writes.
 *
 * The menu's whole job is to save a person from working out that the three
 * numbers above them are `B2:B4`. So picking SUM in an empty cell writes
 * `=SUM(B2:B4)` already filled in, guessed from the numbers it can see. The
 * guess is the feature; a menu that wrote `=SUM()` and left the user counting
 * rows would be slower than typing.
 *
 * Spec: ops/docs/archive/table-formulas.md
 */

/** A function that takes a range reads the cells around the caret; the rest do not. */
const TAKES_A_RANGE = new Set(['SUM', 'PRODUCT', 'AVG', 'AVERAGE', 'MEDIAN', 'MIN', 'MAX', 'COUNT']);

/** A bare constant is written without brackets, the way a person would type it. */
const IS_CONSTANT = new Set(['PI', 'E', 'TAU', 'PHI']);

/** The menu rows, in the order they are offered. AVERAGE is hidden: it is AVG under another name. */
export const FORMULA_MENU: readonly string[] = FORMULA_NAMES.filter((name) => name !== 'AVERAGE');

/** Bijective base 26, the inverse of the parser's reader: 0 is A, 26 is AA. */
export function columnLetters(index: number): string {
  let letters = '';
  for (let n = index + 1; n > 0; n = Math.floor((n - 1) / 26)) {
    letters = String.fromCharCode(65 + ((n - 1) % 26)) + letters;
  }
  return letters;
}

export type CellAddress = { row: number; col: number };

/** Every cell of a table as plain strings, the same shape the engine reads. */
function gridOf(table: ProseMirrorNode): string[][] {
  const map = TableMap.get(table);
  const grid: string[][] = [];
  for (let row = 0; row < map.height; row++) {
    const cells: string[] = [];
    for (let col = 0; col < map.width; col++) {
      const pos = map.map[row * map.width + col];
      cells.push(pos === undefined ? '' : (table.nodeAt(pos)?.textContent ?? ''));
    }
    grid.push(cells);
  }
  return grid;
}

/** Where the caret is, as a grid, or null when it is outside a table. */
export function caretCell(state: EditorState): { grid: string[][]; at: CellAddress } | null {
  const { $anchor } = state.selection;
  for (let depth = $anchor.depth; depth > 0; depth--) {
    if ($anchor.node(depth).type.name !== 'table') continue;
    const table = $anchor.node(depth);
    const map = TableMap.get(table);
    // The cell is two levels below the table: the row, then the cell.
    if ($anchor.depth < depth + 2) return null;
    const cellPos = $anchor.before(depth + 2) - ($anchor.before(depth) + 1);
    const index = map.map.indexOf(cellPos);
    if (index < 0) return null;
    return { grid: gridOf(table), at: { row: Math.floor(index / map.width), col: index % map.width } };
  }
  return null;
}

/**
 * The run of numbers the person most likely means.
 *
 * Looks up the column first, because a total sits under its column far more
 * often than beside its row, and falls back to the left along the row. The run
 * stops at the first cell that is not a number, which is what keeps a header
 * and a blank spacer row out of it without either being a special case.
 *
 * Returns null when there is nothing numeric to point at, and the caller then
 * writes empty brackets and puts the caret inside them.
 */
export function guessRange(grid: readonly (readonly string[])[], at: CellAddress): string | null {
  // A cell holding a formula is a number as far as the guess is concerned.
  // Reading the raw text alone was wrong in the most ordinary table there is:
  // an invoice whose line totals are `=B2*C2`, where the subtotal below them
  // found no numbers at all and offered empty brackets.
  const computed = evaluateTable(grid);
  const numberAt = (row: number, col: number) => {
    const result = computed[row]?.[col];
    if (result) return 'value' in result;
    return cellNumber(grid[row]?.[col] ?? '') !== null;
  };

  let top = at.row;
  while (top > 0 && numberAt(top - 1, at.col)) top--;
  if (top < at.row) {
    return `${columnLetters(at.col)}${top + 1}:${columnLetters(at.col)}${at.row}`;
  }

  let left = at.col;
  while (left > 0 && numberAt(at.row, left - 1)) left--;
  if (left < at.col) {
    return `${columnLetters(left)}${at.row + 1}:${columnLetters(at.col - 1)}${at.row + 1}`;
  }

  return null;
}

/**
 * The text a menu choice writes, and where the caret lands inside it.
 *
 * `caret` is an offset from the start of the inserted text. It points inside
 * the brackets whenever there was no range to guess, so the next keystroke
 * goes where it is needed.
 */
export function formulaInsertion(name: string, grid: readonly (readonly string[])[] | null, at: CellAddress | null): { text: string; caret: number } {
  if (IS_CONSTANT.has(name)) return { text: `=${name}`, caret: name.length + 1 };

  const range = TAKES_A_RANGE.has(name) && grid && at ? guessRange(grid, at) : null;
  const text = `=${name}(${range ?? ''})`;
  // With a range filled in the caret goes to the end, because the formula is
  // finished. Without one it goes between the brackets.
  return { text, caret: range ? text.length : name.length + 2 };
}
