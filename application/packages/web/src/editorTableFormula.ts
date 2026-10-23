import { Plugin, PluginKey, TextSelection } from '@tiptap/pm/state';
import type { EditorState } from '@tiptap/pm/state';
import type { EditorView } from '@tiptap/pm/view';
import type { Node as ProseMirrorNode } from '@tiptap/pm/model';
import { Decoration, DecorationSet } from '@tiptap/pm/view';
import { TableMap } from '@tiptap/pm/tables';
import { activeLocale } from './i18n';
import { evaluateTable, formatFormulaValue, isFormulaText } from './tableFormula';

/**
 * Draw the result of a table formula over the formula itself.
 *
 * Nothing here touches the document. The cell's text stays `=SUM(B2:B7)` from
 * the moment it is typed to the moment it is saved; a decoration hides that
 * text and a widget paints the number in its place. That is what makes the
 * feature free of a migration, free of a schema change, and impossible to
 * lose: there is no second copy of the formula to fall out of step, and a
 * reader whose app has never heard of this sees the formula rather than a
 * stale number.
 *
 * Click-to-edit needs no machinery at all, which is the point of keeping the
 * formula in plain text. A cell the selection is inside is simply not
 * decorated, so the caret lands on the source the user typed and the number
 * comes back when the caret leaves. The inline-math node has the opposite
 * problem (backlog #136: its source re-renders only on a remount) precisely
 * because it swaps a node for text and needs an input rule to swap it back.
 *
 * Spec: ops/docs/archive/table-formulas.md
 */

const formulaKey = new PluginKey<DecorationSet>('tableFormula');

/** One cell we can both evaluate and draw over. */
type Target = { from: number; to: number; row: number; col: number };

/**
 * The text range of a cell, when the cell is simple enough to paint over.
 *
 * Only a cell holding exactly one paragraph of exactly one text node
 * qualifies. A cell carrying a mark, an image, a note-link or a second
 * paragraph is left alone: the position arithmetic below assumes the plain
 * shape, and a formula is plain text by definition, so nothing a user would
 * want computed is excluded by the rule.
 */
function plainTextRange(cell: ProseMirrorNode, cellPos: number): { from: number; to: number; text: string } | null {
  if (cell.childCount !== 1) return null;
  const paragraph = cell.firstChild;
  if (!paragraph || paragraph.type.name !== 'paragraph' || paragraph.childCount !== 1) return null;
  const text = paragraph.firstChild;
  if (!text?.isText || text.marks.length) return null;
  // cellPos is the cell node itself: +1 enters the cell, +1 again enters the
  // paragraph, and the text starts there.
  const from = cellPos + 2;
  return { from, to: from + (text.text?.length ?? 0), text: text.text ?? '' };
}

/** Every formula cell of one table, with the grid it must be evaluated against. */
function tableTargets(table: ProseMirrorNode, tablePos: number): { grid: string[][]; targets: Target[] } {
  const map = TableMap.get(table);
  const start = tablePos + 1;
  const grid: string[][] = [];
  const targets: Target[] = [];
  // A merged cell appears at every coordinate it covers, so the same text is
  // read more than once. That is right for the grid, where a reference to any
  // covered coordinate should find it, and wrong for the decorations, where it
  // would paint the cell twice.
  const painted = new Set<number>();
  for (let row = 0; row < map.height; row++) {
    const cells: string[] = [];
    for (let col = 0; col < map.width; col++) {
      const cellPos = map.map[row * map.width + col];
      const cell = cellPos === undefined ? null : table.nodeAt(cellPos);
      if (cellPos === undefined || !cell) {
        cells.push('');
        continue;
      }
      cells.push(cell.textContent);
      const range = plainTextRange(cell, start + cellPos);
      if (!range || !isFormulaText(range.text) || painted.has(cellPos)) continue;
      painted.add(cellPos);
      targets.push({ from: range.from, to: range.to, row, col });
    }
    grid.push(cells);
  }
  return { grid, targets };
}

/**
 * The span that carries the number.
 *
 * It has to handle its own mousedown. The span is `contenteditable=false`, so
 * a click landing ON it never reaches the text underneath and ProseMirror
 * leaves the selection where it was: the cell looked inert, and the formula
 * appeared only when the click happened to land PAST the number, in the
 * cell's empty space, where the caret could reach the hidden text by itself.
 * So the widget puts the caret at the end of the formula, which is both what
 * a click on a total should do and where a person wants to start editing.
 */
function valueWidget(view: EditorView, getPos: () => number | undefined, shown: string, source: string): HTMLElement {
  const span = document.createElement('span');
  span.className = 'pn-formula-value';
  span.textContent = shown;
  // The formula itself, so hovering a total says where the number came from.
  // It is the user's own text, never a translated string.
  span.title = source;
  span.contentEditable = 'false';
  span.addEventListener('mousedown', (event) => {
    event.preventDefault();
    const from = getPos();
    // The decoration can be gone by the time a click lands on it.
    if (from === undefined) return;
    const end = Math.min(from + source.length, view.state.doc.content.size);
    view.dispatch(view.state.tr.setSelection(TextSelection.create(view.state.doc, end)));
    view.focus();
  });
  return span;
}

function buildDecorations(state: EditorState): DecorationSet {
  const decorations: Decoration[] = [];
  const { from: selFrom, to: selTo } = state.selection;

  state.doc.descendants((node, pos) => {
    if (node.type.name !== 'table') {
      // Never walk into inline content: a table cannot live inside a
      // paragraph, and the text nodes of a long note are the bulk of the tree.
      return !node.inlineContent;
    }
    const { grid, targets } = tableTargets(node, pos);
    if (targets.length) {
      const results = evaluateTable(grid);
      for (const target of targets) {
        const result = results[target.row]?.[target.col];
        // A formula that cannot produce a number is drawn as the text the
        // user typed. One failure mode, and it is the same thing a reader
        // without the feature sees.
        if (!result || 'error' in result) continue;
        // The caret inside the cell means the user is editing: show the
        // source. One position of slack at each end so a click landing on the
        // cell boundary opens it rather than looking inert.
        if (selFrom <= target.to + 1 && selTo >= target.from - 1) continue;
        const source = state.doc.textBetween(target.from, target.to);
        decorations.push(Decoration.inline(target.from, target.to, { class: 'pn-formula-src' }));
        decorations.push(
          Decoration.widget(target.from, (view, getPos) => valueWidget(view, getPos, formatFormulaValue(result.value, activeLocale()), source), {
            side: -1,
            ignoreSelection: true,
          }),
        );
      }
    }
    return false;
  });

  return DecorationSet.create(state.doc, decorations);
}

/**
 * The plugin.
 *
 * It asks nothing about Pro, and that is deliberate: the result of a formula
 * is drawn for every account. The formula is plain text in the person's own
 * file, so a gate here would mean a free account's note showed `=SUM(B2:B4)`
 * in the app and `1,575` in its own PDF, because the export renderer has no
 * account to ask. What Pro buys is the menu that writes the formula for you
 * (FormulaSuggestion.tsx and the table toolbar button), not the arithmetic.
 */
export function tableFormulaPlugin(): Plugin<DecorationSet> {
  return new Plugin<DecorationSet>({
    key: formulaKey,
    state: {
      init: (_config, state) => buildDecorations(state),
      // The selection decides what is painted as much as the document does,
      // so a plain caret move has to rebuild.
      apply: (tr, value, _old, newState) => (tr.docChanged || tr.selectionSet ? buildDecorations(newState) : value),
    },
    props: {
      /**
       * `undefined` rather than an empty set when there is nothing to draw,
       * which is most documents: a note with no table has no formulas.
       *
       * It is not only tidier. ProseMirror keeps every source that returns a
       * set and, past one source, merges them with an `instanceof` check. A
       * test runner that loads prosemirror-view twice (an ESM copy for our
       * modules, a CJS copy inside the view) fails that check for EVERY
       * source and merges them into undefined, so one extra source turned 81
       * unrelated editor tests red. Returning nothing keeps this plugin out
       * of the merge entirely unless it has something to say.
       */
      decorations(state) {
        const set = formulaKey.getState(state);
        return set && set !== DecorationSet.empty ? set : undefined;
      },
    },
  });
}
