/**
 * The node views of a Kanban board and its columns. Both are callouts
 * (Callout.tsx draws them through here), so the stored form, copy, paste,
 * export and the importers need nothing of their own. Every edit is a
 * function of kanban.ts, run as one transaction.
 *
 * The board menu holds Color, Columns (3, 4, Add column) and Remove board;
 * the column menu holds Move left, Move right and Delete column; a tap on a
 * card's grip opens Move to. Add column is Pro.
 * Spec: ops/issues/0270.md (Spec)
 */

import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import { NodeViewContent, NodeViewWrapper, type NodeViewProps, type Editor as TipTapEditor } from '@tiptap/react';
import type { Node as PMNode } from '@tiptap/pm/model';
import { TextSelection, type Transaction } from '@tiptap/pm/state';
import { ContextMenu, useContextMenu, type ContextMenuItem } from './ContextMenu';
import { ColorSwatchRow, IconButton } from './ui';
import { BackRow } from './ui/BackRow';
import { ActionItem, Group, OptionsMenu } from './OptionsMenu';
import type { LookColor } from './itemStyles';
import { ArrowLeft, ArrowRight, Check, Columns, DotsThree, Kanban, Palette, Plus, Trash, XSquare } from './icons';
import { isColumnColor } from './calloutKeywords';
import { writeKanbanPref } from './editorPrefs';
import { DEFAULT_COLORS, slotName, startLayout } from './kanbanLayout';
import {
  CARD_MENU_EVENT,
  type CardMenuDetail,
  MAX_COLUMNS,
  MIN_COLUMNS,
  addColumn,
  columnsOf,
  deleteColumn,
  isBoard,
  isPlaceholderTask,
  makeBoard,
  moveCard,
  moveColumn,
  removeBoard,
  setColumnColor,
  setColumnCount,
} from './kanban';

export interface KanbanOptions {
  /** True for Pro and the demo: Add column runs. */
  kanbanUnlocked: () => boolean;
  /** Opens the upgrade window for a free account. */
  onUpgrade: () => void;
}


/** Inserts a new board where the caret is: the count and colors of the last
 *  board on this device, the default names in the reader's language. */
export function insertKanbanBoard(editor: TipTapEditor, t: TFunction) {
  const { names, colors } = startLayout(t);
  const count = names.length as 3 | 4;
  editor
    .chain()
    .focus()
    .command(({ tr, state, dispatch }) => {
      const board = makeBoard(state.schema, names, colors);
      if (dispatch) {
        const from = tr.selection.from;
        tr.replaceSelectionWith(board);
        // The caret goes into the first card of the first column.
        const start = tr.mapping.map(from, -1);
        let target = -1;
        tr.doc.nodesBetween(start, Math.min(tr.doc.content.size, start + board.nodeSize + 4), (node, pos) => {
          if (target === -1 && node.type.name === 'taskItem') {
            target = pos + 2;
            return false;
          }
          return target === -1;
        });
        if (target >= 0) tr.setSelection(TextSelection.create(tr.doc, target));
        tr.scrollIntoView();
      }
      return true;
    })
    .run();
  writeKanbanPref({ count, colors });
}

/** Remembers a board of 3 or 4 columns for the next insert. */
function rememberBoard(board: PMNode | null | undefined) {
  if (!board || !isBoard(board)) return;
  const cols = columnsOf(board);
  if (cols.length !== 3 && cols.length !== 4) return;
  const defaults = DEFAULT_COLORS[cols.length];
  writeKanbanPref({
    count: cols.length,
    colors: cols.map((c, i) => (isColumnColor(c.attrs.meta) ? (c.attrs.meta as string) : defaults[i]!)),
  });
}

function columnName(column: PMNode, t: TFunction): string {
  const title = column.firstChild?.type.name === 'calloutTitle' ? column.firstChild.textContent.trim() : '';
  return title || t('editor:callout.types.column');
}

/** Runs one board edit as one transaction. */
function useBoardEdit(editor: TipTapEditor, getPos: () => number | undefined) {
  return (edit: (tr: Transaction, pos: number) => boolean) => {
    const pos = getPos();
    // A menu opened before the note turned read-only must not edit it.
    if (typeof pos !== 'number' || !editor.isEditable) return;
    const tr = editor.state.tr;
    if (!edit(tr, pos)) return;
    editor.view.dispatch(tr);
    rememberBoard(editor.state.doc.nodeAt(pos));
  };
}

export function KanbanBoardView({ node, editor, getPos, extension }: NodeViewProps) {
  const { t } = useTranslation('editor');
  const options = extension.options as KanbanOptions;
  const edit = useBoardEdit(editor, getPos);
  const ctx = useContextMenu();
  const dotsRef = useRef<HTMLSpanElement | null>(null);
  const [menu, setMenu] = useState<null | 'main' | 'color'>(null);
  const closeMenu = () => setMenu(null);
  const columns = columnsOf(node);
  const count = columns.length;
  const titleEmpty = node.firstChild?.type.name === 'calloutTitle' && node.firstChild.content.size === 0;
  const editable = editor.isEditable;


  // A tap on a card's grip asks this board for the Move to menu.
  useEffect(() => {
    const onCardMenu = (e: Event) => {
      const board = dotsRef.current?.closest('.pn-callout-kanban');
      if (!board || (e.target as HTMLElement | null)?.closest('.pn-callout-kanban') !== board) return;
      const { pos, column, x, y } = (e as CustomEvent<CardMenuDetail>).detail;
      const items: ContextMenuItem[] = [
        { type: 'header', label: t('kanban.moveTo') },
        ...columnsOf(editor.state.doc.nodeAt(getPos() ?? -1) ?? node).map((col, i) => ({
          label: columnName(col, t),
          checked: i === column,
          onSelect: () => {
            if (i === column || !editor.isEditable) return;
            const tr = editor.state.tr;
            if (moveCard(tr, pos, i)) editor.view.dispatch(tr);
          },
        })),
      ];
      ctx.open({ clientX: x, clientY: y, preventDefault() {}, stopPropagation() {} }, items);
    };
    document.addEventListener(CARD_MENU_EVENT, onCardMenu);
    return () => document.removeEventListener(CARD_MENU_EVENT, onCardMenu);
  });

  const unlocked = options.kanbanUnlocked();
  // Each column's color, as the dots at the end of the Color row.
  const colorDots = (
    <span className="inline-flex items-center gap-1" aria-hidden="true">
      {columns.map((col, i) => (
        <span
          key={i}
          className="w-3 h-3 rounded-full border border-divider"
          style={{ background: `var(--pn-label-${isColumnColor(col.attrs.meta) ? (col.attrs.meta as string) : 'gray'}-ink)` }}
        />
      ))}
    </span>
  );
  const boardMenu = menu && (
    <OptionsMenu
      anchorRef={dotsRef}
      label={t('formatBar.optionsFor', { item: t('callout.types.kanban') })}
      view={menu}
      onClose={closeMenu}
      onEscape={() => (menu === 'main' ? closeMenu() : setMenu('main'))}
      // The Color view holds a row of ten swatches; the main view only short rows.
      className={menu === 'color' ? 'w-80' : 'w-60'}
    >
      {menu === 'color' ? (
        <>
          <BackRow title={t('kanban.color')} onBack={() => setMenu('main')} />
          <div className="px-4 py-3 flex flex-col gap-3">
            {columns.map((col, i) => (
              <div key={i} className="flex flex-col gap-1.5">
                <span className="text-[13px] text-pn-muted truncate" dir="auto">{columnName(col, t)}</span>
                <ColorSwatchRow
                  selected={isColumnColor(col.attrs.meta) ? (col.attrs.meta as LookColor) : 'none'}
                  noneLabel={t('color.remove')}
                  colorLabel={(c) => t(`color.names.${c}`)}
                  onPick={(c) => edit((tr, pos) => setColumnColor(tr, pos, i, c))}
                />
              </div>
            ))}
          </div>
        </>
      ) : (
        <>
          <Group>
            <ActionItem
              label={t('kanban.color')}
              icon={<Palette size={16} aria-hidden="true" />}
              value={colorDots}
              chevron
              onClick={() => setMenu('color')}
            />
          </Group>
          <Group>
            {([3, 4] as const).map((n) => (
              <ActionItem
                key={n}
                label={t('kanban.columnCount', { count: n })}
                icon={<Columns size={16} aria-hidden="true" />}
                value={count === n ? <Check size={14} aria-hidden="true" className="text-accent" /> : undefined}
                onClick={() => {
                  edit((tr, pos) => setColumnCount(tr, pos, n, (c, slot) => slotName(t, c, slot)));
                  closeMenu();
                }}
              />
            ))}
            <ActionItem
              label={t('kanban.addColumn')}
              icon={<Plus size={16} aria-hidden="true" />}
              pro={!unlocked}
              disabled={count >= MAX_COLUMNS}
              onClick={() => {
                closeMenu();
                if (!options.kanbanUnlocked()) options.onUpgrade();
                else edit((tr, pos) => addColumn(tr, pos, '', null));
              }}
            />
          </Group>
          <Group>
            <ActionItem
              label={t('kanban.removeBoard')}
              icon={<XSquare size={16} aria-hidden="true" />}
              tone="danger"
              onClick={() => {
                closeMenu();
                edit((tr, pos) => removeBoard(tr, pos));
              }}
            />
          </Group>
        </>
      )}
    </OptionsMenu>
  );

  return (
    <NodeViewWrapper
      as="div"
      className={`pn-callout pn-callout-kanban${count > 0 ? ' pn-kanban-has-columns' : ''}`}
      data-callout=""
      data-type="kanban"
      role="group"
      aria-label={titleEmpty ? t('callout.types.kanban') : `${t('callout.types.kanban')}: ${node.firstChild?.textContent ?? ''}`}
      style={{ ['--kanban-cols' as string]: Math.max(1, count) } as React.CSSProperties}
    >
      <span className="pn-kanban-icon" contentEditable={false} aria-hidden="true">
        <Kanban size={18} weight="bold" />
      </span>
      {titleEmpty && (
        <span className="pn-callout-placeholder pn-kanban-placeholder" contentEditable={false} aria-hidden="true">
          {t('callout.types.kanban')}
        </span>
      )}
      {editable && (
        <span className="pn-kanban-tools" contentEditable={false} ref={dotsRef}>
          <IconButton
            label={t('formatBar.optionsFor', { item: t('callout.types.kanban') })}
            position="start"
            aria-haspopup="dialog"
            aria-expanded={!!menu}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => setMenu((m) => (m ? null : 'main'))}
          >
            <DotsThree size={18} weight="bold" />
          </IconButton>
        </span>
      )}
      <NodeViewContent className="pn-callout-content" />
      {boardMenu}
      <ContextMenu state={ctx.state} onClose={ctx.close} />
    </NodeViewWrapper>
  );
}

/** The number of cards in a column: the tasks of its top-level task lists. */
function cardCount(column: PMNode): number {
  let n = 0;
  column.forEach((child) => {
    if (child.type.name === 'taskList') {
      child.forEach((item) => {
        if (!isPlaceholderTask(item)) n++;
      });
    }
  });
  return n;
}

export function KanbanColumnView({ node, editor, getPos }: NodeViewProps) {
  const { t } = useTranslation('editor');
  const [menuOpen, setMenuOpen] = useState(false);
  const dotsRef = useRef<HTMLSpanElement | null>(null);
  // The theme's label tokens, the colors the swatches show: gray without a color.
  const key = isColumnColor(node.attrs.meta as string | null) ? (node.attrs.meta as string) : 'gray';
  const titleEmpty = node.firstChild?.type.name === 'calloutTitle' && node.firstChild.content.size === 0;
  const editable = editor.isEditable;

  // The board around this column and this column's place in it.
  const place = () => {
    const pos = getPos();
    if (typeof pos !== 'number') return null;
    const $pos = editor.state.doc.resolve(pos);
    const board = $pos.parent;
    if (!isBoard(board)) return null;
    let index = -1;
    board.forEach((child, _o, i) => {
      if (i <= $pos.index() && child.type.name === 'callout' && child.attrs.type === 'column') index++;
    });
    return { boardPos: $pos.before(), board, index };
  };
  const inBoard = !!place();

  const run = (edit: (tr: Transaction, boardPos: number, index: number) => boolean) => {
    const p = place();
    if (!p || !editor.isEditable) return;
    const tr = editor.state.tr;
    if (!edit(tr, p.boardPos, p.index)) return;
    editor.view.dispatch(tr);
    rememberBoard(editor.state.doc.nodeAt(p.boardPos));
  };

  const p = menuOpen ? place() : null;
  const total = p ? columnsOf(p.board).length : 0;
  const pick = (edit: (tr: Transaction, boardPos: number, index: number) => boolean) => {
    setMenuOpen(false);
    run(edit);
  };
  const columnMenu = p && (
    <OptionsMenu
      anchorRef={dotsRef}
      label={t('formatBar.optionsFor', { item: columnName(node, t) })}
      view="main"
      onClose={() => setMenuOpen(false)}
      className="w-max min-w-48"
    >
      <Group>
        <ActionItem
          label={t('formatBar.moveLeft')}
          icon={<ArrowLeft size={16} aria-hidden="true" />}
          disabled={p.index === 0}
          onClick={() => pick((tr, b, i) => moveColumn(tr, b, i, -1))}
        />
        <ActionItem
          label={t('formatBar.moveRight')}
          icon={<ArrowRight size={16} aria-hidden="true" />}
          disabled={p.index >= total - 1}
          onClick={() => pick((tr, b, i) => moveColumn(tr, b, i, 1))}
        />
      </Group>
      <Group>
        <ActionItem
          label={t('table.deleteColumn')}
          icon={<Trash size={16} aria-hidden="true" />}
          tone="danger"
          disabled={total <= MIN_COLUMNS}
          onClick={() => pick((tr, b, i) => deleteColumn(tr, b, i))}
        />
      </Group>
    </OptionsMenu>
  );

  return (
    <NodeViewWrapper
      as="div"
      className="pn-callout pn-callout-column"
      data-callout=""
      data-type="column"
      role="group"
      aria-label={`${columnName(node, t)}, ${t('kanban.cardCount', { count: cardCount(node) })}`}
      style={{ ['--cs' as string]: `var(--pn-label-${key}-ink)`, ['--ct' as string]: `var(--pn-label-${key}-tint)` } as React.CSSProperties}
    >
      {titleEmpty && (
        <span className="pn-callout-placeholder pn-column-placeholder" contentEditable={false} aria-hidden="true">
          {t('callout.types.column')}
        </span>
      )}
      <span className="pn-column-tools" contentEditable={false} ref={dotsRef}>
        <span className="pn-column-count" aria-hidden="true">{cardCount(node)}</span>
        {editable && inBoard && (
          <IconButton
            label={t('formatBar.optionsFor', { item: columnName(node, t) })}
            position="start"
            aria-haspopup="dialog"
            aria-expanded={menuOpen}
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => setMenuOpen((o) => !o)}
          >
            <DotsThree size={16} weight="bold" />
          </IconButton>
        )}
      </span>
      <NodeViewContent className="pn-callout-content" />
      {columnMenu}
    </NodeViewWrapper>
  );
}
