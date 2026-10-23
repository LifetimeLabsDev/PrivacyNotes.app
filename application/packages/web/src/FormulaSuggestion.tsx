/**
 * The table formula menu.
 *
 * Typing `=` at the start of a table cell opens a list of every function,
 * filtered as the person keeps typing. Picking one writes the formula with
 * its range already guessed from the numbers above the caret, so the menu's
 * real job is done before the list even closes: a person should never have to
 * work out that the three numbers above them are `B2:B4`.
 *
 * The same list is the table toolbar's button, which simply types `=` into the
 * cell. One menu, one set of behaviour, two ways in.
 *
 * It is a near-twin of NoteLinkSuggestion.tsx on purpose. Both are a
 * `@tiptap/suggestion` run rendering a plain DOM popup through a
 * `ReactRenderer`, and every awkward detail in there was earned by a bug
 * (a mousedown that stole focus, an Android backspace that blurs the editor,
 * Escape meaning "stay away for the rest of this run"). Copying the shape is
 * cheaper than rediscovering them.
 *
 * Spec: ops/docs/archive/table-formulas.md
 */

import { ReactRenderer } from '@tiptap/react';
import Suggestion, { type SuggestionOptions, type SuggestionProps, type SuggestionKeyDownProps } from '@tiptap/suggestion';
import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Editor } from '@tiptap/core';
import { PluginKey, TextSelection } from '@tiptap/pm/state';
import { textMatcher } from './textMatch';
import { FORMULA_MENU, caretCell, formulaInsertion } from './tableFormulaInsert';

type FormulaItem = { name: string };

type ListProps = {
  items: FormulaItem[];
  command: (props: FormulaItem) => void;
};

type ListRef = { onKeyDown: (props: SuggestionKeyDownProps) => boolean };

const FormulaList = forwardRef<ListRef, ListProps>(({ items, command }, ref) => {
  const { t } = useTranslation('editor');
  const [selectedIndex, setSelectedIndex] = useState(0);
  const listRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => setSelectedIndex(0), [items]);

  useEffect(() => {
    listRef.current?.querySelector('[data-selected="true"]')?.scrollIntoView({ block: 'nearest' });
  }, [selectedIndex]);

  useImperativeHandle(ref, () => ({
    onKeyDown: ({ event }: SuggestionKeyDownProps) => {
      if (event.key === 'ArrowUp') {
        event.preventDefault();
        setSelectedIndex((i) => (i <= 0 ? items.length - 1 : i - 1));
        return true;
      }
      if (event.key === 'ArrowDown') {
        event.preventDefault();
        setSelectedIndex((i) => (i >= items.length - 1 ? 0 : i + 1));
        return true;
      }
      if (event.key === 'Enter' || event.key === 'Tab') {
        const item = items[selectedIndex];
        // Enter with nothing matching is a plain Enter: the person is writing
        // their own formula and the menu is in the way.
        if (!item) return false;
        event.preventDefault();
        command(item);
        return true;
      }
      // Escape is the suggestion plugin's to handle.
      return event.key === 'Escape';
    },
  }));

  if (items.length === 0) {
    return (
      <div className="z-50 w-64 rounded-lg border border-divider bg-surface-2 shadow-lg overflow-hidden">
        <div className="px-3 py-2 text-sm text-pn-muted">{t('table.formulaNoMatch')}</div>
      </div>
    );
  }

  return (
    <div ref={listRef} className="z-50 w-72 max-h-64 overflow-y-auto rounded-lg border border-divider bg-surface-2 shadow-lg">
      {items.map((item, index) => (
        <button
          key={item.name}
          type="button"
          data-selected={index === selectedIndex}
          onClick={() => command(item)}
          onMouseEnter={() => setSelectedIndex(index)}
          className={`w-full text-start px-3 py-1.5 text-sm flex items-baseline gap-2 transition ${
            index === selectedIndex ? 'bg-accent/10 text-accent-strong dark:bg-accent/20' : 'text-pn hover:bg-pn/5'
          }`}
        >
          <span className="font-mono shrink-0">{item.name}</span>
          <span className="text-xs text-pn-muted truncate">{t(`table.formula.${item.name}`)}</span>
        </button>
      ))}
    </div>
  );
});
FormulaList.displayName = 'FormulaList';

/**
 * Build the suggestion options. Called from the table extension, which owns
 * the Pro flag.
 *
 * `unlocked` is read inside `allow` rather than captured, so an upgrade during
 * the session opens the menu without rebuilding the extension set.
 */
export function formulaSuggestion(editor: Editor, unlocked: () => boolean): ReturnType<typeof Suggestion> {
  const options: SuggestionOptions<FormulaItem, FormulaItem> = {
    pluginKey: new PluginKey('tableFormulaSuggestion'),
    editor,
    char: '=',
    allowedPrefixes: null,

    /**
     * Three conditions, and the third is the one that is easy to miss.
     *
     * The `=` must be at the very start of a table cell, because a formula is
     * the whole cell or it is not a formula, and without that test an `=`
     * anywhere in prose would open the menu while somebody wrote "x = y".
     *
     * And what follows the `=` must still be a bare name. Every cell that
     * already HOLDS a formula starts with `=` at the cell start, so without
     * this the menu reopened over a finished `=SUM(B2:B4)` the moment the
     * caret entered the cell to edit it, offering a list that matched nothing
     * and covering the text being edited. Letters only means the menu is open
     * exactly while the person is still choosing a function, and gone the
     * moment they type a bracket.
     */
    allow: ({ state, range }) => {
      if (!unlocked()) return false;
      const $from = state.doc.resolve(range.from);
      if ($from.parent.type.name !== 'paragraph') return false;
      const cell = $from.node(-1)?.type.name;
      if (cell !== 'tableCell' && cell !== 'tableHeader') return false;
      if (range.from !== $from.start()) return false;
      // The WHOLE cell, not just the text before the caret. A caret parked
      // after the `S` of a finished `=SUM(B2:B4)` has `=S` behind it and
      // would pass a test that only looked backwards, so the menu reopened in
      // the middle of editing a formula that was already written.
      return /^=[A-Za-z]*$/.test($from.parent.textContent);
    },

    items: ({ query }) => {
      const names = query ? ranked(FORMULA_MENU, query) : FORMULA_MENU;
      return names.map((name) => ({ name }));
    },

    command: ({ editor: ed, range, props }) => {
      const here = caretCell(ed.state);
      const { text, caret } = formulaInsertion(props.name, here?.grid ?? null, here?.at ?? null);
      // `insertText` on a transaction, not `insertContent`. insertContent
      // parses its string argument as content, and `=SUM(D2:D4)` came back as
      // two paragraphs inside the cell. A formula is text and nothing else.
      const tr = ed.state.tr.insertText(text, range.from, range.to);
      const target = Math.min(range.from + caret, tr.doc.content.size);
      tr.setSelection(TextSelection.create(tr.doc, target));
      ed.view.dispatch(tr);
      ed.view.focus();
    },

    render: () => {
      let component: ReactRenderer<ListRef> | null = null;
      let popup: HTMLDivElement | null = null;
      let blurHandler: (() => void) | null = null;
      let dismissed = false;

      return {
        onStart(props: SuggestionProps<FormulaItem, FormulaItem>) {
          dismissed = false;
          mount(props);
        },

        onUpdate(props: SuggestionProps<FormulaItem, FormulaItem>) {
          if (!component && !dismissed) {
            mount(props);
            return;
          }
          component?.updateProps({ items: props.items, command: props.command });
          if (popup) updatePosition(popup, props.clientRect);
        },

        onKeyDown(props: SuggestionKeyDownProps) {
          if (props.event.key === 'Escape') {
            dismissed = true;
            cleanup();
            return true;
          }
          return component?.ref?.onKeyDown(props) ?? false;
        },

        onExit() {
          dismissed = false;
          cleanup();
        },
      };

      function mount(props: SuggestionProps<FormulaItem, FormulaItem>) {
        component = new ReactRenderer(FormulaList, {
          props: { items: props.items, command: props.command },
          editor: props.editor,
        });
        popup = document.createElement('div');
        popup.style.position = 'absolute';
        popup.style.zIndex = '9999';
        // A mousedown inside the popup would blur the editor, and focusout
        // tears the popup down before the click handler can run.
        popup.addEventListener('mousedown', (e) => e.preventDefault());
        popup.appendChild(component.element);
        document.body.appendChild(popup);
        updatePosition(popup, props.clientRect);
        blurHandler = () => cleanup();
        props.editor.view.dom.addEventListener('focusout', blurHandler);
      }

      function cleanup() {
        if (blurHandler) {
          editor.view.dom.removeEventListener('focusout', blurHandler);
          blurHandler = null;
        }
        component?.destroy();
        component = null;
        popup?.remove();
        popup = null;
      }
    },
  };

  return Suggestion(options);
}

/** Best match first, then the catalogue order. Array sort is stable. */
function ranked(names: readonly string[], query: string): string[] {
  const match = textMatcher(query);
  return names
    .map((name) => ({ name, rank: match(name)?.rank ?? 0 }))
    .filter((r) => r.rank > 0)
    .sort((a, b) => b.rank - a.rank)
    .map((r) => r.name);
}

/** Below the caret, nudged left when it would run off the right edge. */
function updatePosition(popup: HTMLDivElement, clientRect?: (() => DOMRect | null) | null) {
  if (!clientRect) return;
  const rect = clientRect();
  if (!rect) return;
  popup.style.top = `${rect.bottom + window.scrollY + 4}px`;
  popup.style.left = `${rect.left + window.scrollX}px`;
  requestAnimationFrame(() => {
    const popupRect = popup.getBoundingClientRect();
    if (popupRect.right > window.innerWidth - 8) {
      popup.style.left = `${window.innerWidth - popupRect.width - 8}px`;
    }
  });
}
