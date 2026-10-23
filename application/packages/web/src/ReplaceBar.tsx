import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Editor as TipTapEditor } from '@tiptap/react';
import { MagnifyingGlass, ArrowsLeftRight, TextAa, X } from './icons';
import { HoverLabel } from './HoverLabel';
import { isImeComposing } from './imeComposing';
import { BAR_BTN, BAR_INPUT, MatchNav, ReplaceToggle, TEXT_BTN } from './MatchNav';
import { bindingKeyText, keyText } from './shortcutMatch';
import {
  setSearchQuery,
  setActiveMatch,
  clearSearch,
  getSearchInfo,
  scrollToCurrentMatch,
  replaceActiveMatch,
  replaceAllMatches,
  type SearchInfo,
} from './editorSearch';

type Props = {
  editor: TipTapEditor;
  /** Bumped by the parent on every open so the search input refocuses + selects. */
  focusTick: number;
  /** The term to start on when the reader grew the find bar into this one. */
  startQuery?: string;
  /** Shrinks the bar back to the find bar with the current term. */
  onSwap: (query: string) => void;
  /** Free account (the demo opens the bar anyway): the Pro rocket. */
  swapPro?: boolean;
  onClose: () => void;
};

/**
 * Floating find-and-replace bar, the Pro twin of FindBar. Same shell, same
 * slot, same search plugin; the first row is the find bar plus a match-case
 * toggle, the second row holds the replacement and the two replace buttons.
 * Enter in the search row steps to the next match, Enter in the replace row
 * replaces the current one. The parent gates the bar on Pro before it ever
 * mounts, so nothing in here checks.
 *
 * Below the `sm` breakpoint the bar spans the pane instead of hugging the
 * end edge: two rows of input and buttons do not fit in the width the find
 * bar gets away with. `min-w-0` on the bar is load-bearing there: a flex
 * item's minimum width defaults to its content's intrinsic width, and two
 * text inputs are wider than a phone, so without it the bar refused to
 * shrink and hung 28px past the pane's start edge.
 *
 * Esc deliberately does not close it, for the reason FindBar documents:
 * the shortcut that opened it closes it, and the X is the mouse path.
 */
export function ReplaceBar({ editor, focusTick, startQuery, onSwap, swapPro = false, onClose }: Props) {
  const { t } = useTranslation('editor');
  const searchRef = useRef<HTMLInputElement>(null);
  const replaceRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState(startQuery ?? '');
  const [replacement, setReplacement] = useState('');
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [info, setInfo] = useState<SearchInfo>({ active: -1, total: 0, activeIsNode: false });
  // How many matches the last replace-all rewrote. Shown in the count slot
  // until the next search change or step: without it a successful
  // replace-all ends on a red "0/0", which reads as a failure.
  const [replaced, setReplaced] = useState<number | null>(null);

  const refresh = useCallback(() => {
    setInfo(getSearchInfo(editor.view));
  }, [editor]);

  // Prefill from the current selection (single line, sane length), the way a
  // browser find does. Runs once on open, and not after a swap, which
  // brought its term along.
  useEffect(() => {
    if (startQuery) return;
    const { from, to } = editor.state.selection;
    if (to > from) {
      const sel = editor.state.doc.textBetween(from, to, ' ').trim();
      if (sel && sel.length <= 80 && !sel.includes('\n')) setQuery(sel);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Push the query and the case rule into the plugin, refresh the count,
  // jump to the first hit.
  useEffect(() => {
    setSearchQuery(editor.view, query, caseSensitive);
    setReplaced(null);
    refresh();
    if (query) requestAnimationFrame(() => scrollToCurrentMatch(editor.view));
  }, [query, caseSensitive, editor, refresh]);

  // Keep the count fresh while the note is edited under an open bar.
  useEffect(() => {
    editor.on('update', refresh);
    return () => { editor.off('update', refresh); };
  }, [editor, refresh]);

  // Clear highlights when the bar closes.
  useEffect(() => {
    return () => { if (!editor.isDestroyed) clearSearch(editor.view); };
  }, [editor]);

  // Focus + select the search input on open.
  useEffect(() => {
    const el = searchRef.current;
    if (!el) return;
    el.focus();
    el.select();
  }, [focusTick]);

  const go = useCallback((dir: 1 | -1) => {
    const { active, total } = getSearchInfo(editor.view);
    if (total === 0) return;
    setActiveMatch(editor.view, (active < 0 ? 0 : active) + dir);
    setReplaced(null);
    refresh();
    requestAnimationFrame(() => scrollToCurrentMatch(editor.view));
  }, [editor, refresh]);

  const replaceOne = useCallback(() => {
    if (!replaceActiveMatch(editor.view, replacement)) return;
    setReplaced(null);
    refresh();
    requestAnimationFrame(() => scrollToCurrentMatch(editor.view));
  }, [editor, replacement, refresh]);

  const replaceEvery = useCallback(() => {
    const n = replaceAllMatches(editor.view, replacement);
    refresh();
    if (n > 0) setReplaced(n);
  }, [editor, replacement, refresh]);

  // Tab goes from the search to the replacement and Shift+Tab back, the
  // way a find-and-replace bar reads; the buttons between the two fields
  // have the Enter keys and the shortcut instead.
  const onSearchKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Tab' && !e.shiftKey && replaceRef.current) {
      e.preventDefault();
      replaceRef.current.focus();
      return;
    }
    if (e.key === 'Enter' && !isImeComposing(e)) {
      e.preventDefault();
      go(e.shiftKey ? -1 : 1);
    }
  };

  const onReplaceKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Tab' && e.shiftKey) {
      e.preventDefault();
      searchRef.current?.focus();
      return;
    }
    if (e.key === 'Enter' && !isImeComposing(e)) {
      e.preventDefault();
      replaceOne();
    }
  };

  const hasQuery = query.trim().length > 0;
  const noHits = replaced == null && info.total === 0 && hasQuery;
  const count =
    replaced != null
      ? t('find.replacedCount', { count: replaced })
      : info.total > 0
        ? `${info.active + 1}/${info.total}`
        : hasQuery
          ? '0/0'
          : '';
  const canReplace = info.total > 0 && !info.activeIsNode;
  const iconCls = 'text-pn-muted shrink-0 ms-0.5 me-0.5';

  return (
    <div className="pointer-events-auto mt-1 ms-2 me-2 flex flex-1 min-w-0 sm:flex-none sm:w-[22rem] flex-col gap-1 rounded-lg border border-divider bg-surface-1 shadow-lg px-1.5 py-1">
      <div className="flex items-center gap-0.5">
        <MagnifyingGlass size={15} className={iconCls} />
        <input
          ref={searchRef}
          type="text"
          value={query}
          onChange={(e) => setQuery(e.target.value)}
          onKeyDown={onSearchKeyDown}
          placeholder={t('find.placeholder')}
          aria-label={t('find.label')}
          spellCheck={false}
          autoComplete="off"
          className={BAR_INPUT}
        />
        <HoverLabel label={t('find.caseSensitiveTitle')} position="below">
          <button
            type="button"
            onMouseDown={(e) => e.preventDefault()}
            onClick={() => setCaseSensitive((v) => !v)}
            aria-pressed={caseSensitive}
            aria-label={t('find.caseSensitive')}
            className={`${BAR_BTN}${caseSensitive ? ' bg-pn/10 text-accent' : ''}`}
          >
            <TextAa size={15} />
          </button>
        </HoverLabel>
        <MatchNav count={count} noHits={noHits} canStep={info.total > 0} onStep={go} />
        <ReplaceToggle open pro={swapPro} onClick={() => onSwap(query)} />
        <div className="w-px h-5 bg-divider mx-0.5 shrink-0" aria-hidden="true" />
        <HoverLabel label={t('find.closeReplaceTitle')} keys={keyText('findReplace')} position="below-end">
          <button
            type="button"
            onMouseDown={(e) => e.preventDefault()}
            onClick={onClose}
            aria-label={t('find.closeReplace')}
            className={BAR_BTN}
          >
            <X size={15} />
          </button>
        </HoverLabel>
      </div>
      <div className="flex items-center gap-0.5">
        <ArrowsLeftRight size={15} className={iconCls} />
        <input
          type="text"
          value={replacement}
          ref={replaceRef}
          onChange={(e) => setReplacement(e.target.value)}
          onKeyDown={onReplaceKeyDown}
          placeholder={t('find.replacePlaceholder')}
          aria-label={t('find.replaceLabel')}
          spellCheck={false}
          autoComplete="off"
          className={BAR_INPUT}
        />
        <HoverLabel label={t('find.replaceTitle')} keys={bindingKeyText({ key: 'Enter' })} position="below">
          <button
            type="button"
            onMouseDown={(e) => e.preventDefault()}
            onClick={replaceOne}
            disabled={!canReplace}
            className={TEXT_BTN}
          >
            {t('find.replace')}
          </button>
        </HoverLabel>
        <HoverLabel label={t('find.replaceAllTitle')} position="below-end">
          <button
            type="button"
            onMouseDown={(e) => e.preventDefault()}
            onClick={replaceEvery}
            disabled={info.total === 0}
            className={TEXT_BTN}
          >
            {t('find.replaceAll')}
          </button>
        </HoverLabel>
      </div>
    </div>
  );
}
