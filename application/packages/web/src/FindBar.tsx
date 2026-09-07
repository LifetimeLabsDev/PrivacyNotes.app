import { useCallback, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { Editor as TipTapEditor } from '@tiptap/react';
import { MagnifyingGlass, X } from './icons';
import { HoverLabel } from './HoverLabel';
import { BAR_BTN, MatchNav } from './MatchNav';
import {
  setSearchQuery,
  setActiveMatch,
  clearSearch,
  getSearchInfo,
  scrollToCurrentMatch,
  type SearchInfo,
} from './editorSearch';

type Props = {
  editor: TipTapEditor;
  /** Bumped by the parent on every Cmd/Ctrl+F so the input refocuses + selects. */
  focusTick: number;
  onClose: () => void;
};

/**
 * Floating find-in-note bar. Sits top-right just below the editor toolbar
 * (positioned by the parent). Type to highlight matches; the up/down arrows
 * (or Shift+Enter / Enter) jump between them and scroll the active match into
 * view. Cmd/Ctrl+F or the X closes it and returns focus to the note; Esc
 * deliberately does not (see onKeyDown).
 *
 * All match-finding and highlighting lives in editorSearch.ts; this is just
 * the control surface. ReplaceBar.tsx is its Pro twin on the same plugin,
 * and MatchNav.tsx holds the count and arrows both bars draw.
 */
export function FindBar({ editor, focusTick, onClose }: Props) {
  const { t } = useTranslation('editor');
  const inputRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState('');
  const [info, setInfo] = useState<SearchInfo>({ active: -1, total: 0, activeIsNode: false });

  const refresh = useCallback(() => {
    setInfo(getSearchInfo(editor.view));
  }, [editor]);

  // Prefill from the current selection (single line, sane length), the way a
  // browser find does. Runs once on open.
  useEffect(() => {
    const { from, to } = editor.state.selection;
    if (to > from) {
      const sel = editor.state.doc.textBetween(from, to, ' ').trim();
      if (sel && sel.length <= 80 && !sel.includes('\n')) setQuery(sel);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  // Push the query into the plugin, refresh the count, jump to the first hit.
  useEffect(() => {
    setSearchQuery(editor.view, query);
    refresh();
    if (query) requestAnimationFrame(() => scrollToCurrentMatch(editor.view));
  }, [query, editor, refresh]);

  // Keep the count fresh while the note is edited under an open bar.
  useEffect(() => {
    editor.on('update', refresh);
    return () => { editor.off('update', refresh); };
  }, [editor, refresh]);

  // Clear highlights when the bar closes.
  useEffect(() => {
    return () => { if (!editor.isDestroyed) clearSearch(editor.view); };
  }, [editor]);

  // Focus + select on open and on every subsequent Cmd/Ctrl+F.
  useEffect(() => {
    const el = inputRef.current;
    if (!el) return;
    el.focus();
    el.select();
  }, [focusTick]);

  const go = useCallback((dir: 1 | -1) => {
    const { active, total } = getSearchInfo(editor.view);
    if (total === 0) return;
    setActiveMatch(editor.view, (active < 0 ? 0 : active) + dir);
    refresh();
    requestAnimationFrame(() => scrollToCurrentMatch(editor.view));
  }, [editor, refresh]);

  /**
   * Enter / Shift+Enter step through matches.
   *
   * NEITHER Esc NOR Cmd+F is handled here. Escape is a global "get me out"
   * that scrolls the note back to the top, which fought the caret-parking fix
   * (the bar closed correctly, then the note jumped anyway), so it is no
   * longer a way to close the bar at all. Cmd+F IS the way to close it, but
   * that shortcut is owned by a capture-phase document listener in Editor.tsx
   * which runs before this bubble-phase handler could ever see the key - so
   * the toggle lives there, next to the code that opens the bar. The X button
   * is the mouse equivalent and calls onClose directly.
   */
  const onKeyDown = (e: React.KeyboardEvent<HTMLInputElement>) => {
    if (e.key === 'Enter') {
      e.preventDefault();
      go(e.shiftKey ? -1 : 1);
    }
  };

  const hasQuery = query.trim().length > 0;
  const noHits = info.total === 0 && hasQuery;
  const count = info.total > 0 ? `${info.active + 1}/${info.total}` : hasQuery ? '0/0' : '';

  return (
    <div className="pointer-events-auto mt-1 me-2 flex items-center gap-0.5 rounded-lg border border-divider bg-surface-1 shadow-lg px-1.5 py-1">
      <MagnifyingGlass size={15} className="text-neutral-400 dark:text-neutral-500 shrink-0 ms-0.5 me-0.5" />
      <input
        ref={inputRef}
        type="text"
        value={query}
        onChange={(e) => setQuery(e.target.value)}
        onKeyDown={onKeyDown}
        placeholder={t('find.placeholder')}
        aria-label={t('find.label')}
        spellCheck={false}
        autoComplete="off"
        className="w-36 sm:w-44 bg-transparent text-sm text-neutral-800 dark:text-neutral-100 placeholder:text-neutral-400 dark:placeholder:text-neutral-500 outline-none px-1"
      />
      <MatchNav count={count} noHits={noHits} canStep={info.total > 0} onStep={go} />
      <div className="w-px h-5 bg-divider mx-0.5 shrink-0" aria-hidden="true" />
      <HoverLabel label={t('find.closeTitle')} position="below-end">
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          // NOT `close` - that is `window.close`, a DOM global. When the local
          // `close` helper was removed here, `onClick={close}` kept
          // type-checking against it and silently did nothing at runtime.
          onClick={onClose}
          aria-label={t('find.close')}
          className={BAR_BTN}
        >
          <X size={15} />
        </button>
      </HoverLabel>
    </div>
  );
}
