import { useCallback, useEffect, useRef, useState, type ReactNode } from 'react';
import { useTheme } from './theme';
import { registerEditorCommand } from './editorCommands';
import { formatInstant } from './intlFormat';
import { APP_KEYS, matchesKey } from './shortcutMatch';
import { isImeComposing } from './imeComposing';
import { proUnlocked } from './demo';
import { SourceSearchBar } from './SourceSearchBar';
import { replaceAllText, type TextMatch } from './markdownSourceSearch';

type Props = {
  /** Initial markdown content. Only read on mount - use a `key` prop to force reload. */
  value: string;
  /** Called with the latest markdown on every keystroke. */
  onChange: (markdown: string) => void;
  readOnly?: boolean;
  /** Turns on find (free) and replace (Pro) for this view, with the keys and
   *  the command entries the rich editor has. */
  search?: { isPro: boolean; onOpenUpgrade?: (trigger: 'replace') => void };
};

/**
 * Plain markdown source editor: a textarea bound to the note body.
 *
 * The body is already stored as markdown (Editor.tsx parses markdown in
 * and serializes markdown out via tiptap-markdown), so this shares the
 * exact same value/onChange contract and the same save + sync path. No
 * serialization, no schema change.
 *
 * Deliberately boring - no toolbar, no note-link autocomplete, no image
 * paste. It is the reliable fallback when the rich editor misbehaves, and
 * the source view for people who prefer raw markdown. With `search` it has
 * the find and replace bars, which see the raw text: a code block's
 * language, a link's address, the markup itself (GitHub #455).
 *
 * Uncontrolled (defaultValue + key), mirroring Editor, so typing never
 * round-trips through parent state.
 *
 * Spec: ops/specs/editor-mode-toggle.md (no custom Tab-key handling in v1, deliberately)
 */
export function MarkdownSourceEditor({ value, onChange, readOnly = false, search }: Props) {
  const ref = useRef<HTMLTextAreaElement>(null);
  const rootRef = useRef<HTMLDivElement>(null);
  const { spellcheck } = useTheme();
  const [text, setText] = useState(value);

  // Grow to fit the content so the note scrolls in the editor pane
  // rather than in a nested textarea scrollbar.
  function fit() {
    const el = ref.current;
    if (!el) return;
    el.style.height = 'auto';
    el.style.height = `${el.scrollHeight}px`;
  }

  useEffect(() => {
    fit();
  }, []);

  function change(markdown: string) {
    onChange(markdown);
    setText(markdown);
    fit();
  }

  /** Writes `insert` over [from, to) through the same change as typing, so the
   *  field's own undo takes it back in one step, and gives focus back to
   *  whatever held it. */
  function writeRange(from: number, to: number, insert: string) {
    const el = ref.current;
    if (!el) return;
    const back = document.activeElement as HTMLElement | null;
    el.focus();
    el.setSelectionRange(from, to);
    if (!document.execCommand?.('insertText', false, insert)) {
      el.setRangeText(insert, from, to, 'end');
      change(el.value);
    }
    if (back && back !== el) back.focus();
  }

  /** The date, or the date and time, at the caret, through the same change as
   *  typing. insertText keeps the field's own undo, which the tag row's undo
   *  drives; setRangeText is the way where the browser has no insertText. */
  function insertDate(style: 'date' | 'dateTime') {
    const el = ref.current;
    if (!el) return;
    const text = formatInstant(new Date(), style);
    el.focus();
    if (document.execCommand?.('insertText', false, text)) return;
    el.setRangeText(text, el.selectionStart, el.selectionEnd, 'end');
    change(el.value);
  }

  const [bar, setBar] = useState<'none' | 'find' | 'replace'>('none');
  const barRef = useRef(bar);
  barRef.current = bar;
  const [barFocusTick, setBarFocusTick] = useState(0);
  const [barSeed, setBarSeed] = useState('');
  const [hits, setHits] = useState<{ matches: TextMatch[]; active: number }>({ matches: [], active: -1 });
  const onHits = useCallback((matches: TextMatch[], active: number) => setHits({ matches, active }), []);

  const openBar = (next: 'find' | 'replace') => {
    const el = ref.current;
    const sel = el ? el.value.slice(el.selectionStart, el.selectionEnd).trim() : '';
    if (barRef.current === 'none') setBarSeed(sel && sel.length <= 80 && !sel.includes('\n') ? sel : '');
    setBar(next);
    setBarFocusTick((n) => n + 1);
  };

  /** Back to the text with the active match selected, the way the rich bar
   *  leaves the caret on it. */
  const closeBar = () => {
    const el = ref.current;
    const m = hits.matches[hits.active];
    setBar('none');
    if (!el) return;
    el.focus();
    if (m) el.setSelectionRange(m.from, m.to);
  };

  // Replace is the Pro half of search, gated here for the key and the "..."
  // row alike, as useEditorPanels gates the rich editor's.
  // Spec: ops/docs/pro-features.md (Find and replace)
  const toggleReplace = () => {
    if (!search || readOnly) return;
    if (barRef.current === 'replace') return closeBar();
    if (!proUnlocked(search.isPro)) return search.onOpenUpgrade?.('replace');
    openBar('replace');
  };
  const toggleFind = () => {
    if (barRef.current === 'find') closeBar();
    else openBar('find');
  };
  const togglesRef = useRef({ toggleFind, toggleReplace });
  togglesRef.current = { toggleFind, toggleReplace };

  const hasSearch = !!search;
  useEffect(() => {
    if (!hasSearch) return;
    const off = [
      registerEditorCommand('find', () => togglesRef.current.toggleFind()),
      ...(readOnly ? [] : [registerEditorCommand('findReplace', () => togglesRef.current.toggleReplace())]),
    ];
    return () => off.forEach((f) => f());
  }, [hasSearch, readOnly]);

  // The same keys as the rich editor's (useEditorPanels.ts): capture phase on
  // the document, standing down in a field that is not this view's, and
  // keeping Escape from the global cascade while a bar is open.
  useEffect(() => {
    if (!hasSearch) return;
    const onKeyDown = (e: KeyboardEvent) => {
      if (isImeComposing(e)) return;
      const ae = document.activeElement as HTMLElement | null;
      const ours = !!ae && !!rootRef.current?.contains(ae);
      const inForeignField = !!ae && /^(input|textarea)$/i.test(ae.tagName) && !ours;
      if (e.key === 'Escape') {
        if (barRef.current !== 'none' && !inForeignField) {
          e.preventDefault();
          e.stopPropagation();
        }
        return;
      }
      const isReplace = matchesKey(e, APP_KEYS.findReplace);
      if (!isReplace && !matchesKey(e, APP_KEYS.find)) return;
      if (inForeignField) return;
      e.preventDefault();
      if (isReplace) togglesRef.current.toggleReplace();
      else togglesRef.current.toggleFind();
    };
    document.addEventListener('keydown', onKeyDown, true);
    return () => document.removeEventListener('keydown', onKeyDown, true);
  }, [hasSearch]);

  useEffect(() => {
    if (readOnly) setBar((b) => (b === 'replace' ? 'none' : b));
  }, [readOnly]);

  // Scroll the active match into view as the bar steps or the query changes,
  // not while the reader types in the note under an open bar.
  useEffect(() => {
    if (hits.active < 0 || document.activeElement === ref.current) return;
    rootRef.current?.querySelector('[data-pn-hit-current]')?.scrollIntoView({ block: 'center' });
  }, [hits]);

  // The rich editor is not mounted in this view, so the field registers the
  // date inserts and takes their keys itself.
  const insertRef = useRef(insertDate);
  insertRef.current = insertDate;
  useEffect(() => {
    if (readOnly) return;
    const off = [
      registerEditorCommand('insertDate', () => insertRef.current('date')),
      registerEditorCommand('insertDateTime', () => insertRef.current('dateTime')),
    ];
    return () => off.forEach((f) => f());
  }, [readOnly]);

  const textarea = (
    <textarea
      ref={ref}
      // The tag row's undo/redo drive the native undo stack of whichever
      // textarea holds focus, and reach for this one by name when nothing
      // does. See handleHistory in NotesView.tsx.
      data-pn-source
      defaultValue={value}
      readOnly={readOnly}
      spellCheck={spellcheck}
      onChange={(e) => change(e.target.value)}
      onKeyDown={(e) => {
        if (readOnly) return;
        const key = e.nativeEvent;
        const style = matchesKey(key, APP_KEYS.insertDate) ? 'date' : matchesKey(key, APP_KEYS.insertDateTime) ? 'dateTime' : null;
        if (!style) return;
        e.preventDefault();
        insertDate(style);
      }}
      // Tracks the Text size setting like the rich editor does, from the
      // same --pn-text-scale knob. Its own 14px base is kept (monospace
      // runs visually larger than the prose face at the same size).
      style={{ fontSize: 'calc(14px * var(--pn-text-scale))' }}
      className={`${search ? 'relative' : 'mt-4'} w-full min-h-[60vh] resize-none border-0 bg-transparent p-0 font-mono leading-relaxed text-pn outline-none`}
    />
  );
  if (!search) return textarea;

  // The matches are painted on a copy of the text under the transparent
  // textarea: same font, size, width and wrapping, so each mark sits exactly
  // under its characters. A textarea has no highlight of its own.
  let marks: ReactNode = null;
  if (bar !== 'none' && hits.matches.length > 0) {
    const parts: ReactNode[] = [];
    let at = 0;
    hits.matches.forEach((m, i) => {
      parts.push(text.slice(at, m.from));
      parts.push(
        <mark
          key={m.from}
          className={i === hits.active ? 'pn-search-hit pn-search-hit-current' : 'pn-search-hit'}
          {...(i === hits.active ? { 'data-pn-hit-current': '' } : {})}
        >
          {text.slice(m.from, m.to)}
        </mark>,
      );
      at = m.to;
    });
    parts.push(text.slice(at));
    marks = (
      <div
        aria-hidden="true"
        style={{ fontSize: 'calc(14px * var(--pn-text-scale))' }}
        className="pn-source-marks pointer-events-none absolute inset-0 whitespace-pre-wrap break-words font-mono leading-relaxed text-transparent"
      >
        {parts}
      </div>
    );
  }

  // mt-4: the rich editor's formatting bar normally separates the body from
  // the sticky tag row above. There is no bar here, so the textarea owns that
  // gap or the text sits glued to the row.
  // min-h-[60vh]: matches `.ProseMirror` in index.css so toggling modes does
  // not jump the page height.
  // The bar takes the rich editor's slot: a zero-height sticky row pinned
  // under the tag row, floating over the text.
  return (
    <div ref={rootRef} className="mt-4">
      {bar !== 'none' && (
        <div
          className="sticky z-[5] flex h-0 items-start justify-end overflow-visible pointer-events-none"
          style={{ top: 'var(--pn-tagrow-h, 0px)' }}
        >
          <SourceSearchBar
            mode={bar}
            text={text}
            focusTick={barFocusTick}
            initialQuery={barSeed}
            onHits={onHits}
            onReplaceOne={(m, replacement) => writeRange(m.from, m.to, replacement)}
            onReplaceAll={(matches, replacement) => {
              const first = matches[0]!.from;
              const last = matches[matches.length - 1]!.to;
              const next = replaceAllText(text, matches, replacement);
              writeRange(first, last, next.slice(first, next.length - (text.length - last)));
            }}
            onClose={closeBar}
          />
        </div>
      )}
      <div className="relative">
        {marks}
        {textarea}
      </div>
    </div>
  );
}
