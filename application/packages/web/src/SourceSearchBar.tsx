import { useEffect, useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { MagnifyingGlass, ArrowsLeftRight, TextAa, X } from './icons';
import { HoverLabel } from './HoverLabel';
import { isImeComposing } from './imeComposing';
import { BAR_BTN, BAR_INPUT, MatchNav, TEXT_BTN } from './MatchNav';
import { keyText } from './shortcutMatch';
import { findTextMatches, type TextMatch } from './markdownSourceSearch';

type Props = {
  mode: 'find' | 'replace';
  /** The source text as it is now. */
  text: string;
  /** Bumped by the parent on every open so the search input refocuses + selects. */
  focusTick: number;
  /** The textarea's selection when the bar opened, a single short line. */
  initialQuery: string;
  /** The matches and the active one, for the highlight layer under the textarea. */
  onHits: (matches: TextMatch[], active: number) => void;
  onReplaceOne: (match: TextMatch, replacement: string) => void;
  onReplaceAll: (matches: TextMatch[], replacement: string) => void;
  onClose: () => void;
};

/**
 * The find and replace bars of the Markdown source view: the same two bars as
 * FindBar and ReplaceBar, in the same slot and with the same strings, over the
 * raw text instead of the rich editor's document. Find is one row, replace
 * adds the match-case toggle and the replacement row. The parent gates
 * replace on Pro and on an editable note before this mounts.
 */
export function SourceSearchBar({ mode, text, focusTick, initialQuery, onHits, onReplaceOne, onReplaceAll, onClose }: Props) {
  const { t } = useTranslation('editor');
  const searchRef = useRef<HTMLInputElement>(null);
  const replaceRef = useRef<HTMLInputElement>(null);
  const [query, setQuery] = useState(initialQuery);
  const [replacement, setReplacement] = useState('');
  const [caseSensitive, setCaseSensitive] = useState(false);
  const [active, setActive] = useState(0);
  // How many matches the last replace-all rewrote, shown in the count slot
  // until the next search change or step, so a replace-all does not end on a
  // red "0/0".
  const [replaced, setReplaced] = useState<number | null>(null);

  const matches = useMemo(
    () => findTextMatches(text, query, mode === 'replace' && caseSensitive),
    [text, query, caseSensitive, mode],
  );
  const current = matches.length === 0 ? -1 : Math.min(active, matches.length - 1);

  useEffect(() => { onHits(matches, current); }, [matches, current, onHits]);
  useEffect(() => () => onHits([], -1), [onHits]);

  useEffect(() => {
    setActive(0);
    setReplaced(null);
  }, [query, caseSensitive]);

  useEffect(() => {
    const el = searchRef.current;
    if (!el) return;
    el.focus();
    el.select();
  }, [focusTick]);

  const go = (dir: 1 | -1) => {
    if (matches.length === 0) return;
    setActive((current + dir + matches.length) % matches.length);
    setReplaced(null);
  };

  const replaceOne = () => {
    const m = matches[current];
    if (!m) return;
    setReplaced(null);
    onReplaceOne(m, replacement);
  };

  const replaceEvery = () => {
    if (matches.length === 0) return;
    const n = matches.length;
    onReplaceAll(matches, replacement);
    setReplaced(n);
  };

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
  const total = matches.length;
  const noHits = replaced == null && total === 0 && hasQuery;
  const count =
    replaced != null
      ? t('find.replacedCount', { count: replaced })
      : total > 0
        ? `${current + 1}/${total}`
        : hasQuery
          ? '0/0'
          : '';
  const iconCls = 'text-pn-muted shrink-0 ms-0.5 me-0.5';
  const closeLabel = mode === 'replace'
    ? t('find.closeReplaceTitle', { keys: keyText('findReplace') })
    : t('find.closeTitle', { keys: keyText('find') });

  return (
    <div className={`pointer-events-auto mt-1 me-2 flex flex-col gap-1 rounded-lg border border-divider bg-surface-1 shadow-lg px-1.5 py-1 ${
      mode === 'replace' ? 'ms-2 flex-1 min-w-0 sm:flex-none sm:w-[22rem]' : ''
    }`}>
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
          className={mode === 'replace' ? BAR_INPUT : 'w-36 sm:w-44 bg-transparent text-sm text-pn placeholder:text-pn-muted outline-none px-1'}
        />
        {mode === 'replace' && (
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
        )}
        <MatchNav count={count} noHits={noHits} canStep={total > 0} onStep={go} />
        <div className="w-px h-5 bg-divider mx-0.5 shrink-0" aria-hidden="true" />
        <HoverLabel label={closeLabel} position="below-end">
          <button
            type="button"
            onMouseDown={(e) => e.preventDefault()}
            onClick={onClose}
            aria-label={mode === 'replace' ? t('find.closeReplace') : t('find.close')}
            className={BAR_BTN}
          >
            <X size={15} />
          </button>
        </HoverLabel>
      </div>
      {mode === 'replace' && (
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
          <HoverLabel label={t('find.replaceTitle')} position="below">
            <button
              type="button"
              onMouseDown={(e) => e.preventDefault()}
              onClick={replaceOne}
              disabled={total === 0}
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
              disabled={total === 0}
              className={TEXT_BTN}
            >
              {t('find.replaceAll')}
            </button>
          </HoverLabel>
        </div>
      )}
    </div>
  );
}
