import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { normalizeTag } from './notesRepo';
import { textMatcher } from './textMatch';
import { isImeComposing } from './imeComposing';
import { useEscapeToClose } from './useEscapeToClose';
import { MagnifyingGlass, X } from './icons';
import { TagMark } from './looks/LookGlyph';

/**
 * Pick a tag for one item or for a selection: filter the existing tags,
 * or type a new one and create it.
 *
 * It is the same centred window the folder picker uses, and deliberately
 * so. The two sit next to each other in the note menu and do the same job
 * (search a list, take one, or make a new one), so one shape serves both.
 * It was an anchored popover once, which meant the window's position had
 * to be solved against whatever opened it, and a trigger far from the
 * right edge threw it backwards across the pane.
 * Spec: ops/docs/ui-patterns.md
 */
export function TagPicker({
  allTags,
  onSelect,
  onClose,
}: {
  allTags: [string, number][];
  onSelect: (tag: string) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('shell');
  const [filter, setFilter] = useState('');

  useEscapeToClose(onClose);

  const needle = filter.replace(/^#/, '').trim();
  const filtered = useMemo(() => {
    const sorted = [...allTags].sort((a, b) => a[0].localeCompare(b[0]));
    if (!needle) return sorted;
    const match = textMatcher(needle);
    return sorted.filter(([tag]) => match(tag));
  }, [allTags, needle]);

  // The create row appears when what was typed is not already a tag.
  const normalizedFilter = normalizeTag(filter);
  const showCreate =
    normalizedFilter &&
    !allTags.some(([tag]) => tag.toLowerCase() === normalizedFilter.toLowerCase());

  function handleKeyDown(e: React.KeyboardEvent<HTMLInputElement>) {
    if (e.key !== 'Enter' || isImeComposing(e)) return;
    e.preventDefault();
    if (showCreate) onSelect(normalizedFilter);
    else if (filtered.length === 1 && filtered[0]) onSelect(filtered[0][0]);
  }

  return (
    <div
      className="fixed inset-0 bg-black/40 dark:bg-black/40 flex items-center justify-center p-4 sm:p-6 z-50"
      onClick={onClose}
    >
      <div
        role="dialog"
        aria-label={t('selectionToolbar.tag')}
        // The global chrome menu means nothing on top of a picker.
        data-no-app-menu
        className="bg-surface-2/95 backdrop-blur-xl border border-divider/80 text-pn rounded-lg max-w-sm w-full max-h-[70vh] flex flex-col overflow-hidden"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-center justify-between gap-2 px-4 pt-4 pb-2">
          <h2 className="text-[15px] font-semibold m-0">{t('selectionToolbar.tag')}</h2>
          <button
            onClick={onClose}
            aria-label={t('common:actions.close')}
            className="p-1 -m-1 rounded text-neutral-400 hover:text-neutral-700 dark:hover:text-neutral-200 transition"
          >
            <X size={16} />
          </button>
        </div>

        <div className="px-4 pb-2 shrink-0">
          <div className="flex items-center gap-2 rounded-md bg-surface-1 border border-divider px-2.5">
            <MagnifyingGlass size={14} className="shrink-0 text-neutral-400 dark:text-neutral-500" aria-hidden="true" />
            <input
              autoFocus
              value={filter}
              onChange={(e) => setFilter(e.target.value)}
              onKeyDown={handleKeyDown}
              placeholder={t('selectionToolbar.addTagPlaceholder')}
              autoComplete="off"
              className="flex-1 min-w-0 h-9 bg-transparent text-[14px] focus:outline-none placeholder:text-pn-muted"
            />
          </div>
        </div>

        <div className="flex-1 overflow-y-auto px-2 pb-2 min-h-0">
          {filtered.map(([tag, count]) => (
            <button
              key={tag}
              type="button"
              onClick={() => onSelect(tag)}
              className="w-full flex items-center gap-2 px-2.5 py-2 rounded-md text-[14px] cursor-pointer hover:bg-surface-1 transition min-h-[36px]"
            >
              <span className="text-neutral-400 dark:text-neutral-600 text-xs shrink-0 inline-flex">
                <TagMark tag={tag} size={13} />
              </span>
              <span className="truncate text-start">{tag}</span>
              <span className="ms-auto shrink-0 text-xs text-neutral-400 dark:text-neutral-600 tabular-nums">{count}</span>
            </button>
          ))}

          {filtered.length === 0 && !showCreate && (
            <div className="px-2.5 py-2 text-[14px] text-neutral-400 dark:text-neutral-600">
              {t('selectionToolbar.noTagsFound')}
            </div>
          )}

          {showCreate && (
            <button
              type="button"
              onClick={() => onSelect(normalizedFilter)}
              className="w-full flex items-center gap-2 px-2.5 py-2 rounded-md text-[14px] cursor-pointer hover:bg-surface-1 transition text-neutral-500 dark:text-neutral-400 min-h-[36px]"
            >
              <span className="text-xs shrink-0">+</span>
              <span className="truncate text-start">{t('selectionToolbar.createTag', { tag: normalizedFilter })}</span>
            </button>
          )}
        </div>
      </div>
    </div>
  );
}
