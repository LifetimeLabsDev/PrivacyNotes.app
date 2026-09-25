/**
 * Pick a picture that is already in Files and show it in the note (issue
 * #330). Nothing is uploaded or copied: the note points at the stored file,
 * so the picture costs no extra storage however many notes show it.
 *
 * The list is the Files pillar's pictures, newest note first, one entry per
 * stored file, and never a picture from a PIN-protected note that is still
 * locked (NotesView builds it).
 *
 * Spec: ops/docs/ui-patterns.md (section 107, the file card and the picker)
 */
import { useEffect, useMemo, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { X } from './icons';
import { useEscapeToClose } from './useEscapeToClose';
import { ListSearchInput } from './ListSearchInput';
import { LazyPicture } from './LazyPicture';
import { isSoftKeyboardDevice } from './softKeyboard';
import { textMatcher } from './textMatch';
import type { MediaRef } from './mediaRefs';

export function PicturePicker({ items, onPick, onClose }: {
  items: MediaRef[];
  onPick: (ref: MediaRef) => void;
  onClose: () => void;
}) {
  const { t } = useTranslation('media');
  const [query, setQuery] = useState('');
  const searchRef = useRef<HTMLInputElement>(null);
  const downOnBackdrop = useRef(false);
  useEscapeToClose(onClose);

  // Straight into the search box where a keyboard is already out; a phone
  // would otherwise raise its keyboard over the pictures on open.
  useEffect(() => {
    if (!isSoftKeyboardDevice()) searchRef.current?.focus({ preventScroll: true });
  }, []);

  const shown = useMemo(() => {
    const q = query.trim();
    if (!q) return items;
    const match = textMatcher(q);
    return items.filter((it) => match(it.name));
  }, [items, query]);

  return createPortal(
    <div
      className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 z-50"
      onPointerDown={(e) => { downOnBackdrop.current = e.target === e.currentTarget; }}
      onClick={(e) => { if (downOnBackdrop.current && e.target === e.currentTarget) onClose(); }}
      role="dialog"
      aria-modal="true"
      aria-label={t('picker.title')}
    >
      <div className="bg-surface-2 border border-divider text-pn rounded-lg w-full max-w-lg flex flex-col max-h-[calc(100dvh-2rem)]">
        <div className="flex items-center justify-between gap-3 px-5 pt-4 pb-3">
          <h2 className="text-lg font-semibold">{t('picker.title')}</h2>
          <button
            type="button"
            onClick={onClose}
            className="shrink-0 text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
            aria-label={t('common:actions.close')}
          >
            <X size={18} />
          </button>
        </div>
        {items.length > 0 && (
          <div className="px-5 pb-3">
            <ListSearchInput
              value={query}
              onChange={setQuery}
              placeholder={t('picker.search')}
              inputRef={searchRef}
            />
          </div>
        )}
        <div className="flex-1 min-h-0 overflow-y-auto px-5 pb-3">
          {items.length === 0 ? (
            <p className="py-10 text-sm text-center text-neutral-500 dark:text-neutral-400">{t('picker.empty')}</p>
          ) : shown.length === 0 ? (
            <p className="py-10 text-sm text-center text-neutral-500 dark:text-neutral-400">{t('picker.noMatch')}</p>
          ) : (
            <div className="grid grid-cols-3 sm:grid-cols-4 gap-2">
              {shown.map((it) => (
                <button
                  key={it.src}
                  type="button"
                  onClick={() => onPick(it)}
                  aria-label={it.name}
                  className="relative block aspect-square rounded-lg overflow-hidden border border-divider hover:border-accent focus-visible:outline-2 focus-visible:outline-accent transition"
                >
                  <LazyPicture src={it.src} />
                  <span
                    className="absolute inset-x-0 bottom-0 block px-1.5 pb-1 pt-4 bg-gradient-to-t from-black/80 to-transparent text-[11px] text-white text-start truncate"
                    dir="auto"
                  >
                    {it.name}
                  </span>
                </button>
              ))}
            </div>
          )}
        </div>
        {items.length > 0 && (
          <p className="px-5 py-3 border-t border-divider text-xs text-neutral-500 dark:text-neutral-400">
            {t('picker.noCopy')}
          </p>
        )}
      </div>
    </div>,
    document.body,
  );
}
