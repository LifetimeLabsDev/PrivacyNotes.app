import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { X } from './icons';

/**
 * The search input shared by the three pillar lists (notes, tasks, files).
 *
 * It exists so the three rows cannot drift apart - they were three
 * byte-identical inputs before - and so the clear button behaves the same
 * everywhere. The button only renders once there is something to clear, so
 * an empty field keeps its full width and stays visually quiet.
 *
 * The input echoes keystrokes from LOCAL state and hands the value to the
 * parent only after a short pause. Binding it straight to view-level state
 * re-rendered the whole list tree on every keystroke, which at a few
 * thousand notes costs ~270 ms per key (#130) - typing in search was the
 * single most expensive interaction in the app. External writes to `value`
 * (Escape, programmatic clears, view switches) still win: a prop value this
 * component didn't just emit is adopted into the draft immediately.
 *
 * Clearing prevents the default mousedown instead of calling focus(): the
 * input keeps whatever focus state it already had, so on desktop you can
 * keep typing and on mobile the keyboard is never forced open by a tap.
 */

const SEARCH_EMIT_DEBOUNCE_MS = 150;

export function ListSearchInput({
  value,
  onChange,
  placeholder,
  inputRef,
  tabIndex,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  inputRef?: React.RefObject<HTMLInputElement | null> | undefined;
  tabIndex?: number | undefined;
}) {
  const { t } = useTranslation('common');
  const [draft, setDraft] = useState(value);
  const lastEmittedRef = useRef(value);
  const debounceRef = useRef<number | null>(null);

  // Adopt external changes (clear button elsewhere, Escape handler,
  // restored state) - but never our own echoes bouncing back.
  useEffect(() => {
    if (value !== lastEmittedRef.current) {
      lastEmittedRef.current = value;
      setDraft(value);
    }
  }, [value]);

  useEffect(
    () => () => {
      if (debounceRef.current) window.clearTimeout(debounceRef.current);
    },
    []
  );

  const emit = (v: string) => {
    lastEmittedRef.current = v;
    onChange(v);
  };

  const handleChange = (v: string) => {
    setDraft(v);
    if (debounceRef.current) window.clearTimeout(debounceRef.current);
    debounceRef.current = window.setTimeout(() => emit(v), SEARCH_EMIT_DEBOUNCE_MS);
  };

  const clear = () => {
    if (debounceRef.current) window.clearTimeout(debounceRef.current);
    setDraft('');
    emit('');
  };

  return (
    <div className="relative flex-1 min-w-0">
      <input
        ref={inputRef}
        tabIndex={tabIndex}
        value={draft}
        onChange={(e) => handleChange(e.target.value)}
        placeholder={placeholder}
        enterKeyHint="search"
        className={`w-full h-10 rounded-md bg-surface-2 border border-divider ps-3 ${
          draft ? 'pe-10' : 'pe-3'
        } text-[15px] focus:outline-none focus:border-accent placeholder:text-pn-muted`}
      />
      {draft && (
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={clear}
          aria-label={t('actions.clearSearch')}
          className="absolute end-1 top-1/2 -translate-y-1/2 inline-flex items-center justify-center w-8 h-8 rounded-md text-pn-muted hover:text-pn hover:bg-neutral-200/70 dark:hover:bg-neutral-800 transition"
        >
          <X size={14} />
        </button>
      )}
    </div>
  );
}
