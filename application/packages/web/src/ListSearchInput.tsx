import { useContext, useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Terminal, X } from './icons';
import { HoverLabel } from './HoverLabel';
import { keyText } from './shortcutMatch';
import { COMMAND_PREFIX, CommandPaletteContext } from './commandPalette';

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
 *
 * The app's list search (the field `CommandPaletteContext` names) is a door
 * into command mode: a ">" typed into the empty field, or its commands
 * button, opens the quick switcher with ">" typed, and the field stays as it
 * was (commandPalette.ts).
 */

const SEARCH_EMIT_DEBOUNCE_MS = 150;

export function ListSearchInput({
  value,
  onChange,
  placeholder,
  inputRef,
  tabIndex,
  onKeyDown,
  ariaLabel,
}: {
  value: string;
  onChange: (v: string) => void;
  placeholder: string;
  inputRef?: React.RefObject<HTMLInputElement | null> | undefined;
  tabIndex?: number | undefined;
  onKeyDown?: (e: React.KeyboardEvent<HTMLInputElement>) => void;
  ariaLabel?: string;
}) {
  const { t } = useTranslation('common');
  const [draft, setDraft] = useState(value);
  const palette = useContext(CommandPaletteContext);
  const commandsHere = !!palette && !!inputRef && inputRef === palette.searchInputRef;
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

  const openCommands = () => {
    inputRef?.current?.blur();
    palette!.openCommands();
  };

  const handleChange = (v: string) => {
    if (commandsHere && !draft && v === COMMAND_PREFIX) return openCommands();
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
        data-search-field=""
        tabIndex={tabIndex}
        value={draft}
        onChange={(e) => handleChange(e.target.value)}
        placeholder={placeholder}
        aria-label={ariaLabel}
        onKeyDown={onKeyDown}
        enterKeyHint="search"
        className={`pn-search-well w-full h-10 rounded-md bg-surface-2 border border-divider ps-3 ${
          draft || commandsHere ? 'pe-10' : 'pe-3'
        } text-[15px] focus:outline-none focus:border-accent placeholder:text-pn-muted`}
      />
      {/* The way into command mode without the ">" key. It shows only on an
          empty field: once there is text, the clear button takes its place.
          The position sits on a wrapper because HoverLabel's own wrapper is
          `relative`, which would win over an `absolute` passed to it. The
          wrapper centres with inset and flex, never a transform: a transform
          makes a stacking context, and the list rows below then paint over
          the tip.
          Spec: ops/docs/archive/keyboard-shortcuts.md (decision D5) */}
      {!draft && commandsHere && (
        <span className="absolute end-1 inset-y-0 flex items-center">
          <HoverLabel label={t('palette.open')} keys={keyText('commandMode')} position="below-end" className="flex">
            <button
              type="button"
              onMouseDown={(e) => e.preventDefault()}
              onClick={openCommands}
              aria-label={t('palette.open')}
              className="inline-flex items-center justify-center w-8 h-8 rounded-md text-pn-muted hover:text-accent hover:bg-pn/5 transition"
            >
              <Terminal size={15} aria-hidden="true" />
            </button>
          </HoverLabel>
        </span>
      )}
      {draft && (
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={clear}
          aria-label={t('actions.clearSearch')}
          className="absolute end-1 top-1/2 -translate-y-1/2 inline-flex items-center justify-center w-8 h-8 rounded-md text-pn-muted hover:text-pn hover:bg-pn/5 transition"
        >
          <X size={14} />
        </button>
      )}
    </div>
  );
}
