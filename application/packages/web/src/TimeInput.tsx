import { useEffect, useRef, useState, type ChangeEvent, type KeyboardEvent } from 'react';
import { isTime, parseTimeText } from './schedule';
import { timeLabel } from './JournalCalendar';
import { toLocalIso } from './intlFormat';
import { isTouchOnly } from './touchOnly';

/** What a native time input's value commits: an `HH:MM` time, `null` for a
 *  cleared field that may be cleared, or `undefined` for nothing to commit. */
export function nativeTimeCommit(raw: string, clearable: boolean): string | null | undefined {
  if (raw === '') return clearable ? null : undefined;
  return isTime(raw) ? raw : undefined;
}

/**
 * A time field. A phone or tablet gets the device's own time picker, which
 * reads and writes the stored `HH:MM` and shows the device's 12 or 24 hour
 * clock. A pointer device gets a text field that shows the time as the clock
 * setting writes it and takes it as typed ("15:00", "3pm"). Both commit on
 * Enter, on the picker's change, or when the field loses focus.
 * Spec: ops/issues/0550.md (Spec)
 */
export function TimeInput({ value, onCommit, label, className, day, clearable = false }: {
  value: string | undefined;
  onCommit: (time: string | null) => void;
  label: string;
  className: string;
  /** The day the time falls on, for the label of a day with a clock change. */
  day?: string;
  /** An emptied field commits `null`; otherwise it keeps the old time. */
  clearable?: boolean;
}) {
  const [draft, setDraft] = useState<string | null>(null);
  const native = isTouchOnly();
  const ref = useRef<HTMLInputElement>(null);
  const commitRef = useRef<(raw: string | null) => void>(() => {});

  const commitRaw = (raw: string | null) => {
    if (raw === null) return;
    setDraft(null);
    const next = native
      ? nativeTimeCommit(raw, clearable)
      : raw.trim() === '' ? (clearable ? null : undefined) : parseTimeText(raw) ?? undefined;
    if (next !== undefined && next !== (value ?? null)) onCommit(next);
  };
  const commit = () => commitRaw(draft);
  commitRef.current = commitRaw;

  // The picker's own change event fires once a time is picked; React's
  // onChange follows every wheel step on iOS, which is too early to save.
  // This listener runs before React's, so it reads the value off the field.
  useEffect(() => {
    const el = ref.current;
    if (!native || !el) return;
    const onChange = () => commitRef.current(el.value);
    el.addEventListener('change', onChange);
    return () => el.removeEventListener('change', onChange);
  }, [native]);

  // Safari's Reset puts back the field's default value, which React keeps
  // equal to the current time; without it, Reset empties a clearable field.
  useEffect(() => {
    if (native && clearable) ref.current?.removeAttribute('value');
  });

  const shared = {
    ref,
    'aria-label': label,
    onChange: (e: ChangeEvent<HTMLInputElement>) => setDraft(e.target.value),
    onBlur: commit,
    onKeyDown: (e: KeyboardEvent<HTMLInputElement>) => {
      if (e.key === 'Enter') { e.preventDefault(); commit(); }
      e.stopPropagation();
    },
    className,
  };

  // A tap on the field opens the picker, so Chrome's clock glyph inside the
  // box only takes room from the time.
  if (native) return <input type="time" value={draft ?? value ?? ''} {...shared} className={`${className} min-w-[6.5rem] [&::-webkit-calendar-picker-indicator]:hidden`} />;
  return (
    <input
      type="text"
      inputMode="text"
      value={draft ?? (value ? timeLabel(day ?? toLocalIso(new Date()), value) : '')}
      placeholder="--:--"
      onFocus={(e) => e.currentTarget.select()}
      {...shared}
    />
  );
}
