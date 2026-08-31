import {
  forwardRef,
  useEffect,
  useImperativeHandle,
  useRef,
  type ChangeEvent,
  type ClipboardEvent,
  type KeyboardEvent,
} from 'react';
import { useTranslation } from 'react-i18next';

export type PinInputHandle = {
  focus: () => void;
  clear: () => void;
};

type Props = {
  value: string;
  onChange: (value: string) => void;
  /** Called when all 4 digits are filled. Receives the full value. */
  onComplete?: (value: string) => void;
  /** Auto-focus the first box on mount. */
  autoFocus?: boolean;
  disabled?: boolean;
  ariaLabel?: string;
};

const LENGTH = 4;

/**
 * The field holds the digit and never paints it. The bullet beside each box
 * is ours instead.
 *
 * A password field is masked by the browser, but Android draws the character
 * first and masks it a second or two later, which is long enough for the
 * person behind you to read the whole PIN one key at a time (issue #254).
 * That reveal is drawn in the field's text colour, so a transparent one
 * leaves nothing to see, on every platform.
 *
 * An inline style rather than a utility class, because this is the only thing
 * standing between a shoulder and the PIN: a class list gets rewritten in
 * passing, and the loss would be invisible on a desktop browser, which masks
 * the character either way. `tests/pinInputMask.test.tsx` watches it too.
 *
 * The boxes stay `type="password"` under the transparent text. If this style
 * is ever lost the app is back to the platform mask and this bug, rather than
 * a PIN in plain sight.
 */
const HIDDEN_TEXT = { color: 'transparent', caretColor: 'transparent' } as const;

/**
 * Four separate boxes for a 4-digit PIN. Handles auto-advance, backspace,
 * arrow navigation, paste, and iOS one-time-code autofill.
 */
export const PinInput = forwardRef<PinInputHandle, Props>(function PinInput(
  {
    value,
    onChange,
    onComplete,
    autoFocus = false,
    disabled = false,
    ariaLabel,
  },
  ref,
) {
  const { t } = useTranslation('security');
  const groupLabel = ariaLabel ?? t('pinInput.ariaLabel');
  const inputs = useRef<Array<HTMLInputElement | null>>([]);

  useImperativeHandle(ref, () => ({
    focus: () => inputs.current[0]?.focus(),
    // Callers are expected to set their `value` state to '' before invoking
    // `clear()` - `clear()` only refocuses the first box. Notifying the
    // parent via `onChange('')` here would race with error-state setters
    // (e.g. `setErr('Incorrect PIN')` followed by `clear()`) because the
    // parent's onChange typically does `setErr(null)` to clear stale
    // messages as the user types. The empty value re-renders fine through
    // the parent's already-set state.
    clear: () => {
      // A frame, not a microtask. Callers clear from an async submit, where the
      // same batch also drops the `busy` flag that disables these boxes - and
      // focusing a disabled input does nothing at all. A microtask can run
      // before React commits that flag, which left a wrong PIN needing a click
      // before the next attempt. A frame always lands after the commit.
      requestAnimationFrame(() => inputs.current[0]?.focus());
    },
  }));

  useEffect(() => {
    if (autoFocus) inputs.current[0]?.focus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const digits = Array.from({ length: LENGTH }, (_, i) => value[i] ?? '');

  function commit(next: string[], focusIndex: number) {
    const joined = next.join('').slice(0, LENGTH);
    onChange(joined);
    inputs.current[Math.min(Math.max(focusIndex, 0), LENGTH - 1)]?.focus();
    if (joined.length === LENGTH) onComplete?.(joined);
  }

  function handleChange(index: number, e: ChangeEvent<HTMLInputElement>) {
    const raw = e.target.value.replace(/\D/g, '');
    if (!raw) {
      const next = digits.slice();
      next[index] = '';
      onChange(next.join(''));
      return;
    }

    const next = digits.slice();
    if (raw.length === 1) {
      next[index] = raw;
      commit(next, index + 1);
      return;
    }

    // Multi-digit: user typed fast, autofilled one-time-code, or pasted.
    for (let i = 0; i < raw.length && index + i < LENGTH; i++) {
      next[index + i] = raw[i]!;
    }
    commit(next, index + raw.length);
  }

  function handleKeyDown(index: number, e: KeyboardEvent<HTMLInputElement>) {
    if (e.key === 'Backspace') {
      if (digits[index]) {
        const next = digits.slice();
        next[index] = '';
        onChange(next.join(''));
      } else if (index > 0) {
        e.preventDefault();
        const next = digits.slice();
        next[index - 1] = '';
        onChange(next.join(''));
        inputs.current[index - 1]?.focus();
      }
    } else if (e.key === 'ArrowLeft' && index > 0) {
      e.preventDefault();
      inputs.current[index - 1]?.focus();
    } else if (e.key === 'ArrowRight' && index < LENGTH - 1) {
      e.preventDefault();
      inputs.current[index + 1]?.focus();
    }
  }

  function handlePaste(index: number, e: ClipboardEvent<HTMLInputElement>) {
    const raw = e.clipboardData
      .getData('text')
      .replace(/\D/g, '')
      .slice(0, LENGTH - index);
    if (!raw) return;
    e.preventDefault();
    const next = digits.slice();
    for (let i = 0; i < raw.length; i++) {
      next[index + i] = raw[i]!;
    }
    commit(next, index + raw.length);
  }

  return (
    // rtl-ok: PIN digit sequence stays LTR so ArrowLeft/ArrowRight focus movement matches spatial order
    <div
      role="group"
      aria-label={groupLabel}
      dir="ltr"
      className="flex gap-3 justify-center"
    >
      {digits.map((d, i) => (
        <div
          key={i}
          className={`relative w-14 h-16 sm:w-16 ${disabled ? 'opacity-40' : ''}`}
        >
          <input
            ref={(el) => {
              inputs.current[i] = el;
            }}
            type="password"
            inputMode="numeric"
            pattern="[0-9]*"
            autoComplete={i === 0 ? 'one-time-code' : 'off'}
            maxLength={1}
            value={d}
            onChange={(e) => handleChange(i, e)}
            onKeyDown={(e) => handleKeyDown(i, e)}
            onPaste={(e) => handlePaste(i, e)}
            onFocus={(e) => e.currentTarget.select()}
            disabled={disabled}
            style={HIDDEN_TEXT}
            aria-label={t('pinInput.digitAriaLabel', { index: i + 1 })}
            className="w-full h-full rounded-md bg-track border border-divider focus:border-accent dark:focus:border-accent text-center text-2xl font-mono focus:outline-none disabled:cursor-not-allowed"
          />
          {d && (
            // The bullet the field no longer draws. Same glyph, size and
            // family the browser used, so the boxes look untouched.
            <span
              aria-hidden="true"
              className="pointer-events-none absolute inset-0 flex items-center justify-center text-pn text-2xl font-mono"
            >
              &bull;
            </span>
          )}
        </div>
      ))}
    </div>
  );
});
