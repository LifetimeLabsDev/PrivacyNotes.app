import { forwardRef, useEffect, useImperativeHandle, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Eye, EyeSlash } from './icons';
import { isImeComposing } from './imeComposing';
import { PinInput, type PinInputHandle } from './PinInput';
import type { SecretKind } from './secretKind';

type Props = {
  value: string;
  onChange: (value: string) => void;
  /** Enter, or the caller's button. Never fired by the field on its own. */
  onSubmit?: (value: string) => void;
  autoFocus?: boolean;
  disabled?: boolean;
  ariaLabel?: string;
  /** The settings pane size; the lock screen and the note gate keep the full one. */
  compact?: boolean;
};

/**
 * The same mask as the PIN boxes (PinInput.tsx, issue #254): the field never
 * paints a character, so the Android reveal of the last key typed is drawn in
 * a transparent colour, and the bullets over it are ours. Inline for the same
 * reason as there; `tests/passcode.test.ts` reads the file for it.
 */
const HIDDEN_TEXT = { color: 'transparent', caretColor: 'transparent' } as const;

/**
 * One masked field for the longer app lock passcode, with a show button. The
 * choice to show is not remembered: every field starts masked.
 */
export const PasscodeInput = forwardRef<PinInputHandle, Props>(function PasscodeInput(
  { value, onChange, onSubmit, autoFocus = false, disabled = false, ariaLabel, compact = false },
  ref,
) {
  const { t } = useTranslation('security');
  const [shown, setShown] = useState(false);
  const mask = !shown;
  const input = useRef<HTMLInputElement>(null);

  useImperativeHandle(ref, () => ({
    focus: () => input.current?.focus(),
    // A frame, as in PinInput: the caller clears from an async submit whose
    // batch also re-enables the field, and a disabled field takes no focus.
    clear: () => {
      requestAnimationFrame(() => input.current?.focus());
    },
  }));

  useEffect(() => {
    if (autoFocus) input.current?.focus();
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  const textSize = compact ? 'text-base' : 'text-lg';

  return (
    // rtl-ok: the masked text has no reading direction, and the bullets must sit where the field draws its text
    <div dir="ltr" className={`relative ${disabled ? 'opacity-40' : ''}`}>
      <input
        ref={input}
        type={mask ? 'password' : 'text'}
        value={value}
        onChange={(e) => onChange(e.target.value)}
        onKeyDown={(e) => {
          // An Enter that commits an input method's composition (Japanese,
          // Chinese, Korean) is not a submit.
          if (isImeComposing(e)) return;
          if (e.key === 'Enter') {
            e.preventDefault();
            onSubmit?.(value);
          }
        }}
        autoComplete="off"
        autoCorrect="off"
        autoCapitalize="off"
        spellCheck={false}
        enterKeyHint="go"
        disabled={disabled}
        style={mask ? HIDDEN_TEXT : undefined}
        aria-label={ariaLabel ?? t('passcodeInput.ariaLabel')}
        className={`w-full rounded-md bg-track text-pn border border-divider focus:border-accent dark:focus:border-accent font-mono focus:outline-none disabled:cursor-not-allowed ps-3 pe-11 ${compact ? 'h-12' : 'h-14'} ${textSize}`}
      />
      {mask && value && (
        // The bullets the field no longer draws, one per character.
        <span
          aria-hidden="true"
          className={`pointer-events-none absolute inset-y-0 start-0 end-11 flex items-center ps-3 overflow-hidden whitespace-nowrap text-pn font-mono ${textSize}`}
        >
          {'•'.repeat([...value].length)}
        </span>
      )}
      <button
        type="button"
        onClick={() => setShown((s) => !s)}
        disabled={disabled}
        aria-pressed={shown}
        aria-label={shown ? t('passcodeInput.hide') : t('passcodeInput.show')}
        title={shown ? t('passcodeInput.hide') : t('passcodeInput.show')}
        className="absolute inset-y-0 end-0 w-11 flex items-center justify-center rounded-e-md text-pn-muted hover:text-pn focus:outline-none focus-visible:text-accent disabled:cursor-not-allowed"
      >
        {shown ? <EyeSlash size={18} /> : <Eye size={18} />}
      </button>
    </div>
  );
});

/**
 * The PIN boxes or the passcode field, by the kind of secret the account
 * holds. A surface swaps its PinInput for this and keeps its layout. For a
 * PIN, `onComplete` fires when the fourth digit lands; for a passcode, on
 * Enter.
 */
export const SecretInput = forwardRef<PinInputHandle, Omit<Props, 'onSubmit'> & {
  kind: SecretKind;
  onComplete?: (value: string) => void;
}>(function SecretInput({ kind, onComplete, ...rest }, ref) {
  return kind === 'passcode'
    ? <PasscodeInput ref={ref} {...rest} onSubmit={onComplete} />
    : <PinInput ref={ref} {...rest} onComplete={onComplete} />;
});
