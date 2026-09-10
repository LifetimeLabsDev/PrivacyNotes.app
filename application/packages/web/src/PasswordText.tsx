import { useEffect, useRef, type ChangeEvent } from 'react';

/* ────────────────────────────────────────────────────────────────
 * Painting a password by character class.
 *
 * A password is read one glyph at a time, and a single text colour leaves
 * the pairs a face cannot separate: the digit 1 against a lowercase l, the
 * capital I against both, a symbol against a letter. Colour carries the
 * class the glyph is ambiguous about, so somebody typing a password into
 * another device can check what they read (issue #315).
 *
 * The glyph itself still says which character it is, so nothing here is the
 * only carrier of anything - a reader who sees no colour at all loses no
 * information.
 * ──────────────────────────────────────────────────────────────── */

export type PasswordCharClass = 'upper' | 'digit' | 'symbol' | 'plain';

const DIGIT = /\p{Nd}/u;
const UPPER = /\p{Lu}|\p{Lt}/u;
const LETTER = /\p{L}|\p{M}/u;

/**
 * A letter whose script has no case of its own - Chinese, Japanese, Korean,
 * Thai, Hebrew - is plain text, not a symbol. Without that branch a
 * passphrase in one of those scripts paints end to end in the symbol colour.
 */
export function passwordCharClass(ch: string): PasswordCharClass {
  if (DIGIT.test(ch)) return 'digit';
  if (UPPER.test(ch)) return 'upper';
  if (LETTER.test(ch)) return 'plain';
  return 'symbol';
}

/**
 * Lowercase keeps the surrounding text colour. It is the bulk of a password
 * and the strongest contrast the page has, so spending a colour on it would
 * dim most of the characters to mark the one class that needs no mark:
 * nothing else on the line looks like a lowercase letter.
 *
 * The light shades sit a step or two darker than the usual pairing, because
 * the palest surface any theme paints has to clear 4.5 to 1 against all
 * three: these are small monospace glyphs somebody is already squinting at.
 * Spec: ops/docs/ui-patterns.md (a revealed password paints its own value)
 */
const CLASS_COLOR: Record<PasswordCharClass, string> = {
  plain: '',
  upper: 'text-purple-700 dark:text-purple-400',
  digit: 'text-blue-700 dark:text-blue-400',
  symbol: 'text-orange-800 dark:text-orange-400',
};

/** A password string, each character painted by its class. */
export function PasswordText({ value }: { value: string }) {
  // Array.from walks code points, so an astral character stays one span
  // rather than splitting into two halves of a surrogate pair.
  return (
    <>
      {Array.from(value).map((ch, i) => (
        <span key={i} className={CLASS_COLOR[passwordCharClass(ch)]}>{ch}</span>
      ))}
    </>
  );
}

/* ────────────────────────────────────────────────────────────────
 * PasswordField - an editable field that paints its own value.
 *
 * A native input paints all of its text in one colour, so the classes
 * cannot be told apart inside it. The input keeps the value, the caret, the
 * selection and the platform mask; while the value is shown its own text
 * goes transparent and a copy above it draws the characters in colour.
 *
 * Spec: ops/docs/ui-patterns.md (a revealed password paints its own value)
 * ──────────────────────────────────────────────────────────────── */

/** The caret is spelled out because `caret-color` follows `color`, and the
 *  selection colour because a browser paints selected text in the highlight
 *  foreground, which would show a second copy of the glyphs underneath. */
const PAINTED_OVER = {
  color: 'transparent',
  caretColor: 'rgb(var(--pn-text))',
} as const;

/** The copy wears the field's own class string, so the two layers can never
 *  disagree about padding, face, size or border width. What it must not
 *  inherit is the paint: an inline value beats any class, whatever order
 *  the utilities land in. */
const COPY_PAINT = { borderColor: 'transparent', background: 'transparent' } as const;

export function PasswordField({
  value,
  onChange,
  revealed,
  disabled,
  placeholder,
  fieldClass,
}: {
  value: string;
  onChange: (e: ChangeEvent<HTMLInputElement>) => void;
  revealed: boolean;
  disabled?: boolean;
  placeholder?: string;
  /** The form's own input styling: border, background, padding, focus ring. */
  fieldClass: string;
}) {
  const inputRef = useRef<HTMLInputElement>(null);
  const copyRef = useRef<HTMLDivElement>(null);
  const box = `${fieldClass} font-mono`;

  // A long value scrolls inside the input, and the copy has to follow it.
  const followScroll = () => {
    const input = inputRef.current;
    const copy = copyRef.current;
    if (input && copy) copy.scrollLeft = input.scrollLeft;
  };
  useEffect(followScroll, [value, revealed]);

  return (
    <div className="relative flex-1 min-w-0">
      <input
        ref={inputRef}
        type={revealed ? 'text' : 'password'}
        dir="ltr" /* rtl-ok: a secret is a code, never reordered */
        value={value}
        onChange={onChange}
        onScroll={followScroll}
        placeholder={placeholder}
        disabled={disabled}
        autoComplete="off"
        spellCheck={false}
        style={revealed ? PAINTED_OVER : undefined}
        className={`${box} ${revealed ? 'selection:text-transparent' : ''}`}
      />
      {revealed && (
        <div
          aria-hidden="true"
          dir="ltr" /* rtl-ok: a secret is a code, never reordered */
          style={COPY_PAINT}
          className={`${box} pointer-events-none absolute inset-0 ${disabled ? 'opacity-60' : ''}`}
        >
          {/* The text sits in a block the size of the content box, and that
              block is what scrolls: `overflow-hidden` clips at the padding
              edge, so text on the outer box would paint across the field's
              padding, where the input's own text never goes. */}
          <div ref={copyRef} className="h-full overflow-hidden whitespace-pre">
            <PasswordText value={value} />
          </div>
        </div>
      )}
    </div>
  );
}
