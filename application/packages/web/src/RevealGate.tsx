import type { Icon } from './icons';
import { Eye } from './icons';

/**
 * The ask-before-you-see banner: a dashed card carrying an icon, a
 * heading, one body line, a reveal button and a footnote.
 *
 * Two callers, two tones:
 *  - BurnNote (`danger`): revealing deletes the note from the server.
 *  - PhraseView (`warning`): the words open every device, so the
 *    settings tab keeps them covered until asked. Nothing is destroyed
 *    here, and red would say otherwise.
 *
 * `compact` is the settings-modal size. The burn page is a wide card on
 * an otherwise empty page; the phrase gate sits inside a max-w-md modal
 * where p-8 and a 48px glyph leave no room for the words underneath.
 */

/**
 * Card, glyph and button per tone. The button pairs are measured, not
 * picked by eye: white on amber-500 is 2.15:1 and white on red-500 is
 * 3.76:1, so neither shipped colour passed. Amber is a light hue and
 * takes dark text (amber-950, 6.97:1); red is a dark hue and takes
 * white, one stop down at red-600 (4.83:1) - which is also the app's
 * existing danger button in ConfirmModal.
 */
const TONES = {
  danger: {
    card: 'border-red-300 dark:border-red-800 bg-red-50 dark:bg-red-950/30',
    glyph: 'text-red-500 dark:text-red-400',
    button: 'bg-red-600 hover:bg-red-700 text-white shadow-red-600/20',
  },
  warning: {
    card: 'border-amber-300 dark:border-amber-800 bg-amber-50 dark:bg-amber-950/30',
    glyph: 'text-amber-500 dark:text-amber-400',
    button: 'bg-amber-500 hover:bg-amber-600 text-amber-950 shadow-amber-500/20',
  },
} as const;

export function RevealGate({
  tone,
  glyph: Glyph,
  heading,
  body,
  actionLabel,
  footnote,
  onReveal,
  compact = false,
}: {
  tone: 'danger' | 'warning';
  glyph: Icon;
  heading: string;
  body: string;
  actionLabel: string;
  footnote: string;
  onReveal: () => void;
  compact?: boolean;
}) {
  const style = TONES[tone];

  return (
    <div
      className={`rounded-lg border-2 border-dashed text-center ${
        compact ? 'p-6 space-y-4' : 'p-8 space-y-6'
      } ${style.card}`}
    >
      <Glyph
        size={compact ? 32 : 48}
        weight="duotone"
        aria-hidden="true"
        className={`mx-auto ${style.glyph}`}
      />
      <div>
        <p className={`font-semibold text-pn ${compact ? 'text-base' : 'text-lg'}`}>
          {heading}
        </p>
        {/* text-balance: two or three short centered lines, where the
            default greedy wrap leaves a stub on the last one. */}
        <p className="text-sm text-neutral-600 dark:text-neutral-400 mt-2 text-balance">
          {body}
        </p>
      </div>
      <button
        onClick={onReveal}
        className={`inline-flex items-center gap-2 rounded-lg font-semibold transition shadow-lg ${
          compact ? 'px-4 py-2 text-sm' : 'px-6 py-3 text-base'
        } ${style.button}`}
      >
        <Eye size={compact ? 16 : 18} aria-hidden="true" />
        {actionLabel}
      </button>
      {/* dark:text-neutral-400, not -600: the tinted card is already dark,
          and -600 measured 1.6:1 against it. The footnote carries the
          consequence ("No second chances"), so it has to be readable. */}
      <p className="text-[11px] text-neutral-500 dark:text-neutral-400">
        {footnote}
      </p>
    </div>
  );
}
