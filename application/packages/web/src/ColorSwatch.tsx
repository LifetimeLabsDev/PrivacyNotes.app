import type { MouseEvent, PointerEvent } from 'react';
import { HoverLabel } from './HoverLabel';
import { Prohibit } from './icons';

/**
 * One round color swatch: the one the editor's text and highlight popovers
 * and the folder and tag look picker all draw, so a color reads the same
 * wherever it is chosen.
 *
 * The look lives here and the events stay with the caller. The editor picks
 * on pointer-down, with the default prevented, so its text selection survives
 * the click. The look picker picks on a click, so a finger that starts a
 * scroll in the phone sheet never picks a color.
 * Spec: ops/docs/plans/folder-tag-icons.md (section 4.3)
 */
export function ColorSwatch({
  label,
  background,
  selected,
  none = false,
  className = '',
  onPointerDown,
  onClick,
}: {
  label: string;
  /** Any CSS background. Left out for the "no color" swatch. */
  background?: string;
  selected: boolean;
  /** The "no color" swatch: a struck circle instead of a fill. */
  none?: boolean;
  className?: string;
  onPointerDown?: (e: PointerEvent<HTMLButtonElement>) => void;
  onClick?: (e: MouseEvent<HTMLButtonElement>) => void;
}) {
  return (
    <HoverLabel label={label} position="above">
      <button
        type="button"
        aria-label={label}
        aria-pressed={selected}
        onPointerDown={onPointerDown}
        onClick={onClick}
        className={`w-6 h-6 rounded-full transition [@media(hover:hover)]:hover:scale-110 ${
          none
            ? 'flex items-center justify-center text-neutral-500 dark:text-neutral-400 border border-divider'
            : 'block'
        } ${
          selected ? 'ring-2 ring-offset-1 ring-accent ring-offset-surface-1' : none ? '' : 'border border-divider'
        } ${className}`}
        style={background ? { background } : undefined}
      >
        {none && <Prohibit size={13} />}
      </button>
    </HoverLabel>
  );
}
