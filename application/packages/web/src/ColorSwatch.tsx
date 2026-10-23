import type { MouseEvent, PointerEvent } from 'react';
import { HoverLabel, type positionClasses } from './HoverLabel';
import { Prohibit } from './icons';
import { LOOK_COLORS, type LookColor } from './itemStyles';

/**
 * One round color swatch: the one the editor's text and highlight popovers
 * and the folder and tag look picker all draw, so a color reads the same
 * wherever it is chosen.
 *
 * The look lives here and the events stay with the caller. The editor picks
 * on pointer-down, with the default prevented, so its text selection survives
 * the click. The look picker picks on a click, so a finger that starts a
 * scroll in the phone sheet never picks a color.
 * Spec: ops/docs/archive/folder-tag-icons.md (section 4.3)
 */
export function ColorSwatch({
  label,
  background,
  selected,
  inherited = false,
  none = false,
  className = '',
  labelPosition = 'above',
  onPointerDown,
  onClick,
}: {
  label: string;
  /** Any CSS background. Left out for the "no color" swatch. */
  background?: string;
  selected: boolean;
  /** The color an item takes from elsewhere, not its own pick: a dashed
   *  ring where a pick has a solid one. */
  inherited?: boolean;
  /** The "no color" swatch: a struck circle instead of a fill. */
  none?: boolean;
  className?: string;
  /** Where the name shows on hover. Below, where the space above is the
   *  clipped top of a scrolling box. */
  labelPosition?: keyof typeof positionClasses;
  onPointerDown?: (e: PointerEvent<HTMLButtonElement>) => void;
  onClick?: (e: MouseEvent<HTMLButtonElement>) => void;
}) {
  return (
    <HoverLabel label={label} position={labelPosition}>
      <button
        type="button"
        aria-label={label}
        aria-pressed={selected}
        onPointerDown={onPointerDown}
        onClick={onClick}
        className={`w-6 h-6 rounded-full transition [@media(hover:hover)]:hover:scale-110 ${
          none
            ? 'flex items-center justify-center text-pn-muted border border-divider'
            : 'block'
        } ${
          selected
            ? 'ring-2 ring-offset-1 ring-accent ring-offset-surface-1'
            : inherited
              ? 'outline-2 outline-dashed outline-offset-2 outline-pn-muted'
              : none
                ? ''
                : 'border border-divider'
        } ${className}`}
        style={background ? { background } : undefined}
      >
        {none && <Prohibit size={13} />}
      </button>
    </HoverLabel>
  );
}

/**
 * The one color row: "no color" first, then every palette color through the
 * theme's `--pn-label-<key>-ink` token, finger-sized on a touch screen. The
 * note color, the folder and tag looks and the Kanban columns all draw it,
 * so a color choice looks and behaves the same everywhere.
 * Spec: ops/docs/archive/folder-tag-icons.md (section 4.3)
 */
export function ColorSwatchRow({
  selected,
  inherited = null,
  noneLabel,
  colorLabel,
  labelSide = 'above',
  onPick,
}: {
  /** The picked color, `none` for the "no color" swatch, null for neither. */
  selected: LookColor | 'none' | null;
  /** A color taken from elsewhere: a dashed ring. */
  inherited?: LookColor | null;
  noneLabel: string;
  /** The name of a palette color, for its tooltip and screen readers. */
  colorLabel: (color: LookColor) => string;
  labelSide?: 'above' | 'below';
  onPick: (color: LookColor | null) => void;
}) {
  return (
    <div className="flex flex-wrap gap-1 [@media(hover:none)]:gap-0.5">
      <ColorSwatch
        label={noneLabel}
        none
        // The first swatch sits at the start edge, where a centered tip
        // would hang out of its panel.
        labelPosition={labelSide === 'above' ? 'above-start' : 'below-start'}
        selected={selected === 'none'}
        className={TOUCH_SWATCH}
        onClick={() => onPick(null)}
      />
      {LOOK_COLORS.map((c) => (
        <ColorSwatch
          key={c}
          label={colorLabel(c)}
          background={`var(--pn-label-${c}-ink)`}
          selected={selected === c}
          inherited={selected !== c && inherited === c}
          className={TOUCH_SWATCH}
          labelPosition={labelSide}
          onClick={() => onPick(c)}
        />
      ))}
    </div>
  );
}

const TOUCH_SWATCH = '[@media(hover:none)]:w-11 [@media(hover:none)]:h-11';
