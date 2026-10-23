import { useRef, type CSSProperties, type KeyboardEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { moodColor } from './moodColors';
import { moodAnchor, moodInk } from './moodMark';

/**
 * One row of numbered tiles for every scale tracker: the mood's 1 to 10, a
 * custom 0 to 10, caffeine's 0 to 5. Every tile is a tap target of the same
 * weight, the columns share the width they are given, so the row fits a
 * phone's list and a wide grid alike, and it is always one row. Arrow keys
 * move along it; Enter or Space picks.
 *
 * `tone` is the one difference between the mood and the other scales: the
 * mood paints every tile in its band's color (`moodColor`, the five colors
 * the month grid paints), the others stay in the accent until picked. A
 * parent may set --pn-tile-shown to paint the unpicked mood tiles one neutral
 * color instead (the check-in card at rest), and unset it to bring the bands
 * back.
 *
 * Under a mouse the row is a meter: the tile under the pointer and every tile
 * before it light up (`pn-scale-row` in index.css). It changes color only,
 * so a row squeezed into a narrow list never pushes a tile into its neighbor.
 * Spec: ops/docs/archive/ui-patterns.md section 141
 */
export function ScaleTiles({ min, max, value, onPick, label, tone = 'accent', ends, nameOf, className = '' }: {
  min: number;
  max: number;
  value: number | null | undefined;
  onPick: (n: number) => void;
  label: string;
  tone?: 'mood' | 'accent';
  /** The words under the two ends of the row. */
  ends?: [ReactNode, ReactNode];
  /** The name a screen reader gives a tile; the number alone when absent. */
  nameOf?: (n: number) => string;
  className?: string;
}) {
  const ref = useRef<HTMLDivElement>(null);
  function onKeyDown(e: KeyboardEvent<HTMLDivElement>) {
    if (e.key !== 'ArrowRight' && e.key !== 'ArrowLeft') return;
    const buttons = [...(ref.current?.querySelectorAll<HTMLButtonElement>('button') ?? [])];
    const at = buttons.indexOf(document.activeElement as HTMLButtonElement);
    if (at < 0) return;
    e.preventDefault();
    const rtl = getComputedStyle(e.currentTarget).direction === 'rtl';
    const step = (e.key === 'ArrowRight') !== rtl ? 1 : -1;
    buttons[Math.min(buttons.length - 1, Math.max(0, at + step))]?.focus();
  }
  const count = max - min + 1;
  return (
    <div className={`min-w-0 @container/scale ${className}`}>
      <div
        ref={ref}
        role="radiogroup"
        aria-label={label}
        onKeyDown={onKeyDown}
        className={`pn-scale-row grid ${count > 10 ? 'gap-0.5' : 'gap-0.5 @[15rem]/scale:gap-1'}`}
        style={{ gridTemplateColumns: `repeat(${count}, minmax(0, 1fr))` }}
      >
        {Array.from({ length: count }, (_, i) => min + i).map((n) => {
          const chosen = value === n;
          const mood = tone === 'mood';
          const band = mood ? moodColor(n) : undefined;
          return (
            <button
              key={n}
              type="button"
              role="radio"
              aria-checked={chosen}
              aria-label={nameOf ? nameOf(n) : String(n)}
              tabIndex={chosen || (value == null && n === min) ? 0 : -1}
              onClick={() => onPick(n)}
              className={`pn-scale-tile ${
                mood
                  ? chosen ? '' : 'pn-scale-mood text-pn'
                  : chosen ? 'bg-accent-fill text-white' : 'pn-scale-accent bg-surface-0 text-pn-soft'
              }`}
              style={mood ? (chosen
                ? { background: band, color: moodInk(n) }
                : { '--pn-tile': `color-mix(in srgb, ${band} 26%, transparent)`, '--pn-tile-lit': `color-mix(in srgb, ${band} 60%, transparent)` } as CSSProperties) : undefined}
            >
              {n}
            </button>
          );
        })}
      </div>
      {ends && (
        <div className="flex justify-between gap-2 pt-1 text-[11px] text-pn-muted px-0.5">
          <span className="min-w-0 truncate">{ends[0]}</span>
          <span className="min-w-0 truncate text-end">{ends[1]}</span>
        </div>
      )}
    </div>
  );
}

/** The one mood picker: 1 to 10 in the band colors, "1 · awful" and
 *  "10 · amazing" under the ends. The Mood pill and the check-in card both
 *  draw it. */
export function MoodScale({ value, onPick, label, className = '' }: {
  value: number | null | undefined;
  onPick: (n: number) => void;
  label: string;
  className?: string;
}) {
  const { t } = useTranslation('trackers');
  return (
    <ScaleTiles
      min={1}
      max={10}
      value={value}
      onPick={onPick}
      label={label}
      tone="mood"
      ends={[`1 · ${t('mood.anchor.1')}`, `10 · ${t('mood.anchor.10')}`]}
      nameOf={(n) => `${n} ${t(`mood.anchor.${moodAnchor(n)}`)}`}
      className={className}
    />
  );
}
