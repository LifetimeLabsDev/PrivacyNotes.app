import { moodColor } from './moodColors';

/**
 * How a logged mood shows outside the scale: its number on a chip in the
 * color of its band (`moodColor`), the same five colors the month grid
 * paints. The anchors (1, 3, 5, 7, 10) name the bands with a word; a 6 reads
 * "okay" and an 8 reads "good", the lower anchor on a tie.
 * Spec: ops/issues/0439.md (Spec), ops/docs/archive/ui-patterns.md section 141
 */
export const MOOD_ANCHOR_VALUES = [1, 3, 5, 7, 10] as const;

/** The anchor a mood belongs to: the nearest one, the lower on a tie. */
export function moodAnchor(mood: number): (typeof MOOD_ANCHOR_VALUES)[number] {
  let best: (typeof MOOD_ANCHOR_VALUES)[number] = 1;
  for (const a of MOOD_ANCHOR_VALUES) {
    if (Math.abs(a - mood) < Math.abs(best - mood)) best = a;
  }
  return best;
}

const DARK_INK = '#1f2937';
const LIGHT_INK = '#ffffff';

function luminance(hex: string): number {
  const lin = (c: number) => {
    const s = c / 255;
    return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
  };
  const [r, g, b] = [1, 3, 5].map((i) => lin(parseInt(hex.slice(i, i + 2), 16)));
  return 0.2126 * r! + 0.7152 * g! + 0.0722 * b!;
}

/** The text color on a band's full color: whichever of white and dark ink
 *  reads better on it, measured, so a band color can change without a
 *  number going unreadable. */
export function moodInk(mood: number): string {
  const l = luminance(moodColor(mood));
  const onLight = (l + 0.05) / (luminance(DARK_INK) + 0.05);
  const onDark = 1.05 / (l + 0.05);
  return onLight > onDark ? DARK_INK : LIGHT_INK;
}

/** A logged mood on one line: its number on the band's chip. */
export function MoodMark({ mood, size = 24, className = '' }: { mood: number; size?: number; className?: string }) {
  return (
    <span
      aria-hidden="true"
      className={`inline-flex shrink-0 items-center justify-center rounded-md font-semibold tabular-nums leading-none ${className}`}
      style={{ width: size, height: size, background: moodColor(mood), color: moodInk(mood), fontSize: Math.round(size * 0.5) }}
    >
      {mood}
    </span>
  );
}

/** A logged mood inside a pill: a small dot in the band's color before the
 *  number, so the number keeps the pill's own type and weight. */
export function MoodDot({ mood }: { mood: number }) {
  return <span aria-hidden="true" className="inline-block shrink-0 w-2 h-2 rounded-full" style={{ background: moodColor(mood) }} />;
}

/** A check-in row's icon: the journal's box, with the mood chip for its glyph. */
export function CheckInRowIcon({ mood }: { mood: number }) {
  return <MoodMark mood={mood} size={28} className="mt-px" />;
}

/** A check-in tile's small glyph, in the slot and size of the type glyph. */
export function CheckInGlyph({ mood }: { mood: number }) {
  return <MoodMark mood={mood} size={16} className="pn-card-glyph" />;
}
