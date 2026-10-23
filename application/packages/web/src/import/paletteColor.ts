import { HIGHLIGHT_COLORS, TEXT_COLORS } from '../editorColors';

/**
 * A color out of another app's export, moved onto the editor's own palette.
 *
 * The note keeps only a palette value, never the stranger's string, so an
 * imported color reads in both themes, shows as the active swatch in the
 * toolbar, and passes `sanitizeColor` in the HTML export and the burn viewer.
 * The same rule the paste path follows (`keepPaletteStyles`).
 *
 * Spec: ops/issues/0553.md (Spec)
 */

/**
 * Hue bands in degrees, start inclusive, end exclusive; red wraps through 0.
 * Every palette value falls in its own band (tests/paletteColor.test.ts), so
 * the table and editorColors.ts cannot drift apart. The edges sit between the
 * palette hues, not on them: Open Color's yellow is at 35 and its purple at 255.
 */
const HUE_BANDS: readonly [name: string, from: number, to: number][] = [
  ['Red', 345, 12],
  ['Orange', 12, 32],
  ['Yellow', 32, 70],
  ['Green', 70, 155],
  ['Teal', 155, 195],
  ['Blue', 195, 245],
  ['Purple', 245, 300],
  ['Pink', 300, 345],
];

/** Below this saturation a color reads as gray, whatever its hue. */
const GRAY_SATURATION = 0.25;
/** Below this alpha a color is not there at all. */
const MIN_ALPHA = 0.1;

type Hsla = { h: number; s: number; l: number; a: number };

/**
 * Hex and rgb()/rgba() only, read with a strict pattern rather than the
 * CSSOM so jsdom and every browser agree. A named color, hsl(), var() or
 * a keyword returns null and the text stays uncolored.
 */
function parse(css: string): Hsla | null {
  const v = css.trim().toLowerCase();
  let rgba: number[] | null = null;
  const hex = v.match(/^#([0-9a-f]{3}|[0-9a-f]{6}|[0-9a-f]{8})$/)?.[1];
  if (hex) {
    const full = hex.length === 3 ? [...hex].map((c) => c + c).join('') : hex;
    rgba = [0, 2, 4].map((i) => parseInt(full.slice(i, i + 2), 16));
    rgba.push(full.length === 8 ? parseInt(full.slice(6, 8), 16) / 255 : 1);
  } else {
    const inner = v.match(/^rgba?\(([^()]*)\)$/)?.[1];
    if (!inner) return null;
    const parts = inner.trim().split(/\s*[\s,/]\s*/);
    if (parts.length !== 3 && parts.length !== 4) return null;
    if (!parts.slice(0, 3).every((p) => /^\d{1,3}(?:\.\d+)?$/.test(p))) return null;
    const alpha = parts[3];
    if (alpha !== undefined && !/^(?:\d*\.)?\d+%?$/.test(alpha)) return null;
    rgba = parts.slice(0, 3).map(Number);
    if (rgba.some((c) => c > 255)) return null;
    rgba.push(alpha === undefined ? 1 : alpha.endsWith('%') ? parseFloat(alpha) / 100 : parseFloat(alpha));
  }
  const [r, g, b] = rgba.slice(0, 3).map((c) => c! / 255) as [number, number, number];
  const max = Math.max(r, g, b);
  const min = Math.min(r, g, b);
  const l = (max + min) / 2;
  const d = max - min;
  const s = d === 0 ? 0 : d / (1 - Math.abs(2 * l - 1));
  let h = 0;
  if (d !== 0) {
    if (max === r) h = 60 * (((g - b) / d) % 6);
    else if (max === g) h = 60 * ((b - r) / d + 2);
    else h = 60 * ((r - g) / d + 4);
  }
  return { h: (h + 360) % 360, s, l, a: rgba[3]! };
}

function paletteName(c: Hsla): string {
  if (c.s < GRAY_SATURATION) return 'Gray';
  const band = HUE_BANDS.find(([, from, to]) => (from < to ? c.h >= from && c.h < to : c.h >= from || c.h < to));
  return band![0];
}

/**
 * The text color nearest to `css`, as a TEXT_COLORS value. Null for a color
 * that cannot be read, and for near-black and near-white, which are the
 * default text of one theme and cannot be read in the other.
 */
export function nearestTextColor(css: string): string | null {
  const c = parse(css);
  if (!c || c.a < MIN_ALPHA || c.l < 0.2 || c.l > 0.85) return null;
  const name = paletteName(c);
  return TEXT_COLORS.find((t) => t.name === name)!.value;
}

/**
 * The highlight nearest to `css`, as a HIGHLIGHT_COLORS entry (`value: null`
 * is the default yellow, written as `==text==`). Null for a color that cannot
 * be read, and for a white background, which is no highlight at all.
 */
export function nearestHighlight(css: string): { name: string; value: string | null } | null {
  const c = parse(css);
  if (!c || c.a < MIN_ALPHA || c.l > 0.92) return null;
  const name = paletteName(c);
  return HIGHLIGHT_COLORS.find((t) => t.name === name)!;
}
