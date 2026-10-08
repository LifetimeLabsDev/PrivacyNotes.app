import { FONT_FAMILIES, FONT_SIZES, HIGHLIGHT_COLORS, TEXT_COLORS } from './editorColors';

/**
 * Styling in HTML pasted from another app is kept only where it is one of the
 * editor's own choices. Google Docs and Word write a colour, a font and a size
 * on every run of text. Kept as they come, black text cannot be read on the
 * dark theme, and Arial at 11pt ignores the note's own font and size setting.
 * A colour, font or size from the toolbar palettes stays, so a
 * coloured word copied from a browser page of a shared note keeps its colour.
 *
 * The editor's own copy carries the document itself and never comes here.
 */

/** A colour as the browser spells it once parsed, so `#e03131` matches `rgb(224, 49, 49)`. */
function canonicalColor(value: string, probe: HTMLElement): string {
  probe.style.color = '';
  probe.style.color = value;
  return probe.style.color;
}

const canonicalFont = (value: string): string => value.replace(/["']/g, '').replace(/\s*,\s*/g, ',').trim().toLowerCase();

export function keepPaletteStyles(html: string): string {
  if (!/style\s*=/i.test(html)) return html;
  const doc = new DOMParser().parseFromString(html, 'text/html');
  const probe = doc.createElement('span');
  const textColors = new Set(TEXT_COLORS.map((c) => canonicalColor(c.value, probe)));
  const highlightColors = new Set(
    HIGHLIGHT_COLORS.flatMap((c) => (c.value ? [canonicalColor(c.value, probe)] : [])),
  );
  const fonts = new Set(FONT_FAMILIES.map((f) => canonicalFont(f.value)));
  const sizes = new Set(FONT_SIZES.map((s) => s.value));

  doc.body.querySelectorAll<HTMLElement>('[style]').forEach((el) => {
    const { style } = el;
    if (style.color && !textColors.has(canonicalColor(style.color, probe))) style.removeProperty('color');
    if (style.fontFamily && !fonts.has(canonicalFont(style.fontFamily))) style.removeProperty('font-family');
    if (style.fontSize && !sizes.has(style.fontSize)) style.removeProperty('font-size');
    if (el.tagName === 'MARK' && style.backgroundColor && !highlightColors.has(canonicalColor(style.backgroundColor, probe))) {
      style.removeProperty('background-color');
    }
    if (!style.length) el.removeAttribute('style');
  });
  return doc.body.innerHTML;
}
