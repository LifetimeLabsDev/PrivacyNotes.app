/**
 * Text color palette shared by the toolbar swatch popover (desktop) and
 * the mobile format sheet. Concrete hex values (not CSS variables) so the
 * serialized markdown stays portable and renders the same color anywhere.
 * Mid-tone values (Open Color step 7) chosen to stay legible on both light
 * and dark editor backgrounds.
 */
export const TEXT_COLORS: { name: string; value: string }[] = [
  { name: 'Gray', value: '#868e96' },
  { name: 'Red', value: '#e03131' },
  { name: 'Orange', value: '#e8590c' },
  { name: 'Yellow', value: '#f08c00' },
  { name: 'Green', value: '#2f9e44' },
  { name: 'Teal', value: '#0c8599' },
  { name: 'Blue', value: '#1971c2' },
  { name: 'Purple', value: '#7048e8' },
  { name: 'Pink', value: '#c2255c' },
];

/**
 * Font families offered by the toolbar's Font popover.
 *
 * Generic stacks, never a single named font: the value is written into stored
 * markdown as an inline `font-family`, so it has to render sanely on a machine
 * that has never heard of it - and the same note opens on macOS, Windows,
 * Linux, Android and iOS. `ui-*` first picks up the platform's own UI face,
 * with concrete fallbacks behind it.
 *
 * NO DOUBLE QUOTES in any value. These land inside a double-quoted HTML
 * attribute; textStyleCss escapes them defensively, but an escaped quote in a
 * font stack is a portability trap not worth introducing.
 */
export const FONT_FAMILIES: { name: string; value: string }[] = [
  { name: 'Sans', value: 'ui-sans-serif, system-ui, sans-serif' },
  { name: 'Serif', value: 'ui-serif, Georgia, Cambria, serif' },
  { name: 'Mono', value: 'ui-monospace, SFMono-Regular, Menlo, monospace' },
];

/**
 * Font sizes offered by the toolbar's Font popover, in `em` rather than `px`.
 *
 * em keeps a sized run proportional to the reader's own text-size setting
 * (`--pn-text-scale`, the sm/md/lg/xl axis in theme.ts). A px value would pin
 * the run absolutely and quietly opt it out of that setting, so someone who
 * scales the app up for legibility would find exactly the passages they had
 * emphasized staying small.
 */
export const FONT_SIZES: { name: string; value: string }[] = [
  { name: 'Small', value: '0.85em' },
  { name: 'Large', value: '1.25em' },
  { name: 'Huge', value: '1.6em' },
];

/**
 * Highlight palette for the toolbar's Highlight popover, twin of
 * TEXT_COLORS and deliberately NOT the same values.
 *
 * TEXT_COLORS are Open Color step 7, chosen to stay legible as FOREGROUND
 * text on both themes. As a background behind inherited body text those
 * same values are far too dark in light mode. So a highlight is a
 * translucent wash instead: the alpha lets the page (white) or the editor
 * (near-black) show through, which is what keeps one stored value legible
 * in both themes without the note knowing which theme it will be read in.
 * The same trick the default `mark` rule in index.css already uses.
 *
 * `value: null` is the DEFAULT highlight: no color attribute on the mark,
 * so it serializes as portable `==text==` and picks up the themed yellow
 * from index.css. Every other entry is written into stored markdown as an
 * inline `<mark style="background-color: ...">`, so the value must be a
 * concrete color the HTML export and the burn viewer can render (they
 * re-validate it through sanitizeColor in markdownRender.ts).
 *
 * Names are reused from TEXT_COLORS so both popovers share the
 * `color.names.*` translations, and so is the ORDER: the two grids sit on
 * the same toolbar and a reader builds muscle memory for a position, not a
 * name. Keep them in step - if one palette is reordered, reorder both. That
 * is why the default entry is fourth rather than first: yellow is where
 * yellow lives in the text grid, and consistency there beats putting the
 * most-used swatch under the cursor.
 *
 * Spec: ops/docs/design-decisions.md (highlight colors)
 */
/**
 * The palette's default entry, named so the toolbar can fall back to it
 * without searching the array for the one member that stores no color.
 * It is a member of HIGHLIGHT_COLORS below, not a copy of one, so the two
 * cannot drift.
 */
export const DEFAULT_HIGHLIGHT: { name: string; value: string | null } = { name: 'Yellow', value: null };

export const HIGHLIGHT_COLORS: { name: string; value: string | null }[] = [
  { name: 'Gray', value: 'rgba(134, 142, 150, 0.32)' },
  { name: 'Red', value: 'rgba(255, 107, 107, 0.35)' },
  { name: 'Orange', value: 'rgba(255, 146, 43, 0.35)' },
  DEFAULT_HIGHLIGHT,
  { name: 'Green', value: 'rgba(64, 192, 87, 0.35)' },
  { name: 'Teal', value: 'rgba(18, 184, 134, 0.35)' },
  { name: 'Blue', value: 'rgba(51, 154, 240, 0.35)' },
  { name: 'Purple', value: 'rgba(151, 117, 250, 0.35)' },
  { name: 'Pink', value: 'rgba(240, 101, 149, 0.35)' },
];
