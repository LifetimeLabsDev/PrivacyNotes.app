import { TextStyle } from '@tiptap/extension-text-style';

/**
 * Text color support.
 *
 * The Color extension stores the chosen color as the `color` attribute on
 * the TextStyle mark. tiptap-markdown ships no serializer for that mark,
 * so without this getMarkdown() would either drop the color silently or
 * throw ("no serializer for mark type textStyle"). We add one here.
 *
 * Color has no native markdown syntax, so we serialize it as an inline
 * HTML <span style="color:..."> - valid CommonMark and the only portable
 * representation. The span is emitted ONLY when a color is actually set,
 * so notes without color round-trip to byte-identical clean markdown.
 *
 * Re-import / paste round-trips automatically: Markdown({ html: true })
 * feeds the raw span to ProseMirror's DOMParser, which matches the
 * TextStyle/Color parseHTML rules and rebuilds the mark.
 *
 * The HTML export and burn-after-reading viewer render this span via
 * markdownRender.ts, which independently allowlists the `color` value
 * (sanitizeColor) so an untrusted note can't smuggle other styles.
 */
/** Attributes FontSize, FontFamily and Color all hang off the one textStyle mark. */
type TextStyleAttrs = {
  color?: string | null;
  fontSize?: string | null;
  fontFamily?: string | null;
};

/**
 * Build the inline `style` value for a textStyle mark.
 *
 * ALL THREE attributes have to be listed here. They share a single mark, and
 * this serializer is the only thing that puts any of them into stored markdown
 * - an attribute missing from this function round-trips as nothing and is
 * silently dropped on the next save, which is exactly how font size and family
 * would have behaved had they been registered without touching this.
 *
 * Returns '' when the mark carries nothing, which is the signal for open/close
 * to emit no span at all. Double quotes are escaped because the value lands
 * inside a double-quoted HTML attribute (font stacks are the realistic source
 * of one, e.g. a family containing "Times New Roman").
 */
function textStyleCss(attrs: TextStyleAttrs): string {
  const parts: string[] = [];
  if (attrs.color) parts.push(`color: ${attrs.color}`);
  if (attrs.fontSize) parts.push(`font-size: ${attrs.fontSize}`);
  if (attrs.fontFamily) parts.push(`font-family: ${attrs.fontFamily}`);
  return parts.join('; ').replace(/"/g, '&quot;');
}

export const TextStyleMarkdown = TextStyle.extend({
  addStorage() {
    return {
      markdown: {
        serialize: {
          open(_state: unknown, mark: { attrs: TextStyleAttrs }) {
            const css = textStyleCss(mark.attrs);
            return css ? `<span style="${css}">` : '';
          },
          close(_state: unknown, mark: { attrs: TextStyleAttrs }) {
            // Must mirror open() exactly: emitting a closing tag for a span
            // that was never opened corrupts the document.
            return textStyleCss(mark.attrs) ? '</span>' : '';
          },
          mixable: true,
          expelEnclosingWhitespace: true,
        },
        parse: {
          // Handled by markdown-it (html: true) -> ProseMirror DOMParser.
        },
      },
    };
  },
});
