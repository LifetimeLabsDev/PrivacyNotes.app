/**
 * On Compact and Tight a paragraph is a line and an empty paragraph is a
 * blank line. HTML that leaves the app with one `<p>` per line looks right
 * only where our margins survive: many paste targets drop inline styles and
 * put their own gap around every paragraph, and a browser copies a page's
 * paragraphs with a blank line between them. Either way one blank line
 * arrived as three (GitHub #345). So a run of paragraphs goes out as ONE
 * paragraph with a `<br>` per line, which every target draws the same way.
 *
 * Used by the editor's copy, the burn viewer and the HTML and PDF export.
 * No imports, so the burn viewer's chunk stays small.
 * Spec: ops/docs/design-decisions.md (editor paragraph rhythm)
 */

/** Marks a joined paragraph and the break that stands for each paragraph
 *  boundary inside it, so a copy pasted back into the app splits again. */
export const LINES_ATTR = 'data-pn-lines';
export const LINE_BREAK_ATTR = 'data-pn-line';
/** The break after a final empty line, which only makes that line draw. */
export const END_BREAK_ATTR = 'data-pn-end';

function sameAttributes(a: Element, b: Element): boolean {
  const own = (el: Element) =>
    Array.from(el.attributes)
      .filter((at) => at.name !== 'data-pm-slice')
      .map((at) => `${at.name}=${at.value}`)
      .sort()
      .join('\n');
  return own(a) === own(b);
}

/** An empty line. The editor's is a paragraph with no content, the only
 *  form a copy may drop, because a copy pastes back exactly; a rendered one
 *  is a paragraph of a non-breaking space. */
function isBlankLine(p: Element, marked: boolean): boolean {
  if (marked) return !p.hasChildNodes();
  return Array.from(p.childNodes).every((c) => c.nodeType === 3 && !/\S/.test(c.textContent ?? ''));
}

/**
 * Joins every run of sibling paragraphs under `root` into one paragraph.
 * Paragraphs with different attributes (alignment) stay apart, and a list
 * item or a table cell keeps one paragraph each. `marked` adds the markers
 * the editor's paste reads back; a page that is only read goes without.
 */
export function joinParagraphLines(root: ParentNode, marked: boolean): void {
  for (const first of Array.from(root.querySelectorAll('p'))) {
    if (!first.parentNode || first.hasAttribute(LINES_ATTR) || first.closest('li, td, th')) continue;
    const prev = first.previousElementSibling;
    if (prev && prev.nodeName === 'P' && sameAttributes(prev, first)) continue;
    const run: HTMLParagraphElement[] = [first];
    let next = first.nextElementSibling;
    while (next && next.nodeName === 'P' && sameAttributes(first, next)) {
      run.push(next as HTMLParagraphElement);
      next = next.nextElementSibling;
    }
    if (run.length < 2) continue;
    const doc = first.ownerDocument;
    const mark = (br: HTMLBRElement, attr: string) => {
      if (marked) br.setAttribute(attr, '');
      return br;
    };
    if (isBlankLine(first, marked)) first.replaceChildren();
    run.slice(1).forEach((p, i) => {
      first.appendChild(mark(doc.createElement('br'), LINE_BREAK_ATTR));
      const blank = isBlankLine(p, marked);
      if (!blank) first.append(...Array.from(p.childNodes));
      if (i === run.length - 2 && blank) first.appendChild(mark(doc.createElement('br'), END_BREAK_ATTR));
      p.remove();
    });
    if (marked) first.setAttribute(LINES_ATTR, '');
  }
}

/** The same for an HTML string, for markup built as text. */
export function joinParagraphLinesHtml(html: string): string {
  if (!html.includes('<p')) return html;
  const doc = new DOMParser().parseFromString(`<body>${html}</body>`, 'text/html');
  joinParagraphLines(doc.body, false);
  return doc.body.innerHTML;
}
