/**
 * Split Markdown into code and prose with one walk over the lines, so an
 * importer can convert dialect syntax without touching code.
 *
 * A regex that pairs fences runs back to the end of the text for every
 * opener it cannot close, which is quadratic on a crafted file (thousands of
 * lines that each open a fence) and freezes the tab. This walk is linear: a
 * fence opens on a line that starts with three or more backticks or tildes
 * and closes on the next line that starts with at least as many of the same
 * character and holds nothing else; an unclosed fence runs to the end, as in
 * CommonMark. Inline code spans are cut out of prose lines with a pattern
 * that cannot cross a line.
 */

const FENCE = /^ {0,3}(`{3,}|~{3,})/;

interface Segment {
  code: boolean;
  text: string;
}

function codeSegments(md: string): Segment[] {
  const out: Segment[] = [];
  const push = (code: boolean, text: string) => {
    if (!text) return;
    const last = out[out.length - 1];
    if (last && last.code === code) last.text += text;
    else out.push({ code, text });
  };
  const lines = md.split('\n');
  let fence: string | null = null;
  lines.forEach((line, i) => {
    const nl = i < lines.length - 1 ? '\n' : '';
    if (fence) {
      const m = FENCE.exec(line);
      if (m && m[1]![0] === fence[0] && m[1]!.length >= fence.length && line.trim() === m[1]) fence = null;
      push(true, line + nl);
      return;
    }
    const open = FENCE.exec(line);
    if (open && !(open[1]![0] === '`' && line.slice(open[0].length).includes('`'))) {
      fence = open[1]!;
      push(true, line + nl);
      return;
    }
    let last = 0;
    for (const m of line.matchAll(/`[^`]+`/g)) {
      push(false, line.slice(last, m.index));
      push(true, m[0]);
      last = m.index! + m[0].length;
    }
    push(false, line.slice(last) + nl);
  });
  return out;
}

/** Run `fn` over the prose of a Markdown text and leave code as it is. */
export function mapOutsideCode(md: string, fn: (prose: string) => string): string {
  return codeSegments(md)
    .map((s) => (s.code ? s.text : fn(s.text)))
    .join('');
}

/** The prose of a Markdown text, with every code part removed. */
export function proseOnly(md: string): string {
  return codeSegments(md)
    .filter((s) => !s.code)
    .map((s) => s.text)
    .join('');
}

/** Remove every `<!-- ... -->` with one forward scan; an unclosed one is left as text. */
export function stripHtmlComments(text: string): string {
  let out = '';
  let pos = 0;
  for (;;) {
    const start = text.indexOf('<!--', pos);
    if (start < 0) break;
    const end = text.indexOf('-->', start + 4);
    if (end < 0) break;
    out += text.slice(pos, start);
    pos = end + 3;
  }
  return out + text.slice(pos);
}
