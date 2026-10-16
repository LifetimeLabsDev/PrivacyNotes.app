/**
 * What the Markdown view's toolbar does to the text: each action reads the
 * text and the selection and returns one replacement, so the field applies it
 * as a single typed change and its own undo takes it back in one step.
 *
 * Marks wrap the selection and unwrap it on a second press. Line prefixes act
 * on every line the selection touches and come off when every line already
 * carries them. Blocks (divider, code block, table) sit on their own lines
 * with a blank line before them, because a `---` right under a line of text
 * makes that line a heading.
 * Spec: ops/issues/0493.md (Spec)
 */

/** Replace [from, to) with `insert`, then select [selFrom, selTo). */
export type SourceEdit = { from: number; to: number; insert: string; selFrom: number; selTo: number };

export type SourceAction =
  | 'bold' | 'italic' | 'strike' | 'inlinecode'
  | 'heading' | 'tasks' | 'bullets' | 'numbered' | 'quote'
  | 'link' | 'notelink' | 'codeblock' | 'table' | 'hr';

function wrap(text: string, s: number, e: number, mark: string): SourceEdit {
  const n = mark.length;
  // A lone '*' must not take one star of a '**' pair.
  const lone = (at: number) => mark !== '*' || text[at] !== '*';
  if (text.slice(s - n, s) === mark && text.slice(e, e + n) === mark && lone(s - n - 1) && lone(e + n)) {
    return { from: s - n, to: e + n, insert: text.slice(s, e), selFrom: s - n, selTo: e - n };
  }
  const sel = text.slice(s, e);
  if (sel.length >= 2 * n && sel.startsWith(mark) && sel.endsWith(mark)) {
    const inner = sel.slice(n, sel.length - n);
    return { from: s, to: e, insert: inner, selFrom: s, selTo: s + inner.length };
  }
  return { from: s, to: e, insert: mark + sel + mark, selFrom: s + n, selTo: e + n };
}

// The first group is the indent, which a nested item keeps. A quote starts
// the line, so it has none.
const LINE_PREFIX: Record<'tasks' | 'bullets' | 'numbered' | 'quote', RegExp> = {
  tasks: /^([ \t]*)- \[[ xX]\] /,
  bullets: /^([ \t]*)[-*+] (?!\[[ xX]\] )/,
  numbered: /^([ \t]*)\d+[.)] /,
  quote: /^()> ?/,
};
// Any list or quote prefix, so a bullet line turns into a task line rather
// than a bullet with a checkbox inside it.
const ANY_LIST = /^([ \t]*)(?:- \[[ xX]\] |[-*+] |\d+[.)] |> ?)/;

function lines(text: string, s: number, e: number, map: (line: string, i: number) => string): SourceEdit {
  const from = text.lastIndexOf('\n', s - 1) + 1;
  // A selection that ends at the start of a line does not take that line.
  const endAt = e > s && text[e - 1] === '\n' ? e - 1 : e;
  const nl = text.indexOf('\n', endAt);
  const to = nl === -1 ? text.length : nl;
  const before = text.slice(from, to).split('\n');
  const after = before.map(map);
  const insert = after.join('\n');
  if (s === e) {
    const delta = after[0]!.length - before[0]!.length;
    const caret = Math.max(from, s + delta);
    return { from, to, insert, selFrom: caret, selTo: caret };
  }
  return { from, to, insert, selFrom: from, selTo: from + insert.length };
}

/** The column a run of spaces and tabs reaches; a tab stops every four. */
function columns(indent: string): number {
  let col = 0;
  for (const ch of indent) col = ch === '\t' ? col + 4 - (col % 4) : col + 1;
  return col;
}

function listToggle(text: string, s: number, e: number, kind: keyof typeof LINE_PREFIX): SourceEdit {
  const from = text.lastIndexOf('\n', s - 1) + 1;
  const endAt = e > s && text[e - 1] === '\n' ? e - 1 : e;
  const nl = text.indexOf('\n', endAt);
  const block = text.slice(from, nl === -1 ? text.length : nl).split('\n');
  const filled = block.filter((l) => l.trim() !== '');
  const off = filled.length > 0 && filled.every((l) => LINE_PREFIX[kind].test(l));
  // One entry per open nesting level: the indent the line had, the indent it
  // gets, the column its text starts at, and its own count. A child moves to
  // its parent's text column, because a marker of another width would
  // otherwise leave it too shallow to nest, and every level counts from 1.
  const levels: { from: number; indent: string; text: number; n: number }[] = [];
  return lines(text, s, e, (line) => {
    if (off) return line.replace(LINE_PREFIX[kind], '$1');
    if (line.trim() === '' && filled.length > 0) return line;
    // A quote wraps the line as it is, list marker and task state included.
    if (kind === 'quote') return `> ${line.replace(LINE_PREFIX.quote, '')}`;
    const m = ANY_LIST.exec(line);
    const own = m ? m[1]! : /^[ \t]*/.exec(line)![0];
    const bare = line.slice(m ? m[0].length : own.length);
    const at = columns(own);
    while (levels.length > 0 && levels[levels.length - 1]!.from > at) levels.pop();
    let level = levels[levels.length - 1];
    if (!level || level.from < at) {
      level = { from: at, indent: level ? ' '.repeat(level.text) : own, text: 0, n: 0 };
      levels.push(level);
    }
    // A task's text starts after `- `: the checkbox is part of its text.
    const marker = kind === 'numbered' ? `${++level.n}. ` : '- ';
    level.text = columns(level.indent) + marker.length;
    return `${level.indent}${marker}${kind === 'tasks' ? '[ ] ' : ''}${bare}`;
  });
}

/** H1, H2, H3, then back to body text. */
function heading(text: string, s: number, e: number): SourceEdit {
  return lines(text, s, e, (line) => {
    const m = /^(#{1,6}) /.exec(line);
    if (!m) return `# ${line}`;
    const body = line.slice(m[0].length);
    return m[1]!.length >= 3 ? body : `${m[1]}# ${body}`;
  });
}

/** `content` on its own lines, with a blank line before and after it. */
function block(text: string, s: number, e: number, content: string, selIn: [number, number]): SourceEdit {
  const head = text.slice(0, s);
  const tail = text.slice(e);
  const lead = head === '' || head.endsWith('\n\n') ? '' : head.endsWith('\n') ? '\n' : '\n\n';
  const trail = tail === '' || tail.startsWith('\n\n') ? '' : tail.startsWith('\n') ? '\n' : '\n\n';
  const insert = lead + content + trail;
  const at = s + lead.length;
  return { from: s, to: e, insert, selFrom: at + selIn[0], selTo: at + selIn[1] };
}

export function sourceEdit(action: SourceAction, text: string, selStart: number, selEnd: number): SourceEdit {
  const s = Math.min(selStart, selEnd);
  const e = Math.max(selStart, selEnd);
  const sel = text.slice(s, e);
  switch (action) {
    case 'bold': return wrap(text, s, e, '**');
    case 'italic': return wrap(text, s, e, '*');
    case 'strike': return wrap(text, s, e, '~~');
    case 'inlinecode': return wrap(text, s, e, '`');
    case 'heading': return heading(text, s, e);
    case 'tasks':
    case 'bullets':
    case 'numbered':
    case 'quote': return listToggle(text, s, e, action);
    case 'link': {
      // The address is the part still to write, so it is what ends selected.
      const url = 'https://';
      const insert = `[${sel}](${url})`;
      return sel === ''
        ? { from: s, to: e, insert, selFrom: s + 1, selTo: s + 1 }
        : { from: s, to: e, insert, selFrom: s + sel.length + 3, selTo: s + sel.length + 3 + url.length };
    }
    case 'notelink':
      return { from: s, to: e, insert: `[[${sel}]]`, selFrom: s + 2, selTo: s + 2 + sel.length };
    case 'codeblock': {
      const content = '```\n' + sel + '\n```';
      return block(text, s, e, content, [4, 4 + sel.length]);
    }
    case 'table': {
      const cell = sel.includes('\n') ? '' : sel;
      const head = cell || 'Column';
      const content = `| ${head} | Column |\n| --- | --- |\n|  |  |`;
      return block(text, s, e, content, [2, 2 + head.length]);
    }
    case 'hr': {
      // After the selection, which it keeps; the caret goes under the line.
      const out = block(text, e, e, '---', [3, 3]);
      const caret = e + out.insert.length;
      return { ...out, selFrom: caret, selTo: caret };
    }
  }
}
