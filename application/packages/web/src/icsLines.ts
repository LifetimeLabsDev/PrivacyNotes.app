/**
 * The content-line layer of iCalendar (RFC 5545), both directions, shared by
 * the importer and the writer. Pure.
 *
 * Reading starts from BYTES: a fold is removed before the text is decoded,
 * because a writer that folds at 75 octets can split a UTF-8 sequence across
 * the fold, and decoding first would turn both halves into U+FFFD. Google
 * folds at 75 characters instead and writes longer lines, so no length is
 * assumed. Parameters are split outside double quotes only: Apple writes a
 * quoted address that holds a colon and semicolons.
 *
 * A file is untrusted input, so the parse is linear and bounded: the limits
 * below refuse a file before it can stall the page.
 * Spec: ops/docs/plans/google-calendar-import.md (sections 3 and 4.1)
 */

export type IcsProp = {
  /** Upper-cased. */
  name: string;
  /** Upper-cased names; each value unquoted. */
  params: Record<string, string[]>;
  /** Raw: TEXT escapes still in place (see `unescapeText`). */
  value: string;
};

export type IcsComponent = {
  /** Upper-cased, e.g. `VEVENT`. */
  type: string;
  props: IcsProp[];
  children: IcsComponent[];
};

export const ICS_LIMITS = {
  components: 50_000,
  propsPerComponent: 200,
  /** More parameters than any writer puts on one line; such a line is skipped. */
  paramsPerLine: 64,
  /** VCALENDAR > VEVENT > VALARM, VCALENDAR > VTIMEZONE > STANDARD. */
  depth: 3,
  valueBytes: 1_000_000,
};

/** Thrown when a file passes one of `ICS_LIMITS`; the import stops with its message. */
export class IcsLimitError extends Error {}

/** Remove every fold (CRLF or LF followed by a space or a tab), then decode. */
export function unfoldBytes(bytes: Uint8Array): string {
  const out = new Uint8Array(bytes.length);
  let n = 0;
  for (let i = 0; i < bytes.length; i++) {
    const b = bytes[i]!;
    if (b === 0x0d && bytes[i + 1] === 0x0a && (bytes[i + 2] === 0x20 || bytes[i + 2] === 0x09)) {
      i += 2;
      continue;
    }
    if (b === 0x0a && (bytes[i + 1] === 0x20 || bytes[i + 1] === 0x09)) {
      i += 1;
      continue;
    }
    out[n++] = b;
  }
  return new TextDecoder('utf-8').decode(out.subarray(0, n));
}

/** One unfolded line as name, parameters and raw value; null when it is not a content line. */
export function parseLine(line: string): IcsProp | null {
  let i = 0;
  while (i < line.length && line[i] !== ';' && line[i] !== ':') i++;
  if (i === 0 || i === line.length) return null;
  const name = line.slice(0, i).toUpperCase();
  if (!/^[A-Z0-9-]+$/.test(name)) return null;
  const params: Record<string, string[]> = {};
  let paramCount = 0;
  while (line[i] === ';') {
    i++;
    const eq = line.indexOf('=', i);
    if (eq < 0) return null;
    const key = line.slice(i, eq).toUpperCase();
    i = eq + 1;
    const values: string[] = [];
    for (;;) {
      let v = '';
      if (line[i] === '"') {
        const close = line.indexOf('"', i + 1);
        if (close < 0) return null;
        v = line.slice(i + 1, close);
        i = close + 1;
      } else {
        const start = i;
        while (i < line.length && line[i] !== ',' && line[i] !== ';' && line[i] !== ':') i++;
        v = line.slice(start, i);
      }
      values.push(v);
      if (line[i] === ',') { i++; continue; }
      break;
    }
    (params[key] ??= []).push(...values);
    if (++paramCount > ICS_LIMITS.paramsPerLine) return null;
  }
  if (line[i] !== ':') return null;
  return { name, params, value: line.slice(i + 1) };
}

/**
 * Every top-level component of an unfolded text (a file holds one
 * `VCALENDAR`, a sloppy one several). Lines that are not content lines and
 * properties outside any component are dropped; a component that never ends
 * ends with the file.
 */
export function parseIcs(text: string): IcsComponent[] {
  const top: IcsComponent[] = [];
  const stack: IcsComponent[] = [];
  let components = 0;
  const encoder = new TextEncoder();
  for (const raw of text.split(/\r?\n/)) {
    if (!raw) continue;
    // Bounded before the line is parsed, so its parameters cannot be the cost.
    if (raw.length > ICS_LIMITS.valueBytes + 4096) throw new IcsLimitError('A line in the calendar file is larger than 1 MB.');
    const prop = parseLine(raw);
    if (!prop) continue;
    if (prop.name === 'BEGIN') {
      if (stack.length >= ICS_LIMITS.depth) throw new IcsLimitError('The calendar file nests components deeper than a calendar does.');
      if (++components > ICS_LIMITS.components) throw new IcsLimitError(`The calendar file holds more than ${ICS_LIMITS.components} entries.`);
      const c: IcsComponent = { type: prop.value.trim().toUpperCase(), props: [], children: [] };
      (stack.at(-1)?.children ?? top).push(c);
      stack.push(c);
      continue;
    }
    if (prop.name === 'END') {
      const type = prop.value.trim().toUpperCase();
      const at = stack.map((c) => c.type).lastIndexOf(type);
      if (at >= 0) stack.length = at;
      continue;
    }
    const current = stack.at(-1);
    if (!current) continue;
    if (current.props.length >= ICS_LIMITS.propsPerComponent) {
      throw new IcsLimitError(`An entry in the calendar file holds more than ${ICS_LIMITS.propsPerComponent} lines.`);
    }
    if (prop.value.length > ICS_LIMITS.valueBytes / 4 && encoder.encode(prop.value).length > ICS_LIMITS.valueBytes) {
      throw new IcsLimitError('A value in the calendar file is larger than 1 MB.');
    }
    current.props.push(prop);
  }
  return top;
}

/** The first property of a name, or undefined. */
export function prop(c: IcsComponent, name: string): IcsProp | undefined {
  return c.props.find((p) => p.name === name);
}

/** Every property of a name, in file order. */
export function props(c: IcsComponent, name: string): IcsProp[] {
  return c.props.filter((p) => p.name === name);
}

/** The first value of a parameter, or undefined. */
export function param(p: IcsProp | undefined, name: string): string | undefined {
  return p?.params[name]?.[0];
}

/** TEXT unescaping: `\\`, `\;`, `\,`, `\n` and `\N`, in one pass. */
export function unescapeText(v: string): string {
  return v.replace(/\\([\\;,nN])/g, (_, c: string) => (c === 'n' || c === 'N' ? '\n' : c));
}

/** A TEXT value split at its unescaped commas (CATEGORIES), each unescaped. */
export function splitTextList(v: string): string[] {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < v.length; i++) {
    const ch = v[i]!;
    if (ch === '\\' && i + 1 < v.length) { cur += ch + v[++i]; continue; }
    if (ch === ',') { out.push(unescapeText(cur)); cur = ''; continue; }
    cur += ch;
  }
  out.push(unescapeText(cur));
  return out;
}

/** TEXT escaping for the writer. A CR is dropped; a line break becomes `\n`. */
export function escapeText(v: string): string {
  return v.replace(/\r\n?/g, '\n').replace(/[\\;,\n]/g, (c) => (c === '\n' ? '\\n' : `\\${c}`));
}

/**
 * One content line folded at 75 octets on a character boundary, each
 * continuation starting with a space, ended with CRLF.
 */
export function foldLine(line: string): string {
  const encoder = new TextEncoder();
  if (encoder.encode(line).length <= 75) return `${line}\r\n`;
  const parts: string[] = [];
  let cur = '';
  let curBytes = 0;
  let limit = 75;
  for (const ch of line) {
    const size = encoder.encode(ch).length;
    if (curBytes + size > limit) {
      parts.push(cur);
      cur = '';
      curBytes = 0;
      // A continuation line starts with the space, which counts.
      limit = 74;
    }
    cur += ch;
    curBytes += size;
  }
  parts.push(cur);
  return `${parts.join('\r\n ')}\r\n`;
}
