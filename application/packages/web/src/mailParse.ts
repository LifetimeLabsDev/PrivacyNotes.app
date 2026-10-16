/**
 * A saved email (`.eml`, RFC 5322 with MIME), read for display as text.
 *
 * Only what a reader needs: the header lines, one body as plain text, and the
 * names and sizes of the attachments. The HTML part of a mail is never
 * rendered. When a mail has no text part, its HTML is reduced to text in an
 * inert document, which loads nothing and runs nothing, so no remote image or
 * tracking pixel can tell the sender the mail was opened.
 * Spec: ops/issues/0522.md
 */

interface MailAttachment {
  name: string;
  /** Decoded size in bytes. */
  size: number;
}

export interface ParsedMail {
  from: string;
  to: string;
  cc: string;
  /** The Date header as an ISO string, or '' when it does not parse. */
  date: string;
  subject: string;
  text: string;
  attachments: MailAttachment[];
}

type Headers = Map<string, string>;

/** Bytes to a string of one char per byte, so offsets and binary parts stay exact. */
function toBinary(bytes: Uint8Array): string {
  let out = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    out += String.fromCharCode(...bytes.subarray(i, i + 0x8000));
  }
  return out;
}

function fromBinary(s: string): Uint8Array {
  const out = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) out[i] = s.charCodeAt(i) & 0xff;
  return out;
}

function decodeCharset(bytes: Uint8Array, charset: string): string {
  try {
    return new TextDecoder(charset || 'utf-8').decode(bytes);
  } catch {
    return new TextDecoder('utf-8').decode(bytes);
  }
}

/** Splits a part at its first blank line into its header block and its body. */
function splitPart(s: string): { head: string; body: string } {
  const m = /\r?\n\r?\n/.exec(s);
  if (!m) return { head: s, body: '' };
  return { head: s.slice(0, m.index), body: s.slice(m.index + m[0].length) };
}

/** Header names in lower case; the first occurrence of a name wins. */
function parseHeaders(head: string): Headers {
  const headers: Headers = new Map();
  const unfolded = head.replace(/\r?\n[ \t]+/g, ' ');
  for (const line of unfolded.split(/\r?\n/)) {
    const colon = line.indexOf(':');
    if (colon <= 0) continue;
    const name = line.slice(0, colon).trim().toLowerCase();
    if (!headers.has(name)) headers.set(name, line.slice(colon + 1).trim());
  }
  return headers;
}

function decodeQ(s: string): Uint8Array {
  const bin = s.replace(/_/g, ' ').replace(/=([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)));
  return fromBinary(bin);
}

function decodeBase64(s: string): Uint8Array {
  // Padding is dropped and added back, so a missing or stray '=' still decodes.
  let clean = s.replace(/[^A-Za-z0-9+/]/g, '');
  if (clean.length % 4 === 1) clean = clean.slice(0, -1);
  clean += '='.repeat((4 - (clean.length % 4)) % 4);
  try {
    return fromBinary(atob(clean));
  } catch {
    return new Uint8Array(0);
  }
}

/** A header value with its encoded words (RFC 2047) decoded. Bytes outside
 *  an encoded word are read as UTF-8, which is what mail clients send today. */
export function decodeHeader(raw: string): string {
  const parts: string[] = [];
  const re = /=\?([^?]+)\?([BbQq])\?([^?]*)\?=/g;
  let last = 0;
  let prevEncoded = false;
  for (let m = re.exec(raw); m; m = re.exec(raw)) {
    const between = raw.slice(last, m.index);
    // Whitespace between two encoded words is not part of the text.
    if (!(prevEncoded && /^\s*$/.test(between))) parts.push(decodeCharset(fromBinary(between), 'utf-8'));
    const charset = m[1]!.split('*')[0]!;
    const bytes = m[2]!.toUpperCase() === 'B' ? decodeBase64(m[3]!) : decodeQ(m[3]!);
    parts.push(decodeCharset(bytes, charset));
    last = m.index + m[0].length;
    prevEncoded = true;
  }
  parts.push(decodeCharset(fromBinary(raw.slice(last)), 'utf-8'));
  return parts.join('').replace(/\s+/g, ' ').trim();
}

/** A structured header such as Content-Type: its value and its parameters. */
function parseParams(raw: string): { value: string; params: Map<string, string> } {
  const params = new Map<string, string>();
  const [value = '', ...rest] = raw.split(';');
  for (const piece of rest) {
    const eq = piece.indexOf('=');
    if (eq < 0) continue;
    let name = piece.slice(0, eq).trim().toLowerCase();
    let v = piece.slice(eq + 1).trim().replace(/^"(.*)"$/, '$1');
    // RFC 2231: name*=charset''percent-encoded
    if (name.endsWith('*')) {
      name = name.slice(0, -1);
      const m = /^([^']*)'[^']*'(.*)$/.exec(v);
      if (m) {
        v = decodeCharset(fromBinary(m[2]!.replace(/%([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16)))), m[1]!);
      }
    } else {
      v = decodeHeader(v);
    }
    if (!params.has(name)) params.set(name, v);
  }
  return { value: value.trim().toLowerCase(), params };
}

function decodeBody(body: string, encoding: string): Uint8Array {
  const cte = encoding.trim().toLowerCase();
  if (cte === 'base64') return decodeBase64(body);
  if (cte === 'quoted-printable') {
    return fromBinary(body.replace(/=\r?\n/g, '').replace(/=([0-9A-Fa-f]{2})/g, (_, h: string) => String.fromCharCode(parseInt(h, 16))));
  }
  return fromBinary(body);
}

function decodedSize(body: string, encoding: string): number {
  if (encoding.trim().toLowerCase() === 'base64') {
    const clean = body.replace(/[^A-Za-z0-9+/=]/g, '');
    const pad = clean.endsWith('==') ? 2 : clean.endsWith('=') ? 1 : 0;
    return Math.max(0, Math.floor((clean.length * 3) / 4) - pad);
  }
  return decodeBody(body, encoding).length;
}

/** HTML as text, through an inert document: scripts do not run and images do
 *  not load in a document made by DOMParser. */
function htmlToText(html: string): string {
  if (typeof DOMParser === 'undefined') {
    return html.replace(/<(script|style|head)[\s\S]*?<\/\1>/gi, '').replace(/<br\s*\/?>/gi, '\n').replace(/<\/(p|div|li|tr|h\d)>/gi, '\n').replace(/<[^>]+>/g, '');
  }
  const doc = new DOMParser().parseFromString(html, 'text/html');
  doc.querySelectorAll('script, style, head, title').forEach((el) => el.remove());
  doc.querySelectorAll('br').forEach((el) => el.replaceWith('\n'));
  doc.querySelectorAll('p, div, li, tr, h1, h2, h3, h4, h5, h6, blockquote').forEach((el) => el.append('\n'));
  return doc.body?.textContent ?? '';
}

interface Collected {
  plain: string | null;
  html: string | null;
  attachments: MailAttachment[];
}

function walk(headers: Headers, body: string, out: Collected, depth: number): void {
  const type = parseParams(headers.get('content-type') ?? 'text/plain');
  const disposition = parseParams(headers.get('content-disposition') ?? '');
  const encoding = headers.get('content-transfer-encoding') ?? '';
  const name = disposition.params.get('filename') ?? type.params.get('name') ?? '';

  if (type.value.startsWith('multipart/') && depth < 20) {
    const boundary = type.params.get('boundary');
    if (!boundary) return;
    const marker = `--${boundary}`;
    // Line by line: the text before the first marker is the preamble, after
    // the closing one the epilogue, and a mail cut short keeps its last part.
    const parts: string[][] = [];
    let current: string[] | null = null;
    for (const line of body.split(/\r?\n/)) {
      const bare = line.trimEnd();
      if (bare === marker) {
        if (current) parts.push(current);
        current = [];
      } else if (bare === `${marker}--`) {
        if (current) parts.push(current);
        current = null;
        break;
      } else if (current) {
        current.push(line);
      }
    }
    if (current) parts.push(current);
    for (const lines of parts) {
      const part = splitPart(lines.join('\n'));
      walk(parseHeaders(part.head), part.body, out, depth + 1);
    }
    return;
  }

  const isAttachment = disposition.value === 'attachment' || Boolean(name) || !type.value.startsWith('text/');
  if (isAttachment) {
    const fallback = type.value === 'message/rfc822' ? 'message.eml' : type.value || 'attachment';
    out.attachments.push({ name: name || fallback, size: decodedSize(body, encoding) });
    return;
  }
  const text = decodeCharset(decodeBody(body, encoding), type.params.get('charset') ?? 'utf-8');
  if (type.value === 'text/html') {
    if (out.html === null) out.html = text;
  } else if (out.plain === null) {
    out.plain = text;
  }
}

function tidy(text: string): string {
  return text
    .replace(/\r\n?/g, '\n')
    .replace(/[ \t]+\n/g, '\n')
    .replace(/\n{3,}/g, '\n\n')
    .trim();
}

export function parseEml(bytes: Uint8Array): ParsedMail {
  const { head, body } = splitPart(toBinary(bytes));
  const headers = parseHeaders(head);
  const out: Collected = { plain: null, html: null, attachments: [] };
  walk(headers, body, out, 0);
  const when = new Date(headers.get('date') ?? '');
  return {
    from: decodeHeader(headers.get('from') ?? ''),
    to: decodeHeader(headers.get('to') ?? ''),
    cc: decodeHeader(headers.get('cc') ?? ''),
    date: Number.isNaN(when.getTime()) ? '' : when.toISOString(),
    subject: decodeHeader(headers.get('subject') ?? ''),
    text: tidy(out.plain ?? (out.html !== null ? htmlToText(out.html) : '')),
    attachments: out.attachments,
  };
}
