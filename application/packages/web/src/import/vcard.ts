/**
 * vCard importer - the .vcf address-book export that Apple (iOS, macOS,
 * iCloud), Google Contacts and the AOSP Android contacts app all write, in
 * versions 2.1, 3.0 and 4.0. One hand-written parser, because no JavaScript
 * library reads 2.1 with quoted-printable, and because every trap below is
 * application knowledge rather than syntax.
 *
 * Every claim here was measured against the fixtures in tests/fixtures/vcard,
 * which are real device output rather than synthesized samples. The order of
 * the first three steps is the whole difficulty of the format:
 *
 *   1. Quoted-printable soft breaks are joined FIRST, on raw lines. Android
 *      ends a QP value with a bare `=` and continues at column one with no
 *      leading space, so the whitespace unfold below cannot see it.
 *   2. Then the whitespace unfold: a line starting with a space or tab
 *      continues the previous one. Everything else, including base64 photo
 *      walls, only exists after this step.
 *   3. Then `NAME[;params]:value`, split at the first colon outside quotes.
 *      A line with no colon, or a name that is not a property name, is
 *      counted and skipped. The parser never throws on a line; it throws
 *      only when the file holds no BEGIN:VCARD at all.
 *
 * Labels come in two dialects that share one mechanism. Apple carries a
 * label as a second line in an `itemN.` group (`item4.TEL` paired with
 * `item4.X-ABLabel`) and wraps its built-in names as `_$!<Mobile>!$_`.
 * Google writes the same groups and wrappers AND its own bare machine
 * constants (`GRAND_CENTRAL`, `DOMESTIC_PARTNER`), so "bare" does not mean
 * "the user typed this": the wrapper is unwrapped, an all-caps constant is
 * lowered with its underscores turned to spaces, and only what is left is
 * user text, kept verbatim. Where no label line exists, the TYPE parameters
 * supply one (CELL is mobile, HOME and WORK are themselves, FAX, PAGER and
 * the rest keep their word); VOICE, PREF and INTERNET are not labels.
 *
 * What lands where is the mapping table in the pillar mockup, section 7.
 * The decisions this file makes on top of it:
 *   - A photo is decoded per card and handed to the blob map under a key
 *     that is unique AND prefix-free (`contactphoto:7.jpg`, never a bare
 *     `contactphoto:7`), because the post-apply rewrite swaps the key by
 *     substring and a bare `contactphoto:1` would also match inside
 *     `contactphoto:10`. A photo that is a URL is never fetched: the line
 *     stays in `extras` and the warning counts it.
 *   - A single-valued property that appears twice keeps its first value;
 *     the surplus line goes to `extras` so its bytes survive the export.
 *     FN, N, UID and REV are the exception and never reach `extras`.
 *   - `X-ABADR` (the country whose postal layout Apple draws an address in)
 *     is consumed with its address and not stored: the country field
 *     already carries it and an ungrouped copy on export would say nothing.
 *   - `PRODID` is dropped. Writing it back would claim another app wrote
 *     our file.
 *
 * Spec: ops/docs/plans/contacts-pillar.md (section 7)
 */

import { base64ToBytes } from '@notes/shared';
import {
  BIRTHDAY_LABEL,
  buildContactBody,
  contactDisplayName,
  contactFullName,
  emptyContact,
  type Contact,
} from '../contactBody';
import { sniffImageFormat } from '../imageMetadata';
import { normalizeTag } from '../notesRepo';
import type { ImportBlob, ImportedNote, ParsedImport } from './types';

/* ------------------------------------------------------------------ */
/* Lines                                                              */
/* ------------------------------------------------------------------ */

/** One content line after unfolding, with its value still raw. */
type Line = {
  /** The name as written, group prefix and case included (`item4.TEL`). */
  raw: string;
  /** The `itemN` group, lower-cased; '' when the line has none. */
  group: string;
  /** The property name, upper-cased, without its group. */
  name: string;
  /** The parameter text between the name and the colon, verbatim. */
  params: string;
  /** TYPE values and the bare 2.1 parameters, upper-cased. */
  types: string[];
  /** Bare `X-` parameters with their case kept: a 2.1 writer's custom
   *  label (`TEL;X-Fvfgghh:` from the AOSP contacts app). */
  customTypes: string[];
  /** Named parameters other than TYPE, keys lower-cased, quotes stripped. */
  named: Map<string, string>;
  /** The value as written: unfolded, not decoded, not unescaped. */
  value: string;
};

const NAME = /^(?:([A-Za-z0-9-]+)\.)?([A-Za-z0-9-]+)$/;

/** Index of the first `ch` outside double quotes, or -1. */
function indexOutsideQuotes(s: string, ch: string, from = 0): number {
  let quoted = false;
  for (let i = from; i < s.length; i++) {
    const c = s[i];
    if (c === '"') quoted = !quoted;
    else if (c === ch && !quoted) return i;
  }
  return -1;
}

function splitOutsideQuotes(s: string, ch: string): string[] {
  const out: string[] = [];
  let start = 0;
  for (;;) {
    const i = indexOutsideQuotes(s, ch, start);
    if (i < 0) break;
    out.push(s.slice(start, i));
    start = i + 1;
  }
  out.push(s.slice(start));
  return out;
}

/** Split on `ch` where it is not escaped by a backslash; escapes stay in place. */
function splitUnescaped(s: string, ch: string): string[] {
  const out: string[] = [];
  let cur = '';
  for (let i = 0; i < s.length; i++) {
    const c = s[i]!;
    if (c === '\\' && i + 1 < s.length) {
      cur += c + s[i + 1];
      i++;
    } else if (c === ch) {
      out.push(cur);
      cur = '';
    } else {
      cur += c;
    }
  }
  out.push(cur);
  return out;
}

function parseLine(text: string): Line | null {
  const colon = indexOutsideQuotes(text, ':');
  if (colon < 0) return null;
  const head = text.slice(0, colon);
  const semi = indexOutsideQuotes(head, ';');
  const raw = (semi < 0 ? head : head.slice(0, semi)).trim();
  const m = NAME.exec(raw);
  if (!m) return null;
  const params = semi < 0 ? '' : head.slice(semi + 1);
  const types: string[] = [];
  const customTypes: string[] = [];
  const named = new Map<string, string>();
  for (const part of splitOutsideQuotes(params, ';')) {
    // `TEL;:` is a parameter list holding one empty entry. Android writes it.
    if (!part.trim()) continue;
    const eq = part.indexOf('=');
    if (eq < 0) {
      const bare = part.trim();
      types.push(bare.toUpperCase());
      if (/^X-.+/i.test(bare)) customTypes.push(bare.slice(2));
      continue;
    }
    const key = part.slice(0, eq).trim().toLowerCase();
    const value = part.slice(eq + 1).trim().replace(/^"(.*)"$/, '$1');
    if (key === 'type') {
      for (const t of value.split(',')) if (t.trim()) types.push(t.trim().toUpperCase());
    } else if (!named.has(key)) {
      named.set(key, value);
    }
  }
  return {
    raw,
    group: (m[1] ?? '').toLowerCase(),
    name: m[2]!.toUpperCase(),
    params,
    types,
    customTypes,
    named,
    value: text.slice(colon + 1),
  };
}

/* ------------------------------------------------------------------ */
/* Values                                                             */
/* ------------------------------------------------------------------ */

/** `\n` becomes a newline; `\,` `\;` `\:` and `\\` become the literal. */
function unescapeText(s: string): string {
  return s.replace(/\\([nN,;:\\])/g, (_, c: string) => (c === 'n' || c === 'N' ? '\n' : c));
}

/**
 * The file as a string with ONE character per byte. Every value keeps its
 * bytes this way until its own line says which charset they are in: a
 * Japanese 2.1 export writes raw Shift_JIS into N and SOUND, a Chinese one
 * GBK, and reading the file as UTF-8 up front would turn both into mojibake
 * before any parameter could be read.
 */
function binaryString(bytes: Uint8Array): string {
  let s = '';
  for (let i = 0; i < bytes.length; i += 0x8000) {
    s += String.fromCharCode.apply(null, bytes.subarray(i, i + 0x8000) as unknown as number[]);
  }
  return s;
}

/**
 * The file's bytes as a binary string. A UTF-16 file (a byte-order mark of
 * FF FE or FE FF, which some Windows address books write) is turned into
 * UTF-8 bytes first, so that one path reads every file.
 */
function fileBytes(bytes: Uint8Array): string {
  const utf16 =
    bytes[0] === 0xff && bytes[1] === 0xfe ? 'utf-16le' : bytes[0] === 0xfe && bytes[1] === 0xff ? 'utf-16be' : null;
  if (!utf16) return binaryString(bytes);
  const text = new TextDecoder(utf16).decode(bytes.subarray(2));
  return binaryString(new TextEncoder().encode(text));
}

/** Bytes (one per character) to text under a charset, UTF-8 when none or
 *  when the name is one the platform does not know. */
function decodeBinary(s: string, charset: string): string {
  const data = new Uint8Array(s.length);
  for (let i = 0; i < s.length; i++) data[i] = s.charCodeAt(i) & 0xff;
  try {
    return new TextDecoder(charset || 'utf-8').decode(data);
  } catch {
    return new TextDecoder().decode(data);
  }
}

/**
 * Quoted-printable to text. Literal characters mixed into the encoded run
 * are bytes already, so the whole run decodes under one charset.
 */
function decodeQuotedPrintable(s: string, charset: string): string {
  const bytes: number[] = [];
  const token = /=([0-9A-Fa-f]{2})|[\s\S]/gu;
  let m: RegExpExecArray | null;
  while ((m = token.exec(s)) !== null) {
    if (m[1] !== undefined) bytes.push(parseInt(m[1], 16));
    else bytes.push(m[0].charCodeAt(0) & 0xff);
  }
  const data = Uint8Array.from(bytes);
  try {
    return new TextDecoder(charset || 'utf-8').decode(data);
  } catch {
    return new TextDecoder().decode(data);
  }
}

function isQuotedPrintable(line: Line): boolean {
  return (line.named.get('encoding') ?? '').toUpperCase() === 'QUOTED-PRINTABLE' || line.types.includes('QUOTED-PRINTABLE');
}

/** Decode one raw piece of a line's value: transfer encoding, then escapes. */
function decode(line: Line, piece: string): string {
  const charset = line.named.get('charset') ?? '';
  const text = isQuotedPrintable(line) ? decodeQuotedPrintable(piece, charset) : decodeBinary(piece, charset);
  return unescapeText(text);
}

/** The whole value as text. */
function text(line: Line): string {
  return decode(line, line.value);
}

/**
 * A structured value's components. The split runs on the RAW value, before
 * decoding: an encoded `=3B` inside a component must not become a divider,
 * and an escaped `\;` must not either.
 */
function components(line: Line): string[] {
  return splitUnescaped(line.value, ';').map((c) => decode(line, c));
}

/* ------------------------------------------------------------------ */
/* Labels                                                             */
/* ------------------------------------------------------------------ */

const APPLE_WRAPPED = /^_\$!<(.+)>!\$_$/;

/** Apple built-in names whose lower-case form is not the label word. */
const APPLE_LABEL_WORDS: Record<string, string> = {
  homepage: 'homepage',
  homefax: 'home fax',
  workfax: 'work fax',
  iphone: 'mobile',
};

/** Google machine constants whose lowered form is not the label word. */
const GOOGLE_LABEL_WORDS: Record<string, string> = {
  HOME_PAGE: 'homepage',
};

const GOOGLE_CONSTANT = /^[A-Z][A-Z0-9_]*$/;

/** An X-ABLabel value as the label word it means. */
function decodeLabel(raw: string): string {
  const label = unescapeText(raw).trim();
  const wrapped = APPLE_WRAPPED.exec(label);
  if (wrapped) {
    // `AssistantPhone` reads as "assistant phone"; the table keys the
    // few names whose spaced form is still not the label word.
    const inner = wrapped[1]!.replace(/([a-z])([A-Z])/g, '$1 $2').toLowerCase();
    // Own property only: the label comes out of the file, and an inherited one
    // answers with a function, which reaches contactBody and throws there.
    const key = inner.replace(/ /g, '');
    return Object.hasOwn(APPLE_LABEL_WORDS, key) ? APPLE_LABEL_WORDS[key]! : inner;
  }
  if (GOOGLE_CONSTANT.test(label)) {
    const spaced = label.toLowerCase().replace(/_/g, ' ');
    return Object.hasOwn(GOOGLE_LABEL_WORDS, label) ? GOOGLE_LABEL_WORDS[label]! : spaced;
  }
  return label;
}

const TYPE_PLACE: Record<string, string> = { HOME: 'home', WORK: 'work' };
const TYPE_KIND: Record<string, string> = {
  CELL: 'mobile',
  IPHONE: 'mobile',
  MAIN: 'main',
  FAX: 'fax',
  PAGER: 'pager',
  OTHER: 'other',
  CAR: 'car',
  ISDN: 'isdn',
  TLX: 'tlx',
  MSG: 'msg',
};

/** The label the TYPE parameters spell: place first, then kind (`work fax`),
 *  else a 2.1 writer's custom `X-` type as typed. */
function labelFromTypes(types: string[], customTypes: string[]): string {
  const words: string[] = [];
  for (const table of [TYPE_PLACE, TYPE_KIND]) {
    for (const t of types) {
      const w = table[t];
      if (w && !words.includes(w)) words.push(w);
    }
  }
  if (words.length === 0 && customTypes[0]) return customTypes[0];
  return words.join(' ');
}

/* ------------------------------------------------------------------ */
/* Photos                                                             */
/* ------------------------------------------------------------------ */

type PhotoSink = {
  blobs: Map<string, ImportBlob>;
  decoded: number;
  failed: number;
  links: number;
};

const IMAGE_MIME: Record<string, { mime: string; ext: string }> = {
  jpeg: { mime: 'image/jpeg', ext: 'jpg' },
  png: { mime: 'image/png', ext: 'png' },
  gif: { mime: 'image/gif', ext: 'gif' },
  webp: { mime: 'image/webp', ext: 'webp' },
  bmp: { mime: 'image/bmp', ext: 'bmp' },
  tiff: { mime: 'image/tiff', ext: 'tiff' },
  heic: { mime: 'image/heic', ext: 'heic' },
};

/** The image format a TYPE or MEDIATYPE parameter names (`JPEG`, `image/png`). */
function declaredFormat(line: Line, dataUriMime: string): string {
  const candidates = [dataUriMime, line.named.get('mediatype') ?? '', ...line.types];
  for (const c of candidates) {
    const word = c.toLowerCase().replace(/^image\//, '').replace(/^jpg$/, 'jpeg').replace(/^tif$/, 'tiff');
    // Own property only: the word comes out of the file, and `constructor`
    // is on every plain object, so `in` answered yes and the read below
    // handed back a function where a mime string was expected.
    if (Object.hasOwn(IMAGE_MIME, word)) return word;
  }
  return '';
}

/**
 * The bytes of an embedded photo, 'link' for a URL the parser will not
 * fetch, null for a value that does not decode to a known image.
 */
function decodePhoto(line: Line): { data: Uint8Array; mime: string; ext: string } | 'link' | null {
  let b64 = line.value.trim();
  let dataUriMime = '';
  const dataUri = /^data:([^;,]*)((?:;[^;,]*)*),(.*)$/s.exec(b64);
  if (dataUri) {
    if (!/;base64/i.test(dataUri[2] ?? '')) return null;
    dataUriMime = dataUri[1] ?? '';
    b64 = dataUri[3] ?? '';
  } else if ((line.named.get('value') ?? '').toLowerCase() === 'uri' || /^[a-z][a-z0-9+.-]*:\/\//i.test(b64)) {
    return 'link';
  }
  let data: Uint8Array;
  try {
    data = base64ToBytes(b64.replace(/\s+/g, ''));
  } catch {
    return null;
  }
  if (data.length === 0) return null;
  const sniffed = sniffImageFormat(data);
  const format = sniffed === 'unknown' ? declaredFormat(line, dataUriMime) : sniffed;
  const kind = Object.hasOwn(IMAGE_MIME, format) ? IMAGE_MIME[format] : undefined;
  return kind ? { data, ...kind } : null;
}

/* ------------------------------------------------------------------ */
/* Cards                                                              */
/* ------------------------------------------------------------------ */

/** `X-` chat properties and the service word each one means. */
const IM_SERVICE: Record<string, string> = {
  'X-AIM': 'aim',
  'X-MSN': 'msn',
  'X-ICQ': 'icq',
  'X-JABBER': 'jabber',
  'X-YAHOO': 'yahoo',
  'X-QQ': 'qq',
  'X-SKYPE': 'skype',
  'X-SKYPE-USERNAME': 'skype',
  'X-GTALK': 'googletalk',
  'X-GOOGLE-TALK': 'googletalk',
  'X-SIP': 'sip',
  'X-WHATSAPP': 'whatsapp',
};

/** Properties whose `itemN.X-ABLabel` sibling is their label. */
const LABELLED = new Set([
  'TEL',
  'EMAIL',
  'URL',
  'ADR',
  'X-ABDATE',
  'X-ABRELATEDNAMES',
  'IMPP',
  'X-SOCIALPROFILE',
  'RELATED',
  ...Object.keys(IM_SERVICE),
]);

const ANDROID_CUSTOM = 'vnd.android.cursor.item/';

/** ContactsContract relation types, index = the DATA2 value; 0 is custom. */
const ANDROID_RELATION = [
  '',
  'assistant',
  'brother',
  'child',
  'domestic partner',
  'father',
  'friend',
  'manager',
  'mother',
  'parent',
  'partner',
  'referred by',
  'relative',
  'sister',
  'spouse',
];

/** ContactsContract event types, index = the DATA2 value; 0 is custom. */
const ANDROID_EVENT = ['', 'anniversary', 'other', BIRTHDAY_LABEL];

type Card = { contact: Contact; fn: string; tags: string[]; rev: string };

function readCard(lines: Line[], sink: PhotoSink): Card {
  const c = emptyContact();
  const tags: string[] = [];
  const notes: string[] = [];
  let fn = '';
  let rev = '';

  // Labels by group, and the groups whose label a modelled property takes.
  // A label left over in a group of unmodelled lines stays with them in
  // `extras`, verbatim, so the export keeps the pair together.
  const labels = new Map<string, string>();
  const taken = new Set<string>();
  const present = new Set<string>();
  for (const l of lines) {
    present.add(l.name);
    if (!l.group) continue;
    if (l.name === 'X-ABLABEL') labels.set(l.group, decodeBinary(l.value, l.named.get('charset') ?? ''));
    else if (LABELLED.has(l.name)) taken.add(l.group);
  }
  const groupLabel = (l: Line): string | undefined => {
    const raw = l.group ? labels.get(l.group) : undefined;
    return raw === undefined ? undefined : decodeLabel(raw);
  };
  const labelOf = (l: Line): string => groupLabel(l) ?? labelFromTypes(l.types, l.customTypes);

  // Single-valued properties keep their first value.
  const seen = new Set<string>();
  const first = (l: Line): boolean => {
    if (seen.has(l.name)) return false;
    seen.add(l.name);
    return true;
  };

  const androidCustom = (l: Line): boolean => {
    const [kind = '', data1 = '', data2 = '', data3 = ''] = components(l);
    if (!kind.startsWith(ANDROID_CUSTOM)) return false;
    const record = kind.slice(ANDROID_CUSTOM.length);
    const type = /^\d+$/.test(data2.trim()) ? Number(data2) : -1;
    if (record === 'nickname') {
      c.nickname = [c.nickname, data1.trim()].filter(Boolean).join(', ');
      return true;
    }
    if (record === 'contact_event') {
      const label = type === 0 ? data3.trim() : (ANDROID_EVENT[type] ?? '');
      c.dates.push({ label, value: data1 });
      return true;
    }
    if (record === 'relation') {
      const label = type === 0 ? data3.trim() : (ANDROID_RELATION[type] ?? '');
      c.related.push({ label, value: data1 });
      return true;
    }
    return false;
  };

  const photo = (l: Line): boolean => {
    if (c.photo) return false;
    const decoded = decodePhoto(l);
    if (decoded === 'link') {
      sink.links++;
      return false;
    }
    if (!decoded) {
      sink.failed++;
      return true;
    }
    const key = `contactphoto:${++sink.decoded}.${decoded.ext}`;
    sink.blobs.set(key, {
      data: decoded.data,
      mime: decoded.mime,
      name: `photo.${decoded.ext}`,
      ceiling: 'contact',
    });
    c.photo = key;
    return true;
  };

  /** Place one line in the contact. False means it belongs in `extras`. */
  const place = (l: Line): boolean => {
    switch (l.name) {
      case 'BEGIN':
      case 'END':
      case 'VERSION':
      case 'PRODID':
      case 'X-ABADR':
        return true;
      case 'X-ABLABEL':
        return l.group !== '' && taken.has(l.group);
      case 'FN':
        if (first(l)) fn = text(l).trim();
        return true;
      case 'N': {
        if (!first(l)) return true;
        const [last = '', firstName = '', middle = '', prefix = '', suffix = ''] = components(l);
        Object.assign(c, { last, first: firstName, middle, prefix, suffix });
        return true;
      }
      case 'UID':
        if (first(l)) c.uid = text(l).trim();
        return true;
      case 'REV':
        if (first(l)) rev = text(l).trim();
        return true;
      case 'NICKNAME':
        c.nickname = [c.nickname, text(l).trim()].filter(Boolean).join(', ');
        return true;
      case 'SOUND': {
        // Japanese phones write the reading (furigana) here, last;first, and
        // it is how their address books sort and find a person.
        if (!l.types.includes('X-IRMC-N') || !first(l)) return false;
        const [last = '', firstName = ''] = components(l);
        c.phonetic.last = c.phonetic.last || last.trim();
        c.phonetic.first = c.phonetic.first || firstName.trim();
        return true;
      }
      case 'ORG': {
        if (!first(l)) return false;
        const [org = '', ...rest] = components(l);
        c.org = org;
        c.department = rest.map((s) => s.trim()).filter(Boolean).join(', ');
        return true;
      }
      case 'TITLE':
        if (!first(l)) return false;
        c.jobTitle = text(l);
        return true;
      case 'ROLE':
        if (present.has('TITLE') || !first(l)) return false;
        c.jobTitle = text(l);
        return true;
      case 'NOTE':
        notes.push(text(l));
        return true;
      case 'X-PHONETIC-FIRST-NAME':
        if (!first(l)) return false;
        c.phonetic.first = text(l);
        return true;
      case 'X-PHONETIC-MIDDLE-NAME':
        if (!first(l)) return false;
        c.phonetic.middle = text(l);
        return true;
      case 'X-PHONETIC-LAST-NAME':
        if (!first(l)) return false;
        c.phonetic.last = text(l);
        return true;
      case 'TEL':
        c.phones.push({ label: labelOf(l), value: text(l) });
        return true;
      case 'EMAIL':
        c.emails.push({ label: labelOf(l), value: text(l) });
        return true;
      case 'URL':
        // iPhone percent-encodes a stray line break at the end of a URL.
        c.urls.push({ label: labelOf(l), value: text(l).replace(/(?:%0[AD])+$/i, '') });
        return true;
      case 'ADR': {
        const [pobox = '', extended = '', street = '', city = '', region = '', postal = '', country = ''] = components(l);
        c.addresses.push({
          label: labelOf(l),
          street: [pobox, extended, street].filter((s) => s.trim()).join('\n'),
          city,
          region,
          postal,
          country,
        });
        return true;
      }
      case 'BDAY':
        if (!first(l)) return false;
        c.dates.push({ label: BIRTHDAY_LABEL, value: text(l) });
        return true;
      case 'ANNIVERSARY':
        c.dates.push({ label: 'anniversary', value: text(l) });
        return true;
      case 'X-ABDATE':
        c.dates.push({ label: labelOf(l), value: text(l) });
        return true;
      case 'X-ABRELATEDNAMES':
        c.related.push({ label: labelOf(l), value: text(l) });
        return true;
      case 'RELATED':
        c.related.push({
          label: groupLabel(l) ?? l.types.filter((t) => t !== 'PREF').map((t) => t.toLowerCase()).join(' '),
          value: text(l),
        });
        return true;
      case 'IMPP': {
        const value = text(l);
        const service = l.named.get('x-service-type');
        const scheme = value.includes(':') ? value.slice(0, value.indexOf(':')) : '';
        const label = (service || groupLabel(l) || scheme).toLowerCase();
        c.profiles.push({ label, value });
        return true;
      }
      case 'X-SOCIALPROFILE': {
        const service = l.types.find((t) => t !== 'PREF') ?? '';
        c.profiles.push({ label: service.toLowerCase(), value: text(l) });
        return true;
      }
      case 'X-ANDROID-CUSTOM':
        return androidCustom(l);
      case 'PHOTO':
        return photo(l);
      case 'CATEGORIES':
        for (const part of splitUnescaped(l.value, ',')) {
          const tag = normalizeTag(decode(l, part));
          if (tag && !tags.includes(tag)) tags.push(tag);
        }
        return true;
      default: {
        // Own property only. The property name is a stranger's, and the
        // uppercasing it goes through is not what makes this safe.
        const service = Object.hasOwn(IM_SERVICE, l.name) ? IM_SERVICE[l.name] : undefined;
        if (!service) return false;
        c.profiles.push({ label: service, value: text(l) });
        return true;
      }
    }
  };

  for (const l of lines) {
    if (!place(l)) {
      const charset = l.named.get('charset') ?? '';
      c.extras.push({ name: l.raw, params: decodeBinary(l.params, charset), value: decodeBinary(l.value, charset) });
    }
  }
  // A card can carry the same row twice: an iPhone export writes a URL once
  // with and once without its stray line break. An identical second copy
  // says nothing, so it is dropped; the same value under another label stays.
  // Phone numbers are left alone, duplicates included.
  for (const key of ['emails', 'urls', 'profiles'] as const) {
    const seen = new Set<string>();
    c[key] = c[key].filter((r) => {
      const id = `${r.label}\u0000${r.value}`;
      if (seen.has(id)) return false;
      seen.add(id);
      return true;
    });
  }
  c.notes = notes.join('\n');
  return { contact: c, fn, tags, rev };
}

/* ------------------------------------------------------------------ */
/* File                                                               */
/* ------------------------------------------------------------------ */

/**
 * A REV stamp as ISO 8601, in the shapes seen: `2015-01-19T09:25:56Z`,
 * `20150119T092556Z`, a bare date, an offset instead of Z. Anything else
 * yields the fallback.
 */
function revToIso(rev: string, fallback: string): string {
  const m = /^(\d{4})-?(\d{2})-?(\d{2})(?:T(\d{2}):?(\d{2}):?(\d{2})(?:\.\d+)?(Z|[+-]\d{2}:?\d{2})?)?$/i.exec(rev);
  if (!m) return fallback;
  const zone = (m[7] ?? 'Z').replace(/^([+-]\d{2})(\d{2})$/, '$1:$2');
  const t = Date.parse(`${m[1]}-${m[2]}-${m[3]}T${m[4] ?? '00'}:${m[5] ?? '00'}:${m[6] ?? '00'}${zone}`);
  return Number.isNaN(t) ? fallback : new Date(t).toISOString();
}

const QP_LINE = /^[^:]*;(?:ENCODING=)?QUOTED-PRINTABLE(?:[;:]|$)/i;

/**
 * Raw file text to content lines: soft breaks joined, then folded lines
 * unfolded. Returns the lines and the count of lines nothing could attach.
 */
/** A physical line that starts a property, as opposed to a bare value line. */
const PROPERTY_START = /^(?:[A-Za-z0-9-]+\.)?[A-Za-z][A-Za-z0-9-]*[;:]/;

/** An odd run of backslashes at the end of a line: a 2.1 writer's value break. */
const BACKSLASH_BREAK = /(?<!\\)(?:\\\\)*\\$/;

function unfold(raw: string): { lines: string[]; orphans: number } {
  // Old iOS ended every folded photo line with CR CR LF; the second CR must
  // not become an empty line between a value and its continuation.
  const physical = raw.replace(/^\xEF\xBB\xBF/, '').replace(/\r\r\n/g, '\r\n').split(/\r\n|\r|\n/);
  const joined: string[] = [];
  for (let i = 0; i < physical.length; i++) {
    let line = physical[i]!;
    if (QP_LINE.test(line)) {
      while (line.endsWith('=') && i + 1 < physical.length) line = line.slice(0, -1) + physical[++i]!;
    }
    // The AOSP contacts app breaks a long 2.1 value with a bare backslash at
    // the end of the line; the break is a newline inside the value.
    while (BACKSLASH_BREAK.test(line) && i + 1 < physical.length && !PROPERTY_START.test(physical[i + 1]!)) {
      line = line.slice(0, -1) + '\\n' + physical[++i]!;
    }
    joined.push(line);
  }
  const lines: string[] = [];
  let orphans = 0;
  for (const line of joined) {
    if (line.startsWith(' ') || line.startsWith('\t')) {
      if (lines.length === 0) orphans++;
      else lines[lines.length - 1] += line.slice(1);
    } else if (line === '') {
      // Nothing to keep, and a fold after it belongs to the value above.
      continue;
    } else {
      lines.push(line);
    }
  }
  return { lines, orphans };
}

function count(n: number, singular: string, plural: string): string {
  return `${n} ${n === 1 ? singular : plural}`;
}

export async function parseVcard(file: File, onProgress?: (msg: string) => void): Promise<ParsedImport> {
  onProgress?.('Reading file…');
  const { lines, orphans } = unfold(fileBytes(new Uint8Array(await file.arrayBuffer())));

  // Cards, as raw lines. A card that never closes ends with the file.
  const cards: string[][] = [];
  let current: string[] | null = null;
  let unread = orphans;
  for (const line of lines) {
    if (/^BEGIN:VCARD\s*$/i.test(line)) {
      if (current) cards.push(current);
      current = [];
    } else if (/^END:VCARD\s*$/i.test(line)) {
      if (current) cards.push(current);
      else unread++;
      current = null;
    } else if (!line.trim()) {
      continue;
    } else if (current) {
      current.push(line);
    } else {
      unread++;
    }
  }
  if (current) cards.push(current);
  if (cards.length === 0) {
    throw new Error('Not a vCard file - expected at least one BEGIN:VCARD.');
  }

  const now = new Date().toISOString();
  const sink: PhotoSink = { blobs: new Map(), decoded: 0, failed: 0, links: 0 };
  const notes: ImportedNote[] = [];
  const allTags = new Set<string>();
  let empty = 0;
  let untagged = 0;

  for (let i = 0; i < cards.length; i++) {
    const parsed: Line[] = [];
    for (const text of cards[i]!) {
      const line = parseLine(text);
      if (line) parsed.push(line);
      else unread++;
    }
    const { contact, fn, tags, rev } = readCard(parsed, sink);
    const title = fn || contactDisplayName('', contact).trim();
    if (!fn && !contactFullName(contact) && contact.phones.length === 0 && contact.emails.length === 0) empty++;
    if (tags.length === 0) untagged++;
    for (const t of tags) allTags.add(t);
    const stamp = revToIso(rev, now);
    notes.push({
      title,
      body: buildContactBody(contact),
      tags,
      createdAt: stamp,
      updatedAt: stamp,
      type: 'contact',
    });
    if ((i + 1) % 200 === 0) onProgress?.(`Reading contacts… ${i + 1} of ${cards.length}`);
  }

  const warnings: string[] = [];
  if (unread > 0) {
    warnings.push(`${count(unread, 'line', 'lines')} could not be read and ${unread === 1 ? 'was' : 'were'} skipped.`);
  }
  if (sink.failed > 0) {
    warnings.push(
      `${count(sink.failed, 'photo', 'photos')} could not be decoded and ${sink.failed === 1 ? 'was' : 'were'} left out.`,
    );
  }
  if (sink.links > 0) {
    warnings.push(
      `${count(sink.links, 'photo was a web link', 'photos were web links')}, not a picture. Nothing was downloaded; the link stays with the contact.`,
    );
  }
  const transforms: string[] = [];
  if (sink.decoded > 0) {
    transforms.push(`${count(sink.decoded, 'contact photo', 'contact photos')} decoded from the file.`);
  }

  return {
    notes,
    warnings,
    transforms,
    stats: {
      totalNotes: notes.length,
      emptyNotes: empty,
      untaggedNotes: untagged,
      uniqueTags: allTags.size,
    },
    source: 'vcard',
    ...(sink.blobs.size > 0
      ? { blobs: sink.blobs, blobBytes: [...sink.blobs.values()].reduce((sum, b) => sum + b.data.length, 0) }
      : {}),
  };
}
