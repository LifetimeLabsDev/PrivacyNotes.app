/**
 * vCard 3.0 writer for the Contacts pillar - the file the export hands back
 * to the phone an address book came from.
 *
 * 3.0 rather than 4.0 because it is what Apple and Google both read, and
 * what their own exports are. Labels are written in Apple's dialect, which
 * Google reads as well:
 *   - A label the format has a TYPE for becomes that parameter: `mobile`
 *     is `TYPE=CELL`, `home` and `work` are themselves, and a two-word
 *     label such as `work fax` becomes both parameters.
 *   - A built-in name with no TYPE (homepage, anniversary, mother and the
 *     rest) becomes an `itemN.` group whose `X-ABLabel` carries the wrapped
 *     `_$!<Name>!$_` form.
 *   - Anything else is a custom label, written bare in the same pair.
 * Groups are numbered per card, starting past any `itemN.` an `extras` line
 * already uses, so a re-emitted line never collides with a generated one.
 *
 * Written: the name, the organisation, every labelled row, the notes, the
 * tags as CATEGORIES, REV from the note's modified time, the stored UID,
 * and every `extras` line verbatim. Not written: the photo, which lives in
 * the app's blob store where this writer has no bytes in hand, and PRODID
 * from the source, which would claim another app wrote this file.
 *
 * Lines end in CRLF and fold at 75 octets on character boundaries, so a
 * multi-byte character is never cut.
 *
 * Spec: ops/docs/plans/contacts-pillar.md (section 8)
 */

import { BIRTHDAY_LABEL, contactDisplayName, parseContactBody } from './contactBody';

/** What the writer needs from a contact note. */
export type VcardSource = { title: string; body: string; tags: string[]; updatedAt: string };

/** The labels each property carries as TYPE parameters. */
const TEL_TYPES: Record<string, string> = {
  home: 'HOME',
  work: 'WORK',
  mobile: 'CELL',
  main: 'MAIN',
  fax: 'FAX',
  pager: 'PAGER',
  other: 'OTHER',
  car: 'CAR',
  isdn: 'ISDN',
  tlx: 'TLX',
  msg: 'MSG',
};
const EMAIL_TYPES: Record<string, string> = { home: 'HOME', work: 'WORK' };
const ADR_TYPES: Record<string, string> = { home: 'HOME', work: 'WORK', other: 'OTHER' };
const URL_TYPES: Record<string, string> = { home: 'HOME', work: 'WORK' };
const NO_TYPES: Record<string, string> = {};

/** Apple's built-in label names, written wrapped as `_$!<Name>!$_`. */
const APPLE_NAMES: Record<string, string> = {
  home: 'Home',
  work: 'Work',
  other: 'Other',
  mobile: 'Mobile',
  main: 'Main',
  homepage: 'HomePage',
  'home fax': 'HomeFAX',
  'work fax': 'WorkFAX',
  anniversary: 'Anniversary',
  mother: 'Mother',
  father: 'Father',
  parent: 'Parent',
  brother: 'Brother',
  sister: 'Sister',
  child: 'Child',
  friend: 'Friend',
  spouse: 'Spouse',
  partner: 'Partner',
  assistant: 'Assistant',
  'assistant phone': 'AssistantPhone',
  manager: 'Manager',
};

/**
 * Chat services, with the X-SERVICE-TYPE spelling Apple writes for each;
 * a profile with any other label is written as a social profile.
 */
const CHAT_SERVICES: Record<string, string> = {
  skype: 'Skype',
  jabber: 'Jabber',
  xmpp: 'XMPP',
  msn: 'MSN',
  aim: 'AIM',
  icq: 'ICQ',
  yahoo: 'Yahoo',
  googletalk: 'GoogleTalk',
  qq: 'QQ',
  gadugadu: 'GaduGadu',
  whatsapp: 'WhatsApp',
  signal: 'Signal',
  telegram: 'Telegram',
  wechat: 'WeChat',
  line: 'LINE',
  viber: 'Viber',
  matrix: 'Matrix',
  threema: 'Threema',
  sip: 'SIP',
  irc: 'IRC',
};

const FOLD_OCTETS = 75;

/** Text escaping per 3.0: backslash first, then newline, comma, semicolon. */
function escapeText(s: string): string {
  return s
    .replace(/\r\n?/g, '\n')
    .replace(/\\/g, '\\\\')
    .replace(/\n/g, '\\n')
    .replace(/,/g, '\\,')
    .replace(/;/g, '\\;');
}

/** A parameter value, quoted when it holds a character that would end it early. */
function paramValue(s: string): string {
  const clean = s.replace(/["\r\n]/g, '');
  return /[;:,]/.test(clean) ? `"${clean}"` : clean;
}

function utf8Length(ch: string): number {
  const cp = ch.codePointAt(0)!;
  return cp < 0x80 ? 1 : cp < 0x800 ? 2 : cp < 0x10000 ? 3 : 4;
}

/** Fold one logical line into physical lines of at most 75 octets. */
function fold(line: string): string[] {
  const out: string[] = [];
  let cur = '';
  let octets = 0;
  for (const ch of line) {
    const n = utf8Length(ch);
    if (octets + n > FOLD_OCTETS) {
      out.push(cur);
      cur = ' ';
      octets = 1;
    }
    cur += ch;
    octets += n;
  }
  out.push(cur);
  return out;
}

/** `20150119T092556Z`, or null when the stamp does not parse. */
function formatRev(updatedAt: string): string | null {
  const t = Date.parse(updatedAt);
  if (Number.isNaN(t)) return null;
  return new Date(t).toISOString().replace(/[-:]/g, '').replace(/\.\d{3}Z$/, 'Z');
}

function buildCard(source: VcardSource): string[] {
  const c = parseContactBody(source.body);
  const lines: string[] = ['BEGIN:VCARD', 'VERSION:3.0', 'PRODID:-//PrivacyNotes//EN'];

  let group = 0;
  for (const e of c.extras) {
    const m = /^item(\d+)\./i.exec(e.name);
    if (m) group = Math.max(group, Number(m[1]));
  }

  /** One labelled property, in whichever of the three label forms fits. */
  const labelled = (name: string, label: string, value: string, types: Record<string, string>) => {
    if (!label) {
      lines.push(`${name}:${value}`);
      return;
    }
    const words = label.split(' ').map((w) => types[w]);
    if (words.every(Boolean)) {
      lines.push(`${name};${words.map((t) => `TYPE=${t}`).join(';')}:${value}`);
      return;
    }
    const item = `item${++group}`;
    const apple = APPLE_NAMES[label];
    lines.push(`${item}.${name}:${value}`);
    lines.push(`${item}.X-ABLabel:${apple ? `_$!<${apple}>!$_` : escapeText(label)}`);
  };

  const fn = contactDisplayName(source.title, c);
  if (fn) lines.push(`FN:${escapeText(fn)}`);
  lines.push(`N:${[c.last, c.first, c.middle, c.prefix, c.suffix].map(escapeText).join(';')}`);
  if (c.nickname) lines.push(`NICKNAME:${escapeText(c.nickname)}`);
  if (c.org || c.department) {
    lines.push(`ORG:${escapeText(c.org)}${c.department ? `;${escapeText(c.department)}` : ''}`);
  }
  if (c.jobTitle) lines.push(`TITLE:${escapeText(c.jobTitle)}`);
  if (c.phonetic.first) lines.push(`X-PHONETIC-FIRST-NAME:${escapeText(c.phonetic.first)}`);
  if (c.phonetic.middle) lines.push(`X-PHONETIC-MIDDLE-NAME:${escapeText(c.phonetic.middle)}`);
  if (c.phonetic.last) lines.push(`X-PHONETIC-LAST-NAME:${escapeText(c.phonetic.last)}`);

  for (const p of c.phones) labelled('TEL', p.label, escapeText(p.value), TEL_TYPES);
  for (const e of c.emails) labelled('EMAIL', e.label, escapeText(e.value), EMAIL_TYPES);
  for (const u of c.urls) labelled('URL', u.label, escapeText(u.value), URL_TYPES);
  for (const a of c.addresses) {
    const value = `;;${[a.street, a.city, a.region, a.postal, a.country].map(escapeText).join(';')}`;
    labelled('ADR', a.label, value, ADR_TYPES);
  }

  let birthday = false;
  for (const d of c.dates) {
    if (d.label === BIRTHDAY_LABEL && !birthday) {
      birthday = true;
      lines.push(`BDAY:${escapeText(d.value)}`);
    } else {
      labelled('X-ABDATE', d.label, escapeText(d.value), NO_TYPES);
    }
  }
  for (const r of c.related) labelled('X-ABRELATEDNAMES', r.label, escapeText(r.value), NO_TYPES);
  for (const p of c.profiles) {
    const chat = CHAT_SERVICES[p.label];
    if (chat) lines.push(`IMPP;X-SERVICE-TYPE=${chat}:${escapeText(p.value)}`);
    else if (p.label) lines.push(`X-SOCIALPROFILE;type=${paramValue(p.label)}:${escapeText(p.value)}`);
    else lines.push(`X-SOCIALPROFILE:${escapeText(p.value)}`);
  }

  if (c.notes) lines.push(`NOTE:${escapeText(c.notes)}`);
  if (source.tags.length > 0) lines.push(`CATEGORIES:${source.tags.map(escapeText).join(',')}`);
  const rev = formatRev(source.updatedAt);
  if (rev) lines.push(`REV:${rev}`);
  if (c.uid) lines.push(`UID:${escapeText(c.uid)}`);
  for (const e of c.extras) lines.push(`${e.name}${e.params ? `;${e.params}` : ''}:${e.value}`);
  lines.push('END:VCARD');
  return lines;
}

/** One vCard 3.0 file holding every contact given, in order. */
export function buildVcardFile(contacts: VcardSource[]): string {
  return contacts.map((c) => `${buildCard(c).flatMap(fold).join('\r\n')}\r\n`).join('');
}
