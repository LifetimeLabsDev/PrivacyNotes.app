/**
 * Contact ('contact') note body helpers - the single source of truth for
 * how a contact stores and displays its fields.
 *
 * A contact is a note with `type: 'contact'` whose body is a JSON document,
 * mirroring the vault's login body and the bookmark body. The display name
 * lives in the note's own `title`, because sorting, search, the list row
 * and note-links all read `title`. Everything else is in the body, in three
 * tiers: the fields the form always shows, the fields it shows only when
 * present, and `extras`, one row per vCard line the app does not model,
 * kept with its parameters so the export can write it back unchanged.
 *
 * Rules the whole pillar leans on:
 *   - Empty is absent. A field the contact does not have is not a key with
 *     an empty string; `buildContactBody` drops blanks and blank rows.
 *   - A phone number is stored exactly as typed or imported. The digits-only
 *     copy exists for the search index and the `tel:` link, nowhere else.
 *   - A date is a string. `--03-14` with no year is legal and common, and
 *     Apple writes the year 1604 to mean "none given".
 *   - Labels are free strings. The picker suggests a vocabulary; whatever
 *     the source said is kept, including a custom label.
 *
 * Spec: ops/docs/plans/contacts-pillar.md (section 5)
 */

/** A labelled value: a phone, an email, a website, a profile, a date, a related name. */
export type ContactLabelled = { label: string; value: string };

/**
 * A postal address. `street` holds the whole address as a multi-line blob
 * when that is all the source had (Android writes it that way), and the
 * form renders such an address without demanding the user split it.
 */
export type ContactAddress = {
  label: string;
  street: string;
  city: string;
  region: string;
  postal: string;
  country: string;
};

/** One vCard line the app does not model, kept verbatim for the export. */
type ContactExtra = { name: string; params: string; value: string };

/** The stored body, every field optional. */
type ContactBody = {
  first?: string;
  last?: string;
  phones?: ContactLabelled[];
  emails?: ContactLabelled[];
  /** The stored photo as its `pn:img/<uuid>` reference, so the blob GC that
   *  scans note bodies for that form tracks it like an editor image. */
  photo?: string;
  /** The stored photo's size in bytes, so a row's size and the size sort
   *  count the picture without a database read per note. */
  photoBytes?: number;
  middle?: string;
  prefix?: string;
  suffix?: string;
  nickname?: string;
  phonetic?: { first?: string; middle?: string; last?: string };
  org?: string;
  department?: string;
  jobTitle?: string;
  addresses?: ContactAddress[];
  urls?: ContactLabelled[];
  /** Chat and social alike, one shape: label is the service, value the handle. */
  profiles?: ContactLabelled[];
  /** The birthday is the row labelled `birthday`. */
  dates?: ContactLabelled[];
  related?: ContactLabelled[];
  notes?: string;
  extras?: ContactExtra[];
  /** Import bookkeeping for the re-import matcher. Never rendered. */
  uid?: string;
};

/** The runtime shape: every list present, every string present, so a
 *  renderer never checks for undefined. */
export type Contact = {
  first: string;
  last: string;
  phones: ContactLabelled[];
  emails: ContactLabelled[];
  photo: string;
  photoBytes: number;
  middle: string;
  prefix: string;
  suffix: string;
  nickname: string;
  phonetic: { first: string; middle: string; last: string };
  org: string;
  department: string;
  jobTitle: string;
  addresses: ContactAddress[];
  urls: ContactLabelled[];
  profiles: ContactLabelled[];
  dates: ContactLabelled[];
  related: ContactLabelled[];
  notes: string;
  extras: ContactExtra[];
  uid: string;
  /** Stored keys this version does not model, kept as they were read. A newer
   *  version can add a field and an older one will hand it back untouched. */
  carried: Record<string, unknown>;
};

/** Every key this version models, and the reason `carried` can exist: a stored
 *  key that is not in here was written by a version that knows more than this
 *  one. Kept in step with `buildContactBody` by tests/contactBody.test.ts. */
const MODELLED_KEYS = new Set([
  'first', 'last', 'phones', 'emails', 'photo', 'photoBytes', 'middle', 'prefix',
  'suffix', 'nickname', 'phonetic', 'org', 'department', 'jobTitle', 'addresses',
  'urls', 'profiles', 'dates', 'related', 'notes', 'extras', 'uid',
]);

/** Keys that are never carried, whatever a body holds: assigning one of them
 *  onto a plain object rewrites its prototype rather than adding a field, and a
 *  body arrives from a server this app does not trust. */
const NEVER_CARRIED = new Set(['__proto__', 'constructor', 'prototype']);

/** The label the picker suggests first for each kind of row. */
export const CONTACT_LABELS = ['mobile', 'home', 'work', 'main', 'other'] as const;

/** The date label the form treats as the birthday row. */
export const BIRTHDAY_LABEL = 'birthday';

export function emptyContact(): Contact {
  return {
    first: '',
    last: '',
    phones: [],
    emails: [],
    photo: '',
    photoBytes: 0,
    middle: '',
    prefix: '',
    suffix: '',
    nickname: '',
    phonetic: { first: '', middle: '', last: '' },
    org: '',
    department: '',
    jobTitle: '',
    addresses: [],
    urls: [],
    profiles: [],
    dates: [],
    related: [],
    notes: '',
    extras: [],
    uid: '',
    carried: {},
  };
}

function str(v: unknown): string {
  return typeof v === 'string' ? v : '';
}

function labelledList(v: unknown): ContactLabelled[] {
  if (!Array.isArray(v)) return [];
  const out: ContactLabelled[] = [];
  for (const row of v) {
    if (!row || typeof row !== 'object') continue;
    const r = row as Record<string, unknown>;
    const value = str(r.value);
    if (!value) continue;
    out.push({ label: str(r.label), value });
  }
  return out;
}

function addressList(v: unknown): ContactAddress[] {
  if (!Array.isArray(v)) return [];
  const out: ContactAddress[] = [];
  for (const row of v) {
    if (!row || typeof row !== 'object') continue;
    const r = row as Record<string, unknown>;
    const a: ContactAddress = {
      label: str(r.label),
      street: str(r.street),
      city: str(r.city),
      region: str(r.region),
      postal: str(r.postal),
      country: str(r.country),
    };
    if (isAddressEmpty(a)) continue;
    out.push(a);
  }
  return out;
}

function extraList(v: unknown): ContactExtra[] {
  if (!Array.isArray(v)) return [];
  const out: ContactExtra[] = [];
  for (const row of v) {
    if (!row || typeof row !== 'object') continue;
    const r = row as Record<string, unknown>;
    const name = str(r.name);
    if (!name) continue;
    out.push({ name, params: str(r.params), value: str(r.value) });
  }
  return out;
}

/** Parse a stored body. A body that does not parse yields an empty contact. */
export function parseContactBody(body: string): Contact {
  const c = emptyContact();
  let data: Record<string, unknown>;
  try {
    const parsed: unknown = JSON.parse(body);
    if (!parsed || typeof parsed !== 'object') return c;
    data = parsed as Record<string, unknown>;
  } catch {
    return c;
  }
  c.first = str(data.first);
  c.last = str(data.last);
  c.phones = labelledList(data.phones);
  c.emails = labelledList(data.emails);
  c.photo = str(data.photo);
  c.photoBytes = typeof data.photoBytes === 'number' && Number.isFinite(data.photoBytes) && data.photoBytes > 0 ? Math.floor(data.photoBytes) : 0;
  c.middle = str(data.middle);
  c.prefix = str(data.prefix);
  c.suffix = str(data.suffix);
  c.nickname = str(data.nickname);
  const ph = data.phonetic && typeof data.phonetic === 'object' ? (data.phonetic as Record<string, unknown>) : {};
  c.phonetic = { first: str(ph.first), middle: str(ph.middle), last: str(ph.last) };
  c.org = str(data.org);
  c.department = str(data.department);
  c.jobTitle = str(data.jobTitle);
  c.addresses = addressList(data.addresses);
  c.urls = labelledList(data.urls);
  c.profiles = labelledList(data.profiles);
  c.dates = labelledList(data.dates);
  c.related = labelledList(data.related);
  c.notes = str(data.notes);
  c.extras = extraList(data.extras);
  c.uid = str(data.uid);
  for (const [key, value] of Object.entries(data)) {
    if (MODELLED_KEYS.has(key) || NEVER_CARRIED.has(key)) continue;
    c.carried[key] = value;
  }
  return c;
}

export function isAddressEmpty(a: ContactAddress): boolean {
  return !a.street.trim() && !a.city.trim() && !a.region.trim() && !a.postal.trim() && !a.country.trim();
}

/** Drop rows with no value, and trim the value. The label is kept as typed. */
function packLabelled(rows: ContactLabelled[]): ContactLabelled[] | undefined {
  const out = rows
    .map((r) => ({ label: r.label.trim(), value: r.value.trim() }))
    .filter((r) => r.value);
  return out.length ? out : undefined;
}

/**
 * Serialize a contact for storage: every empty string, empty list and
 * blank row is dropped, so the stored document holds only what exists.
 */
export function buildContactBody(c: Contact): string {
  const body: ContactBody = {};
  // What a newer version stored goes back, minus anything this version models
  // itself. The filter runs at both ends rather than only at the parse, so a
  // modelled key can never reach the document from here - not even the empty
  // ones, which are dropped below and would otherwise leave a carried copy of
  // themselves standing.
  for (const [key, value] of Object.entries(c.carried)) {
    if (MODELLED_KEYS.has(key)) continue;
    (body as Record<string, unknown>)[key] = value;
  }
  const put = (key: keyof ContactBody, value: string) => {
    const v = value.trim();
    if (v) (body as Record<string, unknown>)[key] = v;
  };
  put('first', c.first);
  put('last', c.last);
  const phones = packLabelled(c.phones);
  if (phones) body.phones = phones;
  const emails = packLabelled(c.emails);
  if (emails) body.emails = emails;
  put('photo', c.photo);
  if (c.photo.trim() && c.photoBytes > 0) body.photoBytes = c.photoBytes;
  put('middle', c.middle);
  put('prefix', c.prefix);
  put('suffix', c.suffix);
  put('nickname', c.nickname);
  const phonetic: ContactBody['phonetic'] = {};
  if (c.phonetic.first.trim()) phonetic.first = c.phonetic.first.trim();
  if (c.phonetic.middle.trim()) phonetic.middle = c.phonetic.middle.trim();
  if (c.phonetic.last.trim()) phonetic.last = c.phonetic.last.trim();
  if (Object.keys(phonetic).length) body.phonetic = phonetic;
  put('org', c.org);
  put('department', c.department);
  put('jobTitle', c.jobTitle);
  const addresses = c.addresses
    .map((a) => ({
      label: a.label.trim(),
      street: a.street.trim(),
      city: a.city.trim(),
      region: a.region.trim(),
      postal: a.postal.trim(),
      country: a.country.trim(),
    }))
    .filter((a) => !isAddressEmpty(a));
  if (addresses.length) body.addresses = addresses;
  const urls = packLabelled(c.urls);
  if (urls) body.urls = urls;
  const profiles = packLabelled(c.profiles);
  if (profiles) body.profiles = profiles;
  const dates = packLabelled(c.dates);
  if (dates) body.dates = dates;
  const related = packLabelled(c.related);
  if (related) body.related = related;
  put('notes', c.notes);
  if (c.extras.length) body.extras = c.extras.map((e) => ({ name: e.name, params: e.params, value: e.value }));
  put('uid', c.uid);
  return JSON.stringify(body);
}

/**
 * The body with its photo's stored size filled in, once the import has
 * stored the picture and knows the bytes. The body is returned as it was
 * when it holds no photo or the size is not known.
 */
export function withContactPhotoBytes(body: string, bytesOf: (uri: string) => number | undefined): string {
  const c = parseContactBody(body);
  if (!c.photo) return body;
  const bytes = bytesOf(c.photo);
  if (!bytes) return body;
  return buildContactBody({ ...c, photoBytes: bytes });
}

/** The stored photo size a contact body records, 0 when none. A regex, not
 *  a parse: the size sort calls this for every contact in the list. */
export function contactPhotoBytes(body: string): number {
  const m = /"photoBytes":(\d+)/.exec(body);
  return m ? Number(m[1]) : 0;
}

/** The name the form's name fields spell, with no fallback. '' when blank. */
export function contactFullName(c: Contact): string {
  return [c.prefix, c.first, c.middle, c.last, c.suffix]
    .map((s) => s.trim())
    .filter(Boolean)
    .join(' ');
}

/**
 * What a row and a header call this contact: the stored title, else the
 * name the fields spell, else the nickname, else the organisation, else the
 * first email, else the first phone number, else the first chat handle. A
 * contact with none of those is unnamed.
 */
export function contactDisplayName(title: string, c: Contact): string {
  const t = title.trim();
  if (t) return t;
  return (
    contactFullName(c) ||
    c.nickname.trim() ||
    c.org.trim() ||
    c.emails[0]?.value ||
    c.phones[0]?.value ||
    c.profiles[0]?.value ||
    ''
  );
}

/**
 * The second line of a list row: the first phone number, else the
 * organisation, else the first email. '' when the contact has none.
 */
export function contactSecondLine(c: Contact): string {
  return c.phones[0]?.value || c.org.trim() || c.emails[0]?.value || '';
}

/**
 * Up to two initials for the round chip: the first letter of the first two
 * words of the display name, upper-cased in the name's own script. An
 * email address yields its first letter; an empty name yields ''.
 */
export function contactInitials(name: string): string {
  const cleaned = name.trim();
  if (!cleaned) return '';
  if (cleaned.includes('@')) return cleaned.slice(0, 1).toUpperCase();
  const words = cleaned.split(/\s+/).filter((w) => /\p{L}|\p{N}/u.test(w));
  const letters = words.slice(0, 2).map((w) => {
    const m = w.match(/\p{L}|\p{N}/u);
    return m ? m[0]! : '';
  });
  return letters.join('').toUpperCase();
}

/**
 * The initials the chip shows for a contact: the first letters of the first
 * and last name when the fields are filled ("Dr. C. Obermeyer" reads CO,
 * not DC), else the display name's first two words.
 */
export function contactInitialsFor(title: string, c: Contact): string {
  const first = c.first.trim();
  const last = c.last.trim();
  if (first || last) return contactInitials(`${first} ${last}`.trim());
  return contactInitials(contactDisplayName(title, c));
}

/** The number of chip hues the list draws; the hue index is stable per name. */
const CONTACT_HUES = 8;

/**
 * A stable hue index for a name, so the same person wears the same colour
 * on every device: the name is data that syncs, a random pick would not.
 */
export function contactHue(name: string): number {
  let h = 0;
  for (const ch of name.trim().toLowerCase()) h = (h * 31 + ch.codePointAt(0)!) >>> 0;
  return h % CONTACT_HUES;
}

/** The digits of a phone number, for the search index. '+49 176' becomes '49176'. */
export function phoneDigits(value: string): string {
  return value.replace(/\D/g, '');
}

/**
 * The `tel:` link for a stored number: the number as typed, minus the
 * spaces, dots, dashes and brackets a person writes for their own eyes.
 * The dialer accepts `+`, digits, `*`, `#` and the pause characters.
 */
export function telHref(value: string): string {
  return `tel:${value.replace(/[^\d+*#,;]/g, '')}`;
}

/** The `sms:` link for a stored number, same cleaning as `telHref`. */
export function smsHref(value: string): string {
  return `sms:${value.replace(/[^\d+*#,;]/g, '')}`;
}

/**
 * Everything the search index reads for a contact: the name fields, the
 * nickname, the organisation and title, every phone number twice (as typed
 * and as digits), every email, the notes. Never the uid, the photo or the
 * extras.
 */
export function contactSearchText(c: Contact): string {
  const parts = [
    c.first,
    c.last,
    c.middle,
    c.nickname,
    c.phonetic.first,
    c.phonetic.last,
    c.org,
    c.department,
    c.jobTitle,
    ...c.phones.flatMap((p) => [p.value, phoneDigits(p.value)]),
    ...c.emails.map((e) => e.value),
    ...c.urls.map((u) => u.value),
    ...c.profiles.map((p) => p.value),
    ...c.related.map((r) => r.value),
    c.notes,
  ];
  return parts.filter(Boolean).join(' ');
}

/**
 * The parts of a stored date, from the vCard forms in the wild: `2015-03-04`,
 * `--03-14` (no year), `20150304`, and Apple's `1604-02-02`, whose year
 * means "none given". A string in no known shape is returned as text.
 */
function parseContactDate(value: string): { year: number | null; month: number; day: number } | null {
  const v = value.trim();
  let m = v.match(/^(\d{4})-?(\d{2})-?(\d{2})$/);
  if (m) {
    const year = Number(m[1]);
    return { year: year === 1604 ? null : year, month: Number(m[2]), day: Number(m[3]) };
  }
  m = v.match(/^--(\d{2})-?(\d{2})$/);
  if (m) return { year: null, month: Number(m[1]), day: Number(m[2]) };
  return null;
}

/**
 * A stored date as the reader's language writes it: "14 March" for a date
 * with no year, "4 March 2015" with one. Unparseable text is shown as it is.
 */
export function formatContactDate(value: string, locale: string): string {
  const d = parseContactDate(value);
  if (!d || d.month < 1 || d.month > 12 || d.day < 1 || d.day > 31) return value;
  try {
    // A leap year, so 29 February formats without a year rolling it over.
    const date = new Date(Date.UTC(d.year ?? 2000, d.month - 1, d.day));
    const opts: Intl.DateTimeFormatOptions = d.year === null
      ? { day: 'numeric', month: 'long', timeZone: 'UTC' }
      : { day: 'numeric', month: 'long', year: 'numeric', timeZone: 'UTC' };
    return new Intl.DateTimeFormat(locale, opts).format(date);
  } catch {
    return value;
  }
}

/** One line of an address for a row or a card, blank parts skipped. */
export function formatAddressLines(a: ContactAddress): string[] {
  const lines: string[] = [];
  for (const line of a.street.split(/\r?\n/)) if (line.trim()) lines.push(line.trim());
  const cityLine = [a.postal.trim(), a.city.trim()].filter(Boolean).join(' ');
  const regionLine = [cityLine, a.region.trim()].filter(Boolean).join(', ');
  if (regionLine) lines.push(regionLine);
  if (a.country.trim()) lines.push(a.country.trim());
  return lines;
}

/* ── The re-import matcher ─────────────────────────────────────────────
 * A second import must not duplicate hundreds of people, and there is no
 * sync to lean on. A card is the same person when its uid matches, or when
 * its normalised name matches and the two share a phone number by digits
 * (or neither has a number), or when they share an email address. The
 * fallback carries the weight: Apple exports carry a UID, Android and
 * Google exports carry none, and a macOS export can carry only an email.
 * Spec: ops/docs/plans/contacts-pillar.md (section 7.5)
 */

export type ContactMatchIndex = {
  uids: Set<string>;
  /** Normalised name -> the digit strings of that person's numbers; an
   *  empty string marks a person with no number at all. */
  names: Map<string, Set<string>>;
  emails: Set<string>;
};

/** Case, whitespace and accents folded away, so "Anna  BAUMANN" and "anna baumann" agree. */
function normalizeContactName(name: string): string {
  return name
    .normalize('NFD')
    .replace(/\p{M}+/gu, '')
    .toLowerCase()
    .replace(/\s+/g, ' ')
    .trim();
}

function matchKeys(title: string, c: Contact): { name: string; digits: string[]; emails: string[] } {
  const name = normalizeContactName(contactDisplayName(title, c));
  const digits = c.phones.map((p) => phoneDigits(p.value)).filter((d) => d.length >= 4);
  const emails = c.emails.map((e) => e.value.trim().toLowerCase()).filter(Boolean);
  return { name, digits, emails };
}

export function emptyContactMatchIndex(): ContactMatchIndex {
  return { uids: new Set(), names: new Map(), emails: new Set() };
}

export function addToContactMatchIndex(index: ContactMatchIndex, title: string, body: string): void {
  const c = parseContactBody(body);
  if (c.uid.trim()) index.uids.add(c.uid.trim());
  const { name, digits, emails } = matchKeys(title, c);
  if (name) {
    const set = index.names.get(name) ?? new Set<string>();
    if (digits.length === 0) set.add('');
    for (const d of digits) set.add(d);
    index.names.set(name, set);
  }
  for (const e of emails) index.emails.add(e);
}

/** True when the account already holds this person, by the rule above. */
export function contactMatches(index: ContactMatchIndex, title: string, body: string): boolean {
  const c = parseContactBody(body);
  if (c.uid.trim() && index.uids.has(c.uid.trim())) return true;
  const { name, digits, emails } = matchKeys(title, c);
  if (name) {
    const known = index.names.get(name);
    if (known) {
      if (digits.length === 0 && known.has('')) return true;
      if (digits.some((d) => known.has(d))) return true;
    }
  }
  return emails.some((e) => index.emails.has(e));
}
