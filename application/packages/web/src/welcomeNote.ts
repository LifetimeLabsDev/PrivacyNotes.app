/**
 * Starter notes seeded once per user on first sign-in.
 *
 * THE NOTES ARE NOT LISTED HERE, on purpose. Every starter note is one
 * `.md` file under `seeds/en/`, and its frontmatter carries the id, title,
 * note type, tags, folder and demo-only flag. Adding a starter note means
 * adding a file; removing one means deleting a file. `seeds/index.ts`
 * discovers them and explains the frontmatter keys.
 *
 * What stays here is everything that is NOT a markdown note:
 *   - the seeding mechanics (deterministic ids, idempotent writes)
 *   - the Vault items: Google, GitHub with a TOTP key so the rotating 2FA
 *     code has something to show, and a demo credit card. These are JSON
 *     bodies rather than markdown, so a `.md` file is the wrong shape.
 *   - the hand-maintained bookmark rows
 *   - the starter folder tree a seed file files itself into by name, and
 *     the extra tracker pills the demo switches on to show that data off
 *
 * Tracker VALUES moved into the markdown frontmatter on 2026-08-26, so a
 * journal seed is editable in one place. Only `journalDate` is still
 * computed, from the file's `journalDay: friday|saturday|sunday`: a fixed
 * date would age, and a seeded weekend has to be a recent one.
 *
 * Run `node tools/check-seeds.mjs` after touching the seed files: two files
 * sharing an `id` derive the SAME note UUID and one silently overwrites the
 * other.
 *
 * Each seed has a deterministic UUID derived from the user's pubkey, so
 * StrictMode double-mounts and re-seeds are idempotent - Dexie .put just
 * overwrites the identical row.
 */

import type { NoteType } from '@notes/shared';
import { db, type LocalNote } from './db';
import type {
  BuiltinTrackerId,
  JournalTrackerData,
  FactorDef,
  MedicationTemplate,
} from './trackerTypes';
import { isDemoMode } from './demo';
import i18n from './i18n';
import { TASK_LIST_EMPTY_BODY, toLocalIso } from './notesViewUtils';
import { loadLocalSettings, saveLocalSettings } from './userSettings';
import type { SignInStamp } from './liveSignIn';
import { SEED_FOLDER_IDS, type FolderDef } from './folders';
import { folderLookKey, seedIcons, tagLookKey } from './itemStyles';
import { buildLinkBody } from './linkBody';
import { buildContactBody, emptyContact } from './contactBody';
import { setRootSpace } from './spaces';
import { loadSeeds, seedDayIso, type SeedDoc } from './seeds';

/* ── Vault seed items ─────────────────────────────────────────── */

const LOGIN_NOTE_TITLE = 'Google';

const LOGIN_NOTE_BODY = JSON.stringify({
  url: 'https://accounts.google.com',
  username: 'test@gmail.com',
  password: 'xK9#mQ2$vL7nR4pW',
  notes: 'Example login. Edit or delete anytime.',
});

const TOTP_LOGIN_NOTE_TITLE = 'GitHub';

const TOTP_LOGIN_NOTE_BODY = JSON.stringify({
  url: 'https://github.com',
  username: 'test@example.com',
  password: 'rT4$wN8&kP2mX6qZ',
  totp: 'JBSWY3DPEHPK3PXP',
  notes: 'Example login with a 2FA code. Edit or delete anytime.',
});

// Matches what deriveCardTitle() in CardForm.tsx produces for the number
// below, down to the wording. A hand-written title drifts from the card it
// describes and the seed then contradicts itself on screen: this one claimed
// a card ending 4242 while the vault entry beside it read 0366.
const CARD_NOTE_TITLE = 'Visa ending in 0366';

const CARD_NOTE_BODY = JSON.stringify({
  cardholderName: 'John Doe',
  cardNumber: '4532015112830366',
  expMonth: '09',
  expYear: '2028',
  cvv: '847',
  billingZip: '10001',
  notes: 'Example credit card. Edit or delete anytime.',
});

/** Deterministic medication ID for the seed Multivitamin. */
const SEED_MED_ID = '00000000-0000-4000-b000-000000000001';

/** Pre-configured medication template seeded alongside the wellness note. */
export const SEED_MEDICATION: MedicationTemplate = {
  id: SEED_MED_ID,
  name: 'Multivitamin',
  dosage: '1 tablet',
  timing: 'morning',
  startedAt: toLocalIso(new Date()),
  dosageHistory: [],
};

/** The starter factors a fresh vault holds as its own list. The other
 *  starter names stay suggestions in the Factors tab of the tracker setup. */
const SEED_FACTOR_KEYS = ['work', 'family', 'travel', 'holiday', 'deadline', 'sick', 'period', 'badWeather'] as const;

/**
 * The list with the seed factors in it, named in the active language. Only an
 * untouched list takes them: a removed seed leaves a tombstone, so it never
 * comes back. Fixed ids, so two devices that both seed merge into one list.
 */
export function withSeedFactors(list: readonly FactorDef[] | undefined): FactorDef[] {
  if (list && list.length > 0) return [...list];
  const now = new Date().toISOString();
  return SEED_FACTOR_KEYS.map((key, i) => ({
    id: `00000000-0000-4000-b100-${String(i + 1).padStart(12, '0')}`,
    name: i18n.t(`trackers:factors.starter.${key}`),
    createdAt: now,
  }));
}

/**
 * Build a deterministic UUID from the pubkey and a 4-char hex sentinel.
 * Same pattern as the original welcome-note ID generator: the sentinel
 * sits in the node-id position so we can tell the three seeds apart
 * later (and so two seeds for the same user never collide).
 */
function seedId(pubkey: string, sentinel: string): string {
  const p = pubkey.toLowerCase().replace(/[^0-9a-f]/g, '').padEnd(32, '0');
  return `${p.slice(0, 8)}-${p.slice(8, 12)}-4${p.slice(12, 15)}-${sentinel}-${p.slice(15, 27)}`;
}

async function seedNote(
  id: string,
  title: string,
  body: string,
  tags: string[],
  starred: boolean,
  timestamp?: string,
  trackers?: JournalTrackerData,
  type: NoteType = 'note',
  folderId: string | null = null,
): Promise<LocalNote> {
  const existing = await db.notes.get(id);
  if (existing && existing.deleted === 0) return existing;

  const now = timestamp ?? new Date().toISOString();
  const note: LocalNote = {
    id,
    title,
    body,
    tags,
    createdAt: now,
    updatedAt: now,
    editedAt: now,
    dirty: 1,
    deleted: 0,
    trashed: 0,
    starred: starred ? 1 : 0,
    locked: 0,
    pinProtected: 0,
    type,
    folderId,
    ...(trackers ? { trackers: trackers as Record<string, unknown> } : {}),
  };
  await db.notes.put(note);
  return note;
}

/**
 * The tracker values a seed is born with: the ones in its frontmatter, plus
 * its `journalDate` when it names a day. The VALUES live in the markdown
 * beside everything else about the note; only the date is computed, because
 * a fixed one would age. Without an explicit date the three journal entries
 * land on the day they were seeded, and the stats collapse them into one
 * tracked day.
 */
function seedTrackers(doc: SeedDoc): JournalTrackerData | undefined {
  const date = seedDayIso(doc.journalDay);
  const end = seedDayIso(doc.journalDayEnd);
  if (!doc.trackers && !date) return undefined;
  const trackers = (doc.trackers ?? {}) as JournalTrackerData;
  if (!date) return trackers;
  return { ...trackers, journalDate: date, ...(end && end > date && doc.type !== 'journal' ? { dateEnd: end } : {}) } as JournalTrackerData;
}

/**
 * Seed one markdown-defined note. Everything except the tracker values and
 * the folder lookup comes straight off the file's frontmatter, which is what
 * makes adding a starter note a matter of adding a file.
 */
async function seedDoc(pubkey: string, doc: SeedDoc, timestamp: string): Promise<void> {
  // A journal seed is stamped 21:00 on the evening it describes, not on the
  // moment the vault was seeded, so the list does not show one identical
  // "Modified" date on every entry, which reads as three copies of one note
  // rather than as a weekend. A dated note or task list keeps the seeding
  // time: its day is a plan, and 21:00 today would lie in the future.
  const day = doc.type === 'journal' ? seedDayIso(doc.journalDay) : null;
  await seedNote(
    seedId(pubkey, doc.id),
    doc.title,
    doc.body,
    doc.tags,
    doc.starred,
    day ? new Date(`${day}T21:00:00`).toISOString() : timestamp,
    seedTrackers(doc),
    doc.type,
    // A `folder:` in frontmatter files the note in every vault. Browsing
    // the tree is free; the Pro gate sits on each folder ACTION.
    doc.folder ? (SEED_FOLDERS[doc.folder]?.id ?? null) : null,
  );
}

/* ── Bookmark seeds - the rows from the mockup, so the pillar is never
 * empty on first sight. Hand-maintained: edit the list below to change
 * what a new vault links to. Same idempotent seedNote path; bodies use
 * the canonical link-body JSON. Spec: ops/docs/archive/bookmarks-pillar.md */
const BOOKMARK_SEEDS: { sentinel: string; title: string; url: string; tags: string[] }[] = [
  { sentinel: '10b1', title: 'Like on AlternativeTo.net', url: 'https://alternativeto.net/software/privacynotes/about/', tags: ['rating'] },
  { sentinel: '10b2', title: 'Rate on PrivacyTools.io', url: 'https://privacytools.io/app/privacynotes', tags: ['privacy', 'rating'] },
  { sentinel: '10b3', title: 'Star ⭐ on Github.com', url: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app', tags: ['rating'] },
  { sentinel: '10b4', title: 'Review on SaasHub.com', url: 'https://www.saashub.com/privacynotes-alternatives', tags: ['rating'] },
  { sentinel: '10b5', title: 'Review on Capterra.com', url: 'https://www.capterra.com/p/10050664/PrivacyNotes/', tags: ['rating'] },
];

async function seedBookmarkNotes(pubkey: string, baseTs: number): Promise<void> {
  // All five sit in PrivacyNotes, next to Moving in.
  const folderId = SEED_FOLDERS.PrivacyNotes?.id ?? null;
  await Promise.all(
    BOOKMARK_SEEDS.map((b, i) =>
      seedNote(
        seedId(pubkey, b.sentinel),
        b.title,
        buildLinkBody(b.url),
        b.tags,
        false,
        new Date(baseTs - i * 100).toISOString(),
        undefined,
        'link',
        folderId,
      ),
    ),
  );
}

/* ── The contact seeds. The first has every field a card can render
 * filled in, because the pillar's job on first sight is to show what a
 * contact holds. She is a joke with a point: the company's head of
 * security has never shown her face. Her birthday falls six days after the
 * seeding, so the first weeks of the calendar show a birthday.
 *
 * Every value is a placeholder or one of our own public links. The photo
 * is a static asset rather than a stored blob, the way every other seeded
 * picture is, so it costs no quota and draws on a device that never ran
 * the seeding. Spec: ops/docs/archive/contacts-pillar.md */
// Built at seed time, so the translated sentences read in the active language.
function contactSeeds(): { sentinel: string; title: string; tags: string[]; body: string }[] {
  return [
  {
    sentinel: '10c1',
    title: 'Kon Kitsune',
    tags: ['work'],
    body: buildContactBody({
      ...emptyContact(),
      prefix: 'Agent',
      first: 'Kon',
      middle: 'Nine',
      last: 'Kitsune',
      suffix: 'IX',
      nickname: 'Nine-Tails',
      phonetic: { first: 'kon', middle: '', last: 'kit-su-ne' },
      photo: '/onboarding/kitsune.webp',
      photoBytes: 18898,
      org: 'PrivacyNotes',
      department: i18n.t('shell:contacts.seedDepartment'),
      jobTitle: i18n.t('shell:contacts.seedJobTitle'),
      phones: [
        { label: 'work', value: '+81 3 9999 0009' },
        { label: 'mobile', value: '+81 90 9999 0009' },
      ],
      emails: [{ label: 'work', value: 'kitsune@example.com' }],
      addresses: [
        { label: 'work', street: '9 Fox Alley', city: 'Shibuya', region: 'Tokyo', postal: '150-0001', country: 'Japan' },
        { label: 'home', street: 'Ninth Torii, Inari Shrine', city: 'Shibuya', region: 'Tokyo', postal: '', country: 'Japan' },
      ],
      urls: [
        { label: 'homepage', value: 'https://privacynotes.app/' },
        { label: 'Issues', value: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues/' },
      ],
      // A profile row only offers an Open button when its value parses as
      // a link, so these hold the whole URL rather than a bare handle.
      profiles: [
        { label: 'X', value: 'https://x.com/PrivacyNotesApp' },
        { label: 'Reddit', value: 'https://www.reddit.com/r/PrivacyNotes/' },
        { label: 'Mastodon', value: 'https://mastodon.social/@privacynotes' },
        { label: 'YouTube', value: 'https://www.youtube.com/@PrivacyNotesApp' },
        { label: 'Facebook', value: 'https://www.facebook.com/PrivacyNotesApp/' },
      ],
      dates: [
        { label: 'birthday', value: birthdaySoon() },
        { label: 'anniversary', value: '2019-09-09' },
      ],
      related: [
        { label: 'Familiar', value: 'Tofu the Fox' },
        { label: 'Colleague', value: 'The Night Shift' },
      ],
      notes: i18n.t('shell:contacts.seedNote'),
    }),
  },
  ];
}

/** A birthday six days after today, as a yearless contact date (`--MM-DD`). */
function birthdaySoon(now = new Date()): string {
  const d = new Date(now.getFullYear(), now.getMonth(), now.getDate() + 6, 12);
  return `--${String(d.getMonth() + 1).padStart(2, '0')}-${String(d.getDate()).padStart(2, '0')}`;
}

async function seedContactNotes(pubkey: string, baseTs: number): Promise<void> {
  await Promise.all(
    contactSeeds().map((c, i) =>
      seedNote(
        seedId(pubkey, c.sentinel),
        c.title,
        c.body,
        c.tags,
        false,
        new Date(baseTs - i * 100).toISOString(),
        undefined,
        'contact',
        null,
      ),
    ),
  );
}

/* ── The demo's Work space: one root folder in Work and a repeating event
 * in it, so the calendar shows a Work item with its briefcase every week
 * and the space switch has something to switch. Demo only: a real vault
 * starts with one space. Spec: ops/docs/archive/calendar-pillar-spec.md (step 2) */
const DEMO_WORK_FOLDER = { id: 'f01de001-0000-4000-8000-000000000007', name: 'Team', nameKey: 'shell:folders.seedTeam', icon: 'briefcase' };

async function seedWorkEvent(pubkey: string, baseTs: number): Promise<void> {
  const friday = seedDayIso('friday');
  if (!friday) return;
  await seedNote(
    seedId(pubkey, '10e1'),
    i18n.t('shell:calendar.seedWeeklyReview'),
    i18n.t('shell:calendar.seedWeeklyReviewBody'),
    [],
    false,
    new Date(baseTs).toISOString(),
    { journalDate: friday, time: '16:00', timeEnd: '17:00', repeat: { every: 'week', interval: 1 } } as unknown as JournalTrackerData,
    'event',
    DEMO_WORK_FOLDER.id,
  );
}

/* ── The demo's calendar: a few weeks of everyday items around today, so
 * each calendar feature has an example to look at: timed and all-day items,
 * an alert, two items at the same time, a multi-day trip, a night past
 * midnight, repeats on chosen weekdays, every other week, on a day of the
 * month and on the Nth weekday, and a dated task list and note. Demo only,
 * like the Work event. Spec: ops/docs/archive/calendar-pillar-spec.md (step 2) */
async function seedCalendarDemo(pubkey: string, baseTs: number, now = new Date()): Promise<void> {
  const at = (n: number) => new Date(now.getFullYear(), now.getMonth(), now.getDate() + n, 12);
  const day = (n: number) => toLocalIso(at(n));
  /** The first day from today that is weekday `wd` (0 = Sunday). */
  const next = (wd: number) => day((wd - now.getDay() + 7) % 7);
  /** The first day from today that is the `nth` weekday `wd` of its month. */
  const nthWeekday = (nth: number, wd: number) => {
    for (let n = 0; n < 70; n++) if (at(n).getDay() === wd && Math.ceil(at(n).getDate() / 7) === nth) return day(n);
    return day(0);
  };
  const firstOfMonth = toLocalIso(new Date(now.getFullYear(), now.getMonth() + (now.getDate() === 1 ? 0 : 1), 1, 12));
  const items: [sentinel: string, key: string, type: NoteType, folder: string | null, trackers: Record<string, unknown>][] = [
    ['10e2', 'lunch', 'event', null, { journalDate: day(0), time: '12:30', timeEnd: '13:30' }],
    ['10e3', 'dentist', 'event', null, { journalDate: day(1), time: '10:30', timeEnd: '11:15', alerts: [{ before: 60 }] }],
    ['10e4', 'callAna', 'event', null, { journalDate: day(1), time: '11:00', timeEnd: '11:30' }],
    ['10e5', 'groceries', 'task', null, { journalDate: day(1), time: '18:00' }],
    ['10e6', 'concert', 'event', null, { journalDate: day(2), time: '20:00', timeEnd: '23:30' }],
    ['10e7', 'giftIdeas', 'note', null, { journalDate: day(5) }],
    ['10e8', 'flight', 'event', null, { journalDate: day(7), time: '18:10', timeEnd: '20:35', alerts: [{ before: 120 }] }],
    ['10e9', 'conference', 'event', null, { journalDate: day(8), dateEnd: day(10) }],
    ['10ea', 'nightTrain', 'event', null, { journalDate: day(12), time: '22:30', timeEnd: '06:15' }],
    ['10eb', 'yoga', 'event', null, { journalDate: [next(1), next(3)].sort()[0], time: '07:00', timeEnd: '08:00', repeat: { every: 'week', interval: 1, weekdays: [1, 3] } }],
    ['10ec', 'sprint', 'event', DEMO_WORK_FOLDER.id, { journalDate: next(1), time: '10:00', timeEnd: '11:00', repeat: { every: 'week', interval: 2 } }],
    ['10ed', 'bookClub', 'event', null, { journalDate: nthWeekday(2, 4), time: '19:00', timeEnd: '21:00', repeat: { every: 'month', interval: 1, monthly: 'weekday', nth: 2 } }],
    ['10ee', 'rent', 'event', null, { journalDate: firstOfMonth, repeat: { every: 'month', interval: 1, monthly: 'day' }, alerts: [{ days: 1, at: '09:00' }] }],
  ];
  await Promise.all(
    items.map(([sentinel, key, type, folder, trackers], i) =>
      seedNote(
        seedId(pubkey, sentinel),
        i18n.t(`shell:calendar.seedDemo.${key}`),
        type === 'task' ? TASK_LIST_EMPTY_BODY : '',
        [],
        false,
        new Date(baseTs - i * 100).toISOString(),
        trackers as unknown as JournalTrackerData,
        type,
        folder,
      ),
    ),
  );
}

/** Insert the demo login vault item. Idempotent. */
async function seedLoginNote(
  pubkey: string,
  timestamp?: string,
): Promise<LocalNote> {
  return seedNote(
    seedId(pubkey, '109a'),
    LOGIN_NOTE_TITLE,
    LOGIN_NOTE_BODY,
    [],
    false,
    timestamp,
    undefined,
    'login',
  );
}

/** Insert the second demo login (with a TOTP authenticator key). Idempotent. */
async function seedTotpLoginNote(
  pubkey: string,
  timestamp?: string,
): Promise<LocalNote> {
  return seedNote(
    seedId(pubkey, '2fa0'),
    TOTP_LOGIN_NOTE_TITLE,
    TOTP_LOGIN_NOTE_BODY,
    [],
    false,
    timestamp,
    undefined,
    'login',
  );
}

/** Insert the demo credit card vault item. Idempotent. */
async function seedCardNote(
  pubkey: string,
  timestamp?: string,
): Promise<LocalNote> {
  return seedNote(
    seedId(pubkey, 'ca4d'),
    CARD_NOTE_TITLE,
    CARD_NOTE_BODY,
    [],
    false,
    timestamp,
    undefined,
    'card',
  );
}

/**
 * Seed all onboarding notes (Welcome, Getting started, Tokyo journal,
 * Wellness journal, demo login, demo card) in parallel. Each is
 * individually idempotent, so re-running this function is safe.
 *
 * Timestamps are staggered one second apart down the `order` list, so the
 * starred Welcome note keeps the largest timestamp and stays pinned to the
 * top under `updatedAt desc`. The Vault and bookmark rows come after every
 * markdown note.
 *
 * The seed list is resolved first, because the files decide the note titles
 * and folders as well as the bodies.
 */
export async function seedOnboardingNotes(
  pubkey: string,
  /** The stamp of a sign-in that is not live yet, for its settings write. */
  since?: SignInStamp,
): Promise<void> {
  const docs = (await loadSeeds()).filter((d) => !d.demoOnly || isDemoMode());
  const base = Date.now();

  // The folder tree has to exist before its notes are filed into it.
  await seedFolderTree(since);

  const vaultBase = base - (docs.length + 1) * 1000;
  await Promise.all([
    // Markdown notes, newest first: one second per step down the `order`
    // list, so the starred Welcome note keeps the largest timestamp and
    // stays pinned above everything else under `updatedAt desc`.
    ...docs.map((doc, i) => seedDoc(pubkey, doc, new Date(base - i * 1000).toISOString())),
    seedLoginNote(pubkey, new Date(vaultBase).toISOString()),
    seedTotpLoginNote(pubkey, new Date(vaultBase - 500).toISOString()),
    seedCardNote(pubkey, new Date(vaultBase - 1000).toISOString()),
    seedBookmarkNotes(pubkey, vaultBase - 1500),
    seedContactNotes(pubkey, vaultBase - 2500),
    ...(isDemoMode() ? [seedWorkEvent(pubkey, vaultBase - 3000), seedCalendarDemo(pubkey, vaultBase - 3500)] : []),
  ]);
}

/* ── Starter folder tree ────────────────────────────────────────────
 * Every new vault opens on this tree, the same one the public demo shows.
 * The ids are in `folders.ts`, because the sidebar recognises a starter
 * folder by id to decide whether a free account may delete it; the names
 * and the nesting are here, where the seeding happens.
 *
 * The tree files notes the vault already has rather than inventing notes
 * to fill it:
 *
 *   PrivacyNotes        Welcome, Moving in, Bifana, and the five bookmarks
 *     Markdown          Everything markdown can do here
 *     Security          How your notes are protected
 *   Travel              the three Tokyo journal entries
 *
 * Two things it has to show. Every folder has a count, so nothing looks
 * abandoned; and nesting has a reason, PrivacyNotes being the area and
 * Markdown and Security the two subjects inside it.
 *
 * A seed file joins the tree by naming one of these in its `folder:`
 * frontmatter, and `tools/check-seeds.mjs` fails on a name that is not a
 * key below. Adding a folder means adding a row here and an id there.
 *
 * `PrivacyNotes` and `Markdown` are proper nouns and read the same in
 * every language. The other two are ordinary words, so they carry a
 * catalog key and seed in the user's own language. The literal `name`
 * beside it is the English, and the fallback if the key ever goes.
 * Spec: ops/specs/folders.md (starter tree)
 */
interface SeedFolder {
  id: string;
  name: string;
  /** Catalog key, when the name is a word rather than a proper noun. */
  nameKey?: string;
  parentId: string | null;
  order: number;
  /** Its look icon (looks/lookIcons.ts), a starting point the user can change. */
  icon: string;
}

const SEED_FOLDERS: Record<string, SeedFolder> = {
  PrivacyNotes: {
    id: SEED_FOLDER_IDS.PrivacyNotes,
    name: 'PrivacyNotes',
    parentId: null,
    order: 0,
    icon: 'lock',
  },
  Markdown: {
    id: SEED_FOLDER_IDS.Markdown,
    name: 'Markdown',
    parentId: SEED_FOLDER_IDS.PrivacyNotes,
    order: 0,
    icon: 'pencil',
  },
  Security: {
    id: SEED_FOLDER_IDS.Security,
    name: 'Security',
    nameKey: 'shell:folders.seedSecurity',
    parentId: SEED_FOLDER_IDS.PrivacyNotes,
    order: 1,
    icon: 'shield',
  },
  Travel: {
    id: SEED_FOLDER_IDS.Travel,
    name: 'Travel',
    nameKey: 'shell:folders.seedTravel',
    parentId: null,
    order: 1,
    icon: 'airplane',
  },
};

/**
 * The look icon of each tag the seeds use. Seed tags are the same English
 * words in every language, so the keys are fixed.
 * Spec: ops/docs/archive/folder-tag-icons.md (section 6.2)
 */
export const SEED_TAG_ICONS: Record<string, string> = {
  encryption: 'key',
  privacy: 'fingerprint',
  recipes: 'cooking-pot',
  tokyo: 'map-pin',
  rating: 'star',
  work: 'briefcase',
};

/** The tree as the settings blob stores it, named in the user's language. */
function seedFolderDefs(): FolderDef[] {
  return Object.values(SEED_FOLDERS).map((f) => ({
    id: f.id,
    name: f.nameKey ? i18n.t(f.nameKey) : f.name,
    parentId: f.parentId,
    order: f.order,
  }));
}

/**
 * Extra tracker pills switched on for the demo only.
 *
 * `defaultTrackerSettings()` deliberately ships seven pills, because a wall
 * of them is a bad first run for someone logging their own day. The demo has
 * the opposite job: the three Tokyo entries carry values for all of these,
 * and a pill that is off renders nothing, so the data would be invisible.
 * Real vaults keep the quieter default.
 */
const DEMO_EXTRA_TRACKERS: BuiltinTrackerId[] = [
  'habits',
  'sleepScore',
  'steps',
  'heartRate',
  'water',
  'caffeine',
  'screenTime',
  'social',
];

/**
 * Prepare the vault's settings: the starter folder tree and the icons of
 * the starter folders and tags for everyone, and the wider pill set in the
 * demo.
 *
 * Additive by id, so a name, an order or a nesting the user changed is
 * never reset. It does NOT remember a deletion, which is safe only
 * because seeding runs once per account (the `welcomeNoteSeeded` flag)
 * and once per fresh demo tab session. Call it a second time inside one
 * session and a folder the user deleted comes back.
 */
async function seedFolderTree(since?: SignInStamp): Promise<void> {
  const settings = loadLocalSettings();
  const have = new Set(settings.folders.map((f) => f.id));
  // A starter folder the user deleted stays deleted. Seeding runs once per
  // account, so this only matters on a re-seed, and coming back from the
  // dead is the one thing a deleted folder must never do.
  const removed = new Set(settings.foldersDeleted.map((d) => d.id));
  const demoWork: FolderDef[] = isDemoMode()
    ? [{ id: DEMO_WORK_FOLDER.id, name: i18n.t(DEMO_WORK_FOLDER.nameKey), parentId: null, order: 2 }]
    : [];
  const missingFolders = [...seedFolderDefs(), ...demoWork].filter(
    (f) => !have.has(f.id) && !removed.has(f.id),
  );

  const active = settings.trackerSettings.activeBuiltins;
  const missingPills = isDemoMode()
    ? DEMO_EXTRA_TRACKERS.filter((id) => !active.includes(id))
    : [];

  // Icons for the starter folders still in the tree and for the seed tags.
  const icons: Record<string, string> = {};
  for (const f of Object.values(SEED_FOLDERS)) {
    if (!removed.has(f.id)) icons[folderLookKey(f.id)] = f.icon;
  }
  for (const [tag, icon] of Object.entries(SEED_TAG_ICONS)) icons[tagLookKey(tag)] = icon;
  if (demoWork.length && !removed.has(DEMO_WORK_FOLDER.id)) icons[folderLookKey(DEMO_WORK_FOLDER.id)] = DEMO_WORK_FOLDER.icon;
  let itemStyles = seedIcons(settings.itemStyles, icons);
  if (demoWork.length && !removed.has(DEMO_WORK_FOLDER.id)) itemStyles = setRootSpace(itemStyles, DEMO_WORK_FOLDER.id, 'work');

  if (missingFolders.length === 0 && missingPills.length === 0 && itemStyles === settings.itemStyles) return;
  saveLocalSettings({
    ...settings,
    itemStyles,
    folders: [...settings.folders, ...missingFolders],
    trackerSettings: {
      ...settings.trackerSettings,
      activeBuiltins: [...active, ...missingPills],
    },
  }, since);
}
