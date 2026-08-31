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
 *   - the demo folder tree a seed file can file itself into by name, and
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
  MedicationTemplate,
} from './trackerTypes';
import { isDemoMode } from './demo';
import { toLocalIso } from './notesViewUtils';
import { loadLocalSettings, saveLocalSettings } from './userSettings';
import type { FolderDef } from './folders';
import { buildLinkBody } from './linkBody';
import { loadSeeds, type SeedDoc } from './seeds';

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

const CARD_NOTE_TITLE = 'Visa ending 4242';

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
  startedAt: new Date().toISOString().slice(0, 10),
  dosageHistory: [],
};

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
 * The most recent Friday, Saturday and Sunday, as local ISO dates.
 *
 * The three journal seeds describe one weekend, so they have to LAND on a
 * weekend or the story reads wrong in the calendar. Today counts when today
 * is a Sunday; otherwise this steps back to the Sunday just gone.
 */
function lastWeekendIso(): { fri: string; sat: string; sun: string } {
  const today = new Date();
  const sun = new Date(today);
  sun.setDate(today.getDate() - today.getDay());
  const sat = new Date(sun);
  sat.setDate(sun.getDate() - 1);
  const fri = new Date(sun);
  fri.setDate(sun.getDate() - 2);
  return { fri: toLocalIso(fri), sat: toLocalIso(sat), sun: toLocalIso(sun) };
}

/**
 * Stamp the entry's `journalDate` onto its tracker values.
 *
 * The VALUES live in the markdown frontmatter, alongside everything else
 * about the note - only the date is computed, because a fixed one would age:
 * a seeded weekend has to be a RECENT weekend or the calendar reads wrong.
 * Without an explicit date all three entries land on the day they were
 * seeded, and the stats collapse them into one tracked day.
 */
function seedTrackers(doc: SeedDoc): JournalTrackerData | undefined {
  if (!doc.trackers) return undefined;
  const trackers = doc.trackers as JournalTrackerData;
  const date = journalDayIso(doc);
  return date ? { ...trackers, journalDate: date } : trackers;
}

/**
 * The local ISO date a journal seed belongs to, or null when it is not a
 * journal seed.
 *
 * Frontmatter spells the day out; keep that mapping explicit rather than
 * slicing three letters off, so an unknown value falls through to "no date"
 * instead of silently producing one.
 */
function journalDayIso(doc: SeedDoc): string | null {
  if (!doc.journalDay) return null;
  const weekend = lastWeekendIso();
  return doc.journalDay === 'friday' ? weekend.fri
    : doc.journalDay === 'saturday' ? weekend.sat
    : doc.journalDay === 'sunday' ? weekend.sun
    : null;
}

/**
 * Seed one markdown-defined note. Everything except the tracker values and
 * the folder lookup comes straight off the file's frontmatter, which is what
 * makes adding a starter note a matter of adding a file.
 */
async function seedDoc(pubkey: string, doc: SeedDoc, timestamp: string): Promise<void> {
  // A journal seed is stamped 21:00 on the evening it describes, not on the
  // moment the vault was seeded. All three carried the seeding time before
  // this, so the list showed one identical "Modified" date on every entry,
  // which reads as three copies of one note rather than as a weekend.
  const day = journalDayIso(doc);
  await seedNote(
    seedId(pubkey, doc.id),
    doc.title,
    doc.body,
    doc.tags,
    doc.starred,
    day ? new Date(`${day}T21:00:00`).toISOString() : timestamp,
    seedTrackers(doc),
    doc.type,
    // Folders are Pro and real vaults start with an empty tree on purpose,
    // so a `folder:` in frontmatter only files the note in the demo.
    isDemoMode() && doc.folder ? (DEMO_FOLDERS[doc.folder]?.id ?? null) : null,
  );
}

/* ── Bookmark seeds - the rows from the mockup, so the pillar is never
 * empty on first sight. Hand-maintained: edit the list below to change
 * what a new vault links to. Same idempotent seedNote path; bodies use
 * the canonical link-body JSON. Spec: ops/docs/plans/bookmarks-pillar.md */
const BOOKMARK_SEEDS: { sentinel: string; title: string; url: string; tags: string[] }[] = [
  { sentinel: '10b1', title: 'Like on AlternativeTo.net', url: 'https://alternativeto.net/software/privacynotes/about/', tags: ['rating'] },
  { sentinel: '10b2', title: 'Rate on PrivacyTools.io', url: 'https://privacytools.io/app/privacynotes', tags: ['privacy', 'rating'] },
  { sentinel: '10b3', title: 'Star ⭐ on Github.com', url: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app', tags: ['rating'] },
  { sentinel: '10b4', title: 'Review on SaasHub.com', url: 'https://www.saashub.com/privacynotes-alternatives', tags: ['rating'] },
  { sentinel: '10b5', title: 'Review on Capterra.com', url: 'https://www.capterra.com/p/10050664/PrivacyNotes/', tags: ['rating'] },
];

async function seedBookmarkNotes(pubkey: string, baseTs: number): Promise<void> {
  // Same demo-only folder rule the markdown seeds follow: a real vault starts
  // with an empty tree because folders are Pro, so this only files them in the
  // demo. All five sit in PrivacyNotes, next to Moving in.
  const folderId = isDemoMode() ? (DEMO_FOLDERS.PrivacyNotes?.id ?? null) : null;
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
export async function seedOnboardingNotes(pubkey: string): Promise<void> {
  const docs = (await loadSeeds()).filter((d) => !d.demoOnly || isDemoMode());
  const base = Date.now();

  // The demo folder tree has to exist before its notes are filed into it.
  await seedDemoFolderTree();

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
  ]);
}

/* ── Demo folder tree ──────────────────────────────────────────────
 * Folders is Pro and unlocked in the public demo as a teaser (like zen),
 * so demo visitors get a small pre-built tree. Demo only - real fresh
 * accounts start with an empty tree, deliberately: folders are Pro, and
 * a stranger's filing system is a worse first run than an empty tree
 * with a New folder button.
 *
 * The tree files notes the demo already has rather than inventing notes
 * to fill it:
 *
 *   PrivacyNotes        Moving in, plus the five seeded bookmarks
 *     Markdown          Everything markdown can do here
 *     Security          How your notes are protected
 *   Travel              the three Tokyo journal entries
 *
 * Two things it has to show. Every folder has a count, so nothing looks
 * abandoned; and nesting has a reason, PrivacyNotes being the area and
 * Markdown and Security the two subjects inside it. The Welcome note and
 * the recipe stay unfiled on purpose, so the tree is visibly a choice
 * rather than somewhere every note has to go.
 *
 * A seed file joins the tree by naming one of these in its `folder:`
 * frontmatter. IDs are fixed and permanent; adding a folder means adding
 * a row here with a fresh id.
 * Spec: ops/specs/folders.md (demo seed)
 */
const DEMO_FOLDER_PRIVACYNOTES = 'f01de001-0000-4000-8000-000000000004';

const DEMO_FOLDERS: Record<string, FolderDef> = {
  PrivacyNotes: {
    id: DEMO_FOLDER_PRIVACYNOTES,
    name: 'PrivacyNotes',
    parentId: null,
    order: 0,
  },
  Markdown: {
    id: 'f01de001-0000-4000-8000-000000000005',
    name: 'Markdown',
    parentId: DEMO_FOLDER_PRIVACYNOTES,
    order: 0,
  },
  Security: {
    id: 'f01de001-0000-4000-8000-000000000006',
    name: 'Security',
    parentId: DEMO_FOLDER_PRIVACYNOTES,
    order: 1,
  },
  Travel: {
    id: 'f01de001-0000-4000-8000-000000000001',
    name: 'Travel',
    parentId: null,
    order: 1,
  },
};

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
  'sleepScore',
  'steps',
  'heartRate',
  'water',
  'caffeine',
  'screenTime',
  'social',
];

/**
 * Prepare the demo's settings: the folder tree, and the wider pill set.
 * No-op outside the demo. Idempotent, and additive only - a visitor who
 * removes a folder or switches a pill off keeps that choice for the session.
 */
async function seedDemoFolderTree(): Promise<void> {
  if (!isDemoMode()) return;
  const settings = loadLocalSettings();
  const have = new Set(settings.folders.map((f) => f.id));
  const missingFolders = Object.values(DEMO_FOLDERS).filter((f) => !have.has(f.id));

  const active = settings.trackerSettings.activeBuiltins;
  const missingPills = DEMO_EXTRA_TRACKERS.filter((id) => !active.includes(id));

  if (missingFolders.length === 0 && missingPills.length === 0) return;
  saveLocalSettings({
    ...settings,
    folders: [...settings.folders, ...missingFolders],
    trackerSettings: {
      ...settings.trackerSettings,
      activeBuiltins: [...active, ...missingPills],
    },
  });
}
