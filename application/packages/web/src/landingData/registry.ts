/**
 * Shared registry for the static landing pages (/vs/<x>, /<feature>, /for/<x>).
 *
 * Everything selectable across pages lives here: trust chips, benefit cards,
 * the comparison row set (including OUR cell per row) and shared FAQ
 * entries. Page datasets under src/landingData/pages/ reference these by
 * id; landing-pages.ts joins and validates at build time and fails the
 * build loudly on an unknown id.
 *
 * This module must stay FREE OF IMPORTS, like the dataset files: the landing
 * builder (tools/landing-builder) transpiles it standalone and evaluates it
 * as a data-URL module. landing-pages.ts imports it statically, which is
 * also fine.
 *
 * Prices are never written into copy. Strings carry {price}, {earlyPrice}
 * and {proPrice} tokens which landing-pages.ts resolves from src/pricing.ts;
 * the build fails if a dataset hardcodes the current dollar values.
 * Spec: ops/docs/plans/marketing-pages.md (maintenance mechanisms)
 */

/** Trust ribbon chips. Wording mirrors the homepage ribbon (landing.json). */
export const CHIPS = {
  'free-forever': { label: 'Free forever' },
  'zero-knowledge': { label: 'Zero knowledge' },
  'swiss-servers': { label: 'Swiss servers' },
  'no-subscription': { label: 'No subscription' },
  'open-source': { label: 'Open source' },
  'no-email': { label: 'No email required' },
} as const;

/** Feature benefit cards. `icon` keys into the glyph set in landing-pages.ts. */
export const BENEFITS = {
  'real-editor': {
    icon: 'pencil',
    title: 'A real editor, not a toy',
    body: 'Headings, tables, callouts, code blocks, task lists. Live preview as you type, and the raw markdown source one click away.',
  },
  'private-architecture': {
    icon: 'lock',
    title: 'Private by architecture',
    body: 'Notes encrypt on your device with a key derived from your 12-word phrase. We could not read your drafts if we tried.',
  },
  'note-links': {
    icon: 'graph',
    title: 'Note-links',
    body: 'Type [[ to link one note to another and build a second brain instead of a pile. Backed by instant full-text search and tags.',
  },
  'tasks-surface': {
    icon: 'check',
    title: 'Tasks that surface',
    body: 'Every checkbox you write, in any note, shows up in one Tasks view. Your markdown is also your to-do system.',
  },
  'plain-files': {
    icon: 'folder',
    title: 'Plain files, in and out',
    body: 'Import a folder of markdown, export everything back out as markdown, free tier included. No proprietary trap between you and your words.',
  },
  'offline-first': {
    icon: 'globe',
    title: 'Works offline, everywhere',
    body: 'Browser, macOS, Windows, Linux, iOS, Android. A dead connection never blocks writing; sync catches up, encrypted, when you are back.',
  },
} as const;

/**
 * The fixed comparison row set. `us` is PrivacyNotes' cell on every /vs/
 * page; competitor datasets supply only their own cells. Bias lives in which
 * rows exist at all - every cell must survive a fact-check.
 * Cell values: yes | partial | paid | pro | no ("pro" = included in the
 * one-time Pro purchase; "paid" = needs the competitor's subscription).
 */
type CellValue = 'yes' | 'partial' | 'paid' | 'pro' | 'no';
export type Cell = { v: CellValue; note?: string };
export type VsRow = {
  label: string;
  small?: string;
  group: 'privacy' | 'pillars' | 'editor' | 'price';
  us: Cell;
};

export const VS_ROWS: Record<string, VsRow> = {
  e2ee: {
    label: 'End-to-end encrypted by default',
    small: 'Sealed on your device before anything is sent',
    group: 'privacy',
    us: { v: 'yes' },
  },
  'zero-knowledge': {
    label: 'Zero knowledge',
    small: 'The provider cannot read your notes',
    group: 'privacy',
    us: { v: 'yes' },
  },
  'no-account': {
    label: 'No email or account required',
    small: 'Start and sync with a 12-word phrase alone',
    group: 'privacy',
    us: { v: 'yes' },
  },
  'verifiable-crypto': {
    label: 'Published, verifiable encryption',
    group: 'privacy',
    us: { v: 'yes', note: 'Published: crypto, schema, threat model' },
  },
  'open-source': {
    label: 'Fully open-source clients and server',
    group: 'privacy',
    us: { v: 'partial', note: 'Clients, encryption, schema and threat model published' },
  },
  notes: {
    label: 'Notes with tags and instant search',
    group: 'pillars',
    us: { v: 'yes' },
  },
  tasks: {
    label: 'Tasks in one view',
    small: 'Every checkbox across your notes, one view',
    group: 'pillars',
    us: { v: 'yes' },
  },
  journal: {
    label: 'Journal with mood, sleep and medication tracking',
    small: 'Research-backed tags, doctor export',
    group: 'pillars',
    us: { v: 'yes' },
  },
  vault: {
    label: 'Password and card vault',
    small: 'Passwords, cards, SSH keys, encrypted like everything else',
    group: 'pillars',
    us: { v: 'yes' },
  },
  files: {
    label: 'Encrypted file attachments on the free tier',
    group: 'pillars',
    us: { v: 'yes', note: 'Images, docs, audio, video up to 5 MB each' },
  },
  burn: {
    label: 'Burn After Reading',
    small: 'Share a note that destroys itself once read',
    group: 'pillars',
    us: { v: 'yes' },
  },
  markdown: {
    label: 'Markdown editing on the free tier',
    group: 'editor',
    us: { v: 'yes', note: 'Live preview, markdown-native' },
  },
  'md-on-disk': {
    label: 'Works on a folder of plain .md files',
    small: 'Desktop: your notes on disk, edits save in place',
    group: 'editor',
    us: { v: 'yes' },
  },
  history: {
    label: 'Note history and version restore',
    group: 'editor',
    us: { v: 'pro', note: 'Last 20 versions, part of the one-time Pro' },
  },
  'pin-protect': {
    label: 'Protect individual notes',
    group: 'editor',
    us: { v: 'pro', note: 'PIN hides the contents' },
  },
  offline: {
    label: 'Works fully offline',
    group: 'editor',
    us: { v: 'yes' },
  },
  platforms: {
    label: 'Web, macOS, Windows, Linux, iOS, Android',
    group: 'editor',
    us: { v: 'yes' },
  },
  'no-subscription': {
    label: 'Full version without a subscription',
    group: 'price',
    us: { v: 'yes', note: '{price} once' },
  },
  'free-tier': {
    label: 'Useful free tier',
    small: 'What you get without paying, forever',
    group: 'price',
    us: { v: 'yes', note: 'All seven pillars including markdown, 2 devices' },
  },
  export: {
    label: 'Export everything to plain files',
    group: 'price',
    us: { v: 'yes', note: 'Markdown, on the free tier too' },
  },
};
export const VS_GROUP_LABELS: Record<VsRow['group'], string> = {
  privacy: 'Privacy and trust',
  pillars: 'One app, whole life',
  editor: 'Editor and workflow',
  price: 'Ownership and price',
};

/** FAQ entries reusable across pages. */
export const SHARED_FAQS = {
  'verify-encryption': {
    q: 'Do I have to trust you on the encryption?',
    a: 'No. Notes are encrypted on your device with XChaCha20-Poly1305, keys derived from your phrase, and the encryption code and threat model are published. You can watch the ciphertext leave your own browser in the network tab.',
  },
  'lose-phrase': {
    q: 'What if I lose my 12-word phrase?',
    a: 'The notes are unrecoverable, by us or anyone. There is no reset flow, because a reset flow would also be a backdoor. Keep the phrase like a physical key: in a password manager or somewhere safe.',
  },
  'export-leave': {
    q: 'What if I want to leave later?',
    a: 'Export everything as plain markdown at any time, free tier included. Leaving being easy is a feature we advertise on purpose.',
  },
  'account-needed': {
    q: 'Do I need an account?',
    a: 'Not to try it: the demo is a full app with no signup. To keep notes and sync them you create a vault, which needs a 12-word phrase, or a Google, Apple, or GitHub sign-in if you prefer. An email address is never required.',
  },
} as const;
