/**
 * Which published source document a help answer hands the reader.
 *
 * The help center answers "what does it do". These four files answer
 * "prove it": this map is the route from an answer to its evidence, so a
 * reader who finishes an answer about encryption can go straight to the
 * encryption.
 *
 * STRUCTURE, NOT COPY. A row renders as the file name plus the exact
 * heading it jumps to, both quoted from the document itself, so there is
 * nothing here to translate and no locale batch when an entry gains a
 * row. The two strings around the block (its title and the line saying
 * the documents are English) live in `page.sourcesTitle` and
 * `page.sourcesNote` in every faq.json.
 *
 * A `heading` must match a real heading in that file character for
 * character: `pnpm check:docs` reads the four documents and fails when
 * one does not resolve, which is the only thing standing between a
 * renamed heading and a link that silently drops the reader at the top
 * of a long page. Omit `heading` to link the whole document.
 *
 * Keep this module import-free. `help-page.ts` evaluates it in Node at
 * build time, next to `faq.ts`.
 *
 * // Spec: ops/docs/help-center.md (source blocks)
 */

/** Repository root. Every document below is published from it. */
const REPO_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app';

/** The published files a source row may point at, keyed to their paths. */
export const SOURCE_FILES = {
  security: 'SECURITY.md',
  threatModel: 'THREAT_MODEL.md',
  verify: 'VERIFY.md',
  crypto: 'crypto/crypto.ts',
} as const;

type SourceDoc = keyof typeof SOURCE_FILES;

/** One row: a file, and the heading inside it that answers this question. */
export type FaqSource = {
  doc: SourceDoc;
  /** Exact heading text, minus the leading hashes. Omit to link the file. */
  heading?: string;
};

/**
 * GitHub's heading anchor: lower case, punctuation dropped, then every
 * space becomes a hyphen. Runs of spaces are NOT collapsed, because
 * GitHub does not collapse them either: a heading with a standalone
 * slash leaves two spaces behind once the slash is stripped, and the
 * anchor it serves carries two hyphens ("Lock / PIN-protect notes"
 * becomes `lock--pin-protect-notes`).
 *
 * `check:docs` re-derives every anchor with this function from the real
 * headings, so the two can never drift apart.
 */
function headingAnchor(heading: string): string {
  return heading
    .trim()
    .toLowerCase()
    .replace(/[^\w\- ]+/g, '')
    .replace(/ /g, '-');
}

/** The URL one row links to. */
export function sourceUrl(src: FaqSource): string {
  const file = `${REPO_URL}/blob/main/${SOURCE_FILES[src.doc]}`;
  return src.heading ? `${file}#${headingAnchor(src.heading)}` : file;
}

/**
 * Entry id to source rows. Two rows is the ceiling: a third competes
 * with the answer above it, and an answer that genuinely needs three
 * documents is usually two answers.
 */
export const FAQ_SOURCES: Readonly<Record<string, readonly FaqSource[]>> = {
  // Security & privacy
  'what-can-you-see': [
    { doc: 'security', heading: 'What the server sees' },
    { doc: 'verify', heading: 'Tier 1: one minute, no tools' },
  ],
  'phrase-vs-password': [{ doc: 'threatModel', heading: 'Key derivation' }],
  'threat-model-levels': [
    { doc: 'threatModel', heading: 'OAuth users' },
    { doc: 'security', heading: 'OAuth and custodial mode' },
  ],
  'twelve-word-phrase': [{ doc: 'threatModel', heading: 'Key derivation' }],
  'guess-phrase': [
    { doc: 'threatModel', heading: 'Key derivation' },
    { doc: 'threatModel', heading: 'Out-of-scope threats' },
  ],
  'why-no-2fa': [{ doc: 'threatModel', heading: 'Out-of-scope threats' }],
  'bip39-wordlist': [{ doc: 'crypto' }],
  'no-ai': [{ doc: 'verify', heading: 'Tier 1: one minute, no tools' }],
  'burn-notes': [{ doc: 'threatModel', heading: 'Burn notes (one-time shares)' }],
  'share-with-someone': [{ doc: 'threatModel', heading: 'Burn notes (one-time shares)' }],
  'locked-vs-protected': [{ doc: 'threatModel', heading: 'Lock / PIN-protect notes' }],
  'biometric-unlock': [
    { doc: 'threatModel', heading: 'Local phrase-at-rest: biometric and PIN wrapping' },
  ],
  'open-source': [{ doc: 'verify' }, { doc: 'crypto' }],
  'report-vulnerability': [{ doc: 'security', heading: 'Reporting a vulnerability' }],

  // Account & recovery
  'oauth-recovery': [{ doc: 'threatModel', heading: 'OAuth users' }],
  'lost-device': [{ doc: 'threatModel', heading: 'Devices and fingerprint hashes' }],
  'forgot-pin': [{ doc: 'threatModel', heading: 'PIN protection' }],

  // Getting started
  'signup-options': [{ doc: 'threatModel', heading: 'OAuth users' }],

  // Sync & devices
  'add-second-device': [{ doc: 'threatModel', heading: 'QR sign-in and phrase handoff' }],
  'what-syncs': [{ doc: 'security', heading: 'What the server sees' }],
  'sync-conflicts': [{ doc: 'threatModel', heading: 'Sync, conflicts, and deletion' }],
  'remove-device': [{ doc: 'threatModel', heading: 'Devices and fingerprint hashes' }],
  'over-quota': [{ doc: 'security', heading: 'Quotas' }],

  // Your data
  'data-location': [
    { doc: 'security', heading: 'What the server sees' },
    { doc: 'threatModel', heading: 'Local storage at rest' },
  ],
  'clear-browser-data': [{ doc: 'threatModel', heading: 'Local storage at rest' }],
  'data-rights': [{ doc: 'security', heading: 'What we measure' }],

  // Apps & platforms
  'verify-download': [{ doc: 'verify', heading: 'Tier 3: a weekend, building it' }],
};
