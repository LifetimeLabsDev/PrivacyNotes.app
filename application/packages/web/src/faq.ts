/**
 * Public-facing FAQ: structure only - entry ids, group membership and
 * render order. The strings live in `src/locales/<lng>/faq.json`, with
 * English as the source of truth.
 *
 * RULE BOOK: `ops/docs/help-center.md`. Adding, writing, ordering and
 * retiring an entry are all covered there, including the two rules that
 * matter most here: an id is the public URL `/help/<id>/`, and
 * entries sharing a group must stay adjacent below.
 *
 * Keep this module import-free: `help-page.ts` transpiles it standalone
 * (esbuild) and evaluates it in Node at build time.
 */

export type FaqGroupKey =
  | 'gettingStarted'
  | 'securityPrivacy'
  | 'accountRecovery'
  | 'syncDevices'
  | 'yourData'
  | 'pricingPro'
  | 'appsPlatforms';

/** Group render order. Labels come from `groups.<key>` in the catalog. */
export const FAQ_GROUP_ORDER: readonly FaqGroupKey[] = [
  'gettingStarted',
  'securityPrivacy',
  'accountRecovery',
  'syncDevices',
  'yourData',
  'pricingPro',
  'appsPlatforms',
];

/**
 * Entry ids in render order. The id is the leaf URL `/help/<id>/` and
 * the hub anchor (never change one casually: shared links point at it).
 */
export const FAQ_STRUCTURE: ReadonlyArray<{ id: string; group: FaqGroupKey }> = [
  { id: 'try-before-signup', group: 'gettingStarted' },
  { id: 'signup-options', group: 'gettingStarted' },
  { id: 'need-email', group: 'gettingStarted' },
  { id: 'import-from-other-apps', group: 'gettingStarted' },
  { id: 'markdown-folder', group: 'gettingStarted' },
  { id: 'markdown-support', group: 'gettingStarted' },
  { id: 'markdown-syntax', group: 'gettingStarted' },
  { id: 'tasks', group: 'gettingStarted' },
  { id: 'journal', group: 'gettingStarted' },
  { id: 'bookmarks', group: 'gettingStarted' },
  { id: 'folders', group: 'gettingStarted' },
  { id: 'tags', group: 'gettingStarted' },
  { id: 'note-links', group: 'gettingStarted' },
  { id: 'appearance', group: 'gettingStarted' },
  { id: 'keyboard-shortcuts', group: 'gettingStarted' },
  { id: 'hotkey-cheat-sheet', group: 'gettingStarted' },
  { id: 'ask-an-ai', group: 'gettingStarted' },
  { id: 'what-can-you-see', group: 'securityPrivacy' },
  { id: 'phrase-vs-password', group: 'securityPrivacy' },
  { id: 'threat-model-levels', group: 'securityPrivacy' },
  { id: 'twelve-word-phrase', group: 'securityPrivacy' },
  { id: 'guess-phrase', group: 'securityPrivacy' },
  { id: 'why-no-2fa', group: 'securityPrivacy' },
  { id: 'bip39-wordlist', group: 'securityPrivacy' },
  { id: 'search-local', group: 'securityPrivacy' },
  { id: 'no-ai', group: 'securityPrivacy' },
  { id: 'burn-notes', group: 'securityPrivacy' },
  { id: 'share-with-someone', group: 'securityPrivacy' },
  { id: 'locked-vs-protected', group: 'securityPrivacy' },
  { id: 'biometric-unlock', group: 'securityPrivacy' },
  { id: 'open-source', group: 'securityPrivacy' },
  { id: 'report-vulnerability', group: 'securityPrivacy' },
  { id: 'lost-phrase', group: 'accountRecovery' },
  { id: 'oauth-recovery', group: 'accountRecovery' },
  { id: 'phrase-compromised', group: 'accountRecovery' },
  { id: 'lost-device', group: 'accountRecovery' },
  { id: 'forgot-pin', group: 'accountRecovery' },
  { id: 'delete-account', group: 'accountRecovery' },
  { id: 'add-second-device', group: 'syncDevices' },
  { id: 'what-syncs', group: 'syncDevices' },
  { id: 'offline', group: 'syncDevices' },
  { id: 'pause-sync', group: 'syncDevices' },
  { id: 'wifi-only', group: 'syncDevices' },
  { id: 'sync-conflicts', group: 'syncDevices' },
  { id: 'remove-device', group: 'syncDevices' },
  { id: 'device-limit', group: 'syncDevices' },
  { id: 'over-quota', group: 'syncDevices' },
  { id: 'data-location', group: 'yourData' },
  { id: 'export', group: 'yourData' },
  { id: 'print', group: 'yourData' },
  { id: 'backup-strategy', group: 'yourData' },
  { id: 'restore-backup', group: 'yourData' },
  { id: 'clear-browser-data', group: 'yourData' },
  { id: 'android-backup', group: 'yourData' },
  { id: 'storage-usage', group: 'yourData' },
  { id: 'storage-after-delete', group: 'yourData' },
  { id: 'attachment-limits', group: 'yourData' },
  { id: 'upload-failed', group: 'yourData' },
  { id: 'trash-auto-delete', group: 'yourData' },
  { id: 'note-history', group: 'yourData' },
  { id: 'vault', group: 'yourData' },
  { id: 'vault-totp', group: 'yourData' },
  { id: 'note-size-limit', group: 'yourData' },
  { id: 'leaving', group: 'yourData' },
  { id: 'data-rights', group: 'yourData' },
  { id: 'referral-links', group: 'yourData' },
  { id: 'shutdown', group: 'yourData' },
  { id: 'free-vs-pro', group: 'pricingPro' },
  { id: 'one-time-pricing', group: 'pricingPro' },
  { id: 'pro-cross-platform', group: 'pricingPro' },
  { id: 'family-sharing', group: 'pricingPro' },
  { id: 'business-use', group: 'pricingPro' },
  { id: 'pro-not-active', group: 'pricingPro' },
  { id: 'storage-addons', group: 'pricingPro' },
  { id: 'manage-storage-addon', group: 'pricingPro' },
  { id: 'store-purchases', group: 'pricingPro' },
  { id: 'refunds', group: 'pricingPro' },
  { id: 'paddle-privacy', group: 'pricingPro' },
  { id: 'buy-pro-anonymously', group: 'pricingPro' },
  { id: 'platforms', group: 'appsPlatforms' },
  { id: 'verify-download', group: 'appsPlatforms' },
  { id: 'feature-requests', group: 'appsPlatforms' },
  { id: 'android-updates', group: 'appsPlatforms' },
  { id: 'obtainium', group: 'appsPlatforms' },
  { id: 'play-vs-apk', group: 'appsPlatforms' },
  { id: 'languages', group: 'appsPlatforms' },
  { id: 'translation-quality', group: 'appsPlatforms' },
];

/** A displayed entry, assembled from structure + a language catalog. */
export type FaqEntry = {
  /** Stable slug: the hub anchor id and the leaf URL segment. */
  id: string;
  /** Localized group headline. */
  group: string;
  question: string;
  /** One string per paragraph. Markdown [text](url) links only. */
  answer: string[];
};

/**
 * Assembles the ordered, grouped entry list from the structure and two
 * lookups. `entryStrings` returns null (or an empty/missing shape) to
 * skip an entry, which keeps group adjacency intact by construction.
 */
export function assembleFaq(
  groupLabel: (key: FaqGroupKey) => string,
  entryStrings: (id: string) => { question: string; answer: string[] } | null,
): FaqEntry[] {
  const out: FaqEntry[] = [];
  for (const row of FAQ_STRUCTURE) {
    const s = entryStrings(row.id);
    if (!s || !s.question || !Array.isArray(s.answer) || s.answer.length === 0) continue;
    out.push({ id: row.id, group: groupLabel(row.group), question: s.question, answer: s.answer });
  }
  return out;
}
