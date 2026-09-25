/**
 * The index of the settings search: one entry per setting a reader can look
 * for, pointing at the catalog keys its pane already shows. Every language
 * gets its index from its own catalogs, so nothing here is translated.
 *
 * `id` is also the `data-setting` marker on the rendered row; the anchor test
 * (tests/settingsSearch.test.ts) holds the two lists together. A key is
 * written `namespace:path`. `brand` marks a label that is a product name and
 * reads the same in every language. `keywords` says the entry has a list under
 * `settingsSearch:keywords.<id with dots as underscores>`. `shownOn` names the
 * pane's own rule for a row some devices never show; the search reads it
 * through `isShown` in SettingsSearchResults.tsx, which keeps this file data.
 * Spec: ops/docs/ui-patterns.md (section 114, settings search)
 */
export type SectionId =
  | 'stats'
  | 'journals'
  | 'import'
  | 'plan'
  | 'storage'
  | 'images'
  | 'security'
  | 'me'
  | 'appearance'
  | 'language'
  | 'about'
  | 'help';

export type SettingEntry = {
  id: string;
  section: SectionId;
  /** The inner tab the row lives on, handed to the pane as its first tab. */
  tab?: string;
  label: string;
  brand?: true;
  options?: readonly string[];
  keywords?: true;
  shownOn?: 'storeBuild' | 'keyboard';
  /** An entry for a whole section: it opens the pane and flashes nothing. */
  isSection?: true;
};

/** Each section's name, the key the rail already shows. */
export const SECTION_LABEL: Record<SectionId, string> = {
  stats: 'notes:settings.statsLabel',
  journals: 'notes:settings.journalsLabel',
  import: 'notes:settings.importLabel',
  plan: 'notes:settings.planLabel',
  storage: 'notes:settings.storageLabel',
  images: 'notes:settings.imagesLabel',
  security: 'notes:settings.securityLabel',
  me: 'notes:settings.accountLabel',
  appearance: 'notes:settings.appearanceLabel',
  language: 'notes:settings.languageLabel',
  about: 'notes:settings.aboutLabel',
  help: 'notes:settings.helpLabel',
};

/** The label of each inner tab, shown after a result's name. */
export const TAB_LABEL: Record<string, string> = {
  'stats/writing': 'stats:tabs.writing',
  'stats/wellness': 'stats:tabs.wellness',
  'import/import': 'importExport:shell.tabImport',
  'import/export': 'importExport:shell.tabExport',
  'import/restore': 'importExport:shell.tabRestore',
  'import/vault': 'importExport:shell.tabVault',
  'security/pin': 'security:modal.tabPin',
  'security/biometric': 'security:modal.tabBiometric',
  'security/phrase': 'security:modal.tabPhrase',
  'appearance/style': 'settings:appearance.tabStyle',
  'appearance/lists': 'settings:appearance.tabLists',
  'about/about': 'landing:about.tabs.about',
  'about/changelog': 'landing:about.tabs.changelog',
  'about/hotkeys': 'landing:about.tabs.hotkeys',
  'about/rating': 'landing:about.tabs.rating',
};

const SECTION_ENTRIES: SettingEntry[] = (Object.keys(SECTION_LABEL) as SectionId[]).map((section) => ({
  id: `section.${section}`,
  section,
  label: SECTION_LABEL[section],
  keywords: true,
  isSection: true,
}));

/** An importer row, named by its product. */
const importer = (id: string, name: string, tab: 'import' | 'vault' = 'import'): SettingEntry => ({
  id: `import.source.${id}`,
  section: 'import',
  tab,
  label: name,
  brand: true,
});

/** An importer row whose name is translated. */
const keyedImporter = (id: string, key: string, tab: 'import' | 'vault' = 'import'): SettingEntry => ({
  id: `import.source.${id}`,
  section: 'import',
  tab,
  label: key,
});

const ROW_ENTRIES: SettingEntry[] = [
  // Statistics
  { id: 'stats.writing', section: 'stats', tab: 'writing', label: 'stats:tabs.writing', keywords: true },
  { id: 'stats.streak', section: 'stats', tab: 'writing', label: 'stats:writing.currentStreak', options: ['stats:writing.longestStreak'], keywords: true },
  { id: 'stats.wellness', section: 'stats', tab: 'wellness', label: 'stats:tabs.wellness', keywords: true },
  { id: 'stats.moodTrend', section: 'stats', tab: 'wellness', label: 'stats:wellness.overview.moodTrend' },
  { id: 'stats.wellnessExport', section: 'stats', tab: 'wellness', label: 'stats:wellness.export.heading', keywords: true },

  // Journals
  { id: 'journals.suffix', section: 'journals', label: 'settings:journals.suffixTitle', keywords: true },

  // Import & Export
  { id: 'import.import', section: 'import', tab: 'import', label: 'importExport:shell.tabImport' },
  { id: 'import.autoTag', section: 'import', tab: 'import', label: 'importExport:importPick.autoTagLabel' },
  keyedImporter('browser-bookmarks', 'importExport:sourceLabel.browserBookmarks'),
  keyedImporter('vcard', 'importExport:sourceLabel.vcard'),
  importer('apple-journal', 'Apple Journal'),
  importer('apple-notes', 'Apple Notes'),
  importer('evernote', 'Evernote'),
  importer('google-keep', 'Google Keep'),
  importer('ia-writer', 'iA Writer'),
  keyedImporter('markdown-folder', 'importExport:sourceLabel.markdownFolder'),
  importer('nextcloud-notes', 'Nextcloud Notes'),
  importer('notesnook', 'Notesnook'),
  importer('obsidian', 'Obsidian'),
  importer('samsung-notes', 'Samsung Notes'),
  importer('simplenote', 'Simplenote'),
  importer('standard-notes', 'Standard Notes'),
  importer('typora', 'Typora'),
  importer('upnote', 'UpNote'),
  importer('zettlr', 'Zettlr'),
  { id: 'import.export', section: 'import', tab: 'export', label: 'importExport:shell.tabExport', keywords: true },
  { id: 'export.zipBackup', section: 'import', tab: 'export', label: 'importExport:export.zipBackupTitle', keywords: true },
  { id: 'export.encryptedZip', section: 'import', tab: 'export', label: 'importExport:export.encryptedZipBackupTitle' },
  { id: 'export.encryptedBackup', section: 'import', tab: 'export', label: 'importExport:export.encryptedBackupTitle' },
  { id: 'export.htmlArchive', section: 'import', tab: 'export', label: 'importExport:export.htmlArchiveTitle' },
  { id: 'export.textBackup', section: 'import', tab: 'export', label: 'importExport:export.textBackupTitle' },
  { id: 'export.bookmarks', section: 'import', tab: 'export', label: 'importExport:export.bookmarksExportTitle' },
  { id: 'export.contacts', section: 'import', tab: 'export', label: 'importExport:export.contactsExportTitle' },
  { id: 'export.vault', section: 'import', tab: 'export', label: 'importExport:export.vaultExportTitle' },
  { id: 'import.restore', section: 'import', tab: 'restore', label: 'importExport:shell.tabRestore' },
  { id: 'restore.fullBackup', section: 'import', tab: 'restore', label: 'importExport:restorePick.fullBackupTitle' },
  { id: 'restore.encryptedBackup', section: 'import', tab: 'restore', label: 'importExport:restorePick.encryptedBackupTitle' },
  { id: 'import.vault', section: 'import', tab: 'vault', label: 'importExport:shell.tabVault', keywords: true },
  importer('bitwarden', 'Bitwarden', 'vault'),
  keyedImporter('browser-passwords', 'importExport:sourceLabel.browserPasswords', 'vault'),

  // Account (the plan pane)
  { id: 'plan.devices', section: 'plan', label: 'settings:devices.heading', keywords: true },
  { id: 'plan.upgrade', section: 'plan', label: 'settings:plan.upgradeToPro', keywords: true },
  { id: 'plan.restorePurchases', section: 'plan', label: 'settings:plan.restore.heading', shownOn: 'storeBuild' },
  { id: 'plan.signOut', section: 'plan', label: 'settings:account.signOut', keywords: true },
  { id: 'plan.dangerZone', section: 'plan', label: 'settings:danger.heading', keywords: true },

  // Storage
  { id: 'storage.quota', section: 'storage', label: 'settings:storage.quotaLabel', keywords: true },
  { id: 'storage.addon', section: 'storage', label: 'settings:storage.addonHeading', keywords: true },

  // Images
  { id: 'images.spaceSaver', section: 'images', label: 'settings:images.spaceSaverTitle', keywords: true },
  { id: 'images.contactPhotos', section: 'images', label: 'settings:images.contactTitle' },
  { id: 'images.removeLocation', section: 'images', label: 'settings:images.removeLocationTitle', keywords: true },

  // Security
  { id: 'security.pin', section: 'security', tab: 'pin', label: 'security:modal.tabPin', keywords: true },
  { id: 'security.setPin', section: 'security', tab: 'pin', label: 'security:pinTab.setPin', options: ['security:pinTab.updatePin'] },
  { id: 'security.removePin', section: 'security', tab: 'pin', label: 'security:pinTab.removePin' },
  { id: 'security.reaskAfter', section: 'security', tab: 'pin', label: 'security:pinTab.reaskAfter', keywords: true },
  { id: 'security.biometric', section: 'security', tab: 'biometric', label: 'security:modal.tabBiometric', keywords: true },
  { id: 'security.enableBiometric', section: 'security', tab: 'biometric', label: 'security:biometricTab.enable' },
  { id: 'security.appLock', section: 'security', tab: 'biometric', label: 'security:biometricTab.lockOnOpen', keywords: true },
  { id: 'security.relockAfter', section: 'security', tab: 'biometric', label: 'security:biometricTab.relockAfter', keywords: true },
  { id: 'security.phrase', section: 'security', tab: 'phrase', label: 'security:modal.tabPhrase', keywords: true },
  { id: 'security.qrCode', section: 'security', tab: 'phrase', label: 'security:phraseView.showQr', options: ['security:phraseView.saveQr'] },
  { id: 'security.copyPhrase', section: 'security', tab: 'phrase', label: 'security:phraseView.copyPhrase' },
  { id: 'security.custody', section: 'security', tab: 'phrase', label: 'security:custody.eyebrow', keywords: true },

  // ID & Sync
  { id: 'me.thisDevice', section: 'me', label: 'settings:syncPanel.thisDevice', options: ['settings:syncPanel.syncNow'] },
  { id: 'me.pauseSync', section: 'me', label: 'settings:syncPanel.pauseSync', keywords: true },
  { id: 'me.filesWifiOnly', section: 'me', label: 'settings:syncPanel.filesWifiOnly', keywords: true },
  { id: 'me.where', section: 'me', label: 'settings:syncPanel.whereTitle', keywords: true },
  { id: 'me.accountId', section: 'me', label: 'settings:accountId.heading', keywords: true },
  { id: 'me.activity', section: 'me', label: 'settings:syncPanel.activity', keywords: true },

  // Appearance
  { id: 'appearance.style', section: 'appearance', tab: 'style', label: 'settings:appearance.tabStyle' },
  { id: 'appearance.mode', section: 'appearance', tab: 'style', label: 'settings:appearance.modeTitle', options: ['settings:appearance.modeAuto', 'settings:appearance.light', 'settings:appearance.dark'], keywords: true },
  { id: 'appearance.theme', section: 'appearance', tab: 'style', label: 'settings:appearance.lightThemes', options: ['settings:appearance.darkThemes'], keywords: true },
  { id: 'appearance.textSize', section: 'appearance', tab: 'style', label: 'settings:appearance.textSizeTitle', options: ['settings:appearance.textSizeSmall', 'settings:appearance.textSizeDefault', 'settings:appearance.textSizeLarge', 'settings:appearance.textSizeLargest'], keywords: true },
  { id: 'appearance.lineSpacing', section: 'appearance', tab: 'style', label: 'settings:appearance.lineSpacingTitle', options: ['settings:appearance.lineSpacingTight', 'settings:appearance.lineSpacingCompact', 'settings:appearance.lineSpacingNormal'], keywords: true },
  { id: 'appearance.tintNotes', section: 'appearance', tab: 'style', label: 'settings:appearance.tintNotesTitle', keywords: true },
  { id: 'appearance.contentWidth', section: 'appearance', tab: 'style', label: 'settings:appearance.contentWidthTitle', options: ['settings:appearance.contentWidthWide', 'settings:appearance.contentWidthFull'], keywords: true },
  { id: 'appearance.editor', section: 'appearance', tab: 'style', label: 'settings:appearance.editorTitle', options: ['settings:appearance.editorFormatted', 'settings:appearance.editorMarkdown'], keywords: true },
  { id: 'appearance.favicons', section: 'appearance', tab: 'style', label: 'settings:appearance.faviconsTitle', keywords: true },
  { id: 'appearance.invisibles', section: 'appearance', tab: 'style', label: 'settings:appearance.invisiblesTitle', keywords: true },
  { id: 'appearance.lists', section: 'appearance', tab: 'lists', label: 'settings:appearance.tabLists' },
  { id: 'appearance.startView', section: 'appearance', tab: 'lists', label: 'settings:appearance.startViewTitle', keywords: true },
  { id: 'appearance.view', section: 'appearance', tab: 'lists', label: 'settings:appearance.viewTitle', options: ['settings:appearance.viewList', 'settings:appearance.viewGrid'], keywords: true },
  { id: 'appearance.sidebar', section: 'appearance', tab: 'lists', label: 'settings:appearance.sidebarTitle', options: ['settings:appearance.colInSidebar', 'settings:appearance.colInAll'], keywords: true },

  // Language
  { id: 'language.spellCheck', section: 'language', label: 'settings:appearance.spellCheckTitle', keywords: true },
  { id: 'language.language', section: 'language', label: 'settings:appearance.language', keywords: true },
  { id: 'language.reportMistake', section: 'language', label: 'settings:language.reportMistake' },

  // About
  { id: 'about.about', section: 'about', tab: 'about', label: 'landing:about.tabs.about' },
  { id: 'about.version', section: 'about', tab: 'about', label: 'landing:about.versionHeading', keywords: true },
  { id: 'about.roadmap', section: 'about', tab: 'about', label: 'landing:about.tabs.roadmap' },
  { id: 'about.openSource', section: 'about', tab: 'about', label: 'landing:trust.openSourceHeading', keywords: true },
  { id: 'about.feedback', section: 'about', tab: 'about', label: 'landing:about.feedbackHeading', keywords: true },
  { id: 'about.dataStorage', section: 'about', tab: 'about', label: 'landing:trust.dataStorageHeading', keywords: true },
  { id: 'about.favicons', section: 'about', tab: 'about', label: 'landing:trust.faviconsHeading' },
  { id: 'about.legal', section: 'about', tab: 'about', label: 'landing:about.legalHeading', options: ['landing:about.privacyPolicy', 'landing:about.termsOfService'] },
  { id: 'about.changelog', section: 'about', tab: 'changelog', label: 'landing:about.tabs.changelog', keywords: true },
  { id: 'about.hotkeys', section: 'about', tab: 'hotkeys', label: 'landing:about.tabs.hotkeys', keywords: true, shownOn: 'keyboard' },
  { id: 'about.rating', section: 'about', tab: 'rating', label: 'landing:about.tabs.rating', keywords: true },
];

/** Sections first, so a section's own name ties ahead of a row with the same word. */
export const SETTING_ENTRIES: readonly SettingEntry[] = [...SECTION_ENTRIES, ...ROW_ENTRIES];

/** The keyword key of an entry. */
export function keywordKey(entry: SettingEntry): string {
  return `settingsSearch:keywords.${entry.id.replace(/\./g, '_')}`;
}
