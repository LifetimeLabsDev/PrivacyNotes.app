import { lazy, Suspense, type ComponentType, type Dispatch, type MutableRefObject, type SetStateAction } from 'react';
import type { TFunction } from 'i18next';
import type { AuthState } from '../auth';
import type { AttachmentStore } from '../attachmentStore';
import type { LocalNote } from '../db';
import type { FolderDef } from '../folders';
import type { ImageStore } from '../imageStore';
import { AppearanceSheet } from '../AppearanceSheet';
import { JournalsSheet } from '../JournalsSheet';
import { LanguageSheet } from '../LanguageSheet';
import { exemptOpts } from '../i18nExempt';
import { Book, ChartBar, CreditCard, Database, Info, Question, Repeat, Shield, Sun, Translate, User } from '../icons';
import { activeLocale } from '../languages';
import { helpPath } from '../localeRoutes';
import { updateNote } from '../notesRepo';
import { isWeekJournal } from '../notesViewUtils';
import type { View } from '../views';
import type { SettingsCategory } from '../SettingsShell';
import { siteHref } from '../siteLinks';
import type { UserSettings } from '../userSettings';

/**
 * Code-split a modal component while keeping its call sites identical.
 * The returned component lazy-loads the chunk on first render; the null
 * Suspense fallback means the modal simply appears a frame later (instant
 * on warm cache, ~one round-trip cold). This keeps the heavy, rarely-open
 * modals (stats, settings, security, about, import, history) out of the
 * boot-path bundle.
 */
function lazyModal<P extends object>(
  load: () => Promise<ComponentType<P>>,
): ComponentType<P> {
  // The casts paper over React.lazy's strict generic variance; the outer
  // signature keeps every call site fully typed against the real props.
  const Inner = lazy(async () => ({
    default: (await load()) as ComponentType<unknown>,
  })) as unknown as ComponentType<P>;
  return function LazyModal(props: P) {
    return (
      <Suspense fallback={null}>
        <Inner {...props} />
      </Suspense>
    );
  };
}

export const StatsModal = lazyModal(() => import('../StatsModal').then((m) => m.StatsModal));
export const AboutModal = lazyModal(() => import('../AboutModal').then((m) => m.AboutModal));
export const SecurityModal = lazyModal(() => import('../SecurityModal').then((m) => m.SecurityModal));
export const SyncOptionsModal = lazyModal(() => import('../SyncOptionsModal').then((m) => m.SyncOptionsModal));
export const NoteHistoryModal = lazyModal(() => import('../NoteHistoryModal').then((m) => m.NoteHistoryModal));
export const ImportModal = lazyModal(() => import('../import/ImportModal').then((m) => m.ImportModal));

type Authed = Extract<AuthState, { status: 'authenticated' }>;

/**
 * Build the SettingsShell categories array. Called inline where the array
 * literal used to sit - fresh on every render, deliberately NOT memoized:
 * the renders close over live view state, and a memoized array would hold
 * stale closures (same rule as contextMenus).
 */
export function buildSettingsCategories({
  t,
  notes,
  userSettings,
  mutateSettings,
  onEditorModeChange,
  onToggleHiddenView,
  auth,
  settingsAutoVerify,
  onOpenNote,
  setShowSettings,
  setShowUpgrade,
  setImportToast,
  handleSignOutClick,
  mergeImportedFolders,
  exportAllMarkdownZip,
  exportAllHtmlZip,
  exportAllJson,
  exportEncryptedBackup,
  exportEncryptedFullBackup,
  decryptFullBackup,
  exportVault,
  exportBookmarks,
  importEncryptedBackup,
  imageStoreRef,
  attachmentStoreRef,
  refresh,
  runSync,
  saveWeekReflection,
}: {
  t: TFunction;
  notes: LocalNote[];
  userSettings: UserSettings;
  mutateSettings: (updater: (prev: UserSettings) => UserSettings) => void;
  /** Sets userSettings.editorMode AFTER flushing buffered body edits -
   *  the mode swap remounts the open note's editor from selected.body.
   *  Built in NotesView; never write editorMode through mutateSettings. */
  onEditorModeChange: (m: 'formatted' | 'markdown') => void;
  /** Switches one view off, or back on, in the sidebar or in the All list.
   *  Built in NotesView because hiding the OPEN view also leaves it, which
   *  this module cannot do; never write hiddenViews/hiddenInAll through
   *  mutateSettings. Spec: ops/docs/plans/sidebar-views.md */
  onToggleHiddenView: (field: 'hiddenViews' | 'hiddenInAll', key: View) => void;
  auth: Authed;
  settingsAutoVerify: boolean;
  /** ID & Sync's "Open" for a note the last pass could not push. */
  onOpenNote: (id: string) => void;
  setShowSettings: Dispatch<SetStateAction<boolean>>;
  setShowUpgrade: (next: { trigger: 'theme' | null }) => void;
  setImportToast: Dispatch<SetStateAction<string | null>>;
  handleSignOutClick: () => void;
  mergeImportedFolders: (incoming: FolderDef[]) => Map<string, string>;
  exportAllMarkdownZip: (ns: LocalNote[]) => Promise<void>;
  exportAllHtmlZip: (ns: LocalNote[]) => Promise<void>;
  exportAllJson: (ns: LocalNote[]) => Promise<void>;
  exportEncryptedBackup: (ns: LocalNote[]) => Promise<void>;
  exportEncryptedFullBackup: (ns: LocalNote[]) => Promise<void>;
  decryptFullBackup: (file: File) => Promise<File>;
  exportVault: (ns: LocalNote[]) => Promise<void>;
  exportBookmarks: (ns: LocalNote[]) => Promise<void>;
  importEncryptedBackup: (file: File) => Promise<number>;
  imageStoreRef: MutableRefObject<ImageStore | null>;
  attachmentStoreRef: MutableRefObject<AttachmentStore | null>;
  refresh: () => Promise<LocalNote[]>;
  runSync: () => Promise<void>;
  /** Writes the weekly reflection, creating the Monday entry if needed. */
  saveWeekReflection: (text: string) => Promise<void>;
}): SettingsCategory[] {
  return [
            {
              id: 'stats',
              label: t('settings.statsLabel'),
              group: t('settings.groupYourNotes'),
              icon: <ChartBar size={18} aria-hidden="true" />,
              render: () => (
                <StatsModal
                  embedded
                  notes={notes}
                  // Deleted medications included on purpose: their log
                  // entries already count toward adherence, and without the
                  // template nothing can resolve the id back into a name.
                  medications={userSettings.medications}
                  isPro={auth.isPro}
                  onOpenUpgrade={() => { setShowSettings(false); setShowUpgrade({ trigger: null }); }}
                  onClose={() => setShowSettings(false)}
                  weekReflection={(() => {
                    const entry = notes.find((n) => n.deleted === 0 && n.trashed === 0 && n.type === 'journal' && isWeekJournal(n));
                    const trackers = entry?.trackers as Record<string, unknown> | undefined;
                    return (trackers?.weekReflection as string) ?? '';
                  })()}
                  onWeekReflectionChange={(text) => void saveWeekReflection(text)}
                />
              ),
            },
            {
              // How new journal entries are titled (GitHub #200). Sits in
              // "Your notes" rather than Appearance: a title shape is
              // content, not chrome.
              id: 'journals',
              label: t('settings.journalsLabel'),
              group: t('settings.groupYourNotes'),
              icon: <Book size={18} aria-hidden="true" />,
              render: () => (
                <JournalsSheet
                  format={userSettings.journalTitleFormat}
                  onFormatChange={(f) => mutateSettings((prev) => ({ ...prev, journalTitleFormat: f }))}
                  suffix={userSettings.journalTitleSuffix}
                  onSuffixChange={(s) => mutateSettings((prev) => ({ ...prev, journalTitleSuffix: s }))}
                />
              ),
            },
            {
              id: 'import',
              label: t('settings.importLabel', exemptOpts('notes:settings.importLabel')),
              group: t('settings.groupYourNotes'),
              icon: <Repeat size={18} aria-hidden="true" />,
              render: () => (
                <ImportModal
                  embedded
                  onClose={() => setShowSettings(false)}
                  initialTab="import"
                  notes={notes}
                  onImportFolders={mergeImportedFolders}
                  onExportAllMdZip={(ns) => void exportAllMarkdownZip(ns)}
                  onExportAllHtmlZip={(ns) => void exportAllHtmlZip(ns)}
                  onExportAllJson={exportAllJson}
                  onExportEncrypted={exportEncryptedBackup}
                  onExportEncryptedZip={(ns) => void exportEncryptedFullBackup(ns)}
                  decryptFullBackup={decryptFullBackup}
                  onExportVault={exportVault}
                  onExportBookmarks={exportBookmarks}
                  onImportEncrypted={importEncryptedBackup}
                  onBlobsRestored={() => {
                    imageStoreRef.current?.processPendingUploads().catch((err) =>
                      console.warn('[imageStore] post-restore processPendingUploads failed:', err),
                    );
                    attachmentStoreRef.current?.processPendingUploads().catch((err) =>
                      console.warn('[attachmentStore] post-restore processPendingUploads failed:', err),
                    );
                  }}
                  onImported={async (count, skippedDuplicates) => {
                    setImportToast(
                      skippedDuplicates
                        ? `${t('toast.importedSyncing', { count })} ${t('shell:bookmarks.importSkipped', { count: skippedDuplicates })}`
                        : t('toast.importedSyncing', { count }),
                    );
                    mutateSettings((prev) =>
                      prev.importHintDismissed ? prev : { ...prev, importHintDismissed: true },
                    );
                    await refresh();
                    void runSync();
                    window.setTimeout(() => setImportToast(null), 4000);
                  }}
                />
              ),
            },
            {
              id: 'plan',
              label: t('settings.planLabel'),
              group: t('settings.groupAccount'),
              icon: <CreditCard size={18} aria-hidden="true" />,
              render: () => (
                <SyncOptionsModal
                  embedded
                  tab="plan"
                  onSyncNow={runSync}
                  onOpenNote={onOpenNote}
                  onClose={() => setShowSettings(false)}
                  onOpenUpgrade={() => { setShowSettings(false); setShowUpgrade({ trigger: null }); }}
                  onSignOut={handleSignOutClick}
                />
              ),
            },
            {
              id: 'storage',
              label: t('settings.storageLabel'),
              group: t('settings.groupAccount'),
              icon: <Database size={18} aria-hidden="true" />,
              render: () => (
                <SyncOptionsModal
                  embedded
                  tab="storage"
                  onSyncNow={runSync}
                  onOpenNote={onOpenNote}
                  onClose={() => setShowSettings(false)}
                  onOpenUpgrade={() => { setShowSettings(false); setShowUpgrade({ trigger: null }); }}
                  onSignOut={handleSignOutClick}
                />
              ),
            },
            {
              id: 'security',
              label: t('settings.securityLabel'),
              group: t('settings.groupAccount'),
              icon: <Shield size={18} aria-hidden="true" />,
              render: () => (
                <SecurityModal
                  embedded
                  phrase={auth.phrase}
                  defaultTab="pin"
                  pinTimeoutMinutes={userSettings.pinTimeoutMinutes}
                  onPinTimeoutChange={(minutes) => {
                    mutateSettings((prev) => ({ ...prev, pinTimeoutMinutes: minutes }));
                  }}
                  userSettings={userSettings}
                  onSettingsChange={(next) => {
                    mutateSettings(() => next);
                  }}
                  onClose={() => setShowSettings(false)}
                  pubkey={auth.pubkey}
                />
              ),
            },
            {
              id: 'me',
              label: t('settings.accountLabel', exemptOpts('notes:settings.accountLabel')),
              group: t('settings.groupAccount'),
              icon: <User size={18} aria-hidden="true" />,
              render: () => (
                <SyncOptionsModal
                  embedded
                  tab="me"
                  onSyncNow={runSync}
                  onOpenNote={onOpenNote}
                  autoVerify={settingsAutoVerify}
                  onClose={() => setShowSettings(false)}
                  onOpenUpgrade={() => { setShowSettings(false); setShowUpgrade({ trigger: null }); }}
                  onSignOut={handleSignOutClick}
                />
              ),
            },
            {
              id: 'appearance',
              label: t('settings.appearanceLabel'),
              group: t('settings.groupBrand'),
              icon: <Sun size={18} aria-hidden="true" />,
              render: () => (
                <AppearanceSheet
                  embedded
                  isPro={auth.isPro ?? false}
                  viewMode={userSettings.viewMode}
                  onViewModeChange={(m) => mutateSettings((prev) => ({ ...prev, viewMode: m }))}
                  editorMode={userSettings.editorMode}
                  onEditorModeChange={onEditorModeChange}
                  hiddenViews={userSettings.hiddenViews}
                  hiddenInAll={userSettings.hiddenInAll}
                  onToggleHidden={onToggleHiddenView}
                  onOpenUpgrade={() => { setShowSettings(false); setShowUpgrade({ trigger: 'theme' }); }}
                  onClose={() => setShowSettings(false)}
                />
              ),
            },
            {
              id: 'language',
              label: t('settings.languageLabel'),
              // No shell description: the pane leads with the spell-check
              // section, so its subtitle sits inside LanguageSheet, directly
              // above the language grid it actually describes.
              group: t('settings.groupBrand'),
              icon: <Translate size={18} aria-hidden="true" />,
              render: () => <LanguageSheet embedded onClose={() => setShowSettings(false)} />,
            },
            {
              id: 'about',
              label: t('settings.aboutLabel'),
              group: t('settings.groupBrand'),
              icon: <Info size={18} aria-hidden="true" />,
              render: () => (
                <AboutModal embedded onClose={() => setShowSettings(false)} />
              ),
            },
            {
              // Link row, not a pane: the static /help site is the only FAQ
              // renderer, so this opens the browser rather than duplicating
              // it in-app. Spec: ops/docs/bundle-size.md (in-app FAQ tab)
              id: 'help',
              label: t('settings.helpLabel'),
              group: t('settings.groupBrand'),
              icon: <Question size={18} aria-hidden="true" />,
              href: siteHref(helpPath(activeLocale())),
            },
          ] satisfies SettingsCategory[];
}
