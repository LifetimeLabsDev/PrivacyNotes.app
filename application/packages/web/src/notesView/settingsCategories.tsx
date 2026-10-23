import type { FormatBarBoardProps } from '../FormatBarBoard';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import { lazyModal } from '../chunkLoad';
import type { TFunction } from 'i18next';
import type { AuthState } from '../auth';
import type { AttachmentStore } from '../attachmentStore';
import type { LocalNote } from '../db';
import { journalOn } from '../notesViewUtils';
import type { FolderDef } from '../folders';
import type { ImportTarget } from '../import/destination';
import type { ImageStore } from '../imageStore';
import type { AppearancePane } from '../AppearanceSheet';
import { exemptOpts } from '../i18nExempt';
import { Calendar, ChartBar, CreditCard, Database, Info, Question, Repeat, ListBullets, Palette, Heartbeat, PencilLine, Shield, Toolbox, Translate, User, type Icon } from '../icons';
import { proUnlocked } from '../demo';
import { activeLocale } from '../languages';
import { helpPath } from '../localeRoutes';
import { updateNote } from '../notesRepo';
import { weekReflectionFor } from '../notesViewUtils';
import type { View } from '../views';
import type { SettingsCategory } from '../SettingsShell';
import { StoragePane } from './StoragePane';
import type { SectionId } from '../settingsSearch/registry';
import { siteHref } from '../siteLinks';
import { withCredentialChanges, type UserSettings } from '../userSettings';
import { applyNoteColorChoice, noteColorChoice } from '../itemStyles';
import type { ViewMode } from '../viewMode';
import { setDeviceLabel } from '../deviceLabels';
import type { ThemeBuilderTarget } from './useThemeBuilder';
import type { UpgradeTrigger } from '../UpgradeModal';

export const StatsModal = lazyModal(() => import('../StatsModal').then((m) => m.StatsModal));
export const AboutModal = lazyModal(() => import('../AboutModal').then((m) => m.AboutModal));
export const FeedbackModal = lazyModal(() => import('../FeedbackModal').then((m) => m.FeedbackModal));
export const SecurityModal = lazyModal(() => import('../SecurityModal').then((m) => m.SecurityModal));
export const PasswordGeneratorModal = lazyModal(() => import('../PasswordGenerator').then((m) => m.PasswordGeneratorModal));
export const SyncOptionsModal = lazyModal(() => import('../SyncOptionsModal').then((m) => m.SyncOptionsModal));
export const ClipPageModal = lazyModal(() => import('../ClipPageModal').then((m) => m.default));
export const NoteHistoryModal = lazyModal(() => import('../NoteHistoryModal').then((m) => m.NoteHistoryModal));
export const ImportModal = lazyModal(() => import('../import/ImportModal').then((m) => m.ImportModal));
export const MediaViewer = lazyModal(() => import('../MediaViewer').then((m) => m.MediaViewer));
export const PicturePicker = lazyModal(() => import('../PicturePicker').then((m) => m.PicturePicker));
// The settings window itself, so a failed load is retried as a whole.
export const SettingsShell = lazyModal(() => import('../SettingsWindow').then((m) => m.SettingsWindow));
export const AppearanceSheet = lazyModal(() => import('../AppearanceSheet').then((m) => m.AppearanceSheet));
const ImagesSheet = lazyModal(() => import('../ImagesSheet').then((m) => m.ImagesSheet));
const LanguageSheet = lazyModal(() => import('../LanguageSheet').then((m) => m.LanguageSheet));
const DateSheet = lazyModal(() => import('../LanguageSheet').then((m) => m.DateSheet));
const CalendarSettings = lazyModal(() => import('../CalendarSettings').then((m) => m.CalendarSettings));
const DateTimePane = lazyModal(() => import('../DateTimePane').then((m) => m.DateTimePane));
const TrackerSettingsPane = lazyModal(() => import('../TrackerConfig').then((m) => m.TrackerSettingsPane));

type Authed = Extract<AuthState, { status: 'authenticated' }>;

/** Each section's rail icon. The quick switcher draws it beside a setting. */
export const SETTINGS_SECTION_ICONS: Record<SectionId, Icon> = {
  stats: ChartBar,
  import: Repeat,
  plan: CreditCard,
  storage: Database,
  security: Shield,
  me: User,
  design: Palette,
  editor: PencilLine,
  formatBar: Toolbox,
  lists: ListBullets,
  trackers: Heartbeat,
  language: Translate,
  date: Calendar,
  about: Info,
  help: Question,
};

function railIcon(id: SectionId) {
  const RailIcon = SETTINGS_SECTION_ICONS[id];
  return <RailIcon size={18} aria-hidden="true" />;
}

/**
 * Build the SettingsShell categories array. Called inline where the array
 * literal used to sit - fresh on every render, deliberately NOT memoized:
 * the renders close over live view state, and a memoized array would hold
 * stale closures (same rule as contextMenus).
 */
export function buildSettingsCategories({
  t,
  notes,
  isNoteLocked,
  userSettings,
  mutateSettings,
  onEditorModeChange,
  viewMode,
  onViewModeChange,
  onToggleHiddenView,
  auth,
  settingsAutoVerify,
  onOpenNote,
  setShowSettings,
  setShowUpgrade,
  setImportToast,
  handleSignOutClick,
  mergeImportedFolders,
  importTarget,
  createImportFolder,
  mergeRestoredSettings,
  applyImportedTagColors,
  exportAllMarkdownZip,
  exportAllHtmlZip,
  exportAllJson,
  exportEncryptedBackup,
  exportEncryptedFullBackup,
  decryptFullBackup,
  exportVault,
  exportBookmarks,
  exportContacts,
  exportCalendar,
  importEncryptedBackup,
  imageStoreRef,
  attachmentStoreRef,
  refresh,
  runSync,
  saveWeekReflection,
  openThemeBuilder,
  formatBarBoard,
}: {
  t: TFunction;
  notes: LocalNote[];
  /** The view's lock predicate, for the readers of a journal's trackers. */
  isNoteLocked: (n: LocalNote) => boolean;
  userSettings: UserSettings;
  mutateSettings: (updater: (prev: UserSettings) => UserSettings) => void;
  /** Sets userSettings.editorMode AFTER flushing buffered body edits -
   *  the mode swap remounts the open note's editor from selected.body.
   *  Built in NotesView; never write editorMode through mutateSettings. */
  onEditorModeChange: (m: 'formatted' | 'markdown') => void;
  /** This device's layout choice (`viewMode.ts`), never the synced value. */
  viewMode: ViewMode;
  onViewModeChange: (m: ViewMode) => void;
  /** Switches one view off, or back on, in the sidebar or in the All list.
   *  Built in NotesView because hiding the OPEN view also leaves it, which
   *  this module cannot do; never write hiddenViews/hiddenInAll through
   *  mutateSettings. Spec: ops/docs/archive/sidebar-views.md */
  onToggleHiddenView: (field: 'hiddenViews' | 'hiddenInAll', key: View) => void;
  auth: Authed;
  settingsAutoVerify: boolean;
  /** ID & Sync's "Open" for a note the last pass could not push. */
  onOpenNote: (id: string) => void;
  setShowSettings: Dispatch<SetStateAction<boolean>>;
  setShowUpgrade: (next: { trigger: UpgradeTrigger }) => void;
  setImportToast: Dispatch<SetStateAction<string | null>>;
  handleSignOutClick: () => void;
  mergeImportedFolders: (
    incoming: FolderDef[],
    originalIds?: ReadonlyMap<string, string>,
    rootParent?: string | null,
  ) => Map<string, string>;
  importTarget: ImportTarget | undefined;
  createImportFolder: (name: string) => string | null;
  applyImportedTagColors: (colors: Map<string, string>) => void;
  mergeRestoredSettings: (
    settings: { itemStyles?: unknown; customThemes?: unknown; factors?: unknown; customHabits?: unknown },
    savedToFinal: ReadonlyMap<string, string>,
  ) => void;
  exportAllMarkdownZip: (ns: LocalNote[]) => Promise<void>;
  exportAllHtmlZip: (ns: LocalNote[]) => Promise<void>;
  exportAllJson: (ns: LocalNote[]) => Promise<void>;
  exportEncryptedBackup: (ns: LocalNote[]) => Promise<void>;
  exportEncryptedFullBackup: (ns: LocalNote[]) => Promise<void>;
  decryptFullBackup: (file: File) => Promise<File>;
  exportVault: (ns: LocalNote[]) => Promise<void>;
  exportBookmarks: (ns: LocalNote[]) => Promise<void>;
  exportContacts: (ns: LocalNote[]) => Promise<void>;
  exportCalendar: (ns: LocalNote[]) => Promise<void>;
  importEncryptedBackup: (file: File) => Promise<{ imported: number; updated: number; unchanged: number }>;
  imageStoreRef: MutableRefObject<ImageStore | null>;
  attachmentStoreRef: MutableRefObject<AttachmentStore | null>;
  refresh: () => Promise<LocalNote[]>;
  runSync: () => Promise<void>;
  /** Writes the weekly reflection, creating the Monday entry if needed. */
  saveWeekReflection: (text: string) => Promise<void>;
  /** Closes Settings and opens the theme builder. */
  openThemeBuilder: (target: ThemeBuilderTarget) => void;
  formatBarBoard: FormatBarBoardProps;
}): SettingsCategory[] {
  // Design, Editor and Lists are three panes of one sheet, one Settings
  // entry each. Spec: ops/docs/archive/ui-patterns.md (section 135)
  const appearancePane = (pane: AppearancePane, initialTab?: string) => (
    <AppearanceSheet
      embedded
      pane={pane}
      initialTab={initialTab}
      isPro={auth.isPro ?? false}
      viewMode={viewMode}
      onViewModeChange={onViewModeChange}
      editorMode={userSettings.editorMode}
      onEditorModeChange={onEditorModeChange}
      formatBar={formatBarBoard}
      lineSpacing={userSettings.lineSpacing}
      onLineSpacingChange={(next) => mutateSettings((prev) => ({ ...prev, lineSpacing: next }))}
      hiddenViews={userSettings.hiddenViews}
      hiddenInAll={userSettings.hiddenInAll}
      archivedInAll={userSettings.archivedInAll}
      onToggleHidden={onToggleHiddenView}
      startView={userSettings.startView}
      onStartViewChange={(next) => mutateSettings((prev) => ({ ...prev, startView: next }))}
      noteColors={noteColorChoice(userSettings.tintNotes, userSettings.noteColorStyle)}
      onNoteColorsChange={(next) => mutateSettings((prev) => applyNoteColorChoice(prev, next))}
      sinkCheckedTasks={userSettings.sinkCheckedTasks}
      onSinkCheckedTasksChange={(on) => mutateSettings((prev) => ({ ...prev, sinkCheckedTasks: on }))}
      taskConfetti={userSettings.taskConfetti}
      onTaskConfettiChange={(on) => mutateSettings((prev) => ({ ...prev, taskConfetti: on }))}
      spaces={userSettings.spaces}
      onSpacesChange={(on) => mutateSettings((prev) => ({ ...prev, spaces: on }))}
      onOpenUpgrade={(trigger) => { setShowSettings(false); setShowUpgrade({ trigger: trigger ?? 'theme' }); }}
      onClose={() => setShowSettings(false)}
      customThemes={userSettings.customThemes}
      onCustomThemesChange={(update) => mutateSettings((prev) => ({ ...prev, customThemes: update(prev.customThemes) }))}
      onOpenThemeBuilder={openThemeBuilder}
    />
  );

  return [
            {
              id: 'stats',
              label: t('settings.statsLabel'),
              group: t('settings.groupYourNotes'),
              icon: railIcon('stats'),
              render: ({ initialTab, navigate }) => (
                <StatsModal
                  onOpenWellnessExport={() => navigate('import', 'wellness')}
                  embedded
                  initialTab={initialTab === 'wellness' || initialTab === 'writing' || initialTab === 'medication' || initialTab === 'mood' ? initialTab : 'overview'}
                  notes={notes}
                  isNoteLocked={isNoteLocked}
                  // Deleted medications included on purpose: their log
                  // entries already count toward adherence, and without the
                  // template nothing can resolve the id back into a name.
                  medications={userSettings.medications}
                  notesCreated={userSettings.notesCreated}
                  firstSeenAt={userSettings.firstSeenAt}
                  trackerSettings={userSettings.trackerSettings}
                  factors={userSettings.factors}
                  onOpenDay={(date) => {
                    const entry = journalOn(notes, date);
                    if (!entry) return;
                    setShowSettings(false);
                    onOpenNote(entry.id);
                  }}
                  isPro={auth.isPro}
                  onOpenUpgrade={() => { setShowSettings(false); setShowUpgrade({ trigger: null }); }}
                  onClose={() => setShowSettings(false)}
                  {...weekReflectionFor(notes, isNoteLocked, (text) => void saveWeekReflection(text))}
                />
              ),
            },
            {
              id: 'import',
              label: t('settings.importLabel', exemptOpts('notes:settings.importLabel')),
              group: t('settings.groupYourNotes'),
              icon: railIcon('import'),
              render: ({ initialTab }) => (
                <ImportModal
                  embedded
                  onClose={() => setShowSettings(false)}
                  initialTab={initialTab === 'export' || initialTab === 'restore' || initialTab === 'vault' || initialTab === 'wellness' ? initialTab : 'import'}
                  notes={notes}
                  onImportFolders={mergeImportedFolders}
                  importTarget={importTarget}
                  onCreateImportFolder={createImportFolder}
                  onImportSettings={mergeRestoredSettings}
                  onImportTagColors={applyImportedTagColors}
                  onExportAllMdZip={(ns) => void exportAllMarkdownZip(ns)}
                  onExportAllHtmlZip={(ns) => void exportAllHtmlZip(ns)}
                  onExportAllJson={exportAllJson}
                  onExportEncrypted={exportEncryptedBackup}
                  onExportEncryptedZip={(ns) => void exportEncryptedFullBackup(ns)}
                  decryptFullBackup={decryptFullBackup}
                  onExportVault={exportVault}
                  onExportBookmarks={exportBookmarks}
                  onExportContacts={exportContacts}
                  onExportCalendar={exportCalendar}
                  wellness={{
                    isNoteLocked,
                    trackerSettings: userSettings.trackerSettings,
                    factors: userSettings.factors,
                    medications: userSettings.medications,
                    isPro: auth.isPro,
                    onOpenUpgrade: () => { setShowSettings(false); setShowUpgrade({ trigger: null }); },
                  }}
                  onImportEncrypted={importEncryptedBackup}
                  onBlobsRestored={() => {
                    imageStoreRef.current?.processPendingUploads().catch((err) =>
                      console.warn('[imageStore] post-restore processPendingUploads failed:', err),
                    );
                    attachmentStoreRef.current?.processPendingUploads().catch((err) =>
                      console.warn('[attachmentStore] post-restore processPendingUploads failed:', err),
                    );
                  }}
                  onImported={async (count, skippedDuplicates, repaired) => {
                    // A restore of our own backup mostly matches what the
                    // vault already holds, so "imported N" would be true and
                    // useless. Say what it did to the notes it recognised.
                    setImportToast(
                      repaired && (repaired.updated > 0 || repaired.unchanged > 0)
                        ? t('toast.restoreSummary', { added: count, updated: repaired.updated, unchanged: repaired.unchanged })
                        : skippedDuplicates
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
              id: 'design',
              label: t('settings.appearanceLabel'),
              group: t('settings.groupPreferences'),
              icon: railIcon('design'),
              render: () => appearancePane('design'),
            },
            {
              id: 'editor',
              label: t('settings.editorLabel'),
              group: t('settings.groupPreferences'),
              icon: railIcon('editor'),
              render: () => appearancePane('editor'),
            },
            {
              id: 'formatBar',
              label: t('settings.formatBarLabel'),
              group: t('settings.groupPreferences'),
              icon: railIcon('formatBar'),
              render: () => appearancePane('formatBar'),
            },
            {
              id: 'lists',
              label: t('settings.listsLabel'),
              group: t('settings.groupPreferences'),
              icon: railIcon('lists'),
              render: ({ initialTab }) => appearancePane('lists', initialTab),
            },
            {
              id: 'trackers',
              label: t('settings.trackersLabel'),
              group: t('settings.groupPreferences'),
              icon: railIcon('trackers'),
              render: ({ initialTab }) => (
                <TrackerSettingsPane
                  initialTab={initialTab}
                  settings={userSettings.trackerSettings}
                  onChange={(ts) => mutateSettings((prev) => ({ ...prev, trackerSettings: ts }))}
                  factors={userSettings.factors}
                  onFactorsChange={(next) => mutateSettings((prev) => ({ ...prev, factors: next }))}
                  customHabits={userSettings.customHabits}
                  onCustomHabitsChange={(next) => mutateSettings((prev) => ({ ...prev, customHabits: next }))}
                  medications={userSettings.medications}
                  onMedicationsChange={(meds) => mutateSettings((prev) => ({ ...prev, medications: meds }))}
                  isPro={auth.isPro}
                  onOpenUpgrade={() => { setShowSettings(false); setShowUpgrade({ trigger: null }); }}
                />
              ),
            },
            {
              id: 'date',
              label: t('settings.dateLabel'),
              group: t('settings.groupPreferences'),
              icon: railIcon('date'),
              render: ({ initialTab }) => (
                <DateTimePane
                  initialTab={initialTab}
                  format={
                    <DateSheet
                      journal={{
                        format: userSettings.journalTitleFormat,
                        onFormatChange: (f) => mutateSettings((prev) => ({ ...prev, journalTitleFormat: f })),
                        suffix: userSettings.journalTitleSuffix,
                        onSuffixChange: (sfx) => mutateSettings((prev) => ({ ...prev, journalTitleSuffix: sfx })),
                        pattern: userSettings.journalTitlePattern,
                        onPatternChange: (p) => mutateSettings((prev) => ({ ...prev, journalTitlePattern: p })),
                      }}
                      dateOrder={userSettings.dateOrder}
                      onDateOrderChange={(order) => mutateSettings((prev) => ({ ...prev, dateOrder: order }))}
                      clock={userSettings.clock}
                      onClockChange={(clock) => mutateSettings((prev) => ({ ...prev, clock }))}
                    />
                  }
                  calendar={
                    <CalendarSettings
                      value={userSettings.calendar}
                      onChange={(next) => mutateSettings((prev) => ({ ...prev, calendar: next }))}
                      alertsUnlocked={proUnlocked(auth.isPro)}
                      showPro={!auth.isPro}
                      onUpgrade={() => setShowUpgrade({ trigger: 'alerts' })}
                    />
                  }
                />
              ),
            },
            {
              id: 'plan',
              label: t('settings.planLabel'),
              group: t('settings.groupAccount'),
              icon: railIcon('plan'),
              render: ({ navigate, initialTab }) => (
                <SyncOptionsModal
                  embedded
                  tab="plan"
                  initialSection={initialTab === 'connectedAccounts' || initialTab === 'keyCustody' ? initialTab : 'overview'}
                  custodySettings={{ hasPin: Boolean(userSettings.pinHash && userSettings.pinSalt), pinCredential: `${userSettings.pinHash ?? ''}:${userSettings.pinSalt ?? ''}`, pinTimeoutMinutes: userSettings.pinTimeoutMinutes,
                    userSettings, onSettingsChange: (next, base) => mutateSettings((prev) => withCredentialChanges(prev, base, next)) }}
                  onOpenPhrase={() => navigate('security', 'phrase')}
                  deviceLabels={userSettings.deviceLabels}
                  onRenameDevice={(deviceId, name, serverName) =>
                    mutateSettings((prev) => ({
                      ...prev,
                      deviceLabels: setDeviceLabel(prev.deviceLabels, deviceId, name, serverName),
                    }))
                  }
                  onOpenRating={() => navigate('about', 'rating')}
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
              icon: railIcon('security'),
              render: ({ initialTab, navigate }) => (
                <SecurityModal
                  embedded
                  phrase={auth.phrase}
                  defaultTab={initialTab === 'biometric' || initialTab === 'phrase' || initialTab === 'twoFactor' ? initialTab : 'pin'}
                  pinTimeoutMinutes={userSettings.pinTimeoutMinutes}
                  onPinTimeoutChange={(minutes) => {
                    mutateSettings((prev) => ({ ...prev, pinTimeoutMinutes: minutes }));
                  }}
                  appLockTimeoutMinutes={userSettings.appLockTimeoutMinutes}
                  onAppLockTimeoutChange={(minutes) => {
                    mutateSettings((prev) => ({ ...prev, appLockTimeoutMinutes: minutes }));
                  }}
                  userSettings={userSettings}
                  onSettingsChange={(next, base) => {
                    mutateSettings((prev) => withCredentialChanges(prev, base, next));
                  }}
                  onClose={() => setShowSettings(false)}
                  onOpenCustody={() => navigate('plan', 'keyCustody')}
                  pubkey={auth.pubkey}
                />
              ),
            },
            {
              id: 'me',
              label: t('settings.accountLabel', exemptOpts('notes:settings.accountLabel')),
              group: t('settings.groupAccount'),
              icon: railIcon('me'),
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
              id: 'storage',
              label: t('settings.storageLabel'),
              group: t('settings.groupAccount'),
              icon: railIcon('storage'),
              render: ({ initialTab }) => (
                <StoragePane
                  initialTab={initialTab}
                  storage={(openImages) => (
                    <SyncOptionsModal
                      embedded
                      tab="storage"
                      onSyncNow={runSync}
                      onOpenNote={onOpenNote}
                      onOpenImageSettings={openImages}
                      onClose={() => setShowSettings(false)}
                      onOpenUpgrade={() => { setShowSettings(false); setShowUpgrade({ trigger: 'storage' }); }}
                      onSignOut={handleSignOutClick}
                    />
                  )}
                  images={
                    <ImagesSheet
                      spaceSaver={userSettings.imageSpaceSaver}
                      stripMetadata={userSettings.imageStripMetadata}
                      contactCeiling={userSettings.imageContactCeiling}
                      onChange={(field, value) => mutateSettings((prev) => ({ ...prev, [field]: value }))}
                    />
                  }
                />
              ),
            },
            {
              id: 'about',
              label: t('settings.aboutLabel'),
              group: t('settings.groupBrand'),
              icon: railIcon('about'),
              render: ({ initialTab }) => (
                <AboutModal
                  embedded
                  onClose={() => setShowSettings(false)}
                  initialTab={initialTab === 'hotkeys' || initialTab === 'rating' ? initialTab : 'about'}
                />
              ),
            },
            {
              // Link row, not a pane: the static /help site is the only FAQ
              // renderer, so this opens the browser rather than duplicating
              // it in-app. Spec: ops/docs/bundle-size.md (in-app FAQ tab)
              id: 'help',
              label: t('settings.helpLabel'),
              group: t('settings.groupBrand'),
              icon: railIcon('help'),
              href: siteHref(helpPath(activeLocale())),
            },
            {
              id: 'language',
              label: t('settings.languageLabel'),
              // No shell description: the language grid's subtitle sits
              // inside LanguageSheet, directly above the grid it describes.
              group: t('settings.groupBrand'),
              icon: railIcon('language'),
              render: () => <LanguageSheet embedded onClose={() => setShowSettings(false)} />,
            },
          ] satisfies SettingsCategory[];
}
