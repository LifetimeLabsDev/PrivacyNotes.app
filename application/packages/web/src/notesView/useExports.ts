import { useEffect, type Dispatch, type MutableRefObject, type SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import type { SupabaseClient } from '@notes/shared';
import type { LocalNote } from '../db';
import { recordAdminEvent } from '../adminEvents';
import type { ExportSource } from '../adminEvents';
import i18n from '../i18n';
import { decodeZipBackup, BACKUP_TOO_SMALL } from '@notes/shared';
import type { MissingBlob } from '../export';
import { RESTORE_WAIT_LINE, restoreGateNow } from '../pullState';
import { remapFolderLooks, settingsAfterRestore } from '../backupRestore';
import type { ImageStore } from '../imageStore';
import type { AttachmentStore } from '../attachmentStore';
import type { UserSettings } from '../userSettings';
import { isChunkLoadError, prefetchChunk } from '../chunkLoad';

const loadExport = () => import('../export');

export function useExports({
  supabase,
  auth,
  userSettings,
  mutateSettings,
  imageStoreRef,
  attachmentStoreRef,
  setExportProgress,
}: {
  supabase: SupabaseClient;
  auth: { encryptionKey: Uint8Array };
  userSettings: UserSettings;
  mutateSettings: (updater: (prev: UserSettings) => UserSettings) => void;
  imageStoreRef: MutableRefObject<ImageStore | null>;
  attachmentStoreRef: MutableRefObject<AttachmentStore | null>;
  setExportProgress: Dispatch<SetStateAction<{ status: string; done: boolean; error?: string } | null>>;
}) {
  const { t } = useTranslation('notes');
  // export.ts, with the renderer it pulls in, loads on the first export and
  // not at boot. It is fetched a few seconds after sign-in so an export made
  // offline later still works: nothing else caches the chunk. Offline at that
  // moment, it is fetched when the connection is back.
  useEffect(() => {
    const prefetch = () => prefetchChunk(loadExport);
    const id = window.setTimeout(() => {
      if (navigator.onLine) prefetch();
      else window.addEventListener('online', prefetch, { once: true });
    }, 4000);
    return () => {
      window.clearTimeout(id);
      window.removeEventListener('online', prefetch);
    };
  }, []);
  // Export wrappers - identical to the raw functions in ./export but
  // they also fire an anonymous admin_events row (`export` + format)
  // so we can see which export paths users actually use. No content,
  // no pubkey, just the format key.
  //
  // Every one of them routes through runExport, which owns the failure UI.
  // Writing the file can throw: the native Save As path reports failures
  // rather than swallowing them (issue #193), and without a shared catch an
  // Android export that saved 0 bytes looks exactly like one that worked,
  // with the user finding out at restore time.
  const runExport = async (format: ExportSource, run: () => Promise<void>) => {
    try {
      await run();
      recordAdminEvent(supabase, 'export', format);
    } catch (err) {
      // Offline before the chunk was ever fetched: the toast already says so,
      // so a progress window the export opened closes rather than waiting.
      if (!navigator.onLine && isChunkLoadError(err)) {
        setExportProgress(null);
        return;
      }
      setExportProgress({
        status: '',
        done: true,
        error: err instanceof Error && err.message
          ? err.message
          : t('importExport:exportErrors.generic'),
      });
    }
  };
  // A file saved without a picture or a file its notes refer to is kept,
  // because a partial copy beats none, and the progress window says what it
  // lacks: a finished export carries a status only then, and the window
  // never calls it complete. A single note opens the window only for that.
  const reportMissing = (missing: MissingBlob[], describeMissing: (m: MissingBlob[]) => string) => {
    if (missing.length > 0) setExportProgress({ status: describeMissing(missing), done: true });
  };
  const exportSingleMarkdown = (n: LocalNote) =>
    runExport('md', async () => {
      const ex = await loadExport();
      reportMissing(
        await ex.exportSingleMarkdown(n, imageStoreRef.current, userSettings.folders, attachmentStoreRef.current),
        ex.describeMissing,
      );
    });
  const exportSingleHtml = (n: LocalNote) =>
    runExport('html', async () => {
      const ex = await loadExport();
      reportMissing(
        await ex.exportSingleHtml(n, imageStoreRef.current, userSettings.folders, attachmentStoreRef.current),
        ex.describeMissing,
      );
    });
  // Both bulk zips open the progress window and both report the same two
  // phases. An empty opening status is deliberate: the modal owns the
  // "Preparing..." wording, in every language.
  const exportAllMarkdownZip = async (ns: LocalNote[]) => {
    setExportProgress({ status: '', done: false });
    await runExport('md-zip', async () => {
      const ex = await loadExport();
      const missing = await ex.exportAllMarkdownZip(ns, imageStoreRef.current, attachmentStoreRef.current, (msg) => {
        setExportProgress({ status: msg, done: false });
      }, userSettings.folders, { itemStyles: userSettings.itemStyles, customThemes: userSettings.customThemes, factors: userSettings.factors, customHabits: userSettings.customHabits });
      setExportProgress({ status: ex.describeMissing(missing), done: true });
    });
  };
  const exportEncryptedFullBackup = async (ns: LocalNote[]) => {
    setExportProgress({ status: '', done: false });
    await runExport('encrypted-zip', async () => {
      const ex = await loadExport();
      const missing = await ex.exportEncryptedFullBackup(ns, imageStoreRef.current, attachmentStoreRef.current, auth.encryptionKey, (msg) => {
        setExportProgress({ status: msg, done: false });
      }, userSettings.folders, { itemStyles: userSettings.itemStyles, customThemes: userSettings.customThemes, factors: userSettings.factors, customHabits: userSettings.customHabits });
      setExportProgress({ status: ex.describeMissing(missing), done: true });
    });
  };
  /** Decrypt a picked .pnbackupz into the plain full-backup zip. The
   *  modal then runs it through the NORMAL zip restore flow - preview,
   *  quota preflight and blob restore all reuse. Errors arrive already
   *  translated, the decryptBackup precedent (issue #193). */
  const decryptFullBackup = async (file: File): Promise<File> => {
    const bytes = new Uint8Array(await file.arrayBuffer());
    try {
      const zip = decodeZipBackup(bytes, auth.encryptionKey);
      return new File([zip as BlobPart], 'backup.zip', { type: 'application/zip' });
    } catch (err) {
      if (err instanceof Error && err.name === BACKUP_TOO_SMALL) {
        throw new Error(i18n.t('importExport:decryptErrors.tooSmall', { size: bytes.length }));
      }
      throw new Error(i18n.t('importExport:decryptErrors.notThisAccount'));
    }
  };
  const exportAllHtmlZip = async (ns: LocalNote[]) => {
    setExportProgress({ status: '', done: false });
    await runExport('html-zip', async () => {
      const ex = await loadExport();
      const missing = await ex.exportAllHtmlZip(ns, imageStoreRef.current, userSettings.folders, (msg) => {
        setExportProgress({ status: msg, done: false });
      }, attachmentStoreRef.current);
      setExportProgress({ status: ex.describeMissing(missing), done: true });
    });
  };
  const exportAllJson = (ns: LocalNote[]) =>
    runExport('json', async () => (await loadExport()).exportAllJson(ns, userSettings.folders, userSettings.itemStyles, userSettings.customThemes, userSettings.factors, userSettings.customHabits));
  const exportEncryptedBackup = (ns: LocalNote[]) =>
    runExport('encrypted', async () =>
      (await loadExport()).exportEncryptedBackup(ns, auth.encryptionKey, userSettings.folders, userSettings.itemStyles, userSettings.customThemes, userSettings.factors, userSettings.customHabits));
  const exportVault = (ns: LocalNote[]) =>
    runExport('vault', async () => (await loadExport()).exportVaultBitwarden(ns, userSettings.folders));
  const exportBookmarks = (ns: LocalNote[]) =>
    runExport('bookmarks', async () => (await loadExport()).exportBookmarksHtml(ns, userSettings.folders));
  const exportContacts = (ns: LocalNote[]) =>
    runExport('contacts', async () => (await loadExport()).exportContactsVcf(ns));
  const exportCalendar = (ns: LocalNote[]) =>
    runExport('calendar', async () => (await loadExport()).exportCalendarIcs(ns));
  const printNote = (n: LocalNote, titleOnly = false) =>
    runExport('pdf', async () =>
      (await loadExport()).printNote(n, imageStoreRef.current, userSettings.folders, attachmentStoreRef.current, titleOnly));
  const importEncryptedBackup = async (file: File): Promise<{ imported: number; updated: number; unchanged: number }> => {
    // The restore matches the backup's notes by id against this device's
    // copy, so it waits for this device's first clean pull (pullState.ts).
    const gate = restoreGateNow();
    if (gate !== 'open') throw new Error(i18n.t(RESTORE_WAIT_LINE[gate]));
    const buf = new Uint8Array(await file.arrayBuffer());
    const backup = (await loadExport()).decryptBackup(buf, auth.encryptionKey);
    recordAdminEvent(supabase, 'import', 'encrypted');
    // v3 backups carry the folder definitions, their looks and the custom
    // themes; merged before the notes so the restored notes' folderId
    // pointers resolve to a real tree (backupRestore.ts).
    mutateSettings((prev) => settingsAfterRestore(prev, backup));
    const { applyImport } = await import('../import/apply');
    const parsed = {
      notes: backup.notes.map((n) => ({
        // The note's own id, which is what turns this from a second copy of
        // the vault into a repair of it. Backups written before ids were
        // carried have none, and those still come in as new notes.
        ...(typeof n.id === 'string' && n.id ? { id: n.id } : {}),
        title: n.title,
        body: n.body,
        tags: n.tags,
        createdAt: n.createdAt,
        updatedAt: n.updatedAt,
        ...(typeof n.editedAt === 'string' ? { editedAt: n.editedAt } : {}),
        starred: n.starred === 1,
        trashed: n.trashed === 1,
        type: n.type,
        locked: n.locked === 1,
        pinProtected: n.pinProtected === 1,
        trackers: n.trackers,
        folderId: n.folderId ?? null,
        archived: n.archived === 1,
      })),
      warnings: [],
      transforms: [],
      stats: { totalNotes: backup.notes.length, emptyNotes: 0, untaggedNotes: 0, uniqueTags: 0 },
      source: 'markdown-folder' as const,
    };
    const result = await applyImport(parsed);
    if (result.errors.length > 0) throw new Error(result.errors.join('\n'));
    return {
      imported: result.imported,
      updated: result.updated ?? 0,
      unchanged: result.unchanged ?? 0,
    };
  };

  /** The looks and custom themes a full backup zip carries, merged as the
   *  .pnbackup restore merges them, with each folder look moved to the id its
   *  folder came back under. */
  const mergeRestoredSettings = (
    settings: { itemStyles?: unknown; customThemes?: unknown; factors?: unknown; customHabits?: unknown },
    savedToFinal: ReadonlyMap<string, string>,
  ) =>
    mutateSettings((prev) =>
      settingsAfterRestore(prev, {
        itemStyles: remapFolderLooks(settings.itemStyles, savedToFinal),
        customThemes: settings.customThemes,
        factors: settings.factors,
        customHabits: settings.customHabits,
      }),
    );
  return {
    mergeRestoredSettings,
    exportSingleMarkdown,
    exportSingleHtml,
    exportAllMarkdownZip,
    exportAllHtmlZip,
    exportAllJson,
    exportEncryptedBackup,
    exportVault,
    exportBookmarks,
    exportContacts,
    exportCalendar,
    printNote,
    importEncryptedBackup,
    exportEncryptedFullBackup,
    decryptFullBackup,
  };
}
