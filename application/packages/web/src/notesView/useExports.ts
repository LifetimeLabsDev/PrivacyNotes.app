import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import type { SupabaseClient } from '@notes/shared';
import type { LocalNote } from '../db';
import { recordAdminEvent } from '../adminEvents';
import type { ExportSource } from '../adminEvents';
import i18n from '../i18n';
import { decodeZipBackup, BACKUP_TOO_SMALL } from '@notes/shared';
import {
  exportSingleMarkdown as baseExportSingleMarkdown,
  exportSingleHtml as baseExportSingleHtml,
  exportAllMarkdownZip as baseExportAllMarkdownZip,
  exportAllHtmlZip as baseExportAllHtmlZip,
  exportAllJson as baseExportAllJson,
  exportEncryptedBackup as baseExportEncryptedBackup,
  exportEncryptedFullBackup as baseExportEncryptedFullBackup,
  exportVaultBitwarden,
  exportBookmarksHtml,
  exportContactsVcf,
  printNote as basePrintNote,
  decryptBackup,
  describeMissing,
  type MissingBlob,
} from '../export';
import { applyRestoredFolders, validateFolders } from '../folders';
import { RESTORE_WAIT_LINE, restoreGateNow } from '../pullState';
import { deletedFolderIds, itemStylesEqual, mergeItemStyles, validateItemStyles } from '../itemStyles';
import type { ImageStore } from '../imageStore';
import type { AttachmentStore } from '../attachmentStore';
import type { UserSettings } from '../userSettings';

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
  const reportMissing = (missing: MissingBlob[]) => {
    if (missing.length > 0) setExportProgress({ status: describeMissing(missing), done: true });
  };
  const exportSingleMarkdown = (n: LocalNote) =>
    runExport('md', async () => reportMissing(
      await baseExportSingleMarkdown(n, imageStoreRef.current, userSettings.folders, attachmentStoreRef.current)));
  const exportSingleHtml = (n: LocalNote) =>
    runExport('html', async () => reportMissing(
      await baseExportSingleHtml(n, imageStoreRef.current, userSettings.folders, attachmentStoreRef.current)));
  // Both bulk zips open the progress window and both report the same two
  // phases. An empty opening status is deliberate: the modal owns the
  // "Preparing..." wording, in every language.
  const exportAllMarkdownZip = async (ns: LocalNote[]) => {
    setExportProgress({ status: '', done: false });
    await runExport('md-zip', async () => {
      const missing = await baseExportAllMarkdownZip(ns, imageStoreRef.current, attachmentStoreRef.current, (msg) => {
        setExportProgress({ status: msg, done: false });
      }, userSettings.folders);
      setExportProgress({ status: describeMissing(missing), done: true });
    });
  };
  const exportEncryptedFullBackup = async (ns: LocalNote[]) => {
    setExportProgress({ status: '', done: false });
    await runExport('encrypted-zip', async () => {
      const missing = await baseExportEncryptedFullBackup(ns, imageStoreRef.current, attachmentStoreRef.current, auth.encryptionKey, (msg) => {
        setExportProgress({ status: msg, done: false });
      }, userSettings.folders);
      setExportProgress({ status: describeMissing(missing), done: true });
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
      const missing = await baseExportAllHtmlZip(ns, imageStoreRef.current, userSettings.folders, (msg) => {
        setExportProgress({ status: msg, done: false });
      }, attachmentStoreRef.current);
      setExportProgress({ status: describeMissing(missing), done: true });
    });
  };
  const exportAllJson = (ns: LocalNote[]) =>
    runExport('json', () => baseExportAllJson(ns, userSettings.folders, userSettings.itemStyles));
  const exportEncryptedBackup = (ns: LocalNote[]) =>
    runExport('encrypted', () =>
      baseExportEncryptedBackup(ns, auth.encryptionKey, userSettings.folders, userSettings.itemStyles));
  const exportVault = (ns: LocalNote[]) =>
    runExport('vault', () => exportVaultBitwarden(ns, userSettings.folders));
  const exportBookmarks = (ns: LocalNote[]) =>
    runExport('bookmarks', () => exportBookmarksHtml(ns, userSettings.folders));
  const exportContacts = (ns: LocalNote[]) =>
    runExport('contacts', () => exportContactsVcf(ns));
  const printNote = async (n: LocalNote) => {
    await basePrintNote(n, imageStoreRef.current, userSettings.folders, attachmentStoreRef.current);
    recordAdminEvent(supabase, 'export', 'pdf');
  };
  const importEncryptedBackup = async (file: File): Promise<{ imported: number; updated: number; unchanged: number }> => {
    // The restore matches the backup's notes by id against this device's
    // copy, so it waits for this device's first clean pull (pullState.ts).
    const gate = restoreGateNow();
    if (gate !== 'open') throw new Error(i18n.t(RESTORE_WAIT_LINE[gate]));
    const buf = new Uint8Array(await file.arrayBuffer());
    const backup = decryptBackup(buf, auth.encryptionKey);
    recordAdminEvent(supabase, 'import', 'encrypted');
    // v3 backups carry the folder definitions - merge them by id so the
    // restored notes' folderId pointers resolve to a real tree.
    const restoredFolders = validateFolders(backup.folders);
    const restoredLooks = validateItemStyles(backup.itemStyles);
    // Through the same helper as the folders-only restore: additive by id,
    // and a folder this account deleted stays deleted, because its tombstone
    // is final. The looks merge after the folders, per value like every sync
    // point: a newer pick in the vault wins over the backup's, a second
    // restore changes nothing, and a deleted folder does not get its look
    // back.
    if (restoredFolders.length > 0 || Object.keys(restoredLooks).length > 0) {
      mutateSettings((prev) => {
        const result = applyRestoredFolders(
          { folders: prev.folders, deleted: prev.foldersDeleted },
          restoredFolders,
        );
        const itemStyles = mergeItemStyles(
          prev.itemStyles,
          restoredLooks,
          deletedFolderIds(result.tree.deleted),
        );
        const looksChanged = !itemStylesEqual(itemStyles, prev.itemStyles);
        if (result.added === 0 && !looksChanged) return prev;
        return {
          ...prev,
          folders: result.tree.folders,
          foldersDeleted: result.tree.deleted,
          ...(looksChanged ? { itemStyles } : {}),
        };
      });
    }
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
        starred: n.starred === 1,
        trashed: n.trashed === 1,
        type: n.type,
        locked: n.locked === 1,
        pinProtected: n.pinProtected === 1,
        trackers: n.trackers,
        folderId: n.folderId ?? null,
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

  return {
    exportSingleMarkdown,
    exportSingleHtml,
    exportAllMarkdownZip,
    exportAllHtmlZip,
    exportAllJson,
    exportEncryptedBackup,
    exportVault,
    exportBookmarks,
    exportContacts,
    printNote,
    importEncryptedBackup,
    exportEncryptedFullBackup,
    decryptFullBackup,
  };
}
