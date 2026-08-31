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
  printNote as basePrintNote,
  decryptBackup,
} from '../export';
import { validateFolders } from '../folders';
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
  const exportSingleMarkdown = (n: LocalNote) =>
    runExport('md', () => baseExportSingleMarkdown(n, imageStoreRef.current, userSettings.folders));
  const exportSingleHtml = (n: LocalNote) =>
    runExport('html', () => baseExportSingleHtml(n, imageStoreRef.current, userSettings.folders));
  const exportAllMarkdownZip = async (ns: LocalNote[]) => {
    setExportProgress({ status: 'Preparing...', done: false });
    await runExport('md-zip', async () => {
      await baseExportAllMarkdownZip(ns, imageStoreRef.current, attachmentStoreRef.current, (msg) => {
        setExportProgress({ status: msg, done: false });
      }, userSettings.folders);
      setExportProgress({ status: '', done: true });
    });
  };
  const exportEncryptedFullBackup = async (ns: LocalNote[]) => {
    setExportProgress({ status: 'Preparing...', done: false });
    await runExport('encrypted-zip', async () => {
      await baseExportEncryptedFullBackup(ns, imageStoreRef.current, attachmentStoreRef.current, auth.encryptionKey, (msg) => {
        setExportProgress({ status: msg, done: false });
      }, userSettings.folders);
      setExportProgress({ status: '', done: true });
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
  const exportAllHtmlZip = (ns: LocalNote[]) =>
    runExport('html-zip', () => baseExportAllHtmlZip(ns, imageStoreRef.current, userSettings.folders));
  const exportAllJson = (ns: LocalNote[]) =>
    runExport('json', () => baseExportAllJson(ns, userSettings.folders));
  const exportEncryptedBackup = (ns: LocalNote[]) =>
    runExport('encrypted', () =>
      baseExportEncryptedBackup(ns, auth.encryptionKey, userSettings.folders));
  const exportVault = (ns: LocalNote[]) =>
    runExport('vault', () => exportVaultBitwarden(ns));
  const exportBookmarks = (ns: LocalNote[]) =>
    runExport('bookmarks', () => exportBookmarksHtml(ns, userSettings.folders));
  const printNote = async (n: LocalNote) => {
    await basePrintNote(n, imageStoreRef.current, userSettings.folders);
    recordAdminEvent(supabase, 'export', 'pdf');
  };
  const importEncryptedBackup = async (file: File): Promise<number> => {
    const buf = new Uint8Array(await file.arrayBuffer());
    const backup = decryptBackup(buf, auth.encryptionKey);
    recordAdminEvent(supabase, 'import', 'encrypted');
    // v3 backups carry the folder definitions - merge them by id so the
    // restored notes' folderId pointers resolve to a real tree.
    const restoredFolders = validateFolders(backup.folders);
    if (restoredFolders.length > 0) {
      mutateSettings((prev) => {
        const have = new Set(prev.folders.map((f) => f.id));
        const merged = [...prev.folders, ...restoredFolders.filter((f) => !have.has(f.id))];
        return { ...prev, folders: validateFolders(merged) };
      });
    }
    const { applyImport } = await import('../import/apply');
    const parsed = {
      notes: backup.notes.map((n) => ({
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
    return result.imported;
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
    printNote,
    importEncryptedBackup,
    exportEncryptedFullBackup,
    decryptFullBackup,
  };
}
