import { useRef, useState } from 'react';
import type { Dispatch, MutableRefObject, SetStateAction } from 'react';
import { useTranslation } from 'react-i18next';
import type { SupabaseClient } from '@notes/shared';
import { fetchQuotaUsage } from '../devices';
import type { AttachmentStore } from '../attachmentStore';
import { formatFileSize, validateAttachment } from '../attachmentValidation';
import { proUnlocked } from '../demo';
import { currentImageOptions, isSupportedImage, processImage } from '../imageProcessing';
import type { LocalNote } from '../db';
import { parseMarkdown } from '../import/markdown';
import { applyImport } from '../import/apply';
import { fileUnfiled } from '../import/destination';
import type { FolderDef } from '../folders';
import { SUPPORTED_EXT } from '../markdownFolder/adapter';
import { createNote } from '../notesRepo';
import type { FileUploadEntry } from '../UploadProgressModal';
import type { View } from '../views';

/**
 * A file whose bytes are read only when its turn in the upload comes: the
 * share inbox hands a batch over this way, so the window lists every file
 * from the start while only one file is ever held in memory.
 */
export interface LaterFile {
  name: string;
  size: number;
  read: () => Promise<File>;
  /** Removes the file from where it waits (the share inbox), for a file the
   *  upload keeps; the upload window offers it on that file's row. */
  discard?: () => Promise<void>;
}

type UploadSource = File | LaterFile;

export function useFilesUpload({
  auth,
  supabase,
  attachmentStoreRef,
  quotaRef,
  refresh,
  runSync,
  refreshStorage,
  setSelectedId,
  setView,
  setImportToast,
  onImportFolders,
  importDestination,
  onBlobsRestored,
  inheritFilters,
}: {
  auth: { isPro: boolean };
  supabase: SupabaseClient;
  attachmentStoreRef: MutableRefObject<AttachmentStore | null>;
  quotaRef: MutableRefObject<{ usedBytes: number; maxBytes: number } | null>;
  refresh: () => Promise<LocalNote[]>;
  runSync: () => Promise<void>;
  refreshStorage: () => void;
  setSelectedId: Dispatch<SetStateAction<string | null>>;
  setView: (next: View) => void;
  setImportToast: Dispatch<SetStateAction<string | null>>;
  /** Merge a rebuilt folder tree into settings under `rootParent` (null: at
   *  the top); returns old id -> kept id. */
  onImportFolders?: (folders: FolderDef[], rootParent: string | null) => Map<string, string> | undefined;
  /** The Import window's default "Add to", decided once per import before the
   *  first await, so a space switch while the files are read cannot move the
   *  import: null for none, else a function that makes (or reuses) the folder,
   *  in Work a folder named after the source, since unfiled reads as Personal.
   *  It is called once the first file has parsed, so a batch that fails to
   *  parse leaves no empty folder. */
  importDestination?: () => (() => string | null) | null;
  /** Kick the pending-upload passes once blobs have landed locally. */
  onBlobsRestored?: () => void;
  /** The folder and tags the list the upload started from is filtered by. A
   *  file that misses them lands outside that list, and the auto-select
   *  effect then drops the selection, so the upload reads as doing nothing
   *  (the fault GitHub #305 describes for contacts). Read at upload time, not
   *  at render time, because the New menu switches to Files on the way here. */
  inheritFilters?: () => { tags: string[]; folderId: string | null };
}) {
  const { t } = useTranslation('notes');

  // Upload progress modal state
  const [uploadEntries, setUploadEntries] = useState<FileUploadEntry[] | null>(null);
  // Files-pillar upload: when the user picks .md/.zip files, ask whether
  // to import-as-notes or store-as-attachments before proceeding.
  const [pendingImportableFiles, setPendingImportableFiles] = useState<File[] | null>(null);
  const filesUploadRef = useRef<HTMLInputElement | null>(null);

  /** Trigger file upload from the Files view. The picker accepts every
   *  type the vault does: the type tabs choose what the list shows, never
   *  what may be added. */
  function handleFilesUpload() {
    filesUploadRef.current?.click();
  }

  /** Handle file(s) selected via the hidden input.
   *  Single file → its own note. Multiple files → one shared note.
   *  When every selected file is .md or .zip (importable markdown),
   *  ask the user whether to import-as-notes or store-as-attachments. */
  async function handleFilesSelected(e: React.ChangeEvent<HTMLInputElement>) {
    const files = e.target.files;
    if (!files || files.length === 0) return;
    const store = attachmentStoreRef.current;
    if (!store) return;
    const fileArr = Array.from(files);
    // Reset so re-selecting the same file fires onChange again.
    e.target.value = '';

    // Detect importable files: anything the markdown importer reads, plus a
    // zip. The extension list is the adapter's, not a second copy - a `.txt`
    // or `.markdown` the importer accepts but this check does not would be
    // silently attached as a file instead of offered as notes.
    const allImportable = fileArr.every(
      (f) => SUPPORTED_EXT.test(f.name) || f.name.toLowerCase().endsWith('.zip'),
    );
    if (allImportable) {
      setPendingImportableFiles(fileArr);
      return; // Wait for user choice in the prompt dialog.
    }

    await doAttachmentUpload(fileArr, store);
  }

  /** Run the import pipeline on markdown/.zip files, bypassing the Import
   *  modal UI for a streamlined experience from the Files pillar.
   *
   *  This has to do everything the modal's confirm step does, or the same zip
   *  imports differently depending on where it was dropped: take the row's
   *  default destination, merge the rebuilt folder tree under it and remap
   *  folderIds onto the ids that survived, file the loose notes into it, then
   *  store the blobs and rewrite the body references. Folder TAGS are the one
   *  thing it leaves out - that is a toggle the modal asks about, and there
   *  is no question to answer here. */
  async function handleImportFromFiles(files: File[]) {
    setPendingImportableFiles(null);
    let totalImported = 0;
    const makeTarget = importDestination?.() ?? null;
    let target: string | null | undefined;
    for (const file of files) {
      try {
        const parsed = await parseMarkdown(file);
        if (target === undefined) target = makeTarget?.() ?? null;
        let toApply = parsed;
        if (parsed.folders && parsed.folders.length > 0) {
          const idMap = onImportFolders?.(parsed.folders, target);
          if (idMap && idMap.size > 0) {
            toApply = {
              ...parsed,
              notes: parsed.notes.map((n) =>
                n.folderId && idMap.has(n.folderId)
                  ? { ...n, folderId: idMap.get(n.folderId)! }
                  : n,
              ),
            };
          }
        }
        toApply = { ...toApply, notes: fileUnfiled(toApply.notes, target) };
        // Pictures and attachments are stored and swapped into the bodies
        // before the notes are written: a row written with a placeholder
        // can be sent by a sync pass that the later rewrite cannot reach
        // (see blobImport.ts). Its own try, so a media failure still
        // leaves the notes, which is what the outer catch would cost.
        let storedBlobs = false;
        if (parsed.blobs && parsed.blobs.size > 0) {
          try {
            const { importBlobs } = await import('../import/blobImport');
            const media = await importBlobs(parsed.blobs, toApply.notes);
            toApply = { ...toApply, notes: media.notes };
            storedBlobs = true;
          } catch (err) {
            console.warn('[Files->Import] media failed for', file.name, err);
          }
        }
        const result = await applyImport(toApply, 'markdown');
        totalImported += result.imported;
        if (storedBlobs) onBlobsRestored?.();
      } catch (err) {
        console.warn('[Files→Import] failed for', file.name, err);
      }
    }
    if (totalImported > 0) {
      setImportToast(
        t('toast.importedSyncing', { count: totalImported })
      );
      await refresh();
      void runSync();
      // Switch to Notes so the user sees the imported content immediately
      // instead of staring at the Files pillar wondering if it worked.
      setView('all');
      window.setTimeout(() => setImportToast(null), 4000);
    }
  }

  /** Proceed with normal encrypted-attachment upload for selected files.
   *  Called explicitly via ConfirmModal's onCancel ("Store as files"). */
  async function handleAttachFromFiles<T extends UploadSource>(files: T[]): Promise<T[]> {
    setPendingImportableFiles(null);
    const store = attachmentStoreRef.current;
    if (!store) return [];
    return doAttachmentUpload(files, store);
  }

  /** Core attachment upload logic (extracted from handleFilesSelected).
   *  Answers the files that are handled: stored on this device, or refused
   *  for good on their size. A file that failed for a reason that can pass
   *  (no room yet, a failed read, a failed local store) is left out, so the
   *  share inbox keeps it. */
  async function doAttachmentUpload<T extends UploadSource>(fileArr: T[], store: AttachmentStore): Promise<T[]> {
    const handled: T[] = [];
    const multi = fileArr.length > 1;
    // Read once, before the first await: the note is written minutes later
    // on a slow batch, and the file belongs to the list the user started
    // from, not to whatever they filtered to while it uploaded.
    const filters = inheritFilters?.() ?? { tags: [], folderId: null };

    // Build initial entries for the modal
    const initial: FileUploadEntry[] = fileArr.map((f) => ({
      name: f.name,
      size: f.size,
      status: 'pending' as const,
    }));
    setUploadEntries([...initial]);

    // For multi-file uploads we collect all body lines and create one
    // note at the end. For single-file uploads we create immediately.
    const bodyLines: string[] = [];
    const bodyNames: string[] = [];
    const serverUploads: Promise<void>[] = [];

    // Quota preflight (backlog #143): one fresh server read for the whole
    // batch. A file that clearly cannot fit is refused BEFORE anything is
    // created - no note, no cached blob, no half-state - and the row says
    // so. The server check stays the authority for races; a best-effort
    // failure here just skips the gate.
    let freeBytes: number | null = null;
    let maxTotalBytes: number | null = null;
    try {
      const q = await fetchQuotaUsage(supabase, true);
      freeBytes = Math.max(0, q.maxTotalBytes - q.totalBytes - q.imageBytes);
      maxTotalBytes = q.maxTotalBytes;
    } catch {
      freeBytes = null;
    }

    for (let i = 0; i < fileArr.length; i++) {
      const source = fileArr[i]!;
      // Per-file cap from the fresh server read when we have one - quotaRef
      // is null before the first sync, which validated an add-on holder
      // against the plain Pro limit while the pane hint said otherwise.
      // Checked on the size alone, so a file read later is refused unread.
      const v = validateAttachment(source, proUnlocked(auth.isPro), (maxTotalBytes ?? quotaRef.current?.maxBytes ?? 0) > 500 * 1000 * 1000);
      if (!v.ok) {
        initial[i] = { ...initial[i]!, status: 'failed', error: v.error };
        setUploadEntries([...initial]);
        // Refused for good only on a limit that was read: before the first
        // quota answer an add-on holder meets the plain limit.
        if (maxTotalBytes !== null || quotaRef.current !== null) handled.push(source);
        continue;
      }
      const later = !(source instanceof File);
      let file: File;
      try {
        file = later ? await source.read() : source;
      } catch (err) {
        initial[i] = { ...initial[i]!, status: 'failed', error: err instanceof Error ? err.message : 'Upload failed' };
        setUploadEntries([...initial]);
        continue;
      }
      // Images obey the two image switches at this door too, and the row
      // then shows the file that is actually stored. A picture the module
      // cannot read is stored as it arrived, the way every non-image is.
      let upload = file;
      if (isSupportedImage(file)) {
        const processed = await processImage(file, currentImageOptions());
        if (processed.ok) {
          upload = new File([processed.image.data as BlobPart], processed.image.name, { type: processed.image.mime });
          initial[i] = { ...initial[i]!, name: upload.name, size: upload.size };
        }
      }
      if (freeBytes !== null) {
        if (upload.size > freeBytes) {
          initial[i] = { ...initial[i]!, status: 'failed', errorCode: 'storage-full' };
          setUploadEntries([...initial]);
          continue;
        }
        // Reserve headroom so a batch cannot collectively overshoot.
        freeBytes -= upload.size;
      }
      initial[i] = { ...initial[i]!, status: 'uploading' };
      setUploadEntries([...initial]);

      try {
        const result = await store.uploadAttachment(upload);
        const { uuid, meta, uploaded } = result;
        const line = `[${meta.name}|${formatFileSize(meta.size)}|${meta.mime}](pn:file/${uuid})`;

        if (multi) {
          handled.push(source);
          bodyLines.push(line);
          bodyNames.push(meta.name);
          serverUploads.push(uploaded);
          // Keep the row on "uploading" until the SERVER upload settles.
          // Marking done at local-cache time told the user a large batch
          // was complete while megabytes were still streaming - closing
          // the app then stranded blobs this modal had reported as Done.
          const row = i;
          uploaded
            .then(() => {
              initial[row] = { ...initial[row]!, status: 'done' };
              setUploadEntries([...initial]);
            })
            .catch((uploadErr) => {
              const uploadMsg = uploadErr instanceof Error ? uploadErr.message : 'Server upload failed';
              const quota = /quota exceeded/i.test(uploadMsg);
              // Quota race lost after the preflight: the blob + note stay
              // local (quotaBlocked) - say that, not just "failed" (#143).
              initial[row] = {
                ...initial[row]!,
                status: 'failed',
                error: uploadMsg,
                ...(quota ? { errorCode: 'storage-full-kept' as const } : {}),
              };
              setUploadEntries([...initial]);
            });
          // A file read later waits for its server upload before the next one
          // is read, so the batch holds one file's bytes at a time.
          if (later) await uploaded.catch(() => {});
        } else {
          // Single file - create its own note immediately.
          const note = await createNote(meta.name, line, filters.tags, undefined, 'file', filters.folderId);
          // Saved from here on, whatever the refresh answers, or the next
          // drain of the share inbox saves the file a second time.
          handled.push(source);
          await refresh().catch((err) => console.warn('[upload] list refresh failed:', err));
          void runSync();
          setSelectedId(note.id);
          try {
            await uploaded;
            initial[i] = { ...initial[i]!, status: 'done' };
          } catch (uploadErr) {
            const uploadMsg = uploadErr instanceof Error ? uploadErr.message : 'Server upload failed';
            const quota = /quota exceeded/i.test(uploadMsg);
            initial[i] = {
              ...initial[i]!,
              status: 'failed',
              error: uploadMsg,
              ...(quota ? { errorCode: 'storage-full-kept' as const } : {}),
            };
          }
        }
      } catch (err) {
        const msg = err instanceof Error ? err.message : 'Upload failed';
        initial[i] = { ...initial[i]!, status: 'failed', error: msg };
      }
      setUploadEntries([...initial]);
    }

    // Multi-file: create one note containing all successfully uploaded files.
    if (multi && bodyLines.length > 0) {
      // One survivor of a batch is a single file and is named like one.
      const title = bodyLines.length === 1
        ? bodyNames[0]!
        : t('importExport:upload.batchTitle', { count: bodyLines.length });
      const body = bodyLines.join('\n');
      const note = await createNote(title, body, filters.tags, undefined, 'file', filters.folderId);
      await refresh().catch((err) => console.warn('[upload] list refresh failed:', err));
      void runSync();
      setSelectedId(note.id);
    }

    // Refresh the storage bar once the bytes have actually been charged.
    // uploadAttachment resolves as soon as the blob is in the local cache;
    // the Storage write and its adjust_blob_bytes call happen in the promise
    // it hands back. Reading the counter before those settle rendered the
    // pre-upload total, so a multi-file drop looked like it consumed nothing.
    void Promise.allSettled(serverUploads).then(refreshStorage);

    // A file from the share inbox that this upload keeps comes back on every
    // drain until it fits; its row lets the person drop it instead.
    fileArr.forEach((source, i) => {
      if (handled.includes(source) || source instanceof File || !source.discard) return;
      const drop = source.discard;
      initial[i] = {
        ...initial[i]!,
        discard: async () => {
          await drop();
          initial[i] = { ...initial[i]!, discard: undefined, discarded: true };
          setUploadEntries([...initial]);
        },
      };
    });
    setUploadEntries([...initial]);
    return handled;
  }

  return {
    uploadEntries,
    setUploadEntries,
    pendingImportableFiles,
    setPendingImportableFiles,
    filesUploadRef,
    handleFilesUpload,
    handleFilesSelected,
    handleImportFromFiles,
    handleAttachFromFiles,
  };
}
