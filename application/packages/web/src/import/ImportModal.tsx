import { useMemo, useRef, useState } from 'react';
import type { ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import i18n from '../i18n';
import { IMPORTERS } from './registry';
import { applyImport } from './apply';
import { withFolderPathTags } from './folderImport';
import { withBrowserTags } from './browserBookmarks';
import type { Importer, ParsedImport, ImportedNote } from './types';
import { useAuth } from '../auth';
import { recordAdminEvent, type ImportSource } from '../adminEvents';
import type { LocalNote } from '../db';
import type { FolderDef } from '../folders';
import { useEscapeToClose } from '../useEscapeToClose';
import { ArrowCounterClockwise, BookOpenText, BracketsCurly, Check, CircleNotch, Download, FileHtml, FileZip, Key, Lock, Upload, X } from '../icons';
import { fetchQuotaUsage, recalculateQuota } from '../devices';
import { estimateNoteStoredBytes, estimateBlobBytes } from '../notesViewUtils';
import { proUnlocked } from '../demo';
import { formatBytes } from '../formatBytes';
import { perFileLimit } from '../attachmentValidation';
import { SectionEyebrow, SettingsCallout } from '../settingsUI';
import { activeLocale } from '../languages';
import { helpPath } from '../localeRoutes';
import { siteHref } from '../siteLinks';
import { HoverLabel } from '../HoverLabel';
import { HelpChip } from '../HelpChip';

/**
 * The `accept` list to hand the file picker, widened on Android.
 *
 * Android picks files by MIME type, and Chrome builds that list by running
 * every extension in `accept` through Android's own extension->MIME table,
 * silently dropping the ones it does not know. `.enex` is not in that table,
 * `.zip` is, so an Evernote importer asking for `.enex,.zip` ends up asking
 * for zips only - and the .enex the user came to import sits greyed out and
 * unselectable next to it. Same for `.pnbackup` and `.nnbackupz`. Reported by
 * a tester on a Pixel 3a, where the export could not be picked at all.
 *
 * There is no way to read that table from here, and it grows with every
 * Android release, so guessing which of our extensions are in it would fail
 * silently and identically. Android therefore gets no filter: an accept list
 * is a convenience everywhere else and a wall here, and every importer
 * already rejects the wrong file with a message naming the right one.
 *
 * iOS is unaffected - WebKit maps an unknown extension to a dynamic UTI that
 * the file itself resolves to as well, so the two still match.
 */
// Spec: ops/docs/gotchas.md (Android file picker drops accept extensions it cannot map to a MIME type)
function pickerAccept(accept: string): string {
  return /android/i.test(navigator.userAgent) ? '*/*' : accept;
}

/** Per-note stored-bytes estimate via the shared server-cost estimator
 *  (UTF-8 measured, base64-expanded: estimating from UTF-16 length x1.4
 *  undercounts CJK imports by ~3x, so the "will not fit" gate would never
 *  fire for exactly the imports most likely to blow the quota). */
function estimateImportBytes(notes: ImportedNote[]): number {
  let total = 0;
  for (const n of notes) {
    total += estimateNoteStoredBytes(n.title ?? '', n.body ?? '', n.tags ?? []);
  }
  return total;
}

type QuotaCheck = {
  estimatedBytes: number;
  availableBytes: number;
  exceeds: boolean;
};

// Map importer ids to the short source keys we record in admin_events.
// The registry uses kebab-case slugs that happen to match 1:1 - this
// cast is just the type narrowing and keeps the set of sources honest.
function importerIdToSource(id: string): ImportSource | null {
  const known: ImportSource[] = [
    'google-keep',
    'standard-notes',
    'obsidian',
    'notesnook',
    'apple-notes',
    'apple-journal',
    'samsung-notes',
    'simplenote',
    'markdown-folder',
    'privacynotes',
    'browser-bookmarks',
    'browser-passwords',
  ];
  return (known as string[]).includes(id) ? (id as ImportSource) : null;
}

/**
 * Import / Export modal - tabbed shell.
 *
 * Import tab - three-phase flow:
 *   1. pick   → choose which importer to run
 *   2. parse  → user picks a file; we read, parse, show preview + warnings
 *   3. apply  → user confirms; we write to Dexie, close, parent triggers sync
 *
 * Export tab - the whole-set exports (.zip of md, .zip of html, .json
 * backup, encrypted variants), plus the bookmarks-only and vault-only
 * writers when there is something for them to write. Callbacks come from
 * the parent so the telemetry wrapper stays in one place.
 *
 * The parent wires an `onImported` callback that refreshes the notes
 * list and kicks off a sync. No server writes happen inside this modal -
 * all encryption / upload goes through the normal sync pass.
 */
export function ImportModal({
  onClose,
  onImported,
  initialTab = 'import',
  notes,
  onExportAllMdZip,
  onExportAllHtmlZip,
  onExportAllJson,
  onExportEncrypted,
  onExportVault,
  onExportBookmarks,
  onImportEncrypted,
  onExportEncryptedZip,
  decryptFullBackup,
  onBlobsRestored,
  onImportFolders,
  embedded = false,
}: {
  onClose: () => void;
  onImported: (count: number, skippedDuplicates?: number) => void;
  /** Render inline as a settings pane (no overlay, no own header/escape). */
  embedded?: boolean;
  initialTab?: 'import' | 'export' | 'restore' | 'vault';
  notes: LocalNote[];
  onExportAllMdZip: (ns: LocalNote[]) => void;
  onExportAllHtmlZip: (ns: LocalNote[]) => void;
  onExportAllJson: (ns: LocalNote[]) => void;
  onExportEncrypted: (ns: LocalNote[]) => void;
  onExportVault: (ns: LocalNote[]) => void;
  onExportBookmarks: (ns: LocalNote[]) => void;
  onImportEncrypted: (file: File) => Promise<number>;
  onExportEncryptedZip: (ns: LocalNote[]) => void;
  /** Decrypts a .pnbackupz into the plain full-backup zip; the modal
   *  then runs the normal zip restore flow on the result. */
  decryptFullBackup: (file: File) => Promise<File>;
  /** Called after restoreBlobs writes images/attachments to IndexedDB.
   *  Parent should re-trigger processPendingUploads so blobs reach Supabase. */
  onBlobsRestored?: () => void;
  /** Merge folders rebuilt by an importer (Obsidian) into the settings
   *  folder tree, reusing any existing folder whose path already matches.
   *  Returns imported-id -> final-id so we can remap each note's folderId
   *  before writing. */
  onImportFolders?: (folders: FolderDef[]) => Map<string, string> | void;
}) {
  const { t } = useTranslation('importExport');
  const { auth, supabase } = useAuth();
  const isPro = auth.status === 'authenticated' ? auth.isPro : false;
  type Phase =
    | { kind: 'pick' }
    | { kind: 'parsing'; importer: Importer; status: string }
    | { kind: 'preview'; importer: Importer; parsed: ParsedImport }
    | { kind: 'applying'; importer: Importer }
    | { kind: 'error'; importer: Importer; message: string };

  useEscapeToClose(onClose, !embedded);
  const [tab, setTab] = useState<'import' | 'export' | 'restore' | 'vault'>(initialTab);
  const [phase, setPhase] = useState<Phase>({ kind: 'pick' });
  const fileInputRef = useRef<HTMLInputElement | null>(null);
  /** Keep the raw file around so restoreBlobs can re-read it after applyImport. */
  const selectedFileRef = useRef<File | null>(null);
  const [activeImporter, setActiveImporter] = useState<Importer | null>(null);
  const [autoTag, setAutoTag] = useState(true);
  /** Obsidian only: also add each folder name as a tag. Folders are
   *  rebuilt regardless; this is extra tag-based navigation. Defaults on
   *  for free (folder actions are locked for them) and off for Pro. */
  const [folderTags, setFolderTags] = useState(!proUnlocked(isPro));
  // Firefox tags and address-bar keywords. On by default: they are the
  // user's own labels, and dropping data silently is the worse default.
  const [browserTags, setBrowserTags] = useState(true);
  /** Quota preflight result. null = not checked yet (e.g. RPC failed,
   *  unauthenticated). Surfaces a warning + blocks the Import button
   *  when the estimated ciphertext exceeds available capacity. */
  const [quotaCheck, setQuotaCheck] = useState<QuotaCheck | null>(null);

  function handlePickImporter(importer: Importer) {
    if (!importer.enabled) return;
    setActiveImporter(importer);
    // Defer clicking until the input exists - React hasn't rendered the
    // hidden input yet on first click. One tick later is enough.
    requestAnimationFrame(() => fileInputRef.current?.click());
  }

  async function handleFileSelected(
    e: React.ChangeEvent<HTMLInputElement>
  ) {
    const file = e.target.files?.[0];
    // Reset the input so picking the same file again still fires change.
    if (fileInputRef.current) fileInputRef.current.value = '';
    if (!file || !activeImporter) return;
    await runParseFlow(activeImporter, file);
  }

  /** Parse one file through one importer: progress, quota preflight,
   *  oversize warnings, preview. The picker enters here with the chosen
   *  file; the .pnbackupz restore enters with the DECRYPTED zip, so the
   *  sealed backup reuses the whole flow, blob restore included. */
  async function runParseFlow(importer: Importer, file: File) {
    selectedFileRef.current = file;

    setPhase({
      kind: 'parsing',
      importer,
      status: t('status.readingFile'),
    });

    try {
      const parsed = await importer.parse(file, (msg) =>
        setPhase((prev) =>
          prev.kind === 'parsing' ? { ...prev, status: msg } : prev
        )
      );
      // Quota preflight - best-effort. If the RPC fails, leave
      // quotaCheck null and let the server enforce on push.
      // The same pass counts blobs over the PER-FILE cap, which the total
      // quota says nothing about: an oversized file imports to this device
      // fine and is then refused by the server on upload, so without this
      // it would sit here looking imported and silently never reach any
      // other device. Journal exports carry video, which is where this
      // bites first, but it is true of every importer that ships blobs.
      let oversize = 0;
      let capLabel = '';
      try {
        // Recalculate before reading: the counter can trail a delete the
        // user just made, promising space the next recalc takes back.
        // Best-effort - a failed recalc still leaves a usable read.
        await recalculateQuota(supabase).catch(() => {});
        const usage = await fetchQuotaUsage(supabase, isPro);
        const available = Math.max(
          0,
          usage.maxTotalBytes - usage.totalBytes - usage.imageBytes,
        );
        // Blob costs: per-blob encryption overhead when the parsed blob set
        // is available, else the raw byte total.
        let blobBytes = 0;
        if (parsed.blobs && parsed.blobs.size > 0) {
          for (const blob of parsed.blobs.values()) blobBytes += estimateBlobBytes(blob.data.length);
        } else {
          blobBytes = parsed.blobBytes ?? 0;
        }
        const estimatedBytes = estimateImportBytes(parsed.notes) + blobBytes;
        setQuotaCheck({
          estimatedBytes,
          availableBytes: available,
          exceeds: estimatedBytes > available,
        });
        const cap = perFileLimit(
          proUnlocked(isPro),
          usage.maxTotalBytes > 500 * 1000 * 1000,
        );
        for (const blob of parsed.blobs?.values() ?? []) {
          if (blob.data.length > cap) oversize++;
        }
        capLabel = formatBytes(cap);
      } catch {
        setQuotaCheck(null);
      }
      setPhase({
        kind: 'preview',
        importer,
        parsed:
          oversize > 0
            ? {
                ...parsed,
                warnings: [
                  ...parsed.warnings,
                  t('preview.oversizeAttachments', { count: oversize, limit: capLabel }),
                ],
              }
            : parsed,
      });
    } catch (err) {
      const message =
        err instanceof Error ? err.message : t('errors.genericParse');
      setPhase({ kind: 'error', importer, message });
    }
  }

  async function handleConfirm() {
    if (phase.kind !== 'preview') return;
    const { importer, parsed } = phase;
    setPhase({ kind: 'applying', importer });
    // Obsidian vaults and Notesnook notebooks rebuild a folder tree:
    // merge it into settings so notes' folderId pointers resolve, then
    // derive folder tags per the toggle (see folderImport).
    let notesForApply = parsed.notes;
    if (parsed.folders && parsed.folders.length > 0) {
      // Merge the tree into settings (reusing existing folders) and remap
      // note folderIds to the ids that survived reconciliation.
      const idMap = onImportFolders?.(parsed.folders);
      const remapped =
        idMap && idMap.size > 0
          ? parsed.notes.map((n) =>
              n.folderId && idMap.has(n.folderId)
                ? { ...n, folderId: idMap.get(n.folderId)! }
                : n
            )
          : parsed.notes;
      notesForApply = withFolderPathTags(remapped, folderTags);
    }
    notesForApply = withBrowserTags(notesForApply, browserTags);
    const parsedForApply =
      notesForApply === parsed.notes
        ? parsed
        : { ...parsed, notes: notesForApply };
    const tag = autoTag && importer.sourceTag ? importer.sourceTag : undefined;
    const result = await applyImport(parsedForApply, tag);
    if (result.errors.length > 0) {
      setPhase({
        kind: 'error',
        importer,
        message: result.errors.join('\n'),
      });
      return;
    }

    // A media failure must never sink into a console.warn: that makes the
    // worst outcome the quietest one, where the notes land, every image
    // reference stays an un-rewritten placeholder token, and the modal
    // closes on a success toast with nothing on screen saying the pictures
    // are gone. Both blob paths below record the reason, and the modal
    // stays open on it - the notes are already written either way,
    // so this is reported ON TOP of a real import, never instead of one.
    let mediaError: string | null = null;

    // Generic blob import: any importer that populates parsed.blobs
    // gets its images/attachments stored in IndexedDB and body refs
    // rewritten to pn:img/ and pn:file/ URIs.
    if (parsed.blobs && parsed.blobs.size > 0) {
      setPhase({
        kind: 'parsing',
        importer,
        status: t('status.importingBlobs'),
      });
      try {
        const { importBlobs } = await import('./blobImport');
        await importBlobs(parsed.blobs, result.noteIds, (msg) =>
          setPhase((prev) =>
            prev.kind === 'parsing' ? { ...prev, status: msg } : prev
          )
        );
        onBlobsRestored?.();
      } catch (err) {
        console.warn('Blob import failed:', err);
        mediaError = err instanceof Error ? err.message : String(err);
      }
    }

    // For PrivacyNotes full backups, restore images + attachments from
    // the zip (uses manifest-based restoration, not parsed.blobs).
    if (importer.id === 'privacynotes' && selectedFileRef.current) {
      setPhase({
        kind: 'parsing',
        importer,
        status: t('status.restoringBlobs'),
      });
      try {
        const { restoreBlobs } = await import('./privacynotes');
        await restoreBlobs(selectedFileRef.current, (msg) =>
          setPhase((prev) =>
            prev.kind === 'parsing' ? { ...prev, status: msg } : prev
          )
        );
        // Re-trigger pending uploads so restored blobs reach Supabase.
        // Without this, blobs sit in local cache but never get uploaded,
        // making them unavailable on other devices.
        onBlobsRestored?.();
      } catch (err) {
        // Notes are already imported, so this never rolls anything back -
        // but a backup that restored its notes and lost its images is not
        // a restore, and the user has to be told.
        console.warn('Blob restore failed:', err);
        mediaError ??= err instanceof Error ? err.message : String(err);
      }
    }

    // Fire anonymous import telemetry. No user identifier, no content -
    // just `{type: 'import', source: 'google-keep' | 'standard-notes'}`
    // so we can see which import paths are actually getting exercised.
    // Swallows its own errors; never blocks the happy path.
    const source = importerIdToSource(importer.id);
    if (source) {
      recordAdminEvent(supabase, 'import', source);
    }

    // The notes exist locally whatever happened to the media, so the
    // parent hears about them first: the list has to refresh and the sync
    // has to run even when the error phase below keeps the modal open.
    onImported(result.imported, result.skippedDuplicates);
    if (mediaError) {
      setPhase({
        kind: 'error',
        importer,
        message: t('errors.blobImportFailed', { detail: mediaError }),
      });
      return;
    }
    onClose();
  }

  function handleBackToPick() {
    setActiveImporter(null);
    selectedFileRef.current = null;
    setQuotaCheck(null);
    setPhase({ kind: 'pick' });
  }

  return (
    <div
      className={embedded ? 'contents' : 'fixed inset-0 bg-black/50 dark:bg-black/70 z-50 flex items-center justify-center p-4'}
      onClick={embedded ? undefined : onClose}
    >
      <div
        className={
          embedded
            ? 'flex-1 min-h-0 flex flex-col text-pn'
            : 'bg-surface-2 border border-divider rounded-lg max-w-lg w-full max-h-[85vh] flex flex-col text-pn'
        }
        onClick={(e) => e.stopPropagation()}
      >
        {!embedded && (
          <div className="flex items-center justify-between px-6 py-4 border-b border-divider">
            <h2 className="text-lg font-semibold">
              {tab === 'import' ? t('shell.importTitle') : tab === 'export' ? t('shell.exportTitle') : tab === 'restore' ? t('shell.restoreTitle') : t('shell.vaultTitle')}
            </h2>
            <button
              onClick={onClose}
              aria-label={t('common:actions.close')}
              className="text-pn-muted hover:text-pn transition p-1 -m-1"
            >
              <X size={18} />
            </button>
          </div>
        )}

        {/* `overflow-x-auto` + `shrink-0` + `whitespace-nowrap` mirror the
            AboutModal tab strip: four labeled tabs overflow a phone-width
            modal, and without a scroll container the last tab just clips
            (reported on an iPhone 2026-08-26, "Passwords" cut off). shrink-0
            is load-bearing for the same reason as there - a scroll container
            has an automatic minimum size of 0, so the flex column may
            otherwise squeeze the strip when a tall tab fills the pane. */}
        <div
          role="tablist"
          aria-label={t('shell.tablistLabel')}
          className="shrink-0 flex items-stretch border-b border-divider px-6 overflow-x-auto"
        >
          {([
            { id: 'import' as const, label: t('shell.tabImport'), icon: <Download aria-hidden="true" /> },
            { id: 'export' as const, label: t('shell.tabExport'), icon: <Upload aria-hidden="true" /> },
            { id: 'restore' as const, label: t('shell.tabRestore'), icon: <ArrowCounterClockwise aria-hidden="true" /> },
            // Key, not a padlock: the same glyph the sidebar gives the Vault
            // pillar (PILLAR_GLYPHS.vault), so the two surfaces agree.
            { id: 'vault' as const, label: t('shell.tabVault'), icon: <Key aria-hidden="true" /> },
          ]).map((tb) => (
            <button
              key={tb.id}
              role="tab"
              aria-selected={tab === tb.id}
              onClick={() => setTab(tb.id)}
              className={`inline-flex items-center gap-1.5 px-3 py-2.5 text-sm font-medium whitespace-nowrap border-b-2 -mb-px transition ${
                tab === tb.id
                  ? 'border-accent text-accent'
                  : 'border-transparent text-pn-soft hover:text-pn'
              }`}
            >
              {tb.icon}
              {tb.label}
            </button>
          ))}
        </div>

        <div className="flex-1 overflow-y-auto px-6 py-4">
          {(tab === 'import' || tab === 'vault') ? (
            <>
              {phase.kind === 'pick' && (
                tab === 'import' ? (
                  <ImportPickPhase
                    onPick={handlePickImporter}
                    autoTag={autoTag}
                    onAutoTagChange={setAutoTag}
                  />
                ) : (
                  <VaultPickPhase onPick={handlePickImporter} />
                )
              )}

              {phase.kind === 'parsing' && (
                <ParsingPhase
                  importerLabel={phase.importer.label}
                  status={phase.status}
                />
              )}

              {phase.kind === 'preview' && (
                <PreviewPhase
                  importerLabel={phase.importer.label}
                  parsed={phase.parsed}
                  quotaCheck={quotaCheck}
                  folderTags={folderTags}
                  browserTags={browserTags}
                  onBrowserTagsChange={setBrowserTags}
                  onFolderTagsChange={setFolderTags}
                />
              )}

              {phase.kind === 'applying' && (
                <ParsingPhase
                  importerLabel={phase.importer.label}
                  status={t('status.writingNotes')}
                />
              )}

              {phase.kind === 'error' && (
                <ErrorPhase
                  importerLabel={phase.importer.label}
                  message={phase.message}
                />
              )}
            </>
          ) : tab === 'restore' ? (
            <>
              {phase.kind === 'pick' && (
                <RestorePickPhase
                  onPickRestore={handlePickImporter}
                  onImportEncrypted={async (file) => {
                    // A .pnbackupz is the full-backup zip sealed under
                    // the phrase key: decrypt, then run the NORMAL zip
                    // restore flow, preview and blob restore included.
                    if (file.name.toLowerCase().endsWith('.pnbackupz')) {
                      const imp = IMPORTERS.find((i) => i.id === 'privacynotes');
                      if (!imp) return;
                      setPhase({ kind: 'parsing', importer: imp, status: t('status.decryptingBackup') });
                      try {
                        const zipFile = await decryptFullBackup(file);
                        await runParseFlow(imp, zipFile);
                      } catch (err) {
                        setPhase({
                          kind: 'error',
                          importer: imp,
                          message: err instanceof Error ? err.message : t('errors.decryptionFailed'),
                        });
                      }
                      return;
                    }
                    setPhase({ kind: 'parsing', importer: { id: 'privacynotes', label: t('encryptedBackupLabel'), description: '', accept: '.pnbackup', enabled: true, sourceTag: '', parse: async () => { throw new Error(); } }, status: t('status.decryptingBackup') });
                    try {
                      const count = await onImportEncrypted(file);
                      onImported(count);
                      onClose();
                    } catch (err) {
                      setPhase({
                        kind: 'error',
                        importer: { id: 'privacynotes', label: t('encryptedBackupLabel'), description: '', accept: '.pnbackup', enabled: true, sourceTag: '', parse: async () => { throw new Error(); } },
                        message: err instanceof Error ? err.message : t('errors.decryptionFailed'),
                      });
                    }
                  }}
                />
              )}
              {phase.kind === 'parsing' && (
                <ParsingPhase importerLabel={phase.importer.label} status={phase.status} />
              )}
              {phase.kind === 'preview' && (
                <PreviewPhase importerLabel={phase.importer.label} parsed={phase.parsed} quotaCheck={quotaCheck} />
              )}
              {phase.kind === 'applying' && (
                <ParsingPhase importerLabel={phase.importer.label} status={t('status.writingNotes')} />
              )}
              {phase.kind === 'error' && (
                <ErrorPhase importerLabel={phase.importer.label} message={phase.message} />
              )}
            </>
          ) : (
            <ExportPanel
              notes={notes}
              onExportAllMdZip={(ns) => {
                onExportAllMdZip(ns);
                onClose();
              }}
              onExportAllHtmlZip={(ns) => {
                onExportAllHtmlZip(ns);
                onClose();
              }}
              onExportAllJson={(ns) => {
                onExportAllJson(ns);
                onClose();
              }}
              onExportEncrypted={(ns) => {
                onExportEncrypted(ns);
                onClose();
              }}
              onExportEncryptedZip={(ns) => {
                onExportEncryptedZip(ns);
                onClose();
              }}
              onExportBookmarks={(ns) => {
                onExportBookmarks(ns);
                onClose();
              }}
              onExportVault={(ns) => {
                onExportVault(ns);
                onClose();
              }}
            />
          )}
        </div>

        <div className="px-5 py-3 border-t border-divider flex items-center justify-between gap-3">
          {tab === 'export' ? (
            <>
              <div className="text-xs text-pn-soft">
                {t('footer.exportNote')}
              </div>
              <button
                onClick={onClose}
                className="text-sm rounded border border-divider px-3 py-1.5 hover:bg-surface-1 transition"
              >
                {t('common:actions.cancel')}
              </button>
            </>
          ) : tab === 'restore' && phase.kind === 'pick' ? (
            <>
              <div className="text-xs text-pn-soft">
                {t('footer.restoreNote')}
              </div>
              <button
                onClick={onClose}
                className="text-sm rounded border border-divider px-3 py-1.5 hover:bg-surface-1 transition"
              >
                {t('common:actions.cancel')}
              </button>
            </>
          ) : phase.kind === 'pick' ? (
            <>
              <div className="text-xs text-pn-soft">
                {t('footer.importNote')}
              </div>
              <button
                onClick={onClose}
                className="text-sm rounded border border-divider px-3 py-1.5 hover:bg-surface-1 transition"
              >
                {t('common:actions.cancel')}
              </button>
            </>
          ) : phase.kind === 'preview' ? (
            <>
              <button
                onClick={handleBackToPick}
                className="text-sm rounded border border-divider px-3 py-1.5 hover:bg-surface-1 transition"
              >
                {t('common:actions.back')}
              </button>
              <button
                onClick={handleConfirm}
                disabled={quotaCheck?.exceeds === true}
                className="text-sm rounded bg-accent text-white px-4 py-1.5 hover:bg-accent-hover transition font-medium disabled:opacity-50 disabled:cursor-not-allowed"
              >
                {t('counts.importButton', { counts: formatTypeCountsShort(phase.parsed.notes) })}
              </button>
            </>
          ) : phase.kind === 'error' ? (
            <>
              <button
                onClick={handleBackToPick}
                className="text-sm rounded border border-divider px-3 py-1.5 hover:bg-surface-1 transition"
              >
                {t('common:actions.back')}
              </button>
              <button
                onClick={onClose}
                className="text-sm rounded border border-divider px-3 py-1.5 hover:bg-surface-1 transition"
              >
                {t('common:actions.cancel')}
              </button>
            </>
          ) : (
            <div className="text-xs text-pn-muted w-full text-center">
              {t('shell.working')}
            </div>
          )}
        </div>

        {/* Hidden file input - shared by all importer cards. */}
        <input
          ref={fileInputRef}
          type="file"
          className="hidden"
          accept={pickerAccept(activeImporter?.accept ?? '')}
          onChange={handleFileSelected}
        />
      </div>
    </div>
  );
}

/** Importers drawn with a phosphor glyph instead of a brand asset, for a
 *  source no single vendor owns. */
const IMPORT_GLYPH: Record<string, ReactNode> = {
  // A key, matching the sidebar's Vault pillar. No browser logo: the same
  // .csv comes out of all of them.
  'browser-passwords': <Key size={20} aria-hidden="true" />,
};

/** App icons for the note importers, reused from the /help import guides
 *  (public/help/icons). markdown-folder maps to the generic markdown mark. */
const IMPORT_ICON: Record<string, string> = {
  // Every browser writes the same bookmarks file, so this row's icon is
  // the one that is not the source app's own logo: the Chrome mark stands
  // in for "your browser" and the description names the other six. Same
  // asset as the /help guide tile and the homepage import pill.
  'browser-bookmarks': '/help/icons/browser-bookmarks.svg',
  'google-keep': '/help/icons/google-keep.svg',
  'apple-notes': '/help/icons/apple-notes.svg',
  'apple-journal': '/help/icons/apple-journal.webp',
  'evernote': '/help/icons/evernote.svg',
  'samsung-notes': '/help/icons/samsung-notes.webp',
  'simplenote': '/help/icons/simplenote.svg',
  'standard-notes': '/help/icons/standard-notes.webp',
  'obsidian': '/help/icons/obsidian.svg',
  'notesnook': '/help/icons/notesnook.svg',
  'upnote': '/help/icons/upnote.svg',
  'markdown-folder': '/help/icons/markdown.svg',
  'bitwarden': '/help/icons/bitwarden.svg',
  'typora': '/help/icons/typora.webp',
  'ia-writer': '/help/icons/ia-writer.webp',
  'zettlr': '/help/icons/zettlr.svg',
  'nextcloud-notes': '/help/icons/nextcloud-notes.svg',
};

/** Maps importer ids to their /help/import/<slug>/ guide slug. Slugs match
 *  ids 1:1 except markdown-folder, whose guide lives under "markdown". */
const GUIDE_SLUG: Record<string, string> = {
  'apple-journal': 'apple-journal',
  'browser-bookmarks': 'browser-bookmarks',
  'apple-notes': 'apple-notes',
  'bitwarden': 'bitwarden',
  'browser-passwords': 'browser-passwords',
  'evernote': 'evernote',
  'google-keep': 'google-keep',
  'markdown-folder': 'markdown',
  'typora': 'typora',
  'ia-writer': 'ia-writer',
  'zettlr': 'zettlr',
  'nextcloud-notes': 'nextcloud-notes',
  'notesnook': 'notesnook',
  'obsidian': 'obsidian',
  'samsung-notes': 'samsung-notes',
  'simplenote': 'simplenote',
  'standard-notes': 'standard-notes',
  'upnote': 'upnote',
};

/** Maps importer ids to their description translation key under sourceDesc. */
const SOURCE_DESC_KEY: Record<string, string> = {
  'browser-bookmarks': 'sourceDesc.browserBookmarks',
  'google-keep': 'sourceDesc.googleKeep',
  'apple-notes': 'sourceDesc.appleNotes',
  'apple-journal': 'sourceDesc.appleJournal',
  'evernote': 'sourceDesc.evernote',
  'samsung-notes': 'sourceDesc.samsungNotes',
  'simplenote': 'sourceDesc.simplenote',
  'standard-notes': 'sourceDesc.standardNotes',
  'obsidian': 'sourceDesc.obsidian',
  'notesnook': 'sourceDesc.notesnook',
  'upnote': 'sourceDesc.upnote',
  'markdown-folder': 'sourceDesc.markdownFolder',
  // One shared line for the four markdown-app aliases: the parser is the
  // same, so four near-identical descriptions would be four copies to keep
  // in step across every locale. What differs per app is in its guide, one
  // click away in the row's guide rail.
  'typora': 'sourceDesc.markdownApp',
  'ia-writer': 'sourceDesc.markdownApp',
  'zettlr': 'sourceDesc.markdownApp',
  'nextcloud-notes': 'sourceDesc.markdownApp',
  'bitwarden': 'sourceDesc.bitwarden',
  'browser-passwords': 'sourceDesc.browserPasswords',
};

/** The 32px plate every Import, Export and Restore row draws its mark on.
 *  `glyph` wins over `src`, so an id must never carry both.
 *  Spec: ops/docs/ui-patterns.md (section 71) */
function RowIcon({ src, glyph }: { src?: string; glyph?: ReactNode }) {
  if (!glyph && !src) return null;
  return (
    <span className="shrink-0 w-8 h-8 rounded-md bg-track flex items-center justify-center overflow-hidden text-pn-soft">
      {glyph ?? (
        <img src={src} alt="" width={20} height={20} className="w-5 h-5 object-contain" loading="lazy" />
      )}
    </span>
  );
}

/** The app's own mark, for the rows that read or write our own format. */
const PN_ICON = '/favicon.svg';

/** One importer row: icon, name, description, and a labelled rail linking
 *  to its /help/import/<slug>/ guide when one exists. Shared by the Import
 *  and Passwords tabs so the two rows never drift apart. */
function ImporterRow({ imp, onPick }: { imp: Importer; onPick: (imp: Importer) => void }) {
  const { t } = useTranslation('importExport');
  const iconSrc = IMPORT_ICON[imp.id];
  const glyph = IMPORT_GLYPH[imp.id];
  const guideSlug = GUIDE_SLUG[imp.id];
  const descKey = SOURCE_DESC_KEY[imp.id];

  return (
    // The border and the rounding sit on the row, not on the button: the guide
    // rail is a second target inside the same frame, and its divider is that
    // frame's only internal line. Do NOT add `overflow-hidden` here - it would
    // clip the rail's hover tip. Spec: ops/docs/ui-patterns.md (section 18)
    <div
      className={`flex items-stretch rounded-lg border transition ${
        imp.enabled ? 'border-divider hover:border-accent' : 'border-divider opacity-40'
      }`}
    >
      <button
        disabled={!imp.enabled}
        onClick={() => onPick(imp)}
        className={`flex-1 min-w-0 text-start rounded-s-lg px-3 py-2.5 transition flex items-center gap-3 ${
          imp.enabled ? 'hover:bg-accent/5 cursor-pointer' : 'cursor-not-allowed'
        }`}
      >
        <RowIcon src={iconSrc} glyph={glyph} />
        <span className="min-w-0">
          <span className="block font-medium text-sm">{imp.label}</span>
          <span className="block text-xs text-pn-soft mt-0.5">
            {descKey ? t(descKey) : imp.description}
          </span>
        </span>
      </button>
      {guideSlug && (
        <a
          href={siteHref(`${helpPath(activeLocale())}/import/${guideSlug}`)}
          target="_blank"
          rel="noopener noreferrer"
          aria-label={t('importPick.guideAria', { app: imp.label })}
          className="shrink-0 w-16 flex items-center justify-center border-s border-divider rounded-e-lg bg-accent/5 text-accent hover:bg-accent/10 transition"
        >
          {/* The tip still opens toward the row (`start`), which is what keeps
              it clear of the modal's scroller edge. */}
          <HoverLabel
            label={t('importPick.guideAria', { app: imp.label })}
            position="start"
            className="flex flex-col items-center gap-1"
          >
            <BookOpenText size={18} aria-hidden="true" />
            <span className="text-[11px] leading-none">{t('importPick.guideLabel')}</span>
          </HoverLabel>
        </a>
      )}
    </div>
  );
}

/** Import tab - notes & journals only, 1-col with descriptions. */
function ImportPickPhase({ onPick, autoTag, onAutoTagChange }: { onPick: (imp: Importer) => void; autoTag: boolean; onAutoTagChange: (v: boolean) => void }) {
  const { t } = useTranslation('importExport');
  const importerMap = Object.fromEntries(IMPORTERS.map((i) => [i.id, i]));
  // Browser bookmarks leads on purpose; everything below it is
  // alphabetical. It is the only entry that is not a note app, and it is
  // the one people arrive looking for. Spec: ops/docs/plans/bookmarks-pillar.md
  const noteIds = ['browser-bookmarks', 'apple-journal', 'apple-notes', 'evernote', 'google-keep', 'ia-writer', 'markdown-folder', 'nextcloud-notes', 'notesnook', 'obsidian', 'samsung-notes', 'simplenote', 'standard-notes', 'typora', 'upnote', 'zettlr'];

  return (
    <div className="space-y-3">
      <label className="flex items-start gap-2 rounded-lg border border-divider p-3 cursor-pointer hover:bg-surface-1 transition">
        <input
          type="checkbox"
          checked={autoTag}
          onChange={(e) => onAutoTagChange(e.target.checked)}
          className="h-4 w-4 mt-0.5 shrink-0 accent-accent"
        />
        <div>
          <div className="text-sm font-medium">{t('importPick.autoTagLabel')}</div>
          <div className="text-xs text-pn-soft mt-0.5">
            <Trans
              i18nKey="importExport:importPick.autoTagDesc"
              components={{
                keep: <span className="font-mono text-accent" />,
                obsidian: <span className="font-mono text-accent" />,
              }}
            />
          </div>
        </div>
      </label>

      <div className="space-y-1.5">
        {noteIds.map((id) => {
          const imp = importerMap[id];
          if (!imp) return null;
          return <ImporterRow key={id} imp={imp} onPick={onPick} />;
        })}
      </div>
    </div>
  );
}

/** Passwords tab - password-manager importers, 1-col with descriptions. */
function VaultPickPhase({ onPick }: { onPick: (imp: Importer) => void }) {
  const { t } = useTranslation('importExport');
  const importerMap = Object.fromEntries(IMPORTERS.map((i) => [i.id, i]));
  const vaultIds = ['bitwarden', 'browser-passwords'];

  return (
    <div className="space-y-3">
      <p className="text-sm text-pn-soft">
        {t('vaultPick.intro')}
      </p>

      <HelpChip surface="vault" />

      <div className="space-y-1.5">
        {vaultIds.map((id) => {
          const imp = importerMap[id];
          if (!imp) return null;
          return <ImporterRow key={id} imp={imp} onPick={onPick} />;
        })}
      </div>
    </div>
  );
}

/** Restore tab pick phase - PrivacyNotes backup restore, 1-col with full descriptions. */
function RestorePickPhase({ onPickRestore, onImportEncrypted }: {
  onPickRestore: (imp: Importer) => void;
  onImportEncrypted: (file: File) => void;
}) {
  const { t } = useTranslation('importExport');
  const encFileRef = useRef<HTMLInputElement | null>(null);
  const importerMap = Object.fromEntries(IMPORTERS.map((i) => [i.id, i]));

  return (
    <div className="space-y-3">
      <p className="text-sm text-pn-soft">
        {t('restorePick.intro')}
      </p>

      <HelpChip surface="restore" />

      <div className="space-y-1.5">
        <ActionRow
          title={t('restorePick.fullBackupTitle')}
          description={t('restorePick.fullBackupDesc')}
          glyph={<FileZip size={20} aria-hidden="true" />}
          onClick={() => {
            const imp = importerMap['privacynotes'];
            if (imp) onPickRestore(imp);
          }}
        />
        <ActionRow
          title={t('restorePick.encryptedBackupTitle')}
          description={t('restorePick.encryptedBackupDesc')}
          locked
          src={PN_ICON}
          onClick={() => encFileRef.current?.click()}
        />
      </div>

      <input
        ref={encFileRef}
        type="file"
        className="hidden"
        accept={pickerAccept('.pnbackup,.pnbackupz')}
        onChange={(e) => {
          const file = e.target.files?.[0];
          if (encFileRef.current) encFileRef.current.value = '';
          if (file) onImportEncrypted(file);
        }}
      />
    </div>
  );
}

function ParsingPhase({
  importerLabel,
  status,
}: {
  importerLabel: string;
  status: string;
}) {
  return (
    <div className="flex flex-col items-center justify-center py-10 text-center">
      <div className="mb-4">
        <CircleNotch size={32} className="animate-spin text-accent" />
      </div>
      <div className="text-sm font-medium">{importerLabel}</div>
      <div className="text-xs text-pn-muted mt-1">
        {status}
      </div>
    </div>
  );
}

/** Derive type-aware counts from notes at render time. */
function computeTypeCounts(notes: ImportedNote[]): { label: string; count: number }[] {
  let noteCount = 0;
  let journalCount = 0;
  let loginCount = 0;
  let cardCount = 0;
  let sshKeyCount = 0;
  for (const n of notes) {
    switch (n.type) {
      case 'journal': journalCount++; break;
      case 'login': loginCount++; break;
      case 'card': cardCount++; break;
      case 'ssh-key': sshKeyCount++; break;
      default: noteCount++; break;
    }
  }
  const parts: { label: string; count: number }[] = [];
  if (noteCount > 0) parts.push({ label: i18n.t('importExport:counts.note', { count: noteCount }), count: noteCount });
  if (journalCount > 0) parts.push({ label: i18n.t('importExport:counts.journal', { count: journalCount }), count: journalCount });
  if (loginCount > 0) parts.push({ label: i18n.t('importExport:counts.login', { count: loginCount }), count: loginCount });
  if (cardCount > 0) parts.push({ label: i18n.t('importExport:counts.card', { count: cardCount }), count: cardCount });
  if (sshKeyCount > 0) parts.push({ label: i18n.t('importExport:counts.sshKey', { count: sshKeyCount }), count: sshKeyCount });
  return parts;
}

/** Format type counts for the confirm button label. */
function formatTypeCountsShort(notes: ImportedNote[]): string {
  const parts = computeTypeCounts(notes);
  if (parts.length === 0) return i18n.t('importExport:counts.zeroItems');
  if (parts.length === 1) return `${parts[0]!.count} ${parts[0]!.label}`;
  return parts.map((p) => `${p.count} ${p.label}`).join(', ');
}

function PreviewPhase({
  importerLabel,
  parsed,
  quotaCheck,
  folderTags,
  onFolderTagsChange,
  browserTags,
  onBrowserTagsChange,
}: {
  importerLabel: string;
  parsed: ParsedImport;
  quotaCheck: QuotaCheck | null;
  folderTags?: boolean;
  onFolderTagsChange?: (v: boolean) => void;
  browserTags?: boolean;
  onBrowserTagsChange?: (v: boolean) => void;
}) {
  const { t } = useTranslation('importExport');
  const { stats, warnings, transforms, notes } = parsed;
  const sampleTitles = notes.slice(0, 5).map((n) => n.title);
  const typeCounts = computeTypeCounts(notes);
  const hasMultipleTypes = typeCounts.length > 1;
  // Every importer that rebuilds a folder tree (Obsidian vaults,
  // Notesnook notebooks) gets the folder-tag toggle. Sources that carry
  // folderIds without a tree of their own (PrivacyNotes backups) do not
  // populate parsed.folders, so they fall through unchanged.
  const showFolderTags = (parsed.folders?.length ?? 0) > 0;
  // Only Firefox writes these, and only for bookmarks the user labelled,
  // so the toggle appears only when the file actually carries some.
  const showBrowserTags = notes.some((n) => (n.browserTags?.length ?? 0) > 0);
  const allLinks = notes.length > 0 && notes.every((n) => n.type === 'link');
  // Reflect the folder tags the import is about to add (reactive to the
  // toggle) so the tag counts match what actually lands, not the raw
  // parse-time count. Non-folder imports fall through to notes unchanged.
  const previewNotes = useMemo(() => {
    const withFolders = showFolderTags
      ? withFolderPathTags(notes, folderTags ?? false)
      : notes;
    return withBrowserTags(withFolders, browserTags ?? false);
  }, [showFolderTags, notes, folderTags, browserTags]);
  const uniqueTagCount = useMemo(
    () => new Set(previewNotes.flatMap((n) => n.tags)).size,
    [previewNotes]
  );
  const untaggedCount = useMemo(
    () => previewNotes.filter((n) => n.tags.length === 0).length,
    [previewNotes]
  );
  return (
    <div className="space-y-4">
      <div>
        <SectionEyebrow className="mb-1">
          {t('preview.sourceLabel')}
        </SectionEyebrow>
        <div className="text-sm font-medium">{importerLabel}</div>
      </div>

      <div className={`grid gap-2 text-sm ${hasMultipleTypes ? 'grid-cols-2' : 'grid-cols-2'}`}>
        {hasMultipleTypes ? (
          <>
            {typeCounts.map((tc) => (
              <StatCell key={tc.label} label={tc.label.charAt(0).toUpperCase() + tc.label.slice(1)} value={tc.count} />
            ))}
            <StatCell label={t('preview.uniqueTags')} value={uniqueTagCount} muted />
            <StatCell label={t('preview.empty')} value={stats.emptyNotes} muted />
          </>
        ) : (
          <>
            <StatCell label={typeCounts[0] ? typeCounts[0].label.charAt(0).toUpperCase() + typeCounts[0].label.slice(1) : t('preview.items')} value={stats.totalNotes} />
            <StatCell label={t('preview.uniqueTags')} value={uniqueTagCount} />
            <StatCell label={t('preview.empty')} value={stats.emptyNotes} muted />
            <StatCell label={t('preview.untagged')} value={untaggedCount} muted />
          </>
        )}
      </div>

      {quotaCheck?.exceeds && (
        <div className="rounded-lg border border-red-400/40 bg-red-50 dark:bg-red-900/10 p-3 text-xs space-y-1 text-red-800 dark:text-red-300">
          <Trans
            i18nKey="importExport:preview.quotaExceeded"
            values={{
              needed: formatBytes(quotaCheck.estimatedBytes),
              available: formatBytes(quotaCheck.availableBytes),
            }}
            components={{ strong: <strong /> }}
          />
        </div>
      )}
      {quotaCheck && !quotaCheck.exceeds && quotaCheck.estimatedBytes > quotaCheck.availableBytes * 0.8 && (
        <div className="rounded-lg border border-amber-400/40 bg-amber-50 dark:bg-amber-900/10 p-3 text-xs text-amber-800 dark:text-amber-300">
          {t('preview.quotaWarning', {
            needed: formatBytes(quotaCheck.estimatedBytes),
            available: formatBytes(quotaCheck.availableBytes),
          })}
        </div>
      )}

      {transforms.length > 0 && (
        <div className="rounded-lg border border-accent/40 bg-accent/5 p-3 text-xs space-y-1">
          {transforms.map((t, i) => (
            <div
              key={i}
              className="text-accent flex items-start gap-1.5"
            >
              <Check size={12} className="mt-0.5 shrink-0" />
              <span>{t}</span>
            </div>
          ))}
        </div>
      )}

      {showFolderTags && onFolderTagsChange && (
        <label className="flex items-start gap-2 rounded-lg border border-divider p-3 cursor-pointer hover:bg-surface-1 transition">
          <input
            type="checkbox"
            checked={folderTags ?? false}
            onChange={(e) => onFolderTagsChange(e.target.checked)}
            className="h-4 w-4 mt-0.5 shrink-0 accent-accent"
          />
          <div>
            <div className="text-sm font-medium">
              {t('folderImport.tagLabel')}
            </div>
            <div className="text-xs text-pn-soft mt-0.5">
              {t('folderImport.tagDesc')}
            </div>
          </div>
        </label>
      )}

      {showBrowserTags && onBrowserTagsChange && (
        <label className="flex items-start gap-2 rounded-lg border border-divider p-3 cursor-pointer hover:bg-surface-1 transition">
          <input
            type="checkbox"
            checked={browserTags ?? false}
            onChange={(e) => onBrowserTagsChange(e.target.checked)}
            className="h-4 w-4 mt-0.5 shrink-0 accent-accent"
          />
          <div>
            <div className="text-sm font-medium">
              {t('browserImport.tagLabel')}
            </div>
            <div className="text-xs text-pn-soft mt-0.5">
              {t('browserImport.tagDesc')}
            </div>
          </div>
        </label>
      )}

      {warnings.length > 0 && (
        <div className="rounded-lg border border-amber-400/40 bg-amber-50 dark:bg-amber-900/10 p-3 text-xs space-y-1">
          {warnings.map((w, i) => (
            <div key={i} className="text-amber-800 dark:text-amber-300">
              {w}
            </div>
          ))}
        </div>
      )}

      {sampleTitles.length > 0 && (
        <div>
          <SectionEyebrow className="mb-1">
            {t('preview.previewLabel')}
          </SectionEyebrow>
          <ul className="text-xs text-pn-soft space-y-0.5 font-mono">
            {sampleTitles.map((title, i) => (
              <li key={i} className="truncate">
                &middot; {title || t('common:state.untitled')}
              </li>
            ))}
            {notes.length > sampleTitles.length && (
              <li className="text-pn-muted">
                {t('preview.andMore', { count: notes.length - sampleTitles.length })}
              </li>
            )}
          </ul>
        </div>
      )}

      <SettingsCallout>
        <strong className="text-pn">
          {t('preview.headsUpLabel')}
        </strong>{' '}
        {/* Bookmarks are the one source apply.ts dedupes, on exact URL, so
            the standing "you will get duplicates" line is false for them. */}
        {allLinks ? t('preview.duplicateSkipNote') : t('preview.duplicateWarning')}
      </SettingsCallout>
    </div>
  );
}

function StatCell({
  label,
  value,
  muted,
}: {
  label: string;
  value: number;
  muted?: boolean;
}) {
  return (
    <div
      className={`rounded-lg border border-divider p-3 ${
        muted ? 'opacity-70' : ''
      }`}
    >
      <SectionEyebrow>
        {label}
      </SectionEyebrow>
      <div className="text-lg font-semibold tabular-nums mt-0.5">{value}</div>
    </div>
  );
}

function ErrorPhase({
  importerLabel,
  message,
}: {
  importerLabel: string;
  message: string;
}) {
  const { t } = useTranslation('importExport');
  return (
    <div className="py-6">
      <SectionEyebrow danger className="mb-1">
        {t('errorPhase.heading', { importer: importerLabel })}
      </SectionEyebrow>
      <div className="text-sm text-pn-soft whitespace-pre-wrap">
        {message}
      </div>
    </div>
  );
}

/**
 * Export tab body - exports that run over the whole note set. The full
 * backups and the portable archives always render; the bookmarks-only and
 * vault-only writers appear once there is something for them to write.
 * Per-note exports live in the note's own share menu, not here. Each click
 * fires the parent's telemetry-wrapped handler, which also closes the modal.
 */
function ExportPanel({
  notes,
  onExportAllMdZip,
  onExportAllHtmlZip,
  onExportAllJson,
  onExportEncrypted,
  onExportEncryptedZip,
  onExportVault,
  onExportBookmarks,
}: {
  notes: LocalNote[];
  onExportAllMdZip: (ns: LocalNote[]) => void;
  onExportAllHtmlZip: (ns: LocalNote[]) => void;
  onExportAllJson: (ns: LocalNote[]) => void;
  onExportEncrypted: (ns: LocalNote[]) => void;
  onExportEncryptedZip: (ns: LocalNote[]) => void;
  onExportVault: (ns: LocalNote[]) => void;
  onExportBookmarks: (ns: LocalNote[]) => void;
}) {
  const { t } = useTranslation('importExport');
  const hasVaultItems = notes.some(
    (n) => n.type === 'login' || n.type === 'card' || n.type === 'ssh-key',
  );
  // Same rule as the vault section: the row appears once there is
  // something for it to write, and stays out of the way otherwise.
  const hasBookmarks = notes.some(
    (n) => n.type === 'link' && n.deleted !== 1 && n.trashed !== 1,
  );
  return (
    <div className="space-y-3">
      <p className="text-sm text-pn-soft">
        {t('export.intro')}
      </p>

      <HelpChip surface="export" />

      <div>
        <SectionEyebrow className="mb-1.5">
          {t('export.fullBackupHeading')}
        </SectionEyebrow>
        <div className="space-y-1.5">
          <ActionRow
            title={t('export.zipBackupTitle')}
            description={t('export.zipBackupDesc')}
            glyph={<FileZip size={20} aria-hidden="true" />}
            onClick={() => onExportAllMdZip(notes)}
          />
          <ActionRow
            title={t('export.encryptedZipBackupTitle')}
            description={t('export.encryptedZipBackupDesc')}
            locked
            src={PN_ICON}
            onClick={() => onExportEncryptedZip(notes)}
          />
          <ActionRow
            title={t('export.encryptedBackupTitle')}
            description={t('export.encryptedBackupDesc')}
            locked
            src={PN_ICON}
            onClick={() => onExportEncrypted(notes)}
          />
        </div>
      </div>

      <div>
        <SectionEyebrow className="mb-1.5">
          {t('export.portableHeading')}
        </SectionEyebrow>
        <div className="space-y-1.5">
          <ActionRow
            title={t('export.htmlArchiveTitle')}
            description={t('export.htmlArchiveDesc')}
            glyph={<FileHtml size={20} aria-hidden="true" />}
            onClick={() => onExportAllHtmlZip(notes)}
          />
          <ActionRow
            title={t('export.textBackupTitle')}
            description={t('export.textBackupDesc')}
            glyph={<BracketsCurly size={20} aria-hidden="true" />}
            onClick={() => onExportAllJson(notes)}
          />
        </div>
      </div>

      {hasBookmarks && (
        <div>
          <SectionEyebrow className="mb-1.5">
            {t('export.bookmarksOnlyHeading')}
          </SectionEyebrow>
          <div className="space-y-1.5">
            <ActionRow
              title={t('export.bookmarksExportTitle')}
              description={t('export.bookmarksExportDesc')}
              glyph={<FileHtml size={20} aria-hidden="true" />}
              onClick={() => onExportBookmarks(notes)}
            />
          </div>
        </div>
      )}

      {hasVaultItems && (
        <div>
          <SectionEyebrow className="mb-1.5">
            {t('export.vaultOnlyHeading')}
          </SectionEyebrow>
          <div className="space-y-1.5">
            <ActionRow
              title={t('export.vaultExportTitle')}
              description={t('export.vaultExportDesc')}
              glyph={<BracketsCurly size={20} aria-hidden="true" />}
              onClick={() => onExportVault(notes)}
            />
          </div>
        </div>
      )}

      {/* The question you leave with, not the one you arrive with, so it
          sits after the last section rather than beside the choice. */}
      <HelpChip surface="exportEnd" />
    </div>
  );
}

/** One Export or Restore tile: mark, title, optional Pro lock, description.
 *  Shared by both tabs so a file type looks the same wherever it appears -
 *  the mark names the FORMAT (.zip, .html, .json), and our own two formats
 *  take the app icon. */
function ActionRow({
  title,
  description,
  locked,
  glyph,
  src,
  onClick,
}: {
  title: string;
  description: string;
  locked?: boolean;
  glyph?: ReactNode;
  src?: string;
  onClick: () => void;
}) {
  return (
    <button
      onClick={onClick}
      className="w-full text-start rounded-lg border border-divider hover:border-accent hover:bg-accent/5 cursor-pointer px-3 py-2.5 transition flex items-center gap-3"
    >
      <RowIcon src={src} glyph={glyph} />
      <span className="min-w-0">
        <span className="block font-medium text-sm flex items-center gap-1.5">
          {title}
          {locked && (
            <Lock size={10} className="text-accent shrink-0" />
          )}
        </span>
        <span className="block text-xs text-pn-soft mt-0.5">{description}</span>
      </span>
    </button>
  );
}
