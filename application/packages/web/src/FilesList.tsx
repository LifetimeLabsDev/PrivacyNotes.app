/**
 * Files view - aggregated view of all images and file attachments
 * across all notes. Shows a storage bar, type filter, and a list of
 * file items with parent note context.
 *
 * Clicking a file opens the parent note in the editor.
 * "Upload files" creates a new note with the uploaded file attached.
 */

import { useState, useMemo, useRef, useEffect, useCallback } from 'react';
import { useTranslation } from 'react-i18next';
import type { ContextMenuItem } from './ContextMenu';
import type { LocalNote } from './db';
import type { ListPrefs, ListPrefsStore } from './listPrefs';
import { resolvePrefs, setPillarPrefs } from './listPrefs';
import { formatBytes } from './formatBytes';
import { StorageBar } from './StorageBar';
import { mimeToLabel, formatModifiedShort } from './notesViewUtils';
import { CardGlyph, FileTileIcon, TagChips } from './NoteRow';
import { iconPin, iconTrash, iconEditPencil, Check, CloudSlash, Folder, Upload, FunnelSimple, PushPin, Shield, PencilSimpleSlash, Files, PILLAR_GLYPHS } from './icons';
import { HoverLabel } from './HoverLabel';
import { SelectionToolbar } from './SelectionToolbar';
import { suppressShiftTextSelection } from './useMultiSelect';
import { ListSearchInput } from './ListSearchInput';
import { ActiveFilterEntry, ActiveSearchEntry, FilteredEmpty, ListFilterChips } from './ListFilterChips';
import type { View } from './views';
import { ListNav } from './notesView/ListNav';
import { ListPrefsPopover } from './ListPrefsPopover';
import { IconUpgrade } from './UpgradeModal';
import { isStorageConfigured } from './paddle';
import { proUnlocked } from './demo';
import { STORAGE_PACKAGES } from './pricing';
import { FILE_SIZE_LIMIT_PRO, FILE_SIZE_LIMIT_STORAGE } from './attachmentValidation';
import { loadEncryptedImageUrl } from './EncryptedImage';
import { useQuotaBlockedUuids } from './usePendingUploads';
import { unescapeMarkdownText } from './fileNames';

// ── Types ──────────────────────────────────────────────────────────────

export type FileType = 'all' | 'image' | 'audio' | 'document';

export interface FileItem {
  uuid: string;
  /** 'image' for pn:img/, 'attachment' for pn:file/ */
  kind: 'image' | 'attachment';
  /** Original filename (attachments) or 'Image' (images) */
  name: string;
  /** MIME type if known */
  mime: string;
  /** Original file size in bytes (0 if unknown) */
  size: number;
  /** Pre-formatted size string from the link (e.g. "164.2 KB"), shown as-is
   *  so the Files tile matches the note excerpt exactly. Empty if unknown. */
  sizeLabel: string;
  /** Parent note ID */
  noteId: string;
  /** Parent note title */
  noteTitle: string;
  /** Parent note updatedAt */
  updatedAt: string;
  /** Parent note createdAt */
  createdAt: string;
  /** true when the parent note is a dedicated file container (body is
   *  just a single pn:file/ link) vs an image/attachment embedded in a
   *  content note. */
  standalone: boolean;
  /** Whether the parent note is starred/pinned. */
  starred: boolean;
  /** Parent note's read-only flag. */
  locked: boolean;
  /** Parent note's PIN-protected flag. */
  pinProtected: boolean;
  /** Parent note's tags. */
  tags: string[];
  /** Parent note's folder, or null when unfiled. Feeds the folder chip. */
  folderId: string | null;
}

/** Categorize a FileItem into a filter bucket. */
function fileCategory(item: FileItem): 'image' | 'audio' | 'document' {
  if (item.kind === 'image') return 'image';
  if (item.mime.startsWith('audio/')) return 'audio';
  if (item.mime.startsWith('image/')) return 'image';
  return 'document';
}

// Sort types are shared via listPrefs.ts (SortField / SortDir).

/** Parse a pre-formatted size string like "42.2 MB" back to bytes. */
function parseSizeToBytes(s: string): number {
  const n = parseFloat(s) || 0;
  if (!n) return 0;
  const lower = s.toLowerCase();
  if (lower.includes('gb')) return n * 1000 * 1000 * 1000;
  if (lower.includes('mb')) return n * 1000 * 1000;
  if (lower.includes('kb')) return n * 1000;
  return n;
}

// ── Extraction ─────────────────────────────────────────────────────────

const IMG_RE = /pn:img\/([0-9a-f-]{36})/g;
// Capture groups exclude newlines so the filename group can't span lines
// and swallow preceding content (e.g. `- [ ] task` checkboxes) up to the
// first `|` later in the body, which corrupted the file-row label.
const ATT_RE = /\[([^|\n]*)\|([^|\n]*)\|([^\]\n]*)\]\(pn:file\/([0-9a-f-]{36})\)/g;
/** Extract all file items from a set of notes. */
export function extractFileItems(notes: LocalNote[]): FileItem[] {
  const items: FileItem[] = [];
  for (const note of notes) {
    if (!note.body) continue;
    const noteTitle = note.title || 'Untitled';
    const isStandaloneFile = note.type === 'file';
    // Images - count per note so we can label "Image 1", "Image 2"
    let m: RegExpExecArray | null;
    let imgIdx = 0;
    IMG_RE.lastIndex = 0;
    while ((m = IMG_RE.exec(note.body)) !== null) {
      imgIdx++;
      items.push({
        uuid: m[1]!,
        kind: 'image',
        name: imgIdx === 1 ? `Image, ${noteTitle}` : `Image ${imgIdx}, ${noteTitle}`,
        mime: 'image/*',
        size: 0,
        sizeLabel: '',
        noteId: note.id,
        noteTitle,
        updatedAt: note.updatedAt,
        createdAt: note.createdAt,
        standalone: false, // images are always embedded via the editor
        starred: note.starred === 1,
        locked: note.locked === 1,
        pinProtected: note.pinProtected === 1,
        tags: note.tags ?? [],
        folderId: note.folderId ?? null,
      });
    }
    // Attachments
    ATT_RE.lastIndex = 0;
    while ((m = ATT_RE.exec(note.body)) !== null) {
      const sizeStr = m[2]!;
      items.push({
        uuid: m[4]!,
        kind: 'attachment',
        // The body text is markdown, so a name holding a bracket or an
        // asterisk arrives escaped. The editor's chip reads the parsed
        // document and never sees the backslashes; this row reads the raw
        // body and would show them.
        name: unescapeMarkdownText(m[1]!) || 'Attachment',
        mime: m[3]! || 'application/octet-stream',
        size: parseSizeToBytes(sizeStr),
        sizeLabel: sizeStr.trim(),
        noteId: note.id,
        noteTitle,
        updatedAt: note.updatedAt,
        createdAt: note.createdAt,
        standalone: isStandaloneFile,
        starred: note.starred === 1,
        locked: note.locked === 1,
        pinProtected: note.pinProtected === 1,
        tags: note.tags ?? [],
        folderId: note.folderId ?? null,
      });
    }
  }
  // Sort by parent note updatedAt descending
  items.sort((a, b) => (a.updatedAt > b.updatedAt ? -1 : a.updatedAt < b.updatedAt ? 1 : 0));
  return items;
}

// ── Component ──────────────────────────────────────────────────────────

interface FilesListProps {
  fileItems: FileItem[];
  filesCount: number;
  /** Pro folders: active folder filter, rendered as a dismissable chip
   *  under the title row. Null when no folder is selected. */
  activeFolderName: string | null;
  /** Pillar switcher + drawer button, folded into this pane's title row. */
  onSelectView: (next: View) => void;
  /** Passed straight to ListNav; see userSettings.hiddenViews. */
  hiddenViews?: import('./views').View[] | undefined;
  onOpenDrawer: () => void;
  onClearFolder: () => void;
  onClearTag: () => void;
  /** Active tag filter - the chip beside the folder one. */
  activeTag: string | null;
  /** Currently open note - file rows whose parent matches highlight as active. */
  currentNoteId: string | null;
  /** Type filter - lifted to parent so it survives unmount/remount. */
  filter: FileType;
  onFilterChange: (f: FileType) => void;
  onOpenNote: (noteId: string, fileUuid?: string) => void;
  /** Rename a stored file: opens its note and puts the chip into rename
   *  mode. The name is only ever written by the chip in the live editor,
   *  so a pending edit there cannot overwrite it. */
  onRenameFile: (noteId: string, fileUuid: string) => void;
  onUploadFiles: () => void;
  mobileTabIndex?: number;
  quotaUsedBytes: number;
  quotaMaxBytes: number;
  onRefreshStorage: () => Promise<void> | void;
  /** Search string - controlled by parent (same search bar state as notes). */
  search: string;
  setSearch: (v: string) => void;
  searchInputRef: React.RefObject<HTMLInputElement | null>;
  /** Pro status - drives size limit shown in empty state. */
  isPro: boolean;
  /** Opens the upgrade modal (for file-size upsell). */
  onOpenUpgrade: () => void;
  /** True when the user holds an active storage subscription (cap above the Pro base). */
  hasStorageSub: boolean;
  /** Opens the storage management modal (SyncOptions storage tab). */
  onManageStorage: () => void;
  /** Shared list preferences (sort field/dir). */
  listPrefs: ListPrefs;
  /** Global layout: narrow rows ('list') or full-width tiles ('grid'). */
  viewMode: 'list' | 'grid';
  listPrefsStore: ListPrefsStore;
  onListPrefsChange: (next: ListPrefsStore) => void;
  /** Multi-select */
  selectionMode: boolean;
  selectedIds: Set<string>;
  selectionAllStarred: boolean;
  onRowClick: (e: React.MouseEvent, noteId: string) => void;
  onToggleSelected: (id: string) => void;
  onRangeSelect: (id: string) => void;
  onLongPressStart: (id: string) => void;
  onLongPressEnd: () => void;
  onClearSelection: () => void;
  onDeselectAll: () => void;
  onSelectAllVisible: () => void;
  onBulkFavorite: () => void;
  onBulkExport: () => void;
  onBulkMoveToFolder: () => void;
  foldersUnlocked: boolean;
  onBulkTrash: () => void;
  /** All existing tags (for the tag picker in SelectionToolbar). */
  allTags?: [string, number][];
  /** Bulk-add a tag to all selected notes. */
  onBulkTag: (tag: string) => void;
  /** Right-click on a file row - opens the per-file context menu. */
  onContextMenu: (e: React.MouseEvent, items: ContextMenuItem[]) => void;
  /** Per-file actions for the context menu. */
  onToggleStar: (noteId: string, starred: boolean) => void;
  onTrash: (noteId: string) => void;
  /** Look up parent note starred status. */
  isNoteStarred: (noteId: string) => boolean;
}

/** Derive a short filetype label from mime or filename extension. */
function getFileTypeLabel(item: FileItem): string {
  if (item.kind === 'image') return 'image';
  // Try extension from filename
  const dot = item.name.lastIndexOf('.');
  if (dot > 0) {
    const ext = item.name.slice(dot + 1).toLowerCase();
    if (ext.length <= 5) return ext;
  }
  // Fall back to mime subtype
  const slash = item.mime.indexOf('/');
  if (slash > 0) {
    const sub = item.mime.slice(slash + 1);
    if (sub !== 'octet-stream' && sub.length <= 10) return sub;
  }
  return 'file';
}

// Free-vs-Pro comparison shown to free users in the Files view (storage-bar
// area and empty state). Values are numbers with short labels so no locale can
// overflow the narrow column. Spec: ops/docs/pro-features.md (free vs Pro limits).
function ProUpsell({ onUpgrade, className = '' }: { onUpgrade: () => void; className?: string }) {
  const { t } = useTranslation('shell');
  const rows = [
    { label: t('filesList.perFile'), free: 5, pro: 50 },
    { label: t('filesList.storage'), free: 50, pro: 500 },
  ];
  return (
    <div className={`w-full ${className}`}>
      {rows.map((r) => (
        <div key={r.label} className="flex items-center justify-between gap-2 text-[11px] py-0.5">
          <span className="text-neutral-500 dark:text-neutral-400">{r.label}</span>
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span className="text-neutral-400 dark:text-neutral-500">
              {r.free} MB <span className="text-[9px] uppercase tracking-wide">{t('filesList.free')}</span>
            </span>
            <span className="text-neutral-400 dark:text-neutral-500" aria-hidden="true">{'→'}</span>
            <span className="text-accent font-medium">
              {r.pro} MB <span className="text-[9px] uppercase tracking-wide">Pro</span>
            </span>
          </span>
        </div>
      ))}
      <button
        type="button"
        onClick={onUpgrade}
        className="mt-2 w-full inline-flex items-center justify-center gap-1.5 rounded-md bg-accent/10 hover:bg-accent/20 text-accent font-medium text-xs px-3 py-2 transition"
      >
        <IconUpgrade size={12} /> {t('filesList.upgradeToPro')}
      </button>
    </div>
  );
}

// Storage upsell shown to Pro users without a storage subscription (Files
// view). Pitches capacity only - the per-file bump ships later alongside the
// storage-backend change. Spec: ops/docs/file-size-storage-upsell.md (final per-file cap numbers still open; flat 100 MB is the plan)
function StorageUpsell({
  onManage,
  currentMaxBytes,
  className = '',
}: {
  onManage: () => void;
  currentMaxBytes: number;
  className?: string;
}) {
  const { t } = useTranslation('shell');
  // Spec: ops/docs/design-decisions.md (Pro base 500 MB storage)
  const MB = 1000 * 1000;
  const GB = 1000 * MB;
  const base = currentMaxBytes > 0 ? currentMaxBytes : 500 * MB;
  const maxAddonGb = Math.max(...STORAGE_PACKAGES.map((p) => p.gb));
  const fromLabel = base >= GB ? `${Math.round((base / GB) * 10) / 10} GB` : `${Math.round(base / MB)} MB`;
  const targetLabel = `${Math.round((base / GB + maxAddonGb) * 10) / 10} GB`;
  const perFileFrom = `${Math.round(FILE_SIZE_LIMIT_PRO / MB)} MB`;
  const perFileTo = `${Math.round(FILE_SIZE_LIMIT_STORAGE / MB)} MB`;
  return (
    <div className={`w-full ${className}`}>
      <div className="flex items-center justify-between gap-2 text-[11px] py-0.5">
        <span className="text-neutral-500 dark:text-neutral-400">{t('filesList.perFile')}</span>
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <span className="text-neutral-400 dark:text-neutral-500">{perFileFrom}</span>
          <span className="text-neutral-400 dark:text-neutral-500" aria-hidden="true">{'→'}</span>
          <span className="text-accent font-medium">{perFileTo}</span>
        </span>
      </div>
      <div className="flex items-center justify-between gap-2 text-[11px] py-0.5">
        <span className="text-neutral-500 dark:text-neutral-400">{t('filesList.storage')}</span>
        <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
          <span className="text-neutral-400 dark:text-neutral-500">{fromLabel}</span>
          <span className="text-neutral-400 dark:text-neutral-500" aria-hidden="true">{'→'}</span>
          <span className="text-accent font-medium">{t('filesList.upToMax', { max: targetLabel })}</span>
        </span>
      </div>
      <button
        type="button"
        onClick={onManage}
        className="mt-2 w-full inline-flex items-center justify-center gap-1.5 rounded-md bg-accent/10 hover:bg-accent/20 text-accent font-medium text-xs px-3 py-2 transition"
      >
        <IconUpgrade size={12} /> {t('filesList.addStorage')}
      </button>
    </div>
  );
}

/** Lazy-loaded encrypted image background for image file tiles in grid mode.
 *  Decrypts + shows the image only once the tile scrolls near the viewport. */
function FileTileImageBg({ uuid }: { uuid: string }) {
  const [url, setUrl] = useState<string | null>(null);
  const ref = useRef<HTMLDivElement>(null);
  useEffect(() => {
    const el = ref.current;
    if (!el) return;
    let cancelled = false;
    const io = new IntersectionObserver(
      (entries) => {
        if (entries.some((e) => e.isIntersecting)) {
          io.disconnect();
          void loadEncryptedImageUrl(uuid).then((u) => {
            if (!cancelled) setUrl(u);
          });
        }
      },
      { rootMargin: '300px' },
    );
    io.observe(el);
    return () => {
      cancelled = true;
      io.disconnect();
    };
  }, [uuid]);
  return (
    <div ref={ref} className="absolute inset-0 bg-neutral-200 dark:bg-neutral-800">
      {url && (
        <img src={url} alt="" className="absolute inset-0 w-full h-full object-cover" draggable={false} />
      )}
    </div>
  );
}

export function FilesList({
  fileItems,
  filesCount,
  activeFolderName,
  onSelectView,
  hiddenViews,
  onOpenDrawer,
  onClearFolder,
  onClearTag,
  activeTag,
  currentNoteId,
  filter,
  onFilterChange: setFilter,
  onOpenNote,
  onRenameFile,
  onUploadFiles,
  mobileTabIndex,
  quotaUsedBytes,
  quotaMaxBytes,
  onRefreshStorage,
  search,
  setSearch,
  searchInputRef,
  isPro,
  onOpenUpgrade,
  hasStorageSub,
  onManageStorage,
  selectionMode,
  selectedIds,
  selectionAllStarred,
  onRowClick,
  onToggleSelected,
  onRangeSelect,
  onLongPressStart,
  onLongPressEnd,
  onClearSelection,
  onDeselectAll,
  onSelectAllVisible,
  onBulkFavorite,
  onBulkExport,
  onBulkMoveToFolder,
  foldersUnlocked,
  onBulkTrash,
  onContextMenu,
  onToggleStar,
  onTrash,
  isNoteStarred,
  allTags,
  onBulkTag,
  listPrefs,
  viewMode,
  listPrefsStore,
  onListPrefsChange,
}: FilesListProps) {
  const { t } = useTranslation(['shell', 'notes', 'media']);
  const showNote = listPrefs.showAttachedNotes;
  /** Blobs kept local because they do not fit the storage quota - the
   *  rows wear the same amber chip as the attachment card (#151). */
  const quotaBlockedUuids = useQuotaBlockedUuids();
  const setShowNote = (v: boolean | ((prev: boolean) => boolean)) => {
    const next = typeof v === 'function' ? v(showNote) : v;
    const updated = { ...resolvePrefs(listPrefsStore, 'files'), showAttachedNotes: next };
    onListPrefsChange(setPillarPrefs(listPrefsStore, 'files', updated));
  };
  const [sortOpen, setSortOpen] = useState(false);

  // Read sort from shared prefs. Map 'modified' → updatedAt, 'title' → name.
  const sortField = listPrefs.sortField;
  const sortDir = listPrefs.sortDir;
  /** Composite key for a file row: "noteId:uuid". Content-hash dedup
   *  means identical files across different notes share the same uuid,
   *  so bare uuid isn't unique in the list (#50). */
  const fileKey = (f: FileItem) => `${f.noteId}:${f.uuid}`;
  const fileKeyFromIds = (noteId: string, uuid: string) => `${noteId}:${uuid}`;

  /** Composite key of the file row that was right-clicked - highlighted
   *  while the context menu is open. */
  const [contextTargetId, setContextTargetId] = useState<string | null>(null);
  /** Composite key of the last-clicked file - only this file highlights,
   *  not all siblings from the same parent note (#67) or same-content
   *  files across notes (#50). */
  const [activeFileId, setActiveFileId] = useState<string | null>(null);

  // ── File-level selection (by composite key, not bare uuid) ──────
  // The parent's useMultiSelect tracks note IDs. Files view needs
  // per-file granularity so selecting one image from a two-image note
  // doesn't highlight both. We keep a local composite-key set for
  // visual state. The parent's selectedIds (noteIds), which is what the
  // bulk actions read, is re-derived from it on every change - see
  // applyFileSelection. Spec: ops/docs/ui-patterns.md section 61.
  const [selectedFileIds, setSelectedFileIds] = useState<Set<string>>(new Set());
  /** Anchor for shift-click range select - the last file toggled on its
   *  own. Mirrors `lastSelectedId` in useMultiSelect, in file-key space. */
  const [lastFileKey, setLastFileKey] = useState<string | null>(null);

  // Clear local file selection when parent clears (e.g. view switch).
  useEffect(() => {
    if (!selectionMode && selectedFileIds.size > 0) {
      setSelectedFileIds(new Set());
      setLastFileKey(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [selectionMode]);

  // Clear active file highlight when the editor navigates away from the
  // active file's parent note (e.g. user opened a different note).
  useEffect(() => {
    if (!activeFileId) return;
    const item = fileItems.find((f) => fileKey(f) === activeFileId);
    if (!item || item.noteId !== currentNoteId) {
      setActiveFileId(null);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [currentNoteId]);

  /** Commit a file-key selection and mirror it onto the parent's note-ID
   *  selection, which is what every bulk action actually reads. A note is
   *  selected iff at least one of its files is, so the parent set is
   *  re-derived from `next` and diffed both ways rather than patched.
   *
   *  Both halves run OUTSIDE any setState updater. The old version called
   *  `onToggleSelected` from inside the `setSelectedFileIds` updater, which
   *  is a parent setState during this component's render ("Cannot update a
   *  component (AuthenticatedView) while rendering a different component
   *  (FilesList)") - and because StrictMode invokes updaters twice, every
   *  note ID was toggled on and straight back off. The parent selection
   *  came back empty, selection mode never latched, and the whole Files
   *  multi-select did nothing. */
  function applyFileSelection(next: Set<string>, anchor: string | null) {
    setSelectedFileIds(next);
    setLastFileKey(anchor);
    const wanted = new Set(
      fileItems.filter((f) => next.has(fileKey(f))).map((f) => f.noteId)
    );
    for (const nid of wanted) if (!selectedIds.has(nid)) onToggleSelected(nid);
    for (const nid of selectedIds) if (!wanted.has(nid)) onToggleSelected(nid);
  }

  function toggleFileSelected(item: FileItem) {
    const key = fileKey(item);
    const next = new Set(selectedFileIds);
    if (next.has(key)) next.delete(key);
    else next.add(key);
    applyFileSelection(next, key);
  }

  /** Shift-click: add every row from the anchor to `item`, inclusive,
   *  additive. Same contract as rangeSelect in useMultiSelect, walked over
   *  the file list's own visible order instead of the note list's. Falls
   *  back to a plain toggle when there is no usable anchor. */
  function rangeSelectFiles(item: FileItem) {
    const key = fileKey(item);
    if (!lastFileKey || lastFileKey === key) {
      toggleFileSelected(item);
      return;
    }
    const keys = filtered.map((f) => fileKey(f));
    const a = keys.indexOf(lastFileKey);
    const b = keys.indexOf(key);
    if (a < 0 || b < 0) {
      toggleFileSelected(item);
      return;
    }
    const [from, to] = a < b ? [a, b] : [b, a];
    const next = new Set(selectedFileIds);
    for (let i = from; i <= to; i++) {
      const k = keys[i];
      if (k) next.add(k);
    }
    applyFileSelection(next, key);
  }

  function selectAllFiles() {
    const keys = filtered.map((f) => fileKey(f));
    applyFileSelection(new Set(keys), keys[keys.length - 1] ?? null);
  }

  function clearFileSelection() {
    setSelectedFileIds(new Set());
    setLastFileKey(null);
    onClearSelection();
  }

  // Long-press for file-level selection (mobile).
  const fileLongPressTimer = useRef<number | null>(null);
  function beginFileLongPress(item: FileItem) {
    cancelFileLongPress();
    fileLongPressTimer.current = window.setTimeout(() => {
      toggleFileSelected(item);
      fileLongPressTimer.current = null;
    }, 500);
  }
  function cancelFileLongPress() {
    if (fileLongPressTimer.current !== null) {
      window.clearTimeout(fileLongPressTimer.current);
      fileLongPressTimer.current = null;
    }
  }
  const sortBtnRef = useRef<HTMLButtonElement | null>(null);
  const listRef = useRef<HTMLDivElement>(null);

  // Clear the context-target highlight on any click (menu close, click elsewhere).
  useEffect(() => {
    if (!contextTargetId) return;
    const clear = () => setContextTargetId(null);
    window.addEventListener('click', clear, true);
    return () => window.removeEventListener('click', clear, true);
  }, [contextTargetId]);

  /** Small checkmark icon for active menu items. */
  const checkIcon = (
    <Check />
  );
  /** Empty spacer matching the checkmark width - keeps labels aligned. */
  const emptyIcon = <span style={{ width: 14 }} />;

  /** Build the per-file context menu with sort/filter/actions. */
  const buildFileMenu = useCallback((item: FileItem): ContextMenuItem[] => {
    const starred = isNoteStarred(item.noteId);
    const isSelected = selectedFileIds.has(fileKey(item));
    return [
      // ── Select / Deselect ────────────────────────────────────────
      {
        label: isSelected ? t('filesList.menuDeselect') : t('filesList.menuSelect'),
        icon: isSelected ? checkIcon : emptyIcon,
        onSelect: () => toggleFileSelected(item),
      },
      { type: 'separator' },
      // ── Filter ───────────────────────────────────────────────────
      { type: 'header', label: t('filesList.menuShow') },
      {
        label: t('filesList.menuAllFiles'),
        icon: filter === 'all' ? checkIcon : emptyIcon,
        onSelect: () => setFilter('all'),
      },
      {
        label: t('filesList.menuImages'),
        icon: filter === 'image' ? checkIcon : emptyIcon,
        onSelect: () => setFilter('image'),
      },
      {
        label: t('filesList.menuAudio'),
        icon: filter === 'audio' ? checkIcon : emptyIcon,
        onSelect: () => setFilter('audio'),
      },
      {
        label: t('filesList.menuDocuments'),
        icon: filter === 'document' ? checkIcon : emptyIcon,
        onSelect: () => setFilter('document'),
      },
      { type: 'separator' },
      {
        label: showNote ? t('filesList.menuHideNoteAttachments') : t('filesList.menuShowNoteAttachments'),
        icon: emptyIcon,
        onSelect: () => setShowNote((v) => !v),
      },
      { type: 'separator' },
      // ── Per-file actions ─────────────────────────────────────────
      {
        label: starred ? t('filesList.menuUnpin') : t('filesList.menuPin'),
        icon: iconPin(starred),
        onSelect: () => onToggleStar(item.noteId, !starred),
      },
      // Images carry no name a reader ever sees here, so there is nothing
      // to rename on one yet.
      ...(item.kind === 'attachment' && !item.locked
        ? [{
            label: t('filesList.menuRename'),
            icon: iconEditPencil(),
            onSelect: () => onRenameFile(item.noteId, item.uuid),
          }]
        : []),
      {
        label: t('filesList.menuMoveToTrash'),
        icon: iconTrash(),
        destructive: true,
        onSelect: () => onTrash(item.noteId),
      },
    ];
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [filter, showNote, selectedFileIds, isNoteStarred, onToggleStar, onTrash, onRenameFile]);

  /** Base items after the three list settings. All three hold on every
   *  tab: the type tabs pick which files are listed, not which settings
   *  apply. `standalone` marks a file that is its own note, so with the
   *  toggle off only files uploaded as files remain. */
  const visibleItems = useMemo(() => {
    let items = fileItems;
    if (!showNote) items = items.filter((f) => f.standalone);
    if (!listPrefs.showLocked) items = items.filter((f) => !f.locked);
    if (!listPrefs.showProtected) items = items.filter((f) => !f.pinProtected);
    return items;
  }, [fileItems, showNote, listPrefs.showLocked, listPrefs.showProtected]);

  const filtered = useMemo(() => {
    let items = visibleItems;
    if (filter !== 'all') {
      items = items.filter((f) => fileCategory(f) === filter);
    }
    // Apply search - match on file name or parent note title.
    const q = search.trim().toLowerCase();
    if (q) {
      items = items.filter(
        (f) =>
          f.name.toLowerCase().includes(q) ||
          f.noteTitle.toLowerCase().includes(q)
      );
    }
    // Sort - pinned files always float to top, then user's chosen sort within each group.
    const dir = sortDir === 'asc' ? 1 : -1;
    items = [...items].sort((a, b) => {
      if (a.starred !== b.starred) return a.starred ? -1 : 1;
      if (sortField === 'title') return dir * a.name.localeCompare(b.name);
      if (sortField === 'size') return dir * (a.size - b.size);
      if (sortField === 'created') return dir * (a.createdAt > b.createdAt ? 1 : a.createdAt < b.createdAt ? -1 : 0);
      // modified - by parent note updatedAt
      return dir * (a.updatedAt > b.updatedAt ? 1 : a.updatedAt < b.updatedAt ? -1 : 0);
    });
    return items;
  }, [visibleItems, filter, search, sortField, sortDir]);

  /* The two standing "here is why you see less" entries, shared with the
     other scoped pillars (ListFilterChips.tsx owns both). "Clear search"
     appears ONLY when the search found nothing: a search explains itself,
     because the text sits in the box the person just typed into, while an
     empty pane has nothing in it to explain the silence. The filter entry
     rides along there, so both possible causes are named, and otherwise
     stands beside results. Both step aside while files are selected, for the
     reason the import offer does elsewhere: neither is a selectable item. */
  const showSearchEntry = search.trim().length > 0 && filtered.length === 0;
  const showFilterEntry = (activeFolderName !== null || activeTag !== null) && selectedFileIds.size === 0;

  return (
    <div className="flex flex-col h-full">
      {/* ── Header bar - matches NotesList h-14 pattern ──────────── */}
      {selectedFileIds.size > 0 ? (
        <SelectionToolbar
          mode="normal"
          allStarred={selectionAllStarred}
          onClear={clearFileSelection}
          onFavorite={onBulkFavorite}
          onTag={onBulkTag}
          onMoveToFolder={onBulkMoveToFolder}
          foldersUnlocked={foldersUnlocked}
          onExport={onBulkExport}
          onDelete={onBulkTrash}
          onRestore={() => {}}
          onDeleteForever={() => {}}
          allTags={allTags}
        />
      ) : (
      <div className="shrink-0 h-14 px-4 border-b border-divider flex items-center justify-between gap-3">

        <ListNav
          hiddenViews={hiddenViews}
          view="files"
          onSelectView={onSelectView}
          onOpenDrawer={onOpenDrawer}
          title={t('filesList.title')}
          icon={<PILLAR_GLYPHS.files size={26} className="text-accent shrink-0" aria-hidden="true" />}
        />
        <button
          type="button"
          onClick={() => onUploadFiles()}
          tabIndex={mobileTabIndex}
          className="shrink-0 inline-flex items-center gap-1.5 rounded-md bg-accent/10 hover:bg-accent/20 text-accent font-semibold px-3 py-1.5 text-lg tracking-tight transition"
        >
          <Upload size={18} />
          {t('filesList.upload')}
        </button>
      </div>
      )}

      {/* Folder filter chip - same shared chip the notes list renders. */}
      <ListFilterChips
        folderName={activeFolderName}
        tag={activeTag}
        onClearFolder={onClearFolder}
        onClearTag={onClearTag}
      />

      {/* ── Selection count strip ──────────────────────────────── */}
      {selectedFileIds.size > 0 && (
        <div className="shrink-0 px-4 py-2 border-b border-divider bg-accent/5 dark:bg-accent/10 flex items-center justify-between gap-2 text-[13px]">
          <span className="font-medium text-neutral-700 dark:text-neutral-200 tabular-nums">
            {t('filesList.selectedOf', { selected: selectedFileIds.size, total: filtered.length })}
          </span>
          {filtered.length > 0 && (
            <button
              onClick={selectedFileIds.size >= filtered.length ? clearFileSelection : selectAllFiles}
              className="font-semibold text-accent hover:underline"
            >
              {selectedFileIds.size >= filtered.length ? t('filesList.deselectAll') : t('filesList.selectAll')}
            </button>
          )}
        </div>
      )}

      {/* ── Storage bar ──────────────────────────────────────────── */}
      {quotaMaxBytes > 0 && (
        <StorageBar
          label={t('filesList.storage')}
          usedBytes={quotaUsedBytes}
          maxBytes={quotaMaxBytes}
          onRefresh={onRefreshStorage}
        />
      )}

      {/* ── Supported types hint (Pro) / Free-vs-Pro upsell (free) ── */}
      <div className="shrink-0 px-4 pb-1">
        {!isPro ? (
          <ProUpsell onUpgrade={onOpenUpgrade} />
        ) : !hasStorageSub && isStorageConfigured() ? (
          <StorageUpsell onManage={onManageStorage} currentMaxBytes={quotaMaxBytes} />
        ) : (
          <p className="text-[11px] text-neutral-600 dark:text-neutral-300 leading-relaxed">
            {t('filesList.supportedTypesHint', { max: hasStorageSub ? '100' : '50' })}
          </p>
        )}
      </div>

      {/* ── Type filter tabs ─────────────────────────────────────── */}
      <div className="shrink-0 px-3 pt-2 pb-1 flex gap-1.5">
        {([
          { key: 'all' as FileType, label: t('filesList.filterAll') },
          { key: 'image' as FileType, label: t('filesList.filterImages') },
          { key: 'audio' as FileType, label: t('filesList.filterAudio') },
          { key: 'document' as FileType, label: t('filesList.filterFiles') },
        ] as const).map(({ key, label }) => (
          <button
            key={key}
            type="button"
            onClick={() => setFilter(key)}
            tabIndex={mobileTabIndex}
            className={`text-xs px-2.5 py-1 rounded-full transition font-medium ${
              filter === key
                ? 'bg-accent text-white'
                : 'bg-surface-1 text-neutral-600 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-surface-2'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Search row + sort button - matches NotesList layout ───── */}
      <div className="shrink-0 p-3 border-b border-divider relative">
        <div className="flex items-stretch gap-2">
          <HoverLabel label={t('filesList.sortOptions')} position="above-start">
          <button
            ref={sortBtnRef}
            type="button"
            onClick={() => setSortOpen((v) => !v)}
            tabIndex={mobileTabIndex}
            aria-label={t('filesList.sortOptions')}
            aria-expanded={sortOpen}
            className={`shrink-0 inline-flex items-center justify-center w-10 h-10 rounded-md border transition ${
              sortOpen
                ? 'bg-accent/10 border-accent text-accent'
                : 'bg-surface-2 border-divider text-neutral-600 hover:border-accent hover:text-accent dark:text-neutral-300'
            }`}
          >
            <FunnelSimple size={18} />
          </button>
          </HoverLabel>
          <ListSearchInput
            inputRef={searchInputRef}
            tabIndex={mobileTabIndex}
            value={search}
            onChange={setSearch}
            placeholder={t('filesList.searchPlaceholder')}
          />
        </div>
        {sortOpen && (
          <ListPrefsPopover
            store={listPrefsStore}
            onChange={onListPrefsChange}
            onClose={() => setSortOpen(false)}
            anchorRef={sortBtnRef}
            className="absolute start-3 top-full mt-1"
            titleLabel={t('filesList.sortName')}
            pillar="files"
          />
        )}
      </div>

      {/* ── Attachment toggle - inline like Trash's auto-delete ──── */}
      <div className="shrink-0 px-4 py-2 border-b border-divider">
        <label className="flex items-center justify-between gap-2 cursor-pointer select-none">
          <span className="text-xs text-neutral-600 dark:text-neutral-400">{t('filesList.showNotesWithAttachments')}</span>
          <button
            type="button"
            role="switch"
            aria-checked={showNote}
            onClick={() => setShowNote((v) => !v)}
            className={`relative inline-flex h-5 w-9 shrink-0 items-center rounded-full transition ${
              showNote ? 'bg-accent' : 'bg-neutral-300 dark:bg-neutral-700'
            }`}
          >
            <span className={`inline-block h-4 w-4 transform rounded-full bg-white transition ${
              showNote ? 'translate-x-4 rtl:-translate-x-4' : 'translate-x-0.5 rtl:-translate-x-0.5'
            }`} />
          </button>
        </label>
      </div>

      {/* ── File list ─────────────────────────────────────────────── */}
      <div ref={listRef} className="flex-1 overflow-y-auto" onMouseDown={suppressShiftTextSelection}>
        {filtered.length === 0 && !search.trim() && (activeFolderName !== null || activeTag !== null) ? (
          /* Filtered down to nothing. The empty state below invites the user
             to upload their first file, which is wrong and alarming for
             someone who has files that a filter is hiding. */
          <FilteredEmpty
            folderName={activeFolderName}
            tag={activeTag}
            onClearFolder={onClearFolder}
            onClearTag={onClearTag}
          />
        ) : filtered.length === 0 ? (
          <div className="flex flex-col items-center justify-center h-full text-center px-6 py-12">
            <div className="w-16 h-16 rounded-full bg-neutral-100 dark:bg-neutral-800 flex items-center justify-center mb-4">
              <Folder size={28} className="text-neutral-400 dark:text-neutral-600" />
            </div>
            <p className="text-sm font-medium text-neutral-600 dark:text-neutral-300 mb-1">
              {search.trim()
                ? t('filesList.noMatches')
                : filter === 'all'
                  ? t('filesList.noFilesYet')
                  : filter === 'document' ? t('filesList.noDocuments') : filter === 'image' ? t('filesList.noImages') : t('filesList.noAudioFiles')}
            </p>
            {!search.trim() && (
              <>
                <p className="text-xs text-neutral-400 dark:text-neutral-600 max-w-[220px] mb-4">
                  {/* States the real cap, so it follows proUnlocked (the demo
                      uploads at the Pro limit). The free-vs-Pro table above
                      is the upsell and stays keyed off isPro. */}
                  {t('filesList.emptyTypesHint', { max: proUnlocked(isPro) ? (hasStorageSub ? '100' : '50') : '5' })}
                </p>
                <button
                  type="button"
                  onClick={() => onUploadFiles()}
                  className="text-xs font-medium text-white bg-accent hover:bg-accent-hover px-4 py-1.5 rounded-md transition"
                >
                  {t('filesList.uploadFiles')}
                </button>
              </>
            )}
            {/* Tile shape in both layouts: an empty pane draws no list and no
                grid, so the entry has to be a card that stands on its own. */}
            {showSearchEntry && (
              <div className="mt-4 flex flex-wrap items-stretch justify-center gap-2">
                <ActiveSearchEntry
                  search={search}
                  onClearSearch={() => setSearch('')}
                  variant="tile"
                  as="div"
                />
                <ActiveFilterEntry
                  folderName={activeFolderName}
                  tag={activeTag}
                  onClearFolder={onClearFolder}
                  onClearTag={onClearTag}
                  variant="tile"
                  as="div"
                />
              </div>
            )}
          </div>
        ) : (
          <div
            className={
              viewMode === 'grid'
                ? 'grid gap-3 p-4 pn-notes-grid'
                : ''
            }
          >
            {filtered.map((item, idx) => {
              const fk = fileKey(item);
              const isSelected = selectedFileIds.has(fk);
              const isOpen = activeFileId === fk;
              // React key must be unique per row. fileKey (noteId:uuid) is NOT
              // unique when the same content is embedded more than once in one
              // note - content-hash dedup gives identical files a shared uuid
              // (#50), so two copies collide on noteId:uuid. Duplicate keys
              // corrupt list reconciliation and strand stale rows when the type
              // filter changes (#92). Suffix the array index to guarantee
              // uniqueness; fk still drives selection/highlight state.
              const rowKey = `${fk}::${idx}`;
              // Image thumbnails only in grid mode; list view keeps the
              // compact icon row (previews were too heavy/odd inline).
              const isImageBg = item.kind === 'image' && viewMode === 'grid';
              // Preview / meta / tags are identical in both layouts, only their
              // ORDER differs: the grid keeps tags above the meta row so the date
              // can pin to the tile bottom (margin-top:auto), the list puts tags
              // last to match NoteRow.
              const previewEl = listPrefs.showPreview && (
                <div className="text-[13px] text-neutral-500 dark:text-neutral-400 truncate mt-0.5">
                  {/* Type word only for a standalone file. Size belongs on the
                      meta line for both row kinds: appending it here would put
                      a standalone row's size and a note-attached row's size in
                      two different places. */}
                  {item.standalone ? mimeToLabel(item.mime) : item.noteTitle}
                </div>
              );
              // TagChips rather than a local copy of the same markup: it also
              // owns the folder chip, so a file row cannot drift from a note row.
              const tagsEl = listPrefs.showTags && (
                <TagChips tags={item.tags} folderId={item.folderId} />
              );
              // Meta line (Concept D): date, then the status icons beside it -
              // keeps them off the title row so narrow tiles never crowd, and
              // anchored to the date rather than the right edge so widening
              // the pane doesn't strand them (same rule as NoteRow).
              // Every list row, standalone or note-attached: one list must not
              // show its sizes in two places, and the preview line carries
              // none. Grid stays out: its tiles carry their own badge beside
              // the content column, where it costs no title width.
              const showRowSize = viewMode !== 'grid' && item.size > 0;
              // Same amber chip as the attachment card's meta line (#151):
              // the blob is kept local because it does not fit the quota.
              const localOnly = quotaBlockedUuids.has(item.uuid);
              const metaEl = (listPrefs.showDate || showRowSize || localOnly || (item.starred && selectedFileIds.size === 0) || item.pinProtected || item.locked) && (
                <div className="pn-card-meta flex items-center gap-1.5 mt-0.5">
                  {listPrefs.showDate && (
                    <span className="pn-card-date min-w-0 text-[12px] text-neutral-400 dark:text-neutral-600 whitespace-nowrap overflow-hidden text-ellipsis">
                      {t('noteRow.modified', { ns: 'notes' })} {formatModifiedShort(item.updatedAt)}
                    </span>
                  )}
                  <span className="pn-card-status shrink-0 flex items-center gap-1.5 text-accent">
                    {item.starred && selectedFileIds.size === 0 && (
                      <PushPin size={12} />
                    )}
                    {item.pinProtected && (
                      <Shield size={12} aria-label={t('filesList.pinProtected')} />
                    )}
                    {item.locked && (
                      <PencilSimpleSlash size={12} aria-label={t('filesList.readOnly')} />
                    )}
                    {/* Icon-only, like the status icons beside it - the WHY
                        lives on the attachment card's amber line (#151). */}
                    {localOnly && (
                      <CloudSlash size={12} className="text-amber-600 dark:text-amber-400" aria-label={t('attachment.localOnly', { ns: 'media' })} />
                    )}
                  </span>
                  {/* Anchored to the date, like the status icons beside it and
                      like NoteRow - not `ms-auto`. Off the title row because a
                      narrow pane made the badge truncate the filename, which is
                      the one thing the row exists to show; off the right edge
                      because section 66 of ui-patterns.md is exactly about a
                      value stranded there when the pane widens. */}
                  {showRowSize && (
                    <span className="shrink-0 text-[11px] text-neutral-400 dark:text-neutral-500 font-medium tabular-nums">
                      {formatBytes(item.size)}
                    </span>
                  )}
                </div>
              );
              const selectBox = (
                <span
                  role="checkbox"
                  aria-checked={isSelected}
                  onClick={(e) => {
                    e.stopPropagation();
                    if (e.shiftKey) rangeSelectFiles(item);
                    else toggleFileSelected(item);
                  }}
                  className={`shrink-0 w-5 h-5 rounded border-2 flex items-center justify-center cursor-pointer transition ${
                    viewMode === 'grid' ? 'mt-0.5' : ''
                  } ${
                    isSelected
                      ? 'bg-accent border-accent text-white'
                      : 'border-neutral-300 dark:border-neutral-600'
                  }`}
                >
                  {isSelected && (
                    <Check size={12} />
                  )}
                </span>
              );
              return (
                <button
                  key={rowKey}
                  type="button"
                  onClick={(e) => {
                    // Same gesture set as the notes list (handleRowClick in
                    // useMultiSelect): shift extends the live selection,
                    // Cmd/Ctrl toggles one and enters selection mode, a plain
                    // click toggles while a selection is live and otherwise
                    // opens the file.
                    if (e.shiftKey && selectedFileIds.size > 0) {
                      rangeSelectFiles(item);
                    } else if (selectedFileIds.size > 0 || e.metaKey || e.ctrlKey) {
                      toggleFileSelected(item);
                    } else {
                      setActiveFileId(fk);
                      onOpenNote(item.noteId, item.uuid);
                    }
                  }}
                  onContextMenu={(e) => {
                    setContextTargetId(fk);
                    onContextMenu(e, buildFileMenu(item));
                  }}
                  onTouchStart={() => beginFileLongPress(item)}
                  onTouchEnd={cancelFileLongPress}
                  onTouchMove={cancelFileLongPress}
                  onTouchCancel={cancelFileLongPress}
                  tabIndex={mobileTabIndex}
                  className={
                    isImageBg
                      ? `${viewMode === 'grid' ? 'pn-lazy-card' : 'pn-lazy-row'} relative overflow-hidden text-start border transition group ${
                          viewMode === 'grid' ? 'rounded-xl min-h-[132px]' : 'w-full border-x-0 border-t-0 min-h-[64px]'
                        } ${
                          isSelected
                            ? 'border-accent ring-2 ring-accent z-[1]'
                            : isOpen
                              ? 'border-accent ring-2 ring-accent/50 z-[1]'
                              : contextTargetId === fk
                                ? 'border-accent/70'
                                : 'border-divider hover:border-accent/60'
                        }`
                      : viewMode === 'grid'
                        ? `pn-card pn-lazy-card text-start p-3 rounded-xl border transition flex items-start gap-2.5 group ${
                            isSelected
                              ? 'bg-accent/15 border-accent dark:bg-accent/20'
                              : isOpen
                                ? 'bg-accent/10 border-accent dark:bg-accent/15'
                                : contextTargetId === fk
                                  ? 'bg-neutral-200/70 border-divider dark:bg-neutral-800/70'
                                  : 'bg-surface-2 border-divider hover:border-accent/60 dark:hover:bg-neutral-900/40'
                          }`
                        : `pn-lazy-row w-full text-start px-4 py-3 transition group border-b border-divider/50 ${
                            isSelected
                              ? 'bg-accent/15 hover:bg-accent/20 border-s-2 border-s-accent dark:bg-accent/20 dark:hover:bg-accent/25'
                              : isOpen
                                ? 'bg-accent/10 hover:bg-accent/15 border-s-2 border-s-accent dark:bg-accent/15 dark:hover:bg-accent/20'
                                : contextTargetId === fk
                                  ? 'bg-neutral-200/70 hover:bg-neutral-200/80 dark:bg-neutral-800/70 dark:hover:bg-neutral-800/80'
                                  : 'hover:bg-neutral-200/50 dark:hover:bg-neutral-900/50'
                          }`
                  }
                >
                  {isImageBg ? (
                    <>
                      <FileTileImageBg uuid={item.uuid} />
                      <div className={`absolute inset-0 pointer-events-none ${viewMode === 'grid' ? 'bg-gradient-to-t from-black/85 via-black/30 to-black/10' : 'bg-gradient-to-r from-black/80 via-black/55 to-black/25'}`} />
                      <div className={`absolute ${viewMode === 'grid' ? 'inset-x-0 bottom-0 p-2.5' : 'inset-0 px-4 py-2.5 flex flex-col justify-center'}`}>
                        <div className="text-[13px] font-semibold text-white truncate flex items-center gap-1.5">
                          {item.starred && selectedFileIds.size === 0 && <PushPin size={11} className="shrink-0" />}
                          {item.pinProtected && <Shield size={11} className="shrink-0" aria-label={t('filesList.pinProtected')} />}
                          {item.locked && <PencilSimpleSlash size={11} className="shrink-0" aria-label={t('filesList.readOnly')} />}
                          {localOnly && <CloudSlash size={11} className="shrink-0 text-amber-400" aria-label={t('attachment.localOnly', { ns: 'media' })} />}
                          <span className="truncate" dir="auto">{item.name}</span>
                        </div>
                        <div className="flex items-center justify-between gap-2 mt-0.5">
                          <span className="text-[11px] text-white/85 truncate">{item.standalone ? getFileTypeLabel(item) : item.noteTitle}</span>
                          {item.size > 0 && <span className="text-[11px] text-white/85 shrink-0">{formatBytes(item.size)}</span>}
                        </div>
                      </div>
                      {selectedFileIds.size > 0 && (
                        <span
                          role="checkbox"
                          aria-checked={isSelected}
                          onClick={(e) => {
                            e.stopPropagation();
                            if (e.shiftKey) rangeSelectFiles(item);
                            else toggleFileSelected(item);
                          }}
                          className={`absolute start-2 top-2 z-10 w-5 h-5 rounded border-2 flex items-center justify-center cursor-pointer transition ${
                            isSelected ? 'bg-accent border-accent text-white' : 'border-white/80 bg-black/30'
                          }`}
                        >
                          {isSelected && <Check size={12} />}
                        </span>
                      )}
                    </>
                  ) : viewMode === 'list' ? (
                  /* List rows mirror NoteRow: icon + name + size on the title
                     line, then preview / meta / tags spanning the FULL row
                     width. Nesting them beside the icon (as the grid tile does)
                     cost ~90px of text width per line, so previews and dates
                     truncated far earlier here than in the notes list. */
                  <>
                    <div className="flex items-center gap-2.5">
                      {selectedFileIds.size > 0 ? selectBox : <FileTileIcon mime={item.mime} />}
                      <div className="min-w-0 flex-1 text-sm font-semibold truncate text-neutral-900 dark:text-white" dir="auto">
                        {item.name}
                      </div>
                    </div>
                    {previewEl}
                    {metaEl}
                    {tagsEl}
                  </>
                  ) : (
                  <>
                  {selectedFileIds.size > 0 ? selectBox : (
                    <FileTileIcon mime={item.mime} className="pn-card-icbox" />
                  )}
                  {/* flex-col + self-stretch lets the meta row's margin-top:auto
                      (grid only, see index.css) pin the date to the tile bottom. */}
                  <div className="min-w-0 flex-1 flex flex-col self-stretch">
                    <div className="pn-card-title text-sm font-semibold truncate flex items-center gap-1.5 text-neutral-900 dark:text-white">
                      <CardGlyph type="file" />
                      <span className="pn-card-titletext truncate" dir="auto">{item.name}</span>
                    </div>
                    {previewEl}
                    {/* Tags sit above the meta row so the date can pin to the
                        tile bottom (margin-top:auto). */}
                    {tagsEl}
                    {metaEl}
                  </div>
                  {item.size > 0 && !item.standalone && (
                    <span className="pn-file-size shrink-0 text-[11px] text-neutral-400 dark:text-neutral-500 font-medium mt-0.5">{formatBytes(item.size)}</span>
                  )}
                  </>
                  )}
                </button>
              );
            })}
            {/* The standing "a filter is on" entry, shared with the other
                scoped pillars (ListFilterChips.tsx owns it). `FilteredEmpty`
                above answers the empty case; this one answers the quiet one,
                where the pane still has rows and a short list reads as every
                file there is. A `div` rather than the `li` the other pillars
                pass: this pane's rows are buttons in a plain container.
                Left out while files are selected, for the reason the import
                offer is elsewhere: it is not a selectable item. */}
            {showFilterEntry && (
              <ActiveFilterEntry
                folderName={activeFolderName}
                tag={activeTag}
                onClearFolder={onClearFolder}
                onClearTag={onClearTag}
                variant={viewMode === 'grid' ? 'tile' : 'row'}
                as="div"
              />
            )}
          </div>
        )}
      </div>
    </div>
  );
}
