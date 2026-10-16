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
import { editedAtOf, mimeToLabel } from './notesViewUtils';
import { formatInstant, useDateFormatKey } from './intlFormat';
import { CardGlyph, FileTileIcon, TagChips } from './NoteRow';
import { ItemFlags, ItemRow, ItemTile, applyCompactRows, type ItemFlag, type ItemRootProps, type ItemState, type ListItem } from './listItem';
import { noteLookStyle, useNoteLook } from './looks/LookGlyph';
import { itemGridClass, routeItemClick, useContextTarget, useItemList } from './itemList';
import { useCompactRows } from './viewMode';
import { iconPin, iconTrash, iconEditPencil, Check, Folder, LinkSimple, Upload, FunnelSimple, Files, PILLAR_GLYPHS } from './icons';
import { NewButton } from './NewButton';
import { HoverLabel } from './HoverLabel';
import { SelectionToolbar } from './SelectionToolbar';
import { suppressShiftTextSelection } from './useMultiSelect';
import { ListSearchInput } from './ListSearchInput';
import { Switch } from './Switch';
import { ActiveFilterEntry, ActiveSearchEntry, FilteredEmpty, ListFilterChips } from './ListFilterChips';
import type { View } from './views';
import { ListNav } from './notesView/ListNav';
import { ListPrefsPopover } from './ListPrefsPopover';
import { IconUpgrade } from './UpgradeModal';
import { proUnlocked } from './demo';
import { LazyPdfCover, LazyPicture } from './LazyPicture';
import { isMail, isPdf, isPictureMime, openMediaViewer, type MediaRef } from './mediaRefs';
import { useQuotaBlockedUuids } from './usePendingUploads';
import { unescapeMarkdownText } from './fileNames';
import { textMatcher } from './textMatch';
import { setItemDragImage, writeItemDrag } from './itemDrag';
import { isShortcutId } from './noteShortcut';

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
  /** The parent note's "last edited" date */
  editedAt: string;
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
        editedAt: editedAtOf(note),
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
        editedAt: editedAtOf(note),
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
  // Sort by the parent note's last edit, newest first
  items.sort((a, b) => (a.editedAt > b.editedAt ? -1 : a.editedAt < b.editedAt ? 1 : 0));
  return items;
}

/**
 * The Files rows of notes the PIN guards right now: one per note, named by the
 * note's title and carrying nothing its body says about the files in it - no
 * file name, size, type or picture, and no count of them. The title stays
 * visible here as it does in every other list, and a click opens the gate.
 * Tested in tests/lockGateLists.test.ts.
 */
function listedWhileGated(items: FileItem[], gated: ReadonlySet<string>): FileItem[] {
  if (gated.size === 0) return items;
  const seen = new Set<string>();
  const out: FileItem[] = [];
  for (const item of items) {
    if (!gated.has(item.noteId)) out.push(item);
    else if (!seen.has(item.noteId)) {
      seen.add(item.noteId);
      out.push({ ...item, kind: 'attachment', name: item.noteTitle, mime: '', size: 0, sizeLabel: '' });
    }
  }
  return out;
}

/** A picture the grid can draw and the viewer can show. */
export function isPictureFileItem(item: FileItem): boolean {
  return item.kind === 'image' || isPictureMime(item.mime);
}

/** A stored PDF: the grid draws its first page, and the viewer reads it. */
function isPdfFileItem(item: FileItem): boolean {
  return item.kind === 'attachment' && isPdf(item.mime, item.name);
}

/** A file whose grid tile shows the file itself: a picture or a PDF's first page. */
function hasCoverFileItem(item: FileItem): boolean {
  return isPictureFileItem(item) || isPdfFileItem(item);
}

/** Anything the viewer can open: a picture, a PDF or a saved email. */
function isViewableFileItem(item: FileItem): boolean {
  return hasCoverFileItem(item) || (item.kind === 'attachment' && isMail(item.mime, item.name));
}

/** The reference a note stores for this file. */
/**
 * The note ids a drag of `item` carries, or none when it does not drag. Only
 * a standalone file drags; in selection mode only a selected one, and it
 * carries every selected standalone file in `shown`.
 */
export function fileDragIds(
  item: FileItem,
  shown: readonly FileItem[],
  isSelected: (f: FileItem) => boolean,
  selecting: boolean,
): string[] {
  if (!item.standalone) return [];
  if (!selecting) return [item.noteId];
  if (!isSelected(item)) return [];
  return [...new Set(shown.filter((f) => f.standalone && isSelected(f)).map((f) => f.noteId))];
}

export function fileItemMediaRef(item: FileItem): MediaRef {
  return item.kind === 'image'
    ? { src: `pn:img/${item.uuid}`, name: item.name, mime: '' }
    : { src: `pn:file/${item.uuid}`, name: item.name, mime: item.mime };
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
  /** Copy the shortcut to a standalone file item. */
  onCopyShortcut: (noteId: string) => void;
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
  selectionAllArchived: boolean;
  onRowClick: (e: React.MouseEvent, noteId: string) => void;
  onToggleSelected: (id: string) => void;
  onRangeSelect: (id: string) => void;
  onLongPressStart: (id: string) => void;
  onLongPressEnd: () => void;
  onClearSelection: () => void;
  onDeselectAll: () => void;
  onSelectAllVisible: () => void;
  onBulkFavorite: () => void;
  onBulkArchive: () => void;
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
  /** Notes the PIN still guards. Their files open the note's gate, never the
   *  viewer, never join the viewer's list, draw no picture on a grid tile,
   *  and list as one row named by the note's title (listedWhileGated) - the
   *  rule the note list applies to a guarded note's preview. */
  gatedNoteIds: () => Set<string>;
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
          <span className="text-pn-muted">{r.label}</span>
          <span className="inline-flex items-center gap-1.5 whitespace-nowrap">
            <span className="text-pn-muted">
              {r.free} MB <span className="text-[9px] uppercase tracking-wide">{t('filesList.free')}</span>
            </span>
            <span className="text-pn-muted" aria-hidden="true">{'→'}</span>
            <span className="text-accent font-medium">
              {r.pro} MB <span className="text-[9px] uppercase tracking-wide">Pro</span>
            </span>
          </span>
        </div>
      ))}
      <button
        type="button"
        onClick={onUpgrade}
        className="mt-2 w-full inline-flex items-center justify-center gap-1.5 rounded-md bg-accent/10 hover:bg-accent/20 text-accent-strong font-medium text-xs px-3 py-2 transition"
      >
        <IconUpgrade size={12} /> {t('filesList.upgradeToPro')}
      </button>
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
  onCopyShortcut,
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
  selectionAllArchived,
  onRowClick,
  onToggleSelected,
  onRangeSelect,
  onLongPressStart,
  onLongPressEnd,
  onClearSelection,
  onDeselectAll,
  onSelectAllVisible,
  onBulkFavorite,
  onBulkArchive,
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
  gatedNoteIds,
}: FilesListProps) {
  const { t } = useTranslation(['shell', 'notes', 'media']);
  // The rows format their dates inline: a new date setting renders them again.
  useDateFormatKey();
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

  // Read sort from shared prefs. Map 'modified' → editedAt, 'title' → name.
  const sortField = listPrefs.sortField;
  const sortDir = listPrefs.sortDir;
  /** Composite key for a file row: "noteId:uuid". Content-hash dedup
   *  means identical files across different notes share the same uuid,
   *  so bare uuid isn't unique in the list (#50). */
  const fileKey = (f: FileItem) => `${f.noteId}:${f.uuid}`;
  const fileKeyFromIds = (noteId: string, uuid: string) => `${noteId}:${uuid}`;

  /** Composite key of the file row that was right-clicked - highlighted
   *  while the context menu is open. */
  const [contextTargetId, setContextTargetId] = useContextTarget();
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
      // A file inside a note is part of that note, which has its own row.
      ...(item.standalone && isShortcutId(item.noteId)
        ? [{
            label: t('shell:shortcut.copyItem'),
            icon: <LinkSimple size={14} aria-hidden="true" />,
            onSelect: () => onCopyShortcut(item.noteId),
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
  }, [filter, showNote, selectedFileIds, isNoteStarred, onToggleStar, onTrash, onRenameFile, onCopyShortcut]);

  /** Notes the PIN guards right now, and a key that changes when they do. */
  const gatedNow = gatedNoteIds();
  const gatedKey = [...gatedNow].sort().join(' ');
  /** Base items after the gate and the three list settings. All three hold
   *  on every tab: the type tabs pick which files are listed, not which
   *  settings apply. `standalone` marks a file that is its own note, so with
   *  the toggle off only files uploaded as files remain. */
  const visibleItems = useMemo(() => {
    let items = listedWhileGated(fileItems, gatedNow);
    if (!showNote) items = items.filter((f) => f.standalone);
    if (!listPrefs.showLocked) items = items.filter((f) => !f.locked);
    if (!listPrefs.showProtected) items = items.filter((f) => !f.pinProtected);
    return items;
  // gatedKey stands in for gatedNow, which is a fresh Set on every render.
  // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [fileItems, gatedKey, showNote, listPrefs.showLocked, listPrefs.showProtected]);

  const filtered = useMemo(() => {
    let items = visibleItems;
    if (filter !== 'all') {
      items = items.filter((f) => fileCategory(f) === filter);
    }
    // Apply search - match on file name or parent note title.
    const q = search.trim();
    if (q) {
      const match = textMatcher(q);
      items = items.filter((f) => match(f.name) || match(f.noteTitle));
    }
    // Sort - pinned files always float to top, then user's chosen sort within each group.
    const dir = sortDir === 'asc' ? 1 : -1;
    items = [...items].sort((a, b) => {
      if (a.starred !== b.starred) return a.starred ? -1 : 1;
      if (sortField === 'title') return dir * a.name.localeCompare(b.name);
      if (sortField === 'size') return dir * (a.size - b.size);
      if (sortField === 'created') return dir * (a.createdAt > b.createdAt ? 1 : a.createdAt < b.createdAt ? -1 : 0);
      // modified - by the parent note's last edit
      return dir * (a.editedAt > b.editedAt ? 1 : a.editedAt < b.editedAt ? -1 : 0);
    });
    return items;
  }, [visibleItems, filter, search, sortField, sortDir]);
  // The files arrive in slices of 200; a different list - a new type filter,
  // search, folder or tag - starts at its top.
  const list = useItemList([filter, search, activeFolderName, activeTag, showNote], filtered.length);
  const compactRows = useCompactRows();

  /**
   * A standalone file drags its note onto a sidebar folder or tag: the file
   * IS that note. A picture or attachment inside a note does not drag, since
   * the drop would move or tag the whole host note. In selection mode a
   * selected standalone file drags every selected standalone file the list
   * shows. Ids only, so a drop into an editor makes nothing.
   * Spec: ops/docs/plans/drag-to-folder-and-tag.md (section 13)
   */
  const fileDragProps = (item: FileItem) => {
    const ids = () => fileDragIds(item, filtered, (f) => selectedFileIds.has(fileKey(f)), selectedFileIds.size > 0);
    if (ids().length === 0) return {};
    return {
      draggable: true,
      'data-file-drag': '',
      onDragStart: (e: React.DragEvent<HTMLElement>) => {
        const carried = ids();
        writeItemDrag(e.dataTransfer, carried, '');
        setItemDragImage(e.dataTransfer, e.currentTarget, carried.length);
      },
    };
  };

  /* The two standing "here is why you see less" entries, shared with the
     other scoped pillars (ListFilterChips.tsx owns both). "Clear search"
     appears ONLY when the search found nothing: a search explains itself,
     because the text sits in the box the person just typed into, while an
     empty pane has nothing in it to explain the silence. The filter entry
     rides along there, so both possible causes are named, and otherwise
     stands beside results. Both step aside while files are selected, for the
     reason the import offer does elsewhere: neither is a selectable item. */
  const showSearchEntry = search.trim().length > 0 && filtered.length === 0;
  // Held back until the revealed slice covers the whole list, so a long
  // filtered list never draws it mid-scroll and then pushes it down again.
  const showFilterEntry =
    (activeFolderName !== null || activeTag !== null) && selectedFileIds.size === 0 && list.reveal.visible >= filtered.length;

  /**
   * A click on a picture or a PDF opens its note, as every file click does,
   * and the viewer over it. The viewer moves through this list as it stands,
   * sorted, filtered and searched, and on close the pane follows it to the
   * note of the file that was on screen. A file in a note the PIN still
   * guards opens the gate instead, and never joins the list.
   * Spec: ops/docs/ui-patterns.md (section 98, the picture viewer)
   */
  function openViewerAt(item: FileItem) {
    if (!isViewableFileItem(item)) return;
    const gated = gatedNoteIds();
    if (gated.has(item.noteId)) return;
    const shown = filtered.filter((f) => isViewableFileItem(f) && !gated.has(f.noteId));
    const index = shown.indexOf(item);
    if (index < 0) return;
    const startKey = fileKey(item);
    openMediaViewer({
      items: shown.map(fileItemMediaRef),
      index,
      onClose: (last) => {
        const landed = shown[last];
        if (!landed || fileKey(landed) === startKey) return;
        setActiveFileId(fileKey(landed));
        onOpenNote(landed.noteId, landed.uuid);
      },
    });
  }

  return (
    <div className="flex flex-col h-full">
      {/* ── Header bar - matches NotesList h-14 pattern ──────────── */}
      {selectedFileIds.size > 0 ? (
        <SelectionToolbar
          mode="normal"
          allStarred={selectionAllStarred}
          allArchived={selectionAllArchived}
          onClear={clearFileSelection}
          onFavorite={onBulkFavorite}
          onArchive={onBulkArchive}
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
      <div className="shrink-0 h-11 md:h-14 px-4 border-b border-divider flex items-center justify-between gap-3">

        <ListNav
          hiddenViews={hiddenViews}
          view="files"
          onSelectView={onSelectView}
          onOpenDrawer={onOpenDrawer}
          title={t('filesList.title')}
          icon={<PILLAR_GLYPHS.files size={26} className="text-accent shrink-0" aria-hidden="true" />}
        />
        <NewButton
          onClick={() => onUploadFiles()}
          tabIndex={mobileTabIndex}
          label={t('filesList.upload')}
        />
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
          <span className="font-medium text-pn-soft tabular-nums">
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

      {/* ── Storage bar: one line that opens Settings > Storage; the
          Free-vs-Pro comparison stays below it for a free account. The
          add-ons live in Settings only, where somebody goes to look. ── */}
      {quotaMaxBytes > 0 && (
        <StorageBar
          label={t('filesList.storage')}
          usedBytes={quotaUsedBytes}
          maxBytes={quotaMaxBytes}
          onRefresh={onRefreshStorage}
          onOpen={onManageStorage}
        />
      )}
      {!isPro && (
        <div className="shrink-0 px-4 pb-1">
          <ProUpsell onUpgrade={onOpenUpgrade} />
        </div>
      )}

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
                ? 'bg-accent-fill text-white'
                : 'bg-surface-1 text-pn-muted hover:bg-pn/10'
            }`}
          >
            {label}
          </button>
        ))}
      </div>

      {/* ── Search row + sort button - matches NotesList layout ───── */}
      <div className="shrink-0 px-3 py-2 md:p-3 border-b border-divider relative">
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
                ? 'bg-accent/10 border-accent text-accent-strong'
                : 'bg-surface-2 border-divider text-pn-soft hover:border-accent hover:text-accent'
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
            showSizeToggle
          />
        )}
      </div>

      {/* ── Attachment toggle - inline like Trash's auto-delete ──── */}
      <div className="shrink-0 px-4 py-2 border-b border-divider">
        <Switch
          label={t('filesList.showNotesWithAttachments')}
          checked={showNote}
          onChange={setShowNote}
          className="gap-2 select-none"
          labelClassName="text-xs text-pn-muted"
        />
      </div>

      {/* ── File list ─────────────────────────────────────────────── */}
      <div
        ref={list.ref as React.RefObject<HTMLDivElement>}
        onScroll={(e) => list.onScroll(e.currentTarget)}
        className="flex-1 overflow-y-auto"
        onMouseDown={suppressShiftTextSelection}
      >
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
            <div className="w-16 h-16 rounded-full bg-track flex items-center justify-center mb-4">
              <Folder size={28} className="text-pn-muted" />
            </div>
            <p className="text-sm font-medium text-pn-soft mb-1">
              {search.trim()
                ? t('filesList.noMatches')
                : filter === 'all'
                  ? t('filesList.noFilesYet')
                  : filter === 'document' ? t('filesList.noDocuments') : filter === 'image' ? t('filesList.noImages') : t('filesList.noAudioFiles')}
            </p>
            {!search.trim() && (
              <>
                <p className="text-xs text-pn-muted max-w-[220px] mb-4">
                  {/* States the real cap, so it follows proUnlocked (the demo
                      uploads at the Pro limit). The free-vs-Pro table above
                      is the upsell and stays keyed off isPro. */}
                  {t('filesList.emptyTypesHint', { max: proUnlocked(isPro) ? (hasStorageSub ? '100' : '50') : '5' })}
                </p>
                <button
                  type="button"
                  onClick={() => onUploadFiles()}
                  className="text-xs font-medium text-white bg-accent-fill hover:bg-accent-fill-hover px-4 py-1.5 rounded-md transition"
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
          <div className={itemGridClass(viewMode === 'grid')}>
            {filtered.slice(0, list.reveal.visible).map((item, idx) => {
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
              // Picture thumbnails only in grid mode; list view keeps the
              // compact icon row (previews were too heavy/odd inline). An
              // uploaded picture is an attachment, and it gets one too, and a
              // PDF tile shows its first page the same way. A note the PIN
              // still guards shows neither, the way the note list hides its
              // preview: its tiles keep the file icon, like any other file.
              const isImageBg = viewMode === 'grid' && !gatedNow.has(item.noteId) && hasCoverFileItem(item);
              // Same amber chip as the attachment card's meta line (#151): the
              // blob is kept local because it does not fit the quota.
              const localOnly = quotaBlockedUuids.has(item.uuid);
              const flags: ItemFlag[] = [];
              if (item.starred && selectedFileIds.size === 0) flags.push('pinned');
              if (item.pinProtected) flags.push('pinProtected');
              if (item.locked) flags.push('readOnly');
              if (localOnly) flags.push('localOnly');
              const rootProps: ItemRootProps = {
                type: 'button',
                onClick: (e) =>
                  routeItemClick(e, selectedFileIds.size > 0, {
                    range: () => rangeSelectFiles(item),
                    toggle: () => toggleFileSelected(item),
                    open: () => {
                      setActiveFileId(fk);
                      onOpenNote(item.noteId, item.uuid);
                      openViewerAt(item);
                    },
                  }),
                onContextMenu: (e) => {
                  setContextTargetId(fk);
                  onContextMenu(e, buildFileMenu(item));
                },
                onTouchStart: () => beginFileLongPress(item),
                onTouchEnd: cancelFileLongPress,
                onTouchMove: cancelFileLongPress,
                onTouchCancel: cancelFileLongPress,
                ...fileDragProps(item),
                tabIndex: mobileTabIndex,
              };
              if (!isImageBg) {
                const gated = gatedNow.has(item.noteId);
                const listItem: Omit<ListItem, 'look'> = {
                  icon: <FileTileIcon mime={item.mime} />,
                  glyph: <CardGlyph type="file" />,
                  title: item.name,
                  // The type word only for a standalone file; a file inside a
                  // note names that note. A note the PIN still guards shows
                  // neither, the way the note list hides its preview.
                  preview: listPrefs.showPreview && !gated
                    ? { text: item.standalone ? mimeToLabel(item.mime) : item.noteTitle, long: false, dir: 'auto' }
                    : null,
                  date: listPrefs.showDate
                    ? { label: t('noteRow.modified', { ns: 'notes' }), row: formatInstant(item.editedAt, 'row'), tile: formatInstant(item.editedAt, 'tile') }
                    : null,
                  // One switch governs the size on every row and tile.
                  size: listPrefs.showSize && item.size > 0 ? formatBytes(item.size) : null,
                  flags,
                  chips: listPrefs.showTags ? <TagChips tags={item.tags} folderId={item.folderId} /> : null,
                  ribbon: false,
                };
                return (
                  <FileEntry
                    key={rowKey}
                    item={listItem}
                    file={item}
                    grid={viewMode === 'grid'}
                    compact={compactRows}
                    state={{ selectionMode: selectedFileIds.size > 0, selected: isSelected, open: isOpen, contextTarget: contextTargetId === fk }}
                    rootProps={rootProps}
                    onToggleSelect={(e) => {
                      if (e.shiftKey) rangeSelectFiles(item);
                      else toggleFileSelected(item);
                    }}
                  />
                );
              }
              // A picture or a PDF in the grid: the first page or the picture
              // fills the tile, and the name, the flags and the size sit on it.
              return (
                <button
                  key={rowKey}
                  {...rootProps}
                  type="button"
                  className={`pn-lazy-card relative overflow-hidden text-start border transition group rounded-xl min-h-[132px] ${
                    isSelected
                      ? 'border-accent ring-2 ring-accent z-[1]'
                      : isOpen
                        ? 'border-accent ring-2 ring-accent/50 z-[1]'
                        : contextTargetId === fk
                          ? 'border-accent/70'
                          : 'border-divider hover:border-accent/60'
                  }`}
                >
                  {isPdfFileItem(item)
                    ? <LazyPdfCover uuid={item.uuid} />
                    : <LazyPicture src={fileItemMediaRef(item).src} />}
                  <div className="absolute inset-0 pointer-events-none bg-gradient-to-t from-black/85 via-black/30 to-black/10" />
                  <div className="absolute inset-x-0 bottom-0 p-2.5">
                    <div className="text-[13px] font-semibold text-white truncate flex items-center gap-1.5">
                      <ItemFlags flags={flags} size={11} onImage />
                      <span data-slot="title" className="truncate" dir="auto">{item.name}</span>
                    </div>
                    <div className="flex items-center justify-between gap-2 mt-0.5">
                      <span className="text-[11px] text-white/85 truncate">{item.standalone ? getFileTypeLabel(item) : item.noteTitle}</span>
                      {listPrefs.showSize && item.size > 0 && <span className="text-[11px] text-white/85 shrink-0">{formatBytes(item.size)}</span>}
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
                        isSelected ? 'bg-accent-fill border-accent-fill text-white' : 'border-white/80 bg-black/30'
                      }`}
                    >
                      {isSelected && <Check size={12} />}
                    </span>
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

/**
 * A file as a list row or a grid tile: the item the Files pane builds, with
 * the color of the parent note's tags or folder, which a file shares with it.
 * Spec: ops/docs/plans/list-grid-parity.md (section 5)
 */
function FileEntry({ item, file, grid, compact, state, rootProps, onToggleSelect }: {
  item: Omit<ListItem, 'look'>;
  file: FileItem;
  grid: boolean;
  compact: boolean;
  state: ItemState;
  rootProps: ItemRootProps;
  onToggleSelect: (e: React.MouseEvent) => void;
}) {
  const look = useNoteLook(file.noteId, file.tags, file.folderId);
  const Layout = grid ? ItemTile : ItemRow;
  return (
    <Layout
      as="button"
      item={applyCompactRows({ ...item, look: look ? { color: look.color, style: look.style, css: noteLookStyle(look) } : null }, compact)}
      state={state}
      rootProps={rootProps}
      onToggleSelect={onToggleSelect}
    />
  );
}
