import React, { useCallback, useContext, useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { activeLocale } from './languages';
import type { LocalNote } from './db';
import type { ListPrefs } from './listPrefs';
import { deriveDisplayTitle, deriveExcerpt, editedAtOf, emptyExcerptLabel, entryDayOf, journalDateOf, rowSizeLabel, fileCount, noteLinkName } from './notesViewUtils';
import { formatDay, formatInstant, useDateFormatKey } from './intlFormat';
import { noteLinkTarget } from './noteLinks';
import { setItemDragImage, writeItemDrag, type ItemDragPayload } from './itemDrag';
import { Favicon } from './VaultItem';
import { parseLoginBody, domainFromUrl } from './LoginForm';
import { parseLinkBody, linkDomain } from './linkBody';
import { contactHue, contactInitials, contactInitialsFor, parseContactBody } from './contactBody';
import { loadEncryptedImageUrl } from './EncryptedImage';
import { Archive, Book, CalendarDots, CheckSquare, File, Image, MusicNotes, Key, CreditCard, Lock, Globe, BookmarkSimple, User, type Icon } from './icons';
import { useFolderName } from './folderNames';
import { ChipFilterContext } from './chipFilter';
import { sortTags } from './notesRepo';
import { usePushFailure } from './pushFailures';
import { FolderGlyph, TagMark, noteLookStyle, useNoteLook } from './looks/LookGlyph';
import { ItemRow, applyCompactRows, type ItemFlag, type ItemRootProps, type ItemState, type ListItem } from './listItem';
import { isSameOriginPath } from './sameOriginPath';
import { useCompactRows } from './viewMode';


export interface NoteRowProps {
  note: LocalNote;
  isOpen: boolean;
  listPrefs: ListPrefs;
  isNoteLocked: boolean;
  onClick: (e: React.MouseEvent) => void;

  /** Context menu handler - omit for simplified rows (e.g. task view). */
  onContextMenu?: (e: React.MouseEvent) => void;
  /** Long-press touch handlers - omit for simplified rows. */
  onTouchStart?: () => void;
  onTouchEnd?: () => void;
  onTouchMove?: () => void;
  onTouchCancel?: () => void;

  /** Multi-select state. */
  selectionMode?: boolean;
  isMultiSelected?: boolean;
  onToggleSelect?: (e: React.MouseEvent) => void;

  /** True when this row is the target of an open context menu. */
  isContextTarget?: boolean;
  /** Show starred / note-type icons. Default false. */
  showTypeIcons?: boolean;
  /** Use sortField-aware date label. Default false (always "Modified"). */
  sortAwareDate?: boolean;
  /** The Journals pillar: the created sort shows the day an entry is for. */
  entryDays?: boolean;
  /** Tint the row icon amber (used in trash view). */
  trashTint?: boolean;
  /** Label an archived item "Archived": set wherever one can appear outside
   *  the Archive view, which is a search of All. */
  showArchived?: boolean;
  /**
   * Always-visible row actions rendered at the END of the title block,
   * inside the row's flex (so the text truncates before them instead of
   * running underneath). Bookmarks use it for their pencil/delete pair,
   * matching the derived-rows buttons exactly.
   */
  trailing?: ReactNode;
  /**
   * Lets the item be dragged: into an editor as a `[[note-link]]`, and onto
   * a sidebar folder or tag by its id. Opt-in, because the Markdown folder
   * list reuses these components for files, which are not notes.
   */
  itemDrag?: boolean;
  /** In selection mode, what a selected item drags: the selected items the
   *  list shows. Read only at dragstart. */
  dragSelection?: () => ItemDragPayload;
}

/**
 * The adapter from a note to a `ListItem`, shared by `NoteRow` and `NoteCard`,
 * so the row and the tile of one note are built once. Every derivation is
 * memoized on the note object: NotesList hands every row fresh inline
 * callbacks, which defeats React.memo, so each row renders on every keystroke,
 * and without these memos the excerpt, title, date and size would be derived
 * again for every row each time. displayNotes keeps object identity for
 * unchanged notes, so keying on the note means a value is recomputed only
 * when that note changes.
 */
export function useNoteItem(p: NoteRowProps): ListItem {
  const {
    note: n,
    listPrefs,
    isNoteLocked: locked,
    showTypeIcons = false,
    sortAwareDate = false,
    entryDays = false,
    trashTint = false,
    showArchived = false,
  } = p;
  const { t } = useTranslation('notes');
  const compactRows = useCompactRows();
  // Subscribed per item: the set changes once per pass at most, and only when
  // a note's verdict changes, so this costs nothing while idle.
  const pushFailure = usePushFailure(n.id);
  // The tag or folder color; never in the trash, which keeps its own look.
  const noteLook = useNoteLook(n.id, n.tags, n.folderId);
  const look = trashTint ? null : noteLook;
  const isVault = n.type === 'login' || n.type === 'card' || n.type === 'ssh-key';
  const locale = activeLocale();
  const displayTitle = useMemo(() => deriveDisplayTitle(n, locked), [n, locked, locale]);
  const excerpt = useMemo(() => deriveExcerpt(n, listPrefs.longPreview), [n, listPrefs.longPreview, locale]);
  /** One rule for when a size appears. `noteSizeBytes` memoizes per note, so
   *  this is a map lookup after the first call. */
  const sizeText = rowSizeLabel(n, listPrefs.sortField) || null;
  /** Favicon for the mini glyph - bookmarks and logins only, never in trash
   *  (the boxed chip drops the favicon there too, for the amber icon), and
   *  never behind the PIN, where the address is the content the gate keeps. */
  const faviconDomain = useMemo(() => (trashTint || locked ? '' : noteFaviconDomain(n)), [n, trashTint, locked]);
  // In Journals the created sort is by the day each entry is for, and the
  // date line names that day.
  const created = sortAwareDate && listPrefs.sortField === 'created';
  const entryDay = entryDays && created && n.type === 'journal';
  // A note or a task list attached to a day names that day in place of the stamp.
  // Spec: ops/docs/plans/note-date.md
  const noteDay = n.type === 'note' || n.type === 'task' ? journalDateOf(n) : null;
  const dateLabel = noteDay ? t('noteRow.date') : entryDay ? t('noteRow.entryDate') : created ? t('noteRow.created') : t('noteRow.modified');
  // A new date setting or language formats the date again without a remount.
  const dateFormatKey = useDateFormatKey();
  const dates = useMemo(() => {
    if (noteDay || entryDay) {
      const day = formatDay(noteDay ?? entryDayOf(n), 'tile');
      return { row: day, tile: day };
    }
    const at = created ? n.createdAt : editedAtOf(n);
    return { row: formatInstant(at, 'row'), tile: formatInstant(at, 'tile') };
  }, [n, created, dateFormatKey, entryDay, noteDay]);

  const flags: ItemFlag[] = [];
  if (pushFailure) flags.push('notBackedUp');
  if (showTypeIcons && n.starred === 1) flags.push('pinned');
  if (n.pinProtected === 1) flags.push('pinProtected');
  if (n.locked === 1) flags.push('readOnly');
  if (showArchived && n.archived === 1) flags.push('archived');

  return applyCompactRows({
    id: n.id,
    icon: <RowIcon note={n} isVault={isVault} isFile={n.type === 'file'} isJournal={n.type === 'journal'} hasTasks={n.type === 'task'} trashTint={trashTint} locked={locked} />,
    glyph: <CardGlyph type={n.type} domain={faviconDomain} />,
    compactIcon: <CompactPicture note={n} domain={faviconDomain} hidden={trashTint || locked} />,
    title: displayTitle,
    preview: listPrefs.showPreview && !locked
      ? { text: excerpt || emptyExcerptLabel(n), long: listPrefs.longPreview, dir: 'auto' }
      : null,
    date: listPrefs.showDate ? { label: dateLabel, ...dates } : null,
    size: sizeText,
    flags,
    chips: listPrefs.showTags ? <TagChips tags={n.tags} folderId={n.folderId} /> : null,
    ribbon: n.type === 'link',
    look: look ? { color: look.color, style: look.style, css: noteLookStyle(look) } : null,
  }, compactRows);
}

/** What a note row or tile hands its root besides the item: the handlers and
 *  the drag. */
export function noteRootProps(p: NoteRowProps): ItemRootProps {
  return {
    onClick: p.onClick,
    onContextMenu: p.onContextMenu,
    onTouchStart: p.onTouchStart,
    onTouchEnd: p.onTouchEnd,
    onTouchMove: p.onTouchMove,
    onTouchCancel: p.onTouchCancel,
    ...itemDragProps({
      note: p.note,
      isNoteLocked: p.isNoteLocked,
      itemDrag: p.itemDrag ?? false,
      selectionMode: p.selectionMode ?? false,
      isMultiSelected: p.isMultiSelected ?? false,
      trashTint: p.trashTint ?? false,
      dragSelection: p.dragSelection,
    }),
  };
}

export function noteItemState(p: NoteRowProps): ItemState {
  return {
    selectionMode: p.selectionMode ?? false,
    selected: p.isMultiSelected ?? false,
    open: p.isOpen,
    contextTarget: p.isContextTarget ?? false,
  };
}

/** The list row of a note. React.memo skips the render when only the active
 *  note's body changes: every other row keeps its props. Critical for
 *  large-note perf (#58, #64). */
export default React.memo(function NoteRow(props: NoteRowProps) {
  const item = useNoteItem(props);
  return (
    <ItemRow
      item={item}
      state={noteItemState(props)}
      rootProps={noteRootProps(props)}
      onToggleSelect={props.onToggleSelect}
      trailing={props.trailing}
    />
  );
});

/* ── Unified 28px row icon ────────────────────────────────────────── */

/** Glyph size for the 28px row-icon boxes - favicon and type icons alike, so
 *  they all read the same size (an 18px glyph in the 28px box). */
const ROW_ICON_PX = 18;

/** Favicon size for the mini card glyph - the small-tile stand-in for the
 *  28px chip. Two pixels over the 13px type glyphs it replaces, because a
 *  site logo needs the extra room to stay recognizable. */
const MINI_FAVICON_PX = 15;

/**
 * Domain whose favicon stands in for this note's type icon, '' when it has
 * none - every type except bookmarks and vault logins, plus a login whose URL
 * is missing or unparseable. One derivation for both places the favicon
 * appears: the boxed `SiteChip` on rows and cards, and the inline `CardGlyph`
 * the mini card shows instead of that box.
 */
export function noteFaviconDomain(note: LocalNote): string {
  if (note.type === 'link') return linkDomain(parseLinkBody(note.body).url);
  if (note.type === 'login') {
    try {
      return domainFromUrl(parseLoginBody(note.body).url);
    } catch {
      return '';
    }
  }
  return '';
}

/**
 * The note-links for a set of items, one per line, in the order given. The
 * target comes from `noteLinkName`, so an untitled note, and a bookmark's
 * domain behind a closed gate, are skipped rather than linked by a body line.
 */
function noteLinkText(notes: readonly LocalNote[], isLocked: (n: LocalNote) => boolean): string {
  return notes
    .map((n) => noteLinkTarget(noteLinkName(n, isLocked(n))))
    .filter(Boolean)
    .map((target) => `[[${target}]]`)
    .join('\n');
}

/** What a drag of these items carries, in the order given: every id, and the
 *  note-links of the ones that have a link name. */
export function itemDragSelection(picked: readonly LocalNote[], isLocked: (n: LocalNote) => boolean): ItemDragPayload {
  return { ids: picked.map((n) => n.id), linkText: noteLinkText(picked, isLocked) };
}

/**
 * The drag props for a row or tile, or none. Outside selection mode the item
 * drags itself; in selection mode a selected item drags the selection, and
 * an unselected one does not drag. An untitled item drags with no link text,
 * so it files onto a folder or tag and drops nothing into an editor. A
 * trashed item does not drag.
 */
function itemDragProps(
  p: Pick<NoteRowProps, 'note' | 'isNoteLocked' | 'itemDrag' | 'selectionMode' | 'isMultiSelected' | 'trashTint' | 'dragSelection'>,
) {
  if (!p.itemDrag || p.trashTint) return {};
  let payload: () => ItemDragPayload;
  if (p.selectionMode) {
    if (!p.isMultiSelected || !p.dragSelection) return {};
    payload = p.dragSelection;
  } else {
    const own = itemDragSelection([p.note], () => p.isNoteLocked);
    payload = () => own;
  }
  return {
    draggable: true,
    onDragStart: (e: React.DragEvent) => {
      const { ids, linkText } = payload();
      if (ids.length === 0) {
        e.preventDefault();
        return;
      }
      writeItemDrag(e.dataTransfer, ids, linkText);
      setItemDragImage(e.dataTransfer, e.currentTarget, ids.length);
    },
  };
}

/** 28px icon box rendered for every row type. Color is type-based,
 *  overridden to amber when `trashTint` is true. Vault logins use
 *  favicon instead of a generic icon. */
function RowIcon({ note, isVault, isFile, isJournal, hasTasks, trashTint, locked, tall = false }: {
  note: LocalNote;
  isVault: boolean;
  isFile: boolean;
  isJournal: boolean;
  hasTasks: boolean;
  trashTint: boolean;
  /** The note is behind the PIN right now. The chip then reads nothing from
   *  its body: no photo, no favicon (whose lookup would also send the
   *  domain out), no file type, and no initials but the stored title's;
   *  the note's type still shows. */
  locked: boolean;
  /** 36px chip spanning the title + sub-line pair (vault logins, bookmarks). */
  tall?: boolean;
}) {
  // Contacts - the round chip: initials, or the photo when there is one.
  if (note.type === 'contact') {
    const c = parseContactBody(note.body);
    return <ContactChip name={deriveDisplayTitle(note, locked)} initials={locked ? contactInitials(note.title) : contactInitialsFor(note.title, c)} photo={locked ? '' : c.photo} size={tall ? 36 : 28} trashTint={trashTint} tile />;
  }
  // Bookmarks - favicon chip, globe fallback.
  // In Trash the link row wears the amber BOOKMARK icon, the same rule
  // vault logins follow (login icon there, favicon only while live).
  if (note.type === 'link') return <SiteChip domain={locked ? '' : noteFaviconDomain(note)} tall={tall} trashTint={trashTint} fallback={trashTint ? 'bookmark' : 'globe'} />;
  // Vault - favicon for logins, colored icon for cards/keys
  if (isVault) return <VaultRowIcon note={note} trashTint={trashTint} locked={locked} tall={tall} />;

  // Files share one boxed icon with the Files view - see FileTileIcon.
  if (isFile) return <FileTileIcon mime={locked ? '' : fileMimeFromBody(note.body)} />;

  // Determine color classes (non-file types)
  let bg: string;
  let text: string;
  if (trashTint) {
    bg = 'bg-amber-100/80 dark:bg-amber-900/30';
    text = 'text-warning';
  } else if (isJournal) {
    bg = 'bg-purple-100/80 dark:bg-purple-900/30';
    text = 'text-purple-600 dark:text-purple-400';
  } else if (note.type === 'event') {
    // theme-ok: the event teal, a fixed hue like the journal purple
    bg = 'bg-teal-100/80 dark:bg-teal-900/30';
    text = typeGlyph('event').color;
  } else if (hasTasks) {
    bg = 'bg-emerald-100/80 dark:bg-emerald-900/30';
    text = 'text-success';
  } else {
    bg = 'bg-accent/10 dark:bg-accent/15';
    text = 'text-accent';
  }

  return (
    <span className={`shrink-0 w-7 h-7 rounded-md ${bg} flex items-center justify-center ${text} mt-px`}>
      {isJournal ? <Book size={ROW_ICON_PX} /> : note.type === 'event' ? <CalendarDots size={ROW_ICON_PX} /> : hasTasks ? <CheckSquare size={ROW_ICON_PX} /> : <File size={ROW_ICON_PX} />}
    </span>
  );
}

/** Extract the MIME type from a file note's single pn:file link. */
function fileMimeFromBody(body: string): string {
  const m = body.match(/\[[^|]*\|[^|]*\|([^\]]*)\]\(pn:file\//);
  return (m?.[1] || '').toLowerCase();
}

/**
 * Amber boxed file icon - the glyph (image / audio / document) is chosen from
 * the MIME type. Single source of truth for the file tile icon in note rows
 * and cards (via RowIcon) and in the Files view, so the two cannot drift apart.
 */
export function FileTileIcon({ mime, className = '' }: { mime: string; className?: string }) {
  const m = (mime || '').toLowerCase();
  const Icon = m.startsWith('image/') ? Image : m.startsWith('audio/') ? MusicNotes : File;
  return (
    <span className={`shrink-0 w-7 h-7 rounded-md bg-amber-100/80 dark:bg-amber-900/30 flex items-center justify-center text-warning mt-px ${className}`}>
      <Icon size={ROW_ICON_PX} />
    </span>
  );
}

// theme-ok: a light tile keeps dark favicons readable in every theme
const FAVICON_TILE = 'bg-[#f0efec] border border-black/[0.06] dark:border-white/[0.08]';

/**
 * Favicon chip shared by vault logins, bookmark rows and the bookmark
 * editor's URL field. Two sizes:
 *   - compact (28px box, 22px favicon) for one-line contexts,
 *   - tall (36px box, 28px favicon) when the chip spans the title + sub-line
 *     pair, so the tile is exactly as tall as the text block beside it.
 * The favicon fills most of the box on purpose - the old 18px-in-28px
 * rendering read as a dot in a frame. Fallback, also while a site's icon is
 * missing: Globe for bookmarks, Lock for logins, on the accent tint; amber in
 * trash.
 * Spec: ops/docs/plans/bookmarks-pillar.md (row chip)
 */
export function SiteChip({ domain, tall, trashTint, fallback }: {
  domain: string;
  tall?: boolean;
  trashTint?: boolean;
  fallback: 'globe' | 'lock' | 'bookmark';
}) {
  const box = tall ? 'w-9 h-9 rounded-lg' : 'w-7 h-7 rounded-md';
  const icon = tall ? 28 : 22;
  const [missing, setMissing] = useState(false);
  const onMissing = useCallback((m: boolean) => setMissing(m), []);
  const FallbackIcon = fallback === 'lock' ? Lock : fallback === 'bookmark' ? BookmarkSimple : Globe;
  if (domain && !trashTint) {
    // The light tile only behind a real icon; while there is none, the same
    // box wears the themed placeholder below, and the Favicon inside stays
    // mounted (hidden) so it can still load and report back.
    return (
      <span className={`shrink-0 ${box} flex items-center justify-center mt-px overflow-hidden ${missing ? 'bg-accent/10 dark:bg-accent/15 text-accent' : FAVICON_TILE}`}>
        <span className={missing ? 'hidden' : 'contents'}>
          <Favicon domain={domain} size={icon} onMissing={onMissing} />
        </span>
        {missing && <FallbackIcon size={tall ? 20 : ROW_ICON_PX} />}
      </span>
    );
  }
  // A theme's accent, like the rest of the row chrome; Trash keeps its warning tint.
  const bg = trashTint ? 'bg-amber-100/80 dark:bg-amber-900/30' : 'bg-accent/10 dark:bg-accent/15';
  const text = trashTint ? 'text-warning' : 'text-accent';
  return (
    <span className={`shrink-0 ${box} ${bg} flex items-center justify-center ${text} mt-px`}>
      <FallbackIcon size={tall ? 20 : ROW_ICON_PX} />
    </span>
  );
}

/** The chip hues a contact can wear. The index is stable per name (contactHue),
 *  so the same person is the same colour on every device. */
const CONTACT_HUE_CLASSES = [
  'bg-rose-100 text-rose-700 dark:bg-rose-900/40 dark:text-rose-300',
  'bg-orange-100 text-orange-700 dark:bg-orange-900/40 dark:text-orange-300',
  'bg-amber-100 text-amber-700 dark:bg-amber-900/40 dark:text-amber-300',
  'bg-emerald-100 text-emerald-700 dark:bg-emerald-900/40 dark:text-emerald-300',
  'bg-teal-100 text-teal-700 dark:bg-teal-900/40 dark:text-teal-300',
  'bg-sky-100 text-sky-700 dark:bg-sky-900/40 dark:text-sky-300',
  'bg-violet-100 text-violet-700 dark:bg-violet-900/40 dark:text-violet-300',
  'bg-pink-100 text-pink-700 dark:bg-pink-900/40 dark:text-pink-300',
];

/**
 * The one new visual primitive of the Contacts pillar: a CIRCLE holding the
 * initials, or the photo when the contact has one. Round-for-a-person against
 * the square icon chips every other row wears is the convention every address
 * book shares, and it is what lets the eye pick people out of the All list.
 * The circle is CSS over the stored image, which is never cropped in storage.
 * Spec: ops/docs/plans/contacts-pillar.md (section 4, the one new primitive)
 */
export function ContactChip({ name, initials: given, photo, size, trashTint = false, tile = false }: {
  /** The display name; it picks the hue. */
  name: string;
  /** The letters to draw; derived from the name when absent. */
  initials?: string;
  /** The stored `pn:img/<uuid>` reference, a static path for the seeded
   *  contact, or ''. */
  photo: string;
  /** Diameter in px. */
  size: number;
  trashTint?: boolean;
  /** A list row's icon: the rounded square every other row icon wears, on
   *  the same 1px drop, instead of the circle of the contact's own page. */
  tile?: boolean;
}) {
  // A path rather than a uuid is the seeded contact's picture: a static
  // asset every install already ships, so it needs no blob, no quota and
  // no sync, and it draws on a second device that never ran the seeding.
  const staticSrc = isSameOriginPath(photo) ? photo : '';
  const uuid = photo.startsWith('pn:img/') ? photo.slice('pn:img/'.length) : '';
  const [url, setUrl] = useState<string | null>(null);
  useEffect(() => {
    if (!uuid) { setUrl(null); return; }
    let alive = true;
    void loadEncryptedImageUrl(uuid).then((u) => { if (alive) setUrl(u); });
    return () => { alive = false; };
  }, [uuid]);
  const initials = given ?? contactInitials(name);
  const tone = trashTint
    ? 'bg-amber-100/80 text-amber-600 dark:bg-amber-900/30 dark:text-amber-400'
    : CONTACT_HUE_CLASSES[contactHue(name)]!;
  return (
    <span
      className={`shrink-0 ${tile ? 'rounded-md mt-px' : 'rounded-full'} overflow-hidden inline-flex items-center justify-center font-semibold select-none ${tone}`}
      style={{ width: size, height: size, fontSize: Math.round(size * 0.36) }}
      aria-hidden="true"
    >
      {staticSrc || url ? (
        <img src={staticSrc || url!} alt="" className="w-full h-full object-cover" draggable={false} />
      ) : (
        initials || <User size={Math.round(size * 0.5)} />
      )}
    </span>
  );
}

/** Vault row icon - favicon chip for logins, type icon for cards/keys. */
function VaultRowIcon({ note, trashTint, locked, tall = false }: { note: LocalNote; trashTint: boolean; locked: boolean; tall?: boolean }) {
  if (note.type === 'login') {
    if (!trashTint && !locked) {
      const domain = noteFaviconDomain(note);
      if (domain) return <SiteChip domain={domain} tall={tall} fallback="lock" />;
    }
    // Fallback / trash: standard login icon (Lock, so it stays distinct from the
    // ssh-key's Key glyph; the favicon above is the primary path for logins).
    return <SiteChip domain="" tall={tall} trashTint={trashTint} fallback="lock" />;
  }
  if (note.type === 'card') {
    const bg = trashTint ? 'bg-amber-100/80 dark:bg-amber-900/30' : 'bg-amber-100/80 dark:bg-amber-900/30';
    const text = trashTint ? 'text-warning' : 'text-warning';
    return (
      <span className={`shrink-0 w-7 h-7 rounded-md ${bg} flex items-center justify-center ${text} mt-px`}>
        <CreditCard size={ROW_ICON_PX} />
      </span>
    );
  }
  // ssh-key - terminal look (black box, white icon) so it reads distinct from
  // the journal purple. theme-ok: the black box is the same in every theme.
  const bg = trashTint ? 'bg-amber-100/80 dark:bg-amber-900/30' : 'bg-neutral-900 dark:bg-black border border-white/10';
  const text = trashTint ? 'text-warning' : 'text-white';
  return (
    <span className={`shrink-0 w-7 h-7 rounded-md ${bg} flex items-center justify-center ${text} mt-px`}>
      <Key size={ROW_ICON_PX} />
    </span>
  );
}

/**
 * The chip row under a list row or a grid tile: the item's folder first,
 * then up to four tags. Shared by `NoteRow`, `NoteCard` and `FilesList` so
 * the three cannot draw the same metadata three ways.
 *
 * The folder chip is AMBER and the tag chips are accent, which is the
 * split the whole app uses: amber means folder in the tree, the picker and
 * here, and accent means tag. Neither is a raw Tailwind neutral any more -
 * the tags used neutral-200, a COOL grey, so on the warm-cream and slate
 * themes they sat on a warm or blue surface at almost the same lightness and
 * read as disabled chrome. Spec: ops/docs/ui-patterns.md (section 82, the
 * same pair in the editor tag row)
 *
 * The folder chip is omitted entirely for an unfiled item rather than drawn
 * empty, which also means a free account (no folders) sees the row exactly
 * as before. Renders nothing at all when there is neither a folder nor a
 * tag.
 *
 * The tags are sorted by name, exactly as the editor's tag row sorts them,
 * which also decides WHICH four survive the slice below: an insertion-ordered
 * list showed a different four per note for no reason a reader could see.
 * Spec: issue #259.
 *
 * A click on a chip filters the list by it (`chipFilter.ts`). The element
 * stays a span whether or not the filter is on: a long press turns
 * selection mode on mid-touch, and swapping the element then would drop
 * the click that follows it. A modifier click is a selection gesture, so it
 * passes through to the row.
 */
export function TagChips({ tags, folderId }: { tags: string[]; folderId?: string | null }) {
  const visible = useMemo(() => sortTags(tags), [tags]);
  const folderName = useFolderName(folderId);
  const filter = useContext(ChipFilterContext);
  if (visible.length === 0 && !folderName) return null;
  const onPick = (run: (f: NonNullable<typeof filter>) => void) =>
    filter
      ? (e: React.MouseEvent) => {
          if (e.metaKey || e.ctrlKey || e.shiftKey) return;
          e.stopPropagation();
          run(filter);
        }
      : undefined;
  const pickable = filter ? ' pn-chip-pick cursor-pointer transition' : '';
  return (
    <div data-slot="tags" className="mt-1 md:mt-1.5 flex flex-wrap gap-1">
      {folderName && folderId && (
        <span
          data-slot="folder"
          onClick={onPick((f) => f.folder(folderId))}
          className={`inline-flex items-center gap-1 max-w-[12rem] text-[11px] px-1.5 py-0.5 rounded pn-chip text-accent-strong${pickable}`}
        >
          <FolderGlyph folderId={folderId} size={11} className="shrink-0 text-label" />
          <span className="truncate" dir="auto">{folderName}</span>
        </span>
      )}
      {visible.slice(0, 4).map((t) => (
        <span
          key={t}
          dir="auto"
          onClick={onPick((f) => f.tag(t))}
          className={`inline-flex items-center text-[11px] px-1.5 py-0.5 rounded pn-chip text-accent-strong${pickable}`}
        >
          <TagMark tag={t} size={11} />
          {t}
        </span>
      ))}
    </div>
  );
}

/**
 * Inline type glyph for the compact (mini) card layout - the small-tile
 * variant used in the docked list panel and the phone grid. Hidden by
 * default (`.pn-card-glyph { display: none }`); the mini CSS reveals it
 * inline, ahead of the title. Shared by NoteCard and FilesList so both
 * grids render an identical icon (single source of truth).
 *
 * `domain` (bookmarks and vault logins, from `noteFaviconDomain`) draws the
 * site favicon here instead of a type icon. The mini tile hides the boxed
 * chip, and on a bookmark the site IS the identity - a grid of identical sky
 * bookmark glyphs names none of them. Omit it (or pass '') anywhere the box
 * shows no favicon either, and the type glyph is drawn as before.
 */
export function CardGlyph({ type, override, domain }: { type: LocalNote['type']; override?: Icon; domain?: string }) {
  // A row adapted from something that is not a note (a Markdown file) carries
  // type 'note' and would draw the note glyph. The caller names the glyph; the
  // size and class contract stays here, where the mini CSS can find it. Returns
  // before the type branches rather than feeding into them, so the override
  // cannot be overwritten by a type the caller does not control.
  if (override) {
    const Override = override;
    return <Override size={13} className="pn-card-glyph shrink-0 text-accent" aria-hidden="true" />;
  }
  // Same slot, same class contract - only the artwork differs, so the mini CSS
  // positions the favicon exactly where it positions a type glyph. The chip's
  // own favicon sits in a `display: none` box while this one shows (and the
  // reverse on a wide tile), so a card still fetches exactly one icon.
  if (domain) return <CardFavGlyph type={type} domain={domain} />;
  const { Icon, color } = typeGlyph(type);
  return <Icon size={13} className={`pn-card-glyph shrink-0 ${color}`} aria-hidden="true" />;
}

/** The mini tile's site icon, or the type glyph while there is none (the
 *  demo, favicons off, a failed load), never the grey globe on a light tile. */
function CardFavGlyph({ type, domain }: { type: LocalNote['type']; domain: string }) {
  const [missing, setMissing] = useState(false);
  const onMissing = useCallback((m: boolean) => setMissing(m), []);
  const { Icon, color } = typeGlyph(type);
  return (
    <>
      <span className="pn-card-glyph pn-card-glyph-fav shrink-0" style={missing ? { display: 'none' } : undefined} aria-hidden="true">
        <Favicon domain={domain} size={MINI_FAVICON_PX} onMissing={onMissing} />
      </span>
      {missing && <Icon size={13} className={`pn-card-glyph shrink-0 ${color}`} aria-hidden="true" />}
    </>
  );
}

/** The size of the picture a Compact row keeps in place of the 28px chip. */
const COMPACT_PICTURE_PX = 16;

/** A Compact row's picture: a bookmark's or a login's site icon, or a
 *  contact's photo. Nothing for any other item, behind the PIN, in the
 *  trash, or while the site icon is missing (the demo, site icons off). */
function CompactPicture({ note, domain, hidden }: { note: LocalNote; domain: string; hidden: boolean }) {
  if (hidden) return null;
  if (note.type === 'contact') {
    const photo = parseContactBody(note.body).photo;
    return photo ? <ContactChip name={note.title} photo={photo} size={COMPACT_PICTURE_PX} tile /> : null;
  }
  return domain ? <CompactSiteIcon domain={domain} /> : null;
}

/** A site icon at the Compact row size, gone while it has not loaded. */
export function CompactSiteIcon({ domain }: { domain: string }) {
  const [missing, setMissing] = useState(false);
  const onMissing = useCallback((m: boolean) => setMissing(m), []);
  return (
    <span className="shrink-0 inline-flex" style={missing ? { display: 'none' } : undefined} aria-hidden="true">
      <Favicon domain={domain} size={COMPACT_PICTURE_PX} onMissing={onMissing} />
    </span>
  );
}

/** The small glyph and its color for each item type, shared by the mini grid
 *  tile and the tab strip so the two cannot name a type differently. */
export function typeGlyph(type: LocalNote['type']): { Icon: Icon; color: string } {
  let Icon = File;
  let color = 'text-accent';
  if (type === 'file') {
    color = 'text-warning';
  } else if (type === 'journal') {
    Icon = Book;
    color = 'text-purple-600 dark:text-purple-400';
  } else if (type === 'task') {
    Icon = CheckSquare;
    color = 'text-success';
  } else if (type === 'event') {
    // theme-ok: a fixed hue like the journal purple, the same in every theme.
    Icon = CalendarDots;
    color = 'text-teal-600 dark:text-teal-400';
  } else if (type === 'card') {
    Icon = CreditCard;
    color = 'text-warning';
  } else if (type === 'ssh-key') {
    // Mono icon (no box in the mini layout) - dark in light mode, white in dark.
    Icon = Key;
    color = 'text-pn';
  } else if (type === 'login') {
    // Lock (not Key) so logins stay distinct from ssh keys in the mini grid,
    // where the favicon box is hidden and this glyph shows instead.
    Icon = Lock;
  } else if (type === 'link') {
    Icon = BookmarkSimple;
  } else if (type === 'contact') {
    // The accent, like a login and a bookmark: the row chips of all three
    // wear the theme's accent (a contact's chip its own hue), and a fixed
    // blue, sky or teal glyph read as a different app in every theme.
    Icon = User;
  }
  return { Icon, color };
}
