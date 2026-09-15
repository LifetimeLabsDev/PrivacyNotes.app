import React, { useEffect, useMemo, useState } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { activeLocale } from './languages';
import type { LocalNote } from './db';
import type { ListPrefs } from './listPrefs';
import { deriveDisplayTitle, deriveExcerpt, emptyExcerptLabel, rowSizeLabel, formatModified, fileCount } from './notesViewUtils';
import { Favicon } from './VaultItem';
import { parseLoginBody, domainFromUrl } from './LoginForm';
import { parseLinkBody, linkDomain } from './linkBody';
import { contactHue, contactInitials, contactInitialsFor, parseContactBody } from './contactBody';
import { loadEncryptedImageUrl } from './EncryptedImage';
import { Check, PushPin, Shield, PencilSimpleSlash, Book, CheckSquare, File, Image, MusicNotes, Key, CreditCard, Lock, Globe, BookmarkSimple, Folder, Warning, User, type Icon } from './icons';
import { useFolderName } from './folderNames';
import { sortTags } from './notesRepo';
import { usePushFailure } from './pushFailures';


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
  /** Tint the row icon amber (used in trash view). */
  trashTint?: boolean;
  /**
   * Size shown on the title row for notes that are not file-type.
   *
   * File notes derive theirs from the attachment refs in the body; a Markdown
   * file's size comes from the filesystem instead, so it has to be passed in.
   * Rendered in the same span and style as the Files list, so the two lists
   * cannot drift apart visually.
   */
  sizeLabel?: string;
  /**
   * Replaces the derived row glyph.
   *
   * The glyph is normally chosen from the note's type, which is exactly right
   * for the encrypted store. A Markdown file is adapted INTO that shape to
   * reuse this row, so its type says 'note' and it would otherwise draw a note
   * glyph - hiding the one thing that makes the row what it is.
   */
  iconOverride?: ReactNode;
  /**
   * Always-visible row actions rendered at the END of the title block,
   * inside the row's flex (so the text truncates before them instead of
   * running underneath). Bookmarks use it for their pencil/delete pair,
   * matching the derived-rows buttons exactly.
   */
  trailing?: ReactNode;
  /**
   * The same override for the MINI card layout, which draws `CardGlyph` from
   * the note's type instead of the boxed icon above - a container query hides
   * the box below 640px, so a docked grid or a phone would drop back to the
   * note glyph and lose the distinction `iconOverride` exists to make.
   *
   * A component rather than a node, because `CardGlyph` owns the size and the
   * `pn-card-glyph` class that the mini CSS keys off: a caller assembling the
   * element itself would be copying a contract it cannot see. Read only by
   * `NoteCard` - a row has no glyph.
   */
  glyphOverride?: Icon;
}

/** React.memo prevents re-render when only the *active* note's body
 *  changes - all other rows in the list keep their old props and skip
 *  the render entirely. Critical for large-note perf (#58, #64). */
export default React.memo(function NoteRow({
  note: n,
  isOpen,
  listPrefs,
  isNoteLocked: locked,
  onClick,
  onContextMenu,
  onTouchStart,
  onTouchEnd,
  onTouchMove,
  onTouchCancel,
  selectionMode = false,
  isMultiSelected = false,
  onToggleSelect,
  isContextTarget = false,
  showTypeIcons = false,
  sortAwareDate = false,
  trashTint = false,
  sizeLabel,
  iconOverride,
  trailing,
}: NoteRowProps) {
  const { t } = useTranslation('notes');
  // Subscribed per row: the set changes once per pass at most, and only
  // when a note's verdict changes, so this costs nothing while idle.
  const pushFailure = usePushFailure(n.id);
  const isVault = n.type === 'login' || n.type === 'card' || n.type === 'ssh-key';
  const isLink = n.type === 'link';
  const isFile = n.type === 'file';
  const isJournal = n.type === 'journal';
  const isTask = n.type === 'task';
  const hasTasks = isTask;
  const hasStatusIcons =
    (showTypeIcons && n.starred === 1) || n.pinProtected === 1 || n.locked === 1 || pushFailure !== undefined;

  // Per-row derived values are memoized on the note object. NotesList hands
  // every row fresh inline callback props, which defeats this component's
  // React.memo, so each row re-renders on every keystroke. Without these memos
  // the excerpt / title / date / file-size derivations would re-run for every
  // row each time - cheap per note, but it adds up on a large vault. displayNotes
  // keeps object identity for unchanged notes, so keying on `n` means they only
  // recompute when that note actually changes.
  const displayTitle = useMemo(() => deriveDisplayTitle(n), [n, activeLocale()]);
  const excerpt = useMemo(() => deriveExcerpt(n), [n, activeLocale()]);
  /** Shared with `NoteCard` so the row and the tile cannot disagree about when
   *  a size appears. `noteSizeBytes` memoizes per note, so this is a map lookup
   *  after the first call. */
  const sizeText = rowSizeLabel(n, listPrefs.sortField, sizeLabel) || undefined;
  const dateLabel = sortAwareDate && listPrefs.sortField === 'created' ? t('noteRow.created') : t('noteRow.modified');
  const dateValue = useMemo(
    () =>
      formatModified(
        sortAwareDate && listPrefs.sortField === 'created' ? n.createdAt : n.updatedAt,
      ),
    [n, sortAwareDate, listPrefs.sortField],
  );

  return (
    <li
      onClick={onClick}
      onContextMenu={onContextMenu}
      onTouchStart={onTouchStart}
      onTouchEnd={onTouchEnd}
      onTouchMove={onTouchMove}
      onTouchCancel={onTouchCancel}
      // Touch only: long-press is the multi-select gesture, so the row must
      // not also hand the WebView something to select. Desktop keeps normal
      // text selection. Spec: issue #208.
      className={`pn-row pn-lazy-row relative px-4 py-3 cursor-pointer border-b border-divider/50 transition [@media(hover:none)]:select-none ${
        isMultiSelected
          ? 'bg-accent/15 hover:bg-accent/20 border-s-2 border-s-accent dark:bg-accent/20 dark:hover:bg-accent/25'
          : isOpen
          ? 'bg-accent/10 hover:bg-accent/15 border-s-2 border-s-accent dark:bg-accent/15 dark:hover:bg-accent/20'
          : isContextTarget
          ? 'bg-neutral-200/70 hover:bg-neutral-200/80 dark:bg-neutral-800/70 dark:hover:bg-neutral-800/80'
          : 'hover:bg-neutral-200/50 dark:hover:bg-neutral-900/50'
      } ${selectionMode ? 'ps-10' : ''}`}
    >
      {/* Bookmark ribbon - the saved-link marker, see the .pn-ribbon rules in
          index.css. Vault logins stay unmarked. */}
      {isLink && <span className="pn-ribbon" aria-hidden="true" />}
      {selectionMode && (
        <span
          onClick={(e) => {
            e.stopPropagation();
            onToggleSelect?.(e);
          }}
          aria-label={isMultiSelected ? t('noteRow.deselect') : t('noteRow.select')}
          role="checkbox"
          aria-checked={isMultiSelected}
          className={`absolute start-3 top-3.5 w-5 h-5 rounded border flex items-center justify-center transition shrink-0 ${
            isMultiSelected
              ? 'bg-accent border-accent text-white'
              : 'bg-surface-2 border-divider hover:border-accent'
          }`}
        >
          {isMultiSelected && (
            <Check size={12} />
          )}
        </span>
      )}
      {/* ── Title line: icon + title only. Preview / date / tags drop
          below and span the full width, reclaiming the blank gutter
          that used to sit under the icon. ───────────────────────────
          Exception: vault logins and bookmarks, whose sub-line belongs to
          the favicon - a 36px chip spans title + username/URL as one block
          (the chip is exactly as tall as the two lines beside it), so the
          identity of the row reads at a glance. Falls back to the standard
          one-line layout when the preview is hidden or the note is locked. */}
      {(n.type === 'login' || isLink) && listPrefs.showPreview && !locked ? (
        <div className="flex gap-2.5">
          {iconOverride ?? <RowIcon note={n} isVault={isVault} isFile={isFile} isJournal={isJournal} hasTasks={hasTasks} trashTint={trashTint} tall />}
          <div className="min-w-0 flex-1">
            <div className="text-sm font-semibold truncate text-neutral-900 dark:text-white" dir="auto">
              {displayTitle}
            </div>
            <div className="text-[13px] text-neutral-500 dark:text-neutral-400 truncate mt-0.5" dir={isLink ? 'ltr' : 'auto'}>
              {excerpt || t('noteRow.empty')}
            </div>
          </div>
          {trailing && <span className="pn-row-actions shrink-0 self-center flex items-center gap-1">{trailing}</span>}
        </div>
      ) : (
      <>
      <div className="flex items-center gap-2.5">
        {iconOverride ?? <RowIcon note={n} isVault={isVault} isFile={isFile} isJournal={isJournal} hasTasks={hasTasks} trashTint={trashTint} />}
        <div className="min-w-0 flex-1 text-sm font-semibold truncate text-neutral-900 dark:text-white" dir="auto">
          {displayTitle}
        </div>
        {trailing && <span className="pn-row-actions shrink-0 flex items-center gap-1">{trailing}</span>}
      </div>
      {/* Preview - full width */}
      {listPrefs.showPreview && !locked && (
        <div className="text-[13px] text-neutral-500 dark:text-neutral-400 truncate mt-1" dir="auto">
          {excerpt || emptyExcerptLabel(n)}
        </div>
      )}
      </>
      )}
      {/* Meta line: date, then the status icons (starred / PIN-protected /
          read-only) directly beside it - mirrors the grid card (Concept D) so
          list and grid read the same. The icons are anchored to the date, NOT
          pushed to the row's right edge: widening the list pane is a request
          for more title, and icons that rode that edge ended up marooned in
          empty space halfway across the row. */}
      {(listPrefs.showDate || hasStatusIcons || sizeText) && (
        <div className="mt-0.5 flex items-center gap-1.5">
          {listPrefs.showDate && (
            <span className="min-w-0 text-[12px] text-neutral-400 dark:text-neutral-600 whitespace-nowrap overflow-hidden text-ellipsis">
              {dateLabel} {dateValue}
            </span>
          )}
          <span className="shrink-0 flex items-center gap-1.5 text-accent">
            {pushFailure && (
              <Warning size={12} className="text-amber-500 dark:text-amber-400" aria-label={t('noteRow.notBackedUp')} />
            )}
            {showTypeIcons && n.starred === 1 && (
              <PushPin size={12} />
            )}
            {n.pinProtected === 1 && (
              <Shield size={12} aria-label={t('noteRow.pinProtected')} />
            )}
            {n.locked === 1 && (
              <PencilSimpleSlash size={12} aria-label={t('noteRow.readOnly')} />
            )}
          </span>
          {/* Anchored to the date in normal flow, exactly like the status icons
              above it - NOT `ms-auto`. It rode the row's right edge until
              2026-08-13, which is the very thing section 66 of ui-patterns.md
              was written to stop: the pane resizes to 620px, and a value pinned
              to that edge ends up marooned in empty space with nothing to align
              against, reading as a stray number. It stays off the TITLE line
              for the original reason - there it competed with the filename for
              the space that matters most. */}
          {sizeText && (
            <span className="shrink-0 text-[11px] text-neutral-400 dark:text-neutral-500 font-medium tabular-nums">
              {sizeText}
            </span>
          )}
        </div>
      )}
      {/* Folder chip + tags - full width */}
      {listPrefs.showTags && <TagChips tags={n.tags} folderId={n.folderId} />}
    </li>
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

/** 28px icon box rendered for every row type. Color is type-based,
 *  overridden to amber when `trashTint` is true. Vault logins use
 *  favicon instead of a generic icon. */
export function RowIcon({ note, isVault, isFile, isJournal, hasTasks, trashTint, tall = false }: {
  note: LocalNote;
  isVault: boolean;
  isFile: boolean;
  isJournal: boolean;
  hasTasks: boolean;
  trashTint: boolean;
  /** 36px chip spanning the title + sub-line pair (vault logins, bookmarks). */
  tall?: boolean;
}) {
  // Contacts - the round chip: initials, or the photo when there is one.
  if (note.type === 'contact') {
    const c = parseContactBody(note.body);
    return <ContactChip name={deriveDisplayTitle(note)} initials={contactInitialsFor(note.title, c)} photo={c.photo} size={tall ? 36 : 28} trashTint={trashTint} />;
  }
  // Bookmarks - favicon chip, globe fallback.
  // In Trash the link row wears the amber BOOKMARK icon, the same rule
  // vault logins follow (login icon there, favicon only while live).
  if (note.type === 'link') return <SiteChip domain={noteFaviconDomain(note)} tall={tall} trashTint={trashTint} fallback={trashTint ? 'bookmark' : 'globe'} />;
  // Vault - favicon for logins, colored icon for cards/keys
  if (isVault) return <VaultRowIcon note={note} trashTint={trashTint} tall={tall} />;

  // Files share one boxed icon with the Files view - see FileTileIcon.
  if (isFile) return <FileTileIcon mime={fileMimeFromBody(note.body)} />;

  // Determine color classes (non-file types)
  let bg: string;
  let text: string;
  if (trashTint) {
    bg = 'bg-amber-100/80 dark:bg-amber-900/30';
    text = 'text-amber-600 dark:text-amber-400';
  } else if (isJournal) {
    bg = 'bg-purple-100/80 dark:bg-purple-900/30';
    text = 'text-purple-600 dark:text-purple-400';
  } else if (hasTasks) {
    bg = 'bg-emerald-100/80 dark:bg-emerald-900/30';
    text = 'text-emerald-600 dark:text-emerald-400';
  } else {
    bg = 'bg-accent/10 dark:bg-accent/15';
    text = 'text-accent';
  }

  return (
    <span className={`shrink-0 w-7 h-7 rounded-md ${bg} flex items-center justify-center ${text} mt-px`}>
      {isJournal ? <Book size={ROW_ICON_PX} /> : hasTasks ? <CheckSquare size={ROW_ICON_PX} /> : <File size={ROW_ICON_PX} />}
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
    <span className={`shrink-0 w-7 h-7 rounded-md bg-amber-100/80 dark:bg-amber-900/30 flex items-center justify-center text-amber-600 dark:text-amber-400 mt-px ${className}`}>
      <Icon size={ROW_ICON_PX} />
    </span>
  );
}

/**
 * Favicon chip shared by vault logins, bookmark rows and the bookmark
 * editor's URL field. Two sizes:
 *   - compact (28px box, 22px favicon) for one-line contexts,
 *   - tall (36px box, 28px favicon) when the chip spans the title + sub-line
 *     pair, so the tile is exactly as tall as the text block beside it.
 * The favicon fills most of the box on purpose - the old 18px-in-28px
 * rendering read as a dot in a frame. Fallback: Globe for bookmarks, Lock
 * for logins, amber-tinted in trash.
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
  if (domain && !trashTint) {
    return (
      <span className={`shrink-0 ${box} bg-[#f0efec] border border-black/[0.06] dark:border-white/[0.08] flex items-center justify-center mt-px overflow-hidden`}>
        <Favicon domain={domain} size={icon} />
      </span>
    );
  }
  const bg = trashTint ? 'bg-amber-100/80 dark:bg-amber-900/30' : fallback === 'lock' ? 'bg-blue-100/80 dark:bg-blue-900/30' : 'bg-sky-100/80 dark:bg-sky-900/30';
  const text = trashTint ? 'text-amber-600 dark:text-amber-400' : fallback === 'lock' ? 'text-blue-600 dark:text-blue-400' : 'text-sky-600 dark:text-sky-400';
  const FallbackIcon = fallback === 'lock' ? Lock : fallback === 'bookmark' ? BookmarkSimple : Globe;
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
export function ContactChip({ name, initials: given, photo, size, trashTint = false }: {
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
}) {
  // A path rather than a uuid is the seeded contact's picture: a static
  // asset every install already ships, so it needs no blob, no quota and
  // no sync, and it draws on a second device that never ran the seeding.
  const staticSrc = photo.startsWith('/') ? photo : '';
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
      className={`shrink-0 rounded-full overflow-hidden inline-flex items-center justify-center font-semibold select-none ${tone}`}
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
function VaultRowIcon({ note, trashTint, tall = false }: { note: LocalNote; trashTint: boolean; tall?: boolean }) {
  if (note.type === 'login') {
    if (!trashTint) {
      const domain = noteFaviconDomain(note);
      if (domain) return <SiteChip domain={domain} tall={tall} fallback="lock" />;
    }
    // Fallback / trash: standard login icon (Lock, so it stays distinct from the
    // ssh-key's Key glyph; the favicon above is the primary path for logins).
    return <SiteChip domain="" tall={tall} trashTint={trashTint} fallback="lock" />;
  }
  if (note.type === 'card') {
    const bg = trashTint ? 'bg-amber-100/80 dark:bg-amber-900/30' : 'bg-amber-100/80 dark:bg-amber-900/30';
    const text = trashTint ? 'text-amber-600 dark:text-amber-400' : 'text-amber-600 dark:text-amber-400';
    return (
      <span className={`shrink-0 w-7 h-7 rounded-md ${bg} flex items-center justify-center ${text} mt-px`}>
        <CreditCard size={ROW_ICON_PX} />
      </span>
    );
  }
  // ssh-key - terminal look (black box, white icon) so it reads distinct from
  // the journal purple it used to share.
  const bg = trashTint ? 'bg-amber-100/80 dark:bg-amber-900/30' : 'bg-neutral-900 dark:bg-black border border-white/10';
  const text = trashTint ? 'text-amber-600 dark:text-amber-400' : 'text-white';
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
 */
export function TagChips({ tags, folderId }: { tags: string[]; folderId?: string | null }) {
  const visible = useMemo(() => sortTags(tags), [tags]);
  const folderName = useFolderName(folderId);
  if (visible.length === 0 && !folderName) return null;
  return (
    <div className="mt-1.5 flex flex-wrap gap-1">
      {folderName && (
        <span className="inline-flex items-center gap-1 max-w-[12rem] text-[11px] px-1.5 py-0.5 rounded bg-accent/10 text-accent">
          <Folder size={11} className="shrink-0 text-amber-600/80 dark:text-amber-500/80" aria-hidden="true" />
          <span className="truncate" dir="auto">{folderName}</span>
        </span>
      )}
      {visible.slice(0, 4).map((t) => (
        <span
          key={t}
          dir="auto"
          className="text-[11px] px-1.5 py-0.5 rounded bg-accent/10 text-accent"
        >
          #{t}
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
  if (domain) {
    return (
      <span className="pn-card-glyph pn-card-glyph-fav shrink-0" aria-hidden="true">
        <Favicon domain={domain} size={MINI_FAVICON_PX} />
      </span>
    );
  }
  let Icon = File;
  let color = 'text-accent';
  if (type === 'file') {
    color = 'text-amber-600 dark:text-amber-400';
  } else if (type === 'journal') {
    Icon = Book;
    color = 'text-purple-600 dark:text-purple-400';
  } else if (type === 'task') {
    Icon = CheckSquare;
    color = 'text-emerald-600 dark:text-emerald-400';
  } else if (type === 'card') {
    Icon = CreditCard;
    color = 'text-amber-600 dark:text-amber-400';
  } else if (type === 'ssh-key') {
    // Mono icon (no box in the mini layout) - dark in light mode, white in dark.
    Icon = Key;
    color = 'text-neutral-900 dark:text-white';
  } else if (type === 'login') {
    // Lock (not Key) so logins stay distinct from ssh keys in the mini grid,
    // where the favicon box is hidden and this glyph shows instead.
    Icon = Lock;
    color = 'text-blue-600 dark:text-blue-400';
  } else if (type === 'link') {
    Icon = BookmarkSimple;
    color = 'text-sky-600 dark:text-sky-400';
  } else if (type === 'contact') {
    Icon = User;
    color = 'text-teal-600 dark:text-teal-400';
  }
  return <Icon size={13} className={`pn-card-glyph shrink-0 ${color}`} aria-hidden="true" />;
}
