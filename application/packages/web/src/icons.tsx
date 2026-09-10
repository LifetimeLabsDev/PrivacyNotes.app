// Central icon module - the ONLY file that imports @phosphor-icons/react.
// Components import icons from here so the sitewide style stays in one place.
// Style guide: ops/docs/ui-patterns.md (icon weights and sizes).
//
// - Default UI icons: ICON_WEIGHT (bold) at 14px via IconDefaults provider.
// - Active/toggled states (starred, pinned, selected): weight "fill".
// - Large decorative icons (empty states, heroes): weight "duotone".

import type { ReactNode } from 'react';
import type { IconProps } from '@phosphor-icons/react';
import { IconContext } from '@phosphor-icons/react';
import {
  AddressBook,
  ArrowCounterClockwise,
  ArrowSquareOut,
  UserPlus,
  Bookmark as PhBookmark,
  Bookmarks as PhBookmarks,
  BookmarkSimple,
  CheckFat,
  FileMd,
  Files as PhFiles,
  NotePencil,
  PenNib,
  PencilSimple,
  PlusSquare,
  ShieldPlus,
  SquaresFour,
  ArrowElbowDownRight as PhArrowElbowDownRight,
  ArrowLeft as PhArrowLeft,
  ArrowRight as PhArrowRight,
  ArrowsOutSimple,
  Book,
  CaretLeft as PhCaretLeft,
  CaretRight as PhCaretRight,
  CheckSquare,
  Copy,
  Download,
  Fire,
  FileHtml,
  Printer,
  Folder,
  Gear,
  Key,
  Note,
  PencilSimpleSlash,
  PushPin,
  Shield,
  Sidebar,
  SignOut,
  Trash,
  Upload,
} from '@phosphor-icons/react';

// Spec: ops/docs/ui-patterns.md (sitewide icon style)
const ICON_WEIGHT = 'bold' as const;
const ICON_WEIGHT_ACTIVE = 'fill' as const;
const ICON_SIZE = 14;

/** Wraps the app root; sets sitewide icon defaults for every Phosphor icon. */
export function IconDefaults({ children }: { children: ReactNode }) {
  return (
    <IconContext.Provider value={{ size: ICON_SIZE, weight: ICON_WEIGHT, color: 'currentColor' }}>
      {children}
    </IconContext.Provider>
  );
}

// Everything Phosphor exports is re-exported so components can import any
// icon from './icons' without touching this file. Tree-shaking keeps only
// the icons that are actually imported in the bundle.
export * from '@phosphor-icons/react';

// Spatial-navigation icons mirror under RTL: they point somewhere on screen,
// so their meaning flips with reading direction. The named exports below
// shadow the star re-export above (explicit named exports win over a star
// export for the same name), so every existing call site gets the mirror
// for free. ArrowUUpLeft/ArrowUUpRight (undo/redo) are deliberately NOT
// wrapped here: undo/redo follow the time metaphor, not reading direction,
// matching macOS and Windows Arabic conventions.
// App-wide glyph swap (2026-08-22): every "add" affordance renders
// PlusSquare - the bare Plus read too naked beside the boxed row icons.
// The explicit re-export shadows the star re-export above, so every
// `import { Plus } from './icons'` call site gets the boxed glyph for
// free, the same mechanism the RTL mirrors below use.
export { PlusSquare as Plus } from '@phosphor-icons/react';

function mirrorClassName(className?: string) {
  return className ? `rtl:-scale-x-100 ${className}` : 'rtl:-scale-x-100';
}
export function ArrowLeft(props: IconProps) {
  return <PhArrowLeft {...props} className={mirrorClassName(props.className)} />;
}
export function ArrowRight(props: IconProps) {
  return <PhArrowRight {...props} className={mirrorClassName(props.className)} />;
}
export function CaretLeft(props: IconProps) {
  return <PhCaretLeft {...props} className={mirrorClassName(props.className)} />;
}
export function CaretRight(props: IconProps) {
  return <PhCaretRight {...props} className={mirrorClassName(props.className)} />;
}
export function ArrowElbowDownRight(props: IconProps) {
  return <PhArrowElbowDownRight {...props} className={mirrorClassName(props.className)} />;
}


// Legacy helpers kept so existing call sites don't change.
/**
 * SINGLE SOURCE OF TRUTH for pillar identity glyphs. Every surface that
 * draws a pillar - the sidebar rails (TagsRail, CollapsedSidebar), the
 * view headers, the mobile pillar switcher (ListNav) - renders from THIS
 * map, so the three can never drift again (they did, 2026-08-22).
 * Row/type glyphs (RowIcon, CardGlyph) are deliberately separate.
 */
export const PILLAR_GLYPHS = {
  all: SquaresFour,
  pinned: PushPin,
  notes: NotePencil,
  tasks: CheckFat,
  vault: Key,
  files: PhFiles,
  // A nib, not a notebook. Files and Journals both used a rounded rectangle
  // with interior detail, so at rail size the two rows read as the same
  // silhouette and the pair was reported as indistinguishable. A nib shares
  // its outline with nothing else in the set.
  journals: PenNib,
  markdown: FileMd,
  bookmarks: PhBookmarks,
  contacts: AddressBook,
  trash: Trash,
} as const;

/**
 * The "create one of these" glyphs: the New buttons, the New dropdown's
 * rows, and the right-click New entries all render from this map.
 */
export const NEW_GLYPHS = {
  generic: PlusSquare,
  note: NotePencil,
  task: CheckFat,
  login: ShieldPlus,
  file: Upload,
  journal: PenNib,
  bookmark: PhBookmark,
  contact: UserPlus,
} as const;

/**
 * Glyphs for "get this note out of the app": the share menu and the note
 * context menu both list the same three destinations, and they drew different
 * pictures for them - the share menu named each format, the context menu used
 * one download arrow three times. One map, so a person learns each format once.
 * Sizes stay with the caller; the two menus draw at different scales.
 */
export const EXPORT_GLYPHS = {
  markdown: FileMd,
  html: FileHtml,
  print: Printer,
  /** Not accent, and deliberately: the flame is the one entry here that
   *  publishes something outside the account. */
  burn: Fire,
} as const;

export function iconNote() {
  return <NEW_GLYPHS.note size={14} />;
}
export function iconBookmark() {
  return <NEW_GLYPHS.bookmark size={14} />;
}
export function iconNewTask() {
  return <NEW_GLYPHS.task size={14} />;
}
export function iconNewLogin() {
  return <NEW_GLYPHS.login size={14} />;
}
export function iconNewJournal() {
  return <NEW_GLYPHS.journal size={14} />;
}
export function iconExternal() {
  return <ArrowSquareOut size={14} />;
}
export function iconEditPencil() {
  return <PencilSimple size={14} />;
}
export function iconPin(filled: boolean) {
  return <PushPin size={14} weight={filled ? ICON_WEIGHT_ACTIVE : ICON_WEIGHT} />;
}
export function iconCopy() {
  return <Copy size={14} />;
}
export function iconDownload() {
  return <Download size={14} />;
}
export function iconUpload() {
  return <Upload size={14} />;
}
export function iconTrash() {
  return <Trash size={14} />;
}
export function iconSignOut() {
  return <SignOut size={14} />;
}
export function iconCheckbox() {
  return <CheckSquare size={14} />;
}
export function iconRestore() {
  return (
    <span className="text-emerald-600 dark:text-emerald-400">
      <ArrowCounterClockwise size={14} />
    </span>
  );
}
export function iconFlame() {
  return <Fire size={14} />;
}
export function iconZen() {
  return <ArrowsOutSimple size={14} />;
}
export function iconSidebar() {
  return <Sidebar size={14} />;
}
export function iconFolder() {
  return <Folder size={14} />;
}
export function iconSettings() {
  return <Gear size={14} />;
}
export function iconReadOnly() {
  return <PencilSimpleSlash size={14} />;
}
export function iconShield() {
  return <Shield size={14} />;
}
