/**
 * The one way a folder or tag glyph is drawn, anywhere: the sidebar, the Move
 * to folder window, the tag picker, the editor's chips. Each resolves the
 * picked icon or the default glyph, and the color or none, so no surface keeps
 * a rule of its own about what a folder looks like.
 *
 * A context feeds them, the way FolderNamesContext feeds the folder chip:
 * the glyphs sit deep inside components that never read the settings.
 * NotesView provides it once, so a pick redraws every glyph at once.
 *
 * The caller keeps its size and its color classes. A color, when there is
 * one, is set on the glyph itself and so wins over the caller's amber; an
 * active row keeps its colored glyph, because its background already says
 * that it is active.
 * Spec: ops/docs/plans/folder-tag-icons.md (section 7)
 */
import { createContext, useContext, useMemo, type CSSProperties } from 'react';
import { Folder, Hash, Star } from '../icons';
import {
  folderColor,
  folderLookKey,
  isLookColor,
  lookOf,
  resolveItemColor,
  tagLookKey,
  type ColorFilter,
  type ItemStyles,
  type LookColor,
} from '../itemStyles';
import { useLookIcons } from './lookIconsLoader';

export interface LooksValue {
  styles: ItemStyles;
  /** The "Color note backgrounds" switch: rows, tiles and the open note. */
  tintNotes: boolean;
  /** The list's tag and folder filter, whose colors win (resolveItemColor). */
  filter?: ColorFilter;
}

export const LooksContext = createContext<LooksValue>({ styles: {}, tintNotes: false });

/** For a list whose items are outside the looks: Markdown files carry tags
 *  of their own, which must not take a vault tag's look. */
export const NO_LOOKS: LooksValue = { styles: {}, tintNotes: false };

/** A note's color, or null while the switch is off or none applies. */
export function useNoteColor(tags: readonly string[], folderId: string | null): LookColor | null {
  const { styles, tintNotes, filter } = useContext(LooksContext);
  return useMemo(
    () => (tintNotes ? resolveItemColor(tags, folderId, styles, filter) : null),
    [tags, folderId, styles, tintNotes, filter],
  );
}

/** A color as a light background, drawn as an image so the background color
 *  of a state underneath (open, selected, hover) still shows through. */
export function tintStyle(color: LookColor | null): CSSProperties | undefined {
  return color
    ? { backgroundImage: `linear-gradient(var(--pn-label-${color}-tint), var(--pn-label-${color}-tint))` }
    : undefined;
}

/** The open note's color, as a variable the note body reads (index.css,
 *  `--pn-note-tint`), so the body takes it and the chrome around it does not. */
export function noteTintVars(color: LookColor | null): CSSProperties | undefined {
  return color ? ({ '--pn-note-tint': `var(--pn-label-${color}-tint)` } as CSSProperties) : undefined;
}

export function inkStyle(color: LookColor | null): CSSProperties | undefined {
  return color ? { color: `var(--pn-label-${color}-ink)` } : undefined;
}

/**
 * A look icon from its generated paths: Phosphor's own 256 box and bold
 * weight, filled with the current color like every Phosphor icon, and sized
 * by the caller the same way.
 */
export function PathGlyph({
  paths,
  size = 14,
  className,
  style,
}: {
  paths: readonly string[];
  size?: number;
  className?: string;
  style?: CSSProperties;
}) {
  return (
    <svg
      xmlns="http://www.w3.org/2000/svg"
      width={size}
      height={size}
      viewBox="0 0 256 256"
      fill="currentColor"
      className={className}
      style={style}
      aria-hidden="true"
    >
      {paths.map((d, i) => (
        <path key={i} d={d} />
      ))}
    </svg>
  );
}

/** A folder's glyph: its own icon and its own color. */
export function FolderGlyph({
  folderId,
  size,
  className,
}: {
  folderId: string;
  size?: number;
  className?: string;
}) {
  const { styles } = useContext(LooksContext);
  const icon = lookOf(styles, folderLookKey(folderId)).icon;
  const catalog = useLookIcons(icon !== null);
  const paths = icon ? catalog?.LOOK_ICONS[icon] : undefined;
  const style = inkStyle(folderColor(folderId, styles));
  if (paths) return <PathGlyph paths={paths} size={size} className={className} style={style} />;
  return <Folder size={size} className={className} style={style} aria-hidden="true" />;
}

/** A tag's glyph: its icon, else the filled star of a favorite, else the
 *  hash. A favorite with an icon wears the icon; the caller's brighter amber
 *  still marks it when the tag has no color of its own. */
export function TagGlyph({
  tag,
  favorite = false,
  size,
  className,
}: {
  tag: string;
  favorite?: boolean;
  size?: number;
  className?: string;
}) {
  const { styles } = useContext(LooksContext);
  const look = lookOf(styles, tagLookKey(tag));
  const catalog = useLookIcons(look.icon !== null);
  const paths = look.icon ? catalog?.LOOK_ICONS[look.icon] : undefined;
  const style = inkStyle(isLookColor(look.color) ? look.color : null);
  if (paths) return <PathGlyph paths={paths} size={size} className={className} style={style} />;
  if (favorite) {
    return <Star size={size} weight="fill" className={className} style={style} aria-hidden="true" />;
  }
  return <Hash size={size} className={className} style={style} aria-hidden="true" />;
}

/**
 * The mark before a tag's name in a text chip or pill: its icon when it has
 * one, else the `#` it always had, in the tag's color when it has one.
 */
export function TagMark({ tag, size = 12 }: { tag: string; size?: number }) {
  const { styles } = useContext(LooksContext);
  const look = lookOf(styles, tagLookKey(tag));
  const catalog = useLookIcons(look.icon !== null);
  const paths = look.icon ? catalog?.LOOK_ICONS[look.icon] : undefined;
  const style = inkStyle(isLookColor(look.color) ? look.color : null);
  if (paths) {
    return <PathGlyph paths={paths} size={size} className="shrink-0 self-center me-0.5" style={style} />;
  }
  return (
    <span style={style} aria-hidden="true">
      #
    </span>
  );
}
