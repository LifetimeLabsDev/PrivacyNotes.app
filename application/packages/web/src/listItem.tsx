/**
 * One list item, two layouts. An adapter builds a `ListItem` from what the
 * pane holds (a note, a file, a link found in a note, a Markdown file), and
 * `ItemRow` and `ItemTile` only arrange it. A field belongs to the item, not
 * to a layout, so a part cannot show in the row and be missing from the tile:
 * `tests/listItemParity.test.ts` renders both and compares every `data-slot`.
 *
 * Both layouts keep the CSS hooks of `index.css` (`pn-row`, `pn-card`,
 * `pn-card-head`, `pn-card-icbox`, `pn-card-glyph`, `pn-card-title`,
 * `pn-card-titletext`, `pn-card-preview`, `pn-card-meta`, `pn-card-date`,
 * `pn-card-status`, `pn-card-actions`, `pn-ribbon`, `pn-card--select`,
 * `pn-lazy-row`, `pn-lazy-card`), so the mini tile and the lazy-paint gate
 * work unchanged.
 * Spec: ops/docs/plans/list-grid-parity.md (section 5)
 */
import type { CSSProperties, HTMLAttributes, ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { Archive, Check, CloudSlash, PencilSimpleSlash, PushPin, Shield, Warning, type Icon } from './icons';

export type ItemFlag = 'notBackedUp' | 'pinned' | 'pinProtected' | 'readOnly' | 'archived' | 'localOnly';

/** Every flag in its one draw order, with its glyph, its name and its tone.
 *  A flag missing here does not compile. */
const FLAGS: Record<ItemFlag, { Icon: Icon; label?: string; ns?: string; warn?: boolean }> = {
  notBackedUp: { Icon: Warning, label: 'noteRow.notBackedUp', warn: true },
  pinned: { Icon: PushPin },
  pinProtected: { Icon: Shield, label: 'noteRow.pinProtected' },
  readOnly: { Icon: PencilSimpleSlash, label: 'noteRow.readOnly' },
  archived: { Icon: Archive, label: 'noteRow.archived' },
  localOnly: { Icon: CloudSlash, label: 'attachment.localOnly', ns: 'media', warn: true },
};
const FLAG_ORDER = Object.keys(FLAGS) as ItemFlag[];

export interface ListItem {
  /** The note id the list's middle-click and Alt-click read, or none for an
   *  entry that is not a stored item. */
  id?: string;
  /** The boxed 28px icon. */
  icon: ReactNode;
  /** The bare glyph the mini tile shows in place of the box. */
  glyph: ReactNode;
  title: string;
  /** Null when the row carries no preview line. */
  preview: { text: string; long: boolean; dir: 'auto' | 'ltr' } | null;
  /** The label and both formats: the row prints the long one, the tile the short. */
  date: { label: string; row: string; tile: string } | null;
  size: string | null;
  flags: ItemFlag[];
  /** The folder chip and the tag chips, or null when the row shows none. */
  chips: ReactNode;
  ribbon: boolean;
  /** The tag or folder color, from `useNoteLook`. */
  look: { color?: string; style?: string; css?: CSSProperties } | null;
  /** Compact rows, set by `applyCompactRows`. */
  compact?: boolean;
}

/**
 * Compact rows applied to an item, in the data, so the row and the tile of
 * one item carry the same parts: the type icon, the mini glyph and the status
 * flags go (the warnings stay). The
 * layouts read `compact` for the rest - the short date and the flags on the
 * title line, less spacing. Adapters call it last, after any part of their own.
 */
export function applyCompactRows(item: ListItem, compact: boolean): ListItem {
  if (!compact) return item;
  // The status flags go with the icon; the two warnings stay, because they
  // say the item is not safe yet.
  const flags = item.flags.filter((f) => FLAGS[f].warn);
  return { ...item, icon: null, glyph: null, flags, compact: true };
}

/** What the pane knows about the item that the item does not. */
export interface ItemState {
  selectionMode: boolean;
  selected: boolean;
  open: boolean;
  contextTarget: boolean;
}

function itemStateClass(s: ItemState, layout: 'row' | 'tile'): string {
  if (layout === 'row') {
    return s.selected
      ? 'pn-on-tint bg-accent/15 hover:bg-accent/20 border-s-2 border-s-accent dark:bg-accent/20 dark:hover:bg-accent/25'
      : s.open
        ? 'pn-on-tint bg-accent/10 hover:bg-accent/15 border-s-2 border-s-accent dark:bg-accent/15 dark:hover:bg-accent/20'
        : s.contextTarget
          ? 'pn-on-tint bg-pn/10 hover:bg-pn/10'
          : 'hover:bg-pn/5';
  }
  return s.selected
    ? 'pn-on-tint bg-accent/15 border-accent dark:bg-accent/20'
    : s.open
      ? 'pn-on-tint bg-accent/10 border-accent dark:bg-accent/15'
      : s.contextTarget
        ? 'pn-on-tint bg-pn/10 border-divider'
        : 'bg-surface-2 border-divider hover:border-accent/60 hover:bg-pn/5';
}

/** The flag icons, in their one order. `onImage` is the white-on-photo tone of
 *  a picture tile. */
export function ItemFlags({ flags, size = 12, onImage = false }: { flags: readonly ItemFlag[]; size?: number; onImage?: boolean }) {
  const { t } = useTranslation('notes');
  return (
    <>
      {FLAG_ORDER.filter((f) => flags.includes(f)).map((f) => {
        const { Icon, label, ns, warn } = FLAGS[f];
        const tone = warn ? (onImage ? 'text-amber-400' : 'text-warning') : '';
        return (
          <Icon
            key={f}
            size={size}
            className={`${onImage ? 'shrink-0 ' : ''}${tone}`.trim() || undefined}
            aria-label={label ? t(label, ns ? { ns } : undefined) : undefined}
          />
        );
      })}
    </>
  );
}

/** Handlers and element props the pane hands the item's root. */
export type ItemRootProps = HTMLAttributes<HTMLElement> & {
  draggable?: boolean;
  type?: 'button';
};

interface LayoutProps {
  item: ListItem;
  state: ItemState;
  /** `li` in a list, `button` in the Files pane, whose rows sit in a div. */
  as?: 'li' | 'button';
  rootProps?: ItemRootProps;
  onToggleSelect?: (e: React.MouseEvent) => void;
  /** Always-visible actions: at the end of the title line in a row, on the
   *  footer of a tile. */
  trailing?: ReactNode;
}

function SelectBox({ selected, onToggle, layout, compact = false }: { selected: boolean; onToggle?: (e: React.MouseEvent) => void; layout: 'row' | 'tile'; compact?: boolean }) {
  const { t } = useTranslation('notes');
  return (
    <span
      onClick={(e) => {
        e.stopPropagation();
        onToggle?.(e);
      }}
      aria-label={selected ? t('noteRow.deselect') : t('noteRow.select')}
      role="checkbox"
      aria-checked={selected}
      className={`absolute ${layout === 'row' ? (compact ? 'start-3 top-2' : 'start-3 top-3.5') : 'start-2 top-2 z-10'} w-5 h-5 rounded border flex items-center justify-center transition shrink-0 ${
        selected ? 'bg-accent-fill border-accent-fill text-white' : 'bg-surface-2 border-divider hover:border-accent'
      }`}
    >
      {selected && <Check size={12} />}
    </span>
  );
}

function rootAttrs(item: ListItem, state: ItemState) {
  return {
    // Read by the list pane's one middle-click and Alt-click handler, which
    // opens the item as a tab. Spec: ops/docs/plans/note-tabs.md
    'data-item-id': item.id,
    'aria-current': state.open || undefined,
    style: item.look?.css,
    'data-color': item.look?.color,
    'data-color-style': item.look?.style,
  };
}

/**
 * The list row: icon and title on the first line; preview, the meta line
 * (date, flags, size) and the chips below it at full width. The flags and the
 * size are anchored to the date, never to the row's end, where a wide pane
 * would strand them (ui-patterns.md section 66).
 */
export function ItemRow({ item, state, as: Root = 'li', rootProps, onToggleSelect, trailing }: LayoutProps) {
  const onTitle = flagsOnTitle(item);
  const meta = !onTitle && (item.date || item.flags.length > 0 || item.size);
  const compact = !!item.compact;
  return (
    <Root
      {...rootAttrs(item, state)}
      {...rootProps}
      // Touch only: long-press is the multi-select gesture, so the row must
      // not also hand the WebView something to select. Spec: issue #208.
      className={`pn-row pn-lazy-row relative ${Root === 'button' ? 'block w-full text-start ' : ''}px-4 ${compact ? 'py-2' : 'py-3'} cursor-pointer border-b border-divider/50 transition [@media(hover:none)]:select-none ${itemStateClass(state, 'row')} ${state.selectionMode ? 'ps-10' : ''}`}
    >
      {/* The saved-link marker, see the .pn-ribbon rules in index.css. */}
      {item.ribbon && <span data-slot="ribbon" className="pn-ribbon" aria-hidden="true" />}
      {state.selectionMode && <SelectBox selected={state.selected} onToggle={onToggleSelect} layout="row" compact={compact} />}
      {/* A compact row's date, or a row's lone flags, end the title line, in
          the corner the ribbon claims (16px from the end, 14px wide), so the
          line stops short of it. */}
      <div className={`flex items-center gap-2.5${(compact || onTitle) && item.ribbon ? ' pe-5' : ''}`}>
        {item.icon && <span data-slot="icon" className="contents">{item.icon}</span>}
        <div data-slot="title" className="min-w-0 flex-1 text-sm font-semibold truncate text-pn" dir="auto">
          {item.title}
        </div>
        {onTitle && (
          <span data-slot="flags" className="shrink-0 flex items-center gap-1.5 text-accent">
            <ItemFlags flags={item.flags} />
          </span>
        )}
        {/* Compact rows carry the short date, the flags and the size at the
            end of the title line. */}
        {compact && meta && <MetaLine item={item} form="tile" />}
        {trailing && <span className="pn-row-actions shrink-0 flex items-center gap-1">{trailing}</span>}
      </div>
      {item.preview && (
        <div data-slot="preview" className={`text-[13px] text-pn-muted ${compact ? 'mt-0.5' : 'mt-1'} ${item.preview.long ? 'pn-preview-long' : 'truncate'}`} dir={item.preview.dir}>
          {item.preview.text}
        </div>
      )}
      {!compact && meta && (
        <div className="mt-0.5 flex items-center gap-1.5">
          <MetaLine item={item} form="row" />
        </div>
      )}
      {item.chips}
    </Root>
  );
}

/** True when a row's flags are its only meta: they then end the title line
 *  instead of standing alone on a line of their own. */
function flagsOnTitle(item: ListItem): boolean {
  return !item.date && !item.size && item.flags.length > 0;
}

/** The date, the flags and the size, anchored to one another, never to the
 *  item's end, where a wide pane would strand them (ui-patterns.md section
 *  66). A compact item prints the date without its label. */
function MetaLine({ item, form }: { item: ListItem; form: 'row' | 'tile' }) {
  const compact = !!item.compact;
  const date = item.date && (compact ? item.date.tile : `${item.date.label} ${item.date[form]}`);
  return (
    <>
      {date && (
        <span data-slot="date" className={`${form === 'tile' && !compact ? 'pn-card-date ' : ''}${compact ? 'shrink-0' : 'min-w-0'} text-[12px] text-pn-muted whitespace-nowrap overflow-hidden text-ellipsis`}>
          {date}
        </span>
      )}
      <span data-slot="flags" className={`${form === 'tile' ? 'pn-card-status ' : ''}shrink-0 flex items-center gap-1.5 text-accent`}>
        <ItemFlags flags={item.flags} />
      </span>
      {item.size && (
        <span data-slot="size" className="shrink-0 text-[11px] text-pn-muted font-medium tabular-nums">
          {item.size}
        </span>
      )}
    </>
  );
}

/**
 * The grid tile: the parts the row shows, as a card. The chips sit above the
 * meta line so `margin-top: auto` (index.css) pins the date to the tile's
 * bottom and dates line up across a grid row. On small tiles the container
 * query hides the boxed icon and shows the glyph beside the title.
 */
export function ItemTile({ item, state, as: Root = 'li', rootProps, onToggleSelect, trailing }: LayoutProps) {
  // A tile keeps its flags on the meta line even alone: floated into a mini
  // tile's wrapping title they pushed the first word below the glyph.
  const meta = item.date || item.flags.length > 0 || item.size;
  return (
    <Root
      {...rootAttrs(item, state)}
      {...rootProps}
      className={`pn-card pn-lazy-card relative flex flex-col gap-1.5 rounded-xl border p-3 cursor-pointer text-start transition [@media(hover:none)]:select-none ${
        state.selectionMode ? 'pn-card--select ' : ''
      }${itemStateClass(state, 'tile')}`}
    >
      {/* The ribbon owns the tile's top END corner, which is why the checkbox
          sits at the START edge the way the row's does. */}
      {item.ribbon && <span data-slot="ribbon" className="pn-ribbon" aria-hidden="true" />}
      {state.selectionMode && <SelectBox selected={state.selected} onToggle={onToggleSelect} layout="tile" />}
      <div className="pn-card-head flex items-center gap-2.5 min-w-0">
        {item.icon && <span data-slot="icon" className="pn-card-icbox contents">{item.icon}</span>}
        <div className={`pn-card-title${item.glyph ? '' : ' pn-card-title--bare'} min-w-0 flex-1 text-sm font-semibold truncate flex items-center gap-1.5 text-pn`}>
          {item.glyph}
          <span data-slot="title" className="pn-card-titletext truncate" dir="auto">{item.title}</span>
        </div>
      </div>
      {item.preview && (
        <div data-slot="preview" className={`pn-card-preview${item.preview.long ? ' pn-preview-long' : ''} text-[13px] text-pn-muted leading-snug`} dir={item.preview.dir}>
          {item.preview.text}
        </div>
      )}
      {item.chips}
      {meta && (
        <div className="pn-card-meta flex items-center gap-1.5">
          <MetaLine item={item} form="tile" />
        </div>
      )}
      {/* The buttons stop propagation themselves, so the tile's own click
          stays intact. */}
      {trailing && <span className="pn-card-actions flex items-center gap-1 pt-1">{trailing}</span>}
    </Root>
  );
}
