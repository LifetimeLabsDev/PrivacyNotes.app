/**
 * The data a dragged list item carries.
 *
 * Two types travel on one drag. `text/plain` holds the item's note-links,
 * which an editor drop turns into links. ITEM_TYPE holds the item ids, which
 * a sidebar folder or tag row reads. A drag of an untitled item has ids and
 * no link text, so it files but never links. `text/html` is never written:
 * the editor would read it instead of the plain text and skip the link rule.
 *
 * The ids carry no content. The link text, which names the notes, travels on
 * the same drag.
 *
 * Every target takes the drop as a copy, so the cursor shows the same plus
 * over an editor, a tag and a folder.
 * Spec: ops/docs/archive/drag-to-folder-and-tag.md (section 6)
 */

export const ITEM_TYPE = 'application/x-privacynotes-items';

/** What one drag carries: the ids, and the link text (empty when none). */
export interface ItemDragPayload {
  ids: string[];
  linkText: string;
}

/** Write a list item's drag. Clears what the browser put there first. */
export function writeItemDrag(dt: DataTransfer, ids: readonly string[], linkText: string): void {
  dt.clearData();
  if (linkText) dt.setData('text/plain', linkText);
  dt.setData(ITEM_TYPE, JSON.stringify(ids));
  dt.effectAllowed = 'copy';
}

/**
 * The drag picture: a chip with the row's own icon and title, and "+N" when
 * the drag carries more items. The browser's default picture is the whole
 * row at full size, which covers the rows a drop aims at. The chip is built
 * off screen, taken by the browser during `dragstart`, and removed on the
 * next task. `row` is a list row or tile, read through its `data-slot` parts.
 */
export function setItemDragImage(dt: DataTransfer, row: Element, count: number): void {
  const chip = document.createElement('div');
  chip.className =
    'pointer-events-none fixed top-[-1000px] start-0 inline-flex max-w-[260px] items-center gap-2 rounded-lg border border-divider bg-surface-2 py-1 ps-1 pe-3 text-[13px] font-medium text-pn';
  const icon = row.querySelector('[data-slot="icon"]');
  if (icon) {
    const box = document.createElement('span');
    // The row's icon is 28 px, 36 for a login or a bookmark: smaller here.
    box.className = 'inline-flex shrink-0 [zoom:0.75]';
    box.append(icon.cloneNode(true));
    chip.append(box);
  }
  const title = document.createElement('span');
  title.className = 'min-w-0 truncate';
  title.dir = 'auto';
  title.textContent = row.querySelector('[data-slot="title"]')?.textContent ?? '';
  chip.append(title);
  if (count > 1) {
    const more = document.createElement('span');
    more.className = 'shrink-0 rounded-full bg-accent-fill px-1.5 text-[11px] font-semibold tabular-nums text-white';
    more.textContent = `+${count - 1}`;
    chip.append(more);
  }
  document.body.append(chip);
  // The pointer sits on the icon, the way a file manager holds a dragged file.
  dt.setDragImage(chip, 14, 14);
  setTimeout(() => chip.remove(), 0);
}

/**
 * True when the drag came from a list item. Safe in `dragenter` and
 * `dragover`, where the browser shows the type names and hides the data.
 */
export function isItemDrag(dt: DataTransfer | null): boolean {
  return !!dt && Array.from(dt.types).includes(ITEM_TYPE);
}

/**
 * The ids of a list-item drag, read at `drop`. Anything but a JSON array of
 * non-empty strings yields none, so a malformed or foreign value moves
 * nothing. Duplicates go.
 */
export function readItemDrag(dt: DataTransfer | null): string[] {
  if (!dt) return [];
  let value: unknown;
  try {
    value = JSON.parse(dt.getData(ITEM_TYPE));
  } catch {
    return [];
  }
  if (!Array.isArray(value) || !value.every((v) => typeof v === 'string' && v !== '')) return [];
  return [...new Set(value as string[])];
}

/** The ids that name a live item, in the order given. `active` is the
 *  untrashed notes; the store already holds no deleted rows. */
export function liveItemIds(ids: readonly string[], active: readonly { id: string }[]): string[] {
  const live = new Set(active.map((n) => n.id));
  return ids.filter((id) => live.has(id));
}
