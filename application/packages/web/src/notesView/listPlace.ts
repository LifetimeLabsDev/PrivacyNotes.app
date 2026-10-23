/**
 * Where the person was, so a switch of view or space and back lands on the
 * same place: each list's selected item and scroll offset, and the reading
 * line of each note.
 *
 * Module state and never storage: it lives as long as the page, and an
 * anchor holds words of the note's text, which must not reach the disk in
 * the clear. The one thing that outlives the page is the id of the note last
 * open, which a cold start opens again.
 * Spec: ops/docs/archive/keep-my-place.md
 */
import { isDemoMode } from '../demo';
import type { ViewAnchor } from '../viewSwitchAnchor';

type ListPlace = { top: number; revealed: number };

const lists = new Map<string, ListPlace>();
const selections = new Map<string, string | null>();
const anchors = new Map<string, ViewAnchor>();
type ItemSize = { width: number; height: number };
const itemSizes = new Map<string, Map<string, ItemSize>>();

/** Geometry follows an item id across refreshed database objects. */
export function windowItemSizes(id: string): Map<string, ItemSize> {
  let sizes = itemSizes.get(id);
  if (!sizes) itemSizes.set(id, sizes = new Map());
  return sizes;
}
/** The oldest anchor is dropped past this many notes. */
const ANCHOR_CAP = 50;

/** A list's offset and how many of its rows were drawn. */
export function rememberListTop(key: string, top: number, revealed: number): void {
  // The initial slice can restore the top; old off-screen rows need not remount.
  lists.set(key, { top, revealed: top === 0 ? 0 : revealed });
}

export function listTop(key: string): ListPlace | null {
  return lists.get(key) ?? null;
}

/** The item open in a list scope; null when the person closed the editor. */
export function rememberSelection(scope: string, id: string | null): void {
  selections.set(scope, id);
}

/** Undefined when this scope was never visited. */
export function rememberedSelection(scope: string): string | null | undefined {
  return selections.get(scope);
}

/** Null forgets the note's line: it was read from its top. */
export function rememberNoteAnchor(id: string, anchor: ViewAnchor | null): void {
  anchors.delete(id);
  if (!anchor) return;
  anchors.set(id, anchor);
  if (anchors.size > ANCHOR_CAP) anchors.delete(anchors.keys().next().value!);
}

export function noteAnchor(id: string): ViewAnchor | null {
  return anchors.get(id) ?? null;
}

/** Sign-out: the next account starts with no place. */
export function clearPlaces(): void {
  lists.clear();
  selections.clear();
  anchors.clear();
  itemSizes.clear();
}

const LAST_OPEN_KEY = 'privacynotes.lastOpen';

/** The demo shares its origin with a real install, so it keeps its own copy
 *  in sessionStorage, as the open tabs do. */
function store(): Storage {
  return isDemoMode() ? sessionStorage : localStorage;
}

/** The note open at the last quit, or null. */
export function readLastOpen(): string | null {
  try {
    const id = store().getItem(LAST_OPEN_KEY);
    return id && id.length <= 64 ? id : null;
  } catch {
    return null;
  }
}

/** Only an id is written, never cleared on a close: a switch to a view with
 *  nothing open must not forget the note a cold start brings back. */
export function writeLastOpen(id: string): void {
  try { store().setItem(LAST_OPEN_KEY, id); } catch { /* storage unavailable */ }
}
