/**
 * The format bar a person arranges: every toolbar item, where it lives by
 * default, and the rules that turn a saved arrangement into the bar, the '+'
 * menu and the hidden set.
 *
 * Every item has three possible homes: the bar, the '+' menu (in the
 * person's order inside its own group), or hidden. The bar has two zones,
 * both in the person's order: the row, which gives way behind the "•••" when
 * the bar is narrow, and the end, after the '+', which always stays visible.
 * Two kinds of item never go into the menu: a control that opens a React
 * popover, because the menu closes on the press that would open it, and the
 * recorder, whose button shows the running recording.
 *
 * The saved arrangement names every list, so a key in none of them is an
 * item a later version added. It takes its stock home and stock position, so
 * a person who arranged the bar still meets the new button.
 * Spec: ops/docs/plans/format-bar.md
 */
import {
  mergeRegisterMaps,
  registerMapsEqual,
  stampAfter,
  validateRegisterMap,
  type RegisterMap,
} from './registers';

/** Where an item lives. `bar` and `end` are the two zones of the bar. */
export type FormatBarHome = 'bar' | 'end' | 'menu' | 'hidden';
export type FormatBarGroup = 'format' | 'insert' | 'blocks' | 'notation';

export type FormatBarItem = {
  key: string;
  /** Stock home. */
  home: 'bar' | 'end' | 'menu';
  /** The menu group the item sits in when it is in the menu. */
  group: FormatBarGroup;
  /** False for a popover trigger and for the recorder: on the bar or hidden. */
  menuAllowed: boolean;
};

const row = (key: string, menuAllowed = true): FormatBarItem => ({ key, home: 'bar', group: 'format', menuAllowed });
const menu = (key: string, group: FormatBarGroup): FormatBarItem => ({ key, home: 'menu', group, menuAllowed: true });
const end = (key: string, menuAllowed = true): FormatBarItem => ({ key, home: 'end', group: 'insert', menuAllowed });

/** Stock order: the row, the menu, then the end of the bar. */
export const FORMAT_BAR_ITEMS: readonly FormatBarItem[] = [
  row('bold'), row('italic'), row('underline'), row('heading', false), row('tasks'),
  row('link', false), row('notelink'),
  row('color', false), row('align', false), row('font', false),
  row('highlight', false), row('callout', false), row('strike'),
  menu('table', 'insert'), menu('hr', 'insert'), menu('bullets', 'insert'), menu('numbered', 'insert'),
  menu('fromFiles', 'insert'), menu('date', 'insert'), menu('dateTime', 'insert'),
  menu('quote', 'blocks'), menu('codeblock', 'blocks'), menu('copybox', 'blocks'),
  menu('inlinecode', 'notation'), menu('math', 'notation'), menu('blockmath', 'notation'),
  menu('superscript', 'notation'), menu('subscript', 'notation'), menu('spoiler', 'notation'),
  menu('footnote', 'notation'),
  end('image'), end('attach'), end('audio', false),
];

export const FORMAT_BAR_GROUPS: readonly FormatBarGroup[] = ['format', 'insert', 'blocks', 'notation'];

const BY_KEY = new Map(FORMAT_BAR_ITEMS.map((i) => [i.key, i]));
const STOCK_INDEX = new Map(FORMAT_BAR_ITEMS.map((i, n) => [i.key, n]));

export function formatBarItem(key: string): FormatBarItem | undefined {
  return BY_KEY.get(key);
}

/** What a person saved. */
export type FormatBarLayout = { bar: string[]; end: string[]; menu: string[]; hidden: string[] };

/** What the toolbar draws. */
export type ResolvedFormatBar = {
  /** The row, in order. */
  bar: string[];
  /** The end of the bar, after the '+', in order; it always stays visible. */
  end: string[];
  /** Menu items, grouped in FORMAT_BAR_GROUPS order, the person's order inside a group. */
  menu: string[];
  hidden: string[];
};

const byStock = (a: string, b: string) => STOCK_INDEX.get(a)! - STOCK_INDEX.get(b)!;

/** Menu order: by group, then the given order inside each group. */
function groupMenu(keys: string[]): string[] {
  return FORMAT_BAR_GROUPS.flatMap((g) => keys.filter((k) => BY_KEY.get(k)!.group === g));
}

/**
 * Put `key` into `list` at its stock place: before the first key that follows
 * it in stock order and is already in the list, else at the end. `sameRun`
 * limits the comparison to keys of the same menu group.
 */
function insertAtStockPlace(list: string[], key: string, sameRun: (k: string) => boolean = () => true): void {
  const at = list.findIndex((k) => sameRun(k) && byStock(k, key) > 0);
  if (at === -1) {
    // After the last key of the same run, so a menu item lands in its group.
    let last = -1;
    list.forEach((k, n) => { if (sameRun(k)) last = n; });
    list.splice(last === -1 ? list.length : last + 1, 0, key);
  } else {
    list.splice(at, 0, key);
  }
}

export function stockFormatBar(): ResolvedFormatBar {
  const stock = (home: FormatBarItem['home']) => FORMAT_BAR_ITEMS.filter((i) => i.home === home).map((i) => i.key);
  return { bar: stock('bar'), end: stock('end'), menu: groupMenu(stock('menu')), hidden: [] };
}

function strings(raw: unknown): string[] {
  return Array.isArray(raw) ? raw.filter((k): k is string => typeof k === 'string') : [];
}

/**
 * An item that some editors do not offer: a Markdown folder note has no
 * picture, file, recording or "picture from Files", and the Linux app has no
 * recorder. None of them counts as the button that keeps a bar usable, or
 * that editor could draw an empty bar.
 */
const SOMETIMES_ABSENT = new Set(['fromFiles', 'image', 'attach', 'audio']);
const keepsBar = (k: string) => !SOMETIMES_ABSENT.has(k);

/**
 * Turn a saved arrangement into what the toolbar draws. Total: any input,
 * however malformed, gives a usable bar.
 */
export function resolveFormatBar(saved: Partial<FormatBarLayout> | null | undefined): ResolvedFormatBar {
  if (!saved || typeof saved !== 'object') return stockFormatBar();
  const seen = new Set<string>();
  const take = (raw: unknown) => strings(raw).filter((k) => {
    if (!BY_KEY.has(k) || seen.has(k)) return false;
    seen.add(k);
    return true;
  });
  const bar = take(saved.bar);
  const endList = take(saved.end);
  const menuList: string[] = [];
  for (const k of take(saved.menu)) {
    // An item that cannot be in the menu goes back to the end of the bar.
    if (BY_KEY.get(k)!.menuAllowed) menuList.push(k);
    else endList.push(k);
  }
  const hidden = take(saved.hidden);

  // Items no list names: a later version added them. Stock home, stock place.
  for (const item of FORMAT_BAR_ITEMS) {
    if (seen.has(item.key)) continue;
    if (item.home === 'bar') insertAtStockPlace(bar, item.key);
    else if (item.home === 'end') insertAtStockPlace(endList, item.key);
    else insertAtStockPlace(menuList, item.key, (k) => BY_KEY.get(k)!.group === item.group);
  }

  // A bar with no button every editor offers is never what a person saved
  // (the Settings board keeps one); it is damage, and the stock arrangement
  // is the safe answer.
  if (![...bar, ...endList].some(keepsBar)) return stockFormatBar();

  return { bar, end: endList, menu: groupMenu(menuList), hidden };
}

/** The arrangement to save for what the board shows. */
export function layoutOf(r: ResolvedFormatBar): FormatBarLayout {
  return { bar: [...r.bar], end: [...r.end], menu: [...r.menu], hidden: [...r.hidden] };
}

export function isStockFormatBar(r: ResolvedFormatBar): boolean {
  const s = stockFormatBar();
  return r.bar.join() === s.bar.join() && r.end.join() === s.end.join()
    && r.menu.join() === s.menu.join() && r.hidden.length === 0;
}

export function homeOf(r: ResolvedFormatBar, key: string): FormatBarHome | null {
  for (const home of ['bar', 'end', 'menu', 'hidden'] as const) if (r[home].includes(key)) return home;
  return null;
}

/** Why a move is refused, or null when it is allowed. */
export type FormatBarRefusal = 'menuNotAllowed' | 'lastOnBar' | null;

export function refusalFor(r: ResolvedFormatBar, key: string, to: FormatBarHome): FormatBarRefusal {
  const item = BY_KEY.get(key);
  if (!item) return null;
  if (to === 'menu' && !item.menuAllowed) return 'menuNotAllowed';
  const onBar = [...r.bar, ...r.end];
  if ((to === 'menu' || to === 'hidden') && onBar.includes(key) && !onBar.some((k) => k !== key && keepsBar(k))) {
    return 'lastOnBar';
  }
  return null;
}

/**
 * Move `key` to `to`, before `beforeKey` when that key is in the same list
 * (and, for the menu, the same group), else to the end of the list or group.
 * Returns the input unchanged when the move is refused.
 */
export function placeItem(r: ResolvedFormatBar, key: string, to: FormatBarHome, beforeKey: string | null = null): ResolvedFormatBar {
  const item = BY_KEY.get(key);
  if (!item || refusalFor(r, key, to)) return r;
  const out: ResolvedFormatBar = {
    bar: r.bar.filter((k) => k !== key),
    end: r.end.filter((k) => k !== key),
    menu: r.menu.filter((k) => k !== key),
    hidden: r.hidden.filter((k) => k !== key),
  };
  if (to === 'menu') {
    const sameGroup = (k: string) => BY_KEY.get(k)!.group === item.group;
    const at = beforeKey && sameGroup(beforeKey) ? out.menu.indexOf(beforeKey) : -1;
    if (at >= 0) {
      out.menu.splice(at, 0, key);
    } else {
      let last = -1;
      out.menu.forEach((k, n) => { if (sameGroup(k)) last = n; });
      if (last === -1) {
        out.menu.push(key);
        out.menu = groupMenu(out.menu);
      } else {
        out.menu.splice(last + 1, 0, key);
      }
    }
    return out;
  }
  const list = out[to];
  const at = beforeKey ? list.indexOf(beforeKey) : -1;
  if (at >= 0) list.splice(at, 0, key);
  else list.push(key);
  return out;
}

/**
 * Move `key` one step inside its own list (and, in the menu, its own group).
 * The bar's two zones are one line: a step past the row's last place goes to
 * the start of the end, and a step back from the end's first place goes to
 * the row's last.
 */
export function stepItem(r: ResolvedFormatBar, key: string, dir: -1 | 1): ResolvedFormatBar {
  const home = homeOf(r, key);
  if (!home || home === 'hidden') return r;
  const list = [...r[home]];
  const at = list.indexOf(key);
  const to = at + dir;
  if (home === 'bar' && to >= list.length) {
    return { ...r, bar: list.filter((k) => k !== key), end: [key, ...r.end] };
  }
  if (home === 'end' && to < 0) {
    return { ...r, bar: [...r.bar, key], end: list.filter((k) => k !== key) };
  }
  if (to < 0 || to >= list.length) return r;
  if (home === 'menu' && BY_KEY.get(list[to]!)!.group !== BY_KEY.get(key)!.group) return r;
  [list[at], list[to]] = [list[to]!, list[at]!];
  return { ...r, [home]: list };
}

/** Whether `stepItem` would move the item. */
export function canStep(r: ResolvedFormatBar, key: string, dir: -1 | 1): boolean {
  return stepItem(r, key, dir) !== r;
}

// ------------------------------------------------------------------
// Storage: one register in the settings blob
// ------------------------------------------------------------------

/**
 * The settings field. A register map with one key, so it merges like the
 * looks and the custom themes: the later stamp wins at every sync point, and
 * a device that pushes an old blob after some other change cannot take an
 * arrangement back. The value is the arrangement as JSON; null is "stock".
 */
export type FormatBarSetting = RegisterMap;

const REGISTER_KEY = 'layout';
const JSON_MAX = 4096;

export function validateFormatBarSetting(raw: unknown, now = Date.now()): FormatBarSetting {
  return validateRegisterMap(raw, (k) => k === REGISTER_KEY, JSON_MAX, now);
}

export function mergeFormatBarSettings(local: FormatBarSetting, remote: FormatBarSetting, now = Date.now()): FormatBarSetting {
  return mergeRegisterMaps(local, remote, now);
}

export const formatBarSettingsEqual = registerMapsEqual;

/** The saved arrangement, or null for stock (no register, a reset, or bad JSON). */
export function readFormatBarSetting(setting: FormatBarSetting | undefined): FormatBarLayout | null {
  const v = setting?.[REGISTER_KEY]?.v;
  if (typeof v !== 'string') return null;
  try {
    const parsed = JSON.parse(v) as unknown;
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return null;
    const p = parsed as Record<string, unknown>;
    return { bar: strings(p.bar), end: strings(p.end), menu: strings(p.menu), hidden: strings(p.hidden) };
  } catch {
    return null;
  }
}

/** Write an arrangement; the stock one is written as a reset. */
export function writeFormatBarSetting(setting: FormatBarSetting, next: ResolvedFormatBar | null): FormatBarSetting {
  const prev = setting[REGISTER_KEY];
  const v = !next || isStockFormatBar(next) ? null : JSON.stringify(layoutOf(next));
  if (prev ? prev.v === v : v === null) return setting;
  return { ...setting, [REGISTER_KEY]: { v, at: stampAfter(prev?.at) } };
}
