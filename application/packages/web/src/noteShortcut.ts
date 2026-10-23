import { APP_ORIGIN, isApexHost } from './hosts';
import { isDemoMode } from './demo';

/**
 * A shortcut is an address that opens one item of the signed-in vault, and
 * optionally one heading in it: `https://use.privacynotes.app/note#<id>` or
 * `.../note#<id>/h-<code>`. The desktop form `privacynotes://note/<id>`
 * carries the same parts as a path.
 *
 * `parseShortcut` is the only guard. Every entry point (the web boot, a
 * native deep link, a click inside a note) goes through it, and the only
 * thing a valid shortcut can do is select an item and scroll. It never
 * creates, changes or deletes anything, and nothing read from the address
 * is ever shown.
 *
 * The id rides in the fragment on the web, which the browser never sends to
 * a server.
 *
 * Spec: ops/docs/archive/note-shortcuts.md
 */

export type ShortcutTarget = { id: string; heading?: string };

const UUID = '[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}';
const TARGET = new RegExp(`^(${UUID})(?:/(h-[0-9a-f]{8}(?:-(?:[2-9]|[1-9][0-9]))?))?$`, 'i');
const ID = new RegExp(`^${UUID}$`, 'i');
const PATH = '/note';

/** The word the copy rows use for an item: "note" for the ones written in
 *  the editor, "item" for a login, a card, a key, a bookmark, a contact or
 *  a file. */
export function shortcutNoun(type: string | undefined): 'note' | 'item' {
  return !type || type === 'note' || type === 'task' || type === 'journal' ? 'note' : 'item';
}

/** True when the app would accept a shortcut to this id. */
export function isShortcutId(id: string): boolean {
  return ID.test(id);
}

function target(raw: string): ShortcutTarget | null {
  const m = TARGET.exec(raw);
  if (!m) return null;
  const out: ShortcutTarget = { id: m[1]!.toLowerCase() };
  if (m[2]) out.heading = m[2].toLowerCase();
  return out;
}

function isNative(): boolean {
  return typeof window !== 'undefined' && ('__TAURI_INTERNALS__' in window || '__TAURI__' in window);
}

/** The origin a shortcut copied here should open on. */
function shortcutOrigin(): string {
  if (typeof window === 'undefined' || isNative() || isApexHost()) return APP_ORIGIN;
  return window.location.origin;
}

/** `?demo=1` when the demo was turned on by that query, so a shortcut
 *  copied there opens the demo again. Nothing else of the query is kept. */
function demoQuery(): string {
  return new URLSearchParams(window.location.search).get('demo') === '1' ? '?demo=1' : '';
}

/** The address of an item, or of one heading in it. */
export function shortcutUrl(id: string, heading?: string): string {
  const query = isDemoMode() ? demoQuery() : '';
  return `${shortcutOrigin()}${PATH}${query}#${id}${heading ? `/${heading}` : ''}`;
}

/** The form the desktop app registers, for the "Open in app" offer. */
export function desktopShortcutUrl(t: ShortcutTarget): string {
  return `privacynotes://note/${t.id}${t.heading ? `/${t.heading}` : ''}`;
}

/** The target an address names, or null for anything that is not a shortcut. */
export function parseShortcut(raw: string): ShortcutTarget | null {
  let url: URL;
  try {
    url = new URL(raw);
  } catch {
    return null;
  }
  // No user or password: an address that names one is not ours, even when
  // it would select the same item. The origin check below covers the port
  // of the web form.
  if (url.username || url.password) return null;
  if (url.protocol === 'privacynotes:') {
    if (url.hostname !== 'note' || url.port || url.search || url.hash) return null;
    return target(url.pathname.replace(/^\//, ''));
  }
  if (url.protocol !== 'https:' && url.protocol !== 'http:') return null;
  const own = typeof window !== 'undefined' ? window.location.origin : '';
  if (url.origin !== APP_ORIGIN && url.origin !== own) return null;
  if (url.pathname !== PATH) return null;
  return target(url.hash.replace(/^#/, ''));
}

/** 32-bit FNV-1a as 8 hex digits. Synchronous, so a copy stays inside its
 *  click: Safari drops the clipboard permission across an await. */
function fnv1a(text: string): string {
  let h = 0x811c9dc5;
  for (const byte of new TextEncoder().encode(text)) {
    h ^= byte;
    h = Math.imul(h, 0x01000193) >>> 0;
  }
  return h.toString(16).padStart(8, '0');
}

/**
 * The codes of a note's headings, in order, from their link keys. A heading
 * is named by a hash and not by its words, because the address goes into
 * other apps and the browser history. The item id is in the hash, so one
 * word in two notes gives two codes. A repeated heading takes `-2`, `-3`.
 */
export function headingCodes(itemId: string, keys: readonly string[]): string[] {
  const seen = new Map<string, number>();
  return keys.map((key) => {
    const base = `h-${fnv1a(`${itemId.toLowerCase()}\n${key}`)}`;
    const n = (seen.get(base) ?? 0) + 1;
    seen.set(base, n);
    return n === 1 ? base : `${base}-${n}`;
  });
}

// ── The desktop app offer ───────────────────────────────────────────

const OFFER_DISMISSED_KEY = 'privacynotes.ui.desktopOfferDismissed';

/** True in a browser on a computer, where the desktop app may be installed.
 *  A phone that has the app opens the link there itself, and the demo's
 *  items exist in no app. Spec: ops/docs/archive/note-shortcuts.md (6) */
export function isComputerBrowser(): boolean {
  if (isNative() || isDemoMode()) return false;
  const ua = navigator.userAgent;
  if (/iPhone|iPad|Android/.test(ua) || (/Macintosh/.test(ua) && navigator.maxTouchPoints > 1)) return false;
  return /Windows NT|Mac OS X|Macintosh|CrOS|Linux/.test(ua);
}

/** True when the signed-in bar may show: a computer browser that has not
 *  closed the offer. */
export function offersDesktopApp(): boolean {
  if (!isComputerBrowser()) return false;
  try {
    return localStorage.getItem(OFFER_DISMISSED_KEY) !== '1';
  } catch {
    return true;
  }
}

/** The x on the bar: no more offers on this browser. */
export function dismissDesktopOffer(): void {
  try {
    localStorage.setItem(OFFER_DISMISSED_KEY, '1');
  } catch {
    /* storage unavailable: the bar comes back next time */
  }
}

// ── The web boot ────────────────────────────────────────────────────

const PENDING_KEY = 'privacynotes.shortcut.pending';
const PENDING_TTL_MS = 30 * 60 * 1000;

/**
 * Read a shortcut from the address the page loaded with, before the app
 * mounts. A valid target waits in this tab's sessionStorage for the vault
 * to open, through sign-in and the app lock. The address is rewritten to
 * `/` either way, which the web sign-in return requires and which stops a
 * reload from opening the item again.
 */
export function captureShortcutFromLocation(): void {
  try {
    if (window.location.pathname.replace(/\/+$/, '') !== PATH) return;
    const t = parseShortcut(window.location.href);
    if (t) sessionStorage.setItem(PENDING_KEY, JSON.stringify({ ...t, at: Date.now() }));
    window.history.replaceState(null, '', `/${demoQuery()}`);
  } catch {
    /* storage or history unavailable: the app opens without the target */
  }
}

/** The target waiting from the boot, without removing it. */
export function peekPendingShortcut(): ShortcutTarget | null {
  try {
    const raw = sessionStorage.getItem(PENDING_KEY);
    if (!raw) return null;
    const v = JSON.parse(raw) as { id?: unknown; heading?: unknown; at?: unknown };
    if (typeof v.at !== 'number' || Date.now() - v.at > PENDING_TTL_MS) return null;
    if (typeof v.id !== 'string') return null;
    return target(typeof v.heading === 'string' ? `${v.id}/${v.heading}` : v.id);
  } catch {
    return null;
  }
}

/** The target waiting from the boot, removed so it opens once. */
export function takePendingShortcut(): ShortcutTarget | null {
  const t = peekPendingShortcut();
  try {
    sessionStorage.removeItem(PENDING_KEY);
  } catch {
    /* storage unavailable: nothing was stored */
  }
  return t;
}

// ── In-app opens ────────────────────────────────────────────────────

let opener: ((t: ShortcutTarget) => void) | null = null;

/** The notes view registers how to open a target; the click handlers that
 *  cannot reach its state call `openShortcutInApp`. */
export function setShortcutOpener(fn: ((t: ShortcutTarget) => void) | null): void {
  opener = fn;
}

/** Open a shortcut clicked inside the app. False when no view can take it,
 *  so the caller opens the address the normal way. */
export function openShortcutInApp(href: string): boolean {
  const t = parseShortcut(href);
  if (!t || !opener) return false;
  opener(t);
  return true;
}
