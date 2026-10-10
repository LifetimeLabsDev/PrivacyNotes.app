/**
 * The window of a Markdown file opened from the file manager while the app was
 * closed: a size of its own, so the app reads as a Markdown editor and not a
 * workspace. Two sizes are remembered on this device, the workspace window and
 * the file window, each updated by the person resizing it. A double-click into
 * an app that is already open never resizes it; only the panes fold.
 *
 * The window-state plugin saves whatever size the window has on quit, so a
 * session that ends inside the file window leaves a flag, and the next start
 * without a file puts the workspace size back.
 *
 * Desktop only. Window positions are physical pixels throughout, the unit the
 * monitor work area and the window getters report.
 * Spec: ops/docs/plans/markdown-folder.md (section 11)
 */
import { detectPlatform } from '../devices';

type Rect = { w: number; h: number; x: number; y: number; max: boolean };

const WORKSPACE_KEY = 'privacynotes.ui.workspaceWindow';
const FILE_KEY = 'privacynotes.ui.fileWindow';
/** Set while the file window is up, so a quit inside it is known next start. */
const OPEN_KEY = 'privacynotes.ui.fileWindowOpen';

let active = false;
let stopWatching: (() => void) | null = null;

function readRect(key: string): Rect | null {
  try {
    const v = JSON.parse(localStorage.getItem(key) ?? 'null') as Partial<Rect> | null;
    if (v && [v.w, v.h, v.x, v.y].every((n) => typeof n === 'number' && Number.isFinite(n)) && v.w! > 0 && v.h! > 0) {
      return { w: v.w!, h: v.h!, x: v.x!, y: v.y!, max: !!v.max };
    }
  } catch { /* no storage: fall back to the default */ }
  return null;
}

function isOpenFlagged(): boolean {
  try { return localStorage.getItem(OPEN_KEY) === '1'; } catch { return false; }
}

function store(key: string, value: string | null): void {
  try {
    if (value === null) localStorage.removeItem(key);
    else localStorage.setItem(key, value);
  } catch { /* no storage: nothing to remember */ }
}

async function api() {
  const mod = await import('@tauri-apps/api/window');
  return { win: mod.getCurrentWindow(), mod };
}

async function currentRect(): Promise<Rect> {
  const { win } = await api();
  const [size, pos, max] = await Promise.all([win.outerSize(), win.outerPosition(), win.isMaximized()]);
  return { w: size.width, h: size.height, x: pos.x, y: pos.y, max };
}

async function applyRect(rect: Rect): Promise<void> {
  const { win, mod } = await api();
  if (rect.max) { await win.maximize(); return; }
  if (await win.isMaximized()) await win.unmaximize();
  await win.setSize(new mod.PhysicalSize(rect.w, rect.h));
  await win.setPosition(new mod.PhysicalPosition(rect.x, rect.y));
}

/** The first file window: half the work area's width at its full height,
 *  centred. Never narrower than the layout step where the list stops folding
 *  (768 CSS px), or widening the window would bring the list back. */
const MIN_FILE_WIDTH_CSS = 820;

async function defaultFileRect(): Promise<Rect | null> {
  const { mod } = await api();
  const monitor = await mod.currentMonitor();
  if (!monitor) return null;
  const area = monitor.workArea;
  const w = Math.min(area.size.width, Math.max(Math.round(area.size.width / 2), Math.round(MIN_FILE_WIDTH_CSS * monitor.scaleFactor)));
  return { w, h: area.size.height, x: area.position.x + Math.round((area.size.width - w) / 2), y: area.position.y, max: false };
}

/** The app was started by a double-clicked file: move to the file window. */
export async function enterFileWindow(): Promise<void> {
  if (detectPlatform() !== 'desktop' || active) return;
  try {
    const { win } = await api();
    if (await win.isFullscreen()) return;
    // A quit inside the file window left the workspace size saved already, and
    // the window the plugin restored is the file window, not the workspace.
    if (!isOpenFlagged()) store(WORKSPACE_KEY, JSON.stringify(await currentRect()));
    const target = readRect(FILE_KEY) ?? (await defaultFileRect());
    if (!target) return;
    await applyRect(target);
    active = true;
    store(OPEN_KEY, '1');
    let timer: number | undefined;
    const save = () => {
      window.clearTimeout(timer);
      timer = window.setTimeout(() => {
        if (active) void currentRect().then((r) => { if (active) store(FILE_KEY, JSON.stringify(r)); });
      }, 400);
    };
    const offs = await Promise.all([win.onResized(save), win.onMoved(save)]);
    stopWatching = () => { window.clearTimeout(timer); offs.forEach((off) => off()); };
  } catch {
    // A refused grant or a window that went away: the panes still fold, which
    // is the half of the feature that matters.
  }
}

/** The reader went back to the workspace: so does the window. */
export async function leaveFileWindow(): Promise<void> {
  if (!active) return;
  active = false;
  stopWatching?.();
  stopWatching = null;
  await restoreWorkspace();
}

/** A start without a file, after a session that quit inside the file window. */
export async function settleWindowAtStart(): Promise<void> {
  if (detectPlatform() !== 'desktop' || active || !isOpenFlagged()) return;
  await restoreWorkspace();
}

async function restoreWorkspace(): Promise<void> {
  store(OPEN_KEY, null);
  const rect = readRect(WORKSPACE_KEY);
  if (!rect) return;
  try {
    await applyRect(rect);
  } catch { /* the window keeps the size it has */ }
}
