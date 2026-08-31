/**
 * One way to reach files on disk, over two very different platform APIs.
 *
 * The browser has the File System Access API, which hands back opaque handles
 * and no paths at all. The desktop app has Tauri's fs plugin, which has paths
 * and no handles. Neither can be expressed in the other's terms, so the rest of
 * the feature talks to `OpenedFileRef` / `OpenedDirectoryRef` and never learns
 * which one it got.
 *
 * A one-shot `<input type="file">` is deliberately NOT one of the backends. It
 * yields a `File` snapshot with no way to write back, which is fine for reading
 * and a dead end the moment editing exists - and a read-only path that cannot
 * grow into the real one is a second implementation to keep working.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 5, platform matrix)
 */
import { detectPlatform } from '../devices';
import { SUPPORTED_EXTENSIONS, isSupportedFile } from './adapter';
import type { StoredFolder } from './folderMemory';

/** What we compare to decide whether a file changed under us. Deliberately not
 *  a hash: hashing a large file on every save costs more than it protects, and
 *  size plus mtime catches every case a human or another editor can produce. */
export interface FileStamp {
  size: number;
  mtime: number;
}

export interface OpenedFileRef {
  /** Filename including extension. */
  name: string;
  /** Shown to the user. A full path on desktop, a relative one inside a chosen
   *  folder, or just the name on the web, where the API withholds the location. */
  location: string;
  read(): Promise<string>;
  write(text: string): Promise<void>;
  /** Current on-disk fingerprint, or null when the platform cannot answer.
   *  A null must never be treated as "unchanged" - see `stampsMatch`. */
  stamp(): Promise<FileStamp | null>;
}

export interface DirectoryEntry {
  /** Path relative to the chosen root, e.g. `projects/2026/api.md`. Unique
   *  within a scan, which is why it doubles as the list's React key. */
  relPath: string;
  /** Everything before the filename, `''` at the root. Shown as the row's chip
   *  because filenames collide constantly across a real vault - `daily/` and
   *  `refs/` both holding a `2026-08-13.md` is the normal case, not an edge one. */
  dir: string;
  ref: OpenedFileRef;
}

export interface OpenedDirectoryRef {
  name: string;
  location: string;
  /** What to persist so this folder reopens after a reload. Only a freshly
   *  PICKED folder carries it: one rebuilt from memory is already remembered,
   *  and rewriting it on every restore would be a pointless IndexedDB write. */
  remember?: StoredFolder;
  /** Every supported file at any depth, alphabetically by path. */
  scan(): Promise<DirectoryEntry[]>;
  /** Create a new note file at `relPath` and hand back a ref to it. Rejects
   *  with `FileExistsError` rather than overwriting: the caller picks a free
   *  name first, and picks another one if the name was taken after all. */
  createFile(relPath: string, contents: string): Promise<OpenedFileRef>;
  /** Move a file into `.trash/` inside the folder. Never an unlink - a delete
   *  the user regrets has to be recoverable in their own file manager, which is
   *  what every editor in this space does and what our spec commits to. */
  trashFile(relPath: string): Promise<void>;
  /** Write a binary asset (a pasted image) at `relPath`. */
  writeAsset(relPath: string, bytes: Uint8Array<ArrayBuffer>): Promise<void>;
  /**
   * A displayable URL for a non-note file inside this folder, by path from the
   * root. Null when it is not there.
   *
   * Separate from `scan`, which only ever yields notes: images are referenced
   * BY notes rather than listed alongside them, so they are fetched on demand
   * and only when something points at one.
   */
  resolveAsset(relPath: string): Promise<string | null>;
}

/**
 * Something is already at that path, so `createFile` refused to write.
 *
 * Its own class because the caller CAN act on it - the name it picked from the
 * last scan was taken in the meantime, so the answer is to rescan and pick
 * another - where a generic failure only leaves it a message to show. Neither
 * backend renames behind the user's back: choosing the name is the caller's
 * job, and quietly writing to a different file than the one asked for is how a
 * new note ends up somewhere nobody looks.
 */
export class FileExistsError extends Error {
  constructor(relPath: string) {
    super(`file_exists: ${relPath}`);
    this.name = 'FileExistsError';
  }
}

/**
 * Directories a scan never descends into.
 *
 * Anything dot-prefixed covers `.git`, `.obsidian`, `.trash` and whatever else
 * a tool has parked there. This is a read AND a write boundary: `.obsidian`
 * holds another app's configuration, and the spec is explicit that we never
 * write into it. Not descending is how that stays true by construction rather
 * than by remembering.
 */
function isSkippedDir(name: string): boolean {
  return name.startsWith('.') || name === 'node_modules';
}

/** Hidden files are somebody's dotfile, not a note. */
function isSkippedFile(name: string): boolean {
  return name.startsWith('.') || !isSupportedFile(name);
}

/* ── Single file ──────────────────────────────────────────────────── */

/**
 * Ask the user for a file and return a handle we can read and write.
 *
 * Resolves null when the user cancels, which is not an error and must not be
 * reported as one.
 */
export async function pickFile(): Promise<OpenedFileRef | null> {
  if (detectPlatform() === 'desktop') {
    const [{ open }, fs] = await Promise.all([
      import('@tauri-apps/plugin-dialog'),
      import('@tauri-apps/plugin-fs'),
    ]);
    const picked = await open({
      multiple: false,
      directory: false,
      filters: [{ name: 'Markdown', extensions: SUPPORTED_EXTENSIONS }],
    });
    return typeof picked === 'string' ? tauriFileRef(fs, picked, picked) : null;
  }

  const picker = (window as unknown as {
    showOpenFilePicker?: (opts: unknown) => Promise<FileSystemFileHandle[]>;
  }).showOpenFilePicker;
  if (!picker) return null;

  try {
    const [handle] = await picker({
      multiple: false,
      types: [{ description: 'Markdown', accept: { 'text/markdown': SUPPORTED_EXTENSIONS.map((e) => `.${e}`) } }],
    });
    // The API gives no path by design, and inventing one would be a lie in the
    // UI. The name is what the user picked and what they will recognise.
    return handle ? handleFileRef(handle, handle.name) : null;
  } catch {
    // The picker throws AbortError when the user cancels. Every other failure
    // here (a blocked permission, a detached user gesture) is equally "no file
    // was chosen" from the caller's point of view.
    return null;
  }
}

/**
 * A ref for a path the OS handed us, rather than one the user picked in-app.
 *
 * Desktop only: this exists for the file-association path, where the double
 * click happened in Finder or Explorer and there was never a picker. The web
 * has no equivalent and never will - a page cannot be handed a path.
 */
export async function openPath(path: string): Promise<OpenedFileRef | null> {
  if (detectPlatform() !== 'desktop') return null;
  const fs = await import('@tauri-apps/plugin-fs');
  return tauriFileRef(fs, path, path);
}

/* ── Folder ───────────────────────────────────────────────────────── */

/** Rebuild a directory ref from a remembered desktop path - no picker, because
 *  the user already chose it and a path needs no permission. */
export async function directoryFromPath(path: string): Promise<OpenedDirectoryRef> {
  const fs = await import('@tauri-apps/plugin-fs');
  const name = path.slice(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1);
  return {
    name,
    location: path,
    scan: () => scanTauri(fs, path),
    resolveAsset: (rel) => resolveTauriAsset(fs, path, rel),
    createFile: (rel, contents) => createTauriFile(fs, path, rel, contents),
    trashFile: (rel) => trashTauriFile(fs, path, rel),
    writeAsset: (rel, bytes) => writeTauriAsset(fs, path, rel, bytes),
  };
}

/** Rebuild a directory ref from a remembered browser handle. The caller is
 *  responsible for having confirmed permission first - see `folderMemory`. */
export function directoryFromHandle(dir: FileSystemDirectoryHandle): OpenedDirectoryRef {
  return {
    name: dir.name,
    location: dir.name,
    scan: () => scanHandles(dir, ''),
    resolveAsset: (rel) => resolveHandleAsset(dir, rel),
    createFile: (rel, contents) => createHandleFile(dir, rel, contents),
    trashFile: (rel) => trashHandleFile(dir, rel),
    writeAsset: (rel, bytes) => writeHandleAsset(dir, rel, bytes),
  };
}

/**
 * Ask the user for a folder. Null on cancel, same contract as `pickFile`.
 *
 * Built by the two factories above rather than by a third and fourth object
 * literal: a freshly picked folder differs from a restored one in exactly one
 * field, `remember`, and a ref assembled twice is a ref where the picked path
 * and the restored path quietly stop behaving alike.
 */
export async function pickDirectory(): Promise<OpenedDirectoryRef | null> {
  if (detectPlatform() === 'desktop') {
    const { open } = await import('@tauri-apps/plugin-dialog');
    // `recursive` is what the picker passes to `allow_directory`, and it is the
    // difference between granting `<picked>/*` and `<picked>/**`. Without it a
    // vault outside $HOME scans its top level and then fails on every
    // subfolder, because the static capability scope does not cover it either.
    // A vault inside $HOME works regardless, which is exactly how this hides.
    const picked = await open({ multiple: false, directory: true, recursive: true });
    if (typeof picked !== 'string') return null;
    return { ...await directoryFromPath(picked), remember: { kind: 'path', path: picked } };
  }

  const picker = (window as unknown as {
    showDirectoryPicker?: (opts?: unknown) => Promise<FileSystemDirectoryHandle>;
  }).showDirectoryPicker;
  if (!picker) return null;

  try {
    // `readwrite` up front: asking again at the first save would put a
    // permission prompt in the middle of someone typing.
    const dir = await picker({ mode: 'readwrite' });
    return { ...directoryFromHandle(dir), remember: { kind: 'handle', handle: dir } };
  } catch {
    return null;
  }
}

async function scanHandles(
  dir: FileSystemDirectoryHandle,
  prefix: string,
): Promise<DirectoryEntry[]> {
  const found: DirectoryEntry[] = [];
  // `entries()` is an async iterator; the cast keeps this compiling against
  // lib.dom versions that predate its typing.
  const iterable = dir as unknown as AsyncIterable<[string, FileSystemHandle]>;
  for await (const [name, handle] of iterable) {
    if (handle.kind === 'directory') {
      if (isSkippedDir(name)) continue;
      found.push(...await scanHandles(handle as FileSystemDirectoryHandle, `${prefix}${name}/`));
      continue;
    }
    if (isSkippedFile(name)) continue;
    const relPath = `${prefix}${name}`;
    found.push({ relPath, dir: prefix, ref: handleFileRef(handle as FileSystemFileHandle, relPath) });
  }
  return sortByPath(found);
}

type TauriFs = typeof import('@tauri-apps/plugin-fs');

async function scanTauri(fs: TauriFs, root: string, prefix = ''): Promise<DirectoryEntry[]> {
  const found: DirectoryEntry[] = [];
  const base = prefix ? `${root}/${prefix.slice(0, -1)}` : root;
  for (const entry of await fs.readDir(base)) {
    if (entry.isDirectory) {
      if (isSkippedDir(entry.name)) continue;
      found.push(...await scanTauri(fs, root, `${prefix}${entry.name}/`));
      continue;
    }
    if (isSkippedFile(entry.name)) continue;
    const relPath = `${prefix}${entry.name}`;
    found.push({ relPath, dir: prefix, ref: tauriFileRef(fs, `${root}/${relPath}`, relPath) });
  }
  return sortByPath(found);
}

/**
 * Alphabetical by path.
 *
 * Deliberately NOT the by-modified default the rest of the app uses. Sorting by
 * mtime means a `stat` per file during the scan - one syscall each on desktop,
 * a whole `getFile()` per handle on the web - which is the difference between a
 * folder opening instantly and a folder crawling. Ordering by recency belongs
 * with a lazily-populated mtime, not with a scan that blocks the first paint.
 */
function sortByPath(entries: DirectoryEntry[]): DirectoryEntry[] {
  return entries.sort((a, b) => a.relPath.localeCompare(b.relPath));
}

/**
 * Walk a relative path to a file and hand back something an `<img>` can load.
 *
 * The browser has no path lookup, so every segment is a `getDirectoryHandle`
 * hop. A missing segment throws, which is the normal "the note points at an
 * image that is not there" case and resolves to null rather than an error.
 *
 * The URL is a blob, which the caller owns and must revoke - see `useAssets`.
 */
/**
 * True when a note-supplied relative path stays inside the opened folder.
 *
 * Rejects any segment equal to `..`, and any absolute or root-relative path.
 * The path comes from note text (an `![alt](path)` image reference), so a
 * shared vault or a single .md file a user was sent could otherwise address a
 * file anywhere on disk by walking up out of the folder. The web backend gets
 * this for free, because the File System Access API rejects `..` in
 * `getDirectoryHandle`; the Tauri backend joins a raw string and had no such
 * guard, next to an asset scope of `**`.
 */
export function isContainedRelPath(relPath: string): boolean {
  if (relPath === '') return false;
  // Absolute (`/x`, `C:\x`) or protocol-relative is not a contained path.
  if (/^([a-zA-Z]:)?[/\\]/.test(relPath)) return false;
  return relPath
    .split(/[/\\]/)
    .every((seg) => seg !== '..');
}

async function resolveHandleAsset(
  root: FileSystemDirectoryHandle,
  relPath: string,
): Promise<string | null> {
  if (!isContainedRelPath(relPath)) return null;
  const parts = relPath.split('/').filter((p) => p && p !== '.');
  const name = parts.pop();
  if (!name) return null;
  try {
    let dir = root;
    for (const part of parts) dir = await dir.getDirectoryHandle(part);
    const file = await (await dir.getFileHandle(name)).getFile();
    return URL.createObjectURL(file);
  } catch {
    return null;
  }
}

/** Desktop resolves through the asset protocol, which needs no read into JS -
 *  the webview streams the file itself. Requires `assetProtocol` in
 *  tauri.conf.json and the `protocol-asset` crate feature; without both, the
 *  URL resolves to nothing. */
async function resolveTauriAsset(
  fs: TauriFs,
  root: string,
  relPath: string,
): Promise<string | null> {
  if (!isContainedRelPath(relPath)) return null;
  const full = `${root}/${relPath}`;
  try {
    if (!(await fs.exists(full))) return null;
  } catch {
    return null;
  }
  const { convertFileSrc } = await import('@tauri-apps/api/core');
  return convertFileSrc(full);
}

/** Where a deleted file goes. Matches what Obsidian does, so a vault shared
 *  between the two apps has one recycle bin rather than two. */
const TRASH_DIR = '.trash';

/** Walk to a directory, creating each missing segment. */
async function ensureDir(root: FileSystemDirectoryHandle, parts: string[]): Promise<FileSystemDirectoryHandle> {
  let dir = root;
  for (const part of parts) dir = await dir.getDirectoryHandle(part, { create: true });
  return dir;
}

/** Whether `name` is taken in `dir`. Asking is the only way: the API has no
 *  existence check, so a `getFileHandle` that does NOT create is the probe and
 *  its NotFoundError is the answer. */
async function handleExists(dir: FileSystemDirectoryHandle, name: string): Promise<boolean> {
  try {
    await dir.getFileHandle(name);
    return true;
  } catch {
    return false;
  }
}

/**
 * Walk to `relPath`, creating missing directories, and write the payload.
 *
 * The single write body on this backend. A note is a string and an asset is
 * bytes, and that is the ONLY difference between the two - `createWritable`
 * takes either - so they share the walk, the mkdir and the swap-on-close
 * rather than being two copies that drift in how a directory gets created.
 *
 * `exclusive` refuses to touch an existing file. It is not the default because
 * an asset write is a write, but `createFile` promises create-or-fail and
 * `getFileHandle(name, { create: true })` OPENS an existing file rather than
 * failing, so the probe below is the only thing standing between a new note and
 * a truncated old one.
 */
async function writeHandleFile(
  root: FileSystemDirectoryHandle,
  relPath: string,
  payload: string | Uint8Array<ArrayBuffer>,
  { exclusive = false } = {},
): Promise<FileSystemFileHandle> {
  const parts = relPath.split('/').filter(Boolean);
  const name = parts.pop()!;
  const dir = await ensureDir(root, parts);
  if (exclusive && await handleExists(dir, name)) throw new FileExistsError(relPath);
  const handle = await dir.getFileHandle(name, { create: true });
  const w = await handle.createWritable();
  await w.write(payload);
  await w.close();
  return handle;
}

async function createHandleFile(
  root: FileSystemDirectoryHandle,
  relPath: string,
  contents: string,
): Promise<OpenedFileRef> {
  return handleFileRef(await writeHandleFile(root, relPath, contents, { exclusive: true }), relPath);
}

async function trashHandleFile(root: FileSystemDirectoryHandle, relPath: string): Promise<void> {
  const parts = relPath.split('/').filter(Boolean);
  const name = parts.pop()!;
  let dir = root;
  for (const part of parts) dir = await dir.getDirectoryHandle(part);
  const original = await (await dir.getFileHandle(name)).getFile();
  // Copy into .trash BEFORE removing the original, so a failure anywhere in
  // here leaves the file where it was rather than nowhere at all.
  const trash = await ensureDir(root, [TRASH_DIR]);
  const dest = await trash.getFileHandle(await freeName(trash, name), { create: true });
  const w = await dest.createWritable();
  await w.write(await original.arrayBuffer());
  await w.close();
  await dir.removeEntry(name);
}

/** A name not already taken in `dir`, suffixing ` 2`, ` 3`, ... before the
 *  extension, so trashing the same filename twice cannot overwrite the first
 *  one. Trashing only: a NEW note's name is the caller's to choose, which is
 *  why `createFile` rejects a taken one instead of renaming it. */
async function freeName(dir: FileSystemDirectoryHandle, name: string): Promise<string> {
  const dot = name.lastIndexOf('.');
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : '';
  for (let i = 1; i < 1000; i++) {
    const candidate = i === 1 ? name : `${stem} ${i}${ext}`;
    if (!await handleExists(dir, candidate)) return candidate;
  }
  return `${stem} ${Date.now()}${ext}`;
}

async function writeHandleAsset(
  root: FileSystemDirectoryHandle,
  relPath: string,
  bytes: Uint8Array<ArrayBuffer>,
): Promise<void> {
  await writeHandleFile(root, relPath, bytes);
}

/**
 * The same single write body for the desktop backend, and the same reason: text
 * and bytes differ by one call, so they share the path join and the mkdir.
 *
 * `exclusive` is `createFile`'s create-or-fail contract. `writeTextFile`
 * truncates whatever is there, so without the check a new note silently eats an
 * existing file - and unlike the web backend there is no swap-on-close to leave
 * the old contents behind. An `exists` that cannot answer rejects rather than
 * writing: refusing costs the user a second attempt, guessing costs them a file.
 */
async function writeTauriFile(
  fs: TauriFs,
  root: string,
  relPath: string,
  payload: string | Uint8Array<ArrayBuffer>,
  { exclusive = false } = {},
): Promise<string> {
  const full = `${root}/${relPath}`;
  if (exclusive && await fs.exists(full)) throw new FileExistsError(relPath);
  const dir = full.slice(0, full.lastIndexOf('/'));
  await fs.mkdir(dir, { recursive: true }).catch(() => {});
  if (typeof payload === 'string') await fs.writeTextFile(full, payload);
  else await fs.writeFile(full, payload);
  return full;
}

async function createTauriFile(
  fs: TauriFs,
  root: string,
  relPath: string,
  contents: string,
): Promise<OpenedFileRef> {
  const full = await writeTauriFile(fs, root, relPath, contents, { exclusive: true });
  return tauriFileRef(fs, full, relPath);
}

async function trashTauriFile(fs: TauriFs, root: string, relPath: string): Promise<void> {
  const full = `${root}/${relPath}`;
  const name = relPath.slice(relPath.lastIndexOf('/') + 1);
  const trashDir = `${root}/${TRASH_DIR}`;
  await fs.mkdir(trashDir, { recursive: true }).catch(() => {});
  let dest = `${trashDir}/${name}`;
  const dot = name.lastIndexOf('.');
  const stem = dot > 0 ? name.slice(0, dot) : name;
  const ext = dot > 0 ? name.slice(dot) : '';
  for (let i = 2; i < 1000 && (await fs.exists(dest).catch(() => false)); i++) {
    dest = `${trashDir}/${stem} ${i}${ext}`;
  }
  // rename is atomic within a filesystem and does not read the file into JS,
  // which matters for a large attachment.
  await fs.rename(full, dest);
}

async function writeTauriAsset(
  fs: TauriFs,
  root: string,
  relPath: string,
  bytes: Uint8Array<ArrayBuffer>,
): Promise<void> {
  await writeTauriFile(fs, root, relPath, bytes);
}

/* ── Backends ─────────────────────────────────────────────────────── */

function handleFileRef(handle: FileSystemFileHandle, location: string): OpenedFileRef {
  return {
    name: handle.name,
    location,
    read: async () => (await handle.getFile()).text(),
    write: async (text) => {
      // `createWritable` writes to a swap file and swaps it in on close, so a
      // crash mid-write leaves the original intact rather than truncated.
      const writable = await handle.createWritable();
      await writable.write(text);
      await writable.close();
    },
    stamp: async () => {
      try {
        const f = await handle.getFile();
        return { size: f.size, mtime: f.lastModified };
      } catch {
        return null;
      }
    },
  };
}

function tauriFileRef(fs: TauriFs, path: string, location: string): OpenedFileRef {
  const name = path.slice(Math.max(path.lastIndexOf('/'), path.lastIndexOf('\\')) + 1);
  return {
    name,
    location,
    read: () => fs.readTextFile(path),
    write: (text) => fs.writeTextFile(path, text),
    stamp: async () => {
      try {
        const s = await fs.stat(path);
        // `mtime` is a Date or null depending on what the platform reports.
        // Falling back to 0 would make every stamp compare equal, silently
        // disabling the clobber guard, so an unknown mtime returns null and
        // lets the caller decide.
        const mtime = s.mtime ? s.mtime.getTime() : null;
        return mtime === null ? null : { size: s.size, mtime };
      } catch {
        return null;
      }
    },
  };
}

/**
 * Whether a file's `location` is a real filesystem path.
 *
 * Only the desktop app has one. The File System Access API withholds it by
 * design - the browser hands back an opaque handle and no way to learn where it
 * came from - so a path-based action (today just Copy path) is desktop-only, and
 * offering it on the web would be a menu row that cannot work.
 *
 * No `revealInFolder` or `openWithDefaultApp` helper belongs here, deliberately;
 * `rowMenu` in MarkdownListPane.tsx records the reason for each. Either one would
 * need its own capability grant to work: `opener:default` does not carry
 * `reveal-item-in-dir`, and a helper missing its grant fails silently at runtime
 * with a clean `cargo check`.
 */
export function hasRealPath(): boolean {
  return detectPlatform() === 'desktop';
}

/** True when the two fingerprints describe the same file contents.
 *
 *  A null on either side means "cannot tell", and cannot-tell is treated as
 *  CHANGED. That is the safe direction: refusing to write costs the user a
 *  click, writing over an edit we failed to notice costs them their work. */
export function stampsMatch(a: FileStamp | null, b: FileStamp | null): boolean {
  if (!a || !b) return false;
  return a.size === b.size && a.mtime === b.mtime;
}
