/**
 * Remembering the chosen folder across reloads.
 *
 * The two platforms differ in what is even possible, and the difference is
 * visible to the user, so it is worth stating plainly:
 *
 *   - **Desktop** stores a path string. A path is just data; it survives a
 *     restart and needs no permission, so the folder reopens silently and
 *     completely.
 *   - **Chromium browsers** store the `FileSystemDirectoryHandle` itself, which
 *     is structured-cloneable and therefore IndexedDB-storable. The handle
 *     survives - but the PERMISSION attached to it does not, by design. After a
 *     reload `queryPermission` usually reports `prompt`, and `requestPermission`
 *     may only be called from a user gesture. So the folder is remembered and
 *     reopening is one click, rather than navigating the picker again. Installed
 *     PWAs can be granted persistent permission, in which case the check below
 *     returns `granted` and it reopens with no click at all.
 *
 * Deliberately its OWN IndexedDB database rather than a table in the app's
 * Dexie one. The Markdown pillar must not be able to reach the encrypted store,
 * and the cleanest way to guarantee that is for it to keep its state somewhere
 * that store cannot see.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 5)
 */

import { isDemoMode } from '../demo';

const DB_NAME = 'privacynotes-markdown';
// `?demo=1` runs on the same origin as a real install, so the demo keeps its
// folder in a database of its own, the way DEMO_DB_NAME keeps its notes: a
// demo tab can neither reopen the real remembered folder nor forget it.
const DEMO_DB = 'privacynotes-markdown-demo';
const STORE = 'folder';
const KEY = 'last';

export type StoredFolder =
  | { kind: 'path'; path: string }
  | { kind: 'handle'; handle: FileSystemDirectoryHandle };

function open(): Promise<IDBDatabase> {
  return new Promise((resolve, reject) => {
    const req = indexedDB.open(isDemoMode() ? DEMO_DB : DB_NAME, 1);
    req.onupgradeneeded = () => {
      if (!req.result.objectStoreNames.contains(STORE)) req.result.createObjectStore(STORE);
    };
    req.onsuccess = () => resolve(req.result);
    req.onerror = () => reject(req.error);
  });
}

async function withStore<T>(mode: IDBTransactionMode, fn: (s: IDBObjectStore) => IDBRequest<T>): Promise<T | null> {
  try {
    const db = await open();
    return await new Promise<T | null>((resolve) => {
      const req = fn(db.transaction(STORE, mode).objectStore(STORE));
      // `close()` waits for the pending transaction to commit, so calling it
      // here is safe and keeps each call from leaving a live connection behind
      // for the rest of the session.
      const settle = (value: T | null) => { db.close(); resolve(value); };
      req.onsuccess = () => settle(req.result ?? null);
      req.onerror = () => settle(null);
    });
  } catch {
    // Private-mode browsers and blocked storage both land here. Forgetting the
    // folder is a downgrade, never a failure - the picker still works.
    return null;
  }
}

export async function rememberFolder(folder: StoredFolder): Promise<void> {
  await withStore('readwrite', (s) => s.put(folder, KEY) as IDBRequest<unknown>);
}

export async function recallFolder(): Promise<StoredFolder | null> {
  return withStore<StoredFolder>('readonly', (s) => s.get(KEY) as IDBRequest<StoredFolder>);
}

export async function forgetFolder(): Promise<void> {
  await withStore('readwrite', (s) => s.delete(KEY) as IDBRequest<unknown>);
}

// The first-run explainer's seen-flag (`hasSeenExplainer` / `markExplainerSeen`,
// key `explained`) lived here until 2026-08-14. The gate it drove is gone: the
// empty state renders the pitch itself, so the modal in front of the picker was
// showing the reader content already on their screen. Existing profiles keep a
// stray `explained: true` record, which nothing reads and which costs a byte.

/** Whether a remembered handle can be used without asking again. */
export type HandlePermission = 'granted' | 'needs-click' | 'lost';

/**
 * Ask the browser whether a stored handle is still usable.
 *
 * `prompt` is not a failure: it means the handle is valid and the user can
 * re-grant with one click. Only a throw means the handle is genuinely gone -
 * the folder was deleted, or the browser dropped it.
 */
export async function checkHandle(handle: FileSystemDirectoryHandle): Promise<HandlePermission> {
  try {
    const h = handle as unknown as {
      queryPermission?: (d: { mode: string }) => Promise<PermissionState>;
    };
    if (!h.queryPermission) return 'needs-click';
    const state = await h.queryPermission({ mode: 'readwrite' });
    return state === 'granted' ? 'granted' : 'needs-click';
  } catch {
    return 'lost';
  }
}

/** Re-grant a stored handle. MUST be called from a user gesture - the browser
 *  rejects it otherwise, which is exactly why this cannot happen on load. */
export async function requestHandle(handle: FileSystemDirectoryHandle): Promise<boolean> {
  try {
    const h = handle as unknown as {
      requestPermission?: (d: { mode: string }) => Promise<PermissionState>;
    };
    if (!h.requestPermission) return false;
    return (await h.requestPermission({ mode: 'readwrite' })) === 'granted';
  } catch {
    return false;
  }
}
