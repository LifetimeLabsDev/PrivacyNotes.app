/**
 * Notice files that appeared or disappeared while the app was in the background.
 *
 * Nothing watches the folder. The web has no watcher to use - the File System
 * Access API has no change event of any kind - and the desktop build does not
 * run `plugin-fs`'s `watch` yet, so until this existed the list was only ever as
 * current as the last manual Rescan. That is wrong for the whole point of the
 * pillar: the folder is shared with Obsidian, git, an agent and Finder, and all
 * of them write to it while this app is not the one in front.
 *
 * So: rescan when the window comes back to the front, which is exactly when the
 * user has finished doing whatever wrote to the folder. This is the web half of
 * the spec's rule 1, applied to both platforms because it costs one listener and
 * needs no native plumbing. Rescan stays as the manual override.
 *
 * Two rules keep it cheap enough to run on every focus:
 *
 *   1. A scan that finds the SAME set of paths publishes nothing. `useTagIndex`
 *      re-runs on every `entries` identity change and stats every file in the
 *      folder when it does, so handing back a fresh-but-identical array on each
 *      alt-tab would turn a free check into a sweep of the whole vault. The
 *      consequence is deliberate and worth knowing: a file EDITED elsewhere
 *      under an unchanged name does not refresh its row here. Its contents are
 *      still safe - the never-clobber stamp check runs before any write - and
 *      the Rescan button is the way to refresh the previews on demand.
 *   2. One scan at a time, and never two within `MIN_INTERVAL_MS`. Focus fires
 *      more often than a person switches apps: a closing OS dialog, devtools,
 *      and the folder picker itself all produce one.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 7, rule 1)
 */
import { useEffect, useRef } from 'react';
import type { DirectoryEntry } from './fileAccess';
import type { OpenedMarkdownDir } from './types';

/** Floor between two automatic scans. */
const MIN_INTERVAL_MS = 2000;

/** Whether two scans list the same files. Both are sorted by path, so this is a
 *  walk rather than a set build. Paths only: contents are rule 1 above. */
function samePaths(a: DirectoryEntry[], b: DirectoryEntry[]): boolean {
  if (a.length !== b.length) return false;
  for (let i = 0; i < a.length; i++) if (a[i]!.relPath !== b[i]!.relPath) return false;
  return true;
}

export function useFolderRefresh(
  dir: OpenedMarkdownDir | null,
  onDir: (next: OpenedMarkdownDir) => void,
) {
  // Both through refs so the listeners are bound once for the life of the view
  // rather than being torn down and re-added on every render of a component
  // this size.
  const dirRef = useRef(dir);
  dirRef.current = dir;
  const onDirRef = useRef(onDir);
  onDirRef.current = onDir;
  const lastRunRef = useRef(0);
  const runningRef = useRef(false);

  useEffect(() => {
    async function refresh() {
      const current = dirRef.current;
      if (!current || runningRef.current) return;
      // A background tab can fire `focus` on the window inside it. Nothing there
      // is visible to refresh, and the user has not come back yet.
      if (document.visibilityState !== 'visible') return;
      const now = Date.now();
      if (now - lastRunRef.current < MIN_INTERVAL_MS) return;
      lastRunRef.current = now;
      runningRef.current = true;
      try {
        const entries = await current.ref.scan();
        const latest = dirRef.current;
        // The user may have closed or swapped the folder mid-scan. Publishing
        // now would put one folder's files under another folder's path.
        if (!latest || latest.ref.location !== current.ref.location) return;
        if (samePaths(latest.entries, entries)) return;
        onDirRef.current({ ref: current.ref, entries });
      } catch {
        // Nobody asked for this scan, so nobody should be told it failed. A
        // revoked permission or a folder that went away surfaces the moment the
        // user does ask for something, with the context to make sense of it.
      } finally {
        runningRef.current = false;
      }
    }

    const onFocus = () => void refresh();
    // `focus` alone misses a browser tab switch, where the window never lost
    // focus - only the tab went to the back.
    const onVisibility = () => { if (document.visibilityState === 'visible') void refresh(); };
    window.addEventListener('focus', onFocus);
    document.addEventListener('visibilitychange', onVisibility);
    return () => {
      window.removeEventListener('focus', onFocus);
      document.removeEventListener('visibilitychange', onVisibility);
    };
  }, []);
}
