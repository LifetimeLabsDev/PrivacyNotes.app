/**
 * Reopening the remembered folder at app start, not at pillar-visit.
 *
 * This lived inside the Markdown pane until v0.309.5, which meant the folder
 * was only restored once someone opened that pillar - and so the sidebar's file
 * count was blank until they did, on every launch. The count is one of the
 * reasons to go there, so it cannot depend on having already gone.
 *
 * Runs at the shell level instead, once per session. Cheap on desktop (a path
 * needs no permission); on the web it costs one `queryPermission` call, and
 * only proceeds to a scan when the answer is already `granted`.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 5)
 */
import { useEffect, useState } from 'react';
import { checkHandle, forgetFolder, recallFolder, requestHandle } from './folderMemory';
import { directoryFromHandle, directoryFromPath } from './fileAccess';
import type { OpenedMarkdownDir } from './types';

export interface FolderRestore {
  /** A remembered browser folder whose permission lapsed. Chromium re-grants
   *  only from a user gesture, so this becomes a button rather than something
   *  the restore can resolve on its own. */
  reopen: FileSystemDirectoryHandle | null;
  /** Call from a click. Resolves the handle and opens the folder. */
  acceptReopen: () => Promise<void>;
}

export function useFolderRestore(
  dir: OpenedMarkdownDir | null,
  onDir: (next: OpenedMarkdownDir | null) => void,
): FolderRestore {
  const [reopen, setReopen] = useState<FileSystemDirectoryHandle | null>(null);

  useEffect(() => {
    if (dir) return;
    let cancelled = false;
    void (async () => {
      const stored = await recallFolder();
      if (!stored || cancelled) return;

      if (stored.kind === 'path') {
        const ref = await directoryFromPath(stored.path);
        const entries = await ref.scan().catch(() => null);
        // A folder since moved or deleted should not haunt the UI forever.
        if (entries === null) { void forgetFolder(); return; }
        if (!cancelled) onDir({ ref, entries });
        return;
      }

      const state = await checkHandle(stored.handle);
      if (cancelled) return;
      if (state === 'lost') { void forgetFolder(); return; }
      if (state === 'needs-click') { setReopen(stored.handle); return; }
      const ref = directoryFromHandle(stored.handle);
      const entries = await ref.scan().catch(() => null);
      if (entries !== null && !cancelled) onDir({ ref, entries });
    })();
    return () => { cancelled = true; };
    // Mount-only: restoring once is the point, and re-running on every `dir`
    // change would fight the user closing the folder.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);

  async function acceptReopen() {
    if (!reopen) return;
    if (!(await requestHandle(reopen))) return;
    const ref = directoryFromHandle(reopen);
    onDir({ ref, entries: await ref.scan() });
    setReopen(null);
  }

  return { reopen, acceptReopen };
}
