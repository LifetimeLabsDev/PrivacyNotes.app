/**
 * Files the OS asked the desktop app to open, delivered once the app can act.
 *
 * Double-clicking a `.md` in Finder or Explorer reaches the Rust side long
 * before the frontend exists - and on a cold start, long before the user has
 * cleared the auth gate and the app lock. So the native side queues the path
 * and this hook drains it from inside the authenticated shell, which is the
 * first moment opening a file is a meaningful thing to do.
 *
 * Two delivery routes, both ending here:
 *   - Cold start: the path is already queued by the time this mounts.
 *   - Already running: `single-instance` (Windows, Linux) or `RunEvent::Opened`
 *     (macOS) queues it and emits `markdown-open-pending`.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 11)
 */
import { useEffect, useRef } from 'react';
import { detectPlatform } from '../devices';
import { openPath } from './fileAccess';
import { adaptFile } from './adapter';
import type { OpenedMarkdownFile } from './types';

export function usePendingFileOpens(
  onOpen: (file: OpenedMarkdownFile) => void,
  /** A queued file we could not open. The user double-clicked and the window
   *  came forward, so saying nothing looks like the app simply ignored them. */
  onError: () => void,
) {
  // Both callbacks arrive as inline arrows from the shell, so their identity
  // changes on every render. The effect below is mount-only and would otherwise
  // pin the first render's closures for the life of the app.
  const onOpenRef = useRef(onOpen);
  const onErrorRef = useRef(onError);
  onOpenRef.current = onOpen;
  onErrorRef.current = onError;

  useEffect(() => {
    if (detectPlatform() !== 'desktop') return;
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    /** Serialises drains. The native side hands the queue over destructively,
     *  so two overlapping drains can never see the same path - but they can
     *  each open a different one, and the loser would replace the file the user
     *  is already looking at. */
    let queue: Promise<void> = Promise.resolve();

    async function openNext() {
      const { invoke } = await import('@tauri-apps/api/core');
      const paths = await invoke<string[]>('take_pending_opens');
      // Only the last one: opening five editors at once from a multi-select is
      // not what anyone means by double-clicking a file, and the list pane can
      // only show one open file anyway.
      const path = paths[paths.length - 1];
      if (!path || cancelled) return;
      const ref = await openPath(path);
      if (cancelled) return;
      // `openPath` only declines off desktop, which the guard above has already
      // ruled out, so a null here is a path that did not become a file.
      if (!ref) { onErrorRef.current(); return; }
      const raw = await ref.read();
      const stamp = await ref.stamp();
      if (cancelled) return;
      onOpenRef.current({ ref, raw, stamp, adapted: adaptFile(ref.name, raw), reloadToken: 0 });
    }

    function drain(): Promise<void> {
      queue = queue.then(async () => {
        if (cancelled) return;
        try {
          await openNext();
        } catch {
          // An unreadable file, a path that moved between the double click and
          // this drain, a permission the OS withheld. All of them end with the
          // user staring at an app that came forward and did nothing, which is
          // the one outcome worth interrupting them about.
          if (!cancelled) onErrorRef.current();
        }
      });
      return queue;
    }

    void (async () => {
      const { listen } = await import('@tauri-apps/api/event');
      const stop = await listen('markdown-open-pending', () => void drain());
      // Unmounting while `listen` was still resolving means the cleanup below
      // has already run and will never see this handle, so drop it here rather
      // than leave a listener behind for the rest of the session.
      if (cancelled) { stop(); return; }
      unlisten = stop;
      await drain();
    })();

    return () => { cancelled = true; unlisten?.(); };
    // Mount-only: the drain takes no inputs, and re-running would register a
    // second listener on every render. The callbacks stay current through the
    // refs above rather than through the dependency list.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, []);
}
