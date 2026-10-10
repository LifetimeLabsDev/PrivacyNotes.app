import { useEffect, useRef } from 'react';
import { detectPlatform } from './devices';
import { parseShortcut, type ShortcutTarget } from './noteShortcut';

const LAST_KEY = 'privacynotes.shortcut.lastNative';

/**
 * Shortcuts that reach an installed app: `privacynotes://note/<id>` on the
 * desktop, the `https://use.privacynotes.app/note` app link on a phone.
 * Mounted by the notes view, so it listens only while the vault is open; a
 * shortcut that arrives before sign-in or unlock is not kept.
 *
 * `getCurrent()` hands back the launch link again after a webview reload and
 * after the view remounts, so a link it returns opens only when it differs
 * from the last one handled in this tab. An `onOpenUrl` event is a new click
 * and always opens. Android delivers a link to a running app without
 * firing `onOpenUrl`, so a resume asks for the current link too, the same
 * as the sign-in listener in authOAuth.ts.
 *
 * Spec: ops/docs/plans/note-shortcuts.md (5.2)
 */
export function useShortcutDeepLinks(onTarget: (t: ShortcutTarget) => void): void {
  const onTargetRef = useRef(onTarget);
  onTargetRef.current = onTarget;

  useEffect(() => {
    if (detectPlatform() === 'web') return;
    let cancelled = false;
    let unlisten: (() => void) | undefined;
    let stopResume: (() => void) | undefined;

    const take = (url: string | undefined, replay: boolean) => {
      if (!url || cancelled) return;
      const t = parseShortcut(url);
      if (!t) return;
      try {
        if (replay && sessionStorage.getItem(LAST_KEY) === url) return;
        sessionStorage.setItem(LAST_KEY, url);
      } catch {
        /* storage unavailable: the link opens, a replay may open it again */
      }
      onTargetRef.current(t);
    };

    void (async () => {
      try {
        const { onOpenUrl, getCurrent } = await import('@tauri-apps/plugin-deep-link');
        take((await getCurrent())?.[0], true);
        const un = await onOpenUrl((urls) => take(urls?.[0], false));
        if (cancelled) {
          un();
          return;
        }
        unlisten = un;
        const onResume = () => {
          if (document.hidden) return;
          getCurrent().then((cur) => take(cur?.[0], true), () => {
            /* transient plugin failure: the next resume asks again */
          });
        };
        window.addEventListener('focus', onResume);
        document.addEventListener('visibilitychange', onResume);
        stopResume = () => {
          window.removeEventListener('focus', onResume);
          document.removeEventListener('visibilitychange', onResume);
        };
      } catch (e) {
        console.error('Shortcut listener setup failed:', e);
      }
    })();
    return () => {
      cancelled = true;
      unlisten?.();
      stopResume?.();
    };
  }, []);
}
