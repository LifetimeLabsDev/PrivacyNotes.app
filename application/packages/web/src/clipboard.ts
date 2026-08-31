import { useCallback, useEffect, useRef, useState } from 'react';

/* ────────────────────────────────────────────────────────────────
 * Shared copy-to-clipboard hook for the vault forms - single source
 * of truth (was duplicated per form).
 *
 * `copy(text, label)` writes to the clipboard and lights the matching
 * button's "Copied" state for 2s. Copies are plain writes: there is
 * deliberately NO timed auto-clear. The web platform cannot do one
 * honestly - clearing from a background tab is rejected (and WebKit
 * wants a user gesture), while re-firing a missed wipe when the user
 * returns cannot know whether the clipboard still holds our secret
 * or something they copied elsewhere in the meantime (reading it
 * back needs a permission prompt), so it risks eating user data.
 * Removed 2026-07-24; if reviving, see ops/docs/roadmap.md (native
 * read-compare-clear via the Tauri clipboard-manager plugin is the
 * only honest path, desktop-only).
 * ──────────────────────────────────────────────────────────────── */
export function useCopyToClipboard() {
  const feedbackTimer = useRef<ReturnType<typeof setTimeout> | undefined>(undefined);
  const [copied, setCopied] = useState<string | null>(null);

  const copy = useCallback((text: string, label: string) => {
    navigator.clipboard.writeText(text).then(() => {
      setCopied(label);
      if (feedbackTimer.current) clearTimeout(feedbackTimer.current);
      feedbackTimer.current = setTimeout(() => setCopied(null), 2000);
    }).catch(() => {
      // Clipboard write denied (revoked permission, sandboxed embed).
      // No "Copied" feedback is the honest signal; without this catch
      // the rejection surfaces as an uncaught error in the console.
    });
  }, []);

  useEffect(() => () => {
    if (feedbackTimer.current) clearTimeout(feedbackTimer.current);
  }, []);

  return { copy, copied };
}
