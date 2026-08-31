/**
 * Anonymous admin events. Fires an identifier-free row into
 * admin_events on import/export. Fire-and-forget; failures
 * never block the user's operation.
 */

import type { SupabaseClient } from '@notes/shared';
import { isDemoMode } from './demo';

export type AdminEventType = 'import' | 'export';

export type ImportSource =
  | 'google-keep'
  | 'standard-notes'
  | 'obsidian'
  | 'notesnook'
  | 'apple-notes'
  | 'apple-journal'
  | 'samsung-notes'
  | 'simplenote'
  | 'markdown-folder'
  | 'privacynotes'
  | 'browser-bookmarks'
  | 'browser-passwords'
  | 'encrypted';

export type ExportSource =
  | 'md'
  | 'html'
  | 'md-zip'
  | 'html-zip'
  | 'json'
  | 'encrypted'
  | 'encrypted-zip'
  | 'vault'
  | 'bookmarks'
  | 'pdf'
  | 'burn';

export type AdminEventSource = ImportSource | ExportSource;

/**
 * Insert a single anonymous event row. Never throws - failures are
 * logged and then swallowed so the caller's happy path keeps running.
 */
export function recordAdminEvent(
  supabase: SupabaseClient,
  type: AdminEventType,
  source: AdminEventSource,
): void {
  // Demo mode makes zero server calls - the sandbox has no account to
  // attribute an event to, and try.privacynotes.app would otherwise
  // write a real admin_events row on every export/import.
  if (isDemoMode()) return;
  // Not awaited. The insert runs in the background while the user's
  // import/export code path finishes. If the network is down or RLS
  // rejects the row for any reason, we do not want that to surface
  // as a failed import.
  void supabase
    .from('admin_events')
    .insert({ type, source })
    .then(
      ({ error }) => {
        if (error) {
          // eslint-disable-next-line no-console
          console.warn('[admin_events] insert failed:', error.message);
        }
      },
      (err: unknown) => {
        // eslint-disable-next-line no-console
        console.warn('[admin_events] insert threw:', err);
      },
    );
}
