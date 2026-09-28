/**
 * The choices a burn link offers its sender. The sender's modal and the
 * viewer page both read this, and the viewer loads nothing else of the app.
 */

/** How long the note stays on the reader's screen, in seconds. */
export const BURN_READ_SECONDS = [120, 300, 900, 1800, 3600] as const;
export const DEFAULT_BURN_READ_SECONDS = 300;

/**
 * How long an unopened link lives, in hours. The database refuses any other
 * value. Spec: packages/supabase/migrations/history/0094_burn_note_lifetime.sql
 */
export const BURN_LIFETIME_HOURS = [1, 24, 72, 168] as const;
export const DEFAULT_BURN_LIFETIME_HOURS = 24;

/**
 * The payload comes from whoever made the link, so anything but a listed
 * value reads as two minutes, the window every link had before the sender
 * could choose.
 */
export function readBurnSeconds(raw: unknown): number {
  return (BURN_READ_SECONDS as readonly unknown[]).includes(raw) ? (raw as number) : 120;
}
