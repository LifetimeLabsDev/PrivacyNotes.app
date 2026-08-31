/**
 * Which app the OS opens Markdown files with, and offering to make it us.
 *
 * The registration that makes a double-click reach the app at all lives in the
 * bundle (`bundle.fileAssociations`). This is the separate question of who the
 * OS considers the DEFAULT handler, and it is three genuinely different features
 * wearing one label:
 *
 *   - **macOS** and **Linux** can be changed from here, in one call.
 *   - **Windows** cannot, at all. Microsoft blocked programmatic default
 *     changes in Windows 8, so the only honest control there is a button that
 *     opens Settings on our page. `settable: false` carries that.
 *
 * Two shapes this deliberately does NOT have, both of which look like the
 * obvious design until you try them:
 *
 * **It is not a toggle.** No platform has an "unset the default handler" API -
 * `LSSetDefaultRoleHandlerForContentType` and `xdg-mime default` can only point
 * a type AT an app, never away from one. A switch would therefore be a control
 * that cannot go back, so the UI is a button that becomes a statement.
 *
 * **It stores nothing.** The OS is the only source of truth, and the answer is
 * per device - a Mac and a Linux box need different ones - so nothing here
 * touches `userSettings` or any other synced store. It also cannot be cached
 * across a session: another installer can take the association while we are
 * running, which is why `useMarkdownDefaultApp` re-reads on window focus.
 *
 * Isolation: this module imports `detectPlatform` and nothing else from outside
 * the pillar. The per-OS wording is chosen from `status.platform`, which the
 * Rust side reports from `cfg!`, rather than sniffed from the user agent - a
 * fact that cannot be wrong, and no new import to get it.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 11)
 */
import { useEffect, useState } from 'react';
import { detectPlatform } from '../devices';

/** Who owns the Markdown association right now. Not exported: consumers reach it
 *  structurally through `MarkdownAssoc['owner']`, and an exported alias nothing
 *  imports by name is what `check:dead` is for. */
type MarkdownAssocOwner =
  /** Us. The one state with nothing to offer. */
  | 'ours'
  /** Another app, named in `otherName` when the OS would say which. */
  | 'other'
  /** Nothing is registered. Double-clicking currently opens a picker. */
  | 'none'
  /** The OS would not answer. Offer the action, claim nothing about the past. */
  | 'unknown';

export type MarkdownAssoc = {
  /** Which file manager to name in the hint. */
  platform: 'macos' | 'windows' | 'linux';
  /** False on Windows, where only the user may change this. */
  settable: boolean;
  owner: MarkdownAssocOwner;
  /** Display name of the current owner, when the OS gave one. */
  otherName: string | null;
};

/** Serialised shape of the Rust command. Mapped rather than used directly so a
 *  field rename on either side is a type error here instead of an undefined at
 *  a render site. */
type RawAssoc = {
  platform: string;
  settable: boolean;
  owner: string;
  other_name: string | null;
};

const OWNERS: MarkdownAssocOwner[] = ['ours', 'other', 'none', 'unknown'];

/** True where this feature exists at all. Web and mobile have no OS-level file
 *  association to read, let alone set. */
export function markdownDefaultAppSupported(): boolean {
  return detectPlatform() === 'desktop';
}

async function invokeStatus(): Promise<MarkdownAssoc | null> {
  if (!markdownDefaultAppSupported()) return null;
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    const raw = await invoke<RawAssoc>('markdown_assoc_status');
    return {
      platform:
        raw.platform === 'macos' || raw.platform === 'windows' ? raw.platform : 'linux',
      settable: raw.settable === true,
      owner: OWNERS.includes(raw.owner as MarkdownAssocOwner)
        ? (raw.owner as MarkdownAssocOwner)
        : 'unknown',
      otherName: raw.other_name ?? null,
    };
  } catch {
    // An older binary with a newer bundle: the command is simply absent. Treat
    // it as "no such feature here" rather than surfacing an error for something
    // the user cannot act on.
    return null;
  }
}

/**
 * Point the Markdown association at us. Throws with a message worth showing.
 *
 * Never called on Windows - the UI offers `openOsDefaultAppSettings` there
 * instead - but the native side rejects it anyway rather than trusting the
 * caller.
 */
export async function claimMarkdownDefaultApp(): Promise<void> {
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('markdown_assoc_claim');
}

/** Windows only: open Settings on our Default apps page. */
export async function openOsDefaultAppSettings(): Promise<void> {
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('markdown_assoc_open_os_settings');
}

/* ── shared state ─────────────────────────────────────────────────────────
 *
 * One status for the whole app rather than one per component. Up to three
 * consumers can be mounted at once (the folder toolbar's button, the popover it
 * opens, and either the resting pane's card or the explainer's row), and with a
 * hook-local `useState` each they would each invoke on mount and on every focus
 * and could disagree for a beat afterwards - the toolbar button showing a tick
 * while the card beside it still offers the button. A module-level value with
 * subscribers makes that impossible, and costs one fetch instead of three.
 */

let cached: MarkdownAssoc | null = null;
let inFlight: Promise<void> | null = null;
/** Serialises reads so two can never apply out of order, and so a forced read
 *  always STARTS after whatever is already running has finished. */
let chain: Promise<void> = Promise.resolve();
const listeners = new Set<(value: MarkdownAssoc | null) => void>();

async function readStatus(): Promise<void> {
  const next = await invokeStatus();
  cached = next;
  for (const listener of listeners) listener(next);
}

/**
 * Re-read from the OS and notify every mounted consumer.
 *
 * Coalesced: three components mounting in the same tick, or a refresh landing on
 * top of a focus event, share one round trip.
 *
 * There is deliberately NO way to force an uncoalesced read, and no caller takes
 * one straight after a write. That combination was the bug: a read started before
 * the write answers with the state the write just changed, because LaunchServices
 * serves an in-process read from a cache that lags behind. `markMarkdownDefault-
 * AppOurs` publishes the outcome instead, and reconciliation waits for the next
 * focus - by which time the OS has settled.
 *
 * Reads are still serialised through `chain` so two of them can never apply out
 * of order, which two focus events in quick succession can otherwise do.
 */
function refreshMarkdownDefaultApp(): Promise<void> {
  if (inFlight) return inFlight;
  // `then(fn, fn)` rather than `then(fn)`: a rejected predecessor must not
  // poison the chain for every later read. `readStatus` swallows its own errors
  // through `invokeStatus`, so this is belt and braces.
  chain = chain.then(readStatus, readStatus);
  const mine = chain;
  inFlight = mine;
  void mine.finally(() => { if (inFlight === mine) inFlight = null; });
  return mine;
}

/**
 * Publish "we own it" without a round trip, after a claim the OS said succeeded.
 *
 * Two reasons this is not laziness. First, LaunchServices answers a read from the
 * SAME process out of a cache that has not caught up with the write, so an
 * immediate read-back can report the handler we just replaced - which is how a
 * successful claim ended up leaving the old status on screen. Second, resolving a
 * bundle id to a bundle can take tens of seconds on a machine with a lot of stale
 * registrations (a dev box with a hundred mounted-and-gone DMGs is the case), and
 * making the user watch a disabled button for that long to be told something the
 * OSStatus already confirmed is the wrong trade.
 *
 * An `OSStatus` of 0 IS the confirmation. Nothing is invented here: if the write
 * somehow did not stick, the next window focus re-reads and corrects it.
 */
export function markMarkdownDefaultAppOurs(): void {
  if (!cached) return;
  cached = { ...cached, owner: 'ours', otherName: null };
  for (const listener of listeners) listener(cached);
}

/**
 * The status, kept current.
 *
 * Re-reads on window focus because the association is OS state we do not own:
 * the user can change it in System Settings, and an installer can take it,
 * while the app sits there showing a stale tick. `focus` and not
 * `visibilitychange` - returning from System Settings refocuses the window
 * without ever hiding it.
 */
export function useMarkdownDefaultApp(): MarkdownAssoc | null {
  const [state, setState] = useState<MarkdownAssoc | null>(cached);

  useEffect(() => {
    if (!markdownDefaultAppSupported()) return;
    listeners.add(setState);
    void refreshMarkdownDefaultApp();
    const onFocus = () => void refreshMarkdownDefaultApp();
    window.addEventListener('focus', onFocus);
    return () => {
      listeners.delete(setState);
      window.removeEventListener('focus', onFocus);
    };
  }, []);

  return state;
}
