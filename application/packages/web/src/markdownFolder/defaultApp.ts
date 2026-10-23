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
 * running, which is why `useDefaultApp` re-reads on window focus.
 *
 * Isolation: this module imports `detectPlatform` and nothing else from outside
 * the pillar. The per-OS wording is chosen from `status.platform`, which the
 * Rust side reports from `cfg!`, rather than sniffed from the user agent - a
 * fact that cannot be wrong, and no new import to get it.
 *
 * Spec: ops/docs/archive/markdown-folder.md (section 11)
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
  /** macOS: another app opens the file, and only Finder's Change All can fix
   *  it, because a claim from the app would be skipped. The UI gives the
   *  steps instead of a button. */
  finderOnly: boolean;
};

/** Serialised shape of the Rust command. Mapped rather than used directly so a
 *  field rename on either side is a type error here instead of an undefined at
 *  a render site. */
type RawAssoc = {
  platform: string;
  settable: boolean;
  owner: string;
  other_name: string | null;
  /** Absent from a binary older than the field. */
  finder_only?: boolean;
};

const OWNERS: MarkdownAssocOwner[] = ['ours', 'other', 'none', 'unknown'];

/** True where this feature exists at all. Web and mobile have no OS-level file
 *  association to read, let alone set. */
export function markdownDefaultAppSupported(): boolean {
  return detectPlatform() === 'desktop';
}

/** Which file type a status or a claim is about. */
export type AssocKind = 'markdown' | 'text';

const COMMANDS: Record<AssocKind, { status: string; claim: string }> = {
  markdown: { status: 'markdown_assoc_status', claim: 'markdown_assoc_claim' },
  text: { status: 'text_assoc_status', claim: 'text_assoc_claim' },
};

async function invokeStatus(kind: AssocKind): Promise<MarkdownAssoc | null> {
  if (!markdownDefaultAppSupported()) return null;
  try {
    const { invoke } = await import('@tauri-apps/api/core');
    // Null for `.txt` on Linux, where the row is not offered.
    const raw = await invoke<RawAssoc | null>(COMMANDS[kind].status);
    if (!raw) return null;
    return {
      platform:
        raw.platform === 'macos' || raw.platform === 'windows' ? raw.platform : 'linux',
      settable: raw.settable === true,
      owner: OWNERS.includes(raw.owner as MarkdownAssocOwner)
        ? (raw.owner as MarkdownAssocOwner)
        : 'unknown',
      otherName: raw.other_name ?? null,
      finderOnly: raw.finder_only === true,
    };
  } catch {
    // An older binary with a newer bundle: the command is simply absent. Treat
    // it as "no such feature here" rather than surfacing an error for something
    // the user cannot act on.
    return null;
  }
}

/**
 * Point the association for `kind` at us. Throws with a message worth showing.
 *
 * Never called on Windows - the UI offers `openOsDefaultAppSettings` there
 * instead - but the native side rejects it anyway rather than trusting the
 * caller.
 */
export async function claimDefaultApp(kind: AssocKind): Promise<void> {
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke(COMMANDS[kind].claim);
}

/** Windows only: open Settings on our Default apps page, which lists every
 *  type we registered. */
export async function openOsDefaultAppSettings(): Promise<void> {
  const { invoke } = await import('@tauri-apps/api/core');
  await invoke('markdown_assoc_open_os_settings');
}

/* ── shared state ─────────────────────────────────────────────────────────
 *
 * One status per file type for the whole app rather than one per component.
 * Up to four consumers of the Markdown status can be mounted at once (the
 * folder toolbar's button, the popover it opens, the resting pane's card or
 * the explainer's row, and the Settings row), and with a hook-local `useState`
 * each would invoke on mount and on every focus and could disagree for a beat
 * afterwards. A module-level value with subscribers makes that impossible.
 */

type Store = {
  cached: MarkdownAssoc | null;
  inFlight: Promise<void> | null;
  /** Serialises reads so two can never apply out of order. */
  chain: Promise<void>;
  listeners: Set<(value: MarkdownAssoc | null) => void>;
};

const newStore = (): Store => ({ cached: null, inFlight: null, chain: Promise.resolve(), listeners: new Set() });
const stores: Record<AssocKind, Store> = { markdown: newStore(), text: newStore() };

/**
 * Re-read from the OS and notify every mounted consumer.
 *
 * Coalesced: components mounting in the same tick, or a refresh landing on
 * top of a focus event, share one round trip.
 *
 * There is deliberately NO way to force an uncoalesced read, and no caller takes
 * one straight after a write. On macOS the write returns while the system's
 * confirmation dialog is still open, so a read then reports the old handler;
 * the read that counts is the one on the focus that follows the dialog.
 */
function refreshDefaultApp(kind: AssocKind): Promise<void> {
  const store = stores[kind];
  if (store.inFlight) return store.inFlight;
  const read = async () => {
    const next = await invokeStatus(kind);
    store.cached = next;
    for (const listener of store.listeners) listener(next);
  };
  // `then(fn, fn)` rather than `then(fn)`: a rejected predecessor must not
  // poison the chain for every later read.
  store.chain = store.chain.then(read, read);
  const mine = store.chain;
  store.inFlight = mine;
  void mine.finally(() => { if (store.inFlight === mine) store.inFlight = null; });
  return mine;
}

/**
 * After a macOS claim: read once a second until the owner changes, for a
 * minute at most. The system dialog does not take focus from the window, so
 * no focus event follows the person's answer. A declined dialog leaves the
 * owner as it was, and the reads stop at the minute.
 * Spec: ops/docs/plans/default-app-settings.md (section 5.1)
 */
export async function watchClaim(kind: AssocKind): Promise<void> {
  const before = stores[kind].cached?.owner;
  for (let i = 0; i < 60; i++) {
    await new Promise((resolve) => setTimeout(resolve, 1000));
    await refreshDefaultApp(kind);
    if (stores[kind].cached?.owner !== before) return;
  }
}

/**
 * Publish "we own it" without a round trip, after a Linux claim.
 *
 * Linux only: `xdg-mime` has written the association when it exits 0. On macOS
 * the call returns 0 before the person answers the system dialog, and also when
 * they decline it, so nothing may be published there until a read confirms it.
 * Spec: ops/docs/plans/default-app-settings.md (section 5.1)
 */
export function markDefaultAppOurs(kind: AssocKind): void {
  const store = stores[kind];
  if (!store.cached) return;
  store.cached = { ...store.cached, owner: 'ours', otherName: null };
  for (const listener of store.listeners) listener(store.cached);
}

/**
 * The status for `kind`, kept current.
 *
 * Re-reads on window focus because the association is OS state we do not own:
 * the user can change it in System Settings, and an installer can take it,
 * while the app sits there showing a stale tick. `focus` and not
 * `visibilitychange` - returning from System Settings refocuses the window
 * without ever hiding it.
 */
export function useDefaultApp(kind: AssocKind): MarkdownAssoc | null {
  const [state, setState] = useState<MarkdownAssoc | null>(stores[kind].cached);

  useEffect(() => {
    if (!markdownDefaultAppSupported()) return;
    const { listeners } = stores[kind];
    listeners.add(setState);
    void refreshDefaultApp(kind);
    const onFocus = () => void refreshDefaultApp(kind);
    window.addEventListener('focus', onFocus);
    return () => {
      listeners.delete(setState);
      window.removeEventListener('focus', onFocus);
    };
  }, [kind]);

  return state;
}
