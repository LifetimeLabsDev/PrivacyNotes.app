/**
 * Items other apps shared into the phone app, taken once the app can act.
 *
 * The system share sheet hands an item to a separate process (the iOS share
 * extension), which drops it into an inbox folder and never sees a key. This
 * hook drains that inbox from inside the authenticated shell: NotesView only
 * mounts after sign-in and after the app lock, so nothing is saved before the
 * user has proved who they are, and each item is encrypted like any other the
 * moment it becomes one. It drains on mount, whenever the app comes back to
 * the front (how a user returns from the iOS share sheet), and on the
 * `pn-share-inbox` event Android's activity fires once a share is copied.
 *
 * A link becomes a bookmark (an address already saved is opened, not doubled),
 * text becomes a note (a text that is only a link becomes a bookmark), and the
 * files go through the Files upload together, in one window, each read only
 * when its turn comes, so only one file is ever held in memory. An item leaves
 * the inbox only once it is saved; one that fails stays for the next drain and
 * does not hold up the items after it.
 * Spec: ops/docs/plans/share-into-app.md
 */
import { useEffect, useRef } from 'react';
import { detectPlatform } from './devices';
import { normalizeUrl } from './linkBody';
import { perFileLimit } from './attachmentValidation';
import { proUnlocked } from './demo';
import type { LaterFile } from './notesView/useFilesUpload';

export interface SharedItem {
  id: string;
  kind: 'url' | 'text' | 'file';
  created: number;
  url?: string;
  title?: string;
  text?: string;
  name?: string;
  mime?: string;
  size?: number;
}

type ShareFile = { id: string; name: string; mime: string; size: number };

export type ShareStep =
  | { kind: 'bookmark'; id: string; url: string; title: string }
  | { kind: 'note'; id: string; text: string }
  | { kind: 'files'; files: ShareFile[] };

/** A text that is nothing but one valid web address, which people share as text. */
function loneWebUrl(text: string): string | null {
  const t = text.trim();
  return /^https?:\/\/\S+$/i.test(t) ? normalizeUrl(t) : null;
}

/** What to create, in the order the items were shared, with every file in one
 *  upload at the place of the first. Pure, for the tests. */
export function planShares(items: SharedItem[]): ShareStep[] {
  const steps: ShareStep[] = [];
  let files: ShareFile[] | null = null;
  for (const item of items) {
    if (item.kind === 'url' && item.url) {
      steps.push({ kind: 'bookmark', id: item.id, url: item.url, title: item.title ?? '' });
    } else if (item.kind === 'text' && item.text) {
      const url = loneWebUrl(item.text);
      steps.push(url
        ? { kind: 'bookmark', id: item.id, url, title: '' }
        : { kind: 'note', id: item.id, text: item.text });
    } else if (item.kind === 'file') {
      if (!files) {
        files = [];
        steps.push({ kind: 'files', files });
      }
      files.push({ id: item.id, name: item.name ?? 'file', mime: item.mime ?? '', size: item.size ?? 0 });
    }
  }
  return steps;
}

export interface ShareHandlers {
  /** Saves a bookmark, or finds the one already saved. Returns its id. */
  addBookmark: (url: string, title: string) => Promise<string>;
  /** Saves a note and returns its id. */
  addNote: (text: string) => Promise<string>;
  /** Stores files through the Files upload path, which shows its own progress.
   *  Answers the files the inbox may let go: each one stored on this device,
   *  and each one refused for good, whose reason the upload window names. A
   *  file that failed for a reason that can pass (no room yet, a failed read
   *  or store) is left out and stays in the inbox for the next drain. Must
   *  reject when it cannot store at all, so every file stays. */
  addFiles: (files: LaterFile[]) => Promise<LaterFile[]>;
  /** Shows the item made last, once the whole inbox is in. */
  reveal: (id: string) => void;
  /** False until the shell's first sync has run, so a fresh sign-in has the
   *  account's bookmarks before a shared link is checked against them. */
  ready: boolean;
  /** Asks the person about the waiting items before anything is saved.
   *  Passed on Android only, where any installed app can send a share with
   *  no step by the person. 'later' leaves every item for the next drain. */
  approve?: (items: SharedItem[]) => Promise<'save' | 'discard' | 'later'>;
}

let publishedLimit: number | null = null;

/**
 * Tells the iOS share extension this account's per-file limit, so a file the
 * upload would refuse is refused in the share sheet, with the reason, instead
 * of after a "Saved". The same rule the Files upload applies; called with the
 * figures of each quota read, so it follows an upgrade or a lapsed add-on.
 */
export function publishShareLimit(isPro: boolean, maxTotalBytes: number) {
  if (detectPlatform() !== 'ios') return;
  const limit = perFileLimit(proUnlocked(isPro), maxTotalBytes > 500 * 1000 * 1000);
  if (limit === publishedLimit) return;
  publishedLimit = limit;
  void import('@tauri-apps/api/core')
    .then(({ invoke }) => invoke('share_limit_set', { bytes: limit }))
    .catch((err) => {
      publishedLimit = null;
      console.warn('[shareInbox] limit not written:', err);
    });
}

/** Module scope, so the drain of a remount (after the app lock, say) waits
 *  for one still running from before; two would save the same item twice. */
let queue: Promise<void> = Promise.resolve();
/** True while a drain waits in the queue behind the running one; a second
 *  trigger in that time adds nothing, so a closed sheet does not reopen once
 *  for every visibility change it saw. */
let drainWaiting = false;
/** The items the person answered "later" for, in this run of the app. They
 *  are not asked about again until a new item arrives or the app restarts. */
const deferred = new Set<string>();

export async function drainOnce(live: () => boolean, handlers: () => ShareHandlers, gone?: Promise<void>) {
  const { invoke } = await import('@tauri-apps/api/core');
  const items = await invoke<SharedItem[]>('share_inbox_list');
  if (items.length === 0) return;
  // The choice covers exactly the items listed: one that arrives while the
  // sheet is open waits for the next drain and its own question.
  const approve = handlers().approve;
  if (approve) {
    if (items.every((it) => deferred.has(it.id))) return;
    // A shell that goes (the app lock, a sign-out) takes the sheet with it,
    // and its question never gets an answer: stop waiting, so the next drain
    // is not stuck behind it.
    const choice = await Promise.race([approve(items), ...(gone ? [gone.then(() => 'gone' as const)] : [])]);
    if (choice === 'gone' || !live()) return;
    if (choice === 'later') {
      for (const it of items) deferred.add(it.id);
      return;
    }
    for (const it of items) deferred.delete(it.id);
    if (choice === 'discard') {
      for (const it of items) await invoke('share_inbox_remove', { id: it.id }).catch(() => {});
      return;
    }
  }
  let last: string | null = null;
  for (const step of planShares(items)) {
    // Checked before each save, never between a save and its removal: an item
    // saved and left in the inbox would be saved again by the next drain.
    if (!live()) return;
    try {
      const h = handlers();
      if (step.kind === 'bookmark') last = await h.addBookmark(step.url, step.title);
      else if (step.kind === 'note') last = await h.addNote(step.text);
      let ids: string[];
      if (step.kind === 'files') {
        const later = step.files.map((f) => ({
          name: f.name,
          size: f.size,
          read: async () =>
            new File([await invoke<ArrayBuffer>('share_inbox_read', { id: f.id })], f.name, { type: f.mime }),
          // A file the upload keeps for a reason that can pass stays in the
          // inbox; this lets the person drop it from the upload window.
          discard: async () => {
            await invoke('share_inbox_remove', { id: f.id });
          },
        }));
        const done = new Set(await h.addFiles(later));
        ids = step.files.filter((_, i) => done.has(later[i]!)).map((f) => f.id);
      } else {
        ids = [step.id];
      }
      for (const id of ids) await invoke('share_inbox_remove', { id });
    } catch (err) {
      console.warn('[shareInbox] item kept for the next drain:', err);
    }
  }
  if (last && live()) handlers().reveal(last);
}

export function useShareInbox(handlers: ShareHandlers) {
  // The shell passes fresh closures on every render; the effect runs once ready.
  const ref = useRef(handlers);
  ref.current = handlers;

  const { ready } = handlers;
  useEffect(() => {
    const platform = detectPlatform();
    if (!ready || (platform !== 'ios' && platform !== 'android')) return;
    let live = true;
    let leave!: () => void;
    const gone = new Promise<void>((resolve) => { leave = resolve; });

    function drain() {
      if (drainWaiting) return;
      drainWaiting = true;
      queue = queue
        .then(() => {
          drainWaiting = false;
          return drainOnce(() => live, () => ref.current, gone);
        })
        .catch((err) => console.warn('[shareInbox] drain failed:', err));
    }

    function onVisible() {
      if (document.visibilityState === 'visible') drain();
    }

    drain();
    document.addEventListener('visibilitychange', onVisible);
    window.addEventListener('pn-share-inbox', drain);
    return () => {
      live = false;
      leave();
      document.removeEventListener('visibilitychange', onVisible);
      window.removeEventListener('pn-share-inbox', drain);
    };
  }, [ready]);
}
