import type { Dispatch, SetStateAction } from 'react';
import type { View } from '../views';
import type { useOpenTabs } from './useOpenTabs';

/**
 * What the tab strip, the tab keys and the "Open in tab" actions do with the
 * open tabs: show one, step round them, close one or several. Closing drops
 * the empty drafts a tab was keeping, the same rule every draft follows.
 * Spec: ops/docs/archive/note-tabs.md
 */
export function useTabActions({
  view,
  setView,
  selectedId,
  tabsShown,
  openTabs,
  selectBookmarkForEdit,
  discardIfEmpty,
  refresh,
  runSync,
  onCloseLast,
}: {
  view: View;
  setView: Dispatch<SetStateAction<View>>;
  selectedId: string | null;
  tabsShown: boolean;
  openTabs: ReturnType<typeof useOpenTabs>;
  selectBookmarkForEdit: (id: string) => Promise<void>;
  discardIfEmpty: (id: string | null, evenWithTab?: boolean) => Promise<boolean>;
  refresh: () => Promise<unknown>;
  runSync: () => Promise<void>;
  /** Empties the editor pane: the open item lost the last tab. */
  onCloseLast: () => void;
}) {
  /** Show a tab's item. It goes through the bookmark path because a plain
   *  selection of a bookmark opens its address, and a tab shows the bookmark.
   *  Trash and Markdown cannot show a live item, so they are left for All
   *  items first. Spec: ops/docs/archive/note-tabs.md (section 4) */
  function showTab(id: string) {
    if (view === 'trash' || view === 'markdown') setView('home');
    void selectBookmarkForEdit(id);
  }

  /** Open items as tabs; an item that already has one keeps it. Shows the
   *  first item that had no tab yet, or the first item when all had one. */
  function openInTab(ids: string[]) {
    const first = ids.find((id) => !openTabs.tabIds.has(id)) ?? ids[0];
    openTabs.addTabs(ids);
    if (first) showTab(first);
  }

  /** The tab before or after the open one, round the strip, as Ctrl+Tab does
   *  in a browser. The header arrows and the tab keys both step here. */
  function stepTab(direction: 1 | -1) {
    const tabs = openTabs.tabs;
    if (!tabsShown || tabs.length === 0) return;
    const at = tabs.findIndex((n) => n.id === selectedId);
    const next = at < 0 ? tabs[direction === 1 ? 0 : tabs.length - 1] : tabs[(at + direction + tabs.length) % tabs.length];
    if (next) showTab(next.id);
  }

  /** Closing the open item's tab moves to the tab beside it, the way a
   *  browser does. The last tab takes its item off the screen, as a browser
   *  window closes with its last tab. Spec: ops/issues/0568.md (Spec) */
  function closeTab(id: string) {
    if (openTabs.pinnedIds.has(id)) return;
    if (id === selectedId) {
      const at = openTabs.tabs.findIndex((n) => n.id === id);
      const next = openTabs.tabs[at + 1] ?? openTabs.tabs[at - 1];
      if (next) showTab(next.id);
      else onCloseLast();
    }
    closeTabs([id]);
  }

  /** "Close all tabs": the open item leaves with its tab, and a pinned tab
   *  that stays shows in its place. An open item with no tab stays. */
  function closeAllTabs() {
    const tabs = openTabs.tabs;
    if (selectedId !== null && openTabs.tabIds.has(selectedId) && !openTabs.pinnedIds.has(selectedId)) {
      const pinned = tabs.find((n) => openTabs.pinnedIds.has(n.id));
      if (pinned) showTab(pinned.id);
      else onCloseLast();
    }
    closeTabs(tabs.map((n) => n.id));
  }

  /** Close tabs, then drop the empty drafts a tab was keeping: the rule every
   *  draft follows, applied late. `dropIds` leaves out an item that is still
   *  on screen; that one goes when the person leaves it, as any draft does. */
  function closeTabs(dropIds: string[], ids: string[] = dropIds) {
    openTabs.closeTabs(ids);
    const drafts = dropIds.filter((x) => !openTabs.pinnedIds.has(x));
    if (drafts.length === 0) return;
    void (async () => {
      let dropped = false;
      for (const x of drafts) dropped = (await discardIfEmpty(x, true)) || dropped;
      if (dropped) { await refresh(); void runSync(); }
    })();
  }

  return { showTab, openInTab, stepTab, closeTab, closeAllTabs, closeTabs };
}
