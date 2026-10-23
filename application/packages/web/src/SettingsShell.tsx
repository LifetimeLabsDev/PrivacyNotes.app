import type { ReactNode } from 'react';

export type SettingsCategory = {
  id: string;
  label: string;
  icon: ReactNode;
  /**
   * Optional section label. Consecutive categories sharing a group render
   * under one header; the header shows when the group changes. Categories
   * must be ordered so each group is contiguous.
   */
  group?: string;
  /**
   * Turns the row into an external link instead of a pane: it opens in a new
   * tab (the system browser on desktop, via App.tsx's opener interceptor),
   * never becomes the active selection, and never lands as the desktop
   * default. Use `siteHref()` so the URL is absolute off the web.
   * `render` is ignored when this is set.
   * Spec: ops/docs/archive/ui-patterns.md section 36 (settings standard)
   */
  href?: string;
  /**
   * Renders the pane body. Required unless `href` is set. `navigate` opens
   * a sibling category from inside a pane, on one of its inner tabs when
   * `tab` is given, which is how a pane can carry a link to another pane
   * without knowing the shell. `initialTab` is the inner tab a search result
   * or a `navigate` points at; the pane opens on it.
   */
  render?: (tools: { navigate: (id: string, tab?: string) => void; initialTab?: string }) => ReactNode;
};

export type SettingsShellProps = {
  categories: SettingsCategory[];
  /**
   * Deep-link target. Opens this category's detail on both layouts
   * (on mobile it skips the list). Takes precedence over defaultCategory.
   */
  initialCategory?: string;
  /**
   * A row inside `initialCategory` to land on, the way a search result does:
   * the pane opens on the row's tab and the row flashes. The quick switcher
   * opens a setting this way. `flash: false` opens the tab without the
   * flash, for a door that lands on a whole tab rather than one row.
   */
  initialSetting?: { id: string; tab?: string; flash?: boolean };
  /**
   * Desktop landing category when not deep-linked. Mobile still opens to
   * the list. Falls back to the first category.
   */
  defaultCategory?: string;
  /** Pinned footer action area (e.g. Sign out). */
  footer?: ReactNode;
  /**
   * Desktop only: open on `initialCategory` alone, without the category rail
   * and the search field, for a door that leads to one pane and needs its
   * width (the editor's format bar gear, the Design popover). An "All
   * settings" button in the header brings the rail back.
   */
  solo?: boolean;
  onClose: () => void;
};
