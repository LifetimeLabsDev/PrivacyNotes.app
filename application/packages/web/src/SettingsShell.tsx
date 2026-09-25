import { lazy, Suspense, type ReactNode } from 'react';

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
   * Spec: ops/docs/ui-patterns.md section 36 (settings standard)
   */
  href?: string;
  /**
   * Renders the pane body. Required unless `href` is set. `navigate` opens
   * a sibling category from inside a pane, which is how a pane can carry a
   * link to another pane without knowing the shell. `initialTab` is the
   * inner tab a search result points at; the pane opens on it.
   */
  render?: (tools: { navigate: (id: string) => void; initialTab?: string }) => ReactNode;
};

export type SettingsShellProps = {
  categories: SettingsCategory[];
  /**
   * Deep-link target. Opens this category's detail on both layouts
   * (on mobile it skips the list). Takes precedence over defaultCategory.
   */
  initialCategory?: string;
  /**
   * Desktop landing category when not deep-linked. Mobile still opens to
   * the list. Falls back to the first category.
   */
  defaultCategory?: string;
  /** Pinned footer action area (e.g. Sign out). */
  footer?: ReactNode;
  onClose: () => void;
};

const SettingsWindow = lazy(() => import('./SettingsWindow').then((m) => ({ default: m.SettingsWindow })));

/**
 * The settings window, loaded when it first opens. It appears a frame later
 * on a cold cache, as the other modals do (`lazyModal` in
 * notesView/settingsCategories.tsx), and none of it, the search field
 * included, sits in the boot path. The window itself is SettingsWindow.tsx.
 */
export function SettingsShell(props: SettingsShellProps) {
  return (
    <Suspense fallback={null}>
      <SettingsWindow {...props} />
    </Suspense>
  );
}
