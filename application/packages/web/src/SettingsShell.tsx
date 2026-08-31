import { Fragment, useEffect, useState, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { useIsMobile } from './useIsMobile';
import { ArrowLeft, ArrowSquareOut, CaretRight, X } from './icons';
import { AccentBar, HeadlineRule, SETTINGS_EYEBROW } from './settingsUI';

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
  /** Renders the pane body. Required unless `href` is set. */
  render?: () => ReactNode;
};

type Props = {
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

/**
 * Master-detail settings container.
 *
 * One persistent modal. On desktop (>= lg) a category rail sits beside a
 * detail pane; selecting a category swaps only the pane, so siblings are
 * one click apart and nothing closes until the top-level X / Escape.
 *
 * Below lg it collapses to a push stack: a full-width category list, and
 * tapping a category slides in its detail with a back arrow. Back returns
 * to the list; from the list, close dismisses the shell.
 *
 * The frame is intentionally dumb - it knows nothing about individual
 * panes. Callers pass a `categories` array whose `render()` returns the
 * embedded pane, keeping all prop wiring at the call site.
 */
export function SettingsShell({ categories, initialCategory, defaultCategory, footer, onClose }: Props) {
  const { t } = useTranslation('settings');
  const isMobile = useIsMobile();
  // Desktop landing: deep-link wins, else the configured default, else the
  // first real pane (link rows have no pane to land on).
  const desktopLanding =
    initialCategory ?? defaultCategory ?? categories.find((c) => !c.href)?.id ?? null;
  // null = the mobile list view. Desktop always has a selection.
  const [activeId, setActiveId] = useState<string | null>(
    isMobile ? (initialCategory ?? null) : desktopLanding,
  );

  // Guard against the ghost click from the element that opened us landing
  // on the backdrop and dismissing immediately (mobile drawer pattern).
  const [mountReady, setMountReady] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setMountReady(true));
    return () => cancelAnimationFrame(id);
  }, []);

  // Escape: if a detail is open on mobile, back to the list; else close.
  useEscapeToClose(() => {
    if (isMobile && activeId) setActiveId(null);
    else onClose();
  });

  // Resize across the breakpoint while open: desktop must never show an
  // empty detail, so adopt the default when crossing up from the list.
  useEffect(() => {
    if (!isMobile && activeId === null) setActiveId(desktopLanding);
  }, [isMobile, activeId, desktopLanding]);

  const active = categories.find((c) => c.id === activeId && !c.href) ?? null;

  function backdrop(children: ReactNode) {
    return (
      <div
        // Settings is prose, not app chrome: the global right-click menu
        // only gets in the way of selecting text here. Spec: issue #208.
        data-no-app-menu
        className="fixed inset-0 z-50 flex items-center justify-center bg-black/20 dark:bg-black/20 p-4 sm:p-6"
        onPointerDown={(e) => {
          if (mountReady && e.target === e.currentTarget) onClose();
        }}
      >
        {children}
      </div>
    );
  }

  const closeButton = (
    <button
      onClick={onClose}
      aria-label={t('common:actions.close')}
      className="text-pn-muted hover:text-pn transition p-1 -m-1"
    >
      <X size={18} />
    </button>
  );

  // ---- Mobile: push stack ------------------------------------------------
  if (isMobile) {
    if (active) {
      return backdrop(
        <div className="bg-surface-2 border border-divider rounded-lg w-full max-w-md h-[600px] max-h-[85vh] flex flex-col text-pn">
          <div className="flex items-center gap-2 px-4 py-3 border-b border-divider">
            <button
              onClick={() => setActiveId(null)}
              aria-label={t('common:actions.back')}
              className="text-pn-muted hover:text-pn transition p-1 -m-1"
            >
              <ArrowLeft size={20} />
            </button>
            <h2 className="min-w-0 text-base font-semibold leading-tight">{active.label}</h2>
          </div>
          <div className="flex-1 flex flex-col min-h-0 min-w-0">{active.render?.()}</div>
        </div>,
      );
    }
    return backdrop(
      <div className="bg-surface-2 border border-divider rounded-lg w-full max-w-md max-h-[85vh] flex flex-col text-pn">
        <div className="flex items-center justify-between px-4 py-3 border-b border-divider">
          <h2 className="text-lg font-semibold">{t('shell.title')}</h2>
          {closeButton}
        </div>
        <nav className="flex-1 overflow-y-auto py-1">
          {categories.map((c, i) => (
            <Fragment key={c.id}>
              {c.group && c.group !== categories[i - 1]?.group && (
                <div className={`px-4 pt-3 pb-1 ${SETTINGS_EYEBROW}`}>
                  {c.group}
                </div>
              )}
              {c.href ? (
                <a
                  href={c.href}
                  target="_blank"
                  rel="noopener noreferrer"
                  className="w-full flex items-center gap-3 px-4 py-3 text-sm text-start text-pn hover:bg-surface-1 transition"
                >
                  <span className="shrink-0 text-accent">{c.icon}</span>
                  <span className="flex-1 inline-flex items-center gap-1.5">
                    {c.label}
                    <ArrowSquareOut size={13} className="text-accent shrink-0" />
                  </span>
                </a>
              ) : (
                <button
                  type="button"
                  onClick={() => setActiveId(c.id)}
                  className="w-full flex items-center gap-3 px-4 py-3 text-sm text-start text-pn hover:bg-surface-1 transition"
                >
                  <span className="shrink-0 text-accent">{c.icon}</span>
                  <span className="flex-1">{c.label}</span>
                  <CaretRight size={16} className="text-pn-muted shrink-0" />
                </button>
              )}
            </Fragment>
          ))}
        </nav>
        {footer && (
          <div className="border-t border-divider p-3">{footer}</div>
        )}
      </div>,
    );
  }

  // ---- Desktop: two-pane -------------------------------------------------
  // h-640: the category rail holds 11 rows + 3 group headers and overflowed
  // 600px by 12px once Journals landed, hiding the Help row behind a scroll.
  // 640 clears it with roughly one row of slack and still sits under the
  // 85vh cap on a 13" laptop. Adding a 12th category means re-measuring.
  return backdrop(
    <div className="bg-surface-2 border border-divider rounded-lg w-full max-w-4xl h-[640px] max-h-[85vh] flex flex-col text-pn">
      <div className="flex items-center justify-between px-5 py-3 border-b border-divider">
        <h2 className="text-lg font-semibold">{t('shell.title')}</h2>
        {closeButton}
      </div>
      <div className="flex flex-1 min-h-0">
        <nav className="w-56 shrink-0 border-e border-divider flex flex-col p-2">
          <div className="flex-1 min-h-0 overflow-y-auto">
            {categories.map((c, i) => {
              const on = c.id === activeId;
              const showHeader = c.group && c.group !== categories[i - 1]?.group;
              return (
                <Fragment key={c.id}>
                  {showHeader && (
                    <div className={`px-3 pt-3 pb-1 first:pt-1 ${SETTINGS_EYEBROW}`}>
                      {c.group}
                    </div>
                  )}
                  {c.href ? (
                    <a
                      href={c.href}
                      target="_blank"
                      rel="noopener noreferrer"
                      className="w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm text-start transition text-pn-soft hover:bg-surface-1"
                    >
                      <span className="shrink-0 text-accent">{c.icon}</span>
                      <span className="flex-1 inline-flex items-center gap-1.5">
                        {c.label}
                        <ArrowSquareOut size={12} className="text-accent shrink-0" />
                      </span>
                    </a>
                  ) : (
                    <button
                      type="button"
                      onClick={() => setActiveId(c.id)}
                      aria-current={on}
                      className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm text-start transition ${
                        on
                          ? 'bg-accent/10 text-accent font-medium'
                          : 'text-pn-soft hover:bg-surface-1'
                      }`}
                    >
                      {/* Category icons are always accent, active or not, so the
                          rail reads as one family and matches the sidebar.
                          Spec: ops/docs/ui-patterns.md section 36 */}
                      <span className="shrink-0 text-accent">{c.icon}</span>
                      <span className="flex-1">{c.label}</span>
                    </button>
                  )}
                </Fragment>
              );
            })}
          </div>
          {footer && (
            <div className="border-t border-divider mt-2 pt-2">{footer}</div>
          )}
        </nav>
        <section className="flex-1 flex flex-col min-h-0 min-w-0">
          {active && (
            <div className="px-6 pt-4 pb-1 shrink-0">
              <div className="flex items-center gap-2.5">
                <AccentBar />
                <h3 className="text-base font-semibold">{active.label}</h3>
                <HeadlineRule />
              </div>
            </div>
          )}
          <div className="flex-1 flex flex-col min-h-0 min-w-0">{active?.render?.()}</div>
        </section>
      </div>
    </div>,
  );
}
