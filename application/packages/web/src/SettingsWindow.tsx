import { Fragment, useEffect, useMemo, useRef, useState, type KeyboardEvent as ReactKeyboardEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { ensureSettingsSearchLoaded } from './i18n';
import { isImeComposing } from './imeComposing';
import { useEscapeToClose } from './useEscapeToClose';
import { useIsMobile } from './useIsMobile';
import { ArrowLeft, ArrowSquareOut, CaretRight, X } from './icons';
import { AccentBar, HeadlineRule, SETTINGS_EYEBROW } from './settingsUI';
import type { SettingsShellProps as Props } from './SettingsShell';

type SearchModule = typeof import('./settingsSearch/SettingsSearchResults');
type Hit = import('./settingsSearch/SettingsSearchResults').SettingHit;

/** A search result that has been opened: its row, and the tab it lives on. */
type Landing = { id: string; tab?: string; flash: boolean };

/** Open a link the way a click on it would, so the desktop opener sees it. */
function openLink(href: string) {
  const a = document.createElement('a');
  a.href = href;
  a.target = '_blank';
  a.rel = 'noopener noreferrer';
  document.body.appendChild(a);
  a.click();
  a.remove();
}

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
 * The search field sits in the header on desktop and on top of the list on
 * a phone. Its code and strings load on the field's first focus, so this
 * window carries only the field. Results fill the pane; the rail dims a
 * section with no hit and counts the hits of the others. A result opens its
 * section on the result's tab and flashes the row; "Back to results" keeps
 * the query. Escape clears the query before it closes anything.
 * Spec: ops/docs/ui-patterns.md (section 114, settings search)
 *
 * The frame is intentionally dumb - it knows nothing about individual
 * panes. Callers pass a `categories` array whose `render()` returns the
 * embedded pane, keeping all prop wiring at the call site.
 */
export function SettingsWindow({ categories, initialCategory, defaultCategory, footer, onClose }: Props) {
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

  const [query, setQuery] = useState('');
  const [search, setSearch] = useState<SearchModule | null>(null);
  const [activeIndex, setActiveIndex] = useState(0);
  const [landing, setLanding] = useState<Landing | null>(null);
  // Bumped on every landing, so the pane remounts on the result's tab.
  const [paneKey, setPaneKey] = useState(0);
  const fieldRef = useRef<HTMLInputElement | null>(null);
  const paneRef = useRef<HTMLDivElement | null>(null);

  function loadSearch() {
    if (search) return;
    void Promise.all([import('./settingsSearch/SettingsSearchResults'), ensureSettingsSearchLoaded()])
      .then(([mod]) => setSearch(mod))
      .catch((err) => console.warn('[settings] search failed to load:', err));
  }

  const hits: Hit[] | null = useMemo(
    () => (search && query.trim() ? search.runSettingsSearch(query, new Map(categories.map((c) => [c.id, c.label]))) : null),
    [search, query, categories],
  );
  const searching = query.trim() !== '' && landing === null;

  function changeQuery(next: string) {
    // Focus loads the search; a value that arrives without one (a paste
    // from the context menu, an autofill) loads it too.
    if (next) loadSearch();
    setQuery(next);
    setActiveIndex(0);
    setLanding(null);
  }

  function clearSearch() {
    changeQuery('');
  }

  function openCategory(id: string) {
    if (query) clearSearch();
    setLanding(null);
    setActiveId(id);
  }

  function pick(hit: Hit) {
    const category = categories.find((c) => c.id === hit.entry.section);
    if (!category) return;
    if (category.href) {
      openLink(category.href);
      return;
    }
    setActiveId(category.id);
    setLanding({ id: hit.entry.id, ...(hit.entry.tab ? { tab: hit.entry.tab } : {}), flash: !hit.entry.isSection });
    setPaneKey((k) => k + 1);
  }

  // Scroll to the opened row once its pane has mounted.
  useEffect(() => {
    if (!landing?.flash || !search || !paneRef.current) return;
    return search.jumpToSetting(paneRef.current, landing.id);
  }, [landing, paneKey, search]);

  // Cmd/Ctrl+K reaches this field while the window is open, not the list
  // search behind it. Capture phase, so the app's own shortcut never sees it.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (isImeComposing(e)) return;
      if ((e.metaKey || e.ctrlKey) && !e.altKey && !e.shiftKey && e.code === 'KeyK') {
        e.preventDefault();
        e.stopPropagation();
        if (isMobile && activeId) {
          setActiveId(null);
          setLanding(null);
        }
        requestAnimationFrame(() => {
          fieldRef.current?.focus();
          fieldRef.current?.select();
        });
      }
    }
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [isMobile, activeId]);

  // Guard against the ghost click from the element that opened us landing
  // on the backdrop and dismissing immediately (mobile drawer pattern).
  const [mountReady, setMountReady] = useState(false);
  useEffect(() => {
    const id = requestAnimationFrame(() => setMountReady(true));
    return () => cancelAnimationFrame(id);
  }, []);

  // Escape: a query clears first. Then, if a detail is open on mobile, back
  // to the list; else close.
  useEscapeToClose(() => {
    if (query) clearSearch();
    else if (isMobile && activeId) setActiveId(null);
    else onClose();
  });

  // Resize across the breakpoint while open: desktop must never show an
  // empty detail, so adopt the default when crossing up from the list.
  useEffect(() => {
    if (!isMobile && activeId === null) setActiveId(desktopLanding);
  }, [isMobile, activeId, desktopLanding]);

  const active = categories.find((c) => c.id === activeId && !c.href) ?? null;

  function onFieldKey(e: ReactKeyboardEvent<HTMLInputElement>) {
    if (isImeComposing(e) || !hits || !searching) return;
    if (e.key === 'ArrowDown' || e.key === 'ArrowUp') {
      e.preventDefault();
      if (hits.length === 0) return;
      const step = e.key === 'ArrowDown' ? 1 : -1;
      setActiveIndex((i) => (i + step + hits.length) % hits.length);
    } else if (e.key === 'Enter') {
      const hit = hits[activeIndex];
      if (!hit) return;
      e.preventDefault();
      pick(hit);
    }
  }

  const sectionLabel = (id: string) => categories.find((c) => c.id === id)?.label ?? id;
  const sectionIcon = (id: string) => categories.find((c) => c.id === id)?.icon ?? null;
  const counts = new Map<string, number>();
  if (searching && hits) for (const hit of hits) counts.set(hit.entry.section, (counts.get(hit.entry.section) ?? 0) + 1);

  const field = (
    <div className="relative flex-1 min-w-0">
      {/* Drawn inline: the icon set's glyph would pull its own chunk into the boot path. */}
      <svg
        viewBox="0 0 16 16"
        width="15"
        height="15"
        fill="none"
        stroke="currentColor"
        strokeWidth="1.75"
        strokeLinecap="round"
        className="absolute start-2.5 top-1/2 -translate-y-1/2 text-pn-muted pointer-events-none"
        aria-hidden="true"
      >
        <circle cx="7" cy="7" r="4.75" />
        <path d="M10.5 10.5 14 14" />
      </svg>
      <input
        ref={fieldRef}
        type="search"
        dir="auto"
        value={query}
        onChange={(e) => changeQuery(e.target.value)}
        onFocus={loadSearch}
        onKeyDown={onFieldKey}
        placeholder={t('common:actions.search')}
        aria-label={t('common:actions.search')}
        role="combobox"
        aria-expanded={searching && !!hits && hits.length > 0}
        aria-controls="settings-search-results"
        aria-activedescendant={searching && hits && hits.length > 0 && search ? search.resultOptionId(activeIndex) : undefined}
        autoComplete="off"
        spellCheck={false}
        enterKeyHint="search"
        className="w-full h-8 rounded-md bg-surface-1 border border-divider ps-8 pe-8 text-sm text-pn placeholder:text-pn-muted focus:outline-none focus:border-accent [&::-webkit-search-cancel-button]:appearance-none"
      />
      {query ? (
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={clearSearch}
          aria-label={t('common:actions.clearSearch')}
          className="absolute end-1 top-1/2 -translate-y-1/2 inline-flex items-center justify-center w-6 h-6 rounded text-pn-muted hover:text-pn transition"
        >
          <X size={13} />
        </button>
      ) : (
        !isMobile && (
          <kbd
            dir="ltr"
            aria-hidden="true"
            className="absolute end-2 top-1/2 -translate-y-1/2 rounded border border-divider px-1 font-sans text-[11px] leading-4 text-pn-muted pointer-events-none"
          >
            ⌘K
          </kbd>
        )
      )}
    </div>
  );

  const results =
    searching && search && hits ? (
      <search.SettingsSearchResults
        query={query}
        hits={hits}
        activeIndex={activeIndex}
        onPick={pick}
        onHover={setActiveIndex}
        onClear={() => {
          clearSearch();
          fieldRef.current?.focus();
        }}
        sectionLabel={sectionLabel}
        sectionIcon={sectionIcon}
      />
    ) : null;

  const paneBody = (
    <div key={paneKey} ref={paneRef} className="flex-1 flex flex-col min-h-0 min-w-0">
      {active?.render?.({ navigate: openCategory, ...(landing?.tab ? { initialTab: landing.tab } : {}) })}
    </div>
  );

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
              onClick={() => {
                // Back from a result returns to the results.
                setLanding(null);
                setActiveId(null);
              }}
              aria-label={t('common:actions.back')}
              className="text-pn-muted hover:text-pn transition p-1 -m-1"
            >
              <ArrowLeft size={20} />
            </button>
            <h2 className="min-w-0 text-base font-semibold leading-tight">{active.label}</h2>
          </div>
          {paneBody}
        </div>,
      );
    }
    return backdrop(
      <div className="bg-surface-2 border border-divider rounded-lg w-full max-w-md max-h-[85vh] flex flex-col text-pn">
        <div className="flex items-center justify-between px-4 py-3 border-b border-divider">
          <h2 className="text-lg font-semibold">{t('shell.title')}</h2>
          {closeButton}
        </div>
        <div className="px-4 pt-3 pb-1 flex">{field}</div>
        {searching ? (
          <div className="flex-1 min-h-0 flex flex-col">{results}</div>
        ) : (
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
                    onClick={() => openCategory(c.id)}
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
        )}
        {footer && !searching && (
          <div className="border-t border-divider p-3">{footer}</div>
        )}
      </div>,
    );
  }

  // ---- Desktop: two-pane -------------------------------------------------
  // h-656: the category rail holds 12 rows + 3 group headers, which need
  // 522px of rail; 640 left 514 once Images landed and hid the Help row
  // behind an 8px scroll. 656 clears it with 8px of slack and still sits
  // under the 85vh cap on a 13" laptop. Adding a 13th category means
  // re-measuring (rail scrollHeight against clientHeight). The search field
  // lives in the header for the same reason: the rail has no row to spare.
  return backdrop(
    <div className="bg-surface-2 border border-divider rounded-lg w-full max-w-4xl h-[656px] max-h-[85vh] flex flex-col text-pn">
      <div className="flex items-center gap-4 px-5 py-3 border-b border-divider">
        <h2 className="text-lg font-semibold whitespace-nowrap">{t('shell.title')}</h2>
        <div className="flex flex-1 max-w-xs">{field}</div>
        <div className="ms-auto flex">{closeButton}</div>
      </div>
      <div className="flex flex-1 min-h-0">
        <nav className="w-56 shrink-0 border-e border-divider flex flex-col p-2">
          <div className="flex-1 min-h-0 overflow-y-auto">
            {categories.map((c, i) => {
              const on = !searching && c.id === activeId;
              const count = counts.get(c.id) ?? 0;
              // A rail is not a result set: a section with no hit dims and
              // stays. Spec: ops/docs/ui-patterns.md section 52
              const dim = searching && hits !== null && count === 0;
              const showHeader = c.group && c.group !== categories[i - 1]?.group;
              const badge = searching && count > 0 && (
                <span className="shrink-0 rounded-full bg-accent/10 px-1.5 text-[11px] leading-4 text-accent">{count}</span>
              );
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
                      className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm text-start transition text-pn-soft hover:bg-surface-1 ${dim ? 'opacity-45' : ''}`}
                    >
                      <span className="shrink-0 text-accent">{c.icon}</span>
                      <span className="flex-1 inline-flex items-center gap-1.5">
                        {c.label}
                        <ArrowSquareOut size={12} className="text-accent shrink-0" />
                      </span>
                      {badge}
                    </a>
                  ) : (
                    <button
                      type="button"
                      onClick={() => openCategory(c.id)}
                      aria-current={on}
                      className={`w-full flex items-center gap-2.5 px-3 py-2 rounded-md text-sm text-start transition ${
                        on
                          ? 'bg-accent/10 text-accent font-medium'
                          : 'text-pn-soft hover:bg-surface-1'
                      } ${dim ? 'opacity-45' : ''}`}
                    >
                      {/* Category icons are always accent, active or not, so the
                          rail reads as one family and matches the sidebar.
                          Spec: ops/docs/ui-patterns.md section 36 */}
                      <span className="shrink-0 text-accent">{c.icon}</span>
                      <span className="flex-1">{c.label}</span>
                      {badge}
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
          {searching ? (
            results
          ) : (
            <>
              {active && (
                <div className="px-6 pt-4 pb-1 shrink-0">
                  {landing && query && (
                    <button
                      type="button"
                      onClick={() => setLanding(null)}
                      className="mb-2 inline-flex items-center gap-1 rounded-full border border-divider px-2.5 py-0.5 text-xs text-pn-soft hover:text-pn hover:bg-surface-1 transition"
                    >
                      <ArrowLeft size={12} aria-hidden="true" />
                      {t('settingsSearch:backToResults')}
                    </button>
                  )}
                  <div className="flex items-center gap-2.5">
                    <AccentBar />
                    <h3 className="text-base font-semibold">{active.label}</h3>
                    <HeadlineRule />
                  </div>
                </div>
              )}
              {paneBody}
            </>
          )}
        </section>
      </div>
    </div>,
  );
}
