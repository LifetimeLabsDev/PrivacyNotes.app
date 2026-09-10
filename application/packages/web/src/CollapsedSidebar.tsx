import { useLayoutEffect, useRef, type RefObject } from 'react';
import { useTranslation } from 'react-i18next';
import { LogoIcon } from './LogoIcon';
import { HoverLabel } from './HoverLabel';
import { IconUpgrade } from './UpgradeModal';
import { Plus, SquaresFour, List, Sparkle, PushPin, File, CheckSquare, Shield, Folder, Book, Hash, Trash, Question, CaretRight, Devices, FileMd, BookmarkSimple, NotePencil, CheckFat, Notebook, Bookmarks, Key } from './icons';
import { isViewShown, type View } from './views';
import { viewRows } from './viewRows';
import { exemptOpts } from './i18nExempt';
import { SIDEBAR_ACTIVE } from './sidebarUI';
import { useUpdateAvailable } from './updateAvailable';
import { UpdateDot } from './UpdateDot';
import { marketingHomeHref, siteHref } from './siteLinks';
import { helpPath } from './localeRoutes';
import { activeLocale } from './languages';

interface CollapsedSidebarProps {
  view: View;
  selectedTag: string | null;
  selectedFolder: string | null;
  handleSelectView: (next: View) => void;
  handleSelectTag: (tag: string | null) => void;
  onNew: () => void;
  onExpand: () => void;
  onExpandToTags: () => void;
  /** Expand the sidebar in Folders mode - or open the upsell when free. */
  onExpandToFolders: () => void;
  /** Drives the rocket overlay on the folders button (shown while not Pro). */
  isPro: boolean;
  viewMode: 'auto' | 'list' | 'grid';
  onToggleViewMode: () => void;
  /** Item count per pillar row, for the hover labels. An absent entry draws
   *  no count, which is not a zero: the Markdown pillar scans nothing until a
   *  folder is chosen.
   *  Spec: ops/docs/plans/start-view.md (one counts object) */
  viewCounts: Partial<Record<View, number>>;
  trashedCount: number;
  /** Views switched off in the sidebar options menu; the wide rail hides the
   *  same rows. Spec: ops/docs/plans/sidebar-views.md */
  hiddenViews: View[];
}

// Spec: ops/docs/design-decisions.md (sidebar collapsed icon rail)

/**
 * Fit tiers, cheapest first. Each one buys height back: `shed` drops the
 * `.pn-rail-optional` items, `compact` shrinks the buttons and the gaps, and
 * `scroll` is the floor - a scrolling rail cannot paint over the footer below
 * it, whatever it holds. `index.css` carries what each tier does.
 * Spec: ops/docs/ui-patterns.md section 40 (rail fit tiers)
 */
const RAIL_FIT_TIERS = ['full', 'shed', 'compact', 'scroll'] as const;

/**
 * Escalate the rail through the fit tiers until its content stops overflowing.
 *
 * The rail's height is whatever the shell leaves it (the footer, the demo
 * banner and the footer's own density all subtract), and its CONTENT height is
 * just as variable: a switched-off pillar, an unavailable Markdown pillar and a
 * pinned row that hides at zero move it by a row each. Nothing can compare
 * those two numbers up front, so this measures them.
 *
 * Each tier is applied and then measured. `scrollHeight` is read straight
 * after the write, which flushes it, so the loop reads the layout the tier
 * actually produced rather than the previous one.
 */
function useRailFit(ref: RefObject<HTMLDivElement | null>) {
  useLayoutEffect(() => {
    const rail = ref.current;
    if (!rail) return;
    const fit = () => {
      for (const tier of RAIL_FIT_TIERS) {
        rail.dataset.fit = tier;
        // 1px of slack: both numbers are integers rounded off a fractional
        // rail height, so an exact fit can still read as one pixel over.
        if (tier === 'scroll' || rail.scrollHeight - rail.clientHeight <= 1) return;
      }
    };
    fit();
    // Height changes (window resize, a banner appearing) and row changes (a
    // count crossing zero, a pillar switched off) are the two things that can
    // break the fit, and the second one is watched as a DOM mutation rather
    // than as a dependency list so a row added later is covered for free.
    const ro = new ResizeObserver(fit);
    ro.observe(rail);
    const mo = new MutationObserver(fit);
    mo.observe(rail, { childList: true });
    return () => { ro.disconnect(); mo.disconnect(); };
  }, [ref]);
}

const iconBtn = (active: boolean) =>
  `w-9 h-9 flex items-center justify-center rounded-lg transition shrink-0 ${
    active
      ? SIDEBAR_ACTIVE
      : 'text-neutral-500 hover:bg-neutral-200/60 hover:text-accent dark:text-neutral-500 dark:hover:bg-neutral-900/60 dark:hover:text-accent'
  }`;

const dimIconBtn = (active: boolean) =>
  `w-9 h-9 flex items-center justify-center rounded-lg transition shrink-0 ${
    active
      ? SIDEBAR_ACTIVE
      : 'text-neutral-400 hover:bg-neutral-200/60 hover:text-neutral-600 dark:text-neutral-600 dark:hover:bg-neutral-900/60 dark:hover:text-neutral-400'
  }`;


export function CollapsedSidebar({
  view,
  selectedTag,
  selectedFolder,
  handleSelectView,
  handleSelectTag,
  onNew,
  onExpand,
  onExpandToTags,
  onExpandToFolders,
  isPro,
  viewMode,
  onToggleViewMode,
  viewCounts,
  trashedCount,
  hiddenViews,
}: CollapsedSidebarProps) {
  const { t } = useTranslation('shell');
  // Same store the expanded rail reads; null wherever no updater runs.
  const updateVersion = useUpdateAvailable();
  /** A switched-off row still draws while it IS the open view. */
  const showRow = (v: View) => isViewShown(v, hiddenViews, view);
  const updateTipLabel = `${t('tagsRail.downloads', exemptOpts('shell:tagsRail.downloads'))} - ${t('updateToast.available', { ns: 'common' })}`;
  const railRef = useRef<HTMLDivElement>(null);
  useRailFit(railRef);
  return (
    <div ref={railRef} className="pn-rail h-full flex flex-col items-center gap-1 w-[52px]">
      {/* Logo - h-14 + border-b matches expanded sidebar brand row */}
      <div className="shrink-0 h-14 w-full flex items-center justify-center border-b border-divider">
        <HoverLabel label="PrivacyNotes">
          <button
            type="button"
            onClick={() => handleSelectView('home')}
            aria-label={t('tagsRail.showAllItems')}
            className="hover:opacity-80 transition focus:outline-none focus-visible:ring-2 focus-visible:ring-accent/40 rounded"
          >
            <LogoIcon size={24} className="text-accent" />
          </button>
        </HoverLabel>
      </div>

      {/* New note */}
      <HoverLabel label={t('collapsedSidebar.newNote')}>
        <button
          type="button"
          onClick={onNew}
          aria-label={t('collapsedSidebar.newNote')}
          className="w-9 h-9 flex items-center justify-center rounded-lg text-pn hover:bg-neutral-200/60 hover:text-accent dark:hover:bg-neutral-900/60 dark:hover:text-accent transition"
        >
          <Plus size={18} />
        </button>
      </HoverLabel>

      {/* View mode - cycles auto -> list -> grid; icon shows the current mode.
          pn-rail-optional: shed on short rails (the sort/view popover keeps
          this reachable) so core pillars never overlap the footer below.
          Spec: ops/docs/ui-patterns.md section 40 (rail fit tiers) */}
      <HoverLabel label={t('collapsedSidebar.cycleView')} className="pn-rail-optional">
        <button
          type="button"
          onClick={onToggleViewMode}
          aria-label={t('collapsedSidebar.cycleView')}
          className="w-9 h-9 flex items-center justify-center rounded-lg text-neutral-500 hover:bg-neutral-200/60 hover:text-accent dark:text-neutral-500 dark:hover:bg-neutral-900/60 dark:hover:text-accent transition"
        >
          {viewMode === 'auto' ? <Sparkle size={18} /> : viewMode === 'list' ? <List size={18} /> : <SquaresFour size={18} />}
        </button>
      </HoverLabel>

      <div className="w-7 border-t border-divider my-1" />

      {/* Views, from the same shared list the wide rail draws. Collapsing the
          sidebar must not change which rows exist or what they are called, so
          neither surface keeps a list of its own.
          Spec: ops/docs/plans/start-view.md (one row list, one label namespace) */}
      {viewRows(t).map((r) => {
        // All is never hideable - the logo above goes there too.
        if (r.key !== 'home' && !showRow(r.key)) return null;
        // Hidden at zero, same as the expanded rail. Kept while it is the
        // current view, so unpinning the last note does not move the row you
        // are standing on.
        if (r.key === 'starred' && !(viewCounts.starred ?? 0) && view !== 'starred') return null;
        return (
          <HoverLabel key={r.key} label={r.label} count={viewCounts[r.key]}>
            <button type="button" onClick={() => handleSelectView(r.key)} className={iconBtn(view === r.key)} aria-label={r.label}>
              <r.icon size={18} />
            </button>
          </HoverLabel>
        );
      })}

      <div className="w-7 border-t border-divider my-1" />

      {/* Tags - click expands sidebar scrolled to tags */}
      <HoverLabel label={t('tagsRail.tags')}>
        <button type="button" onClick={onExpandToTags} className={iconBtn(selectedTag !== null && selectedTag !== '__untagged__')} aria-label={t('tagsRail.tags')}>
          <Hash size={18} />
        </button>
      </HoverLabel>

      {/* Folders (Pro) - the 36px rail can't render a tree, so this
          expands the sidebar in Folders mode (or opens the upsell). */}
      <HoverLabel label={t('browseToggle.folders')}>
        <button
          type="button"
          onClick={onExpandToFolders}
          className={`relative ${iconBtn(selectedFolder !== null)}`}
          aria-label={t('browseToggle.folders')}
        >
          <Folder size={18} />
          {!isPro && (
            <span className="absolute -top-0.5 -end-0.5" aria-hidden="true">
              <IconUpgrade size={11} />
            </span>
          )}
        </button>
      </HoverLabel>

      <div className="w-7 border-t border-divider my-1" />

      {/* Trash */}
      <HoverLabel label={t('pillars.trash')} count={trashedCount}>
        <button type="button" onClick={() => handleSelectView('trash')} className={dimIconBtn(view === 'trash')} aria-label={t('pillars.trash')}>
          <Trash size={18} />
        </button>
      </HoverLabel>

      {/* Spacer to push bottom items down */}
      <div className="flex-1" />

      {/* Help - straight to the /help hub, not a modal. pn-rail-optional:
          shed on short rails (feedback and the other footer actions stay
          reachable from the expanded sidebar's icon row).

          While an update is outstanding this slot becomes Downloads instead,
          carrying the same dot the expanded rail shows (ui-patterns.md section
          46). A swap rather than a sixth button: the rail is height-budgeted
          and already sheds pn-rail-optional items on short windows, so adding
          one would push something else out anyway. Help stays one click away
          in the expanded sidebar, and the state is temporary by definition -
          it ends when the user updates. */}
      {updateVersion ? (
        <HoverLabel label={updateTipLabel} className="pn-rail-optional">
          <a
            href={`${marketingHomeHref()}#downloads`}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={`${updateTipLabel} (v${updateVersion})`}
            className="relative w-9 h-9 flex items-center justify-center rounded-lg text-neutral-500 hover:bg-neutral-200/60 hover:text-accent dark:text-neutral-400 dark:hover:bg-neutral-900/60 dark:hover:text-accent transition"
          >
            <Devices size={16} />
            {/* surface-0, not surface-1: this rail sits on the darker column. */}
            <UpdateDot ring="ring-surface-0" />
          </a>
        </HoverLabel>
      ) : (
        <HoverLabel label={t('tagsRail.help')} className="pn-rail-optional">
          <a
            href={siteHref(helpPath(activeLocale()))}
            target="_blank"
            rel="noopener noreferrer"
            aria-label={t('tagsRail.help')}
            className="w-9 h-9 flex items-center justify-center rounded-lg text-neutral-500 hover:bg-neutral-200/60 hover:text-accent dark:text-neutral-400 dark:hover:bg-neutral-900/60 dark:hover:text-accent transition"
          >
            <Question size={16} />
          </a>
        </HoverLabel>
      )}

      {/* Expand toggle - pn-rail-optional: shed on short rails (the edge
          handle beside the rail is the permanent expand affordance). */}
      <HoverLabel label={t('collapsedSidebar.expandSidebar')} className="pn-rail-optional">
        <button
          type="button"
          onClick={onExpand}
          aria-label={t('collapsedSidebar.expandSidebar')}
          className="w-9 h-9 flex items-center justify-center rounded-lg text-neutral-400 hover:bg-neutral-200/60 hover:text-accent dark:text-neutral-600 dark:hover:bg-neutral-900/60 dark:hover:text-accent transition"
        >
          <CaretRight size={16} />
        </button>
      </HoverLabel>
    </div>
  );
}
