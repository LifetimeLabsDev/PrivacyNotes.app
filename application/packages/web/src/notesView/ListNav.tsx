import { useState, useRef, useEffect } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { usePopoverPosition } from '../usePopoverPosition';
import { useEscapeToClose } from '../useEscapeToClose';
import { PILLAR_GLYPHS, List, CaretDown } from '../icons';

import { isViewShown, type View } from '../views';

// 'markdown' is deliberately absent: this switcher is the below-lg (phone and
// small tablet) pillar picker, and the Markdown pillar needs a filesystem API
// no mobile platform has. Offering it here would advertise a view whose only
// possible content is an explanation of why it cannot work.
const PILL_VIEWS: { key: View; labelKey: string; icon: React.JSX.Element }[] = [
  { key: 'home', labelKey: 'pillars.allItems', icon: <PILLAR_GLYPHS.all size={16} /> },
  { key: 'all', labelKey: 'pillars.notes', icon: <PILLAR_GLYPHS.notes size={16} /> },
  { key: 'tasks', labelKey: 'pillars.tasks', icon: <PILLAR_GLYPHS.tasks size={16} /> },
  { key: 'vault', labelKey: 'pillars.vault', icon: <PILLAR_GLYPHS.vault size={16} /> },
  { key: 'files', labelKey: 'pillars.files', icon: <PILLAR_GLYPHS.files size={16} /> },
  { key: 'journal', labelKey: 'pillars.journals', icon: <PILLAR_GLYPHS.journals size={16} /> },
  { key: 'bookmarks', labelKey: 'pillars.bookmarks', icon: <PILLAR_GLYPHS.bookmarks size={16} /> },
];

/**
 * The left-hand cluster of a list pane's h-14 title row: drawer button, view
 * icon, view title, and (below lg) a pillar switcher hanging off the title.
 *
 * This replaces the separate mobile wordmark bar that used to sit above the
 * title row. Two rows both said "Notes" - one as a pillar pill, one as the
 * list title - and cost 56px of a phone screen for the duplication. Folding
 * the drawer button and the pillar switcher into the title the list already
 * renders buys that row back with nothing lost: the wordmark is the one thing
 * dropped, and you do not need telling which app you are inside. GitHub #186
 * follow-up.
 *
 * IMPORTANT - the safe-area inset. The retired bar owned
 * `pt-[max(0.5rem,env(safe-area-inset-top))]`; the app root carries it now
 * (NotesView), because the topmost element on a phone is no longer a single
 * fixed bar - it is whichever of the banners, the list pane, or the editor
 * happens to render first. Keep it on the root, not here.
 * Spec: ops/docs/ui-patterns.md section 51.
 *
 * At lg+ the title renders exactly as it always did: icon, heading, no caret,
 * not clickable (the sidebar owns pillar switching there).
 */
export function ListNav({
  view,
  onSelectView,
  hiddenViews,
  onOpenDrawer,
  icon,
  title,
}: {
  view: View;
  onSelectView: (next: View) => void;
  /** Views switched off in the sidebar options menu. The phone has no rail,
   *  so this dropdown is where that setting shows up here.
   *  Spec: ops/docs/plans/sidebar-views.md */
  hiddenViews?: View[] | undefined;
  onOpenDrawer: () => void;
  /** The list's own view icon - each pillar keeps the glyph it already used. */
  icon: ReactNode;
  title: string;
}) {
  const { t } = useTranslation('shell');
  const [open, setOpen] = useState(false);
  const dropdownRef = useRef<HTMLDivElement>(null);
  const buttonRef = useRef<HTMLButtonElement>(null);
  const dropdownPos = usePopoverPosition(open, buttonRef, dropdownRef, { align: 'start', gap: 6 });

  // Escape / Android back dismiss the dropdown via the shared overlay
  // stack (ui-patterns.md rule 4).
  useEscapeToClose(() => setOpen(false), open);

  useEffect(() => {
    if (!open) return;
    function handleClick(e: PointerEvent) {
      if (
        dropdownRef.current && !dropdownRef.current.contains(e.target as Node) &&
        buttonRef.current && !buttonRef.current.contains(e.target as Node)
      ) {
        setOpen(false);
      }
    }
    document.addEventListener('pointerdown', handleClick);
    return () => document.removeEventListener('pointerdown', handleClick);
  }, [open]);

  return (
    <div className="flex items-center gap-2 min-w-0 text-neutral-900 dark:text-white">
      <button
        onClick={onOpenDrawer}
        aria-label={t('mobileHeader.openMenu')}
        className="lg:hidden rounded p-1.5 -ms-1 text-neutral-600 hover:bg-neutral-200 dark:text-neutral-400 dark:hover:bg-neutral-900 transition shrink-0"
      >
        <List size={20} />
      </button>
      {/* One element for both breakpoints: `lg:pointer-events-none` retires
          the switcher at lg (where the sidebar owns it) without duplicating
          the icon + heading markup for a second, non-interactive copy. */}
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen(o => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex items-center gap-2 min-w-0 lg:pointer-events-none"
      >
        {icon}
        <h2 className="text-lg font-semibold tracking-tight truncate">{title}</h2>
        <CaretDown className={`lg:hidden shrink-0 text-neutral-500 dark:text-neutral-400 transition-transform duration-150 ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <div
          ref={dropdownRef}
          className="fixed bg-surface-2 border border-divider rounded-xl shadow-lg py-1 min-w-[140px] z-[9999]"
          style={{
            top: dropdownPos?.top ?? 0,
            left: dropdownPos?.left ?? 0,
            visibility: dropdownPos ? 'visible' : 'hidden',
          }}
        >
          {PILL_VIEWS.filter((p) => isViewShown(p.key, hiddenViews, view)).map(({ key, labelKey, icon: pillIcon }) => (
            <button
              key={key}
              onClick={() => { onSelectView(key); setOpen(false); }}
              className={`flex items-center gap-2 w-full px-3 py-2 text-sm transition-colors ${
                view === key
                  ? 'text-accent bg-accent/10'
                  : 'text-neutral-600 dark:text-neutral-400 hover:bg-neutral-100 dark:hover:bg-neutral-800'
              }`}
            >
              <span className="shrink-0">{pillIcon}</span>
              {t(labelKey)}
            </button>
          ))}
        </div>
      )}
    </div>
  );
}
