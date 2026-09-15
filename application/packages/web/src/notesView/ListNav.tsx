import { useState, useRef } from 'react';
import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { ViewMenu } from '../ViewMenu';
import { switcherViewRows } from '../viewRows';
import { List, CaretDown } from '../icons';

import { isViewShown, type View } from '../views';

/**
 * The left-hand cluster of a list pane's h-14 title row: drawer button, view
 * icon, view title, and a pillar switcher hanging off the title.
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
 * The switcher is live at every width. Below lg it is the only pillar control,
 * because the rail sits behind the drawer. At lg and above it stands beside the
 * rail rather than replacing it: the same gesture works whatever the window
 * size, and the rail's Content section can be collapsed so tags and folders own
 * that space. GitHub #325.
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
  /** Views switched off in the sidebar options menu. This dropdown honours the
   *  same setting the rail does, so one hidden view is hidden in both.
   *  Spec: ops/docs/plans/sidebar-views.md */
  hiddenViews?: View[] | undefined;
  onOpenDrawer: () => void;
  /** The list's own view icon - each pillar keeps the glyph it already used. */
  icon: ReactNode;
  title: string;
}) {
  const { t } = useTranslation('shell');
  const [open, setOpen] = useState(false);
  const buttonRef = useRef<HTMLButtonElement>(null);

  return (
    <div className="flex items-center gap-2 min-w-0 text-neutral-900 dark:text-white">
      <button
        onClick={onOpenDrawer}
        aria-label={t('mobileHeader.openMenu')}
        className="lg:hidden rounded p-1.5 -ms-1 text-neutral-600 hover:bg-neutral-200 dark:text-neutral-400 dark:hover:bg-neutral-900 transition shrink-0"
      >
        <List size={20} />
      </button>
      {/* One element for both breakpoints, with no second copy of the icon +
          heading markup. Two copies drift. The negative margin keeps the icon
          on the same x as the pane below it, which the hover padding would
          otherwise shift, and the hover tint is gated on a real pointer so a
          tap does not leave it stuck on a phone. */}
      <button
        ref={buttonRef}
        type="button"
        onClick={() => setOpen(o => !o)}
        aria-haspopup="menu"
        aria-expanded={open}
        className="flex items-center gap-2 min-w-0 cursor-pointer rounded-lg px-1.5 py-1 -mx-1.5 transition-colors [@media(hover:hover)]:hover:bg-neutral-200/70 [@media(hover:hover)]:dark:hover:bg-neutral-800/70"
      >
        {icon}
        <h2 className="text-lg font-semibold tracking-tight truncate">{title}</h2>
        <CaretDown className={`shrink-0 text-neutral-500 dark:text-neutral-400 transition-transform duration-150 ${open ? 'rotate-180' : ''}`} />
      </button>
      {open && (
        <ViewMenu
          rows={switcherViewRows(t).filter((r) => isViewShown(r.key, hiddenViews, view))}
          current={view}
          onPick={onSelectView}
          anchorRef={buttonRef}
          onClose={() => setOpen(false)}
        />
      )}
    </div>
  );
}
