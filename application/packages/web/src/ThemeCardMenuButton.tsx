import type { MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { DotsThree, UsersThree, Star } from './icons';
import { IconUpgrade } from './UpgradeModal';

/** The "..." on a theme card: a sibling of the card button inside a
 *  `relative` wrapper, never a button nested in a button. */
export function CardMenuButton({ name, onClick }: { name: string; onClick: (e: MouseEvent<HTMLButtonElement>) => void }) {
  const { t } = useTranslation('settings');
  return (
    <button
      type="button"
      onClick={onClick}
      aria-label={t('appearance.custom.menu', { name })}
      className="absolute top-1 end-1 flex h-6 w-6 items-center justify-center rounded-md bg-surface-2/90 text-pn-soft hover:text-pn transition"
    >
      <DotsThree size={18} weight="bold" aria-hidden="true" />
    </button>
  );
}

/**
 * The Pro mark of a locked theme card, in the top start corner of its swatch
 * on a chip of the card's own surface, where the mark's contrast is measured.
 * The name row below stays free for the name, so no name truncates in the
 * four-in-a-row popover; the menu button owns the end corner.
 */
/**
 * The mark of a community theme, a code that credits its author: the bottom
 * end corner of the swatch, clear of the Pro mark in the top start corner
 * even on the small cards of the Design menu, on the same chip as that mark. The author's
 * name is in the card's hover tip.
 */
/** The mark of a theme shown in the Design quick menu: a star in the bottom
 *  end corner of the swatch, on the same chip as the other marks. */
export function QuickCorner() {
  const { t } = useTranslation('settings');
  return (
    <span
      role="img"
      aria-label={t('appearance.quickMenuMarked')}
      className="absolute bottom-0.5 end-0.5 flex rounded bg-surface-2/90 p-0.5 text-pro"
    >
      <Star size={10} weight="fill" aria-hidden="true" />
    </span>
  );
}

/** The star on a theme card in Settings > Design: a quick way to add the
 *  theme to the Design menu or take it out. It sits in the middle of the
 *  swatch, and it is the one way to star a theme. A starred card always
 *  shows it; an unstarred one shows it while the card is hovered or the star
 *  has focus, and always on a touch screen, which has no hover. While the card
 *  is hovered the star previews the click: "Add" shows the filled star the
 *  card will get, "Remove" shows the outline it will go back to. Starred is
 *  the Pro mark's yellow, the color a star reads as. A sibling of the card
 *  button, never nested in it. */
export function QuickStarButton({ name, marked, onToggle }: { name: string; marked: boolean; onToggle: () => void }) {
  const { t } = useTranslation('settings');
  // The filled star shows at rest when starred and on hover when not; the
  // outline is the other way round. Both stay in the DOM so the swap is CSS.
  const filled = marked ? 'group-hover/card:hidden' : 'hidden group-hover/card:block';
  const outline = marked ? 'hidden group-hover/card:block' : 'group-hover/card:hidden';
  return (
    <button
      type="button"
      onClick={onToggle}
      aria-pressed={marked}
      aria-label={t(marked ? 'appearance.favoriteRemove' : 'appearance.favoriteAdd', { name })}
      className={`absolute start-1/2 top-[26px] -translate-x-1/2 -translate-y-1/2 rtl:translate-x-1/2 flex flex-col items-center gap-px rounded-md bg-surface-2/90 px-1.5 py-1 text-[10px] font-medium leading-none transition focus-visible:opacity-100 ${
        marked ? 'text-pn' : 'text-pn-soft opacity-0 group-hover/card:opacity-100 [@media(hover:none)]:opacity-100'
      }`}
    >
      <Star size={14} weight="fill" className={`text-pro ${filled}`} aria-hidden="true" />
      <Star size={14} weight="bold" className={outline} aria-hidden="true" />
      <span className="hidden group-hover/card:block" aria-hidden="true">{t(marked ? 'appearance.favoriteRemoveShort' : 'appearance.favoriteAddShort')}</span>
    </button>
  );
}

export function CommunityCorner() {
  const { t } = useTranslation('settings');
  return (
    <span
      role="img"
      aria-label={t('appearance.custom.communityTheme')}
      className="absolute bottom-0.5 end-0.5 flex rounded bg-surface-2/90 p-0.5 text-pn-soft"
    >
      <UsersThree size={10} weight="bold" aria-hidden="true" />
    </span>
  );
}

export function ProCorner() {
  const { t } = useTranslation('settings');
  return (
    <span
      role="img"
      aria-label={t('appearance.custom.proTheme')}
      className="absolute top-0.5 start-0.5 flex rounded bg-surface-2/90 p-0.5"
    >
      <IconUpgrade size={10} />
    </span>
  );
}
