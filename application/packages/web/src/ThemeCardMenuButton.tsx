import type { MouseEvent } from 'react';
import { useTranslation } from 'react-i18next';
import { DotsThree } from './icons';
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
      className="absolute top-1 end-1 rounded bg-surface-2/90 p-0.5 text-pn-soft hover:text-pn transition"
    >
      <DotsThree size={14} weight="bold" aria-hidden="true" />
    </button>
  );
}

/**
 * The Pro mark of a locked theme card, in the top start corner of its swatch
 * on a chip of the card's own surface, where the mark's contrast is measured.
 * The name row below stays free for the name, so no name truncates in the
 * four-in-a-row popover; the menu button owns the end corner.
 */
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
