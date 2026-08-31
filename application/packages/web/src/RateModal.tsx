import { useTranslation } from 'react-i18next';
import { LinksModal } from './LinksModal';
import { useRateLinks, RateOutro } from './rateLinks';
import { Star } from './icons';

type Props = {
  onClose: () => void;
  /** Fired when the user opens one of the platforms. The milestone-driven
   *  ask uses it to stop asking: they did the thing we asked for. */
  onRated?: () => void;
};

// The review platforms where a public rating helps discovery. Opened from the
// sidebar footer; the About modal's Rating tab renders the same three strings
// and the same list, both from `rateLinks.tsx`.
export function RateModal({ onClose, onRated }: Props) {
  const { t } = useTranslation('landing');
  const links = useRateLinks();

  return (
    <LinksModal
      title={t('rate.title')}
      titleIcon={<Star size={17} weight="fill" className="shrink-0 text-amber-400" aria-hidden="true" />}
      intro={t('rate.intro')}
      links={links}
      outro={<RateOutro />}
      onLinkClick={onRated}
      onClose={onClose}
    />
  );
}
