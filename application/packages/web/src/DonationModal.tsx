import { Trans, useTranslation } from 'react-i18next';
import { Brand } from './Brand';
import { Modal } from './ui';

type Props = {
  reason: string;
  onClose: () => void;
};

export function DonationModal({ reason, onClose }: Props) {
  const { t } = useTranslation('billing');
  return (
    <Modal onClose={onClose} title={reason} subtitle={t('donation.eyebrow')} className="max-w-md p-6 space-y-4">

        <p className="text-sm text-pn-muted leading-relaxed">
          <Trans
            i18nKey="billing:donation.intro"
            components={{ brand: <Brand /> }}
          />
        </p>

        <p className="text-sm text-pn-muted leading-relaxed">
          {t('donation.proBenefits')}
        </p>

        <div className="flex gap-2 pt-2">
          <button
            onClick={onClose}
            className="flex-1 rounded-md border border-divider hover:bg-pn/5 px-4 py-2 text-sm transition"
          >
            {t('donation.maybeLater')}
          </button>
          <a
            href="https://github.com/LifetimeLabsDev/PrivacyNotes.app"
            target="_blank"
            rel="noreferrer"
            onClick={onClose}
            className="flex-1 rounded-md bg-accent-fill text-white hover:bg-accent-fill-hover px-4 py-2 text-sm font-medium text-center transition"
          >
            {t('donation.support')}
          </a>
        </div>
    </Modal>
  );
}
