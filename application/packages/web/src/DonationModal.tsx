import { Trans, useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { X } from './icons';
import { Brand } from './Brand';

type Props = {
  reason: string;
  onClose: () => void;
};

export function DonationModal({ reason, onClose }: Props) {
  const { t } = useTranslation('billing');
  useEscapeToClose(onClose);
  return (
    <div
      className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6 z-50"
      onClick={onClose}
    >
      <div
        className="bg-surface-2 border border-divider text-pn rounded-lg max-w-md w-full p-6 space-y-4"
        onClick={(e) => e.stopPropagation()}
      >
        <div className="flex items-start justify-between">
          <div>
            <div className="text-xs text-pn-muted uppercase tracking-wide">
              {t('donation.eyebrow')}
            </div>
            <h2 className="text-lg font-semibold mt-1">{reason}</h2>
          </div>
          <button
            onClick={onClose}
            className="text-pn-muted hover:text-pn-soft transition p-1 -m-1"
            aria-label={t('common:actions.close')}
          >
            <X size={18} />
          </button>
        </div>

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
      </div>
    </div>
  );
}
