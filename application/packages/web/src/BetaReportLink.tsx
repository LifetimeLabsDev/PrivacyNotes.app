import { useTranslation } from 'react-i18next';
import { ArrowSquareOut, Flask } from './icons';
import { bugReportUrl } from './bugReportUrl';

/** The flask mark of a feature in beta, in the same green chip on the tab and beside the report line. */
export function BetaFlask() {
  return <span className="inline-flex h-5 w-5 shrink-0 items-center justify-center rounded-md bg-emerald-500/15 text-emerald-600 dark:text-emerald-400">
    <Flask size={14} aria-hidden="true" />
  </span>;
}

/** Says a feature is in beta and links to the GitHub bug form, with version and platform prefilled. */
export function BetaReportLink() {
  const { t } = useTranslation('security');
  return <p className="flex flex-wrap items-center gap-x-2 gap-y-1 text-[13px] text-pn-soft">
    <BetaFlask />
    <span>{t('beta.notice')}</span>
    <a href={bugReportUrl()} target="_blank" rel="noopener noreferrer" className="inline-flex items-center gap-1 text-accent hover:underline">
      {t('beta.reportBug')}
      <ArrowSquareOut size={12} className="shrink-0" aria-hidden="true" />
    </a>
  </p>;
}
