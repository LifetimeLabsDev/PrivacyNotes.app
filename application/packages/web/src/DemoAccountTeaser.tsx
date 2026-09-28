import { useTranslation } from 'react-i18next';
import { DEMO_APP_URL } from './demo';
import { withSource } from './campaignSource';
import { ProviderLabel, type ConnectedAccountProvider } from './ConnectedAccounts';
import { BetaReportLink } from './BetaReportLink';
import { SETTINGS_HELP, SectionEyebrow, SettingsCallout } from './settingsUI';

const PROVIDERS: ConnectedAccountProvider[] = ['google', 'apple', 'github'];

/** What the account security pages hold, shown in the demo. Every one of
 * them needs a server account, so the demo describes the page and links to
 * sign-up instead of offering a control that cannot work. */
export function DemoAccountTeaser({ kind }: { kind: 'accounts' | 'keyCustody' | 'twoFactor' }) {
  const { t } = useTranslation('security');
  return <div className="space-y-3">
    <SectionEyebrow>{t(kind === 'accounts' ? 'connectedAccounts.title' : kind === 'keyCustody' ? 'accountTabs.keyCustody' : 'twoFactor.title')}</SectionEyebrow>
    {kind === 'accounts' && <>
      <p className={SETTINGS_HELP}>{t('connectedAccounts.description')}</p>
      <div className="divide-y divide-divider rounded-md border border-divider">
        {PROVIDERS.map((provider) => <div key={provider} className="p-3"><ProviderLabel provider={provider} /></div>)}
      </div>
    </>}
    {kind === 'twoFactor' && <p className={`${SETTINGS_HELP} leading-relaxed`}>{t('twoFactor.description')}</p>}
    <SettingsCallout>{t(`demoTeaser.${kind}`)}</SettingsCallout>
    <a href={withSource(DEMO_APP_URL)} className="inline-block rounded-md bg-accent px-3 py-2 text-sm text-white hover:bg-accent-hover">
      {t('demoTeaser.createAccount')}
    </a>
    {kind === 'accounts' && <BetaReportLink />}
  </div>;
}
