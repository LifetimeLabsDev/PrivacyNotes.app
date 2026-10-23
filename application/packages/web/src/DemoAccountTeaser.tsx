import { SignIn, Vault, ShieldCheck, UserPlus } from './icons';
import { useTranslation } from 'react-i18next';
import { DEMO_APP_URL } from './demo';
import { withSource } from './campaignSource';
import { ProviderLabel, type ConnectedAccountProvider } from './ConnectedAccounts';
import { BetaReportLink } from './BetaReportLink';
import { SectionEyebrow, SETTINGS_BTN_PRIMARY, SETTINGS_HELP, SettingsCallout } from './settingsUI';

const PROVIDERS: ConnectedAccountProvider[] = ['google', 'apple', 'github'];

/** What the account security pages hold, shown in the demo. Every one of
 * them needs a server account, so the demo describes the page and links to
 * sign-up instead of offering a control that cannot work. */
export function DemoAccountTeaser({ kind }: { kind: 'accounts' | 'keyCustody' | 'twoFactor' }) {
  const { t } = useTranslation('security');
  return <div className="space-y-3">
    <SectionEyebrow icon={kind === 'accounts' ? SignIn : kind === 'keyCustody' ? Vault : ShieldCheck}>{t(kind === 'accounts' ? 'connectedAccounts.title' : kind === 'keyCustody' ? 'accountTabs.keyCustody' : 'twoFactor.title')}</SectionEyebrow>
    {kind === 'accounts' && <>
      <p className={SETTINGS_HELP}>{t('connectedAccounts.description')}</p>
      <div className="divide-y divide-divider rounded-md border border-divider">
        {PROVIDERS.map((provider) => <div key={provider} className="p-3"><ProviderLabel provider={provider} /></div>)}
      </div>
    </>}
    {kind === 'twoFactor' && <p className={`${SETTINGS_HELP} leading-relaxed`}>{t('twoFactor.description')}</p>}
    <SettingsCallout>{t(`demoTeaser.${kind}`)}</SettingsCallout>
    <a href={withSource(DEMO_APP_URL)} className={SETTINGS_BTN_PRIMARY}>
      <UserPlus size={15} aria-hidden="true" className="shrink-0" />
      {t('demoTeaser.createAccount')}
    </a>
    {kind === 'accounts' && <BetaReportLink />}
  </div>;
}
