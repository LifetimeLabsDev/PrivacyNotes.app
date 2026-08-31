import { useTranslation } from 'react-i18next';
import type { ModalLink } from './LinksList';
import { ArrowsLeftRight, GithubLogo, Heart, ShieldCheck, SquaresFour, Star } from './icons';

/**
 * The review platforms where a public rating helps discovery.
 *
 * Two surfaces render this list: the Rate modal off the sidebar footer, and
 * the About modal's Rating tab. It lives here so adding a platform is one
 * edit rather than two that drift.
 */
export function useRateLinks(): ModalLink[] {
  const { t } = useTranslation('landing');

  return [
    {
      // Sits above the review platforms: a star costs one click and needs no account setup
      // or review text, so it is the cheapest ask on the list.
      href: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app',
      label: 'GitHub.com',
      desc: t('rate.descGithub'),
      rel: 'noopener noreferrer',
      icon: <GithubLogo size={16} weight="fill" className="shrink-0" />,
    },
    {
      href: 'https://alternativeto.net/software/privacynotes/about/',
      label: 'AlternativeTo.net',
      desc: t('rate.descAlternativeTo'),
      rel: 'noopener noreferrer',
      icon: <ArrowsLeftRight size={16} weight="fill" className="shrink-0" />,
    },
    {
      href: 'https://www.capterra.com/p/10050664/PrivacyNotes/',
      label: 'Capterra.com',
      desc: t('rate.descCapterra'),
      rel: 'noopener noreferrer',
      icon: <Star size={16} weight="fill" className="shrink-0" />,
    },
    {
      href: 'https://www.saashub.com/privacynotes-alternatives',
      label: 'SaaSHub.com',
      desc: t('rate.descSaasHub'),
      rel: 'noopener noreferrer',
      icon: <SquaresFour size={16} weight="fill" className="shrink-0" />,
    },
    {
      href: 'https://privacytools.io/app/privacynotes',
      label: 'PrivacyTools.io',
      desc: t('rate.descPrivacyTools'),
      rel: 'noopener noreferrer',
      icon: <ShieldCheck size={16} weight="fill" className="shrink-0" />,
    },
  ];
}

/**
 * The closing line under the platform list. The heart is a filled Phosphor
 * mark rather than an emoji, so it matches the star in the title and renders
 * the same on every platform. The project ships no emojis; the heart is a
 * deliberate exception for this one line, and it ships as a mark rather than
 * a character.
 * It follows the last word inline, so it never orphans onto its own line.
 */
export function RateOutro() {
  const { t } = useTranslation('landing');
  return (
    <>
      {t('rate.outro')}
      <Heart
        size={13}
        weight="fill"
        className="ms-1.5 inline-block align-[-0.1em] text-red-500"
        aria-hidden="true"
      />
    </>
  );
}
