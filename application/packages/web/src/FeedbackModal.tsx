import { useTranslation } from 'react-i18next';
import { bugReportUrl } from './bugReportUrl';
import { LinksModal, type ModalLink } from './LinksModal';
import { Bug, GithubLogo, MastodonLogo, RedditLogo, XLogo } from './icons';

type Props = { onClose: () => void };

export function FeedbackModal({ onClose }: Props) {
  const { t } = useTranslation('landing');

  const links: ModalLink[] = [
    {
      // Prefilled with the running version and platform, so the reporter never types either and
      // we never get a guess. See bugReportUrl.ts for why the version is supplied rather than
      // asked for. Sits above the general GitHub link: a bug is the common case, and the link
      // below still covers feature requests, questions, and everything else.
      href: bugReportUrl(),
      label: t('feedback.labelReportBug'),
      desc: t('feedback.descReportBug'),
      rel: 'noopener noreferrer',
      icon: <Bug size={16} weight="fill" className="shrink-0" />,
    },
    {
      // The template picker, not the issue list: it shows every template plus the security
      // contact, which the bare /issues list does not. Sits above the social links: the
      // catch-all inbox outranks the follow-us destinations.
      href: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues/new/choose',
      label: 'GitHub',
      desc: t('feedback.descGithub'),
      rel: 'noopener noreferrer',
      icon: <GithubLogo size={16} weight="fill" className="shrink-0" />,
    },
    {
      href: 'https://x.com/PrivacyNotesApp',
      label: 'X.com',
      desc: t('feedback.descX'),
      rel: 'noopener noreferrer',
      icon: <XLogo size={16} weight="fill" className="shrink-0" />,
    },
    {
      href: 'https://www.reddit.com/r/PrivacyNotes/',
      label: 'Reddit',
      desc: t('feedback.descReddit'),
      rel: 'noopener noreferrer',
      icon: <RedditLogo size={16} weight="fill" className="shrink-0" />,
    },
    {
      href: 'https://mastodon.social/@privacynotes',
      label: 'Mastodon',
      desc: t('feedback.descMastodon'),
      // rel="me" is required by Mastodon to verify this link back to the profile.
      rel: 'noopener noreferrer me',
      icon: <MastodonLogo size={16} weight="fill" className="shrink-0" />,
    },
  ];

  return <LinksModal title={t('feedback.title')} intro={t('feedback.intro')} links={links} onClose={onClose} />;
}
