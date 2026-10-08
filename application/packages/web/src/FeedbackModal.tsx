import { Trans, useTranslation } from 'react-i18next';
import { bugReportUrl } from './bugReportUrl';
import { LinksModal, type ModalLink } from './LinksModal';
import { Bug, Chat, GithubLogo } from './icons';
import { FOLLOW_LINKS, GITHUB_NEW_ISSUE } from './followLinks';

type Props = { onClose: () => void };

const FOLLOW_ICON = { size: 18, weight: 'fill', className: 'shrink-0' } as const;

export function FeedbackModal({ onClose }: Props) {
  const { t } = useTranslation('landing');

  const links: ModalLink[] = [
    {
      // Prefilled with the running version and platform, so the reporter never types either and
      // we never get a guess. See bugReportUrl.ts for why the version is supplied rather than
      // asked for.
      href: bugReportUrl(),
      label: t('feedback.labelReportBug'),
      desc: t('feedback.descReportBug'),
      rel: 'noopener noreferrer',
      icon: <Bug size={16} weight="fill" className="shrink-0" />,
    },
    {
      // The template picker, not the issue list: it shows every template plus the security
      // contact, which the bare /issues list does not.
      href: GITHUB_NEW_ISSUE,
      label: 'GitHub',
      desc: t('feedback.descGithub'),
      rel: 'noopener noreferrer',
      icon: <GithubLogo size={16} weight="fill" className="shrink-0" />,
    },
  ];

  return (
    <LinksModal
      title={t('feedback.title')}
      titleIcon={<Chat size={17} weight="fill" className="shrink-0 text-accent" aria-hidden="true" />}
      intro={t('feedback.intro')}
      links={links}
      outro={
        <Trans
          i18nKey="landing:feedback.outro"
          components={{
            contact: (
              <a
                href="https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/SECURITY.md"
                target="_blank"
                rel="noopener noreferrer"
                className="text-accent hover:underline"
              />
            ),
          }}
        />
      }
      grid
      onClose={onClose}
    >
      <h3 className="mt-4 mb-2 text-xs font-medium text-pn-muted">{t('feedback.followHeading')}</h3>
      {/* Deliberately smaller than the two GitHub cards above: these read as
          updates, not as a second inbox. Five across once the container is wide enough for "Mastodon" to fit a tile, three
          across below that (a phone). A container query for the same reason as LinksList. */}
      <div className="@container">
        <div className="grid grid-cols-3 gap-2 @md:grid-cols-5">
          {FOLLOW_LINKS.map((l) => (
            <a
              key={l.href}
              href={l.href}
              target="_blank"
              rel={l.rel}
              className="flex flex-col items-center gap-1 px-1 py-2.5 rounded-lg border border-divider hover:bg-surface-1 transition group"
            >
              <span className="text-pn-muted group-hover:text-accent transition"><l.Icon {...FOLLOW_ICON} /></span>
              <span className="max-w-full truncate text-xs font-medium text-accent">{l.label}</span>
            </a>
          ))}
        </div>
      </div>
    </LinksModal>
  );
}
