import { FacebookLogo, MastodonLogo, RedditLogo, XLogo, YoutubeLogo } from './icons';

/** Where to follow along: news and updates only. Bug reports and feature
 *  requests go to GitHub and nowhere else, so every surface that lists these
 *  shows the GitHub links apart from them. */
export const FOLLOW_LINKS = [
  { href: 'https://x.com/PrivacyNotesApp', label: 'X.com', rel: 'noopener noreferrer', Icon: XLogo },
  { href: 'https://www.reddit.com/r/PrivacyNotes/', label: 'Reddit', rel: 'noopener noreferrer', Icon: RedditLogo },
  // rel="me" is required by Mastodon to verify this link back to the profile.
  { href: 'https://mastodon.social/@privacynotes', label: 'Mastodon', rel: 'noopener noreferrer me', Icon: MastodonLogo },
  { href: 'https://www.youtube.com/@PrivacyNotesApp', label: 'YouTube', rel: 'noopener noreferrer', Icon: YoutubeLogo },
  { href: 'https://www.facebook.com/PrivacyNotesApp/', label: 'Facebook', rel: 'noopener noreferrer', Icon: FacebookLogo },
] as const;

/** The GitHub template picker: every issue template plus the security contact. */
export const GITHUB_NEW_ISSUE = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues/new/choose';
