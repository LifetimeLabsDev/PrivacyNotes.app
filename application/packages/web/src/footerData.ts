// Single source of truth for the site footer's link columns. Consumed by
// BOTH the homepage footer (SiteFooter.tsx, React + Tailwind) and the
// static pre-rendered pages (../static-page-chrome.ts, raw HTML+CSS).
//
// Plain data only - no JSX, no Tailwind, no React/DOM imports - so the
// static-page build plugin (which runs in Node) can import it too. Each
// renderer maps the `icon` key to its own icon implementation (a Phosphor
// React component vs an inline SVG path), because the two style systems
// cannot be merged: the static pages ship no Tailwind and no JS under the
// CSP, so the JSX footer can't render there.
//
// Brand wordmark, version pill, and the bottom legal bar are stable
// presentational chrome and stay in each renderer; the link lists below
// are the part that actually changes, so they live here.

export type FooterIcon =
  | 'github'
  | 'shield'
  | 'download'
  | 'faq'
  | 'changelog'
  | 'roadmap'
  | 'brand'
  | 'x'
  | 'reddit'
  | 'mastodon'
  | 'lock'
  | 'file'
  | 'refund'
  | 'scales'
  | 'print';

type FooterLink = {
  label: string;
  href: string;
  icon: FooterIcon;
  /**
   * Shorter label for the static-page header nav, which has far less room
   * than a footer column ("Help & FAQ" is a fine footer row and a bad nav
   * pill). Only the Help column carries these, because only that column
   * feeds the nav - see siteNav() in ../static-page-chrome.ts. A Help-column
   * link WITHOUT one is footer-only: the nav renders the column's sections,
   * not its utility links (the hotkey cheat sheet is the precedent).
   */
  short?: string;
  /** Opens in a new tab with noopener noreferrer. Omit for same-origin links. */
  external?: boolean;
  /** Adds rel="me" alongside noopener noreferrer, for Mastodon profile verification. */
  relMe?: boolean;
};

export type FooterColumn = {
  /** Rendered as a "// HEADING" kicker. */
  heading: string;
  links: FooterLink[];
};

// The first column also carries the brand wordmark + version pill, added by
// each renderer above the heading.
export const FOOTER_COLUMNS: FooterColumn[] = [
  {
    // One group, not two: a lone "Download" heading above a lone "Open source"
    // heading left column 1 twice as tall as the other three. Every row is a
    // way to get the software - the binary, the source, and the proof.
    heading: 'Download',
    links: [
      // Order is what the reader wants in order of how many want it: the
      // binary, then the source it was built from, then the proof. The href
      // is a placeholder: both renderers re-point 'download' at the active
      // locale's homepage (/de#downloads), like they do for 'faq'.
      { label: 'All platforms', href: '/en#downloads', icon: 'download' },
      // "Open source on GitHub" wrapped to two lines in the 151px mobile
      // column; the GitHub mark already says where the link goes.
      { label: 'Open source', href: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app', icon: 'github', external: true },
      // The one deep link in the footer, and it earns the place: this is the
      // only row that answers "prove it" rather than "here it is". Every
      // static page carries this footer, so the help center, the changelog,
      // the roadmap and the brand page all gain the route in one edit.
      { label: 'Verify it yourself', href: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/blob/main/VERIFY.md', icon: 'shield', external: true },
    ],
  },
  {
    // Also the source for the static-page header nav (siteNav() in
    // ../static-page-chrome.ts) - these four ARE the marketing site's
    // sections, so the header and the footer can never list different ones.
    // A new section added here appears in both without a second edit.
    heading: 'Help',
    links: [
      { label: 'Help & FAQ', short: 'Help', href: '/help', icon: 'faq' },
      { label: 'Changelog', short: 'Changelog', href: '/changelog', icon: 'changelog' },
      { label: 'Roadmap', short: 'Roadmap', href: '/roadmap', icon: 'roadmap' },
      { label: 'Brand kit', short: 'Brand', href: '/brand', icon: 'brand' },
      // No `short`: footer-only, never a nav pill. The printable cheat
      // sheet is English-only by design, so the href carries no locale.
      { label: 'Hotkeys', href: '/help/keyboard-shortcuts/cheat-sheet', icon: 'print' },
    ],
  },
  {
    heading: 'Feedback',
    links: [
      { label: 'X.com', href: 'https://x.com/PrivacyNotesApp', icon: 'x', external: true },
      { label: 'reddit.com', href: 'https://www.reddit.com/r/PrivacyNotes/', icon: 'reddit', external: true },
      { label: 'GitHub.com', href: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/issues/', icon: 'github', external: true },
      { label: 'Mastodon', href: 'https://mastodon.social/@privacynotes', icon: 'mastodon', external: true, relMe: true },
    ],
  },
  {
    heading: 'Legal',
    links: [
      { label: 'Privacy Policy', href: 'https://lifetimelabs.dev/privacy/', icon: 'lock', external: true },
      { label: 'Terms of Service', href: 'https://lifetimelabs.dev/terms/', icon: 'file', external: true },
      { label: 'Refund Policy', href: 'https://lifetimelabs.dev/terms/#refunds', icon: 'refund', external: true },
      // The one place product copy names the app license. Links to the
      // repo root, where GitHub surfaces the license itself; never a
      // LICENSE deep link.
      { label: 'Licensed AGPL-3.0', href: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app', icon: 'scales', external: true },
    ],
  },
];
