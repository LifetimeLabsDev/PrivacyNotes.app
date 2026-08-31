// Static announcement registry: one banner mechanism, many announcements.
// The list ships in the bundle by design - a fetched list would add a
// server call to every boot, and announcements are rare enough that a
// deploy per announcement is the correct cost. Adding the next one is a
// new entry here plus its locale keys, not a feature.
// Spec: ops/docs/backlog.md (#175, the general announcement banner)

type AnnouncementSurface = 'app' | 'site' | 'both';

export type Announcement = {
  /** Stable id. Dismissals key on it, so never reuse one. */
  id: string;
  /**
   * Where it shows: the app shell, the marketing homepage, or both.
   * An `app` announcement never touches the site's localStorage store.
   */
  surface: AnnouncementSurface;
  /** landing.json keys. The narrow forms render below the sm line. */
  textKey: string;
  textNarrowKey: string;
  ctaKey: string;
  ctaNarrowKey: string;
  href: string;
};

export const ANNOUNCEMENTS: Announcement[] = [
  {
    id: 'oss-launch',
    surface: 'both',
    textKey: 'announcement.ossText',
    textNarrowKey: 'announcement.ossTextNarrow',
    ctaKey: 'announcement.ossCta',
    ctaNarrowKey: 'announcement.ossCtaNarrow',
    href: 'https://github.com/LifetimeLabsDev/PrivacyNotes.app',
  },
];

// The site's dismissal store. Per browser, because the apex visitor has
// no account; the app's store is the synced `dismissedAnnouncements`
// field in UserSettings. The two origins are separate and never share a
// dismissal - accepted: somebody who dismisses on the homepage sees the
// banner once more in the app. Both stores hold a SET of ids, never a
// boolean, so the next announcement shows to somebody who dismissed
// this one.
const SITE_DISMISS_KEY = 'privacynotes.announcementsDismissed';

export function siteDismissedIds(): string[] {
  try {
    const raw = localStorage.getItem(SITE_DISMISS_KEY);
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    return Array.isArray(parsed)
      ? parsed.filter((x): x is string => typeof x === 'string')
      : [];
  } catch {
    return [];
  }
}

export function dismissOnSite(id: string): void {
  try {
    const ids = siteDismissedIds();
    if (ids.includes(id)) return;
    localStorage.setItem(SITE_DISMISS_KEY, JSON.stringify([...ids, id]));
  } catch {
    /* storage disabled - the banner returns next visit, which is harmless */
  }
}
