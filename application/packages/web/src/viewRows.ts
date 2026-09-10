import type { TFunction } from 'i18next';
import { PILLAR_GLYPHS, type Icon } from './icons';
import { markdownSupport } from './markdownFolder/capability';
import type { View } from './views';

/** One row in a list of views: the view it opens, its label, its glyph. */
export type ViewRow = { key: View; label: string; icon: Icon };

/**
 * Every view a list of views can offer, in sidebar order.
 *
 * Five surfaces draw such a list - the wide rail, the collapsed strip, the
 * phone switcher, the two option menus, and the Appearance settings - and each
 * one used to keep its own copy against its own label keys. Two of those copies
 * read `pillars.*` and two read `tagsRail.*` for the same nine words, so a
 * reworded pillar could have half the app saying one thing and half the other,
 * in every language, with locale parity green because both keys existed.
 *
 * The `t` is bound to the SHELL namespace by the caller. Adding a pillar means
 * one entry here and nowhere else.
 * Spec: ops/docs/plans/start-view.md (one row list, one label namespace)
 */
export function viewRows(t: TFunction): ViewRow[] {
  return [
    { key: 'home', label: t('tagsRail.allItems'), icon: PILLAR_GLYPHS.all },
    { key: 'starred', label: t('tagsRail.pinned'), icon: PILLAR_GLYPHS.pinned },
    { key: 'all', label: t('tagsRail.notes'), icon: PILLAR_GLYPHS.notes },
    { key: 'tasks', label: t('tagsRail.tasks'), icon: PILLAR_GLYPHS.tasks },
    { key: 'vault', label: t('tagsRail.vault'), icon: PILLAR_GLYPHS.vault },
    { key: 'files', label: t('tagsRail.files'), icon: PILLAR_GLYPHS.files },
    { key: 'journal', label: t('tagsRail.journals'), icon: PILLAR_GLYPHS.journals },
    // Plain-text files on the user's own disk. Absent wherever no filesystem
    // API exists, so the row is never offered on a platform that cannot open
    // a folder.
    ...(markdownSupport() !== 'unavailable'
      ? [{ key: 'markdown' as View, label: t('tagsRail.markdown'), icon: PILLAR_GLYPHS.markdown }]
      : []),
    { key: 'contacts', label: t('tagsRail.contacts'), icon: PILLAR_GLYPHS.contacts },
    { key: 'bookmarks', label: t('tagsRail.bookmarks'), icon: PILLAR_GLYPHS.bookmarks },
  ];
}

/**
 * The rows the "Show in sidebar" menu and the Appearance table offer.
 *
 * All is absent because it cannot be hidden from itself: it is the home view
 * and the collapsed rail's logo goes there.
 * Spec: ops/docs/plans/sidebar-views.md
 */
export function sidebarViewRows(t: TFunction): ViewRow[] {
  return viewRows(t).filter((r) => r.key !== 'home');
}

/**
 * The rows the "Show in All" menu offers.
 *
 * Pinned is a state rather than a type, and Markdown files live on the user's
 * disk and never enter the encrypted store, so neither contributes items the
 * All list could hold.
 */
export function allViewRows(t: TFunction): ViewRow[] {
  return sidebarViewRows(t).filter((r) => r.key !== 'starred' && r.key !== 'markdown');
}

/**
 * The rows the below-lg pillar switcher offers.
 *
 * Markdown is dropped whatever the platform says: this switcher only opens
 * below lg, and no phone has the filesystem API the pillar needs. Pinned is
 * dropped because the switcher has never carried it - the drawer does. That is
 * behaviour this list inherited rather than chose; changing it is its own call.
 */
export function switcherViewRows(t: TFunction): ViewRow[] {
  return viewRows(t).filter((r) => r.key !== 'starred' && r.key !== 'markdown');
}

/**
 * The rows the "Start in" setting offers, and the reader that resolves it.
 *
 * Markdown is never a start view: its folder handle is session-only by design,
 * so the app would open on a pillar that can only explain itself. A view the
 * user has hidden is not offered either.
 * Spec: ops/docs/plans/start-view.md (a hidden start view falls back to All)
 */
export function startViewRows(t: TFunction, hidden: View[] | undefined): ViewRow[] {
  return viewRows(t).filter((r) => r.key !== 'markdown' && !hidden?.includes(r.key));
}

/**
 * The view a stored "Start in" choice resolves to.
 *
 * Filtering here rather than rewriting the stored value on hide means
 * un-hiding a view brings the choice back, which is what somebody who hid it
 * by accident expects.
 */
export function resolveStartView(stored: View, hidden: View[] | undefined): View {
  if (stored === 'home') return 'home';
  if (stored === 'markdown' || stored === 'trash') return 'home';
  if (hidden?.includes(stored)) return 'home';
  return stored;
}
