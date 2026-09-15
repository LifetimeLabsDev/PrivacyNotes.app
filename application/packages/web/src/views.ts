import type { NoteType } from '@notes/shared';

/**
 * The app shell's pillar/view union - the single source of truth.
 *
 * Copies of this union stay structurally compatible until a value is added to
 * one and not the others; each stale copy then breaks the build separately,
 * surfacing only after the previous is fixed. So it lives here once, and
 * everything else imports it.
 *
 * It is a leaf module on purpose: a type shared by thirteen files should not
 * hang off one of them, and `ListNav` importing from `TagsRail` would create a
 * component-to-component dependency for a string union.
 *
 * Adding a view means adding it HERE and nowhere else. Anything that switches
 * exhaustively on it will then fail to compile until it is handled, which is
 * the whole point.
 */
export type View =
  | 'all'
  | 'home'
  | 'journal'
  | 'starred'
  | 'trash'
  | 'tasks'
  | 'vault'
  | 'files'
  /** Plain-text files on the user's own disk. Never touches the encrypted
   *  store. Spec: ops/docs/plans/markdown-folder.md (no sync, history, or PIN-protect - vault-only features) */
  | 'markdown'
  /** Bookmarks pillar - notes of type 'link'. GUI name "Bookmarks", never
   *  "Links". Spec: ops/docs/plans/bookmarks-pillar.md (free feature, not gated behind Pro) */
  | 'bookmarks'
  /** Contacts pillar - notes of type 'contact'. Free and ungated, like
   *  bookmarks. Spec: ops/docs/plans/contacts-pillar.md (section 4, the View union member) */
  | 'contacts';

/**
 * Whether a view's row is drawn, given the user's hidden list and the view
 * that is open right now.
 *
 * A switched-off row still draws while it IS the open view. Several actions
 * move the app into a view on their own - an upload opens Files, a search hit
 * opens its item, the New menu opens the pillar it created into - and a hidden
 * target would leave the sidebar highlighting nothing with the user unable to
 * tell where they are. It is the rule Pinned has always followed at zero count.
 *
 * The exemption covers navigation the APP performs, never a hide the user
 * just asked for: switching a view off while standing in it moves the user to
 * All first (NotesView.handleToggleHiddenView), so the row goes at once. Left
 * to this rule alone the row stayed until the next view change or reload, and
 * the menu read as a dead control (reported for Bookmarks 2026-08-25).
 *
 * Read by all three lists that draw views: the wide rail (`TagsRail`), the
 * narrow icon strip (`CollapsedSidebar`) and the pillar dropdown in a list
 * title (`notesView/ListNav`). Platform availability is checked separately, and
 * first: Markdown stays hidden where no filesystem API exists whatever this
 * says. Spec: ops/docs/plans/sidebar-views.md (governs Show in sidebar only, separate from Show in All)
 */
export function isViewShown(view: View, hidden: View[] | undefined, current: View): boolean {
  return view === current || !hidden?.includes(view);
}

/**
 * The note types each view owns, for the All list's type filter.
 *
 * Views absent from this map contribute no types: 'home' is the All list
 * itself, 'starred' and 'trash' are states rather than types, and 'markdown'
 * reads the user's disk and never enters the encrypted store at all.
 * Spec: ops/docs/plans/sidebar-views.md (feeds the Show in All filter, the funnel icon setting)
 */
export const VIEW_NOTE_TYPES: Partial<Record<View, NoteType[]>> = {
  // 'all' is the Notes pillar, NOT the All list - see the union above, where
  // 'home' is All Items. The two names read backwards from their labels.
  all: ['note'],
  tasks: ['task'],
  journal: ['journal'],
  files: ['file'],
  vault: ['login', 'card', 'ssh-key'],
  bookmarks: ['link'],
  contacts: ['contact'],
};
