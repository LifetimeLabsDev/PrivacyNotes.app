/**
 * Which community themes of one mode the app's gallery shows, and in what
 * order. Under All: a short row of COMMUNITY_ALL_SHOWN; under Community: up
 * to COMMUNITY_SHOWN_PER_MODE. Both follow the order toggle, by date or by
 * votes. Every
 * shipped theme still counts for a pick and a paste, and the theme a slot
 * shows stays on view even when it is not picked here (the caller adds it).
 * Its own module, so the Settings pane that names the number does not pull
 * the community list into boot.
 * Spec: ops/docs/color-themes.md (section 6)
 */
export const COMMUNITY_SHOWN_PER_MODE = 20;
/** Under All: a short row, after the team's themes. */
export const COMMUNITY_ALL_SHOWN = 8;

export type CommunitySort = 'votes' | 'newest';

export interface CommunityPickable {
  /** The day it was added (YYYY-MM-DD). */
  added: string;
  /** Upvotes on its discussion thread, from the shipped snapshot. */
  votes: number;
}

/** Newest first; a stable sort keeps list order within one day. */
function byNewest<T extends CommunityPickable>(list: T[]): T[] {
  return [...list].sort((a, b) => b.added.localeCompare(a.added));
}

/** Most votes first; a tie goes to the newer theme. */
function byVotes<T extends CommunityPickable>(list: T[]): T[] {
  return byNewest(list).sort((a, b) => b.votes - a.votes);
}

/** The community themes of one mode a gallery shows, in the order it shows them. */
export function pickCommunity<T extends CommunityPickable>(list: T[], filter: 'all' | 'community', sort: CommunitySort): T[] {
  const limit = filter === 'community' ? COMMUNITY_SHOWN_PER_MODE : COMMUNITY_ALL_SHOWN;
  return (sort === 'votes' ? byVotes(list) : byNewest(list)).slice(0, limit);
}
