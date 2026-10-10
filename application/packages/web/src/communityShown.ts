/**
 * How many community themes of one mode the app's gallery shows: the newest.
 * Every shipped one still counts for a pick and a paste, and the theme a slot
 * shows stays on view even when it is older. Its own module, so the Settings
 * pane that names the number does not pull the community list into boot.
 * Spec: ops/docs/color-themes.md (section 6)
 */
export const COMMUNITY_SHOWN_PER_MODE = 20;
