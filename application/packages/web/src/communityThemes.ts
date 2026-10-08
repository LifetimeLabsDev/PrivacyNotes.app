/**
 * The community themes: themes people sent in through the theme form in the
 * public repository's issues. Only privacynotes.app/themes shows them, with
 * their credits; a person takes one into the app with Copy code and Paste
 * theme code, so a new one needs no app release. The team's own themes are
 * in teamThemes.ts.
 *
 * An entry is a permanent id (twelve lower-case letters and digits), a theme
 * code as the app copies it, and the GitHub username of the person who made
 * it, from their submission. The team reviews each one and may adjust a color
 * before it lands here; `pnpm theme:check "<code>"` prints every check and a
 * fixed code. The build refuses an entry whose code does not parse or fails a
 * check, whose username GitHub would not accept, or whose id or name another
 * entry has, here or in the team list.
 *
 * A credit carries the username the person gave in a public issue for this
 * page, with their consent in that form, and nothing else about them.
 *
 * Import-free: themes-page.ts loads this file on its own.
 * Spec: ops/docs/color-themes.md (section 6)
 */
export interface CommunityTheme {
  id: string;
  code: string;
  author: string;
}

export const COMMUNITY_THEMES: CommunityTheme[] = [];
