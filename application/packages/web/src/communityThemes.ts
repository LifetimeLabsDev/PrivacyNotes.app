/**
 * The community themes: themes people sent in through the theme form in the
 * Themes category of the public repository's Discussions. The app's galleries ship the list as it is at
 * build time, and privacynotes.app/themes shows it with each credit, so a
 * theme newer than an install still reaches it through Copy code and Paste
 * theme code. The team's own themes are in teamThemes.ts.
 *
 * An entry is a permanent id (twelve lower-case letters and digits) and a
 * theme code as the app copies it, which ends in `by=` and the GitHub
 * username of the person who made it, from their submission. The code
 * carries the credit, so it stays with the theme in the app. The team reviews each one and may adjust a color
 * before it lands here; `pnpm theme:check "<code>"` prints every check and a
 * fixed code. The build refuses an entry whose code does not parse or fails a
 * check, that credits nobody, or whose id or name another
 * entry has, here or in the team list.
 *
 * A credit carries the username the person gave in a public issue, with
 * their consent in that form to show it in the app and on the page, and
 * nothing else about them.
 *
 * Import-free: themes-page.ts loads this file on its own.
 * Spec: ops/docs/color-themes.md (section 6)
 */
export interface CommunityTheme {
  id: string;
  code: string;
  /** The day it was added (YYYY-MM-DD). The app lists the newest first and
   *  shows only the newest of each mode; /themes lists every one. */
  added: string;
}

export const COMMUNITY_THEMES: CommunityTheme[] = [
  { id: 'voidamethyst', code: 'pn1:Void Amethyst:1B1C22,16171C,262831,EBECF0,ACACAC,8A75F0:paper=14151A,well=13151B,by=BackupSFG', added: '2026-10-08' },
  { id: 'terminal0000', code: 'pn1:Terminal:090C0D,0E1214,2A363D,DCE4DF,879994,63F2AB:list=13191C,well=13191C,soft=B4C3BD,hover=8AF6C0,fill=35835C,danger=FF6E7A,warning=F0C674,success=63F2AB,by=Real-Fruit-Snacks', added: '2026-10-09' },
];
