/**
 * The team's own themes made from a theme code. The app shows them in
 * Settings, Appearance, Themes after the hand-tuned built-in themes, with no
 * credit, and privacynotes.app/themes shows them under "Made by the team".
 *
 * An entry is a permanent id (twelve lower-case letters and digits; a device
 * stores it in its theme slot, so it never changes) and a theme code as the
 * app copies it. An entry is never removed either: a slot that names a theme
 * this version does not list goes back to Default without a word. Its colors
 * may change, and a device that shows it then repaints. The build refuses an entry whose code does not parse or fails
 * a check, or whose id another entry has, here or in the community list, or
 * whose name another theme of the same mode has.
 *
 * Import-free: themes-page.ts loads this file on its own.
 * Spec: ops/docs/color-themes.md (section 6)
 */
export interface TeamTheme {
  id: string;
  code: string;
}

export const TEAM_THEMES: TeamTheme[] = [
  { id: 'midnightink0', code: 'pn1:Midnight:0B0B0B,000000,262626,E6E6E6,8A8A8A,E0A458' },
  { id: 'rosewater000', code: 'pn1:Rose:FDF8F8,F2E4E4,E6D3D3,2A1A1F,6B4E57,A33A5A' },
  { id: 'frost0000000', code: 'pn1:Frost:3B4252,2E3440,434C5E,ECEFF4,B8C0CE,88C0D0' },
  { id: 'papermint000', code: 'pn1:Mint:FBFCFA,EEF3EF,DCE5DE,1C2620,55665B,286E50' },
  { id: 'espresso0000', code: 'pn1:Espresso:2A211C,211A16,3D312A,EDE3D9,B5A597,D99A5B' },
  { id: 'lavender0000', code: 'pn1:Lavender:FAF8FD,EFEBF7,DDD6EC,221D2E,5F5874,6B46C1' },
  { id: 'plum00000000', code: 'pn1:Plum:2A2133,211A29,3B2F47,EDE6F3,B3A6C2,E58FB8' },
  { id: 'apricot00000', code: 'pn1:Apricot:FFF9F4,FBEBDD,F0D9C6,2B1D14,6E5646,A9401B' },
];
