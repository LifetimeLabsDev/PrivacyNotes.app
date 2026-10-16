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
 * check, that credits nobody, or whose id another entry has, here or in the
 * team list, or whose name another theme of the same mode has.
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
  /** The day it was added (YYYY-MM-DD). The app's gallery picks by it and by
   *  votes (communityShown.ts); /themes lists every one. */
  added: string;
  /** The number of the theme's thread in the public repository's Themes
   *  discussions, where people leave feedback. /themes links the credit to it;
   *  without one the credit links to the author's GitHub profile. */
  discussion?: number;
}

/** The Themes discussions of the public repository; a theme's thread is
 *  this URL, a slash and its `discussion` number. */
export const THEME_DISCUSSIONS_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/discussions';

export const COMMUNITY_THEMES: CommunityTheme[] = [
  { id: 'voidamethyst', code: 'pn1:Void Amethyst:1B1C22,16171C,262831,EBECF0,ACACAC,8A75F0:paper=14151A,well=13151B,by=BackupSFG', added: '2026-10-08', discussion: 460 },
  { id: 'terminal0000', code: 'pn1:Terminal:090C0D,0E1214,2A363D,DCE4DF,879994,63F2AB:list=13191C,well=13191C,soft=B4C3BD,hover=8AF6C0,fill=35835C,danger=FF6E7A,warning=F0C674,success=63F2AB,by=Real-Fruit-Snacks', added: '2026-10-09', discussion: 459 },
  { id: 'simpledark00', code: 'pn1:Simple Dark:1A1C1E,15141A,272625,D9D4CC,E6DEC1,DFDEC8:well=1A1816,soft=BDB6AC,hover=EAECD5,danger=E55254,warning=D0AF53,success=3CD7A6,label=E6E8D4,by=alearndro', added: '2026-10-15', discussion: 520 },
  { id: 'sailcloth000', code: 'pn1:Sailcloth:FFF8EE,F6E6CF,E3CDA8,2B1E14,6E5A45,1F6F78:by=privacytoolsIO', added: '2026-10-13', discussion: 507 },
  { id: 'koipond00000', code: 'pn1:Koi Pond:0F2A2E,0A1F22,1F4549,EAF2EF,9FB8B4,F2763B:by=privacytoolsIO', added: '2026-10-13', discussion: 506 },
  { id: 'centralperk0', code: 'pn1:Central Perk:1F2A22,172019,34433A,F3EBDD,B1A996,E8823A:by=privacytoolsIO', added: '2026-10-13', discussion: 505 },
  { id: 'citypop00000', code: 'pn1:City Pop:F0E5F0,D5C6E8,B9A5D8,14263F,4A4F80,055986:list=F6D3CF,well=F5C6C1,fill=007AAF,fillhover=085D9C,danger=992D38,warning=7B4900,success=245F46,by=Real-Fruit-Snacks', added: '2026-10-13', discussion: 502 },
  { id: 'mastersword0', code: 'pn1:Master Sword:121A2B,0D1422,26324A,E8E4D4,A9AFBF,E8C547:danger=FF8A7A,warning=E8C547,success=5FCF7A,by=privacytoolsIO', added: '2026-10-11', discussion: 485 },
  { id: 'shrine000000', code: 'pn1:Shrine:15313A,0F242C,2A4F5B,E4F2F5,9DBAC2,5AD8F5:danger=FF8A7A,warning=F2A23A,success=6FD39A,by=privacytoolsIO', added: '2026-10-11', discussion: 484 },
  { id: 'kokiriforest', code: 'pn1:Kokiri Forest:2A1F17,0F1F14,3A3424,EDE3BE,B8AE80,4CC24C:danger=F08A6A,warning=E8C860,success=4CC24C,by=privacytoolsIO', added: '2026-10-11', discussion: 483 },
  { id: 'hyrule000000', code: 'pn1:Hyrule:163A24,102C1B,26573A,F2EAC8,C9C29E,ECC046:danger=FF9A80,warning=E0A848,success=8FD3E0,by=privacytoolsIO', added: '2026-10-11', discussion: 482 },
  { id: 'strangernote', code: 'pn1:Stranger Notes:141B22,0E141A,2A3540,E4E8EC,98A4AE,FF4A4A:danger=FF8A70,warning=F2B84B,success=6FCF8A,by=privacytoolsIO', added: '2026-10-11', discussion: 481 },
  { id: 'harrynoter01', code: 'pn1:Harry Noter:F3E6C6,E3D0A4,C9AF7E,2B1D12,67503A,8B1A1A:by=privacytoolsIO', added: '2026-10-11', discussion: 480 },
  { id: 'harrynoter00', code: 'pn1:HarryNoter:2A0909,4A1012,6A1E1A,F4E8CA,CFBA94,F0BE3A:danger=FF9A8A,warning=F0BE3A,success=8FCF8A,by=privacytoolsIO', added: '2026-10-11', discussion: 479 },
  { id: 'breathofthen', code: 'pn1:Breath of the Notes:FEEEDC,F7DEA9,EAC673,1A2340,5A5A6E,375FBD:by=privacytoolsIO', added: '2026-10-11', discussion: 478 },
  { id: 'noteboy00000', code: 'pn1:Note Boy:EDEBE6,D3D0CA,B3B0AA,1B237A,55566A,9A2257:list=DCE2C2,by=privacytoolsIO', added: '2026-10-11', discussion: 477 },
  { id: 'rgbmadness00', code: 'pn1:RGB Madness:000000,0F0F0F,0000FF,00FF00,FFFF00,FF0000:by=bio-chemical', added: '2026-10-11', discussion: 474 },
  { id: 'outrun000000', code: 'pn1:Outrun:120B2A,1A1040,392266,F3EAFF,A99BD1,2CF2FF:well=120B2A,hover=FF81C5,fill=DE0074,fillhover=8D44FF,danger=FF6B9E,warning=FFB347,success=2CF2FF,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 470 },
  { id: 'ambercrt0000', code: 'pn1:Amber CRT:0D0A06,14100A,3A2E1C,E8DCC4,9A8B70,FFB000:list=1A140C,well=1A140C,soft=C9BBA0,hover=FFC640,fill=8F6200,danger=FF6B5E,warning=F0C674,success=8BD17C,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 468 },
  { id: 'honeycomb000', code: 'pn1:Honeycomb:FFF9E8,FBEFC9,E8D59A,2A2110,6B5A30,8A5A00:list=FFFCF4,well=FFFCF4,soft=41351B,hover=684400,fill=8A5A00,fillhover=784E00,danger=A8322A,warning=8A5A00,success=3F6B1F,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 467 },
  { id: 'hazard000000', code: 'pn1:Hazard:000000,000000,2B2B2B,F2F2F2,9A9A9A,FFD400:list=0C0C0C,well=0C0C0C,soft=D3D3D3,hover=FFE14C,fill=8A7300,fillhover=786400,danger=FF5C5C,warning=FF9F1A,success=6FDB8C,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 466 },
  { id: 'brassvault00', code: 'pn1:Brass Vault:16191C,101214,34393F,E4E2DC,969A9E,D4A94E:list=202326,well=202326,soft=C9C9C6,hover=E1C383,fill=8D7034,fillhover=7B612D,danger=E8736B,warning=D4A94E,success=8CC29A,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 465 },
  { id: 'eink00000000', code: 'pn1:E-Ink:E9E9E4,DDDDD7,BDBDB6,1C1C1A,5E5E59,2B2B28:list=EFEFEA,paper=F3F3EF,well=EFEFEA,soft=333330,hover=20201E,fill=2B2B28,fillhover=252523,danger=8C1D18,warning=6B5200,success=2F5D3A,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 464 },
  { id: 'mono00000000', code: 'pn1:Mono:0A0A0A,111111,333333,E6E6E6,8C8C8C,FFFFFF:list=181818,well=181818,soft=BFBFBF,hover=CCCCCC,fill=4D4D4D,danger=FF6E7A,warning=F0C674,success=7FD99A,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 463 },
  { id: 'grimoire0000', code: 'pn1:Grimoire:161219,0E0B12,584924,EAE2D0,C9BFA9,D4AF37:well=161219,hover=BF972C,danger=D35763,warning=D35763,success=5FA37A,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 462 },
];
