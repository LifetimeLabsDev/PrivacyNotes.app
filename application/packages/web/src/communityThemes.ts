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
  /** What the author wrote about the theme in the form's "Anything we should
   *  know" field, rewritten into the house pattern (inspiration, colon,
   *  colors) with the same content: plain text on one line, at most 240
   *  characters (ops/docs/community-themes.md, section 3). /themes shows it on
   *  the card and in the viewer; the app does not show it. */
  description?: string;
}

/** The Themes discussions of the public repository; a theme's thread is
 *  this URL, a slash and its `discussion` number. */
export const THEME_DISCUSSIONS_URL = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app/discussions';

export const COMMUNITY_THEMES: CommunityTheme[] = [
  { id: 'whiterabbit0', code: 'pn1:White Rabbit:000000,030803,0F2A12,A8F5A8,4F9A58,00FF41:list=080C08,well=080C08,soft=89D58C,hover=B8FFC8,fill=008422,fillhover=00731E,danger=FF5C5C,warning=E8E05A,success=00FF41,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 589, description: "Falling green code on black." },
  { id: 'krustykrab00', code: 'pn1:Krusty Krab:FFF4E6,FCE0C2,F0C295,3A2410,7A5228,C8102E:list=FFFAF2,well=FFFAF2,soft=503418,hover=0B5886,fill=C8102E,fillhover=AE0E28,danger=B3261E,warning=7A5200,success=2E6B3A,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 588, description: "A fast-food shack: patty-bun cream with ketchup red and a blue hover." },
  { id: 'bikinibottom', code: 'pn1:Bikini Bottom:F8F6D8,FFF2A8,E8D66A,2B3A1C,6B6A2E,0B70AA:list=FCFAEC,well=FCFAEC,soft=414B22,hover=745900,fill=0B7AB8,fillhover=0A6AA0,danger=C8102E,warning=7A5200,success=2E7D32,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 587, description: "Under the sea: sandy yellow with lagoon-blue buttons and a sponge-yellow hover." },
  { id: 'madteaparty0', code: 'pn1:Mad Tea Party:1B0F24,150B1C,45305A,F0E4F5,AE9BBD,C77DFF:list=261A2E,well=261A2E,soft=D9CAE1,hover=3DF5C4,fill=905AB8,fillhover=7D4EA0,danger=FF6B8A,warning=F2C14E,success=7FD99A,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 586, description: "Alice in Wonderland: the Hatter's purple with a teacup-turquoise hover." },
  { id: 'thegrid00000', code: 'pn1:The Grid:030609,02050A,0E2A38,D6F4FF,6FA6BC,00D8FF:list=0E1215,well=0E1215,soft=B2D9E8,hover=FF7449,fill=007F96,fillhover=006E82,danger=FF6A3D,warning=FFB84D,success=7DF0C0,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 585, description: "A black arena: cyan light lines, with the other team's orange on hover." },
  { id: 'marmaladesan', code: 'pn1:Marmalade Sandwich:F7F1E6,E2E8EE,C9CFD6,1C2A4A,5B6478,B14416:list=FBF8F2,well=FBF8F2,soft=323E5A,hover=1F4E9A,fill=1F4E9A,fillhover=1B4486,danger=B3261E,warning=7A5200,success=2E6B3A,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 584, description: "A bear in a blue duffle coat and red hat: cream paper, blue buttons and links, and marmalade orange for icons and pins." },
  { id: 'risograph000', code: 'pn1:Risograph:FBF6EF,F4EFD9,E4D2A8,1F1F2A,5F5B6E,CF0074:list=FDFAF4,well=FDFAF4,soft=353442,hover=096168,fill=0077A8,fillhover=006892,danger=C0273A,warning=7A5200,success=0D7580,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 583, description: "A riso print on cream stock: fluorescent pink with a teal second ink and blue buttons." },
  { id: 'highcontrst1', code: 'pn1:High Contrast Light:FFFFFF,FFFFFF,000000,000000,303030,0000CC:list=FFFFFF,well=FFFFFF,soft=111111,hover=000000,fill=0000CC,fillhover=0000B1,danger=B00020,warning=7A4A00,success=006B2E,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 581, description: "Pure white and black with a strong blue accent. The light counterpart of High Contrast Dark." },
  { id: 'highcontrst0', code: 'pn1:High Contrast Dark:000000,000000,FFFFFF,FFFFFF,D0D0D0,FFFF00:list=0D0D0D,well=0D0D0D,soft=EFEFEF,hover=FFFFFF,fill=0060DF,fillhover=0054C2,danger=FF5C5C,warning=FFB000,success=3DFF8A,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 580, description: "Pure black and white with a yellow accent and blue buttons, for low vision and bright sunlight." },
  { id: 'candycane000', code: 'pn1:Candy Cane:FFFFFF,FCEFF1,F0C9CF,1A1A1A,5E5E5E,C8102E:list=FFFFFF,well=FFFFFF,soft=323232,hover=1F6B3A,fill=C8102E,fillhover=AE0E28,danger=C8102E,warning=7A5200,success=1F6B3A,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 577, description: "Christmas: crisp white with a peppermint-red accent and a green hover." },
  { id: 'cranberry000', code: 'pn1:Cranberry:1A0C10,140A0D,4A1F2B,F4E3E6,B49399,E85A6B:list=25171B,well=25171B,soft=DEC7CB,hover=EF8C97,fill=BD4A57,fillhover=A4404C,danger=FF7A85,warning=E8B45A,success=8FCB7A,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 576, description: "Thanksgiving: dark cranberry with a bright berry accent." },
  { id: 'graveyardfog', code: 'pn1:Graveyard Fog:1C1F1C,151815,353A35,DDE1DA,98A096,A8D08D:list=262926,well=262926,soft=C5CAC2,hover=C2DEAF,fill=647A53,fillhover=576A48,danger=FF7A7A,warning=E8C15A,success=A8D08D,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 575, description: "Halloween: fog grey with a pale moss-green accent." },
  { id: 'jackolantern', code: 'pn1:Jack-o-Lantern:0E0A14,0A0710,3A2A1A,F2E6D2,B09A86,FF8C1A:list=19151E,well=19151E,soft=DBCBB7,hover=FFB347,fill=AA5D10,fillhover=94510E,danger=FF5C5C,warning=FFB84D,success=8BD17C,by=Real-Fruit-Snacks', added: '2026-10-20', discussion: 574, description: "Halloween: a near-black violet night with carved-pumpkin orange and a candle-glow hover." },
  { id: 'zengarden000', code: 'pn1:Zen Garden:26292D,1D1F22,3D4248,E6E9E4,A3AAA6,6BBF45:paper=2A2D31,danger=FF8A7A,warning=E8A93A,success=6BBF45,by=privacytoolsIO', added: '2026-10-20', discussion: 573, description: "A zen garden: a waterfall, grey walls, green grass and a stone walkway." },
  { id: 'voidamethyst', code: 'pn1:Void Amethyst:1B1C22,16171C,262831,EBECF0,ACACAC,8A75F0:paper=14151A,well=13151B,by=BackupSFG', added: '2026-10-08', discussion: 460, description: "Obsidian: a dark purple theme in the colors of the Obsidian app." },
  { id: 'terminal0000', code: 'pn1:Terminal:090C0D,0E1214,2A363D,DCE4DF,879994,63F2AB:list=13191C,well=13191C,soft=B4C3BD,hover=8AF6C0,fill=35835C,danger=FF6E7A,warning=F0C674,success=63F2AB,by=Real-Fruit-Snacks', added: '2026-10-09', discussion: 459, description: "The author's Terminal Workbench Suite theme: near-black graphite surfaces, soft muted text and vibrant mint-green accents, for a clean developer look." },
  { id: 'simpledark00', code: 'pn1:Simple Dark:1A1C1E,15141A,272625,D9D4CC,E6DEC1,DFDEC8:well=1A1816,soft=BDB6AC,hover=EAECD5,danger=E55254,warning=D0AF53,success=3CD7A6,label=E6E8D4,by=alearndro', added: '2026-10-15', discussion: 520, description: "Best with folder colors and colored folder backgrounds." },
  { id: 'sailcloth000', code: 'pn1:Sailcloth:FFF8EE,F6E6CF,E3CDA8,2B1E14,6E5A45,1F6F78:by=privacytoolsIO', added: '2026-10-13', discussion: 507, description: "A summer harbor: a warm cream canvas, a sand-colored sidebar and a deep navy accent, like rope and sails. Soft on the eyes in daylight." },
  { id: 'koipond00000', code: 'pn1:Koi Pond:0F2A2E,0A1F22,1F4549,EAF2EF,9FB8B4,F2763B:by=privacytoolsIO', added: '2026-10-13', discussion: 506, description: "A Japanese garden pond: dark green-blue water with koi orange, calm for long writing sessions, with one warm color for links and buttons." },
  { id: 'centralperk0', code: 'pn1:Central Perk:1F2A22,172019,34433A,F3EBDD,B1A996,E8823A:by=privacytoolsIO', added: '2026-10-13', discussion: 505, description: "Friends: the dark green walls of the Central Perk coffee house and its famous orange sofa." },
  { id: 'citypop00000', code: 'pn1:City Pop:F0E5F0,D5C6E8,B9A5D8,14263F,4A4F80,055986:list=F6D3CF,well=F5C6C1,fill=007AAF,fillhover=085D9C,danger=992D38,warning=7B4900,success=245F46,by=Real-Fruit-Snacks', added: '2026-10-13', discussion: 502, description: "A Hiroshi Nagai print: lavender dusk, a pink pool deck and pool-blue water." },
  { id: 'mastersword0', code: 'pn1:Master Sword:121A2B,0D1422,26324A,E8E4D4,A9AFBF,E8C547:danger=FF8A7A,warning=E8C547,success=5FCF7A,by=privacytoolsIO', added: '2026-10-11', discussion: 485, description: "Zelda: the night-blue steel of the Master Sword with Triforce gold." },
  { id: 'shrine000000', code: 'pn1:Shrine:15313A,0F242C,2A4F5B,E4F2F5,9DBAC2,5AD8F5:danger=FF8A7A,warning=F2A23A,success=6FD39A,by=privacytoolsIO', added: '2026-10-11', discussion: 484, description: "Zelda, Breath of the Wild: the teal stone of a shrine with its cyan glow and amber highlights." },
  { id: 'kokiriforest', code: 'pn1:Kokiri Forest:2A1F17,0F1F14,3A3424,EDE3BE,B8AE80,4CC24C:danger=F08A6A,warning=E8C860,success=4CC24C,by=privacytoolsIO', added: '2026-10-11', discussion: 483, description: "Zelda, Ocarina of Time: the deep forest and wooden tree houses of the Kokiri, with the green of the Kokiri tunic and fairy gold." },
  { id: 'hyrule000000', code: 'pn1:Hyrule:163A24,102C1B,26573A,F2EAC8,C9C29E,ECC046:danger=FF9A80,warning=E0A848,success=8FD3E0,by=privacytoolsIO', added: '2026-10-11', discussion: 482, description: "Zelda: the green of Hyrule Field with Triforce gold." },
  { id: 'strangernote', code: 'pn1:Stranger Notes:141B22,0E141A,2A3540,E4E8EC,98A4AE,FF4A4A:danger=FF8A70,warning=F2B84B,success=6FCF8A,by=privacytoolsIO', added: '2026-10-11', discussion: 481, description: "Stranger Things: the cold blue-grey of the Upside Down with the neon red of the title." },
  { id: 'harrynoter01', code: 'pn1:Spellbook:F3E6C6,E3D0A4,C9AF7E,2B1D12,67503A,8B1A1A:by=privacytoolsIO', added: '2026-10-11', discussion: 480, description: "Harry Potter: Marauder's Map parchment, ink-brown text and a wax-seal red." },
  { id: 'harrynoter00', code: 'pn1:Wax Seal:2A0909,4A1012,6A1E1A,F4E8CA,CFBA94,F0BE3A:danger=FF9A8A,warning=F0BE3A,success=8FCF8A,by=privacytoolsIO', added: '2026-10-11', discussion: 479, description: "Harry Potter: a scarlet house-banner sidebar with Gryffindor gold." },
  { id: 'breathofthen', code: 'pn1:Breath of the Notes:FEEEDC,F7DEA9,EAC673,1A2340,5A5A6E,375FBD:by=privacytoolsIO', added: '2026-10-11', discussion: 478, description: "Zelda, Breath of the Wild: the game's world as a light theme." },
  { id: 'noteboy00000', code: 'pn1:Note Boy:EDEBE6,D3D0CA,B3B0AA,1B237A,55566A,9A2257:list=DCE2C2,by=privacytoolsIO', added: '2026-10-11', discussion: 477, description: "The original Game Boy: the grey body, the navy logo text, the magenta A and B buttons, and the green screen on the notes list." },
  { id: 'rgbmadness00', code: 'pn1:RGB Madness:000000,0F0F0F,0000FF,00FF00,FFFF00,FF0000:by=bio-chemical', added: '2026-10-11', discussion: 474, description: "High contrast: every color made of only 0 and F." },
  { id: 'outrun000000', code: 'pn1:Outrun:120B2A,1A1040,392266,F3EAFF,A99BD1,2CF2FF:well=120B2A,hover=FF81C5,fill=DE0074,fillhover=8D44FF,danger=FF6B9E,warning=FFB347,success=2CF2FF,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 470, description: "A neon night: deep purple with cyan and hot pink." },
  { id: 'ambercrt0000', code: 'pn1:Amber CRT:0D0A06,14100A,3A2E1C,E8DCC4,9A8B70,FFB000:list=1A140C,well=1A140C,soft=C9BBA0,hover=FFC640,fill=8F6200,danger=FF6B5E,warning=F0C674,success=8BD17C,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 468, description: "An amber monochrome monitor: warm black with a glowing orange-yellow accent." },
  { id: 'honeycomb000', code: 'pn1:Honeycomb:FFF9E8,FBEFC9,E8D59A,2A2110,6B5A30,8A5A00:list=FFFCF4,well=FFFCF4,soft=41351B,hover=684400,fill=8A5A00,fillhover=784E00,danger=A8322A,warning=8A5A00,success=3F6B1F,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 467, description: "A honeycomb: cream and wax yellow with dark honey for buttons and links." },
  { id: 'hazard000000', code: 'pn1:Hazard:000000,000000,2B2B2B,F2F2F2,9A9A9A,FFD400:list=0C0C0C,well=0C0C0C,soft=D3D3D3,hover=FFE14C,fill=8A7300,fillhover=786400,danger=FF5C5C,warning=FF9F1A,success=6FDB8C,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 466, description: "True black for OLED screens with a single warning-tape yellow." },
  { id: 'brassvault00', code: 'pn1:Brass Vault:16191C,101214,34393F,E4E2DC,969A9E,D4A94E:list=202326,well=202326,soft=C9C9C6,hover=E1C383,fill=8D7034,fillhover=7B612D,danger=E8736B,warning=D4A94E,success=8CC29A,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 465, description: "A bank vault door: brushed steel and brass fittings. Fitting for a privacy app." },
  { id: 'eink00000000', code: 'pn1:E-Ink:E9E9E4,DDDDD7,BDBDB6,1C1C1A,5E5E59,2B2B28:list=EFEFEA,paper=F3F3EF,well=EFEFEA,soft=333330,hover=20201E,fill=2B2B28,fillhover=252523,danger=8C1D18,warning=6B5200,success=2F5D3A,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 464, description: "An e-reader page: soft grey paper in pure greyscale, with no color to pull your attention." },
  { id: 'mono00000000', code: 'pn1:Mono:0A0A0A,111111,333333,E6E6E6,8C8C8C,FFFFFF:list=181818,well=181818,soft=BFBFBF,hover=CCCCCC,fill=4D4D4D,danger=FF6E7A,warning=F0C674,success=7FD99A,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 463, description: "Pure greyscale on black, with white as the accent." },
  { id: 'grimoire0000', code: 'pn1:Grimoire:161219,0E0B12,584924,EAE2D0,C9BFA9,D4AF37:well=161219,hover=BF972C,danger=D35763,warning=D35763,success=5FA37A,by=Real-Fruit-Snacks', added: '2026-10-11', discussion: 462, description: "A tarot card: antique gold on near-black." },
];
