/**
 * The theme code of each hand-tuned built-in palette, by mode and palette id:
 * its six colors, plus an override wherever the palette in index.css differs
 * from the color the code would suggest, so the code paints the palette
 * exactly. Copy code, Duplicate and New theme read these, a pasted code that
 * equals one picks the built-in palette, and /themes shows them.
 * tests/builtinThemeCodes.test.ts proves each code against index.css, so a
 * palette change there fails until its code here follows. The two Default
 * codes carry the mode in their names, because a theme name is unique.
 *
 * Import-free: themes-page.ts loads this file on its own.
 * Spec: ops/docs/color-themes.md (section 6)
 */
export const BUILTIN_THEME_CODES: Record<'light' | 'dark', Record<string, string>> = {
  light: {
    'default': 'pn1:Default Light:FFFFFF,F5F5F5,E5E5E5,0A0A0A,6A6A6A,1E40AF:list=FAFAF9,well=F5F5F5,soft=404040,hover=1E3A8A,fillhover=1E3A8A',
    'warm-cream': 'pn1:Cream:F0EBDE,E1D8C4,CBC1A8,2D2416,645944,1840B1:list=E4DCCA,well=E4DCCA,soft=574B38,hover=1E3A8A,fillhover=1E3A8A,danger=C10007',
    'slate': 'pn1:Slate:F0F2F5,DDE1E8,C0C6D1,121524,595E71,4338CA:list=E9ECF1,well=E2E6ED,soft=3D4356,hover=3730A3,fillhover=3730A3',
    'sage': 'pn1:Sage:F6F8F3,E1E7DE,CCD6C7,17201A,55665A,2B6A4D:list=EBF0E8,well=E4EAE0,soft=38463B,hover=1F533B,fillhover=1F533B',
  },
  dark: {
    'default': 'pn1:Default Dark:23211E,171514,302D29,D9D4CC,958E84,4A90D9:well=1A1816,soft=BDB6AC,hover=74AAE2',
    'soft-dark': 'pn1:Soft:282D36,1C1F26,363C48,CDD3DE,929AAA,89B7E6:well=181B21,soft=A6AEBD,hover=9EC4EB,fill=3D78B4',
    'navy-depths': 'pn1:Navy:161F35,0D1321,1E2A45,D4DAE7,8892A8,83A4F8:list=121A2E,well=0A0F1B,soft=AEB7C9,hover=99B4F9,fill=446FDD',
    'oled': 'pn1:OLED:000000,000000,262626,E8E8E8,8F8F8F,4A90D9:well=161616,soft=BDBDBD,hover=74AAE2',
  },
};
