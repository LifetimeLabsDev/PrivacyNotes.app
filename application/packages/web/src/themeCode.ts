/**
 * Custom color themes: the theme code and the colors a theme resolves to.
 *
 * A person picks six colors. The app suggests the other values a palette
 * needs from those six, and the person can override each suggestion. A
 * theme travels as one line of text, the theme code:
 *
 *   pn1:<name>:<background>,<sidebar>,<border>,<text>,<muted>,<accent>[:<key>=<hex>,...][,logo=original][,by=<username>]
 *
 * Every hex value is exactly six hex digits, and nothing else is accepted,
 * so no pasted text can reach CSS. A well-formed pair with a key this
 * version does not know is kept as text and never painted, so a code from a
 * later version still pastes and its new keys travel on when it is copied. `by` credits the person who made the
 * theme: a GitHub username, shown as text and never as a color.
 * `logo=original` keeps the logo in its original colors; without it the logo
 * takes the accent. The name is plain text that cannot hold
 * ":" or ",". The `pn1` prefix freezes the grammar, the rules that derive
 * the suggested values and the rule that reads the mode: a code pasted in a
 * later version paints the same colors. A change to any of them is `pn2`.
 *
 * Import-free on purpose. The /themes page build loads this file on its own
 * (themes-page.ts), and the app loads it lazily, so it stays off the boot
 * path. Spec: ops/docs/color-themes.md (section 6)
 */

const PREFIX = 'pn1';
const THEME_NAME_MAX = 32;
/** The longest name the builder lets a person type, so a card keeps its
 *  layout. A code from elsewhere may still carry up to THEME_NAME_MAX. */
export const THEME_NAME_INPUT_MAX = 20;
/** The longest code the parser reads, and the register size in the blob. */
const THEME_CODE_MAX = 512;

export const SEED_KEYS = ['background', 'sidebar', 'border', 'text', 'muted', 'accent'] as const;
export type SeedKey = (typeof SEED_KEYS)[number];

/** The values the app suggests, in the order a code writes them. */
export const MORE_KEYS = ['list', 'paper', 'well', 'soft', 'hover', 'fill', 'fillhover', 'danger', 'warning', 'success', 'label'] as const;
export type MoreKey = (typeof MORE_KEYS)[number];

/** A color as `#RRGGBB`, upper case. */
export type Hex = string;
export type ThemeMode = 'light' | 'dark';

export interface CustomTheme {
  name: string;
  seeds: Record<SeedKey, Hex>;
  overrides: Partial<Record<MoreKey, Hex>>;
  /** The GitHub username of the person who made it. A change of any color
   *  drops it, so a credit always names the colors its author picked. */
  author?: string;
  /** Set when the logo keeps its original colors; absent, it takes the
   *  accent, as in every built-in palette but Default. */
  logo?: ThemeLogo;
  /** Pairs a later version added (`key=value`), in the order the code had
   *  them. Never painted; kept so a copy passes them on. */
  extra?: string[];
}

export type ThemeLogo = 'original';

/** A GitHub username: letters, digits and single hyphens inside, up to 39. */
export const AUTHOR = /^[A-Za-z0-9](?:[A-Za-z0-9]|-(?=[A-Za-z0-9])){0,38}$/;

/** The `--pn-*` tokens a custom theme sets. Every other token is the mode's. */
export const TOKEN_KEYS = [
  'surface-0', 'surface-1', 'surface-2', 'track', 'divider',
  'text', 'text-soft', 'text-muted',
  'accent', 'accent-hover', 'accent-fill', 'accent-fill-hover',
  'danger', 'warning', 'success',
] as const;
export type TokenKey = (typeof TOKEN_KEYS)[number];

export interface ResolvedTheme {
  mode: ThemeMode;
  colors: Record<TokenKey, Hex>;
  /** What the app suggests for each value it derives, before an override. */
  suggested: Record<MoreKey, Hex>;
  /** The ink of a folder or tag with no color of its own, and of the Jump to
   *  hover: the code's `label`, or the suggestion. */
  label: Hex;
  /** The writing area: the code's `paper`, or the background. */
  paper: Hex;
}

// ---------------------------------------------------------------- parsing

const HEX6 = /^[0-9A-Fa-f]{6}$/;
const EXTRA_PAIR = /^[a-z]{1,12}=[0-9A-Za-z-]{1,40}$/;
// Characters that draw nothing and can disguise a name, so two names that look
// alike stay different and a name can look empty. Refused: every format
// character, the letters and marks that draw nothing (the Hangul fillers, the
// braille blank, the combining grapheme joiner, the Khmer inherent vowels, the
// Mongolian variation selectors), and every variation selector. Kept where a
// script or an emoji needs them: a joiner between two letters of a script that
// is not Latin, or between emoji; the selector of an emoji or a keycap; the
// ideographic variation selector after an ideograph; and the tag characters of
// a subdivision flag.
const FORMAT = /\p{Cf}/u;
const BLANK = new Set([0x115f, 0x1160, 0x3164, 0xffa0, 0x2800, 0x034f, 0x17b4, 0x17b5, 0x180b, 0x180c, 0x180d, 0x180e, 0x180f]);
const PICTOGRAPHIC = /\p{Extended_Pictographic}/u;
const IDEOGRAPH = /\p{Ideographic}/u;
const JOINABLE = /[\p{L}\p{M}\p{Extended_Pictographic}]/u;
const LATIN_OR_DIGIT = /[\p{Script=Latin}\p{Nd}]/u;
const BLACK_FLAG = 0x1f3f4;
const isTag = (cp: number) => cp >= 0xe0020 && cp <= 0xe007f;

function hasHidden(name: string): boolean {
  const chars = [...name];
  const cps = chars.map((c) => c.codePointAt(0)!);
  return cps.some((cp, i) => {
    const prev = chars[i - 1] ?? '';
    const next = chars[i + 1] ?? '';
    if (BLANK.has(cp)) return true;
    if (cp === 0x200c || cp === 0x200d) {
      const ok = (c: string) => JOINABLE.test(c) && !LATIN_OR_DIGIT.test(c);
      return !(ok(prev) && ok(next));
    }
    if (isTag(cp)) {
      // A tag run must start at a black flag and end with the cancel tag.
      let j = i;
      while (j > 0 && isTag(cps[j - 1]!)) j--;
      let k = i;
      while (k < cps.length - 1 && isTag(cps[k + 1]!)) k++;
      return !(cps[j - 1] === BLACK_FLAG && cps[k] === 0xe007f);
    }
    if (cp >= 0xfe00 && cp <= 0xfe0f) return !(PICTOGRAPHIC.test(prev) || next === '\u20E3');
    if (cp >= 0xe0100 && cp <= 0xe01ef) return !IDEOGRAPH.test(prev);
    return FORMAT.test(chars[i]!);
  });
}

/** A name as a theme keeps it, or null when it cannot be one. */
export function cleanThemeName(raw: string): string | null {
  const name = raw.normalize('NFC').replace(/\s+/g, ' ').trim();
  if (name === '' || [...name].length > THEME_NAME_MAX) return null;
  if (/[:,]/.test(name) || /\p{Cc}/u.test(name) || hasHidden(name)) return null;
  return name;
}

/** Read a theme code. Anything that is not exactly a code is null. */
export function parseThemeCode(input: string): CustomTheme | null {
  if (typeof input !== 'string') return null;
  const code = input.trim();
  if (code === '' || code.length > THEME_CODE_MAX || /[\r\n]/.test(code)) return null;
  const parts = code.split(':');
  if (parts.length !== 3 && parts.length !== 4) return null;
  const [prefix, rawName, seedPart, morePart] = parts as [string, string, string, string | undefined];
  if (prefix !== PREFIX) return null;
  const name = cleanThemeName(rawName);
  if (name === null) return null;

  const seedValues = seedPart.split(',');
  if (seedValues.length !== SEED_KEYS.length || !seedValues.every((v) => HEX6.test(v))) return null;
  const seeds = {} as Record<SeedKey, Hex>;
  SEED_KEYS.forEach((k, i) => { seeds[k] = `#${seedValues[i]!.toUpperCase()}`; });

  const overrides: Partial<Record<MoreKey, Hex>> = {};
  let author: string | undefined;
  let logo: ThemeLogo | undefined;
  const extra: string[] = [];
  const seen = new Set<string>();
  if (morePart !== undefined) {
    if (morePart === '') return null;
    for (const pair of morePart.split(',')) {
      const key = pair.slice(0, pair.indexOf('='));
      if (seen.has(key)) return null;
      seen.add(key);
      if (pair.startsWith('by=')) {
        const by = pair.slice(3);
        if (author !== undefined || !AUTHOR.test(by)) return null;
        author = by;
        continue;
      }
      if (pair.startsWith('logo=')) {
        const value = pair.slice(5);
        if (logo !== undefined || value !== 'original') return null;
        logo = value;
        continue;
      }
      if ((MORE_KEYS as readonly string[]).includes(key)) {
        const m = /^[a-z]+=([0-9A-Fa-f]{6})$/.exec(pair);
        if (!m) return null;
        overrides[key as MoreKey] = `#${m[1]!.toUpperCase()}`;
        continue;
      }
      // A key from a later version: kept, never painted. Its value cannot
      // hold ":" or ",", so it cannot change how the rest of the code reads.
      if (!EXTRA_PAIR.test(pair)) return null;
      extra.push(pair);
    }
  }
  return {
    name, seeds, overrides,
    ...(logo ? { logo } : {}),
    ...(author === undefined ? {} : { author }),
    ...(extra.length ? { extra } : {}),
  };
}

/** The one canonical code for a theme: upper-case hex, overrides in key order. */
export function serializeThemeCode(theme: CustomTheme): string {
  const seeds = SEED_KEYS.map((k) => theme.seeds[k].slice(1)).join(',');
  const pairs = MORE_KEYS.filter((k) => theme.overrides[k]).map((k) => `${k}=${theme.overrides[k]!.slice(1)}`);
  if (theme.logo) pairs.push(`logo=${theme.logo}`);
  if (theme.extra) pairs.push(...theme.extra);
  if (theme.author) pairs.push(`by=${theme.author}`);
  const more = pairs.join(',');
  return `${PREFIX}:${theme.name}:${seeds}${more ? `:${more}` : ''}`;
}

// ---------------------------------------------------------------- color math

type RGB = [number, number, number];
const rgbOf = (h: Hex): RGB => [1, 3, 5].map((i) => parseInt(h.slice(i, i + 2), 16)) as RGB;
const hexOf = (c: RGB): Hex =>
  `#${c.map((v) => Math.round(Math.min(255, Math.max(0, v))).toString(16).padStart(2, '0')).join('')}`.toUpperCase();

/** `t` of the way from `a` to `b`, in 8-bit sRGB, each channel rounded. */
function mix(a: Hex, b: Hex, t: number): Hex {
  const x = rgbOf(a);
  const y = rgbOf(b);
  return hexOf([0, 1, 2].map((i) => x[i]! * (1 - t) + y[i]! * t) as RGB);
}

const channel = (v: number) => {
  const s = v / 255;
  return s <= 0.03928 ? s / 12.92 : ((s + 0.055) / 1.055) ** 2.4;
};
const luminance = (h: Hex) => {
  const [r, g, b] = rgbOf(h);
  return 0.2126 * channel(r) + 0.7152 * channel(g) + 0.0722 * channel(b);
};

/** WCAG contrast ratio of two colors. */
function contrast(a: Hex, b: Hex): number {
  const x = luminance(a);
  const y = luminance(b);
  return (Math.max(x, y) + 0.05) / (Math.min(x, y) + 0.05);
}

/** Dark when the background is darker than the text. */
function themeMode(seeds: Record<SeedKey, Hex>): ThemeMode {
  return luminance(seeds.background) < luminance(seeds.text) ? 'dark' : 'light';
}

// ---------------------------------------------------------------- the mode's own colors

// Copied from the :root and :root.dark blocks of index.css, which every theme
// of a mode inherits, in the `r g b` form those blocks write a token in;
// tests/themeCode.test.ts fails when the two disagree.
const STATUS_CHANNELS: Record<ThemeMode, Record<'danger' | 'warning' | 'success', string>> = {
  light: { danger: '193 0 7', warning: '151 60 0', success: '0 96 69' },
  dark: { danger: '255 100 103', warning: '255 185 0', success: '0 212 146' },
};
const PRO_CHANNELS: Record<ThemeMode, string> = { light: '180 83 9', dark: '245 197 24' };
const fromChannels = (c: string): Hex => hexOf(c.split(' ').map(Number) as RGB);
const STATUS = {
  light: { danger: fromChannels(STATUS_CHANNELS.light.danger), warning: fromChannels(STATUS_CHANNELS.light.warning), success: fromChannels(STATUS_CHANNELS.light.success) },
  dark: { danger: fromChannels(STATUS_CHANNELS.dark.danger), warning: fromChannels(STATUS_CHANNELS.dark.warning), success: fromChannels(STATUS_CHANNELS.dark.success) },
};
const PRO: Record<ThemeMode, Hex> = { light: fromChannels(PRO_CHANNELS.light), dark: fromChannels(PRO_CHANNELS.dark) };
// The folder and tag ink follows the accent, the color of the sidebar's own
// icons, so a theme starts calm with one color; a person colors a single
// folder or tag in its look, and a theme code may still set `label=`. The
// built-in palettes point --pn-label at --pn-accent in index.css.
/** Folder and tag colors: the glyph ink, and the tint of a note (rgb, alpha). */
const LABEL_INKS: Record<ThemeMode, Hex[]> = {
  light: ['#5A6168', '#BA1C1C', '#A43F08', '#8D5200', '#206D2F', '#096878', '#1661A7', '#653AE6', '#B52356'],
  dark: ['#8E969D', '#EA7171', '#F46D24', '#F08C00', '#33AA49', '#0FA4BC', '#469AE7', '#A085F0', '#E36F98'],
};
const TINT_RGB: Hex[] = ['#868E96', '#FF6B6B', '#FF922B', '#FACC15', '#40C057', '#12B886', '#339AF0', '#9775FA', '#F06595'];
const TINT_ALPHA: Record<ThemeMode, number[]> = {
  light: [0.12, 0.12, 0.12, 0.12, 0.12, 0.12, 0.12, 0.12, 0.12],
  dark: [0.1, 0.1, 0.1, 0.08, 0.1, 0.1, 0.1, 0.1, 0.1],
};
export const MODE_COLORS = { STATUS_CHANNELS, PRO_CHANNELS, LABEL_INKS, TINT_RGB, TINT_ALPHA };

// ---------------------------------------------------------------- resolving

const BLACK = '#000000';
const WHITE = '#FFFFFF';
/** A suggestion aims a little above the 4.5:1 floor, so rounding never drops it under. */
const AIM = 4.6;

/** The first color on the way from `start` to `toward` that `ok` accepts. */
function walk(start: Hex, toward: Hex, ok: (c: Hex) => boolean): Hex {
  for (let i = 0; i <= 100; i++) {
    const c = mix(start, toward, i / 100);
    if (ok(c)) return c;
  }
  return toward;
}

interface Grounds {
  surfaces: Hex[];
  selectedRow: Hex;
  accentTints: Hex[];
  tints: Hex[];
}

function grounds(theme: CustomTheme, mode: ThemeMode, list: Hex, well: Hex): Grounds {
  const s = theme.seeds;
  // The writing area is a surface like the others, and a note's tint lies on
  // it as well as on the background.
  const paper = theme.overrides.paper ?? s.background;
  const tinted = paper === s.background ? [s.background] : [s.background, paper];
  // The strongest accent tint that text sits on at rest, on any pane: a
  // selected row, chip or toolbar button. Hover tints go deeper; neither
  // these checks nor the audit of the built-in palettes measure them.
  const level = mode === 'dark' ? 0.2 : 0.15;
  return {
    surfaces: [s.sidebar, list, s.background, well, ...(paper === s.background ? [] : [paper])],
    selectedRow: mix(s.sidebar, s.accent, level),
    accentTints: [s.sidebar, list, ...tinted].map((pane) => mix(pane, s.accent, level)),
    tints: tinted.flatMap((ground) => TINT_RGB.map((c, i) => mix(ground, c, TINT_ALPHA[mode][i]!))),
  };
}

const worstOn = (fg: Hex, bgs: Hex[]) => Math.min(...bgs.map((b) => contrast(fg, b)));

/** Every color a theme paints: its six, the suggestions, and its overrides. */
export function resolveTheme(theme: CustomTheme): ResolvedTheme {
  const s = theme.seeds;
  const o = theme.overrides;
  const mode = themeMode(s);
  const dark = mode === 'dark';
  const away = dark ? WHITE : BLACK;

  const suggestedList = mix(s.sidebar, s.background, 0.5);
  // The well behind a segmented control or a field sits a clear step from the
  // panel it is on, as in the built-in themes (1.09:1 to 1.25:1): darker in
  // a light theme, darker in a dark one when there is room below, lighter on
  // a near-black background.
  const apart = (c: Hex) => contrast(c, s.background) >= 1.15;
  const suggestedWell = dark
    ? contrast(BLACK, s.background) >= 1.15
      ? walk(s.background, BLACK, apart)
      : walk(s.background, s.text, apart)
    : walk(s.background, s.text, apart);
  const list = o.list ?? suggestedList;
  const well = o.well ?? suggestedWell;
  const g = grounds(theme, mode, list, well);
  const passes = (c: Hex) => worstOn(c, g.surfaces) >= AIM;

  // Note text sits on a folder's tint: the soft level in light mode, the full
  // level in dark mode (the prose-pn rule in index.css).
  const suggestedSoft = walk(mix(s.text, s.muted, 0.5), s.text, (c) =>
    passes(c) && contrast(c, g.selectedRow) >= AIM && (dark || worstOn(c, g.tints) >= AIM));
  const suggestedHover = walk(mix(s.accent, s.text, 0.25), s.text, (c) => passes(c) && worstOn(c, g.accentTints) >= AIM);
  const suggestedFill = walk(s.accent, BLACK, (c) => contrast(WHITE, c) >= AIM);
  const fill = o.fill ?? suggestedFill;
  const suggestedFillHover = mix(fill, BLACK, 0.14);
  const status = (k: 'danger' | 'warning' | 'success') => walk(STATUS[mode][k], away, passes);
  // The accent already reads as text; the walk only matters for a code
  // whose accent was set by hand below that.
  const suggestedLabel = walk(s.accent, s.text, (c) => worstOn(c, g.surfaces) >= 3.2);

  const suggested: Record<MoreKey, Hex> = {
    list: suggestedList,
    paper: s.background,
    well: suggestedWell,
    soft: suggestedSoft,
    hover: suggestedHover,
    fill: suggestedFill,
    fillhover: suggestedFillHover,
    danger: status('danger'),
    warning: status('warning'),
    success: status('success'),
    label: suggestedLabel,
  };
  const v = (k: MoreKey) => o[k] ?? suggested[k];
  return {
    mode,
    suggested,
    label: o.label ?? suggestedLabel,
    paper: o.paper ?? s.background,
    colors: {
      'surface-0': s.sidebar,
      'surface-1': list,
      'surface-2': s.background,
      track: well,
      divider: s.border,
      text: s.text,
      'text-soft': v('soft'),
      'text-muted': s.muted,
      accent: s.accent,
      'accent-hover': v('hover'),
      'accent-fill': fill,
      'accent-fill-hover': v('fillhover'),
      danger: v('danger'),
      warning: v('warning'),
      success: v('success'),
    },
  };
}

// ---------------------------------------------------------------- checks

export type CheckId =
  | 'sides' | 'text' | 'soft' | 'muted' | 'accent' | 'hover' | 'accent-tint' | 'selected'
  | 'fill' | 'fill-hover' | 'danger' | 'warning' | 'success' | 'tinted-notes' | 'labels' | 'label' | 'pro';

export interface ThemeCheck {
  id: CheckId;
  /** The contrast measured, or null for a rule that is not a ratio. */
  ratio: number | null;
  min: number;
  pass: boolean;
  /** The value that Fix moves, or null when only the background can fix it. */
  fix: SeedKey | MoreKey | null;
}

/**
 * The contrast every theme must keep: the text levels and the accent as text
 * on every surface, accent text on a tint, a selected row, white on the fill,
 * the status colors, note text on a folder's tint, and the folder and tag
 * colors and the Pro mark as glyphs. Text needs 4.5:1, a glyph 3:1.
 */
export function checkTheme(theme: CustomTheme): ThemeCheck[] {
  const r = resolveTheme(theme);
  const c = r.colors;
  const dark = r.mode === 'dark';
  const g = grounds(theme, r.mode, c['surface-1'], c.track);
  const text = (id: CheckId, fg: Hex, fix: SeedKey | MoreKey, bgs = g.surfaces): ThemeCheck => {
    const ratio = worstOn(fg, bgs);
    return { id, ratio, min: 4.5, pass: ratio >= 4.5, fix };
  };
  const onWhite = (id: CheckId, bg: Hex, fix: MoreKey): ThemeCheck => {
    const ratio = contrast(WHITE, bg);
    return { id, ratio, min: 4.5, pass: ratio >= 4.5, fix };
  };
  const side = (h: Hex) => luminance(h) < luminance(c.text);
  const sameSide = side(theme.seeds.sidebar) === side(theme.seeds.background);

  const body = dark ? c.text : c['text-soft'];
  const noteRatio = worstOn(body, g.tints);
  const datesPass = worstOn(c['text-muted'], g.tints) >= 3;
  const inkRatio = Math.min(...LABEL_INKS[r.mode].map((ink) => worstOn(ink, g.surfaces)));
  const proRatio = worstOn(PRO[r.mode], g.surfaces);
  // The folder and tag ink on every surface, and the active one (the accent)
  // on the selected row it sits on.
  const labelRatio = Math.min(worstOn(r.label, g.surfaces), contrast(c.accent, g.selectedRow));

  return [
    { id: 'sides', ratio: null, min: 0, pass: sameSide, fix: null },
    text('text', c.text, 'text'),
    text('soft', c['text-soft'], 'soft'),
    text('muted', c['text-muted'], 'muted'),
    text('accent', c.accent, 'accent'),
    text('hover', c['accent-hover'], 'hover'),
    text('accent-tint', c['accent-hover'], 'hover', g.accentTints),
    text('selected', c['text-soft'], 'soft', [g.selectedRow]),
    onWhite('fill', c['accent-fill'], 'fill'),
    onWhite('fill-hover', c['accent-fill-hover'], 'fillhover'),
    text('danger', c.danger, 'danger'),
    text('warning', c.warning, 'warning'),
    text('success', c.success, 'success'),
    { id: 'tinted-notes', ratio: noteRatio, min: 4.5, pass: noteRatio >= 4.5 && datesPass, fix: dark ? 'text' : 'soft' },
    { id: 'labels', ratio: inkRatio, min: 3, pass: inkRatio >= 3, fix: null },
    { id: 'label', ratio: labelRatio, min: 3, pass: labelRatio >= 3, fix: 'label' },
    { id: 'pro', ratio: proRatio, min: 3, pass: proRatio >= 3, fix: null },
  ];
}

/** Whether a theme keeps every check, so it can be saved. */
export function themePasses(theme: CustomTheme): boolean {
  return checkTheme(theme).every((ch) => ch.pass);
}

const isSeed = (k: SeedKey | MoreKey): k is SeedKey => (SEED_KEYS as readonly string[]).includes(k);

/** The theme with no credit. */
export function withoutAuthor(theme: CustomTheme): CustomTheme {
  const next = { ...theme };
  delete next.author;
  return next;
}

/** The theme with its logo choice set, or cleared with undefined. A changed
 *  choice is no longer the author's, so the credit goes. */
export function withLogo(theme: CustomTheme, logo: ThemeLogo | undefined): CustomTheme {
  const base = theme.logo === logo ? theme : withoutAuthor(theme);
  const next = { ...base };
  if (logo) next.logo = logo;
  else delete next.logo;
  return next;
}

/** The theme with one value set: a seed, or an override of a suggestion. A
 *  changed color is no longer the author's, so the credit goes. */
export function withValue(theme: CustomTheme, key: SeedKey | MoreKey, value: Hex): CustomTheme {
  const same = (isSeed(key) ? theme.seeds[key] : theme.overrides[key]) === value;
  const base = same ? theme : withoutAuthor(theme);
  return isSeed(key)
    ? { ...base, seeds: { ...theme.seeds, [key]: value } }
    : { ...base, overrides: { ...theme.overrides, [key]: value } };
}

/**
 * Fix: move one value away from the surfaces (toward black in a light theme,
 * toward white in a dark one, toward black for a button fill) in steps of one
 * hundredth, and stop at the first color that passes every check it owns.
 */
export function fixTheme(theme: CustomTheme, key: SeedKey | MoreKey): CustomTheme {
  const r = resolveTheme(theme);
  const keyToken: Record<Exclude<MoreKey, 'label' | 'paper'>, TokenKey> = {
    list: 'surface-1', well: 'track', soft: 'text-soft', hover: 'accent-hover', fill: 'accent-fill',
    fillhover: 'accent-fill-hover', danger: 'danger', warning: 'warning', success: 'success',
  };
  const start = isSeed(key) ? theme.seeds[key] : key === 'label' ? r.label : key === 'paper' ? r.paper : r.colors[keyToken[key]];
  const toward = key === 'fill' || key === 'fillhover' || r.mode === 'light' ? BLACK : WHITE;
  for (let i = 0; i <= 100; i++) {
    const next = withValue(theme, key, mix(start, toward, i / 100));
    if (checkTheme(next).every((ch) => ch.fix !== key || ch.pass)) return next;
  }
  return withValue(theme, key, toward);
}

/**
 * The one line the builder shows for the checks. A failure only a new
 * background can clear wins over every fixable one, because no Fix button
 * clears it and the background has to move first.
 */
export type ContrastSummary =
  | { state: 'pass' }
  | { state: 'one'; check: ThemeCheck }
  | { state: 'many'; count: number }
  | { state: 'background'; check: ThemeCheck };

export function contrastSummary(checks: ThemeCheck[]): ContrastSummary {
  const failing = checks.filter((ch) => !ch.pass);
  if (failing.length === 0) return { state: 'pass' };
  const stuck = failing.find((ch) => ch.fix === null);
  if (stuck) return { state: 'background', check: stuck };
  // Two checks can fail on one value (accent hover as text and on a tint),
  // and one Fix clears both, so the line counts values, not checks.
  const values = new Set(failing.map((ch) => ch.fix));
  if (values.size === 1) return { state: 'one', check: failing[0]! };
  return { state: 'many', count: values.size };
}

/** Fix every check a value can fix. What is left needs a new background. */
export function fixAll(theme: CustomTheme): CustomTheme {
  let next = theme;
  // A fix moves one value; moving the text can move a suggestion with it, so
  // a second pass picks up what the first one shifted.
  for (let pass = 0; pass < 3; pass++) {
    const keys = [...new Set(checkTheme(next).filter((ch) => !ch.pass && ch.fix).map((ch) => ch.fix!))];
    if (keys.length === 0) break;
    for (const key of keys) next = fixTheme(next, key);
  }
  return next;
}

// ---------------------------------------------------------------- suggest from one color

/**
 * A whole theme from its accent and a mode, for a person with no palette in
 * mind: the five other seeds are near-neutral, each tinted a little toward
 * the accent, muted text and the accent move until they read on every
 * surface, every suggestion is taken as is, and Fix all clears what is left.
 * The name stays; the credit goes, because the colors are new.
 */
export function suggestFromAccent(theme: CustomTheme, mode: ThemeMode): CustomTheme {
  const accent = theme.seeds.accent;
  const dark = mode === 'dark';
  const background = dark ? mix('#15161B', accent, 0.06) : mix('#FDFDFE', accent, 0.025);
  const sidebar = dark ? mix(background, BLACK, 0.18) : mix(mix(background, accent, 0.06), BLACK, 0.03);
  const border = dark ? mix(background, WHITE, 0.09) : mix(background, '#15161C', 0.13);
  const text = dark ? mix('#ECEDF1', accent, 0.04) : mix('#15161C', accent, 0.06);
  // The list sits between sidebar and background, and the well one step off
  // the background, so these three cover every surface text lands on.
  const surfaces = [sidebar, background, mix(background, dark ? BLACK : text, dark ? 0.15 : 0.08)];
  const reads = (c: Hex) => worstOn(c, surfaces) >= AIM;
  const seeds: Record<SeedKey, Hex> = {
    background,
    sidebar,
    border,
    text,
    muted: walk(mix(background, text, 0.5), text, reads),
    accent: walk(accent, text, reads),
  };
  return fixAll({ name: theme.name, seeds, overrides: {} });
}
