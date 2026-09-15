/**
 * Theme system: orthogonal appearance axes.
 *
 * 1. Light / dark - Tailwind `darkMode: 'class'`, toggles `dark` on <html>.
 *    What the user picks is a MODE ('auto' | 'light' | 'dark'); 'auto'
 *    resolves against the OS `prefers-color-scheme` and re-resolves live
 *    when the OS flips, so a phone on a sunrise/sunset schedule follows
 *    along without reopening the app.
 * 2. Color theme - toggles `theme-<name>` on <html>, drives CSS custom
 *    properties defined in index.css (--pn-accent, --pn-warm, etc.).
 * 3. Text size - sets `data-text-size` on <html>, drives --pn-text-scale
 *    in index.css, which the editor's type scale derives from.
 * 4. Content width - sets `data-content-width` on <html>, drives
 *    --pn-content-max, the cap on the editor's reading column.
 * 5. Spell check - paints nothing. A flag the writing surfaces read to
 *    decide whether to hand the engine's own spell checker an off switch.
 * 6. Website icons - paints nothing. Read by every surface that draws a
 *    link or a vault login, and the off switch for the proxy request.
 * 7. Invisible characters - paints nothing. The editor drives the
 *    extension's show/hide commands from it.
 * 8. Line spacing - sets `data-line-spacing` on <html>, drives
 *    --pn-para-gap, the gap between two paragraphs.
 *
 * Axes 1 to 7 persist to localStorage and NONE of them reaches the
 * server: each is a property of the screen in front of you rather than
 * of the account, and a desktop and a phone can reasonably disagree.
 * A sign-out leaves them standing for that same reason. The one thing
 * that clears them is a different account arriving on this install -
 * see `resetAppearance`.
 *
 * Line spacing is the exception and owns no state here. It describes how
 * somebody writes rather than the screen they write on, so it lives on
 * UserSettings, syncs with everything else there, and this module only
 * paints what it is handed.
 */
import { useCallback, useSyncExternalStore } from 'react';

// ------------------------------------------------------------------
// Light / dark axis
// ------------------------------------------------------------------

const STORAGE_KEY = 'privacynotes.theme';

/** The appearance actually painted on <html>. */
export type Theme = 'light' | 'dark';

/** What the user chose. 'auto' defers to the OS. */
export type ThemeMode = Theme | 'auto';

/** Picker order, Auto first (matches the View segmented right below it). */
export const THEME_MODES: readonly ThemeMode[] = ['auto', 'light', 'dark'];

/**
 * The OS preference right now. Deliberately asks for `light` rather than
 * `dark`: a browser that cannot answer (no matchMedia, no preference)
 * then lands on dark, which is what this app has always fallen back to.
 */
export function getSystemTheme(): Theme {
  if (typeof window === 'undefined' || !window.matchMedia) return 'dark';
  return window.matchMedia('(prefers-color-scheme: light)').matches ? 'light' : 'dark';
}

/** Read the stored mode. Anything unrecognised (including nothing at
 *  all, i.e. a fresh install) means follow the system. */
function getStoredThemeMode(): ThemeMode {
  const stored = localStorage.getItem(STORAGE_KEY);
  if (stored === 'light' || stored === 'dark' || stored === 'auto') return stored;
  return 'auto';
}

/** The stored mode resolved to something paintable. */
function getStoredTheme(): Theme {
  const mode = getStoredThemeMode();
  return mode === 'auto' ? getSystemTheme() : mode;
}

/**
 * Browser and OS chrome color: the Android Chrome address bar, the iOS
 * Safari / installed-PWA status bar, the Android task switcher card.
 * Values mirror the two metas in index.html.
 * Spec: ops/docs/color-themes.md (section 1, theme-color)
 */
const THEME_COLOR: Record<Theme, string> = { light: '#F5F5F5', dark: '#171514' };

/**
 * Keep `theme-color` in step with the painted theme.
 *
 * index.html ships two metas gated on `prefers-color-scheme`, which is
 * the right answer before JS boots and while the mode is 'auto', but
 * wrong the moment someone pins Light on a dark OS - the app went light
 * and the address bar stayed charcoal. Once we are running we own the
 * value, so the media-gated pair is dropped and replaced by a single
 * meta we rewrite on every paint.
 *
 * Deliberately not palette-aware: Cream and Slate sit close enough to
 * the default surfaces that a per-theme table would be churn for a strip
 * of browser chrome.
 */
function paintThemeColorMeta(theme: Theme): void {
  const head = document.head;
  if (!head) return;
  head.querySelectorAll('meta[name="theme-color"][media]').forEach((m) => m.remove());
  let meta = head.querySelector<HTMLMetaElement>('meta[name="theme-color"]:not([media])');
  if (!meta) {
    meta = document.createElement('meta');
    meta.name = 'theme-color';
    head.appendChild(meta);
  }
  meta.content = THEME_COLOR[theme];
}

declare global {
  interface Window {
    /** Installed by MainActivity.kt in the Android app; absent everywhere else. */
    __pnBars?: { set: (color: string, dark: boolean) => void };
  }
}

/**
 * Android system-bar strips (#205).
 *
 * The Android app consumes the window insets to fix the soft keyboard, so
 * the webview does not draw under the status and navigation bars - the
 * activity paints those strips itself. It has no way to know what we
 * painted, and guessing from the system uiMode got it wrong twice over:
 * the light/dark MODE can be pinned against the OS, and the color theme
 * on top of it (Cream, Slate, Navy) lands nowhere near either default. A
 * Cream app on a dark phone showed black bars.
 *
 * So push, on every theme change of either axis. `--pn-surface-0` is the
 * app shell's own background (NotesView's `h-dvh` column), which is what
 * sits against both strips, and its default light/dark values are the two
 * colors the activity used to hardcode - this generalizes them rather
 * than replacing them.
 *
 * Unlike the `theme-color` meta above, this one IS palette-aware: a strip
 * physically touching the app's own chrome shows a seam that a browser
 * address bar never does.
 *
 * Inert on every other platform (no bridge, no call).
 */
function paintNativeBars(): void {
  const bars = window.__pnBars;
  if (!bars) return;
  const root = document.documentElement;
  // Palette values are stored as space-separated RGB channels so Tailwind
  // can wrap them in rgb() with an alpha; Android wants #RRGGBB.
  const channels = getComputedStyle(root)
    .getPropertyValue('--pn-surface-0')
    .trim()
    .split(/\s+/)
    .map(Number);
  if (channels.length !== 3 || channels.some((n) => !Number.isFinite(n))) return;
  const hex = channels.map((n) => n.toString(16).padStart(2, '0')).join('');
  bars.set(`#${hex}`, root.classList.contains('dark'));
}

/** Paint a resolved theme on <html>. Does NOT persist anything.
 *
 * The `theme-animating` class is toggled briefly around the class flip
 * so a global CSS rule in index.css can crossfade background/color/
 * border during the ~280ms window and then get out of the way. Skipped
 * on the very first call (initial bootstrap) so the initial paint
 * doesn't flash. */
let hasAppliedOnce = false;
function paintTheme(theme: Theme): void {
  const root = document.documentElement;
  const wantsCrossfade = hasAppliedOnce && typeof window !== 'undefined';
  if (wantsCrossfade) {
    root.classList.add('theme-animating');
  }
  if (theme === 'dark') {
    root.classList.add('dark');
  } else {
    root.classList.remove('dark');
  }
  paintThemeColorMeta(theme);
  paintNativeBars();
  if (wantsCrossfade) {
    window.setTimeout(() => {
      root.classList.remove('theme-animating');
    }, 320);
  }
  hasAppliedOnce = true;
}

/** Persist a mode and paint what it resolves to. */
function applyThemeMode(mode: ThemeMode): Theme {
  localStorage.setItem(STORAGE_KEY, mode);
  const resolved = mode === 'auto' ? getSystemTheme() : mode;
  paintTheme(resolved);
  return resolved;
}

/** Repaint from the stored preference. Views call this on entry and exit
 *  so a stale paint from a previous view never survives a transition.
 *  (This used to release the marketing page's forced-light pin; the pin
 *  was retired when the landing shipped its washi dark palette.) */
export function applyStoredTheme(): Theme {
  const resolved = getStoredTheme();
  paintTheme(resolved);
  return resolved;
}

/**
 * Repaint when the OS flips, but only while the mode is 'auto'.
 * Registered once from initTheme() and never torn down - it has to
 * outlive every view.
 *
 * The color theme is deliberately left alone here. Each palette's CSS
 * block is scoped to one mode (`:root:not(.dark).theme-warm-cream`,
 * `:root.dark.theme-soft-dark`), so a palette belonging to the other
 * mode simply stops applying and the default one shows through. Wiping
 * it on every sunset would quietly destroy a Pro user's choice twice a
 * day; leaving it means Cream comes back at sunrise.
 */
function watchSystemTheme(): void {
  if (typeof window === 'undefined' || !window.matchMedia) return;
  const mql = window.matchMedia('(prefers-color-scheme: light)');
  mql.addEventListener('change', () => {
    if (getStoredThemeMode() !== 'auto') return;
    paintTheme(getSystemTheme());
    emitThemeChange();
  });
}

/** One-shot bootstrap: call from main.tsx before React renders. */
export function initTheme(): Theme {
  const theme = getStoredTheme();
  paintTheme(theme);
  watchSystemTheme();
  initColorTheme();
  applyTextSize(getStoredTextSize());
  applyContentWidth(getStoredContentWidth());
  return theme;
}

// ------------------------------------------------------------------
// Text size axis
// ------------------------------------------------------------------

const TEXT_SIZE_KEY = 'privacynotes.textSize';

/**
 * How big the writing surface renders. Drives `--pn-text-scale` in
 * index.css, which the editor's type scale derives from; nothing else
 * in the app chrome scales (that is a much larger job - most of the
 * chrome is pinned to literal pixel sizes).
 *
 * Device-local on purpose, like every other axis: a phone held at arm's
 * length and a 27" monitor want different answers, so syncing this would
 * mean fixing it on one device and breaking it on another. Same
 * reasoning as the light/dark mode above.
 */
export const TEXT_SIZES = ['sm', 'md', 'lg', 'xl'] as const;
export type TextSize = (typeof TEXT_SIZES)[number];

/** Type guard. */
function isTextSize(v: unknown): v is TextSize {
  return typeof v === 'string' && (TEXT_SIZES as readonly string[]).includes(v);
}

/** Read the stored size. Anything unrecognised means the default. */
function getStoredTextSize(): TextSize {
  const stored = localStorage.getItem(TEXT_SIZE_KEY);
  return isTextSize(stored) ? stored : 'md';
}

/** Currently applied size (mirrors <html>, for the React snapshot). */
let activeTextSize: TextSize = 'md';

/** Apply a text size to <html> and persist it. */
function applyTextSize(size: TextSize): void {
  activeTextSize = size;
  document.documentElement.dataset.textSize = size;
  localStorage.setItem(TEXT_SIZE_KEY, size);
}

// ------------------------------------------------------------------
// Line spacing axis
// ------------------------------------------------------------------

/**
 * The gap between two paragraphs. Drives `--pn-para-gap` in index.css,
 * which the shared `.prose` block reads - the editor, the burn note
 * viewer, the note history modal and the markdown file pane at once.
 *
 * 'compact' is zero, so Enter costs the same line as Shift+Enter. It is
 * also the absent state, which is what a surface with no account behind
 * it paints: a burn page, and any note opened before settings arrive.
 *
 * The one axis in this file the ACCOUNT owns rather than the device.
 * Everything else here is a property of the screen in front of you; this
 * is a property of how somebody writes, and it should follow them from
 * the phone they typed the note on to the laptop they read it on. So the
 * value lives on UserSettings and syncs, this module only paints it, and
 * there is deliberately no localStorage key below.
 * Spec: ops/docs/design-decisions.md (editor paragraph rhythm)
 */
export const LINE_SPACINGS = ['compact', 'normal'] as const;
export type LineSpacing = (typeof LINE_SPACINGS)[number];

/** Type guard, for the settings blob's decode step. */
export function isLineSpacing(v: unknown): v is LineSpacing {
  return typeof v === 'string' && (LINE_SPACINGS as readonly string[]).includes(v);
}

/** Paint a line spacing on <html>. The caller owns the value. */
export function applyLineSpacing(spacing: LineSpacing): void {
  document.documentElement.dataset.lineSpacing = spacing;
}

/**
 * The spacing currently painted. For the two places that need the value
 * without the settings blob in reach: the export stylesheet, which builds a
 * standalone file, and the editor's clipboard serializer. Absent reads as
 * compact, which is also what those two surfaces should produce before any
 * account has been loaded.
 */
export function readLineSpacing(): LineSpacing {
  return document.documentElement.dataset.lineSpacing === 'normal' ? 'normal' : 'compact';
}

// ------------------------------------------------------------------
// Content width axis
// ------------------------------------------------------------------

const CONTENT_WIDTH_KEY = 'privacynotes.contentWidth';

/**
 * How wide the editor's reading column runs. Drives `--pn-content-max`
 * in index.css, which `.pn-content-col` reads - the one place the cap
 * lives, for both the note editor and the markdown file pane.
 *
 * The steps multiply the 56rem default rather than taking a percentage
 * of the pane, so collapsing the notes list never reflows the text.
 * 'full' removes the cap and the column takes the pane whole.
 *
 * Painting it on <html> is what lets zen mode, markdown mode, the trash
 * and read-only notes honour the choice: all four hide the tag row that
 * carries the toggle button, and none of them needs React state to obey
 * a CSS variable. Settings > Appearance is the way back in those modes.
 *
 * Device-local, for the text-size reason: a phone never reaches the cap
 * at all, so syncing this would fix one screen and do nothing for the
 * other.
 * Spec: ops/docs/design-decisions.md (editor content column max-width)
 */
export const CONTENT_WIDTHS = ['default', 'wide', 'full'] as const;
export type ContentWidth = (typeof CONTENT_WIDTHS)[number];

/** Type guard. */
function isContentWidth(v: unknown): v is ContentWidth {
  return typeof v === 'string' && (CONTENT_WIDTHS as readonly string[]).includes(v);
}

/** Read the stored width. Anything unrecognised means the default. */
function getStoredContentWidth(): ContentWidth {
  const stored = localStorage.getItem(CONTENT_WIDTH_KEY);
  return isContentWidth(stored) ? stored : 'default';
}

/** Currently applied width (mirrors <html>, for the React snapshot). */
let activeContentWidth: ContentWidth = 'default';

/** Apply a content width to <html> and persist it. */
function applyContentWidth(width: ContentWidth): void {
  activeContentWidth = width;
  document.documentElement.dataset.contentWidth = width;
  localStorage.setItem(CONTENT_WIDTH_KEY, width);
}

// ------------------------------------------------------------------
// Spell check axis
// ------------------------------------------------------------------

const SPELLCHECK_KEY = 'privacynotes.spellcheck';

/**
 * Whether the writing surfaces let the engine spell-check them. Default on.
 *
 * The app ships no dictionary of its own - every red squiggle comes from
 * the engine the app is rendered in, and that engine picks the dictionary,
 * not us. On Windows the WebView takes it from the system UI language and
 * ignores the document's own language entirely, so someone writing French
 * on an English install gets every word underlined with nothing in the app
 * to change it. This flag is that missing off switch.
 * Spec: ops/docs/design-decisions.md (Spell check is the engine's, not ours)
 *
 * Device-local and NOT synced, for the text-size reason above and one
 * stronger: the dictionary belongs to the machine, not the account. The
 * same notes are usually fine in a browser and wrong in the Windows app,
 * so syncing the fix would break the device that already worked.
 */
function getStoredSpellcheck(): boolean {
  return localStorage.getItem(SPELLCHECK_KEY) !== '0';
}

/** Currently applied value (mirrors localStorage, for the React snapshot). */
let activeSpellcheck: boolean = getStoredSpellcheck();

/** Persist a spell-check choice. Nothing is painted on <html>: the writing
 *  surfaces read the value and emit their own attribute when it is off. */
function applySpellcheck(on: boolean): void {
  activeSpellcheck = on;
  localStorage.setItem(SPELLCHECK_KEY, on ? '1' : '0');
}

// ------------------------------------------------------------------
// Website icons axis
// ------------------------------------------------------------------

const FAVICONS_KEY = 'privacynotes.favicons';

/**
 * Whether links and vault logins show the site's own icon. Default ON.
 *
 * Device-local, for the same reason as the axes above: it is about how
 * someone is reading right now. It is also the only off
 * switch for the one thing the icons cost - a request per new domain to our
 * proxy - so it has to work on the device making the requests.
 *
 * Every surface reads it through `getFavicons()` rather than the hook, so
 * the non-React callers (markdownRender for export, print and burn pages,
 * the editor's decoration plugin) see the same value.
 * Spec: ops/docs/design-decisions.md (Website icons toggle)
 */
function getStoredFavicons(): boolean {
  return localStorage.getItem(FAVICONS_KEY) !== '0';
}

/** Currently applied value (mirrors localStorage, for the React snapshot). */
let activeFavicons: boolean = getStoredFavicons();

/** Read the current choice from anywhere, React or not. */
export function getFavicons(): boolean {
  return activeFavicons;
}

/** Persist a website-icons choice. Nothing is painted on <html>: each
 *  surface reads the value and renders its own placeholder when it is off. */
function applyFavicons(on: boolean): void {
  activeFavicons = on;
  localStorage.setItem(FAVICONS_KEY, on ? '1' : '0');
}

// ------------------------------------------------------------------
// Invisible characters axis
// ------------------------------------------------------------------

const INVISIBLES_KEY = 'privacynotes.invisibles';

/**
 * Whether the editor paints pilcrows, space dots and line-break arrows.
 * Default OFF - it is a proofreading aid, not a writing default.
 *
 * Device-local, for the same reason as spell check and text size above:
 * it is a property of how someone is reading right now, not of the
 * account. Someone who turns it on to hunt a stray double space on the
 * desktop does not want every phone session showing dots.
 *
 * Purely decorative - the extension paints ProseMirror decorations and never
 * touches the document, so nothing here can reach stored markdown.
 * Spec: ops/docs/design-decisions.md (Invisible characters toggle)
 */
function getStoredInvisibles(): boolean {
  return localStorage.getItem(INVISIBLES_KEY) === '1';
}

/** Currently applied value (mirrors localStorage, for the React snapshot). */
let activeInvisibles: boolean = getStoredInvisibles();

/** Persist an invisible-characters choice. Nothing is painted on <html>: the
 *  editor reads the value and drives the extension command from it. */
function applyInvisibles(on: boolean): void {
  activeInvisibles = on;
  localStorage.setItem(INVISIBLES_KEY, on ? '1' : '0');
}

// ------------------------------------------------------------------
// Color theme axis
// ------------------------------------------------------------------

const COLOR_THEME_KEY = 'privacynotes.colorTheme';

/**
 * Available color themes. Grouped by mode (light/dark).
 *
 * 'default' uses the built-in palette for the active mode and needs
 * no extra class on <html>. Named themes add `theme-<name>` which
 * activates CSS custom property overrides in index.css.
 *
 * The list is intentionally kept here (not in a config file) so
 * theme.ts remains the single source of truth for both axes.
 */
const COLOR_THEMES = [
  'default',
  'warm-cream',
  'slate',
  'soft-dark',
  'navy-depths',
] as const;
export type ColorTheme = (typeof COLOR_THEMES)[number];

/** Display names for the picker UI. */
export const THEME_DISPLAY_NAME: Record<ColorTheme, string> = {
  'default': 'Default',
  'warm-cream': 'Cream',
  'slate': 'Slate',
  'soft-dark': 'Soft',
  'navy-depths': 'Navy',
};

/** Themes available for a given mode (for the picker grid). */
export const LIGHT_THEMES: ColorTheme[] = ['default', 'warm-cream', 'slate'];
export const DARK_THEMES: ColorTheme[] = ['default', 'soft-dark', 'navy-depths'];

/** Themes available on the free tier (everything else requires Pro). */
export const FREE_THEMES: ReadonlySet<ColorTheme> = new Set(['default']);

/** Type guard. */
export function isColorTheme(v: unknown): v is ColorTheme {
  return typeof v === 'string' && (COLOR_THEMES as readonly string[]).includes(v);
}

/** Read stored color theme. */
export function getStoredColorTheme(): ColorTheme {
  const stored = localStorage.getItem(COLOR_THEME_KEY);
  if (isColorTheme(stored)) return stored;
  // Legacy migration: cool-white renamed to slate in v0.132.10.
  if (stored === 'cool-white') return 'slate';
  return 'default';
}

/** Currently applied color theme (may differ from localStorage during preview). */
let activeColorTheme: ColorTheme = getStoredColorTheme();

/** Apply color theme class visually without persisting to localStorage.
 *  Used for live previews that may be reverted. */
export function previewColorTheme(ct: ColorTheme): void {
  activeColorTheme = ct;
  const root = document.documentElement;
  const wantsCrossfade = hasAppliedOnce && typeof window !== 'undefined';
  if (wantsCrossfade) root.classList.add('theme-animating');

  const toRemove = [...root.classList].filter(
    (c) => c.startsWith('theme-') && c !== 'theme-animating'
  );
  toRemove.forEach((c) => root.classList.remove(c));
  if (ct !== 'default') root.classList.add(`theme-${ct}`);
  paintNativeBars();

  if (wantsCrossfade) {
    window.setTimeout(() => root.classList.remove('theme-animating'), 320);
  }
}

/** Apply color theme class to <html> and persist. */
function applyColorTheme(ct: ColorTheme): void {
  activeColorTheme = ct;
  const root = document.documentElement;
  const wantsCrossfade = hasAppliedOnce && typeof window !== 'undefined';
  if (wantsCrossfade) {
    root.classList.add('theme-animating');
  }

  // Remove any existing theme-* class (snapshot to array first -
  // mutating classList during forEach skips entries in some engines).
  const toRemove = [...root.classList].filter(
    (c) => c.startsWith('theme-') && c !== 'theme-animating'
  );
  toRemove.forEach((c) => root.classList.remove(c));

  // 'default' needs no class - CSS vars are defined on bare :root
  if (ct !== 'default') {
    root.classList.add(`theme-${ct}`);
  }

  localStorage.setItem(COLOR_THEME_KEY, ct);
  paintNativeBars();

  if (wantsCrossfade) {
    window.setTimeout(() => {
      root.classList.remove('theme-animating');
    }, 320);
  }
}

/** Bootstrap color theme - called from initTheme(). */
function initColorTheme(): void {
  applyColorTheme(getStoredColorTheme());
}

// ------------------------------------------------------------------
// Cross-axis reset
// ------------------------------------------------------------------

/**
 * Put every axis back to its default and repaint.
 *
 * Called from one place only: the account-switch wipe in auth.tsx, when
 * a DIFFERENT account signs in on this install. A plain sign-out leaves
 * the axes alone on purpose, because they describe the screen in front
 * of you and somebody signing back into their own account wants their
 * own setup back. A new owner is the other case - the axes otherwise
 * carried the previous person's taste into a fresh account on a shared
 * machine, and a Pro palette with it, since nothing checks the stored
 * theme against the new account's tier at sign-in.
 *
 * It repaints instead of only dropping the keys, because an account
 * switch never reloads the page: a cleared key alone would leave <html>
 * wearing the old palette until the next boot.
 *
 * Best effort. It runs inside the wipe that gates authentication, so a
 * storage that refuses to write must not take the sign-in down with it.
 */
export function resetAppearance(): void {
  try {
    applyThemeMode('auto');
    applyColorTheme('default');
    applyTextSize('md');
    applyContentWidth('default');
    applySpellcheck(true);
    applyFavicons(true);
    applyInvisibles(false);
  } catch { /* ignore */ }
  emitThemeChange();
}

// ------------------------------------------------------------------
// React hook (shared via useSyncExternalStore)
// ------------------------------------------------------------------

/**
 * Subscribers notified whenever either axis changes. This is the
 * single source of truth - every useTheme() call shares it, so the
 * AppearanceSheet and the bottom-bar toggle can never desync.
 */
const themeListeners = new Set<() => void>();
function subscribeTheme(cb: () => void) {
  themeListeners.add(cb);
  return () => { themeListeners.delete(cb); };
}
function emitThemeChange() {
  themeListeners.forEach((cb) => cb());
}

/** Snapshot functions for useSyncExternalStore. */
function getThemeSnapshot(): Theme { return getStoredTheme(); }
function getThemeModeSnapshot(): ThemeMode { return getStoredThemeMode(); }
function getColorThemeSnapshot(): ColorTheme { return activeColorTheme; }
function getTextSizeSnapshot(): TextSize { return activeTextSize; }
function getContentWidthSnapshot(): ContentWidth { return activeContentWidth; }
function getSpellcheckSnapshot(): boolean { return activeSpellcheck; }
function getInvisiblesSnapshot(): boolean { return activeInvisibles; }
function getFaviconsSnapshot(): boolean { return activeFavicons; }

/**
 * React hook that exposes both axes and controls for each.
 *
 * All instances share state via useSyncExternalStore - changing the
 * theme from any component (AppearanceSheet, bottom toggle, etc.)
 * immediately updates every other consumer.
 */
export function useTheme() {
  const theme = useSyncExternalStore(subscribeTheme, getThemeSnapshot);
  const themeMode = useSyncExternalStore(subscribeTheme, getThemeModeSnapshot);
  const colorTheme = useSyncExternalStore(subscribeTheme, getColorThemeSnapshot);
  const textSize = useSyncExternalStore(subscribeTheme, getTextSizeSnapshot);
  const contentWidth = useSyncExternalStore(subscribeTheme, getContentWidthSnapshot);
  const spellcheck = useSyncExternalStore(subscribeTheme, getSpellcheckSnapshot);
  const invisibles = useSyncExternalStore(subscribeTheme, getInvisiblesSnapshot);
  const favicons = useSyncExternalStore(subscribeTheme, getFaviconsSnapshot);

  /** Pin an explicit light/dark choice, replacing 'auto' if it was set. */
  const setTheme = useCallback((next: Theme) => {
    applyThemeMode(next);
    emitThemeChange();
  }, []);

  const setThemeMode = useCallback((next: ThemeMode) => {
    applyThemeMode(next);
    emitThemeChange();
  }, []);

  const setColorTheme = useCallback((next: ColorTheme) => {
    applyColorTheme(next);
    emitThemeChange();
  }, []);

  const setTextSize = useCallback((next: TextSize) => {
    applyTextSize(next);
    emitThemeChange();
  }, []);

  const setContentWidth = useCallback((next: ContentWidth) => {
    applyContentWidth(next);
    emitThemeChange();
  }, []);

  /** Step to the next width and wrap. The editor's toggle is one button
   *  with no room for three, so it cycles; the tooltip names the step it
   *  will move to, and Appearance shows the whole ladder. */
  const cycleContentWidth = useCallback(() => {
    const i = CONTENT_WIDTHS.indexOf(activeContentWidth);
    applyContentWidth(CONTENT_WIDTHS[(i + 1) % CONTENT_WIDTHS.length] ?? 'default');
    emitThemeChange();
  }, []);

  const setSpellcheck = useCallback((next: boolean) => {
    applySpellcheck(next);
    emitThemeChange();
  }, []);

  const setInvisibles = useCallback((next: boolean) => {
    applyInvisibles(next);
    emitThemeChange();
  }, []);

  const setFavicons = useCallback((next: boolean) => {
    applyFavicons(next);
    emitThemeChange();
  }, []);

  /** Apply a color theme visually without persisting. Reverts on reload. */
  const previewColor = useCallback((next: ColorTheme) => {
    previewColorTheme(next);
    emitThemeChange();
  }, []);

  /** Flip to the opposite of what is on screen and pin it. Someone on
   *  'auto' who reaches for the footer toggle is asking for an explicit
   *  choice right now; Auto is one click away in the Appearance pane. */
  const toggle = useCallback(() => {
    applyThemeMode(getStoredTheme() === 'dark' ? 'light' : 'dark');
    emitThemeChange();
  }, []);

  return { theme, themeMode, toggle, setTheme, setThemeMode, colorTheme, setColorTheme, previewColor, textSize, setTextSize, contentWidth, setContentWidth, cycleContentWidth, spellcheck, setSpellcheck, invisibles, setInvisibles, favicons, setFavicons };
}
