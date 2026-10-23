// Shared light/dark theming for the static pre-rendered pages (/help,
// /changelog, and any future static page). Reuse all three exports in
// every new static page so theming behaves identically everywhere.
//
// Behavior: pages follow the system color scheme by default. The toggle
// button stores an explicit override in localStorage under the SAME key
// the app uses ('privacynotes.theme', see src/theme.ts), so a choice
// made on /help carries into the app and vice versa.
//
// The deployed CSP blocks inline scripts but allows script-src 'self',
// so the logic lives in /public/theme-toggle.js, referenced from <head>.

/** Script tag for <head>. Loads synchronously (tiny) to avoid a theme flash. */
export const THEME_SCRIPT_TAG = '<script src="/theme-toggle.js"></script>';

/**
 * The light ground of every marketing page: the homepage's washi cream
 * (`--wl-*` in src/LandingPage.tsx), mapped onto the static pages' neutral
 * tokens. Pages put it first in their light vars and add only their own
 * semantic colours after it. --faint is a warm grey at the old cool grey's
 * contrast; --imp-bg is the homepage's blue tint. --footer is the footer
 * slab, the homepage's `--wl-footer`.
 */
export const WASHI_LIGHT =
  '--bg:#F7F1E1;--card:#FCF8EC;--fg:#1C1917;--muted:#6A6152;--faint:#857C68;--line:#E0D7BD;--chip:#E6DCBF;--rail:#ECE3C9;--imp-bg:#E8EAF2;--footer:#161210';

/**
 * The dark twin: the homepage's warm sumi. --faint and --imp-bg keep the
 * contrast the cool palette had (3.88:1 on the ground; the accent at 4.72:1
 * on the blue tint), which is why the tint is a step darker than the
 * homepage's `--wl-tint-blue`.
 */
export const WASHI_DARK =
  '--bg:#171310;--card:#201B15;--fg:#EDE7DB;--muted:#A69E8F;--faint:#7A7262;--line:#352D20;--chip:#3A3226;--rail:#241E15;--imp-bg:#1D2234;--footer:#1F1A14';

/**
 * CSS variable blocks for both themes. Dark applies when the user
 * explicitly chose dark (data-theme="dark") OR the system prefers dark
 * and the user has not explicitly chosen light.
 */
export function themeVarsCss(lightVars: string, darkVars: string): string {
  return `:root{${lightVars}}
:root[data-theme=dark]{${darkVars}}
@media(prefers-color-scheme:dark){:root:not([data-theme=light]){${darkVars}}}`;
}

/** Styles for the toggle button and its sun/moon icon swap. */
export const THEME_TOGGLE_CSS = `#theme-toggle{cursor:pointer;background:none;font:inherit;color:var(--fg)}
#theme-toggle .i-sun{display:none}
#theme-toggle .i-moon{display:inline}
:root[data-theme=dark] #theme-toggle .i-sun{display:inline}
:root[data-theme=dark] #theme-toggle .i-moon{display:none}
@media(prefers-color-scheme:dark){
:root:not([data-theme=light]) #theme-toggle .i-sun{display:inline}
:root:not([data-theme=light]) #theme-toggle .i-moon{display:none}
}`;

/** Toggle button markup. Place inside the page's .actions row. */
export const THEME_TOGGLE_BUTTON = `<button class="btn btn-ghost" id="theme-toggle" type="button" aria-label="Toggle dark mode"><svg class="i-moon" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><path d="M21 12.79A9 9 0 1 1 11.21 3 7 7 0 0 0 21 12.79z"/></svg><svg class="i-sun" width="15" height="15" viewBox="0 0 24 24" fill="none" stroke="currentColor" stroke-width="2" stroke-linecap="round" stroke-linejoin="round" aria-hidden="true"><circle cx="12" cy="12" r="4"/><path d="M12 2v2M12 20v2M4.93 4.93l1.41 1.41M17.66 17.66l1.41 1.41M2 12h2M20 12h2M4.93 19.07l1.41-1.41M17.66 6.34l1.41-1.41"/></svg></button>`;
