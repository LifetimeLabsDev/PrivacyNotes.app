/**
 * The custom color themes a person made, kept in the encrypted settings blob
 * as `customThemes`: one register per theme id, whose value is the theme's
 * canonical code (themeCode.ts) and null once the theme is deleted. The
 * whole theme is one value, so a merge can never mix the colors of two
 * versions into a palette nobody saved; the later save wins (registers.ts).
 *
 * A value is a string here and nothing more. Whoever paints or shows a theme
 * reads it through `parseThemeCode`, which refuses anything that is not
 * exactly a code, so an entry a later version writes survives the merge and
 * is never painted by this one.
 *
 * Which theme a device shows stays on the device (theme.ts); this list is
 * only the themes on offer.
 *
 * Spec: ops/docs/color-themes.md (section 6)
 */
import {
  mergeRegisterMaps,
  registerMapsEqual,
  stampAfter,
  validateRegisterMap,
  type RegisterMap,
} from './registers';

export type CustomThemes = RegisterMap;

/** The size of one register value: the longest code themeCode.ts reads. */
const CODE_MAX = 512;
const ID_PATTERN = /^[a-z0-9]{12}$/;
const isCustomThemeId = (id: string) => ID_PATTERN.test(id);

/** Sanitize a raw map from a settings blob. */
export function validateCustomThemes(raw: unknown, now = Date.now()): CustomThemes {
  return validateRegisterMap(raw, isCustomThemeId, CODE_MAX, now);
}

export function mergeCustomThemes(local: CustomThemes, remote: CustomThemes, now = Date.now()): CustomThemes {
  return mergeRegisterMaps(local, remote, now);
}

export const customThemesEqual = registerMapsEqual;

/** A fresh theme id: twelve lower-case letters and digits. */
export function newCustomThemeId(): string {
  const alphabet = 'abcdefghijklmnopqrstuvwxyz0123456789';
  const bytes = crypto.getRandomValues(new Uint8Array(12));
  return [...bytes].map((b) => alphabet[b % alphabet.length]).join('');
}

/** The most themes of your own a person keeps, so the list stays tidy and
 *  the settings blob stays small. Deleted themes do not count. */
export const CUSTOM_THEME_MAX = 50;

/** Whether a save under this id fits: an edit always does, a new theme only
 *  while there is room. */
export function canSaveCustomTheme(themes: CustomThemes, id: string): boolean {
  if (typeof themes[id]?.v === 'string') return true;
  return liveCustomThemes(themes).length < CUSTOM_THEME_MAX;
}

/** Save a theme's code under its id. A new theme past the limit is not kept. */
export function saveCustomTheme(themes: CustomThemes, id: string, code: string): CustomThemes {
  if (!isCustomThemeId(id) || code.length > CODE_MAX || !canSaveCustomTheme(themes, id)) return themes;
  const prev = themes[id];
  if (prev?.v === code) return themes;
  return { ...themes, [id]: { v: code, at: stampAfter(prev?.at) } };
}

/** Delete a theme. The null travels, so no other device brings it back until
 *  registers.ts drops the null at the end of the tombstone window. */
export function deleteCustomTheme(themes: CustomThemes, id: string): CustomThemes {
  const prev = themes[id];
  if (!prev || prev.v === null) return themes;
  return { ...themes, [id]: { v: null, at: stampAfter(prev.at) } };
}

/** The themes that are not deleted, as id and code. */
export function liveCustomThemes(themes: CustomThemes): { id: string; code: string }[] {
  return Object.entries(themes)
    .filter((e): e is [string, { v: string; at: string }] => typeof e[1].v === 'string')
    .map(([id, reg]) => ({ id, code: reg.v }));
}
