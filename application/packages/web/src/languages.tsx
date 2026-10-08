import i18n, { activeLocale, preferredLocale, SUPPORTED_LOCALES, ensureLocaleLoaded } from './i18n';

// LANGUAGE_META + Flag moved to languageData.tsx (dependency-free) so the
// static-page build (faq-page.ts) can share them without importing i18n.
// Re-exported here so existing consumers keep their import path.
export { LANGUAGE_META, Flag, sortByNative } from './languageData';

const EXPLICIT_KEY = 'privacynotes.langExplicit';

/** True when the user picked a language rather than following detection. */
export function hasExplicitLanguage(): boolean {
  return localStorage.getItem(EXPLICIT_KEY) === '1';
}

/** The user's explicit choice, or 'system' when following browser detection. */
export function currentLanguageChoice(): string {
  if (localStorage.getItem(EXPLICIT_KEY) !== '1') return 'system';
  return localStorage.getItem('privacynotes.language') || 'system';
}

// Both accessors live in ./i18n, which owns `normalizeLocale`. Re-exported
// here because this is where callers look for anything about language.
export { activeLocale, preferredLocale };

// Spec: ops/docs/archive/rtl-handoff.md (Arabic numerals: Western digits)
const LATIN_DIGITS = '-u-nu-latn';

/**
 * The BCP-47 tag to pass to any Intl/toLocale* API - `activeLocale()` (or an
 * explicit override, for callers that already resolved a locale elsewhere),
 * except an Arabic tag gains `-u-nu-latn` so the UI renders Western 0-9 digits
 * instead of Intl's Arabic-Indic default. That holds for a tag with a region
 * too ("ar-EG", which the date locale builds). This is the one function that
 * should ever feed one of those APIs; `activeLocale()` itself stays the
 * comparison/routing value (URL slugs, `lang` params, "is this the current
 * language" checks) and must not be given Intl's `-u-nu-latn` suffix.
 */
export function intlLocale(locale: string = activeLocale()): string {
  return locale === 'ar' || locale.startsWith('ar-') ? `${locale}${LATIN_DIGITS}` : locale;
}

/**
 * Every locale tag the device states, for the one thing the app language
 * cannot say: the region a person formats dates in. The runtime's own default
 * leads, because a system webview takes it from the region set in the
 * operating system; the browser's preferred languages follow. The tags are
 * raw, so a Linux box can hand over "C" or "en_US". Every list row asks for
 * them, so a runtime without a languages list must not throw here.
 */
export function deviceLocaleTags(): string[] {
  // date-ok: reads the device region and formats nothing
  const tags = [new Intl.DateTimeFormat().resolvedOptions().locale];
  const preferred: readonly string[] | undefined =
    typeof navigator === 'undefined' ? undefined : navigator.languages;
  if (preferred) tags.push(...preferred);
  return tags;
}



/**
 * Apply a language. 'system' clears the override and follows the browser.
 *
 * Catalogs are lazy per locale (see i18n.ts), so the target's strings are
 * fetched BEFORE the switch - swapping first would render a frame of raw
 * keys or English. A failed fetch leaves the current language in place
 * rather than switching to an empty catalog.
 */
export function setLanguage(value: string): void {
  const target = value === 'system' ? navigator.language || 'en' : value;
  if (value === 'system') {
    localStorage.removeItem('privacynotes.language');
    localStorage.removeItem(EXPLICIT_KEY);
  } else {
    localStorage.setItem('privacynotes.language', value);
    localStorage.setItem(EXPLICIT_KEY, '1');
  }
  void ensureLocaleLoaded(target)
    .then(() => i18n.changeLanguage(target))
    .catch(() => {
      /* keep the current language rather than switching to nothing */
    });
}

