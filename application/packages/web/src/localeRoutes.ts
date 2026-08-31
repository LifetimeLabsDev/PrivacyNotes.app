// Marketing SEO URL slugs <-> locales. Apex '/' is the smart entry (the app
// when signed in, otherwise marketing). Each locale also has an explicit,
// always-marketing slug (/de, /en, ...) for clean per-language SEO URLs and
// for previewing the site in any language while signed in.

const SLUG_TO_LOCALE: Record<string, string> = {
  en: 'en',
  de: 'de',
  fr: 'fr',
  it: 'it',
  es: 'es',
  nl: 'nl',
  pl: 'pl',
  // Portuguese is two sibling variants, not a default and a derivative.
  // /pt is the European norm (Portugal, Angola, Mozambique and the rest of
  // the Lusophone bloc all follow it); /br is Brazil, which outnumbers them
  // and so answers to the generic `pt` hreflang. See seo.ts for the cluster.
  // A slug is not an ISO 639 code: `br` is Brazil here, not Breton.
  pt: 'pt-PT',
  br: 'pt-BR',
  ja: 'ja',
  ko: 'ko',
  // /tw carries Traditional Chinese, the same way /br carries Brazilian: the
  // slug names the market, not an ISO code. hreflang answers to zh-TW plus the
  // zh-Hant/zh-HK/zh-MO aliases (seo.ts).
  tw: 'zh-TW',
  ca: 'ca',
  cs: 'cs',
  tr: 'tr',
  sv: 'sv',
  ar: 'ar',
};

export const LOCALE_TO_SLUG: Record<string, string> = {
  en: '/en',
  de: '/de',
  fr: '/fr',
  it: '/it',
  es: '/es',
  nl: '/nl',
  pl: '/pl',
  'pt-PT': '/pt',
  'pt-BR': '/br',
  ja: '/ja',
  ko: '/ko',
  'zh-TW': '/tw',
  ca: '/ca',
  cs: '/cs',
  tr: '/tr',
  sv: '/sv',
  ar: '/ar',
};

/** The locale named by the first path segment (/de, /pt, /br), or null at apex. */
export function localeFromPath(pathname: string = location.pathname): string | null {
  const seg = pathname.split('/')[1]?.toLowerCase();
  return seg ? (SLUG_TO_LOCALE[seg] ?? null) : null;
}

// Locales that read right-to-left. Drives the `dir` attribute on statically
// emitted pages (help-page.ts, marketing-shell.ts); the SPA handles its own
// direction via i18n.dir().
export const RTL_LOCALES = ['ar'] as const;

/**
 * The Help hub path for a locale: English lives at the apex /help (the
 * x-default), every other locale under its marketing slug (/de/help, ...).
 * Single source for the homepage footer, the in-app "view on web" link,
 * and the static-page build (help-page.ts), so no link can point at the
 * wrong language's page. The old /faq URLs 301 here via worker.ts. Keep
 * this module import-free: Node-side build code imports it too.
 */
export function helpPath(locale: string): string {
  return locale === 'en' ? '/help' : `${LOCALE_TO_SLUG[locale] ?? ''}/help`;
}
