// i18next initialization. English is the source of truth and is always
// bundled as the fallback. Target-locale catalogs are added under
// locales/<lng>/ as they land from the translation pipeline;
// SUPPORTED_LOCALES below is the only list of which ones exist (it used to be
// duplicated here as prose and went stale twice).
//
// Namespaces are auto-discovered from locales/<lng>/*.json via import.meta.glob,
// so adding an area is just dropping a JSON file - no edit to this file and no
// shared registry for parallel work to collide on. Components call
// useTranslation('<namespace>') then t('key').
//
// BUILD_ONLY_NAMESPACES is the one exception: catalogs that exist purely to
// feed the static /help site. help-page.ts reads those JSON files off disk
// itself at build time, so shipping them to the browser too is dead weight -
// faq is the single biggest catalog we have. Keep them out of both globs.
//
// Spec: ops/docs/i18n-spec.md, ops/docs/i18n-extraction-guide.md,
// ops/docs/bundle-size.md (build-only catalogs)
import i18n from 'i18next';
import { initReactI18next } from 'react-i18next';
import LanguageDetector from 'i18next-browser-languagedetector';
import { localeFromPath } from './localeRoutes';

export const SUPPORTED_LOCALES = [
  'en',
  'de',
  'fr',
  'it',
  'es',
  'nl',
  'pl',
  'pt-PT',
  'pt-BR',
  'ja',
  'ko',
  'zh-TW',
  'ca',
  'cs',
  'tr',
  'sv',
  'ar',
] as const;
export type Locale = (typeof SUPPORTED_LOCALES)[number];

// English is EAGER; every other locale is LAZY.
//
// Every catalog used to be bundled eagerly, which put ~2.6 MB of JSON
// (every locale x 16 namespaces) into the entry chunk - about 93% of it -
// and every visitor downloaded all of it before the homepage could paint,
// to use exactly one locale. English stays eager because it is the
// guaranteed fallback for every other locale and what most visitors need
// anyway; the rest is fetched per-locale, on demand.
// Path shape: ./locales/<lng>/<namespace>.json
//
// `faq` and `guides` are build-only (see the header): help-page.ts renders
// them into the static /help pages and no component calls
// useTranslation('faq') or ('guides') any more. They are also the two
// largest catalogs, so excluding them takes ~64 KB off the eager English
// load and drops fourteen lazy chunks entirely.
// Spec: ops/docs/bundle-size.md (build-only catalogs)
const enModules = import.meta.glob<{ default: Record<string, unknown> }>(
  ['./locales/en/*.json', '!./locales/en/faq.json', '!./locales/en/guides.json'],
  { eager: true },
);
const localeModules = import.meta.glob<{ default: Record<string, unknown> }>([
  './locales/*/*.json',
  '!./locales/en/*.json',
  '!./locales/*/faq.json',
  '!./locales/*/guides.json',
]);

type Catalogs = Record<string, Record<string, unknown>>;

const enResources: Catalogs = {};
for (const path in enModules) {
  const ns = path.match(/\/([^/]+)\.json$/)?.[1];
  const mod = enModules[path];
  if (ns && mod) enResources[ns] = mod.default;
}

/**
 * Map any browser or stored tag onto a locale we actually ship. Mirrors the
 * `fallbackLng` table below, so the catalog we preload is the one i18next
 * will resolve to.
 */
export function normalizeLocale(tag: string | null | undefined): Locale {
  const lower = (tag || '').trim().toLowerCase();
  if (!lower) return 'en';
  const exact = SUPPORTED_LOCALES.find((l) => l.toLowerCase() === lower);
  if (exact) return exact;
  // We ship pt-PT and pt-BR (both matched above); every other Portuguese
  // region follows the European norm.
  if (lower === 'pt' || lower.startsWith('pt-')) return 'pt-PT';
  // Traditional Chinese only. Hong Kong, Macau and bare zh-Hant read it;
  // bare `zh` and `zh-CN` mean Simplified, where English is the better
  // answer than Traditional. Mirrors seo.ts.
  if (lower.startsWith('zh-hant') || lower === 'zh-hk' || lower === 'zh-mo') return 'zh-TW';
  if (lower.startsWith('zh')) return 'en';
  // Region-stripped match, but only against the bare locales (de-AT -> de).
  const two = lower.slice(0, 2);
  return SUPPORTED_LOCALES.find((l) => !l.includes('-') && l === two) ?? 'en';
}

/** Detection precedence, mirroring the `lng` + `detection.order` config below. */
function resolveInitialLocale(): Locale {
  const fromPath = localeFromPath();
  if (fromPath) return normalizeLocale(fromPath);
  try {
    const stored = localStorage.getItem('privacynotes.language');
    if (stored) return normalizeLocale(stored);
  } catch {
    /* storage unavailable - fall through to the browser preference */
  }
  return normalizeLocale(navigator.language);
}

const loadedLocales = new Set<string>(['en']);

/** Fetch every namespace catalog for one locale. */
async function catalogsFor(lng: string): Promise<Catalogs> {
  const prefix = `./locales/${lng}/`;
  const out: Catalogs = {};
  await Promise.all(
    Object.entries(localeModules)
      .filter(([p]) => p.startsWith(prefix))
      .map(async ([p, load]) => {
        const ns = p.match(/\/([^/]+)\.json$/)?.[1];
        if (ns) out[ns] = (await load()).default;
      }),
  );
  return out;
}

// i18next initializes with English only; the boot locale (if any) is added
// by `i18nReady` below, which main.tsx waits on before the first render, so
// a non-English visitor never sees an untranslated frame.
const resources: Record<string, Catalogs> = { en: enResources };
const namespaces = Object.keys(enResources);

void i18n
  .use(LanguageDetector)
  .use(initReactI18next)
  .init({
    resources,
    // Portuguese is the one language with no bare catalog: we ship pt-PT and
    // pt-BR, not pt. i18next strips the region before falling back, so without
    // this map every Lusophone region except those two (pt-AO, pt-MZ, pt-CV,
    // pt-TL, pt-MO, and a bare `pt`) lands on English. They all follow the
    // European norm, so `pt` resolves there. de-AT still falls to de by itself
    // because a bare `de` catalog exists; Portuguese has no such catalog.
    // Matches the generic-`pt` hreflang alias in seo.ts.
    //
    // Chinese is the same shape: we ship Traditional (zh-TW) only. Hong Kong and
    // Macau read Traditional, and a bare `zh-Hant` should too, so map all three
    // onto zh-TW. Bare `zh` and `zh-CN` are left to fall through to English on
    // purpose: they overwhelmingly mean Simplified, and serving Traditional to a
    // Simplified reader is worse than serving English. Mirrors seo.ts.
    //
    // Arabic needs no entry here: we ship a bare `ar` catalog, so i18next's
    // built-in region-stripping already resolves ar-SA/ar-AE/ar-EG to `ar`
    // on its own, the same mechanism that resolves de-AT to de.
    fallbackLng: {
      pt: ['pt-PT'],
      'zh-Hant': ['zh-TW'],
      'zh-HK': ['zh-TW'],
      'zh-MO': ['zh-TW'],
      default: ['en'],
    },
    // A locale URL slug (/de, /pt, /br, ...) wins; apex falls to detection below.
    lng: localeFromPath() ?? undefined,
    // No supportedLngs filter: i18next resolves by what is loaded (pt-BR matches
    // pt-BR; de-AT falls to de via load:'all'; anything unknown falls back to en).
    // A supportedLngs filter rejected the region code pt-BR and dropped Brazilian
    // users to English. Since v0.263.2 only English plus the boot locale are
    // loaded at init - `normalizeLocale` above mirrors this table so the catalog
    // we fetch is the one i18next would have resolved to.
    ns: namespaces.length ? namespaces : ['common'],
    defaultNS: 'common',
    interpolation: { escapeValue: false }, // React already escapes
    returnNull: false,
    detection: {
      order: ['localStorage', 'navigator'],
      lookupLocalStorage: 'privacynotes.language',
      caches: ['localStorage'],
    },
  });

// Keep the document language and direction in sync (dir future-proofs RTL).
i18n.on('languageChanged', (lng) => {
  document.documentElement.lang = lng;
  document.documentElement.dir = i18n.dir(lng);
});

/**
 * Load a locale's catalogs into i18next if they aren't already there. Callers
 * must await this BEFORE `changeLanguage`, or the UI renders one frame of
 * untranslated English. `setLanguage` in languages.tsx does exactly that.
 * No-op for English (eager) and for locales already fetched.
 */
export async function ensureLocaleLoaded(tag: string): Promise<void> {
  const lng = normalizeLocale(tag);
  if (loadedLocales.has(lng)) return;
  const catalogs = await catalogsFor(lng);
  for (const [ns, bundle] of Object.entries(catalogs)) {
    i18n.addResourceBundle(lng, ns, bundle, true, true);
  }
  loadedLocales.add(lng);
}

/**
 * Resolves once the boot locale is loaded and applied. main.tsx gates the
 * first render on this, so a non-English visitor never sees an English frame
 * before their catalog lands. Never rejects: if the fetch fails (offline, CDN
 * hiccup) we boot in English, which is a complete catalog and the fallback for
 * every string anyway.
 */
export const i18nReady: Promise<void> = (async () => {
  const target = resolveInitialLocale();
  if (target === 'en') return;
  try {
    await ensureLocaleLoaded(target);
    await i18n.changeLanguage(target);
  } catch {
    /* stay on English */
  }
})();

export default i18n;
