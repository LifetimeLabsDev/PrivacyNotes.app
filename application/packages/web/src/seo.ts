import { localeFromPath } from './localeRoutes';
import { activeLocale } from './languages';
import { HREFLANG, META, ORIGIN, hreflangPairs, marketingPath, ogLocale } from './marketingMeta';

// Per-locale marketing SEO tags applied at runtime, mirroring the tags
// marketing-shell.ts bakes into each pre-rendered locale shell at build time.
// Both read the same table (marketingMeta.ts) so they cannot drift. This pass
// still matters after the shells landed: it retags the head when a signed-in
// reader switches language client-side, without a navigation.

function upsertMeta(attr: 'name' | 'property', key: string, content: string) {
  let el = document.head.querySelector<HTMLMetaElement>(`meta[${attr}="${key}"]`);
  if (!el) {
    el = document.createElement('meta');
    el.setAttribute(attr, key);
    document.head.appendChild(el);
  }
  el.setAttribute('content', content);
}

function upsertCanonical(href: string) {
  let el = document.head.querySelector<HTMLLinkElement>('link[rel="canonical"]');
  if (!el) {
    el = document.createElement('link');
    el.setAttribute('rel', 'canonical');
    document.head.appendChild(el);
  }
  el.setAttribute('href', href);
}

function setHreflang() {
  document.head.querySelectorAll('link[rel="alternate"][hreflang]').forEach((n) => n.remove());
  for (const { hreflang, path } of hreflangPairs()) {
    const l = document.createElement('link');
    l.setAttribute('rel', 'alternate');
    l.setAttribute('hreflang', hreflang);
    l.setAttribute('href', ORIGIN + path);
    document.head.appendChild(l);
  }
}

/**
 * Set per-locale marketing SEO tags (title, description, og/twitter, canonical,
 * hreflang cluster, html lang). Safe to call repeatedly. Canonical self-refers
 * to the current URL's locale slug; apex '/' is x-default.
 */
export function applyMarketingSeo() {
  const urlLocale = localeFromPath();
  const locale = urlLocale || activeLocale();
  const m = META[locale] || META.en || { title: 'PrivacyNotes', description: '' };
  document.title = m.title;
  upsertMeta('name', 'description', m.description);
  upsertMeta('property', 'og:title', m.title);
  upsertMeta('property', 'og:description', m.description);
  upsertMeta('name', 'twitter:title', m.title);
  upsertMeta('name', 'twitter:description', m.description);
  const path = urlLocale ? marketingPath(urlLocale) : '/';
  upsertMeta('property', 'og:url', ORIGIN + path);
  upsertMeta('property', 'og:locale', ogLocale(locale));
  document.documentElement.lang = HREFLANG[locale] || 'en';
  upsertCanonical(ORIGIN + path);
  setHreflang();
}
