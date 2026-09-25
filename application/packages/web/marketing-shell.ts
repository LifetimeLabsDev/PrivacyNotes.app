// Pre-rendered marketing shells, one per locale.
//
// The homepage is a SPA: /de, /fr, /ja and the rest were all served the same
// dist/index.html, whose head is English, and seo.ts retagged it after the
// bundle booted. Anything that does not execute JavaScript therefore saw
// English for every locale, with no canonical and no hreflang - that is every
// social scraper (Slack, X, Facebook, LinkedIn, WhatsApp, Signal) and most AI
// crawlers (GPTBot, PerplexityBot and the rest). One URL per locale, all of
// them identical English text with nothing declaring which one is canonical,
// is also the textbook duplicate-content shape.
//
// So each locale gets its own pre-rendered shell: same bundle, same body, a
// head that is correct on arrival. seo.ts still runs and still matters - it
// retags when a signed-in reader switches language without navigating - but it
// is no longer the only thing standing between a crawler and the right tags.
//
// Copy comes from src/marketingMeta.ts, which seo.ts also reads, so the two
// cannot drift. Nothing here invents a string.
// Spec: ops/docs/design-decisions.md (per-locale marketing shells)

import type { Plugin } from 'vite';
import fs from 'node:fs';
import path from 'node:path';
import { LOCALE_TO_SLUG, RTL_LOCALES } from './src/localeRoutes.ts';
import { META, ORIGIN, hreflangPairs, marketingPath, ogLocale, HREFLANG } from './src/marketingMeta.ts';
import { PRO_PRICE, EARLY_PRICE } from './src/pricing.ts';

const OG_IMAGE = `${ORIGIN}/og-image.png`;

/** Attribute-safe text. Titles carry `&`, descriptions carry apostrophes. */
function esc(s: string): string {
  return s
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;');
}

/**
 * Structured data for the homepage, which is the first thing both Google's
 * knowledge layer and LLM retrieval look for - every help page carries
 * JSON-LD, so the single most important page must not be the one without it.
 *
 * Every claim here is generated from a source of truth rather than typed out:
 * the price from pricing.ts, the beta/list choice from the same env var
 * isBetaPricing() reads in paddle.ts, so the offer can never contradict the
 * price on the page. Platforms are the ones actually shipped
 * (ops/docs/mobile-release-status.md).
 * No aggregateRating: we have no review corpus, and inventing one is a
 * manual-action risk, not a shortcut.
 */
function jsonLd(locale: string): string {
  const m = META[locale] ?? META.en!;
  const url = ORIGIN + marketingPath(locale);
  // Mirrors isBetaPricing() in paddle.ts: the discount ID is what decides
  // which price the page renders, so it decides the offer too.
  const proPrice = process.env.VITE_PADDLE_BETA_DISCOUNT_ID ? EARLY_PRICE : PRO_PRICE;
  const publisher = {
    '@type': 'Organization',
    '@id': `${ORIGIN}/#organization`,
    name: 'PrivacyNotes',
    url: ORIGIN,
    logo: `${ORIGIN}/marketing/brand/privacynotes-icon-color.png`,
    sameAs: [
      'https://x.com/PrivacyNotesApp',
      'https://mastodon.social/@privacynotes',
      'https://www.reddit.com/r/PrivacyNotes/',
      'https://github.com/LifetimeLabsDev/PrivacyNotes.app',
    ],
  };
  const data = {
    '@context': 'https://schema.org',
    '@graph': [
      publisher,
      {
        '@type': 'SoftwareApplication',
        '@id': `${ORIGIN}/#app`,
        name: 'PrivacyNotes',
        url,
        description: m.description,
        applicationCategory: 'ProductivityApplication',
        operatingSystem: 'Web, macOS, Windows, Linux, iOS, Android',
        inLanguage: HREFLANG[locale] ?? 'en',
        publisher: { '@id': `${ORIGIN}/#organization` },
        offers: [
          {
            '@type': 'Offer',
            name: 'Free',
            price: '0',
            priceCurrency: 'USD',
            category: 'free',
          },
          {
            '@type': 'Offer',
            name: 'Pro',
            price: String(proPrice),
            priceCurrency: 'USD',
            // One payment, not a subscription - the thing the pricing page
            // exists to say, and the thing a crawler cannot infer from a number.
            category: 'one-time purchase',
            url: `${ORIGIN}/checkout`,
          },
        ],
      },
    ],
  };
  return `<script type="application/ld+json">${JSON.stringify(data).replace(/</g, '\\u003c')}</script>`;
}

/** The head tags that differ per locale, injected in place of the English set. */
function headFor(locale: string): string {
  const m = META[locale] ?? META.en!;
  const url = ORIGIN + marketingPath(locale);
  const alternates = hreflangPairs()
    .map((p) => `<link rel="alternate" hreflang="${p.hreflang}" href="${ORIGIN}${p.path}" />`)
    .join('\n    ');
  return `<title>${esc(m.title)}</title>
    <meta name="description" content="${esc(m.description)}" />
    <link rel="canonical" href="${url}" />
    ${alternates}
    <meta property="og:title" content="${esc(m.title)}" />
    <meta property="og:description" content="${esc(m.description)}" />
    <meta property="og:image" content="${OG_IMAGE}" />
    <meta property="og:image:width" content="1200" />
    <meta property="og:image:height" content="630" />
    <meta property="og:type" content="website" />
    <meta property="og:url" content="${url}" />
    <meta property="og:site_name" content="PrivacyNotes" />
    <meta property="og:locale" content="${ogLocale(locale)}" />
    <meta name="twitter:card" content="summary_large_image" />
    <meta name="twitter:site" content="@PrivacyNotesApp" />
    <meta name="twitter:title" content="${esc(m.title)}" />
    <meta name="twitter:description" content="${esc(m.description)}" />
    <meta name="twitter:image" content="${OG_IMAGE}" />
    ${jsonLd(locale)}`;
}

// The block index.html hands over: everything from <title> through the last
// twitter tag. Matched rather than assembled so a hand-edit to index.html that
// moves these tags fails the build instead of silently producing two <title>
// elements per locale.
const HEAD_BLOCK = /<title>[\s\S]*?<meta name="twitter:image"[^>]*>/;

/**
 * /llms.txt - the convention AI crawlers read to find out what a site is
 * without parsing the whole SPA. English only by the convention, and short on
 * purpose: it is an index, not a brochure. Its companion /llms-full.txt holds
 * the actual help content, with /llms-index.txt as the token-light tier in
 * front of it; both are emitted by help-page.ts, which owns those catalogs.
 * /changelog.md is the fourth file in that layer and the only one that says
 * what CHANGED rather than how the app works; changelog-page.ts emits it.
 * /docs/index.md is the fifth, and the only one that says how the app is
 * BUILT; publishedDocs.ts emits it and the documents it routes to.
 * The price interpolates from pricing.ts, and the language count from
 * LOCALE_TO_SLUG, so neither can go stale the way a hand-typed number does -
 * the count said 14 for three locale additions.
 *
 * The wording is deliberate: the clients, the encryption layer and the threat
 * model are published, and the sync backend stays closed. The database schema
 * is NOT published and must not be named here.
 * llms.txt is a factual reference rather than a pitch, so it names that
 * split plainly.
 */
function llmsTxt(): string {
  const proPrice = process.env.VITE_PADDLE_BETA_DISCOUNT_ID ? EARLY_PRICE : PRO_PRICE;
  return `# PrivacyNotes

> An end-to-end encrypted notes, tasks, journal and vault app: your notes are encrypted on your device, before they are stored or synced. The server holds ciphertext, which under self-custody it cannot read. Hosted in Switzerland, with no trackers and no analytics of what you write.

Signing up needs no email address: a new account is a generated 12-word recovery phrase and nothing else. Google, Apple and GitHub sign-in are available for people who want them, and the encryption key is still generated on the reader's own device either way.

The free tier is a real tier, not a trial: 2 devices and 50 MB of storage, with no time limit. Pro is a one-time payment of $${proPrice} for unlimited devices and 500 MB, with extra storage sold separately as a yearly add-on. There is no subscription for the app itself.

Available on the web, macOS, Windows, Linux, iOS and Android. The interface and help center are translated into ${Object.keys(LOCALE_TO_SLUG).length} languages.

The app is open source: the web, desktop and mobile clients, the encryption layer and the threat model are all published. The sync backend stays closed and holds nothing but encrypted data.

## Product
- [Homepage](${ORIGIN}/en): what it does, what it costs, and where to download it.
- [Try it without signing up](https://try.privacynotes.app): the full app with sample content, running entirely in the browser. Nothing is saved and nothing reaches a server.
- [Roadmap](${ORIGIN}/roadmap): what has shipped and what is next.
- [Changelog](${ORIGIN}/changelog): every release, newest first.

## Answers
- [Help center](${ORIGIN}/help): security, encryption, recovery phrases, sync, pricing, and step-by-step guides for exporting from another app and importing it here.
- [Question index](${ORIGIN}/llms-index.txt): every help question against the URL that answers it, each one plain text and about 900 bytes. Start here and fetch only what you need.
- [Every help answer in one file](${ORIGIN}/llms-full.txt): the same content in one fetch, about 17,700 tokens, when a second request is not possible.
- [Every release in one file](${ORIGIN}/changelog.md): the whole changelog as plain text, newest first. Read it when the question is about what changed, what is new in a version, or where something moved.
- [Security documentation index](${ORIGIN}/docs/index.md): the published security documents as plain text, with the sections of each. Read it when the question is about the encryption, what the server can read, how to verify any of it, or how sync resolves a conflict.
- [Source, threat model and encryption code](https://github.com/LifetimeLabsDev/PrivacyNotes.app): the repository the documents above are published from, with the clients beside them.

## Press
- [Brand assets](${ORIGIN}/brand): logos, wordmarks and usage rules.
`;
}

export function marketingShellPlugin(): Plugin {
  // The finished shell, captured after Vite has injected the hashed script and
  // stylesheet tags. transformIndexHtml is the only hook that sees it: by
  // generateBundle the HTML is no longer addressable as a bundle entry under
  // rolldown, and reading dist/index.html back off disk would race the write.
  let shell = '';
  let outDir = 'dist';
  return {
    name: 'pn-marketing-shell',
    apply: 'build',
    configResolved(config) {
      outDir = config.build.outDir;
    },
    transformIndexHtml: {
      // After Vite's own injection, so every locale copy carries the same
      // asset URLs the English one does.
      order: 'post',
      handler(html) {
        if (!HEAD_BLOCK.test(html)) {
          throw new Error(
            'pn-marketing-shell: could not find the <title>...twitter:image block in index.html. ' +
              'The head was reshaped - re-check this plugin before shipping.'
          );
        }
        shell = html;
        // The apex is English and keeps its own file; it just gains the tags it
        // never had (canonical, hreflang, og:locale/site_name, twitter:site, JSON-LD).
        return html.replace(HEAD_BLOCK, headFor('en'));
      },
    },
    // `writeBundle`, deliberately not `closeBundle`: closeBundle runs even when
    // the build FAILED, and an earlier plugin throwing in generateBundle means
    // the HTML stage never ran - so `shell` is empty for a reason that has
    // nothing to do with this plugin, and the throw below then replaces the
    // real error in the output. That masking sent a session chasing the
    // marketing shell while the actual failure was a chunk over its size
    // budget. writeBundle only runs once the bundle is written, so reaching it
    // with an empty `shell` is a genuine fault in this plugin.
    writeBundle() {
      if (!shell) throw new Error('pn-marketing-shell: index.html was never transformed');
      const root = path.resolve(process.cwd(), outDir);
      for (const [locale, slug] of Object.entries(LOCALE_TO_SLUG)) {
        const dir = path.join(root, slug.replace(/^\//, ''));
        fs.mkdirSync(dir, { recursive: true });
        fs.writeFileSync(
          path.join(dir, 'index.html'),
          shell
            .replace(
              '<html lang="en">',
              `<html lang="${HREFLANG[locale] ?? 'en'}"${(RTL_LOCALES as readonly string[]).includes(locale) ? ' dir="rtl"' : ''}>`
            )
            .replace(HEAD_BLOCK, headFor(locale))
        );
      }
      fs.writeFileSync(path.join(root, 'llms.txt'), llmsTxt());
      this.info(
        `marketing shells: ${Object.keys(LOCALE_TO_SLUG).length} locales pre-rendered, llms.txt emitted`
      );
    },
  };
}
