/**
 * Import-guide structure: which guides exist and their render order.
 * Ids double as the URL slug under /help/import/<id>/.
 *
 * Strings live in `src/locales/<lng>/guides.json` (namespace `guides`),
 * English first. A guide missing from a locale does NOT stop that locale
 * emitting the page: `loadGuides` (help-page.ts) fills the gap with the
 * English entry and `guideIds` is derived from the English catalog, so an
 * English-only guide ships in every locale, in English, under a translated
 * URL, and `guideHreflang` advertises translations that do not exist. The
 * translation workflow is what prevents that, not the renderer.
 *
 * This module must stay free of imports: help-page.ts transpiles it
 * standalone (esbuild) and evaluates it in Node at build time, exactly
 * like faq.ts.
 *
 * Content ground truth: each guide's export steps must match what the
 * matching importer in `src/import/*.ts` actually accepts (the header
 * comment of each importer documents its expected file shapes). When an
 * importer gains a format, update the guide in the same commit.
 */

type GuideSection = {
  /** Optional section heading. */
  h?: string;
  /** Plain paragraphs. Markdown [text](url) links only, like the FAQ. */
  p?: string[];
  /** Ordered steps, rendered as a numbered list. */
  steps?: string[];
  /**
   * Optional screenshot, rendered above the section's heading so a
   * section carrying only an img sits between the lead and the first
   * heading. `src` is a site-absolute path under /help/img/ and stays
   * identical across locales; only `alt` is translated.
   */
  img?: { src: string; alt: string; width: number; height: number };
};

/**
 * Bare app name + icon file under public/help/icons/ for each guide, in
 * sidebar render order (alphabetical by app name, A to Z). Brand names,
 * deliberately not translated. Single source of truth for which guides
 * exist: the homepage's import pills (LandingPage.tsx) render straight
 * from this map, so adding a guide here (plus its guides.json strings)
 * updates the homepage in the same commit. Icons: svg preferred, webp
 * when no svg exists.
 */
export const GUIDE_META: Record<string, { name: string; icon?: string }> = {
  'apple-journal': { name: 'Apple Journal', icon: 'apple-journal.webp' },
  'apple-notes': { name: 'Apple Notes', icon: 'apple-notes.svg' },
  bitwarden: { name: 'Bitwarden', icon: 'bitwarden.svg' },
  'browser-bookmarks': { name: 'Browser bookmarks', icon: 'browser-bookmarks.svg' },
  // No icon: no single browser owns the passwords .csv, so no logo is
  // honest. It wears the key the app gives the Vault instead - the
  // phosphor glyph in GUIDE_GLYPH (help-page.ts) and on the homepage pill.
  'browser-passwords': { name: 'Browser passwords' },
  evernote: { name: 'Evernote', icon: 'evernote.svg' },
  'google-keep': { name: 'Google Keep', icon: 'google-keep.svg' },
  'ia-writer': { name: 'iA Writer', icon: 'ia-writer.webp' },
  markdown: { name: 'Markdown', icon: 'markdown.svg' },
  'nextcloud-notes': { name: 'Nextcloud Notes', icon: 'nextcloud-notes.svg' },
  notesnook: { name: 'Notesnook', icon: 'notesnook.svg' },
  obsidian: { name: 'Obsidian', icon: 'obsidian.svg' },
  'samsung-notes': { name: 'Samsung Notes', icon: 'samsung-notes.webp' },
  simplenote: { name: 'Simplenote', icon: 'simplenote.svg' },
  'standard-notes': { name: 'Standard Notes', icon: 'standard-notes.webp' },
  typora: { name: 'Typora', icon: 'typora.webp' },
  upnote: { name: 'UpNote', icon: 'upnote.svg' },
  zettlr: { name: 'Zettlr', icon: 'zettlr.svg' },
};

/** Sidebar render order, derived from GUIDE_META so the two never drift. */
export const GUIDE_ORDER: readonly string[] = Object.keys(GUIDE_META);
