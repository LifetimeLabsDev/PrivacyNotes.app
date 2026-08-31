/**
 * The seed content itself: the markdown files, parsed.
 *
 * This module is LAZY on purpose and must stay that way. It is reached only
 * through `loadSeeds()` in `./index.ts`, which dynamic-imports it. Seed
 * prose is read exactly once, at first sign-in, and never again - putting it
 * in the boot path makes every launch pay for text that almost no launch
 * uses. It was in the boot path once and cost about 9 kB gzipped there.
 *
 * The frontmatter keys are documented in `./index.ts`.
 */

import i18n, { normalizeLocale } from '../i18n';
import type { SeedDoc, SeedType } from './index';

/**
 * English: eager WITHIN this lazy chunk. It is the per-field fallback for
 * every other locale, so it has to arrive together with the parser rather
 * than as a second round trip.
 */
const EN_FILES = import.meta.glob<string>('./en/*.md', {
  query: '?raw',
  import: 'default',
  eager: true,
});

/**
 * Every non-English seed file, as lazy importers keyed by path. The `en`
 * exclusion matters: without it these same files would be emitted a second
 * time as dynamic chunks alongside the eager set above.
 */
const TRANSLATED = import.meta.glob<string>(['./*/*.md', '!./en/*.md'], {
  query: '?raw',
  import: 'default',
});

const VALID_TYPES: SeedType[] = ['note', 'task', 'journal', 'link'];

function stemOf(path: string): string {
  return path.slice(path.lastIndexOf('/') + 1).replace(/\.md$/, '');
}

/** Strip one layer of matching surrounding quotes. */
function unquote(v: string): string {
  return v.replace(/^(['"])([\s\S]*)\1$/, '$2');
}

/**
 * Split `---\nkey: value\n---\n\nbody` into a field map plus the body.
 *
 * Deliberately not a YAML parser: the frontmatter is a flat list of scalars,
 * and a dependency to read it would cost more than the feature is worth.
 *
 * The trailing newline every text file ends with is dropped, so the seeded
 * body matches what the file looks like on screen.
 */
function splitFrontmatter(raw: string): { fields: Record<string, string>; body: string } {
  const fence = /^---\r?\n([\s\S]*?)\r?\n---\r?\n/.exec(raw);
  const front = fence?.[1];
  if (!fence || front === undefined) return { fields: {}, body: raw.replace(/\n$/, '') };
  const fields: Record<string, string> = {};
  for (const line of front.split(/\r?\n/)) {
    const at = line.indexOf(':');
    if (at <= 0) continue;
    fields[line.slice(0, at).trim()] = unquote(line.slice(at + 1).trim());
  }
  return {
    fields,
    body: raw.slice(fence[0].length).replace(/^\r?\n/, '').replace(/\n$/, ''),
  };
}

/** Tracker values ride as one line of JSON, the same shape the export writes. */
function parseTrackers(raw: string | undefined): Record<string, unknown> | undefined {
  if (!raw || !raw.trim().startsWith('{')) return undefined;
  try {
    const parsed: unknown = JSON.parse(raw.trim());
    if (!parsed || typeof parsed !== 'object' || Array.isArray(parsed)) return undefined;
    const obj = parsed as Record<string, unknown>;
    return Object.keys(obj).length > 0 ? obj : undefined;
  } catch {
    return undefined;
  }
}

function toDoc(stem: string, raw: string): SeedDoc | null {
  const { fields, body } = splitFrontmatter(raw);
  const id = (fields.id ?? '').toLowerCase();
  const title = fields.title ?? '';
  // A file without a usable identity is skipped rather than seeded wrong:
  // a bad id would collide with another note's UUID.
  if (!/^[0-9a-f]{4}$/.test(id) || !title) return null;
  const type = fields.type as SeedType | undefined;
  return {
    stem,
    id,
    title,
    body,
    type: type && VALID_TYPES.includes(type) ? type : 'note',
    tags: (fields.tags ?? '')
      .split(',')
      .map((t) => t.trim().replace(/^#/, ''))
      .filter(Boolean),
    starred: fields.starred === 'true',
    folder: fields.folder ? fields.folder : null,
    demoOnly: fields.demoOnly === 'true',
    order: Number.isFinite(Number(fields.order)) && fields.order ? Number(fields.order) : 100,
    ...(parseTrackers(fields.trackers) ? { trackers: parseTrackers(fields.trackers) } : {}),
    ...(fields.journalDay ? { journalDay: fields.journalDay } : {}),
  };
}

function sortDocs(docs: SeedDoc[]): SeedDoc[] {
  return docs.sort((a, b) => a.order - b.order || a.stem.localeCompare(b.stem));
}

/** The English set: every parsable file in `en/`, in seeding order. */
const EN_DOCS: SeedDoc[] = sortDocs(
  Object.entries(EN_FILES)
    .map(([path, raw]) => toDoc(stemOf(path), raw))
    .filter((d): d is SeedDoc => d !== null),
);

/**
 * Resolve the seed list for a locale, falling back to English per field.
 *
 * Pass a tag to force one; otherwise the language i18next settled on is
 * used. `main.tsx` gates the first render on `i18nReady`, so by the time
 * anything seeds a vault the boot locale is already applied.
 *
 * Only the TITLE and BODY are taken from a translation. Everything else -
 * id, type, folder, order - stays under English's control, so a translated
 * file cannot accidentally re-file a note or change its identity.
 */
export async function resolveSeeds(tag?: string): Promise<SeedDoc[]> {
  const locale = normalizeLocale(tag ?? i18n.resolvedLanguage ?? i18n.language);
  if (locale === 'en') return EN_DOCS;

  return Promise.all(
    EN_DOCS.map(async (doc) => {
      const load = TRANSLATED[`./${locale}/${doc.stem}.md`];
      if (!load) return doc;
      try {
        const { fields, body } = splitFrontmatter(await load());
        return {
          ...doc,
          title: fields.title || doc.title,
          body: body || doc.body,
        };
      } catch {
        return doc; /* a broken translation keeps the English note */
      }
    }),
  );
}
