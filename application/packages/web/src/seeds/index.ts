/**
 * Seed notes, as real markdown files.
 *
 * One `.md` file is one complete note. Its frontmatter carries everything
 * the seeder needs - id, title, note type, tags, folder, whether it is demo
 * only - so **adding a starter note is adding a file, and removing one is
 * deleting a file.** No TypeScript changes either way. `import.meta.glob`
 * discovers whatever is in `en/`.
 *
 * Frontmatter keys (only `id` and `title` are required):
 *
 *   id         4 hex characters. PERMANENT: it derives the note's UUID, so
 *              changing it re-seeds the note as a duplicate. Must be unique.
 *   title      Shown as the note title. Quote it if it contains a colon.
 *   type       note | task | journal | link          (default note)
 *   tags       comma separated, no leading #         (default none)
 *   starred    true pins it to the top of the list   (default false)
 *   folder     folder name. Files the note in every vault: the starter
 *              tree seeds for everyone, and browsing it is free. The name
 *              must be a key of SEED_FOLDERS in welcomeNote.ts, which
 *              `tools/check-seeds.mjs` enforces.
 *   demoOnly   true seeds it only in the public demo (default false)
 *   order      sort weight, lower is newer and sits higher (default 100)
 *
 * Vite's `?raw` inlines the English files at build time, so they ship as
 * string constants inside the bundle: no fetch, no async at runtime.
 *
 * Locale loading mirrors `i18n.ts` exactly: **English is EAGER, every other
 * locale is LAZY.** English is the per-field fallback anyway, so it has to
 * be in the bundle regardless; a translated set is fetched only when a
 * non-English visitor actually seeds a vault.
 *
 * To add a language: create `seeds/<locale>/` and translate the files into
 * it, keeping each file's name and its `id`. Nothing here changes. A locale
 * may be partial - a missing file or a blank title falls back to English
 * per field, so a half-finished language never seeds an empty note.
 *
 * Seed prose is translated once per locale on a manual trigger
 * (`ops/docs/i18n-spec.md` section 3), and every supported locale ships
 * a full seed directory today.
 */

export type SeedType = 'note' | 'task' | 'journal' | 'link';

export interface SeedDoc {
  /** File stem, e.g. `welcome`. The same stem names the file in every locale. */
  stem: string;
  /** 4 hex characters; the note's identity. */
  id: string;
  title: string;
  body: string;
  type: SeedType;
  tags: string[];
  starred: boolean;
  /** Folder name, applied in every vault. Null when the note is unfiled. */
  folder: string | null;
  demoOnly: boolean;
  order: number;
  /** Journal tracker values, straight off the file's frontmatter. */
  trackers?: Record<string, unknown>;
  /** `friday` | `saturday` | `sunday`: which day of the most recent weekend
   *  this entry is FOR. Resolved to a real `journalDate` at seed time, so the
   *  three Tokyo entries stay on a recent weekend instead of ageing. */
  journalDay?: string;
}

/**
 * `loadSeeds` is the only entry point, and it is deliberately a thin async
 * shell: the markdown, the parser and the locale globs all live in
 * `./content.ts`, which is dynamic-imported here so none of it sits in the
 * boot path. Seeding already happens inside an `await`, so the extra hop
 * costs nothing anybody can perceive.
 */
export async function loadSeeds(tag?: string): Promise<SeedDoc[]> {
  const { resolveSeeds } = await import('./content');
  return resolveSeeds(tag);
}
