// Emits the FAQ question strings the APP links, per locale.
//
// The help chip in a modal shows a real FAQ question, because the question is
// the payload: it is written the way a reader types it into a search box
// (ops/docs/help-center.md section 2). The app cannot read those questions at
// runtime - faq.json is 1.4 MB across the locales and i18n.ts deliberately
// keeps it out of both catalog globs (ops/docs/bundle-size.md, build-only
// catalogs). Hand-copying each question into a normal catalog key would work
// exactly once: /help questions get rewritten for search, and the copy would
// go on confidently saying the old thing with nothing to flag it - the same
// silent way a stale translation fails, one level removed.
//
// So this script copies them, and `--check` proves the copy is current. The
// output is a normal i18n namespace, `helpQuestions`, which buys the whole
// eager-English / lazy-everything-else split for the price of the strings: a
// separate module tree with its own import.meta.glob measured 2.32 kB gzipped
// and one extra chunk on the boot path, against roughly 0.2 kB this way.
//
// It is GENERATED. Do not hand-edit `src/locales/<lng>/helpQuestions.json`;
// the next run overwrites it and `check:help-chips` fails the build meanwhile.
//
// A locale that has not translated an entry yet falls back to the English
// question, exactly as help-page.ts does for a guide missing from a locale.
// The chip then reads English in that locale until the FAQ batch lands, which
// is what the /help page already shows there.
//
// Nobody has to remember to run it: vite.config.ts calls syncHelpChips() on
// buildStart and again whenever a faq.json changes under a running dev server,
// so rewording a question in the help center reaches the chip by itself. The
// CLI and the check exist for CI and for a manual pass.
//
// Usage:
//   node tools/sync-help-chips.mjs           write the files
//   node tools/sync-help-chips.mjs --check   fail if they are out of date
//
// Spec: ops/docs/help-center.md (section 9 - the in-app help chip)

import { readFileSync, readdirSync, writeFileSync, existsSync, statSync } from 'node:fs';
import { join, dirname } from 'node:path';
import { fileURLToPath, pathToFileURL } from 'node:url';

const ROOT = join(dirname(fileURLToPath(import.meta.url)), '..');
const WEB = join(ROOT, 'packages/web');
const LOCALES = join(WEB, 'src/locales');
const MAP = join(WEB, 'src/helpChips.json');

/** Every id any surface links, deduplicated, in a stable order. */
function linkedIds() {
  const surfaces = JSON.parse(readFileSync(MAP, 'utf8'));
  const ids = new Set();
  for (const list of Object.values(surfaces)) for (const id of list) ids.add(id);
  return [...ids].sort();
}

function entriesFor(locale) {
  const p = join(LOCALES, locale, 'faq.json');
  if (!existsSync(p)) return {};
  return JSON.parse(readFileSync(p, 'utf8')).entries ?? {};
}

/**
 * Writes (or with `check`, verifies) one helpQuestions.json per locale.
 * Returns `{ ids, locales, stale }`; throws when a chip names an id the
 * English catalog does not have, because that chip would render blank.
 */
export function syncHelpChips({ check = false } = {}) {
  const locales = readdirSync(LOCALES).filter((d) => statSync(join(LOCALES, d)).isDirectory());
  const ids = linkedIds();
  const en = entriesFor('en');

  const missing = ids.filter((id) => !en[id]);
  if (missing.length) {
    throw new Error(
      `sync-help-chips: no English FAQ entry for ${missing.join(', ')}. ` +
        'A chip must point at an entry that exists: fix src/helpChips.json or write the entry.',
    );
  }

  const stale = [];
  for (const locale of locales) {
    const entries = entriesFor(locale);
    const out = {};
    for (const id of ids) out[id] = (entries[id] ?? en[id]).q;
    const body = JSON.stringify(out, null, 2) + '\n';
    const dest = join(LOCALES, locale, 'helpQuestions.json');
    const current = existsSync(dest) ? readFileSync(dest, 'utf8') : null;
    if (current === body) continue;
    stale.push(locale);
    if (!check) writeFileSync(dest, body);
  }

  return { ids, locales, stale };
}

// CLI only. Imported by vite.config.ts, where this block must not run.
if (process.argv[1] && import.meta.url === pathToFileURL(process.argv[1]).href) {
  const check = process.argv.includes('--check');
  let result;
  try {
    result = syncHelpChips({ check });
  } catch (err) {
    console.error(err.message);
    process.exit(1);
  }
  if (check && result.stale.length) {
    console.error(result.stale.map((l) => `${l}/helpQuestions.json is out of date`).join('\n'));
    console.error(
      `\ncheck:help-chips FAILED\n  ${result.stale.length} file(s) stale: run \`node tools/sync-help-chips.mjs\``,
    );
    process.exit(1);
  }
  console.log(
    check
      ? `check:help-chips OK - ${result.ids.length} question(s) across ${result.locales.length} locales, every copy current.`
      : `sync-help-chips: wrote ${result.ids.length} question(s) across ${result.locales.length} locales.`,
  );
}
