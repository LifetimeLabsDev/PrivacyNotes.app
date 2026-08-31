import MiniSearch from 'minisearch';
import type { LocalNote } from './db';
import { foldArabic } from './arabicFold';
import { hasCJK, segmentWords } from './cjkSegment';
import { perfSpan } from './perf';

/**
 * Client-side full-text search over decrypted notes.
 * Uses incremental updates after the initial full build.
 */

// MiniSearch's default tokenizer splits on whitespace and punctuation, which
// collapses a whole Japanese or Chinese sentence into one token. Route CJK text
// through Intl.Segmenter word segmentation instead; leave everything else on the
// exact default so Latin tokenization is unchanged. Used for both indexing and
// querying (see below) so documents and queries segment identically.
// Spec: ops/docs/i18n-cjk-plan.md (CJK tokenization)
const defaultTokenize = MiniSearch.getDefault('tokenize') as (
  text: string,
  fieldName?: string,
) => string[];

function tokenize(text: string, fieldName?: string): string[] {
  if (!hasCJK(text)) return defaultTokenize(text, fieldName);
  return segmentWords(text);
}

type IndexedDoc = {
  id: string;
  title: string;
  body: string;
  tagsText: string;
};

let index: MiniSearch<IndexedDoc> | null = null;

/** Set of all IDs currently in the index, for fast has-checks. */
const indexedIds = new Set<string>();

function noteToDoc(n: LocalNote): IndexedDoc {
  let body = n.body;
  // Tags are indexed for EVERY type. A tag is a label the user typed and the
  // app shows in the list; it is never a secret, and dropping it here meant a
  // tag on a task, a journal, a file, a bookmark or a vault item could not be
  // found by typing its name - only by clicking the tag rail. Bookmarks made
  // that plain: the pillar's own search box matched tags, this index did not,
  // which is one reason the pane grew a private search (2026-08-22).
  const tagsText = n.tags.join(' ');
  if (n.type !== 'note') {
    try {
      const d = JSON.parse(n.body);
      if (n.type === 'login') {
        body = [d.url ?? '', d.username ?? '', d.notes ?? ''].join(' ');
      } else if (n.type === 'card') {
        body = [d.cardholderName ?? '', d.notes ?? ''].join(' ');
      } else if (n.type === 'ssh-key') {
        body = [d.label ?? '', d.publicKey ?? '', d.notes ?? ''].join(' ');
      }
    } catch { /* keep raw body as fallback */ }
  }
  return { id: n.id, title: n.title, body, tagsText };
}

// MiniSearch's default processTerm just lowercases. Composing foldArabic
// after it keeps that default (Latin behavior is unchanged) while also
// folding tashkeel, alef variants, alef maqsura, teh marbuta, and
// Arabic-Indic digits, so an Arabic query typed without diacritics matches
// note text that carries them. Set at the constructor level (not inside
// searchOptions) so it applies to indexing too - MiniSearch falls back to
// this constructor value for queries whenever searchOptions doesn't
// override processTerm, which it doesn't here.
// Spec: ops/docs/archive/rtl-handoff.md (Arabic search folding)
function processTerm(term: string): string {
  return foldArabic(term.toLowerCase());
}

function createIndex(): MiniSearch<IndexedDoc> {
  return new MiniSearch<IndexedDoc>({
    fields: ['title', 'body', 'tagsText'],
    storeFields: ['id'],
    tokenize,
    processTerm,
    searchOptions: {
      // Same tokenizer at query time, or CJK queries would split differently
      // from the indexed documents and never match.
      tokenize,
      // Fuzzy on a short CJK token means "match almost anything" (a 1-edit
      // distance over a 2-4 character word), so disable it for CJK terms while
      // keeping the 0.2 typo tolerance for Latin queries.
      fuzzy: (term: string) => (hasCJK(term) ? false : 0.2),
      prefix: true,
      boost: { title: 3, tagsText: 2 },
    },
  });
}

/**
 * Full rebuild: the first pass and the many-changes fast path of
 * updateSearchIndex below, plus the seeding entry the search tests use.
 * At runtime the index has exactly one owner - the useSearchIndexSync
 * hook feeding this module from the notes state.
 */
export function buildSearchIndex(notes: LocalNote[]): void {
  const end = perfSpan('buildSearchIndex');
  index = createIndex();
  indexedIds.clear();
  const docs = notes.map(noteToDoc);
  index.addAll(docs);
  for (const d of docs) indexedIds.add(d.id);
  end();
}

/**
 * Incremental update - add/replace/remove only changed notes. Driven by
 * useSearchIndexSync (searchIndexSync.ts), which diffs the notes state,
 * so a note is searchable the moment it exists - no refresh needed.
 * When most of the index changed anyway (a full refresh replaces every
 * row reference), one rebuild beats per-row discard-and-add.
 */
export function updateSearchIndex(
  notes: LocalNote[],
  changed: { added: string[]; updated: string[]; removed: string[] },
): void {
  if (!index || changed.added.length + changed.updated.length > indexedIds.size / 2) {
    buildSearchIndex(notes);
    return;
  }

  const notesById = new Map(notes.map((n) => [n.id, n]));

  // Remove deleted notes from index.
  for (const id of changed.removed) {
    if (indexedIds.has(id)) {
      index.discard(id);
      indexedIds.delete(id);
    }
  }

  // Update modified notes (remove + re-add).
  for (const id of changed.updated) {
    if (indexedIds.has(id)) {
      index.discard(id);
      indexedIds.delete(id);
    }
    const note = notesById.get(id);
    if (note) {
      const doc = noteToDoc(note);
      index.add(doc);
      indexedIds.add(id);
    }
  }

  // Add brand-new notes.
  for (const id of changed.added) {
    if (indexedIds.has(id)) continue;
    const note = notesById.get(id);
    if (note) {
      const doc = noteToDoc(note);
      index.add(doc);
      indexedIds.add(id);
    }
  }
}

export function searchNotes(query: string): string[] {
  if (!index || !query.trim()) return [];
  return index.search(query).map((r) => String(r.id));
}
