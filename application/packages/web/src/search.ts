import MiniSearch from 'minisearch';
import type { LocalNote } from './db';
import { foldArabic } from './arabicFold';
import { hasCJK, segmentWords } from './cjkSegment';
import { perfSpan } from './perf';
import { contactSearchText, parseContactBody } from './contactBody';

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

/**
 * The body text the index reads for a note: the markdown body, or for a
 * vault item the fields that are safe to search. A password is never in it,
 * and neither is a card number. Exported so the phrase check the list runs
 * on a hit (`noteSaysPhrase` in notesViewUtils) reads exactly what the index
 * read, and never more.
 */
export function indexedBodyText(n: LocalNote): string {
  // A contact indexes its name, its numbers (as typed and as digits, so
  // "0176" finds "+49 176 ..."), its emails and its notes; never the uid,
  // the photo or the unmodelled extras.
  if (n.type === 'contact') return contactSearchText(parseContactBody(n.body));
  if (n.type !== 'login' && n.type !== 'card' && n.type !== 'ssh-key') return n.body;
  try {
    const d = JSON.parse(n.body);
    if (n.type === 'login') return [d.url ?? '', d.username ?? '', d.notes ?? ''].join(' ');
    if (n.type === 'card') return [d.cardholderName ?? '', d.notes ?? ''].join(' ');
    return [d.label ?? '', d.publicKey ?? '', d.notes ?? ''].join(' ');
  } catch {
    return n.body;
  }
}

function noteToDoc(n: LocalNote): IndexedDoc {
  // Tags are indexed for EVERY type. A tag is a label the user typed and the
  // app shows in the list; it is never a secret, and dropping it here meant a
  // tag on a task, a journal, a file, a bookmark or a vault item could not be
  // found by typing its name - only by clicking the tag rail. Bookmarks made
  // that plain: the pillar's own search box matched tags, this index did not,
  // which is one reason the pane grew a private search (2026-08-22).
  const tagsText = n.tags.join(' ');
  return { id: n.id, title: n.title, body: indexedBodyText(n), tagsText };
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
      // No typo tolerance, in any script. One edit on a short word is another
      // word ("test" reaches "best", "100" reaches "10"), so a note was listed
      // for a word it does not hold and the find bar had nothing of the
      // reader's to show. Prefix matching covers a word as it is typed.
      fuzzy: false,
      prefix: true,
      boost: { title: 3, tagsText: 2 },
      // Every word of a query must match. A note that holds one word of
      // "encrypted on this device" is not what somebody typing that wants.
      // The phrase itself is the list's job (`noteSaysPhrase`), and this is
      // its cheap first cut: a note that says the phrase holds every word.
      combineWith: 'AND',
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

/**
 * The words in one hit's body that made it a hit for `query`, as the note
 * spells them: a prefix search for "grow" reports "growth", because
 * MiniSearch resolves a query against its term tree before it can find a
 * document at all. Empty when the note was a hit on its title or its tags
 * alone, which the editor has no text for. The find bar tries these after
 * the typed string (GitHub #288).
 */
export function searchBodyTerms(query: string, id: string): string[] {
  if (!index || !query.trim()) return [];
  const hit = index.search(query).find((r) => String(r.id) === id);
  if (!hit) return [];
  return hit.terms.filter((term) => hit.match[term]?.includes('body'));
}

/**
 * Whether a query is a phrase: anything the tokenizer splits into more than
 * one term. A space, but also a hyphen, a dot or an apostrophe:
 * "encrypted-images" is two terms to the index and one string to the reader,
 * and the list and the bar both treat it as the string. A single term keeps
 * prefix and typo tolerance.
 */
export function isPhraseQuery(query: string): boolean {
  return tokenize(query.trim()).length > 1;
}

/**
 * What the find bar tries for a hit, in order. A phrase goes in as typed and
 * nothing else: the bar matches a literal run of text, the list only holds
 * notes that say the phrase, and a note that does not say it gets no bar
 * rather than one term of it. A single term goes in as typed first - the
 * reader's own string, and a prefix lights up inside every word it starts -
 * then the forms the index resolved it to, shortest first, for the text the
 * typed string cannot reach as written (an Arabic word typed without its
 * diacritics). Empty when nothing in the body matched.
 */
export function searchSeedCandidates(query: string, bodyTerms: string[]): string[] {
  if (bodyTerms.length === 0) return [];
  const typed = query.trim().replace(/\s+/g, ' ');
  if (isPhraseQuery(typed)) return [typed];
  const lower = typed.toLowerCase();
  const resolved = bodyTerms.filter((t) => t !== lower).sort((a, b) => a.length - b.length);
  return [typed, ...resolved];
}
