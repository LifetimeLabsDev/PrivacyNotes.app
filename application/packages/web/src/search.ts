import MiniSearch from 'minisearch';
import { isKnownNoteType } from './noteTypes';
import type { LocalNote } from './db';
import { withoutArabicArticle } from './arabicFold';
import { hasCJK, segmentWords } from './cjkSegment';
import { foldText } from './textFold';
import { foldForMatch, textMatcher } from './textMatch';
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
 * Every indexed note as folded text, one line each for the title, a body line
 * and a tag, made from the same copy the index read, so a note behind its PIN
 * holds its title and tags only. A line break keeps a phrase inside one line.
 * Built with the index, so a keystroke never folds a note.
 */
const foldedNotes = new Map<string, string>();

function foldedCopy(doc: IndexedDoc, tags: readonly string[]): string {
  return [doc.title, ...doc.body.split('\n'), ...tags].map(foldForMatch).join('\n');
}

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
  // A type this build does not know is opaque: its body is neither indexed
  // nor kept for the find bar, so a field a newer pillar keeps private is
  // not searchable on a build that cannot read it.
  if (!isKnownNoteType(n.type)) return '';
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

/**
 * The copy of a note the index reads while the PIN guards it: its stored
 * title and its tags, never its body, and so never a name its body spells (a
 * contact's email or number, a bookmark's domain). The view hands the index
 * this in place of the note, so a word from a guarded body finds nothing and
 * the find bar is never seeded from one; the whole note goes back in once its
 * gate opens. Tested in tests/lockGateReads.test.ts.
 */
export function gatedSearchCopy(n: LocalNote): LocalNote {
  return { ...n, body: '' };
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

/**
 * What the index stores for one token: its folded form, and beside it the
 * bare word when Arabic joined the definite article to it. A query is folded
 * but never stripped, so "امان" finds "الأمان", and a reader who types the
 * article still gets only the words that carry it.
 */
function indexTerms(term: string): string | string[] {
  const folded = foldText(term);
  const bare = withoutArabicArticle(folded);
  return bare ? [folded, bare] : folded;
}

function createIndex(): MiniSearch<IndexedDoc> {
  return new MiniSearch<IndexedDoc>({
    fields: ['title', 'body', 'tagsText'],
    // A hit carries the body text it was indexed from, so searchBodyTerms
    // can hand the find bar the note's own spelling of a folded word. It is
    // the indexedBodyText projection, so a vault password is never in it.
    storeFields: ['id', 'body'],
    tokenize,
    processTerm: indexTerms,
    searchOptions: {
      // Same tokenizer at query time, or CJK queries would split differently
      // from the indexed documents and never match.
      tokenize,
      processTerm: foldText,
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
  foldedNotes.clear();
  const docs: IndexedDoc[] = [];
  for (const n of notes) {
    const doc = noteToDoc(n);
    docs.push(doc);
    indexedIds.add(doc.id);
    foldedNotes.set(doc.id, foldedCopy(doc, n.tags));
  }
  index.addAll(docs);
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
    foldedNotes.delete(id);
  }

  // Update modified notes (remove + re-add).
  for (const id of changed.updated) {
    if (indexedIds.has(id)) {
      index.discard(id);
      indexedIds.delete(id);
    }
    foldedNotes.delete(id);
    const note = notesById.get(id);
    if (note) {
      const doc = noteToDoc(note);
      index.add(doc);
      indexedIds.add(id);
      foldedNotes.set(id, foldedCopy(doc, note.tags));
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
      foldedNotes.set(id, foldedCopy(doc, note.tags));
    }
  }
}

/**
 * The notes whose folded copy holds the whole query, anywhere: the rule every
 * other list follows (`textMatcher`). A word-prefix index cannot answer it for
 * a match inside a word ("wagen" in "Einkaufswagen"), a katakana word typed
 * in hiragana, or a Japanese word the segmenter cut another way. The notes
 * list shows the ones the index did not return after its ranked hits. A
 * phrase stays inside one line.
 */
export function notesHolding(query: string): Set<string> {
  const found = new Set<string>();
  const needle = foldForMatch(query).trim();
  if (!needle) return found;
  for (const [id, folded] of foldedNotes) if (folded.includes(needle)) found.add(id);
  return found;
}

export function searchNotes(query: string): string[] {
  if (!index || !query.trim()) return [];
  return index.search(query).map((r) => String(r.id));
}

/**
 * The words in one hit's body that made it a hit for `query`, as the note
 * spells them: "grow" reports "Growth", "securite" reports "Sécurité" and
 * "امان" reports "الأمان". MiniSearch resolves a query to the folded terms it
 * stores, and the find bar matches the text as written, so each matched term
 * goes back through the body's own words to the spellings that fold to it,
 * in query order. The body is read line by line, with the tokenizer the index
 * chose for the whole body, and only until every term has a spelling: this
 * runs on each query change, and a long note is paid for only up to the
 * words it needs. Empty when the note was a hit on its title or its tags
 * alone, which the editor has no text for. A note the index did not return,
 * listed because it holds the query inside a word (`notesHolding`), gets the
 * body's own text where the query matched. The find bar tries these after
 * the typed string (GitHub #288).
 */
export function searchBodyTerms(query: string, id: string): string[] {
  if (!index || !query.trim()) return [];
  const hit = index.search(query).find((r) => String(r.id) === id);
  if (!hit) {
    const match = textMatcher(query);
    for (const line of String(index.getStoredFields(id)?.body ?? '').split('\n')) {
      const found = match(line);
      if (found) return [line.slice(found.start, found.end)];
    }
    return [];
  }
  const spellings = new Map<string, Map<string, string>>();
  for (const term of hit.terms) {
    if (hit.match[term]?.includes('body')) spellings.set(term, new Map());
  }
  if (spellings.size === 0) return [];
  const body = String(hit.body ?? '');
  const tokenizeLine = hasCJK(body) ? segmentWords : defaultTokenize;
  let missing = spellings.size;
  for (const line of body.split('\n')) {
    for (const word of tokenizeLine(line)) {
      const terms = indexTerms(word);
      for (const term of typeof terms === 'string' ? [terms] : terms) {
        const found = spellings.get(term);
        if (!found || found.has(word.toLowerCase())) continue;
        if (found.size === 0) missing -= 1;
        found.set(word.toLowerCase(), word);
      }
    }
    if (missing === 0) break;
  }
  const words = new Map<string, string>();
  for (const found of spellings.values()) {
    for (const [key, word] of found) if (!words.has(key)) words.set(key, word);
  }
  return [...words.values()];
}

/**
 * Whether a query is a phrase: anything the tokenizer splits into more than
 * one term. A space, but also a hyphen, a dot or an apostrophe:
 * "encrypted-images" is two terms to the index and one string to the reader,
 * and the list and the bar both treat it as the string. A single term keeps
 * prefix matching.
 */
export function isPhraseQuery(query: string): boolean {
  return tokenize(query.trim()).length > 1;
}

/**
 * What the find bar tries for a hit, in order. A phrase goes in as typed and
 * nothing else: the bar matches a literal run of text, the list only holds
 * notes that say the phrase, and a note that does not say it gets no bar
 * rather than one term of it. A phrase typed without the accents the note
 * writes is listed and opens no bar, for the same reason. A single term goes
 * in as typed first - the reader's own string, and a prefix lights up inside
 * every word it starts - then the note's own spellings of the words the index
 * matched, shortest first, for the text the typed string cannot reach as
 * written (a word typed without its accents, its diacritics or its Arabic
 * article). A spelling that differs from the typed string only in case is
 * dropped: the bar ignores case, so it would repeat the first try. Empty when
 * nothing in the body matched.
 */
export function searchSeedCandidates(query: string, bodyTerms: string[]): string[] {
  if (bodyTerms.length === 0) return [];
  const typed = query.trim().replace(/\s+/g, ' ');
  if (isPhraseQuery(typed)) return [typed];
  const lower = typed.toLowerCase();
  const resolved = bodyTerms.filter((t) => t.toLowerCase() !== lower).sort((a, b) => a.length - b.length);
  return [typed, ...resolved];
}
