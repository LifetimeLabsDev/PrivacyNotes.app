// Shared word segmentation for scripts that do not delimit words with spaces
// (Japanese, Chinese and Thai). Consumed by both the search index (search.ts) and the
// word counter (wordCountUtils.ts) so the two always agree on what a "word" is.
//
// Why this exists: MiniSearch's default tokenizer and countWords both split on
// whitespace and punctuation. A Japanese, Chinese or Thai run has neither between
// words, so a whole sentence collapsed into a single token - search for a
// substring returned nothing, and a full page counted as one word (which also
// broke writing-milestone unlocks). Intl.Segmenter is ICU-backed word
// segmentation, dependency-free, and present in every browser and Tauri webview
// we ship to (Chrome 87+, Safari 14.1+, Firefox 125+). Where it is somehow
// absent we fall back to per-character CJK handling, which over-segments but
// never merges a run back into one token - i.e. it can over-match, never
// under-match, which is the safe direction for both search and word count.
//
// Korean is deliberately NOT treated as CJK here: it delimits words with spaces
// (eojeol), so the existing whitespace path already works and MiniSearch's
// prefix matching already absorbs particle agglutination. Routing it through the
// segmenter would change established behavior for no gain.
//
// Spec: ops/docs/i18n-cjk-plan.md (CJK tokenization)

// Han (unified + ext A + compatibility ideographs), Hiragana, Katakana,
// halfwidth Katakana, and the Thai block (Thai spaces clauses, never words, so
// ICU segments it by dictionary). Not Hangul, and not the fullwidth
// Latin/punctuation block.
const CJK_SOURCE = '\\u3400-\\u4dbf\\u4e00-\\u9fff\\uf900-\\ufaff\\u3040-\\u309f\\u30a0-\\u30ff\\uff66-\\uff9f\\u0e00-\\u0e7f';
const CJK_TEST = new RegExp(`[${CJK_SOURCE}]`);
const CJK_SPLIT = new RegExp(`([${CJK_SOURCE}])`, 'g');

/** True when the string contains Han, Kana or Thai, i.e. text the space-based
 *  tokenizer and word counter get wrong. */
export function hasCJK(s: string): boolean {
  return CJK_TEST.test(s);
}

const wordSegmenter =
  typeof Intl !== 'undefined' && 'Segmenter' in Intl
    ? new Intl.Segmenter(undefined, { granularity: 'word' })
    : null;

/**
 * Word-like segments of a string that contains CJK or Thai. Handles mixed
 * script: Latin runs segment into their own words, CJK and Thai runs into ICU
 * word units. The
 * segmenter is intentionally locale-independent - a note's script is
 * independent of the UI language, so the global search index and the word count
 * must segment the same way regardless of what language the app is displayed in.
 */
export function segmentWords(s: string): string[] {
  if (wordSegmenter) {
    const out: string[] = [];
    for (const seg of wordSegmenter.segment(s)) {
      if (seg.isWordLike) out.push(seg.segment);
    }
    return out;
  }
  // Fallback (no Intl.Segmenter): isolate each Han, Kana or Thai character as
  // its own token and whitespace-split the rest.
  return s.replace(CJK_SPLIT, ' $1 ').split(/\s+/).filter(Boolean);
}
