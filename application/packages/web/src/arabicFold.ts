// Arabic search normalization ("folding"): strips diacritics and unifies
// letter-shape variants so a query typed without tashkeel/alef distinctions
// still matches note text that carries them, mirroring how Lucene's
// ArabicNormalizer behaves. Kept out of search.ts so cjkSegment.ts and
// arabicFold.ts both read as small, single-purpose script-handling modules
// consumed by the same index-and-query pipeline.
// Spec: ops/docs/design-decisions.md (search folding)

// Covers every character this function touches: tashkeel, tatweel, the alef
// variants, alef maqsura, teh marbuta, and both Arabic-Indic digit blocks.
// A single test against this range is the fast path for the overwhelming
// majority of terms (Latin, CJK) that this function leaves untouched.
const ARABIC_RANGE = /[؀-ۿ]/;

const TASHKEEL_OR_TATWEEL = /[ً-ْـ]/g;
const ALEF_VARIANTS = /[آأإٱ]/g;
const ARABIC_INDIC_DIGIT = /[٠-٩۰-۹]/g;

/**
 * Folds diacritics and letter-shape variants that differ between typed and
 * written Arabic: strips tashkeel and tatweel, unifies alef variants
 * (أ إ آ ٱ -> ا) and alef maqsura (ى -> ي), folds teh marbuta (ة -> ه), and
 * maps Arabic-Indic and Eastern Arabic-Indic digits to ASCII 0-9. Terms with
 * no Arabic-range characters are returned unchanged.
 */
export function foldArabic(term: string): string {
  if (!ARABIC_RANGE.test(term)) return term;
  return term
    .replace(TASHKEEL_OR_TATWEEL, '')
    .replace(ALEF_VARIANTS, 'ا')
    .replace(/ى/g, 'ي')
    .replace(/ة/g, 'ه')
    .replace(ARABIC_INDIC_DIGIT, (d) => {
      const code = d.codePointAt(0) as number;
      return String(code <= 0x0669 ? code - 0x0660 : code - 0x06f0);
    });
}

// The definite article as Arabic writes it, joined to its word: alone, or
// behind a one-letter conjunction or preposition (li- drops the article's
// alef). One per line, so the list does not reorder on screen.
const ARTICLES = [
  'وال', // wa-al
  'بال', // bi-al
  'كال', // ka-al
  'فال', // fa-al
  'لل', // li-l
  'ال', // al
];

/**
 * The word without the definite article joined to it, or null when it has
 * none. Arabic writes the article as part of the word, so "الأمان" (the
 * security) is one token, and a prefix search for "أمان" cannot reach it; the
 * index stores this bare form beside the whole word. At least two letters
 * must remain, the Lucene light-stemmer rule, so a short word that only
 * begins with the same letters ("الم", pain) stays whole. Takes a term that
 * has been through foldArabic, which turns a written "أل" into "ال".
 */
export function withoutArabicArticle(term: string): string | null {
  const first = term.charCodeAt(0);
  if (!(first >= 0x0600 && first <= 0x06ff)) return null;
  for (const article of ARTICLES) {
    if (term.length >= article.length + 2 && term.startsWith(article)) return term.slice(article.length);
  }
  return null;
}
