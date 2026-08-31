// Arabic search normalization ("folding"): strips diacritics and unifies
// letter-shape variants so a query typed without tashkeel/alef distinctions
// still matches note text that carries them, mirroring how Lucene's
// ArabicNormalizer behaves. Kept out of search.ts so cjkSegment.ts and
// arabicFold.ts both read as small, single-purpose script-handling modules
// consumed by the same index-and-query pipeline.
// Spec: ops/docs/archive/rtl-handoff.md (Arabic search folding)

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
