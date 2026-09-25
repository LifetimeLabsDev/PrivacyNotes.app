import { foldArabic } from './arabicFold.ts';

// The Latin, Greek and Cyrillic accent marks NFD splits off (é, ç, the dot of
// the Turkish İ, ё). Arabic and Thai marks sit outside this block.
const COMBINING_ACCENTS = /[\u0300-\u036f]/g;
// Letters NFD cannot split, folded by hand. The dotless ı folds to i, so a
// Turkish word matches when it is typed on a keyboard without that letter.
// The final sigma folds to σ: `toLowerCase` picks ς or σ from the letters
// around it, so without the map a word and the same word folded one letter
// at a time would end in different letters.
const PLAIN_LETTERS: Record<string, string> = { 'ł': 'l', 'ß': 'ss', 'ı': 'i', 'œ': 'oe', 'ς': 'σ' };
// Every character the accent pass can change: the Latin, Greek and Cyrillic
// blocks with the combining marks between them, and Latin and Greek Extended.
const MAY_CARRY_ACCENT = /[\u00c0-\u04ff\u1e00-\u1fff]/;
const ASCII_ONLY = /^[\x00-\x7f]*$/;

// One character without its accent marks, taken from NFD itself so the two
// cannot drift, and remembered per character.
const bareChars = new Map<string, string>();
function bareChar(ch: string): string {
  let bare = bareChars.get(ch);
  if (bare === undefined) {
    bare = PLAIN_LETTERS[ch] ?? ch.normalize('NFD').replace(COMBINING_ACCENTS, '');
    bareChars.set(ch, bare);
  }
  return bare;
}

// Katakana that has a hiragana form, U+30A1 to U+30F6 and the iteration
// marks U+30FD and U+30FE, 0x60 above their hiragana. The long vowel mark ー
// and the four letters with no hiragana form stay as they are.
const KATAKANA = /[ァ-ヶヽヾ]/;

// Katakana as hiragana, so a reading typed in hiragana while the input method
// composes finds the word written in katakana. One pass, as below.
function asHiragana(word: string): string {
  if (!KATAKANA.test(word)) return word;
  let out = '';
  for (let i = 0; i < word.length; i++) {
    const code = word.charCodeAt(i);
    const kana = (code >= 0x30a1 && code <= 0x30f6) || code === 0x30fd || code === 0x30fe;
    out += kana ? String.fromCharCode(code - 0x60) : word.charAt(i);
  }
  return out;
}

// One pass over the word, because a regex replace with a callback per step
// costs several times as much, and the index runs this on every word of
// every note.
function withoutAccents(word: string): string {
  if (!MAY_CARRY_ACCENT.test(word)) return word;
  let out = '';
  for (let i = 0; i < word.length; i++) {
    const code = word.charCodeAt(i);
    const ch = word.charAt(i);
    out += (code >= 0x00c0 && code <= 0x04ff) || (code >= 0x1e00 && code <= 0x1fff) ? bareChar(ch) : ch;
  }
  return out;
}

/**
 * The one fold for text the search compares: the notes index, the query, the
 * list's phrase check and every short-list matcher (`textMatch.ts`) read
 * through it, so a word matches however it was typed. NFKC turns full-width
 * letters from a Japanese keyboard ("ＰＩＮ") and other compatibility forms
 * into plain ones. `toLowerCase`, never the locale form, which turns "PIN"
 * into "pın" under Turkish. The Arabic fold runs before the accents come off:
 * an NFD split turns أ into ا and a hamza mark that foldArabic does not strip.
 * Then each accented letter becomes its NFD base, any combining mark left
 * over goes (the dot that lowercasing gives the Turkish İ), and the letters
 * with no mark to strip map by hand. Katakana becomes hiragana, after NFKC
 * has made half-width katakana full width. NFKC has already composed the
 * text, so a Hangul syllable or a voiced kana stays whole. Pure ASCII takes
 * the short path, which gives the same result.
 * Spec: ops/docs/design-decisions.md (search folding)
 */
export function foldText(text: string): string {
  if (ASCII_ONLY.test(text)) return text.toLowerCase();
  return withoutAccents(asHiragana(foldArabic(text.normalize('NFKC').toLowerCase())));
}
