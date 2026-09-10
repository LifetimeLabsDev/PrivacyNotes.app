/**
 * Password and passphrase generation, and the strength each carries.
 *
 * Pure functions over `crypto.getRandomValues`, so the vault form and the
 * tests share one implementation. Every number here is exact for the
 * construction below rather than an estimate: the bits shown in the
 * generator are the log of how many distinct outputs the same settings can
 * produce, each equally likely.
 * Spec: ops/docs/ui-patterns.md (the password generator)
 */

/**
 * Ambiguous characters (0, O, o, l, 1, I) are left out of every set, and the
 * symbols are the ones that survive most sites' rules: no brackets, pipes,
 * quotes, semicolons or angle brackets, which trip a WAF or a regex.
 */
export const CHAR_SETS = {
  lowercase: 'abcdefghjkmnpqrstuvwxyz',
  uppercase: 'ABCDEFGHJKLMNPQRSTUVWXYZ',
  digits: '23456789',
  symbols: '!@#$%^&*-_+=?~',
} as const;

export const PASSWORD_LENGTH = { min: 8, max: 64 } as const;
export const PASSPHRASE_WORDS = { min: 3, max: 20 } as const;
/** The most digits, and the most symbols, a password is asked to carry. */
export const EXACT_COUNT_MAX = 9;

export const SEPARATORS = ['-', '.', '_', ' '] as const;
type Separator = (typeof SEPARATORS)[number];

export interface PasswordOptions {
  length: number;
  lowercase: boolean;
  uppercase: boolean;
  /** Exact counts; 0 leaves the class out. */
  digits: number;
  symbols: number;
}

export interface PassphraseOptions {
  words: number;
  separator: Separator;
  /** One word, chosen at random, starts with a capital. */
  capitalize: boolean;
  /** One word, chosen at random, ends in a digit. */
  number: boolean;
  /** One word, chosen at random, ends in a symbol. */
  symbol: boolean;
}

/**
 * A uniform integer in [0, n). Rejection rather than a modulo: 2^32 is not
 * a multiple of most set sizes, and the remainder favours the low end of
 * the set by a hair on every draw.
 */
export function randomIndex(n: number): number {
  const limit = Math.floor(0x1_0000_0000 / n) * n;
  const draw = new Uint32Array(1);
  for (;;) {
    crypto.getRandomValues(draw);
    if (draw[0]! < limit) return draw[0]! % n;
  }
}

function pick(chars: string): string {
  return chars.charAt(randomIndex(chars.length));
}

function shuffle(arr: string[]): void {
  for (let i = arr.length - 1; i > 0; i--) {
    const j = randomIndex(i + 1);
    [arr[i], arr[j]] = [arr[j]!, arr[i]!];
  }
}

/** The letters that fill what the exact counts leave; lowercase when both sets are off. */
function letterPool(o: { lowercase: boolean; uppercase: boolean }): string {
  const pool = (o.lowercase ? CHAR_SETS.lowercase : '') + (o.uppercase ? CHAR_SETS.uppercase : '');
  return pool || CHAR_SETS.lowercase;
}

/**
 * Exactly `digits` digits and `symbols` symbols, letters for the rest, all
 * shuffled. The exact counts win over the length: a password asked for more
 * of them than it has room for grows to hold them.
 */
export function generatePassword(o: PasswordOptions): string {
  const out: string[] = [];
  for (let i = 0; i < o.digits; i++) out.push(pick(CHAR_SETS.digits));
  for (let i = 0; i < o.symbols; i++) out.push(pick(CHAR_SETS.symbols));
  const pool = letterPool(o);
  const fill = Math.max(0, o.length - out.length);
  for (let i = 0; i < fill; i++) out.push(pick(pool));
  shuffle(out);
  return out.join('');
}

/**
 * Words drawn with replacement, then the options applied one word each:
 * the capital, the digit and the symbol each land on a word chosen at
 * random, and two of them may land on the same word. The digit and the
 * symbol come from the same sets the password uses.
 */
export function generatePassphrase(o: PassphraseOptions, list: readonly string[]): string {
  const words: string[] = [];
  for (let i = 0; i < o.words; i++) words.push(list[randomIndex(list.length)]!);
  if (o.capitalize) {
    const i = randomIndex(words.length);
    words[i] = words[i]!.charAt(0).toUpperCase() + words[i]!.slice(1);
  }
  if (o.number) words[randomIndex(words.length)] += pick(CHAR_SETS.digits);
  if (o.symbol) words[randomIndex(words.length)] += pick(CHAR_SETS.symbols);
  return words.join(o.separator);
}

function log2Factorial(n: number): number {
  let sum = 0;
  for (let i = 2; i <= n; i++) sum += Math.log2(i);
  return sum;
}

/**
 * log2 of the distinct passwords the options can produce. The three
 * alphabets are disjoint, so a password fixes which positions hold digits,
 * symbols and letters: the count is the ways to place them times the
 * choices in each slot, and the shuffle makes every one equally likely.
 */
export function passwordBits(o: PasswordOptions): number {
  const d = o.digits;
  const s = o.symbols;
  const n = Math.max(o.length, d + s);
  const l = n - d - s;
  const placements = log2Factorial(n) - log2Factorial(d) - log2Factorial(s) - log2Factorial(l);
  return (
    placements +
    l * Math.log2(letterPool(o).length) +
    d * Math.log2(CHAR_SETS.digits.length) +
    s * Math.log2(CHAR_SETS.symbols.length)
  );
}

/**
 * log2 of the distinct passphrases the options can produce from a list of
 * `listSize` lowercase words. Each option multiplies by its choice of word
 * and, for the digit and the symbol, by the character drawn.
 */
export function passphraseBits(o: PassphraseOptions, listSize: number): number {
  let bits = o.words * Math.log2(listSize);
  if (o.capitalize) bits += Math.log2(o.words);
  if (o.number) bits += Math.log2(o.words * CHAR_SETS.digits.length);
  if (o.symbol) bits += Math.log2(o.words * CHAR_SETS.symbols.length);
  return bits;
}

export type Strength = 'weak' | 'fair' | 'strong' | 'veryStrong';

/**
 * Four tiers, one per segment of the meter, read against an offline attack
 * at ten billion guesses a second, the pessimistic case for a leaked fast
 * hash: under 40 bits falls in minutes, 40 to 59 in hours to days, 60 and
 * up takes years, 90 and up outlasts everything. No online attack reaches
 * the second tier, so a vault login is strong from 60.
 */
export function strengthOf(bits: number): Strength {
  if (bits < 40) return 'weak';
  if (bits < 60) return 'fair';
  if (bits < 90) return 'strong';
  return 'veryStrong';
}
