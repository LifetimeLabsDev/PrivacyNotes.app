/**
 * The BIP-39 English word list, exported for the passphrase generator.
 *
 * It is the same array the recovery phrase draws from, which is why the
 * generator costs the app no second list: one import, already on every
 * device that can show a phrase. 2,048 words, all lowercase ASCII, so a
 * passphrase built from it carries 11 bits per word.
 */
export { wordlist as BIP39_WORDS } from '@scure/bip39/wordlists/english.js';
