/**
 * Contents of the downloadable recovery-phrase file. The onboarding screen
 * and the security pane both write it, so the layout lives in one place.
 * Saving stays with the callers: the file decrypts the whole vault, so each
 * one keeps it away from `navigator.share`.
 */

export const PHRASE_FILE_NAME = 'privacynotes-recovery-phrase.txt';

/**
 * The words appear twice by design. The numbered list is for reading and
 * for copying onto paper; the single line under it is the only form the
 * sign-in field accepts, because BIP-39 validation splits the input on
 * single spaces and rejects a paste that carries numbering or line breaks.
 */
export function buildPhraseFile(
  phrase: string,
  strings: { title: string; oneLine: string; footer: string },
): string {
  return [
    strings.title,
    '',
    ...phrase.split(' ').map((w, i) => `${i + 1}. ${w}`),
    '',
    strings.oneLine,
    phrase,
    '',
    strings.footer,
    '',
  ].join('\n');
}
