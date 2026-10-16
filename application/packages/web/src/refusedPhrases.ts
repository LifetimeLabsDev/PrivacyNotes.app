import { bytesToHex, deriveSigningKey, phraseToSeed } from '@notes/shared';

/**
 * Public keys of phrases that are printed in public: the demo's own phrase
 * and the BIP-39 test vectors that wallet docs and developer tools publish.
 * Anyone can type one of these, so an account under it would be readable by
 * everyone. The server refuses the same list (packages/supabase/functions/
 * _shared/refusedPubkeys.ts), which also covers older clients; this copy only lets sign-in say why before any
 * network call. tests/refusedPhrases.test.ts derives both lists from the
 * phrases and fails when they drift.
 */
export const REFUSED_PUBKEYS: ReadonlySet<string> = new Set([
  'd17e432722fd2da0334dc89e653f70726cf4b948b8d31619490ab86075a31a85',
  '2afedefee0719222cba82aa7541fc5edb2c198ec4e6259462da2989f53287314',
  '576b06513b6cd9d64e964a24101c10084342213c49b0c1c33bcb1b784aa47ec1',
  '4f4e8e56804f1511ea4dd4c9cf9874cb4064db7ea7b2b9e3ec89090dca26f092',
  'b0ca2fb2a5e441c2ba394f8aed3373de4445ad977199de810a2d97df62474487',
  'c3bb329c684881c4fd68257b052a70fc5a35bcea24096a3a5c9dcfc31218fb03',
  '57b278eb833d9ee6391494d076d08f78337810e4cbe5710f62b3d394a924929f',
  '4a496951cbe159eb5acb433150d80c1dddb5b3e3ed0a16f32803b98975cc4793',
  '09d4965f6ae9924baa07cd5aa61e7a11d6e1aa3ce48dc6282811c3824f3c5a10',
  '2b0a159a4a5b0cd0cab483fdadc9f44562ab42ef04c4136bf2e0c8020f8ca442',
]);

/** True when a valid phrase derives one of the refused public keys. */
export async function isRefusedPhrase(phrase: string): Promise<boolean> {
  const { publicKey } = await deriveSigningKey(phraseToSeed(phrase));
  return REFUSED_PUBKEYS.has(bytesToHex(publicKey));
}
