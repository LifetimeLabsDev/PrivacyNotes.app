/**
 * Known-answer tests for the crypto core.
 *
 * WHY THIS EXISTS
 * ---------------
 * Every key in PrivacyNotes descends from one 12-word phrase through a fixed
 * derivation path. If that path ever shifts by a byte, existing users do not get an
 * error: they get a different key, their vault silently fails to decrypt, and the app
 * looks like it lost their notes. `tsc` cannot see that. A build passing cannot see
 * that. Only a fixed input with a fixed expected output can see that.
 *
 * So these are known-answer tests (KATs), not unit tests. Every expectation below is a
 * literal, and a literal changing is the alarm. They exist mainly so that upgrading
 * @noble/@scure is a verified ten-minute job instead of a leap of faith over
 * every user's data.
 *
 * ZERO DEPENDENCIES ON PURPOSE
 * ----------------------------
 * Uses node:test and node:assert, built into Node 22, and imports the already-compiled
 * packages/shared/dist. No vitest, no jest, no config, nothing new in the lockfile, and
 * no bundler: it runs anywhere Node runs, including CI and a sandbox.
 *
 *   pnpm --filter shared build && node --test tools/crypto-kat.mjs
 *
 * IF A VECTOR FAILS
 * -----------------
 * Do NOT update the literal to match the new output. That is the test working. A changed
 * vector means the derivation changed, which means every existing vault is now
 * undecryptable. Find out why it moved. The only legitimate reason to edit a vector is a
 * deliberate, versioned migration of the derivation itself, and that needs a plan for
 * everyone already holding a phrase.
 *
 * Spec: ops/docs/THREAT_MODEL.md (cryptographic design), ops/docs/dependency-migration.md
 */

import test from 'node:test';
import assert from 'node:assert/strict';
import {
  generatePhrase,
  isValidPhrase,
  phraseToSeed,
  deriveSigningKey,
  deriveEncryptionKey,
  deriveLocalDataKey,
  deriveAuthPassword,
  authEmailForPubkey,
  signLinkChallenge,
  deriveDeviceId,
  signDeviceRegisterChallenge,
  signDeviceRevokeChallenge,
  deriveFpPepper,
  computeFpHashes,
  bytesToHex,
  hexToBytes,
  bytesToBase64,
  base64ToBytes,
  bytesToBase64url,
  base64urlToBytes,
  encryptNote,
  decryptNote,
  encryptJson,
  decryptJson,
} from '../packages/shared/dist/index.js';

/**
 * The canonical BIP-39 test phrase. Deliberately the all-zeros-entropy vector from the
 * BIP-39 spec, so the seed below is independently checkable against any other BIP-39
 * implementation on earth rather than only against ourselves.
 */
const PHRASE =
  'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about';

/** Second phrase, to prove different phrases produce unrelated keys. */
const PHRASE_2 =
  'legal winner thank year wave sausage worth useful legal winner thank yellow';

// ------------------------------------------------------------------------------------
// BIP-39: phrase to seed
// ------------------------------------------------------------------------------------

test('phraseToSeed matches the published BIP-39 vector', () => {
  // BIP-39 with an EMPTY passphrase, i.e. PBKDF2-HMAC-SHA512(mnemonic, "mnemonic", 2048, 64).
  // Independently reproducible without any of our code:
  //
  //   python3 -c "import hashlib;print(hashlib.pbkdf2_hmac('sha512',
  //     b'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon about',
  //     b'mnemonic', 2048, 64).hex())"
  //
  // Note the trap: the BIP-39 spec's own published vector table uses the passphrase
  // "TREZOR" and gives c55257c3... for this same mnemonic. We use no passphrase, so ours
  // is 5eb00bbd.... Do not "correct" this to the c55257c3 value; that would be testing a
  // configuration we do not ship.
  //
  // If this line fails, @scure/bip39 is no longer producing standard BIP-39 seeds and
  // NOTHING below it can be trusted.
  assert.equal(
    bytesToHex(phraseToSeed(PHRASE)),
    '5eb00bbddcf069084889a8ab9155568165f5c453ccb85e70811aaed6f6da5fc19a5ac40b389cd370d086206dec8aa6c43daea6690f20ad3d8d48b2d2ce9e38e4',
  );
});

test('phraseToSeed is insensitive to case and surrounding whitespace', () => {
  const canonical = bytesToHex(phraseToSeed(PHRASE));
  assert.equal(bytesToHex(phraseToSeed(`  ${PHRASE}  `)), canonical);
  assert.equal(bytesToHex(phraseToSeed(PHRASE.toUpperCase())), canonical);
});

test('isValidPhrase enforces the BIP-39 checksum', () => {
  assert.equal(isValidPhrase(PHRASE), true);
  assert.equal(isValidPhrase(PHRASE.toUpperCase()), true);
  // Real words, wrong checksum.
  assert.equal(
    isValidPhrase(
      'abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon abandon',
    ),
    false,
  );
  assert.equal(isValidPhrase('not actually a mnemonic at all'), false);
  assert.equal(isValidPhrase(''), false);
});

test('generatePhrase produces 12 valid words with real entropy', () => {
  const a = generatePhrase();
  assert.equal(a.split(' ').length, 12);
  assert.equal(isValidPhrase(a), true);
  // Not a proof of randomness, but catches a stub or a constant.
  assert.notEqual(a, generatePhrase());
});

// ------------------------------------------------------------------------------------
// HKDF key derivation. These two vectors are the load-bearing ones: the encryption key
// IS the vault, and the signing pubkey IS the account identifier.
// ------------------------------------------------------------------------------------

// The vault key. If this literal changes, every existing note on every device becomes
// undecryptable. There is no error path for that: it just looks like the data is gone.
// = HKDF-SHA256(ikm=seed, salt=undefined, info="privacynotes-encryption-v1", len=32)
test('deriveEncryptionKey is stable (vault key)', async () => {
  const seed = phraseToSeed(PHRASE);
  assert.equal(
    bytesToHex(deriveEncryptionKey(seed)),
    'e827f1e4e1a8f5dc6737db8d22b75d1039792c8e9d2e6a4ba21fd87b57835520',
  );
});

// The account identity. If the public key changes, the server no longer recognises the
// user: the pubkey IS the account, so a shifted derivation orphans the vault server-side.
// = HKDF-SHA256(ikm=seed, salt=undefined, info="privacynotes-signing-v1", len=32), then
//   ed25519 public key from that.
test('deriveSigningKey is stable (account identity)', async () => {
  const seed = phraseToSeed(PHRASE);
  const { privateKey, publicKey } = await deriveSigningKey(seed);
  assert.equal(privateKey.length, 32);
  assert.equal(publicKey.length, 32);
  assert.equal(
    bytesToHex(privateKey),
    '81cb6c164a396f151202dafdf22a3ecebbe2d27c9fd21e89e9f69097da0cd056',
  );
  assert.equal(
    bytesToHex(publicKey),
    'd17e432722fd2da0334dc89e653f70726cf4b948b8d31619490ab86075a31a85',
  );
});

// The local-data key seals note content at rest on the device. If this literal changes,
// every sealed local row on every device fails authentication on its next read: synced
// notes silently re-pull from the server, but dirty local-only rows have no other copy.
// = HKDF-SHA256(ikm=seed, salt=undefined, info="privacynotes-local-at-rest-v1", len=32)
test('deriveLocalDataKey is stable (local at-rest key)', () => {
  const seed = phraseToSeed(PHRASE);
  assert.equal(
    bytesToHex(deriveLocalDataKey(seed)),
    'd40b56f05f980fc683c5a04bad0db01e10ba9cf4f0add8412f8944f219ac7c2c',
  );
});

// The session credential. Drift here does not lose data, but it fails SILENTLY: password
// sign-in returns invalid_credentials, the client quietly falls back to minting a new
// anonymous auth user per re-mint, and the per-IP rate limit that path exists to retire
// starts biting again. Nothing errors; the regression is only visible in auth traffic.
// = hex(HKDF-SHA256(ikm=seed, salt=undefined, info="privacynotes-auth-password-v1", len=32))
test('deriveAuthPassword is stable (session credential)', () => {
  const seed = phraseToSeed(PHRASE);
  assert.equal(
    deriveAuthPassword(seed),
    'bd0b564a6d6546985d34057b30fe6877b3b6e3a56ffe670b17f6feb58bf902e2',
  );
});

// The sign-in identifier is a contract with the link-pubkey edge function, which derives
// the same address server-side from the verified pubkey. Case matters: GoTrue lowercases
// emails on write, so a case drift signs in to a user that does not exist.
test('authEmailForPubkey is lowercase and pinned to the credential domain', () => {
  assert.equal(
    authEmailForPubkey('D17E432722FD2DA0334DC89E653F70726CF4B948B8D31619490AB86075A31A85'),
    'd17e432722fd2da0334dc89e653f70726cf4b948b8d31619490ab86075a31a85@phrase.privacynotes.app',
  );
});

test('the derived keys are different (domain separation actually separates)', async () => {
  const seed = phraseToSeed(PHRASE);
  const enc = deriveEncryptionKey(seed);
  const local = deriveLocalDataKey(seed);
  const { privateKey } = await deriveSigningKey(seed);
  assert.notEqual(bytesToHex(enc), bytesToHex(privateKey));
  assert.notEqual(deriveAuthPassword(seed), bytesToHex(enc));
  assert.notEqual(deriveAuthPassword(seed), bytesToHex(privateKey));
  assert.notEqual(bytesToHex(local), bytesToHex(enc));
  assert.notEqual(bytesToHex(local), bytesToHex(privateKey));
  assert.notEqual(bytesToHex(local), deriveAuthPassword(seed));
});

test('a different phrase yields unrelated keys', async () => {
  const a = phraseToSeed(PHRASE);
  const b = phraseToSeed(PHRASE_2);
  assert.notEqual(bytesToHex(deriveEncryptionKey(a)), bytesToHex(deriveEncryptionKey(b)));
  assert.notEqual(bytesToHex(deriveLocalDataKey(a)), bytesToHex(deriveLocalDataKey(b)));
  const ka = await deriveSigningKey(a);
  const kb = await deriveSigningKey(b);
  assert.notEqual(bytesToHex(ka.publicKey), bytesToHex(kb.publicKey));
});

test('derivation is deterministic across calls (same phrase, same vault, every device)', async () => {
  const s1 = phraseToSeed(PHRASE);
  const s2 = phraseToSeed(PHRASE);
  assert.equal(bytesToHex(deriveEncryptionKey(s1)), bytesToHex(deriveEncryptionKey(s2)));
  const k1 = await deriveSigningKey(s1);
  const k2 = await deriveSigningKey(s2);
  assert.equal(bytesToHex(k1.publicKey), bytesToHex(k2.publicKey));
});

// ------------------------------------------------------------------------------------
// Challenge signing. The server verifies these, so the exact message bytes are a
// contract with the edge functions, not an implementation detail.
// ------------------------------------------------------------------------------------

test('signLinkChallenge is deterministic and bound to the auth uid', async () => {
  const { privateKey } = await deriveSigningKey(phraseToSeed(PHRASE));
  const a = await signLinkChallenge(privateKey, 'auth-uid-1');
  const b = await signLinkChallenge(privateKey, 'auth-uid-1');
  const c = await signLinkChallenge(privateKey, 'auth-uid-2');
  assert.equal(a.length, 64);
  // ed25519 is deterministic: same key + same message = byte-identical signature.
  assert.equal(bytesToHex(a), bytesToHex(b));
  // A signature for one session must not be replayable into another.
  assert.notEqual(bytesToHex(a), bytesToHex(c));
});

test('device register and revoke challenges are distinct messages', async () => {
  const { privateKey } = await deriveSigningKey(phraseToSeed(PHRASE));
  const reg = await signDeviceRegisterChallenge(privateKey, 'uid', 'device-a');
  const rev = await signDeviceRevokeChallenge(privateKey, 'uid', 'device-a');
  // Same key, same uid, same device: if these collided, a register signature could be
  // replayed as a revoke.
  assert.notEqual(bytesToHex(reg), bytesToHex(rev));
});

// ------------------------------------------------------------------------------------
// Device identity
// ------------------------------------------------------------------------------------

test('deriveDeviceId is stable, 32 hex chars, and scoped per pubkey', () => {
  const secret = hexToBytes('11'.repeat(32));
  const idA = deriveDeviceId('pubkey-aaa', secret);
  const idB = deriveDeviceId('pubkey-bbb', secret);
  assert.equal(idA.length, 32);
  assert.match(idA, /^[0-9a-f]{32}$/);
  assert.equal(deriveDeviceId('pubkey-aaa', secret), idA, 'must be idempotent');
  // Two accounts sharing one machine must not share a device id.
  assert.notEqual(idA, idB);
});

// ------------------------------------------------------------------------------------
// Fingerprint pepper and hashes. The privacy claim in SECURITY.md is that the server
// cannot reverse these and cannot correlate a device across accounts.
// ------------------------------------------------------------------------------------

test('deriveFpPepper is per-user and distinct from the other derived keys', () => {
  const seed = phraseToSeed(PHRASE);
  const pepper = deriveFpPepper(seed);
  assert.equal(pepper.length, 32);
  assert.notEqual(bytesToHex(pepper), bytesToHex(deriveEncryptionKey(seed)));
  assert.notEqual(bytesToHex(pepper), bytesToHex(deriveFpPepper(phraseToSeed(PHRASE_2))));
});

test('computeFpHashes: same hardware, different accounts, uncorrelatable', () => {
  const fp = { platform: 'macOS', gpu: 'Apple M4', cores: 10, language: 'en-US' };
  const a = computeFpHashes(deriveFpPepper(phraseToSeed(PHRASE)), fp);
  const b = computeFpHashes(deriveFpPepper(phraseToSeed(PHRASE_2)), fp);
  // This is the SECURITY.md claim, asserted: identical hardware under two accounts must
  // produce unrelated hashes, or the server could link them.
  assert.notEqual(a.platform_hash, b.platform_hash);
  assert.notEqual(a.gpu_hash, b.gpu_hash);
});

test('computeFpHashes: field prefixes prevent cross-field collisions', () => {
  const pepper = deriveFpPepper(phraseToSeed(PHRASE));
  // Same value in two different fields must not hash the same.
  const h = computeFpHashes(pepper, { platform: 'x', gpu: 'x', cores: 0, language: 'x' });
  assert.notEqual(h.platform_hash, h.gpu_hash);
  assert.notEqual(h.platform_hash, h.language_hash);
});

test('computeFpHashes: unavailable GPU degrades to null, not to a hash of "unknown"', () => {
  const pepper = deriveFpPepper(phraseToSeed(PHRASE));
  assert.equal(
    computeFpHashes(pepper, { platform: 'Linux', gpu: 'unknown', cores: 4, language: 'de' }).gpu_hash,
    null,
  );
  assert.equal(
    computeFpHashes(pepper, { platform: 'Linux', gpu: '', cores: 4, language: 'de' }).gpu_hash,
    null,
  );
});

// ------------------------------------------------------------------------------------
// Encoding helpers. Boring, but hexToBytes feeds key material, so a silent NaN here
// would be a very bad day.
// ------------------------------------------------------------------------------------

test('hex round-trips and rejects malformed input', () => {
  const bytes = new Uint8Array([0, 1, 15, 16, 127, 128, 255]);
  assert.equal(bytesToHex(bytes), '00010f107f80ff');
  assert.deepEqual(base64ToBytes(bytesToBase64(bytes)), bytes);
  assert.deepEqual(hexToBytes(bytesToHex(bytes)), bytes);
  assert.throws(() => hexToBytes('abc'), /odd-length/i);
});

test('base64 and base64url round-trip, and base64url is URL-safe', () => {
  // 0xfb 0xff forces the + and / characters in standard base64.
  const bytes = new Uint8Array([251, 255, 190, 239]);
  assert.deepEqual(base64ToBytes(bytesToBase64(bytes)), bytes);
  assert.deepEqual(base64urlToBytes(bytesToBase64url(bytes)), bytes);
  const url = bytesToBase64url(bytes);
  assert.ok(!url.includes('+') && !url.includes('/') && !url.includes('='), `not url-safe: ${url}`);
});

// ------------------------------------------------------------------------------------
// Note encryption. This is the actual product promise.
// ------------------------------------------------------------------------------------

const NOTE = {
  title: 'Título with ünicode 🔐',
  body: '# Heading\n\nBody with a [[note-link]] and emoji 🎉',
  tags: ['work', 'privé'],
  trashed: false,
  starred: true,
  locked: false,
  pinProtected: false,
  type: 'note',
  folderId: null,
};

test('encryptNote round-trips, unicode intact', () => {
  const key = deriveEncryptionKey(phraseToSeed(PHRASE));
  const { ciphertext, nonce } = encryptNote(NOTE, key);
  const out = decryptNote(ciphertext, nonce, key);
  assert.equal(out.title, NOTE.title);
  assert.equal(out.body, NOTE.body);
  assert.deepEqual(out.tags, NOTE.tags);
  assert.equal(out.starred, true);
});

test('encryptNote uses a fresh 24-byte nonce every time', () => {
  const key = deriveEncryptionKey(phraseToSeed(PHRASE));
  const a = encryptNote(NOTE, key);
  const b = encryptNote(NOTE, key);
  assert.equal(a.nonce.length, 24, '24 bytes is what makes random nonces safe here');
  // Identical plaintext under a reused nonce would leak; these must differ.
  assert.notEqual(bytesToHex(a.nonce), bytesToHex(b.nonce));
  assert.notEqual(bytesToHex(a.ciphertext), bytesToHex(b.ciphertext));
});

test('ciphertext does not leak plaintext', () => {
  const key = deriveEncryptionKey(phraseToSeed(PHRASE));
  const { ciphertext } = encryptNote(NOTE, key);
  const asText = Buffer.from(ciphertext).toString('utf8');
  assert.ok(!asText.includes('Heading'), 'plaintext found in ciphertext');
  assert.ok(!asText.includes('work'), 'tag found in ciphertext');
});

test('decryptNote rejects the wrong key (Poly1305 authenticates)', () => {
  const key = deriveEncryptionKey(phraseToSeed(PHRASE));
  const wrong = deriveEncryptionKey(phraseToSeed(PHRASE_2));
  const { ciphertext, nonce } = encryptNote(NOTE, key);
  assert.throws(() => decryptNote(ciphertext, nonce, wrong));
});

test('decryptNote rejects tampered ciphertext (this is the server-cannot-lie property)', () => {
  const key = deriveEncryptionKey(phraseToSeed(PHRASE));
  const { ciphertext, nonce } = encryptNote(NOTE, key);
  const tampered = Uint8Array.from(ciphertext);
  tampered[0] ^= 0x01; // flip one bit
  assert.throws(() => decryptNote(tampered, nonce, key));
});

test('decryptNote rejects a swapped nonce', () => {
  const key = deriveEncryptionKey(phraseToSeed(PHRASE));
  const a = encryptNote(NOTE, key);
  const b = encryptNote(NOTE, key);
  assert.throws(() => decryptNote(a.ciphertext, b.nonce, key));
});

test('decryptNote defaults missing fields for old ciphertexts', () => {
  // A pre-v0.4.0 payload: no trashed/starred/locked/pinProtected/type.
  const key = deriveEncryptionKey(phraseToSeed(PHRASE));
  const { ciphertext, nonce } = encryptJson({ title: 'old', body: 'note', tags: [] }, key);
  const out = decryptNote(ciphertext, nonce, key);
  assert.equal(out.trashed, false);
  assert.equal(out.starred, false);
  assert.equal(out.locked, false);
  assert.equal(out.pinProtected, false);
  assert.equal(out.type, 'note');
  assert.equal(out.folderId, null);
});

test('encryptJson round-trips arbitrary settings blobs', () => {
  const key = deriveEncryptionKey(phraseToSeed(PHRASE));
  const value = { favoriteTags: ['a', 'b'], nested: { n: 1, ok: true }, nul: null };
  const { ciphertext, nonce } = encryptJson(value, key);
  assert.deepEqual(decryptJson(ciphertext, nonce, key), value);
});
