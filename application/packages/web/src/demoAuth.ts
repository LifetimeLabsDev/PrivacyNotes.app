import {
  phraseToSeed,
  deriveSigningKey,
  deriveEncryptionKey,
  deriveFpPepper,
  bytesToHex,
} from '@notes/shared';
import { clearLocalDatabase } from './notesRepo';
import { clearLocalSettings, loadLocalSettings, saveLocalSettings } from './userSettings';
import { DEMO_PHRASE, demoSessionIsFresh } from './demo';
import { seedOnboardingNotes, SEED_MEDICATION } from './welcomeNote';
import type { AuthState } from './auth';

export async function buildDemoAuthState(): Promise<AuthState> {
  const seed = phraseToSeed(DEMO_PHRASE);
  const { privateKey, publicKey } = await deriveSigningKey(seed);
  const encryptionKey = deriveEncryptionKey(seed);
  const fpPepper = deriveFpPepper(seed);
  const pubkey = bytesToHex(publicKey);
  // Fresh tab session → clean slate; an in-tab refresh keeps edits.
  // Settings live in a demo-only localStorage bucket (see
  // userSettings.ts localKey) and reset alongside the notes so
  // every fresh session starts from defaults.
  if (demoSessionIsFresh()) {
    await clearLocalDatabase();
    clearLocalSettings();
  }
  await seedOnboardingNotes(pubkey); // idempotent
  // Seed the example medication template so the wellness pill
  // renders, mirroring the first-run flow in NotesView.
  const s = loadLocalSettings();
  if (!s.medications?.some((m) => m.id === SEED_MEDICATION.id)) {
    saveLocalSettings({
      ...s,
      medications: [...(s.medications ?? []), SEED_MEDICATION],
    });
  }
  return {
    status: 'authenticated',
    method: 'phrase',
    phrase: DEMO_PHRASE,
    pubkey,
    encryptionKey,
    signingPrivateKey: privateKey,
    fpPepper,
    deviceId: 'demo',
    isPro: false,
    isEarlySupporter: false,
    isCustodial: false,
  };
}
