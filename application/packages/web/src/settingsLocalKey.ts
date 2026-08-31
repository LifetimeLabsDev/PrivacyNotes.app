import { isDemoMode } from './demo';

/**
 * The localStorage key for the settings cache, in its own module so a
 * light module (notesCreated.ts, and through it notesRepo.ts) can reach
 * it without importing the full userSettings chain - that chain pulls
 * theme/i18n, which read browser globals at module load.
 *
 * Demo sessions get their own settings bucket. try.privacynotes.app is
 * already a separate origin, but `?demo=1` runs demo mode on the SAME
 * origin as a real install - without a separate key, real-account
 * settings (folders, prefs) would show up inside the demo and demo
 * seeds would leak back into the account. Mirrors DEMO_DB_NAME.
 */
const LOCAL_KEY = 'privacynotes.settings';
const DEMO_LOCAL_KEY = 'privacynotes.demo.settings';

export function settingsLocalKey(): string {
  return isDemoMode() ? DEMO_LOCAL_KEY : LOCAL_KEY;
}
