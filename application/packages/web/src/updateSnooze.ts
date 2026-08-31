/**
 * 48h dismiss for the two manual-install update toasts (direct APK, Linux .deb).
 *
 * Both channels end in a user-driven download + install, so the only lever we
 * have is the toast itself - which is why it used to be permanent. That made
 * every ordinary patch as loud as a protocol break, on the one platform where
 * updating costs the user data and attention (issue #224). Severity now comes
 * from the release (update-policy.json's minVersion), and anything above the
 * floor can be pushed away for two days.
 *
 * Keyed by the version that was dismissed, never a bare boolean: snoozing
 * v0.305.0 must not also hide v0.306.0, so a genuinely newer release always
 * cuts straight through an active snooze. Required updates never reach here -
 * they render without a dismiss button at all.
 *
 * Spec: ops/docs/android-update-check.md (optional vs required updates)
 */

const KEY = 'privacynotes.updateSnooze';
const SNOOZE_MS = 48 * 60 * 60 * 1000;

type Snoozed = { version: string; until: number };

/** True while `version` is under an unexpired dismissal. */
export function isUpdateSnoozed(version: string): boolean {
  try {
    const raw = localStorage.getItem(KEY);
    if (!raw) return false;
    const s = JSON.parse(raw) as Snoozed;
    return s?.version === version && typeof s?.until === 'number' && Date.now() < s.until;
  } catch {
    // Unparseable or storage blocked: treat as not snoozed. Showing the toast
    // one time too many beats silently swallowing an update prompt forever.
    return false;
  }
}

/** Hide `version` for 48h. A newer version is unaffected. */
export function snoozeUpdate(version: string): void {
  try {
    const s: Snoozed = { version, until: Date.now() + SNOOZE_MS };
    localStorage.setItem(KEY, JSON.stringify(s));
  } catch {
    // Storage full or blocked - the toast just reappears next check.
  }
}
