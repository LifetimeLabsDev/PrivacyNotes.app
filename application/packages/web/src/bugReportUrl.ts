import { VERSION } from './version';
import { detectPlatform } from './devices';
import { detectDeviceOs } from './deviceFingerprint';

/**
 * Builds the GitHub "new bug report" URL with the version and platform already filled in.
 *
 * Why prefill rather than ask: the bug form's version field is optional and carries no
 * placeholder on purpose, because a pre-filled example version just teaches reporters to
 * accept it without looking, and a confidently wrong version is worse than a blank one. The
 * app already knows the real answer, so it should supply it and let the reporter write prose.
 *
 * GitHub issue forms prefill from query params keyed on each field's `id`, so these keys
 * MUST stay in sync with `ops/github/ISSUE_TEMPLATE/bug_report.yml` (`id: version`,
 * `id: where`). A dropdown value that does not match an option string exactly is silently
 * ignored by GitHub - no error, the field just renders empty - so WHERE_OPTIONS below is a
 * verbatim copy of that file's option list. Change one, change both.
 *
 * Spec: ops/docs/gotchas.md (not every channel auto-updates).
 */

const REPO = 'https://github.com/LifetimeLabsDev/PrivacyNotes.app';

/** Verbatim from bug_report.yml's `Where?` dropdown. Order irrelevant, spelling is not. */
const WHERE_OPTIONS = {
  web: 'In a browser',
  mac: 'Mac app',
  windows: 'Windows app',
  linux: 'Linux app',
  ios: 'iPhone or iPad app',
  androidDirect: 'Android app (downloaded from our site)',
  androidPlay: 'Android app (from Google Play)',
} as const;

function detectWhere(): string | null {
  const platform = detectPlatform();
  if (platform === 'web') return WHERE_OPTIONS.web;
  if (platform === 'ios') return WHERE_OPTIONS.ios;
  if (platform === 'android') {
    // VITE_ANDROID_DIST=direct is baked in at build time by the direct-APK build, the same
    // flag that drives the update toast and the keystore choice, so it is a reliable tell.
    return import.meta.env.VITE_ANDROID_DIST === 'direct'
      ? WHERE_OPTIONS.androidDirect
      : WHERE_OPTIONS.androidPlay;
  }
  // Desktop: split by OS. Anything unrecognized returns null and leaves the dropdown for the
  // reporter rather than guessing wrong.
  const os = detectDeviceOs();
  if (os === 'macOS') return WHERE_OPTIONS.mac;
  if (os === 'Windows') return WHERE_OPTIONS.windows;
  if (os === 'Linux') return WHERE_OPTIONS.linux;
  return null;
}

export function bugReportUrl(): string {
  const params = new URLSearchParams({ template: 'bug_report.yml', version: VERSION });
  const where = detectWhere();
  if (where) params.set('where', where);
  return `${REPO}/issues/new?${params.toString()}`;
}
