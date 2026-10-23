/**
 * What a registered device looks like in the Account pane's device list: the
 * operating system behind its logo, the kind of device behind its badge, and
 * whether the version it last reported is below the release floor.
 *
 * Everything is read from the server row. `device_name` is what the device
 * built from its own platform sniff ("macOS", "iPad app", "Desktop app on
 * Windows"), so the OS comes from the name first and from `platform` second.
 *
 * Spec: ops/docs/archive/ui-patterns.md (section 142, Registered devices row)
 */
import policy from '../../desktop/update-policy.json';
import type { DeviceRow } from './devices';
import { knownVersionFloor } from './versionFloor';
import { compareSemver } from './versionCheck';

export type DeviceOs = 'apple' | 'windows' | 'android' | 'linux' | 'chromeos' | 'other';
export type DeviceKind = 'computer' | 'browser' | 'phone' | 'tablet';

export function deviceLook(row: Pick<DeviceRow, 'platform' | 'device_name'>): { os: DeviceOs; kind: DeviceKind } {
  const name = row.device_name.toLowerCase();
  // Android before Linux: an Android name never says Linux, but order the
  // checks so a future "Android (Linux)" name cannot read as a desktop.
  const os: DeviceOs =
    /iphone|ipad|\bios\b|mac/.test(name) ? 'apple'
    : /windows/.test(name) ? 'windows'
    : /android/.test(name) ? 'android'
    : /chrome ?os/.test(name) ? 'chromeos'
    : /linux/.test(name) ? 'linux'
    : row.platform === 'ios' ? 'apple'
    : row.platform === 'android' ? 'android'
    : 'other';
  const kind: DeviceKind =
    row.platform === 'ios' ? (/ipad/.test(name) ? 'tablet' : 'phone')
    : row.platform === 'android' ? 'phone'
    : row.platform === 'desktop' ? 'computer'
    : 'browser';
  return { os, kind };
}

/**
 * The oldest version still allowed to write to the server: the higher of the
 * floor this build shipped with and the floor this channel last fetched. A
 * floor only ever rises, so the bundled one is a safe lower bound on a browser,
 * where no channel reports one.
 */
export function deviceVersionFloor(): string {
  const known = knownVersionFloor();
  return known && compareSemver(known, policy.minVersion) > 0 ? known : policy.minVersion;
}

/** True when a reported version is below the floor. Unknown is not below. */
export function isBelowFloor(version: string | null | undefined, floor: string): boolean {
  return !!version && compareSemver(version, floor) < 0;
}
