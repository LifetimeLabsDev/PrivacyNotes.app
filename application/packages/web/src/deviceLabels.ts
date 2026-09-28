/**
 * Device labels: the name a person gives a registered device, kept in the
 * encrypted settings blob as `deviceLabels`, one register per device id.
 *
 * The label never goes to the server's `device_name` column. That column is
 * plaintext, and `register-device` writes it again from the platform sniff on
 * every registration, so a label kept there would be readable by the server
 * and gone within a day. Here it is encrypted, it syncs to every device, and
 * it merges per device like the folder and tag looks (registers.ts).
 *
 * The map is its own settings field, not a key kind inside `itemStyles`:
 * the looks travel into backups and the JSON export, and a device name has
 * no place in either.
 *
 * Removing a device leaves its label alone. A removed web install that signs
 * in again comes back under the same id and finds its name, and a label for
 * a device that is gone costs a few bytes that nothing shows. Pruning by the
 * server's device list would turn one failed or partial list read into a
 * deletion that travels to every device.
 *
 * Spec: ops/docs/design-decisions.md (device labels live in the settings blob)
 */
import {
  mergeRegisterMaps,
  registerMapsEqual,
  stampAfter,
  validateRegisterMap,
  type RegisterMap,
} from './registers';

export type DeviceLabels = RegisterMap;

/** Longest label the rename field accepts. */
export const DEVICE_LABEL_MAX = 40;

/** A device id: hex from `deriveDeviceId`, with room for older forms. */
const DEVICE_ID_PATTERN = /^[A-Za-z0-9_-]{1,128}$/;
const idOk = (id: string) => DEVICE_ID_PATTERN.test(id);

/** Sanitize a raw map from a settings blob. */
export function validateDeviceLabels(raw: unknown, now = Date.now()): DeviceLabels {
  return validateRegisterMap(raw, idOk, DEVICE_LABEL_MAX, now);
}

export function mergeDeviceLabels(local: DeviceLabels, remote: DeviceLabels, now = Date.now()): DeviceLabels {
  return mergeRegisterMaps(local, remote, now);
}

export const deviceLabelsEqual = registerMapsEqual;

/** The label of one device, or null when it has none. */
export function deviceLabelOf(labels: DeviceLabels, deviceId: string): string | null {
  return labels[deviceId]?.v ?? null;
}

/**
 * The one writer. Trims the name; an empty name, or the device's own server
 * name, resets it. An unchanged value comes back as the same object, so a
 * settings write that changes nothing is a no-op.
 */
export function setDeviceLabel(
  labels: DeviceLabels,
  deviceId: string,
  name: string,
  serverName: string,
): DeviceLabels {
  if (!idOk(deviceId)) return labels;
  const trimmed = name.trim().slice(0, DEVICE_LABEL_MAX);
  const v = trimmed === '' || trimmed === serverName ? null : trimmed;
  const prev = labels[deviceId];
  if ((prev?.v ?? null) === v) return labels;
  // No register and a reset: nothing to write.
  if (!prev && v === null) return labels;
  return { ...labels, [deviceId]: { v, at: stampAfter(prev?.at) } };
}
