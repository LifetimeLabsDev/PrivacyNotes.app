import type { DeviceRow } from './devices';

/**
 * One server-side device slot: every active row that shares a
 * `device_group`. The key is the expression the `count_device_slots` RPC
 * counts, `COALESCE(device_group, device_id)`, so this list and the
 * free-tier cap agree on what one device is. A slot can hold several rows:
 * a browser on the same machine after a cache clear, a reinstalled app, or
 * two machines the fingerprint could not tell apart. Removal therefore
 * works per row, and a whole-slot removal is an explicit second action.
 * Spec: ops/docs/design-decisions.md (device removal is per row)
 */
export type DeviceSlot = {
  key: string;
  /** The most recent `last_seen_at` across the slot's rows. */
  lastSeenAt: string;
  /** True when one of the rows is this install. */
  isSelf: boolean;
  /** Active rows, most recently seen first. Never empty: a slot exists because a row does. */
  rows: [DeviceRow, ...DeviceRow[]];
};

export function slotKey(row: DeviceRow): string {
  return row.device_group ?? row.device_id;
}

/** Enough of a device id to tell two identically named rows apart on screen. */
export function shortDeviceId(deviceId: string): string {
  return deviceId.slice(0, 6);
}

const newestFirst = (a: string, b: string) => new Date(b).getTime() - new Date(a).getTime();

/** Group active rows into slots. Revoked rows are skipped; they belong to the cooldown list. */
export function groupDeviceSlots(rows: DeviceRow[], selfDeviceId: string | null): DeviceSlot[] {
  const slots = new Map<string, DeviceSlot>();
  for (const row of rows) {
    if (row.revoked_at) continue;
    const key = slotKey(row);
    const isSelf = row.device_id === selfDeviceId;
    const slot = slots.get(key);
    if (!slot) {
      slots.set(key, { key, lastSeenAt: row.last_seen_at, isSelf, rows: [row] });
      continue;
    }
    slot.rows.push(row);
    if (isSelf) slot.isSelf = true;
    if (newestFirst(slot.lastSeenAt, row.last_seen_at) > 0) slot.lastSeenAt = row.last_seen_at;
  }
  const out = Array.from(slots.values());
  for (const slot of out) slot.rows.sort((a, b) => newestFirst(a.last_seen_at, b.last_seen_at));
  return out.sort((a, b) => newestFirst(a.lastSeenAt, b.lastSeenAt));
}
