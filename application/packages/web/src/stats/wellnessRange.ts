import type { RangeId } from '../wellnessTypes';

/** The range presets of Statistics > Trackers and its export tab. */
export const RANGE_IDS: RangeId[] = ['7d', '14d', '30d', '3mo', '6mo', '12mo', 'all'];
// Per-device view preference, like the Writing tab's range; not synced.
const RANGE_KEY = 'pn-wellness-range';

/** The range last picked on this device, or null on a first open. */
export function savedWellnessRange(): RangeId | null {
  try {
    const saved = localStorage.getItem(RANGE_KEY);
    if (saved && RANGE_IDS.includes(saved as RangeId)) return saved as RangeId;
  } catch { /* localStorage unavailable */ }
  return null;
}

export function readWellnessRange(): RangeId {
  return savedWellnessRange() ?? 'all';
}

export function writeWellnessRange(id: RangeId): void {
  try { localStorage.setItem(RANGE_KEY, id); } catch { /* ignore */ }
}
