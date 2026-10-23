import { PALETTE } from './editorColors';

/**
 * The mood bands, one color per band of the 1 to 10 scale, from the palette
 * of the app. The charts and the mood look of the Journals calendar read it,
 * so a mood is the same color wherever it is painted.
 */
export const MOOD_COLORS = [PALETTE.red, PALETTE.orange, PALETTE.yellow, PALETTE.green, PALETTE.blue] as const;

export function moodColor(mood: number): string {
  if (mood <= 2) return MOOD_COLORS[0];
  if (mood <= 4) return MOOD_COLORS[1];
  if (mood <= 6) return MOOD_COLORS[2];
  if (mood <= 8) return MOOD_COLORS[3];
  return MOOD_COLORS[4];
}
