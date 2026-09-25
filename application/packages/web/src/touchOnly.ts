/** True when the device has no physical keyboard (phone/tablet). */
export function isTouchOnly(): boolean {
  if (typeof navigator === 'undefined') return false;
  return 'ontouchstart' in window && !window.matchMedia('(pointer: fine)').matches;
}
