/**
 * Re-lock timeout options shared between the Biometric and PIN tabs.
 *
 * "Immediately" (value 0) used to be here but was removed: for
 * PIN-protected notes it would re-prompt on every re-render, and a
 * correct per-note unlock scope would be more complexity than the
 * feature is worth. Users who want a hair-trigger can pick 1 minute.
 *
 * `-1` means "never re-ask for the life of this tab".
 */
export const TIMEOUT_OPTIONS: Array<{ value: number; label: string }> = [
  { value: 1, label: '1 minute' },
  { value: 5, label: '5 minutes' },
  { value: 15, label: '15 minutes' },
  { value: 30, label: '30 minutes' },
  { value: 60, label: '1 hour' },
  { value: 240, label: '4 hours' },
  { value: 480, label: '8 hours' },
  { value: 720, label: '12 hours' },
  { value: -1, label: 'On browser restart' },
];
