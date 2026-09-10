/**
 * Re-lock timeout options shared between the Biometric and PIN tabs.
 *
 * "Immediately" (value 0) used to be here but was removed: for
 * PIN-protected notes it would re-prompt on every re-render, and a
 * correct per-note unlock scope would be more complexity than the
 * feature is worth. Users who want a hair-trigger can pick 1 minute.
 *
 * `-1` means "never re-ask for the life of this tab".
 *
 * Labels are keys rather than text: both call sites already hold the
 * `security` namespace, so each one resolves its own option list.
 */
export const TIMEOUT_OPTIONS: Array<{ value: number; labelKey: string }> = [
  { value: 1, labelKey: 'timeout.min1' },
  { value: 5, labelKey: 'timeout.min5' },
  { value: 15, labelKey: 'timeout.min15' },
  { value: 30, labelKey: 'timeout.min30' },
  { value: 60, labelKey: 'timeout.hour1' },
  { value: 240, labelKey: 'timeout.hour4' },
  { value: 480, labelKey: 'timeout.hour8' },
  { value: 720, labelKey: 'timeout.hour12' },
  { value: -1, labelKey: 'timeout.browserRestart' },
];
