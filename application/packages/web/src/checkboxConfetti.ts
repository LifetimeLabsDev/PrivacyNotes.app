/**
 * A small burst of confetti from a task checkbox when it is ticked, in the
 * editor and in the Tasks list alike (both use `.pn-task-checkbox`). An
 * untick throws nothing, and neither does a tick with the Settings > Editor
 * switch off: `taskConfetti` in the synced settings, which the signed-in
 * view hands over with `setTaskConfetti`. The confetti code loads on the
 * first tick. Experimental.
 *
 * One `click` listener on the document, in the capture phase. A checkbox
 * already holds its new state when its click is dispatched, and the document
 * hears it before anything else: before React, which puts a controlled box
 * (the Tasks list) back to its old state during the click, so a later
 * `change` reads a tick as an untick; and before the editor moves a ticked
 * task to the bottom of its list. A keyboard toggle is a click too. A
 * read-only editor puts the box back, so it throws nothing.
 */

/** On until the settings say otherwise, so a tick before they load throws. */
let enabled = true;

/** Read at each tick, so the switch applies at once. */
export function setTaskConfetti(on: boolean): void {
  enabled = on;
}

function onClick(e: Event): void {
  const box = e.target;
  if (!(box instanceof HTMLInputElement) || !box.classList.contains('pn-task-checkbox') || !box.checked || !enabled) return;
  if (box.disabled || box.closest('.ProseMirror[contenteditable="false"]')) return;
  const rect = box.getBoundingClientRect();
  void import('./confettiRain').then((m) => m.burstConfetti(rect)).catch(() => {});
}

/** Called once from main.tsx, before React mounts. */
export function installCheckboxConfetti(target: Document = document): void {
  target.addEventListener('click', onClick, true);
}
