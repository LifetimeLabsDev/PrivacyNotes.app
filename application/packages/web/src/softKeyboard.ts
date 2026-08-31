/**
 * On-screen keyboard control for touch devices.
 *
 * Android Chrome raises the IME whenever a tap lands inside a contenteditable
 * that ALREADY holds focus, no matter what our handlers do. Skipping
 * `.focus()` therefore only helps while the editor is unfocused, which is why
 * the v0.223.5 checkbox fix looked complete and wasn't: dismiss the keyboard
 * with the Back button, leave the caret blinking, tap a checkbox, and it slides
 * straight back up.
 *
 * Setting `inputmode="none"` on the element suppresses the IME without moving
 * focus, so the caret and the selection survive. Removing the attribute again
 * does not re-open the keyboard by itself - the next ordinary tap does. That
 * makes it safe to arm for a single gesture and drop.
 *
 * Verified on a Pixel 10 / Android 16 against `dumpsys input_method`
 * (`mInputShown`): checkbox toggle, long-press-to-paste (selection handles and
 * the Cut/Copy/Paste bubble still appear, and Paste still inserts), and the
 * toolbar undo/redo buttons all stop raising the keyboard, while an ordinary
 * tap still opens it.
 *
 * One refinement on top (#223 follow-up): a long press ON TEXT is selection
 * intent - the user is grabbing a word to delete or replace it, and the very
 * next thing they reach for is Backspace. Suppressing there strands them with
 * a selection and no keys. So the guard hit-tests the touch point and only
 * suppresses when the press lands on empty space (paste intent, or an
 * accidental press - the two cases #223 reported).
 *
 * Fix: GitHub #153 (checkbox toggle), #222 (undo/redo), #223 (long press)
 */

/**
 * True on touch-first devices (phones, tablets) where moving focus into a
 * contenteditable pops the on-screen keyboard. Mirrors the `(hover: none)`
 * heuristic the toolbar / code-block copy button already use. Deliberately
 * NOT `useIsMobile()`, which is a width test: a desktop window narrowed below
 * `lg` is "mobile" by that measure but still has a hardware keyboard.
 */
export function isSoftKeyboardDevice(): boolean {
  try {
    return window.matchMedia('(hover: none)').matches;
  } catch {
    return false;
  }
}

/**
 * How long `inputmode="none"` stays on after a suppressed gesture. Long enough
 * to outlast Chrome's own show-keyboard decision, which trails the tap by a
 * frame or two, and short enough that the next deliberate tap types normally.
 * Spec: ops/docs/design-decisions.md (Soft keyboard suppression)
 */
const RESTORE_MS = 400;

let restoreTimer: number | null = null;
let suppressed: HTMLElement | null = null;

/**
 * Suppress the on-screen keyboard for the gesture happening right now. No-op
 * with a hardware keyboard.
 *
 * Call it as the gesture starts (a touchstart handler), not after: the
 * attribute has to be in place before the browser decides to show the IME.
 * A touch screen only reports one gesture at a time, so a single pending
 * restore is enough - a second call re-arms the same window.
 */
export function suppressSoftKeyboard(el: HTMLElement | null | undefined): void {
  if (!el || !isSoftKeyboardDevice()) return;
  if (restoreTimer !== null) {
    window.clearTimeout(restoreTimer);
    // A different element may still be holding the attribute if the previous
    // gesture landed elsewhere (editor, then title). Put it back either way.
    if (suppressed && suppressed !== el) suppressed.removeAttribute('inputmode');
  }
  suppressed = el;
  el.setAttribute('inputmode', 'none');
  restoreTimer = window.setTimeout(() => {
    el.removeAttribute('inputmode');
    restoreTimer = null;
    suppressed = null;
  }, RESTORE_MS);
}

/**
 * How long a touch has to stay put before we treat it as a long press. Under
 * Android's own long-press threshold (~500ms) on purpose, so the suppression
 * is already in place by the time the gesture is recognized, and far above an
 * ordinary tap (50-150ms) so typing is unaffected.
 * Spec: ops/docs/design-decisions.md (Soft keyboard suppression)
 */
const LONG_PRESS_MS = 350;

/**
 * Horizontal/vertical slop around a character's box when deciding whether a
 * long press landed on text. Fingers are imprecise; a press a few pixels off
 * a word still means that word. Kept small on purpose: the caret lookup
 * below snaps to the NEAREST text position, so without a tight box check a
 * press half a screen below the last line would still count as "on text".
 * Spec: ops/docs/design-decisions.md (Soft keyboard suppression)
 */
const TEXT_HIT_SLOP_PX = 12;

/**
 * Did the touch land on actual text, as opposed to empty space? Selection
 * intent vs paste intent, for the long-press guard: a press on a word selects
 * it and the user's next stop is Backspace, so the keyboard is wanted; a
 * press on empty space means the Paste bubble (or nothing at all), so it
 * is not.
 */
function pressOnText(x: number, y: number): boolean {
  let node: Node | null = null;
  let offset = 0;
  const doc = document as Document & {
    caretPositionFromPoint?: (x: number, y: number) => { offsetNode: Node; offset: number } | null;
    caretRangeFromPoint?: (x: number, y: number) => Range | null;
  };
  try {
    if (doc.caretPositionFromPoint) {
      const pos = doc.caretPositionFromPoint(x, y);
      if (pos) {
        node = pos.offsetNode;
        offset = pos.offset;
      }
    } else if (doc.caretRangeFromPoint) {
      const range = doc.caretRangeFromPoint(x, y);
      if (range) {
        node = range.startContainer;
        offset = range.startOffset;
      }
    }
  } catch {
    return false;
  }
  if (!node) return false;
  const solid = (ch: string | undefined) => !!ch && !/\s/.test(ch);
  // Text controls (the note title): the caret API reports the control itself
  // with an offset into `value`. There are no character boxes to measure, so
  // settle for the adjacent characters; the cost is that a press PAST the end
  // of the title's text counts as on-text and keeps the old keyboard-opens
  // behavior for that strip. An empty title still suppresses.
  if (node instanceof HTMLTextAreaElement || node instanceof HTMLInputElement) {
    return solid(node.value[offset - 1]) || solid(node.value[offset]);
  }
  if (node.nodeType !== Node.TEXT_NODE) return false;
  const text = node.textContent ?? '';
  const after = solid(text[offset]);
  if (!after && !solid(text[offset - 1])) return false;
  // The caret lookup snaps to the nearest position: a press well below the
  // last line, or right of a line's end, still reports a character. Only
  // count the press as on-text when it falls inside that character's box.
  const probe = document.createRange();
  const start = after ? offset : offset - 1;
  try {
    probe.setStart(node, start);
    probe.setEnd(node, start + 1);
  } catch {
    return false;
  }
  const rect = probe.getBoundingClientRect();
  return (
    x >= rect.left - TEXT_HIT_SLOP_PX &&
    x <= rect.right + TEXT_HIT_SLOP_PX &&
    y >= rect.top - TEXT_HIT_SLOP_PX &&
    y <= rect.bottom + TEXT_HIT_SLOP_PX
  );
}

/**
 * Long-press detector for the keyboard guard, one instance per surface (the
 * editor body and the note title each own one). `start` arms it on touchstart;
 * `cancel` disarms it on anything proving the touch wasn't a long press - a
 * lift, a scroll, a second finger - and on unmount.
 *
 * The wait is the whole point: we cannot ask "was this a long press?" after
 * the fact, because by then the browser has already decided to show the
 * keyboard. So we bet on the press at 350ms and take the bet back if the
 * finger moves. The on-text check waits with it: it only runs for presses
 * that survive the 350ms, never on plain taps, and a touchmove has already
 * disarmed us by then so the touchstart point is still where the finger is.
 */
export function createLongPressGuard(): {
  start: (el: HTMLElement | null | undefined, touch?: { clientX: number; clientY: number }) => void;
  cancel: () => void;
} {
  let timer: number | null = null;
  const cancel = () => {
    if (timer === null) return;
    window.clearTimeout(timer);
    timer = null;
  };
  return {
    start: (el, touch) => {
      cancel();
      timer = window.setTimeout(() => {
        timer = null;
        // Selection intent: a long press on a word selects it, and Backspace
        // is what follows. Let the keyboard come up for that one.
        // Fix: GitHub #223 (follow-up: keep the keyboard for word selection)
        if (touch && pressOnText(touch.clientX, touch.clientY)) return;
        suppressSoftKeyboard(el);
      }, LONG_PRESS_MS);
    },
    cancel,
  };
}
