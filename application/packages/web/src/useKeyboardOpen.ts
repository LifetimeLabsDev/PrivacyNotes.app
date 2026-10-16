/**
 * useKeyboardOpen - detects whether the on-screen keyboard is visible.
 *
 * Uses the Visual Viewport API: stores the maximum observed viewport
 * height as a baseline, then checks if the current height is
 * significantly smaller (keyboard eating space). This works on iOS
 * Safari where `window.innerHeight` also shrinks when the keyboard
 * opens, making a simple `innerHeight - vv.height` delta unreliable.
 *
 * Returns `false` on desktop or when the API isn't available.
 *
 * The same baseline is published as `--pn-stable-vh`, the viewport height with
 * no keyboard in the way. Anything sized against the viewport that must not
 * move while someone types reads that instead of a viewport unit, because
 * `interactive-widget=resizes-content` in index.html resizes the layout
 * viewport itself: on Android every unit, `svh` included, follows the keyboard
 * down. Spec: ops/docs/ui-patterns.md (stable viewport height)
 *
 * While the keyboard is open it also publishes `--pn-app-h`, the height
 * left above the keyboard, which the app shell takes as its height. Android
 * resizes the layout itself (`interactive-widget=resizes-content`), so there
 * it changes nothing. iOS lays the keyboard over the layout and then moves
 * the whole page up to show the caret, which carried the header and the
 * format bar off the screen (GitHub #449). With the shell cut to the visible
 * area the page has nothing to move: it is put back at the top, and the
 * caret is kept in view by scrolling the note instead.
 * Spec: ops/docs/plans/format-bar.md (section 7)
 */

import { useEffect, useRef, useState } from 'react';
import { setSoftKeyboardUp } from './softKeyboard';

const THRESHOLD = 150;

/** Styles that decide where a textarea wraps its text, copied onto the measuring copy. */
const MIRROR_STYLES = [
  'box-sizing', 'width', 'direction', 'font-family', 'font-size', 'font-weight', 'font-style',
  'letter-spacing', 'word-spacing', 'line-height', 'text-transform', 'text-indent', 'tab-size',
  'padding-top', 'padding-right', 'padding-bottom', 'padding-left',
  'border-top-width', 'border-right-width', 'border-bottom-width', 'border-left-width',
];

/**
 * The caret's line inside a textarea, in viewport coordinates. A textarea has
 * no range to measure, so an invisible copy with the same width and font lays
 * out the text up to the caret, and a marker at its end gives the line.
 */
function textareaCaretRect(el: HTMLTextAreaElement): { top: number; bottom: number } {
  const cs = getComputedStyle(el);
  const mirror = document.createElement('div');
  for (const p of MIRROR_STYLES) mirror.style.setProperty(p, cs.getPropertyValue(p));
  mirror.style.cssText += ';position:absolute;top:0;left:-9999px;visibility:hidden;white-space:pre-wrap;overflow-wrap:break-word;border-style:solid';
  mirror.textContent = el.value.slice(0, el.selectionEnd);
  const mark = document.createElement('span');
  mark.textContent = '​';
  mirror.appendChild(mark);
  document.body.appendChild(mirror);
  const line = mark.getBoundingClientRect();
  const offset = line.top - mirror.getBoundingClientRect().top;
  mirror.remove();
  const top = el.getBoundingClientRect().top + offset - el.scrollTop;
  return { top, bottom: top + line.height };
}

/**
 * Scroll the caret's own column, never the page, so the caret clears the keyboard.
 * Nothing here may scroll the window: a window scroll fires the viewport's
 * scroll event, which calls this again on the next frame, and the page shakes
 * (GitHub #509, where `scrollIntoView` on the Markdown view's textarea did it).
 */
function keepCaretVisible() {
  const el = document.activeElement as HTMLElement | null;
  if (!el) return;
  let rect: { top: number; bottom: number };
  if (el instanceof HTMLTextAreaElement) {
    rect = textareaCaretRect(el);
  } else if (el instanceof HTMLInputElement) {
    rect = el.getBoundingClientRect();
  } else if (el.isContentEditable) {
    const sel = window.getSelection();
    if (!sel?.rangeCount) return;
    const range = sel.getRangeAt(0).getBoundingClientRect();
    if (!range.height) return;
    rect = range;
  } else {
    return;
  }
  // The first ancestor that really scrolls up and down. An element that only
  // scrolls sideways (overflow-x: auto) computes overflow-y as auto too.
  let col = el.parentElement;
  while (col && !(col.scrollHeight > col.clientHeight && /(auto|scroll)/.test(getComputedStyle(col).overflowY))) col = col.parentElement;
  if (!col) return;
  const box = col.getBoundingClientRect();
  const margin = 24;
  if (rect.bottom > box.bottom - margin) col.scrollTop += rect.bottom - box.bottom + margin;
}

export function useKeyboardOpen(): boolean {
  const [open, setOpen] = useState(false);
  const maxHeight = useRef(0);
  const lastWidth = useRef(0);

  useEffect(() => {
    const vv = window.visualViewport;
    if (!vv) return;

    const publish = () => {
      document.documentElement.style.setProperty('--pn-stable-vh', `${maxHeight.current}px`);
    };

    // Seed with the larger of innerHeight and current viewport height.
    maxHeight.current = Math.max(window.innerHeight, vv.height);
    lastWidth.current = vv.width;
    publish();

    const check = () => {
      // The on-screen keyboard only changes viewport HEIGHT, never width. A
      // width change is a window resize / orientation change, so re-baseline to
      // the new height and report closed. Without this, dragging a desktop
      // window shorter reads as a keyboard opening and hides mobile chrome (the
      // header hamburger), since the now-narrow window also counts as mobile.
      if (vv.width !== lastWidth.current) {
        lastWidth.current = vv.width;
        maxHeight.current = vv.height;
        publish();
        setSoftKeyboardUp(false);
        setOpen(false);
        return;
      }
      const h = vv.height;
      if (h > maxHeight.current) {
        // Viewport grew (e.g. browser toolbar hide) - update baseline.
        maxHeight.current = h;
        publish();
      }
      const up = maxHeight.current - h > THRESHOLD;
      setSoftKeyboardUp(up);
      setOpen(up);
    };

    const fit = (moved: boolean) => {
      const root = document.documentElement;
      // Only a keyboard counts: the same baseline as `check`, so a desktop
      // zoom or a scrollbar never cuts the shell.
      if (maxHeight.current - vv.height <= THRESHOLD) {
        root.style.removeProperty('--pn-app-h');
        return;
      }
      const h = `${Math.round(vv.height)}px`;
      const grew = root.style.getPropertyValue('--pn-app-h') !== h;
      root.style.setProperty('--pn-app-h', h);
      if (window.scrollY !== 0) window.scrollTo(0, 0);
      if (grew || moved) requestAnimationFrame(keepCaretVisible);
    };
    const onResize = () => { check(); fit(false); };
    const onScroll = () => fit(true);

    vv.addEventListener('resize', onResize);
    vv.addEventListener('scroll', onScroll);
    onResize();
    return () => {
      vv.removeEventListener('resize', onResize);
      vv.removeEventListener('scroll', onScroll);
    };
  }, []);

  return open;
}
