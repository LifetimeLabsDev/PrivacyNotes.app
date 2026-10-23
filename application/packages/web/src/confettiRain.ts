import { PALETTE } from './editorColors';
import { MOOD_COLORS } from './moodColors';

/**
 * Confetti tossed up from the top edge of a rectangle, then falling past it:
 * the check-in card's reward after Finish. Each piece rises and drifts aside
 * for the first sixth of its flight, then sways down and fades out, about
 * five seconds in all, as long as the card holds its success state. A piece
 * is not drawn before it starts, so no band waits on the screen. The layer
 * catches no pointer, is hidden from screen readers and removes itself; with
 * reduced motion nothing is thrown.
 * Spec: ops/docs/archive/ui-patterns.md section 141
 */
const COLORS = [...MOOD_COLORS, PALETTE.purple, PALETTE.pink];
/** One piece per 14 px of width, from 30 on a phone to 80 on a wide card. */
const pieces = (width: number) => Math.round(Math.min(80, Math.max(30, width / 14)));
const STEPS = 30;
/** The part of the flight that goes up. */
const PEAK = 0.16;

const rnd = (a: number, b: number) => a + Math.random() * (b - a);

export function rainConfetti(rect: DOMRect): void {
  if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
  const layer = document.createElement('div');
  if (typeof layer.animate !== 'function') return;
  layer.setAttribute('aria-hidden', 'true');
  Object.assign(layer.style, { position: 'fixed', inset: '0', pointerEvents: 'none', overflow: 'hidden', zIndex: '45' });
  document.body.appendChild(layer);
  const count = pieces(rect.width);
  let left = count;
  const done = () => { if (--left === 0) layer.remove(); };
  for (let i = 0; i < count; i++) {
    const el = document.createElement('span');
    const size = rnd(6, 11);
    const round = Math.random() < 0.3;
    Object.assign(el.style, {
      // Hidden until its animation starts, which then sets the opacity.
      position: 'absolute', left: '0', top: '0', opacity: '0',
      width: `${size}px`, height: `${round ? size : size * rnd(0.4, 0.7)}px`,
      borderRadius: round ? '50%' : '2px',
      background: COLORS[Math.floor(Math.random() * COLORS.length)]!,
    });
    layer.appendChild(el);
    const x0 = rect.left + rnd(0, rect.width);
    const y0 = rect.top + rnd(-4, 4);
    const rise = rnd(50, 120);
    const drift = rnd(-60, 60);
    const fall = rnd(420, 600);
    const sway = rnd(20, 45);
    const spin = rnd(-720, 720);
    const phase = rnd(0, Math.PI * 2);
    const duration = rnd(3900, 4600);
    const frames: Keyframe[] = [];
    for (let s = 0; s <= STEPS; s++) {
      const p = s / STEPS;
      const t = p * duration;
      let x = x0 + Math.sin(phase + t / 260) * sway * p;
      let y: number;
      if (p < PEAK) {
        // Up, slowing to a stop at the top of the toss.
        const q = p / PEAK;
        y = y0 - rise * (1 - (1 - q) * (1 - q));
        x += drift * q;
      } else {
        // Down from there, gathering speed as paper does.
        const q = (p - PEAK) / (1 - PEAK);
        y = y0 - rise + (fall + rise) * (0.2 * q + 0.8 * q * q);
        x += drift;
      }
      frames.push({
        transform: `translate(${x}px, ${y}px) rotate(${spin * p}deg) scaleY(${Math.cos(phase + t / 120)})`,
        opacity: p < 0.75 ? 1 : 1 - (p - 0.75) / 0.25,
        offset: p,
      });
    }
    const anim = el.animate(frames, { duration, delay: rnd(0, 180), easing: 'linear', fill: 'forwards' });
    anim.onfinish = done;
    anim.oncancel = done;
  }
}

/** The burst from a ticked task checkbox: a few pieces, close, and fast. */
const BURST_PIECES = 14;
const BURST_STEPS = 16;

/**
 * Confetti thrown out from the middle of a small rectangle, then pulled down:
 * a ticked task checkbox. Each piece flies off at its own angle, slows, drops
 * a little and fades out, about one second in all. Same layer rules as
 * `rainConfetti`. Experimental.
 */
export function burstConfetti(rect: DOMRect): void {
  if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return;
  const layer = document.createElement('div');
  if (typeof layer.animate !== 'function') return;
  layer.setAttribute('aria-hidden', 'true');
  Object.assign(layer.style, { position: 'fixed', inset: '0', pointerEvents: 'none', overflow: 'hidden', zIndex: '45' });
  document.body.appendChild(layer);
  const cx = rect.left + rect.width / 2;
  const cy = rect.top + rect.height / 2;
  let left = BURST_PIECES;
  const done = () => { if (--left === 0) layer.remove(); };
  for (let i = 0; i < BURST_PIECES; i++) {
    const el = document.createElement('span');
    const size = rnd(4, 7);
    const round = Math.random() < 0.3;
    Object.assign(el.style, {
      position: 'absolute', left: '0', top: '0', opacity: '0',
      width: `${size}px`, height: `${round ? size : size * rnd(0.4, 0.7)}px`,
      borderRadius: round ? '50%' : '1px',
      background: COLORS[Math.floor(Math.random() * COLORS.length)]!,
    });
    layer.appendChild(el);
    // Evenly round the circle, with some jitter, and a little more upward.
    const angle = (i / BURST_PIECES) * Math.PI * 2 + rnd(-0.3, 0.3);
    const reach = rnd(28, 60);
    const dx = Math.cos(angle) * reach;
    const dy = Math.sin(angle) * reach - rnd(8, 20);
    const drop = rnd(30, 55);
    const spin = rnd(-540, 540);
    const duration = rnd(850, 1150);
    const frames: Keyframe[] = [];
    for (let s = 0; s <= BURST_STEPS; s++) {
      const p = s / BURST_STEPS;
      // Fast out, slowing as air holds it, while gravity grows.
      const out = 1 - (1 - p) * (1 - p) * (1 - p);
      const x = cx + dx * out - size / 2;
      const y = cy + dy * out + drop * p * p - size / 2;
      frames.push({
        transform: `translate(${x}px, ${y}px) rotate(${spin * p}deg) scale(${p < 0.1 ? 0.4 + 6 * p : 1})`,
        opacity: p < 0.6 ? 1 : 1 - (p - 0.6) / 0.4,
        offset: p,
      });
    }
    const anim = el.animate(frames, { duration, easing: 'linear', fill: 'forwards' });
    anim.onfinish = done;
    anim.oncancel = done;
  }
}
