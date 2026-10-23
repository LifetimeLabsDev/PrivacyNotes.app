// The rotating typewriter lines: one engine for every surface that shows them.
// The app's loading screen and lock screen mount it through
// TypewriterRotation (LoadingScreen.tsx); the site footer mounts it through
// footerLines.ts, on the homepage (React) and on the static pages (the
// /footer-lines.js bundle). It is plain DOM with no framework and no i18n, so
// the static pages can run it, and a change to the rhythm or to an exit lands
// everywhere at once. Each surface brings its own lines and its own `look`
// (class names), because the app paints with Tailwind and the static pages
// cannot load it.
//
// Lines are intentionally short so the typewriter never feels laborious on
// slow connections. The pool is shuffled per mount so nobody always sees the
// same first line. The lines live in the common catalog: `loading.lines`
// (every screen) and `loading.loadingOnly` (lines about loading).

function shuffle<T>(arr: T[]): T[] {
  const a = arr.slice();
  for (let i = a.length - 1; i > 0; i--) {
    const j = Math.floor(Math.random() * (i + 1));
    const tmp = a[i] as T;
    a[i] = a[j] as T;
    a[j] = tmp;
  }
  return a;
}

// Cadence tuned for the waits users actually sit through (phrase
// sign-in, OAuth setup): a full type-hold-clear cycle on an average
// 34-char line is about 2.3 s. The previous 45/20/1400 cadence took ~3.7 s
// per line, which read as sluggish exactly when the app felt slowest.
// The clear is one of the short exits below, under half a second.
const TYPE_MS = 30;
const HOLD_MS = 900;

// ── How a line leaves (every surface) ───────────────────────────
// Six short exits, none of them a letter-by-letter Backspace (which took a
// long line one to two seconds), each matched to what its line says (owner,
// 2026-10-22): select all and delete, encrypt away (a scanner leaves cipher
// behind it), word by word, fold into a hash, shred, or strike through. With
// reduced motion every line uses select and delete, because the others move.

type Exit = 'select' | 'encrypt' | 'words' | 'hash' | 'shred' | 'strike';
/** The fallback when a catalog does not line up with the lists below. */
const RANDOM_EXITS: Exit[] = ['select', 'encrypt', 'words'];

/**
 * One exit per line, by position in the English `loading.lines` and
 * `loading.loadingOnly`, which every language keeps in the same order. A
 * language whose list has another length (an English edit not translated
 * yet) falls back to a random exit. `tests/typewriterPace.test.ts` holds the
 * lengths to the English catalog.
 *   encrypt: encryption, unreadable   hash: keys, math, checking
 *   shred: boring, dull, nothing found   strike: what we refuse (ads,
 *   tracking, ai, influencers)   words: writing, thinking, ideas
 *   select: personal, calm
 */
export const LINE_EXITS: Exit[] = [
  'hash', 'select', 'encrypt', 'select', 'encrypt', 'shred', 'strike', 'encrypt', 'shred', 'strike',
  'encrypt', 'strike', 'select', 'words', 'strike', 'words', 'hash', 'shred', 'strike', 'encrypt',
  'words', 'hash', 'select', 'shred', 'encrypt', 'select', 'strike', 'hash', 'encrypt', 'shred',
  'select', 'words', 'words', 'select', 'select', 'strike', 'words', 'words', 'strike',
];
export const LOADING_EXITS: Exit[] = [
  'encrypt', 'strike', 'select', 'hash', 'encrypt', 'encrypt', 'hash', 'shred', 'encrypt', 'words',
  'words', 'hash', 'words', 'select', 'strike', 'select', 'words', 'hash', 'words',
];

const SELECT_MS = 420;
const SCAN_MS = 14;
const SCAN_REST_MS = 140;
const SCAN_FADE_MS = 300;
const WORD_MS = 60;
const HASH_FRAME_MS = 70;
const HASH_LENGTH = 8;
const HASH_HOLD_MS = 320;
const SHRED_PER_FRAME = 4;
const SHRED_FRAME_MS = 22;
const SHRED_FALL_MS = 380;
const STRIKE_MS = 550;
const CIPHER = '#%&$@*+=<>/|{}[]01';
const HEX = '0123456789abcdef';

type Line = { text: string; exit?: Exit };

/** The lines of one catalog key, each with its exit when the lengths agree. */
function withExits(lines: string[], exits: Exit[]): Line[] {
  return lines.map((text, i) => ({ text, exit: lines.length === exits.length ? exits[i] : undefined }));
}

/** The shuffled pool: `loading.lines`, plus `loading.loadingOnly` where a surface may say them. */
export function buildPool(lines: string[], loadingOnly: string[] = []): Line[] {
  return shuffle([...withExits(lines, LINE_EXITS), ...withExits(loadingOnly, LOADING_EXITS)]);
}

function exitFor(line: Line | undefined): Exit {
  if (window.matchMedia?.('(prefers-reduced-motion: reduce)').matches) return 'select';
  return line?.exit ?? RANDOM_EXITS[Math.floor(Math.random() * RANDOM_EXITS.length)] ?? 'select';
}

/** One cipher sign per letter, fixed for the whole scan; spaces stay, so the words keep their shape. */
export function cipherOf(line: string): string[] {
  return Array.from(line, (c) => (c === ' ' ? ' ' : CIPHER[Math.floor(Math.random() * CIPHER.length)] ?? '#'));
}

/** How long the hash is at `frame`: the line shrinks by a third a frame, down to a short hash. */
function hashLength(lineLength: number, frame: number): number {
  return Math.max(HASH_LENGTH, Math.floor(lineLength * 0.62 ** frame));
}

function hex(length: number): string {
  return Array.from({ length }, () => HEX[Math.floor(Math.random() * HEX.length)]).join('');
}

/** The line without its last word, the way Option+Backspace takes it. */
function dropLastWord(line: string): string {
  const cut = line.trimEnd().lastIndexOf(' ');
  return cut <= 0 ? '' : line.slice(0, cut);
}

/** A random drop order and tilt for each letter of a shredded line. */
function shredPlan(length: number): { order: number[]; tilt: number[] } {
  const order = shuffle(Array.from({ length }, (_, i) => i));
  const rank: number[] = [];
  order.forEach((letter, k) => { rank[letter] = k; });
  return { order: rank, tilt: Array.from({ length }, () => Math.random() * 60 - 30) };
}

// ── The human rhythm (lock screen, site footer) ─────────────────
// Someone typing, not a machine: every key takes its own time, a word starts
// with a small hesitation, punctuation earns a breath, and now and then a
// key lands on its neighbour and is taken back. A line is read before it
// goes, longer lines longer.

/** Keys around each letter on a QWERTY board, for a believable slip. Letters
 *  outside this map (accents, other scripts) are never mistyped. */
const NEIGHBOURS: Record<string, string> = {
  q: 'wa', w: 'qes', e: 'wrd', r: 'etf', t: 'ryg', y: 'tuh', u: 'yij', i: 'uok', o: 'ipl', p: 'ol',
  a: 'qsz', s: 'adwx', d: 'sfec', f: 'dgrv', g: 'fhtb', h: 'gjyn', j: 'hkum', k: 'jli', l: 'ko',
  z: 'asx', x: 'zcs', c: 'xvd', v: 'cbf', b: 'vng', n: 'bmh', m: 'nj',
};
const TYPO_CHANCE = 0.033;

const between = (min: number, max: number) => min + Math.random() * (max - min);

/** How long the next key takes after `prev`. */
function keyDelay(prev: string, next: string): number {
  let ms = between(55, 150);
  if (prev === ' ') ms += between(40, 200);
  if (/[.,!?:;]/.test(prev)) ms += between(250, 480);
  if (next === ' ') ms = between(45, 95);
  if (Math.random() < 0.04) ms += between(300, 700);
  return ms;
}

// ── The engine ──────────────────────────────────────────────────

/** Class names a surface paints the line with. Geometry and motion stay here. */
export type TypewriterLook = {
  /** Always on the caret: its color. */
  caret: string;
  /** The idle blink of a person's caret. */
  caretBlink: string;
  /** The machine caret's pulse. */
  caretPulse: string;
  /** A line selected before Delete. */
  select: string;
  /** A line struck through. */
  strike: string;
  /** Letters already turned to cipher. */
  cipher: string;
  /** The letter the scanner is on. */
  scanner: string;
};

export type Typewriter = {
  setPaused(paused: boolean): void;
  setRunning(running: boolean): void;
  destroy(): void;
};

/**
 * Types the pool into `host`, line after line, until destroyed. `running`
 * false holds it before its next step (the loading screen's grace window, a
 * footer out of view). `paused` finishes the line on screen and stops there,
 * with a still caret. `human` swaps the even machine cadence for a person
 * typing (lock screen, owner 2026-10-22; site footer).
 */
export function mountTypewriter(host: HTMLElement, opts: {
  pool: Line[];
  look: TypewriterLook;
  human?: boolean;
  paused?: boolean;
  running?: boolean;
}): Typewriter {
  const { pool, look, human = false } = opts;
  let paused = opts.paused ?? false;
  let running = opts.running ?? true;
  let lineIdx = 0;
  let text = '';
  let phase: 'typing' | 'holding' | 'exiting' = 'typing';
  // How the full line leaves, picked per line, and the frame it is on.
  let exit: Exit = 'select';
  let frame = 0;
  let shred: { order: number[]; tilt: number[] } = { order: [], tilt: [] };
  let cipher: string[] = [];
  let timer: ReturnType<typeof setTimeout> | undefined;

  const lineEl = document.createElement('span');
  const caret = document.createElement('span');
  caret.setAttribute('aria-hidden', 'true');
  // An inline box around a word joiner, not an inline-block: an inline-block
  // is a break opportunity, so a line that just fit pushed the caret alone
  // onto the next row. The joiner keeps it on the last word's row.
  caret.textContent = '\u2060';
  caret.style.cssText = 'padding-inline-end:0.5ch;margin-inline-start:1px';
  host.replaceChildren(lineEl, caret);

  // The letter spans of an encrypt or shred exit, built once per line so
  // their transitions run between frames.
  let built: 'plain' | 'encrypt' | 'shred' = 'plain';
  let builtFor = '';

  function render() {
    // A real caret stays solid while keys go down and blinks only when idle.
    const leaving = !paused && phase === 'exiting' && text.length > 0;
    const busy = !paused && (phase === 'typing' || leaving);
    const motion = paused ? '' : human ? (busy ? '' : look.caretBlink) : look.caretPulse;
    caret.className = motion ? `${look.caret} ${motion}` : look.caret;

    const mode = leaving && exit === 'encrypt' ? 'encrypt' : leaving && exit === 'shred' ? 'shred' : 'plain';
    if (mode === 'plain') {
      if (built !== 'plain') { lineEl.style.cssText = ''; built = 'plain'; }
      lineEl.className = !leaving ? '' : exit === 'select' ? look.select : exit === 'strike' ? look.strike : '';
      lineEl.textContent = leaving && frame > 0 && exit === 'hash' ? hex(hashLength(text.length, frame)) : text;
      return;
    }
    if (built !== mode || builtFor !== text) {
      lineEl.className = '';
      lineEl.style.cssText = mode === 'encrypt' ? `transition:opacity ${SCAN_FADE_MS}ms` : '';
      lineEl.replaceChildren(...Array.from(text, (c) => {
        const letter = document.createElement('span');
        letter.textContent = c;
        if (mode === 'shred') {
          letter.style.cssText = `display:inline-block;white-space:pre;transition:transform ${SHRED_FALL_MS}ms ease-in,opacity ${SHRED_FALL_MS}ms ease-in`;
        }
        return letter;
      }));
      built = mode;
      builtFor = text;
    }
    const letters = lineEl.children;
    if (mode === 'encrypt') {
      // The scanner: cipher behind it, the letter it is on lit.
      lineEl.style.opacity = frame > text.length ? '0' : '1';
      Array.from(text, (c, i) => {
        const letter = letters[i];
        if (!letter) return;
        letter.textContent = i < frame ? (cipher[i] ?? c) : c;
        letter.className = i < frame ? look.cipher : i === frame ? look.scanner : '';
      });
      return;
    }
    Array.from(text, (_, i) => {
      const letter = letters[i] as HTMLElement | undefined;
      if (!letter) return;
      const fallen = (shred.order[i] ?? 0) < frame * SHRED_PER_FRAME;
      letter.style.transform = fallen ? `translateY(1.6em) rotate(${shred.tilt[i] ?? 0}deg)` : '';
      letter.style.opacity = fallen ? '0' : '1';
    });
  }

  function later(ms: number, step: () => void) {
    timer = setTimeout(() => {
      timer = undefined;
      step();
      render();
      schedule();
    }, ms);
  }

  function schedule() {
    clearTimeout(timer);
    timer = undefined;
    if (!running || pool.length === 0) return;
    const line = pool[lineIdx % pool.length];
    const current = line?.text ?? '';

    if (paused) {
      // A paused line reads whole, never cut mid-word.
      if (text !== current || phase !== 'holding') {
        text = current;
        phase = 'holding';
        render();
      }
      return;
    }

    if (phase === 'typing') {
      if (text === current) return later(0, () => { phase = 'holding'; });
      if (!human) return later(TYPE_MS, () => { text = current.slice(0, text.length + 1); });
      // A slip on screen (the text has left the line): notice it, take it back.
      if (!current.startsWith(text)) return later(between(180, 380), () => { text = text.slice(0, -1); });
      const next = current[text.length] ?? '';
      const prev = text[text.length - 1] ?? '';
      const around = NEIGHBOURS[next];
      if (around && text.length > 0 && Math.random() < TYPO_CHANCE) {
        const wrong = around[Math.floor(Math.random() * around.length)] ?? next;
        return later(keyDelay(prev, next), () => { text += wrong; });
      }
      return later(keyDelay(prev, next), () => { text += next; });
    }

    if (phase === 'holding') {
      const read = human ? Math.min(1800 + current.length * 40, 4000) : HOLD_MS;
      return later(read, () => {
        const how = exitFor(line);
        if (how === 'shred') shred = shredPlan(current.length);
        if (how === 'encrypt') cipher = cipherOf(current);
        exit = how;
        frame = 0;
        phase = 'exiting';
      });
    }

    // exiting: the line leaves the way its exit says.
    if (text.length === 0) {
      return later(human ? 450 : 80, () => {
        frame = 0;
        lineIdx += 1;
        phase = 'typing';
      });
    }
    if (exit === 'select') {
      // Cmd+A shows the selection for a beat, then Delete takes it all.
      return later(SELECT_MS, () => { text = ''; });
    }
    if (exit === 'encrypt') {
      // A scanner crosses the line and leaves cipher behind it; the line
      // rests a beat as cipher, fades, and goes.
      if (frame < text.length) return later(SCAN_MS, () => { frame += 1; });
      if (frame === text.length) return later(SCAN_REST_MS, () => { frame += 1; });
      return later(SCAN_FADE_MS, () => { text = ''; });
    }
    if (exit === 'hash') {
      // The line folds into ever shorter hex, rests as a short hash, then goes.
      return hashLength(text.length, frame) > HASH_LENGTH
        ? later(HASH_FRAME_MS, () => { frame += 1; })
        : later(HASH_HOLD_MS, () => { text = ''; });
    }
    if (exit === 'shred') {
      // A few letters drop at a time; the line is gone once the last has fallen.
      return frame * SHRED_PER_FRAME < text.length
        ? later(SHRED_FRAME_MS, () => { frame += 1; })
        : later(SHRED_FALL_MS, () => { text = ''; });
    }
    if (exit === 'strike') {
      // Crossed out for a beat, then gone.
      return later(STRIKE_MS, () => { text = ''; });
    }
    // words: Option+Backspace, a whole word at a time.
    return later(human ? 80 : WORD_MS, () => { text = dropLastWord(text); });
  }

  render();
  schedule();
  return {
    setPaused(next) {
      if (next === paused) return;
      paused = next;
      render();
      schedule();
    },
    setRunning(next) {
      if (next === running) return;
      running = next;
      schedule();
    },
    destroy() {
      clearTimeout(timer);
      running = false;
      host.replaceChildren();
    },
  };
}
