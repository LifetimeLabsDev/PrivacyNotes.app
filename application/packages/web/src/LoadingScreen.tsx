import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { buildPool, mountTypewriter, type Typewriter, type TypewriterLook } from './typewriter';

// Full-screen loading state: a blinking caret that types its way
// through a rotating list of on-brand one-liners. Keeps the feel of a
// notes app ("something is being written") without a spinner that
// starts feeling slow after the second second.
//
// The rotation's rhythm, exits and line pool live in ./typewriter, the
// one engine the lock screen and the site footer run too.

// Nothing paints for the first GRACE_MS of a loading session, so a wait
// the user would never have read never appears at all. Measured on a
// signed-in page load, React's Suspense churns this component: mount,
// unmount at 62 ms, remount 1 ms later. Per-mount timing would restart
// the clock on the remount and paint anyway, so the clock lives at
// module scope and spans the churn - liveCount only drops to a real
// zero once nothing has been mounted for SESSION_GAP_MS.
//
// Deliberately no minimum display time: MIN_LOADING_MS was removed
// because holding the screen open made the app feel slow. The fade-in
// covers the boundary case instead - a session that ends just after
// GRACE_MS is caught partway through the fade and reads as a soft
// ghost rather than a flash.
const GRACE_MS = 400;
const SESSION_GAP_MS = 400;

let sessionStart = 0;
let liveCount = 0;
let idleTimer: number | undefined;

// Types a single fixed line once, then holds with the blinking caret.
// Used by overlays that show one known message (e.g. the sign-out
// screen) so they match the loading screen's feel. Deliberately slower
// than the login rotation's TYPE_MS (./typewriter): with one short line and nothing
// following, that cadence reads as a blink rather than typing.
const SINGLE_LINE_TYPE_MS = 60;

export function TypewriterLine({ text }: { text: string }) {
  const [len, setLen] = useState(0);

  useEffect(() => {
    if (len >= text.length) return;
    const t = setTimeout(() => setLen(len + 1), SINGLE_LINE_TYPE_MS);
    return () => clearTimeout(t);
  }, [len, text]);

  return (
    <div className="font-mono text-sm text-pn-muted select-none">
      <span>{text.slice(0, len)}</span>
      <span
        className="inline-block w-[0.5ch] ms-[1px] -mb-[2px] align-baseline bg-pn-muted animate-pulse"
        style={{ height: '1em' }}
        aria-hidden="true"
      />
    </div>
  );
}

// What the app paints the shared engine (./typewriter) with.
const APP_LOOK: TypewriterLook = {
  caret: 'bg-pn-muted',
  caretBlink: 'pn-caret-blink',
  caretPulse: 'animate-pulse',
  select: 'rounded-sm bg-accent/20 text-pn',
  strike: 'line-through decoration-[1.5px]',
  cipher: 'text-accent',
  scanner: 'rounded-sm bg-accent/25 text-pn',
};

/**
 * The rotating typewriter itself: shuffled `loading.lines`, typed, held and
 * cleared in turn, by the shared engine in ./typewriter. `running` false holds
 * it before its first letter (the loading screen's grace window). `paused`
 * finishes the line on screen and stops there, with a still caret, for the
 * lock screen's pause button. `human` swaps the loading screen's even machine
 * cadence for a person typing (the lock screen, owner 2026-10-22); the
 * loading screen keeps the machine.
 */
export function TypewriterRotation({ running = true, paused = false, human = false, loading = false }: {
  running?: boolean;
  paused?: boolean;
  human?: boolean;
  /** Also the lines about loading, opening or decrypting
   *  (`loading.loadingOnly`), which only the loading screen can say truthfully;
   *  the lock screen leaves them out. */
  loading?: boolean;
}) {
  const { t } = useTranslation('common');
  const host = useRef<HTMLDivElement>(null);
  const engine = useRef<Typewriter | null>(null);

  // Mounted once with the lines of the moment; `paused` and `running` follow below.
  useEffect(() => {
    const el = host.current;
    if (!el) return;
    const list = (key: string) => {
      const value = t(key, { returnObjects: true });
      return Array.isArray(value) ? (value as string[]) : [];
    };
    engine.current = mountTypewriter(el, {
      pool: buildPool(list('loading.lines'), loading ? list('loading.loadingOnly') : []),
      look: APP_LOOK,
      human,
      paused,
      running,
    });
    return () => {
      engine.current?.destroy();
      engine.current = null;
    };
    // eslint-disable-next-line react-hooks/exhaustive-deps -- one pool per mount, like the shuffle
  }, []);
  useEffect(() => { engine.current?.setPaused(paused); }, [paused]);
  useEffect(() => { engine.current?.setRunning(running); }, [running]);

  return <div ref={host} className="font-mono text-sm text-pn-muted select-none" />;
}

export function LoadingScreen({ inline = false }: { inline?: boolean } = {}) {
  const [visible, setVisible] = useState(false);

  // Grace window, shared across every mount in the same loading session.
  useEffect(() => {
    window.clearTimeout(idleTimer);
    if (liveCount === 0 && sessionStart === 0) sessionStart = performance.now();
    liveCount += 1;

    const elapsed = performance.now() - sessionStart;
    let showTimer: number | undefined;
    if (elapsed >= GRACE_MS) setVisible(true);
    else showTimer = window.setTimeout(() => setVisible(true), GRACE_MS - elapsed);

    return () => {
      window.clearTimeout(showTimer);
      liveCount -= 1;
      if (liveCount === 0) {
        idleTimer = window.setTimeout(() => { sessionStart = 0; }, SESSION_GAP_MS);
      }
    };
  }, []);

  const inner = (
    <div className={`transition-opacity duration-150 ${visible ? 'opacity-100' : 'opacity-0'}`}>
      <TypewriterRotation running={visible} loading />
    </div>
  );

  if (inline) {
    return <div className="flex justify-center py-8">{inner}</div>;
  }

  return (
    <div className="min-h-screen flex items-center justify-center bg-surface-0">
      {inner}
    </div>
  );
}
