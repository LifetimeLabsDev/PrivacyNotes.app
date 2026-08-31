import { useEffect, useState } from 'react';
import { useTranslation } from 'react-i18next';

// Full-screen loading state: a blinking caret that types its way
// through a rotating list of on-brand one-liners. Keeps the feel of a
// notes app ("something is being written") without a spinner that
// starts feeling slow after the second second.
//
// Lines are intentionally short so the typewriter never feels
// laborious on slow connections. Pool is shuffled per-mount so users
// don't always see the same first line. The line pool lives in the
// common catalog under `loading.lines`.

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
// sign-in, OAuth setup): a full type-hold-delete cycle on an average
// 34-char line is ~2.4 s. The previous 45/20/1400 cadence took ~3.7 s
// per line, which read as sluggish exactly when the app felt slowest.
const TYPE_MS = 30;
const DELETE_MS = 12;
const HOLD_MS = 900;

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
// than the login rotation's TYPE_MS: with one short line and nothing
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
    <div className="font-mono text-sm text-neutral-500 dark:text-neutral-400 select-none">
      <span>{text.slice(0, len)}</span>
      <span
        className="inline-block w-[0.5ch] ms-[1px] -mb-[2px] align-baseline bg-neutral-500 dark:bg-neutral-400 animate-pulse"
        style={{ height: '1em' }}
        aria-hidden="true"
      />
    </div>
  );
}

export function LoadingScreen({ inline = false }: { inline?: boolean } = {}) {
  const { t } = useTranslation('common');
  const [pool] = useState(() =>
    shuffle(t('loading.lines', { returnObjects: true }) as string[])
  );
  const [lineIdx, setLineIdx] = useState(0);
  const [text, setText] = useState('');
  const [phase, setPhase] = useState<'typing' | 'holding' | 'deleting'>(
    'typing'
  );
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

  useEffect(() => {
    if (!visible) return;
    const current = pool[lineIdx % pool.length] ?? '';

    if (phase === 'typing') {
      if (text.length < current.length) {
        const t = setTimeout(
          () => setText(current.slice(0, text.length + 1)),
          TYPE_MS
        );
        return () => clearTimeout(t);
      }
      const t = setTimeout(() => setPhase('holding'), 0);
      return () => clearTimeout(t);
    }

    if (phase === 'holding') {
      const t = setTimeout(() => setPhase('deleting'), HOLD_MS);
      return () => clearTimeout(t);
    }

    // deleting
    if (text.length > 0) {
      const t = setTimeout(
        () => setText(text.slice(0, -1)),
        DELETE_MS
      );
      return () => clearTimeout(t);
    }
    const t = setTimeout(() => {
      setLineIdx((i) => i + 1);
      setPhase('typing');
    }, 80);
    return () => clearTimeout(t);
  }, [visible, phase, text, lineIdx, pool]);

  const inner = (
    <div
      className={`font-mono text-sm text-neutral-500 dark:text-neutral-400 select-none transition-opacity duration-150 ${visible ? 'opacity-100' : 'opacity-0'}`}
    >
      <span>{text}</span>
      <span
        className="inline-block w-[0.5ch] ms-[1px] -mb-[2px] align-baseline bg-neutral-500 dark:bg-neutral-400 animate-pulse"
        style={{ height: '1em' }}
        aria-hidden="true"
      />
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
