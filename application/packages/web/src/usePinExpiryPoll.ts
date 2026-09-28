import { useEffect, useRef } from 'react';
import { shouldPromptForPin } from './pin';

/**
 * Polls the PIN unlock window so an expired timeout re-locks an open note
 * without any interaction. 30s granularity is fine - a 5-minute timeout
 * with up to 30s of drift is well within UX norms.
 *
 * `onChange` runs only when the answer differs from the one the last render
 * drew. An idle tick that changes nothing would otherwise re-render the
 * whole view, every mounted list row included, twice a minute.
 */
export function usePinExpiryPoll(timeoutMinutes: number, onChange: () => void): void {
  const rendered = useRef(true);
  useEffect(() => {
    rendered.current = shouldPromptForPin(timeoutMinutes);
  });
  const latest = useRef(onChange);
  latest.current = onChange;
  useEffect(() => {
    if (timeoutMinutes === -1) return;
    const t = setInterval(() => {
      if (shouldPromptForPin(timeoutMinutes) === rendered.current) return;
      latest.current();
    }, 30_000);
    return () => clearInterval(t);
  }, [timeoutMinutes]);
}
