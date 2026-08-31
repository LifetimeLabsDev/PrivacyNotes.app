/**
 * Cross-tab writer-generation signal for the at-rest rollout.
 *
 * When a tab running the sealed-writer release boots, it announces on
 * this channel. A tab running the READER release that hears the
 * announcement reloads itself once: the server already serves the
 * newer bundle, a reload converges instantly, and an in-flight edit
 * survives through the pagehide flush stash. Reload beats a frozen
 * "please update" overlay - no new UI, no new strings, no tab left
 * half-alive writing plaintext beside a sealed writer.
 *
 * The one-shot marker stops any conceivable reload loop: a tab reloads
 * for this reason at most once per tab session, and a tab that IS the
 * sealed writer never reloads (it only announces; announcing lands in
 * the writer release).
 *
 * Spec: ops/docs/plans/local-at-rest.md (5.2, mechanism 2)
 */
import { isDemoMode } from './demo';
import { sealedWritesOn } from './localSeal';

const CHANNEL = 'pn-writer-gen';
const SEALED_ACTIVE = 'sealed-writer-active';
const RELOADED_MARKER = 'pn:writer-gen-reloaded';

export function initWriterGenListener(): void {
  if (isDemoMode()) return;
  if (typeof BroadcastChannel === 'undefined') return;
  const channel = new BroadcastChannel(CHANNEL);
  channel.onmessage = (ev: MessageEvent) => {
    if (ev.data !== SEALED_ACTIVE) return;
    // A sealed-writer tab hearing another sealed writer needs nothing:
    // only reader-mode tabs retire themselves. This is also what makes
    // a reload loop between two writer tabs impossible.
    if (sealedWritesOn()) return;
    try {
      if (sessionStorage.getItem(RELOADED_MARKER)) return;
      sessionStorage.setItem(RELOADED_MARKER, '1');
    } catch {
      // Unreadable sessionStorage: reload anyway - the marker only
      // guards against repeats, and one reload is the desired outcome.
    }
    window.location.reload();
  };
}

/** The writer release announces itself once at boot, retiring any
 *  reader-mode tabs of the same origin. */
export function announceSealedWriter(): void {
  if (isDemoMode()) return;
  if (typeof BroadcastChannel === 'undefined') return;
  const channel = new BroadcastChannel(CHANNEL);
  channel.postMessage(SEALED_ACTIVE);
  channel.close();
}
