import { Component, lazy, Suspense, type ComponentType, type ReactNode } from 'react';

/**
 * Code split into chunks that load on first use, and what happens when one
 * fails to load. Vite raises `vite:preloadError` for a failed chunk, almost
 * always because the tab outlived a deploy and asks for a chunk hash the CDN
 * no longer has; one reload per tab session fetches the new entry bundle.
 * The native apps load chunks from the bundle, so this is the web tab's.
 */

const RELOADED_KEY = 'pn:reloaded-for-preload-error';
let prefetches = 0;

/**
 * The `vite:preloadError` handler. It reloads once per tab session (the flag
 * clears on tab close, and a second failure after the reload falls through
 * to the caller, because then a reload will not help). Never offline: the
 * reload would land on the browser's error page, so the failure goes to the
 * caller and `pn:chunk-offline` lets the app say why. Never for a prefetch:
 * nobody asked for that chunk yet, and its caller ignores the failure.
 */
export function onPreloadError(event: Event): void {
  if (prefetches > 0) return;
  if (!navigator.onLine) {
    window.dispatchEvent(new Event('pn:chunk-offline'));
    return;
  }
  if (sessionStorage.getItem(RELOADED_KEY) === '1') return;
  sessionStorage.setItem(RELOADED_KEY, '1');
  event.preventDefault();
  window.location.reload();
}

/** Fetch a chunk ahead of need, so it works offline later. */
export function prefetchChunk(load: () => Promise<unknown>): void {
  prefetches++;
  load().catch(() => {}).finally(() => { prefetches--; });
}

/** The error a dynamic import throws when its chunk cannot be fetched. */
export function isChunkLoadError(err: unknown): boolean {
  return err instanceof Error
    && /dynamically imported module|module script failed|unable to preload/i.test(err.message);
}

/**
 * Catches a chunk that failed to load below it and renders nothing, so the
 * caller can close or retry. Any other error is rethrown to the boundary
 * above: a bug in a component must not read as a missing chunk.
 */
class ChunkBoundary extends Component<{ onError: () => void; children: ReactNode }, { error: unknown }> {
  state: { error: unknown } = { error: null };

  static getDerivedStateFromError(error: unknown) {
    return { error };
  }

  componentDidCatch(error: unknown) {
    if (isChunkLoadError(error)) this.props.onError();
  }

  render() {
    const { error } = this.state;
    if (error === null) return this.props.children;
    if (!isChunkLoadError(error)) throw error;
    return null;
  }
}

/** A lazy component that loads again after a failed load: React keeps a
 *  failed lazy load for good, so a fresh one replaces it. */
function retryingLazy<P extends object>(load: () => Promise<ComponentType<P>>) {
  const make = () => lazy(async () => ({
    default: (await load()) as ComponentType<unknown>,
  })) as unknown as ComponentType<P>;
  let Inner = make();
  return {
    Inner: () => Inner,
    remake: () => { Inner = make(); },
  };
}

/**
 * Code-split a modal component while keeping its call sites identical.
 * The returned component lazy-loads the chunk on first render; the null
 * Suspense fallback means the modal simply appears a frame later (instant
 * on warm cache, ~one round-trip cold). This keeps the heavy, rarely-open
 * modals (stats, settings, security, about, feedback, import, history) and the
 * Settings window with its sheets out of the boot-path bundle. Never wrap a
 * component that renders an editor this way: see the Markdown imports in
 * NotesView.tsx for the crash a Suspense boundary above TipTap causes.
 *
 * A chunk that fails to load closes the modal (its `onClose`) instead of
 * replacing the app with the crash screen, and the next open loads it again.
 * A lazy part inside a modal is a `lazyPart`, so it loads again too.
 */
export function lazyModal<P extends object>(
  load: () => Promise<ComponentType<P>>,
): ComponentType<P> {
  const lazyLoad = retryingLazy(load);
  return function LazyModal(props: P) {
    const Inner = lazyLoad.Inner();
    const failed = () => {
      lazyLoad.remake();
      (props as { onClose?: () => void }).onClose?.();
    };
    return (
      <ChunkBoundary onError={failed}>
        <Suspense fallback={null}>
          <Inner {...props} />
        </Suspense>
      </ChunkBoundary>
    );
  };
}

/**
 * A lazy-loaded part of a window that is already open. Its caller keeps its
 * own Suspense fallback. A chunk that fails to load leaves the part empty and
 * the next mount loads it again; the window stays open.
 */
export function lazyPart<P extends object>(
  load: () => Promise<ComponentType<P>>,
): ComponentType<P> {
  const lazyLoad = retryingLazy(load);
  return function LazyPart(props: P) {
    const Inner = lazyLoad.Inner();
    return (
      <ChunkBoundary onError={lazyLoad.remake}>
        <Inner {...props} />
      </ChunkBoundary>
    );
  };
}
