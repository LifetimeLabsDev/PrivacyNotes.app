/**
 * Perf instrumentation for the app-slowness profiling recipe
 * (ops/docs/backlog.md #130). Inert unless the build ran with
 * VITE_PERF=1 - without it every span is the same no-op closure and
 * Vite's dead-branch elimination strips the mark/measure calls.
 *
 * Instrumented spans: refresh, listNotes, buildSearchIndex, syncPass,
 * editorCreate (#150).
 * Read them in the console via performance.getEntriesByType('measure').
 */

const enabled = !!import.meta.env.VITE_PERF;

const noop = () => {};

let seq = 0;

/** Start a named span; call the returned function to end it. */
export function perfSpan(name: string): () => void {
  if (!enabled) return noop;
  const mark = `${name}#${seq++}`;
  performance.mark(mark);
  return () => {
    performance.measure(name, mark);
    performance.clearMarks(mark);
  };
}
