/**
 * Whether long lines in a code block fold to the width instead of scrolling
 * sideways. Default ON: sideways scrolling inside a page that scrolls down is
 * the worst of both on a phone.
 *
 * One value for every block, because a fenced block stores a language and
 * nothing else, so a per-block choice would have to be invented in the
 * user's own Markdown. Device-local like the appearance axes in theme.ts: a
 * phone always wants wrap, a wide screen showing an aligned table may not,
 * and a value somebody flips several times in one sitting would make two
 * devices overwrite each other through the settings blob.
 *
 * Its own module, and read lazily, because the code block's node view needs
 * it and the editor must not load theme.ts, which reads storage the moment
 * it is imported. theme.ts paints it at boot and resets it on an account
 * switch. The toggle is the button in the code block (editorExtensions.ts).
 * Spec: ops/docs/design-decisions.md (code blocks wrap by default)
 */
const CODE_WRAP_KEY = 'privacynotes.codeWrap';

let active: boolean | null = null;
const listeners = new Set<() => void>();

export function getCodeWrap(): boolean {
  if (active === null) {
    try { active = localStorage.getItem(CODE_WRAP_KEY) !== '0'; } catch { active = true; }
  }
  return active;
}

/** `pn-wrap-code` on <html>: the one class every code block's CSS follows. */
export function paintCodeWrap(): void {
  document.documentElement.classList.toggle('pn-wrap-code', getCodeWrap());
}

export function setCodeWrap(on: boolean): void {
  active = on;
  paintCodeWrap();
  try { localStorage.setItem(CODE_WRAP_KEY, on ? '1' : '0'); } catch { /* the class still flipped */ }
  listeners.forEach((cb) => cb());
}

/** Every mounted code block repaints its toggle through this. */
export function subscribeCodeWrap(cb: () => void): () => void {
  listeners.add(cb);
  return () => { listeners.delete(cb); };
}
