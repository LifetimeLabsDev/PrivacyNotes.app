/** A path this app serves itself. A leading slash is not enough: `//host/x`
 *  and `/\host/x` name another host, which the browser resolves to, so a
 *  fetch or an image of such a path must resolve to our own origin too. */
export function isSameOriginPath(ref: string): boolean {
  if (!ref.startsWith('/') || ref.startsWith('//') || ref.startsWith('/\\')) return false;
  try {
    return new URL(ref, location.origin).origin === location.origin;
  } catch {
    return false;
  }
}
