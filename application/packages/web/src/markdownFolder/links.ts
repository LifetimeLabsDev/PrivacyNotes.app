/**
 * Which file in the open folder a link in a local file points at.
 *
 * One rule per syntax, and no guessing between files:
 *   - `[[path/name]]` names a path from the TOP of the folder. The extension
 *     is optional, so `[[sub/bar]]` finds `sub/bar.md`.
 *   - `[text](path.md)` is relative to the file that holds it, which is what
 *     every Markdown renderer does with it, GitHub included.
 * Two files called `bar.md` in different folders therefore never compete: the
 * link says which one it means. The `[[` menu inserts the full path, so a link
 * made here always resolves.
 *
 * Lookup runs against the folder's scan and never against the disk, so a
 * `../` that climbs out of the folder simply finds nothing. The text of the
 * link is never rewritten: it is read at click time and the file keeps saying
 * what it said.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 3, note-links)
 */
import { SUPPORTED_EXTENSIONS } from './adapter';

const HAS_SUPPORTED_EXT = new RegExp(`\\.(${SUPPORTED_EXTENSIONS.join('|')})$`, 'i');

/** A scheme (`https:`, `mailto:`), a protocol-relative `//host`, or a bare
 *  `#anchor`: none of these name a file in the folder. */
export function isLocalHref(href: string): boolean {
  return !/^[a-z][a-z0-9+.-]*:/i.test(href) && !href.startsWith('//') && !href.startsWith('#');
}

/** Resolve `.` and `..` segments. Null when the path climbs above the top. */
function normalize(path: string): string | null {
  const out: string[] = [];
  for (const seg of path.replace(/\\/g, '/').split('/')) {
    if (seg === '' || seg === '.') continue;
    if (seg === '..') {
      if (out.length === 0) return null;
      out.pop();
    } else {
      out.push(seg);
    }
  }
  return out.length > 0 ? out.join('/') : null;
}

function decode(path: string): string {
  try {
    return decodeURI(path);
  } catch {
    return path;
  }
}

/** The first of `candidates` present in the scan, compared case-blind, as a
 *  Mac or Windows disk compares them. */
function findIn(relPaths: readonly string[], candidates: string[]): string | null {
  const byKey = new Map<string, string>();
  for (const p of relPaths) {
    const key = p.toLowerCase();
    if (!byKey.has(key)) byKey.set(key, p);
  }
  for (const c of candidates) {
    const hit = byKey.get(c.toLowerCase());
    if (hit) return hit;
  }
  return null;
}

/** Every path a bare name can mean, in the order the extensions are listed. */
function withExtensions(path: string): string[] {
  return HAS_SUPPORTED_EXT.test(path) ? [path] : SUPPORTED_EXTENSIONS.map((ext) => `${path}.${ext}`);
}

/**
 * The file a `[[target]]` opens. A `#heading` or `#^block` part is dropped:
 * the file opens at its top.
 */
export function resolveNoteLinkPath(relPaths: readonly string[], target: string): string | null {
  const path = normalize(target.split('#')[0]!.trim());
  return path ? findIn(relPaths, withExtensions(path)) : null;
}

/**
 * The file a relative `[text](href)` opens, read from the folder of
 * `fromRelPath`. Null for a web address, an anchor, or a path with nowhere
 * to go.
 */
export function resolveRelativeLinkPath(
  relPaths: readonly string[],
  fromRelPath: string,
  href: string,
): string | null {
  if (!isLocalHref(href)) return null;
  const bare = decode(href.split(/[?#]/)[0]!.trim());
  if (!bare) return null;
  const fromDir = fromRelPath.includes('/') ? fromRelPath.slice(0, fromRelPath.lastIndexOf('/') + 1) : '';
  const path = normalize(bare.startsWith('/') ? bare : `${fromDir}${bare}`);
  return path ? findIn(relPaths, withExtensions(path)) : null;
}

/** The `[[` menu entry for a file: its path from the top, extension dropped
 *  for markdown so the link reads the way Obsidian writes it. */
export function noteLinkPathFor(relPath: string): string {
  return relPath.replace(/\.(md|markdown|mdown|mkd)$/i, '');
}
