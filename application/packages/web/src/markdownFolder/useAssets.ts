/**
 * Making a note's relative image references displayable, and putting them back
 * exactly as they were on save.
 *
 * A vault writes images as paths: `![](attachments/x.png)`, or Obsidian's
 * `![[x.png]]`. Neither means anything to an `<img>` in our app - one resolves
 * against the page URL, the other is not even image syntax. So on the way IN
 * each reference is swapped for a URL the webview can load, and on the way OUT
 * every one of those URLs is swapped back for the original text.
 *
 * The round trip is the entire point, and it is why this is a two-way map
 * rather than a rewrite. **The user's file must keep saying what it said.** A
 * blob URL reaching disk would be a dead link the moment the tab closed, and it
 * would have replaced a path that was correct in every other editor they own.
 * Anything that fails to resolve is left completely untouched, so a broken
 * image link stays broken-but-intact rather than being rewritten into
 * something new.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 8, media)
 */
import { useEffect, useState } from 'react';
import type { OpenedDirectoryRef } from './fileAccess';

/** `![alt](path)` where the path is relative - not a URL, not one of our own
 *  `pn:img/` refs, which belong to the encrypted store and never appear here. */
const MD_IMAGE = /!\[([^\]]*)\]\(([^)\s]+)\)/g;
/** Obsidian's embed. Only treated as an image when it names an image file;
 *  `![[Other Note]]` is a note embed and is left alone. */
const WIKI_EMBED = /!\[\[([^\]]+?)\]\]/g;
const IMAGE_EXT = /\.(png|jpe?g|gif|webp|svg|avif|bmp)$/i;

function isRelative(path: string): boolean {
  return !/^[a-z][a-z0-9+.-]*:/i.test(path) && !path.startsWith('//') && !path.startsWith('/');
}

/** Every distinct relative image path a note references, spelled exactly as the
 *  file spells it - percent-escapes included. Decoding here would make the
 *  decoded form the thing `restoreAssets` writes back, and
 *  `![](my%20image.png)` would save as `![](my image.png)`, which no longer
 *  matches `MD_IMAGE` and is a dead link in Obsidian and on GitHub too. */
function imageRefs(markdown: string): string[] {
  const found = new Set<string>();
  for (const [, , path] of markdown.matchAll(MD_IMAGE)) {
    if (path && isRelative(path) && IMAGE_EXT.test(path)) found.add(path);
  }
  for (const [, target] of markdown.matchAll(WIKI_EMBED)) {
    if (target && IMAGE_EXT.test(target)) found.add(target);
  }
  return [...found];
}

/**
 * Swap resolved references for their URLs.
 *
 * Obsidian embeds become ordinary markdown images, because that is the only
 * form our editor renders. `restoreAssets` turns them back, so the file keeps
 * its `![[…]]` syntax.
 */
export function applyAssets(markdown: string, urls: Map<string, string>): string {
  if (urls.size === 0) return markdown;
  let out = markdown.replace(MD_IMAGE, (whole, alt: string, path: string) => {
    const url = urls.get(path);
    return url ? `![${alt}](${url})` : whole;
  });
  out = out.replace(WIKI_EMBED, (whole, target: string) => {
    const url = urls.get(target);
    return url ? `![${target}](${url})` : whole;
  });
  return out;
}

/** Put every swapped URL back to the exact text it replaced. */
export function restoreAssets(markdown: string, urls: Map<string, string>): string {
  if (urls.size === 0) return markdown;
  return markdown.replace(MD_IMAGE, (whole, alt: string, path: string) => {
    const original = originalFor(path, urls);
    if (original === null) return whole;
    // An Obsidian embed round-trips back to an embed. The alt we synthesised
    // was the path itself, so a user who did not touch it gets their exact
    // line back; one who edited the alt keeps the edit as markdown syntax,
    // which is the only shape that can carry it.
    return alt === original ? `![[${original}]]` : `![${alt}](${original})`;
  });
}

function originalFor(url: string, urls: Map<string, string>): string | null {
  for (const [original, resolved] of urls) if (resolved === url) return original;
  return null;
}

/**
 * Resolve a note's images against the folder, relative to the note's own
 * directory first and the vault root second - which is how Obsidian resolves
 * them, and how anyone moving a note between the two apps expects it to work.
 */
export function useAssets(
  markdown: string,
  dir: OpenedDirectoryRef | null,
  noteDir: string,
): Map<string, string> {
  // Reference text -> loadable URL. The key is the reference EXACTLY as the
  // file spells it, because `restoreAssets` writes that key straight back into
  // the note on save; only the filesystem lookup below sees a decoded path.
  const [urls, setUrls] = useState<Map<string, string>>(new Map());

  useEffect(() => {
    if (!dir) { setUrls(new Map()); return; }
    const refs = imageRefs(markdown);
    if (refs.length === 0) { setUrls(new Map()); return; }

    let cancelled = false;
    const created: string[] = [];

    void (async () => {
      const resolved = new Map<string, string>();
      const taken = new Set<string>();
      for (const ref of refs) {
        const rel = decodePath(ref);
        const url =
          (await resolveQuietly(dir, `${noteDir}${rel}`)) ?? (await resolveQuietly(dir, rel));
        // Recorded before the cancellation check: a blob minted by the run that
        // lost the race still has to be revoked, or it pins the file forever.
        if (url?.startsWith('blob:')) created.push(url);
        if (cancelled) break;
        if (!url) continue;
        // `restoreAssets` finds a reference's original text by searching for
        // its URL, so two spellings of one path must never share a URL - the
        // second would restore as the first. Blobs are unique per call, but the
        // desktop's asset: URLs are derived from the decoded path and do
        // collide. The loser stays unresolved: it renders as plain text, and
        // its spelling survives the save, which is the half that matters.
        if (taken.has(url)) continue;
        taken.add(url);
        resolved.set(ref, url);
      }
      if (cancelled) return;
      setUrls(resolved);
    })();

    return () => {
      cancelled = true;
      // Blob URLs pin the file in memory until revoked. Only ours are revoked;
      // the desktop's asset: URLs are not objects and must be left alone.
      for (const url of created) URL.revokeObjectURL(url);
    };
    // Keyed on the note's identity, not its text: re-resolving on every
    // keystroke would rebuild every blob while the user types.
    // eslint-disable-next-line react-hooks/exhaustive-deps
  }, [dir, noteDir, markdownIdentity(markdown)]);

  return urls;
}

/** The set of image references, as a stable string. Changes only when the note
 *  starts or stops pointing at something, which is when a re-resolve is due.
 *  Joined on NUL because it is the one byte a path cannot contain. */
function markdownIdentity(markdown: string): string {
  return imageRefs(markdown).join('\0');
}

/**
 * The path as the filesystem knows it. Percent-escapes are how a vault writes a
 * filename with a space, so the lookup has to decode - but only the lookup: the
 * map key stays verbatim so the file keeps its own spelling.
 *
 * A malformed escape falls back to the raw text rather than throwing. `%` is a
 * legal filename character, so `100%.png` is far more likely a real name than a
 * truncated escape, and `decodeURI` throws on it - a throw this module cannot
 * afford (see `resolveQuietly`).
 */
function decodePath(path: string): string {
  try {
    return decodeURI(path);
  } catch {
    return path;
  }
}

/**
 * Resolution never throws.
 *
 * `applyAssets` runs during render and there is no error boundary anywhere in
 * the app, so a throw on one broken image reference unmounts the whole window
 * to a blank screen. Failing to null instead lands on the behaviour this module
 * already wants: an unresolvable reference is left exactly as the file wrote
 * it. The adapters return null for the ordinary missing-file case on their own,
 * so anything caught here is a genuine fault and is worth a console line.
 */
async function resolveQuietly(dir: OpenedDirectoryRef, relPath: string): Promise<string | null> {
  try {
    return await dir.resolveAsset(relPath);
  } catch (e) {
    console.warn('[assets] resolve failed', relPath, e);
    return null;
  }
}
