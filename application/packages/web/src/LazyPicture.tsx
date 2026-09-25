import { useEffect, useRef, useState } from 'react';
import { cachedPdfCover, loadPdfCover } from './EncryptedAttachment';
import { loadPictureUrl } from './mediaUrls';
import { useNearScreen } from './useNearScreen';

/**
 * A picture that fills its tile and decrypts only once the tile scrolls near
 * the screen, so a grid of two hundred uploads does not read two hundred
 * files to draw its first row. Spans throughout: the tiles are buttons.
 */
export function LazyPicture({ src }: { src: string }) {
  const [url, setUrl] = useState<string | null>(null);
  const ref = useRef<HTMLSpanElement>(null);
  const near = useNearScreen(ref);

  useEffect(() => {
    if (!near) return;
    let cancelled = false;
    void loadPictureUrl(src).then((u) => {
      if (!cancelled) setUrl(u);
    });
    return () => { cancelled = true; };
  }, [near, src]);

  return (
    <span ref={ref} className="absolute inset-0 block bg-neutral-200 dark:bg-neutral-800">
      {url && (
        <img src={url} alt="" className="absolute inset-0 w-full h-full object-cover" draggable={false} />
      )}
    </span>
  );
}

/**
 * A PDF's first page filling its tile, from the top, where a document names
 * itself. Drawn the way a picture tile decrypts: once the tile comes near the
 * screen. A PDF that cannot be drawn leaves the tile blank under its name.
 */
export function LazyPdfCover({ uuid }: { uuid: string }) {
  const [url, setUrl] = useState<string | null>(() => cachedPdfCover(uuid)?.url ?? null);
  const ref = useRef<HTMLSpanElement>(null);
  const near = useNearScreen(ref, url === null);

  useEffect(() => {
    if (!near || url) return;
    let cancelled = false;
    loadPdfCover(uuid).then((cover) => { if (!cancelled) setUrl(cover.url); }, () => {});
    return () => { cancelled = true; };
  }, [near, url, uuid]);

  return (
    <span ref={ref} className="absolute inset-0 block bg-neutral-200 dark:bg-neutral-800">
      {url && (
        <img src={url} alt="" className="absolute inset-0 w-full h-full object-cover object-top bg-white" draggable={false} />
      )}
    </span>
  );
}
