/**
 * The shared viewer: one picture or PDF at a time, from the list that opened
 * it, on a stage that fills the window.
 *
 * Nothing on the stage takes its size from the item except the item itself.
 * The bar is pinned to the top of the window and the arrows to its sides, so
 * they hold still under the pointer while each picture or PDF takes the room
 * it needs. A picture opens at its fitted size and is scaled up only by the
 * zoom buttons, and no control sits on it: the arrows have gutters of their
 * own, and on a phone they move into the bar.
 *
 * Spec: ops/docs/ui-patterns.md (section 98, the picture viewer)
 */
import { lazy, Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { CaretLeft, CaretRight, Download, MagnifyingGlassMinus, MagnifyingGlassPlus, X } from './icons';
import { useEscapeToClose } from './useEscapeToClose';
import { HoverLabel, type positionClasses } from './HoverLabel';
import { loadAttachmentData } from './EncryptedAttachment';
import { canSaveMedia, loadPictureUrl, saveMedia } from './mediaUrls';
import { FILE_REF_PREFIX, isPdfRef, type MediaRef } from './mediaRefs';

const PdfPages = lazy(() => import('./PdfPages').then((m) => ({ default: m.PdfPages })));

/** Zoom steps for the buttons, as multiples of the picture or PDF page at its
 *  fitted size. Pinch is off app-wide (`user-scalable=no`), so a picture runs
 *  its own pinch, between the same ends. */
const ZOOM_STEPS = [1, 1.5, 2, 3];
const MAX_ZOOM = ZOOM_STEPS[ZOOM_STEPS.length - 1]!;

function clampZoom(z: number): number {
  return Math.min(MAX_ZOOM, Math.max(1, z));
}

/** The widest a PDF page draws before any zoom, in CSS pixels: a page of text
 *  still reads in one glance, and the zoom steps go wider. */
const PDF_FIT_MAX = 872;

/** How far a finger travels sideways, in CSS pixels, before it is a swipe. */
const SWIPE_PX = 50;

/** How much of a fling's speed is left after one 60 Hz frame. */
const FLING_DECAY = 0.95;

/** How far a press may travel and still count as a tap on the backdrop. */
const TAP_SLOP_PX = 10;

function isRtl(): boolean {
  return document.documentElement.dir === 'rtl';
}

/** The empty stage around the item, marked `data-backdrop`. */
function isBackdrop(target: EventTarget | null): boolean {
  return target instanceof HTMLElement && target.dataset.backdrop !== undefined;
}

export function MediaViewer({ items, index: startIndex, onClose }: {
  items: MediaRef[];
  index: number;
  /** Told which item was on screen when the viewer closed. */
  onClose: (index: number) => void;
}) {
  const { t } = useTranslation('media');
  const [index, setIndex] = useState(startIndex);
  const [zoom, setZoom] = useState(1);
  const [saving, setSaving] = useState(false);
  // The item whose save failed. A failed native save can leave an empty or
  // partial file, so the message stays until a save succeeds; a dismissed
  // dialog changes nothing.
  const [failedSave, setFailedSave] = useState<string | null>(null);
  const stageRef = useRef<HTMLDivElement>(null);
  const backdropPress = useRef<{ x: number; y: number } | null>(null);
  const swipe = useRef<{ x: number; y: number; id: number } | null>(null);

  const item = items[index]!;
  const count = items.length;
  const pdf = isPdfRef(item);
  const title = item.name || (pdf ? 'PDF' : t('attachment.imageAlt'));

  const close = useCallback(() => onClose(index), [onClose, index]);
  useEscapeToClose(close);

  const go = useCallback((delta: number) => {
    setIndex((i) => Math.min(count - 1, Math.max(0, i + delta)));
    setZoom(1);
  }, [count]);

  // The arrow keys move through the list. In a right-to-left layout the list
  // runs leftward, so the keys follow the arrows drawn on screen.
  useEffect(() => {
    if (count < 2) return;
    const onKey = (e: KeyboardEvent) => {
      if (e.key !== 'ArrowLeft' && e.key !== 'ArrowRight') return;
      if (e.altKey || e.ctrlKey || e.metaKey || e.shiftKey) return;
      e.preventDefault();
      e.stopPropagation();
      go((e.key === 'ArrowRight') !== isRtl() ? 1 : -1);
    };
    window.addEventListener('keydown', onKey, true);
    return () => window.removeEventListener('keydown', onKey, true);
  }, [count, go]);

  // Focus moves into the dialog, and back to whatever held it on close.
  useEffect(() => {
    const before = document.activeElement instanceof HTMLElement ? document.activeElement : null;
    stageRef.current?.focus({ preventScroll: true });
    return () => before?.focus({ preventScroll: true });
  }, []);

  // The neighbours decrypt in the background, so an arrow answers at once.
  useEffect(() => {
    for (const i of [index - 1, index + 1]) {
      const near = items[i];
      if (near && !isPdfRef(near)) void loadPictureUrl(near.src);
    }
  }, [index, items]);

  const loadPdf = useCallback(async () => {
    if (!item.src.startsWith(FILE_REF_PREFIX)) return null;
    const att = await loadAttachmentData(item.src.slice(FILE_REF_PREFIX.length));
    // pdf.js takes ownership of the bytes it is given, so it gets a copy.
    return att ? new Uint8Array(att.data) : null;
  }, [item.src]);

  const save = useCallback(async () => {
    setSaving(true);
    try {
      const saved = await saveMedia(item);
      if (saved?.ok) setFailedSave(null);
      else if (saved?.reason === 'failed') setFailedSave(item.src);
    } finally {
      setSaving(false);
    }
  }, [item]);

  // A swipe is a finger's gesture; a mouse drag over a picture is not one.
  const onPointerDown = (e: React.PointerEvent) => {
    swipe.current = e.pointerType === 'mouse' || count < 2 || zoom > 1
      ? null
      : { x: e.clientX, y: e.clientY, id: e.pointerId };
  };
  const onPointerUp = (e: React.PointerEvent) => {
    const start = swipe.current;
    swipe.current = null;
    if (!start || start.id !== e.pointerId) return;
    const dx = e.clientX - start.x;
    const dy = e.clientY - start.y;
    if (Math.abs(dx) < SWIPE_PX || Math.abs(dx) < Math.abs(dy)) return;
    // Pulling the picture leftward shows the next one, mirrored for RTL.
    go((dx < 0) !== isRtl() ? 1 : -1);
  };

  const previous = (tip: keyof typeof positionClasses, edge: boolean) => (
    <StageButton label={t('viewer.previous')} tip={tip} edge={edge} disabled={index === 0} onClick={() => go(-1)}>
      <CaretLeft size={edge ? 22 : 18} />
    </StageButton>
  );
  const next = (tip: keyof typeof positionClasses, edge: boolean) => (
    <StageButton label={t('viewer.next')} tip={tip} edge={edge} disabled={index === count - 1} onClick={() => go(1)}>
      <CaretRight size={edge ? 22 : 18} />
    </StageButton>
  );

  return createPortal(
    <div
      ref={stageRef}
      tabIndex={-1}
      role="dialog"
      aria-modal="true"
      aria-label={title}
      data-no-app-menu=""
      data-backdrop=""
      // A tap on the empty stage closes it, and only a tap: a swipe that
      // starts beside the picture, or a press that ends on a button, does not.
      onPointerDown={(e) => {
        backdropPress.current = isBackdrop(e.target) ? { x: e.clientX, y: e.clientY } : null;
      }}
      onClick={(e) => {
        const press = backdropPress.current;
        backdropPress.current = null;
        if (!press || !isBackdrop(e.target)) return;
        if (Math.hypot(e.clientX - press.x, e.clientY - press.y) > TAP_SLOP_PX) return;
        close();
      }}
      className="fixed inset-0 z-50 flex flex-col bg-black/95 text-white outline-none"
    >
      <div className="shrink-0 pt-[env(safe-area-inset-top)]">
        <div className="h-14 flex items-center gap-1 px-2 sm:px-4">
          <h2 className="flex-1 min-w-0 px-2 text-sm font-medium truncate" dir="auto">{title}</h2>
          <div className="shrink-0 flex items-center">
            <StageButton
              label={t('viewer.zoomOut')}
              disabled={zoom <= 1}
              onClick={() => setZoom((z) => [...ZOOM_STEPS].reverse().find((s) => s < z - 0.01) ?? 1)}
            >
              <MagnifyingGlassMinus size={18} />
            </StageButton>
            <StageButton
              label={t('viewer.zoomIn')}
              disabled={zoom >= MAX_ZOOM}
              onClick={() => setZoom((z) => ZOOM_STEPS.find((s) => s > z + 0.01) ?? MAX_ZOOM)}
            >
              <MagnifyingGlassPlus size={18} />
            </StageButton>
          </div>
          {count > 1 && (
            <div className="shrink-0 flex items-center">
              <span className="sm:hidden">{previous('below', false)}</span>
              <span className="px-1.5 text-xs tabular-nums text-white/60 whitespace-nowrap">
                {t('viewer.position', { index: index + 1, count })}
              </span>
              <span className="sm:hidden">{next('below', false)}</span>
            </div>
          )}
          {canSaveMedia(item) && (
            <StageButton label={t('attachment.download')} disabled={saving} onClick={() => void save()}>
              <Download size={18} />
            </StageButton>
          )}
          <StageButton label={t('common:actions.close')} tip="below-end" onClick={close}>
            <X size={20} />
          </StageButton>
        </div>
        {failedSave === item.src && (
          <p className="px-4 pb-2 text-xs text-red-400">{t('viewer.saveFailed')}</p>
        )}
      </div>
      <div data-backdrop="" className="flex-1 min-h-0 flex pb-[max(1rem,env(safe-area-inset-bottom))]">
        <div data-backdrop="" className="hidden sm:flex w-16 shrink-0 items-center justify-center">
          {count > 1 && previous('end', true)}
        </div>
        <div data-backdrop="" className="flex-1 min-w-0 min-h-0">
          {pdf ? (
            <Suspense fallback={<Notice text={t('viewer.pdfLoading')} />}>
              <PdfPages
                key={item.src}
                load={loadPdf}
                zoom={zoom}
                fitMax={PDF_FIT_MAX}
                label={title}
              />
            </Suspense>
          ) : (
            <Picture
              key={item.src}
              src={item.src}
              alt={title}
              zoom={zoom}
              onZoom={setZoom}
              onPointerDown={onPointerDown}
              onPointerUp={onPointerUp}
              onPointerCancel={() => { swipe.current = null; }}
            />
          )}
        </div>
        <div data-backdrop="" className="hidden sm:flex w-16 shrink-0 items-center justify-center">
          {count > 1 && next('start', true)}
        </div>
      </div>
    </div>,
    document.body,
  );
}

/** A control on the stage: a square in the bar, or a round arrow in a gutter. */
function StageButton({ label, tip = 'below', edge = false, disabled = false, onClick, children }: {
  label: string;
  tip?: keyof typeof positionClasses;
  edge?: boolean;
  disabled?: boolean;
  onClick: () => void;
  children: React.ReactNode;
}) {
  return (
    <HoverLabel label={label} position={tip}>
      <button
        type="button"
        onClick={onClick}
        disabled={disabled}
        aria-label={label}
        className={`flex items-center justify-center text-white/80 hover:text-white transition outline-none focus-visible:ring-2 focus-visible:ring-white/70 disabled:opacity-30 disabled:pointer-events-none ${
          edge ? 'w-11 h-11 rounded-full bg-white/10 hover:bg-white/20' : 'w-9 h-9 rounded-md hover:bg-white/10'
        }`}
      >
        {children}
      </button>
    </HoverLabel>
  );
}

function Notice({ text }: { text: string }) {
  return (
    <div className="h-full flex items-center justify-center p-6 text-sm text-center text-white/70">
      {text}
    </div>
  );
}

/**
 * The picture at its stored size, shrunk to fit the stage and never scaled
 * up on its own. A zoom above 1 sizes it at that multiple of the fitted size
 * and lets it scroll. Two fingers pinch it, and a trackpad pinch does the
 * same. The area around it is backdrop, so a tap beside a small picture
 * closes the viewer the way a tap on the stage does.
 */
function Picture({ src, alt, zoom, onZoom, onPointerDown, onPointerUp, onPointerCancel }: {
  src: string;
  alt: string;
  zoom: number;
  onZoom: React.Dispatch<React.SetStateAction<number>>;
  onPointerDown: (e: React.PointerEvent) => void;
  onPointerUp: (e: React.PointerEvent) => void;
  onPointerCancel: () => void;
}) {
  const { t } = useTranslation('media');
  const [url, setUrl] = useState<string | null>(null);
  const [failed, setFailed] = useState(false);
  const boxRef = useRef<HTMLDivElement>(null);
  const imgRef = useRef<HTMLImageElement>(null);
  const [box, setBox] = useState({ w: 0, h: 0 });
  const [natural, setNatural] = useState({ w: 0, h: 0 });
  // The point of the picture that holds still when the zoom changes, as a
  // fraction of the picture, and where it sits in the view. The buttons keep
  // the middle of the view; a pinch keeps the point between the fingers.
  const anchor = useRef({ fx: 0.5, fy: 0.5, px: 0, py: 0 });
  const fingers = useRef(new Map<number, { x: number; y: number }>());
  const pinch = useRef<{ dist: number; zoom: number; fx: number; fy: number } | null>(null);
  // The finger's speed in CSS pixels per millisecond, carried on after it
  // lifts so a flicked picture slides to a stop the way a scroll does.
  const velocity = useRef({ x: 0, y: 0, t: 0 });
  const fling = useRef(0);
  useEffect(() => () => cancelAnimationFrame(fling.current), []);
  const zoomNow = useRef(zoom);
  useEffect(() => { zoomNow.current = zoom; }, [zoom]);

  /** Anchors the picture at a point given in client pixels. */
  const anchorAt = (clientX: number, clientY: number) => {
    const el = boxRef.current;
    const img = imgRef.current;
    if (!el || !img || !img.offsetWidth) return;
    const rect = el.getBoundingClientRect();
    const px = clientX - rect.left;
    const py = clientY - rect.top;
    anchor.current = {
      fx: (el.scrollLeft + px - img.offsetLeft) / img.offsetWidth,
      fy: (el.scrollTop + py - img.offsetTop) / img.offsetHeight,
      px,
      py,
    };
  };
  const anchorCenter = () => {
    const rect = boxRef.current?.getBoundingClientRect();
    if (rect) anchorAt(rect.left + rect.width / 2, rect.top + rect.height / 2);
  };

  useEffect(() => {
    let alive = true;
    void loadPictureUrl(src).then((u) => {
      if (!alive) return;
      if (u) setUrl(u);
      else setFailed(true);
    });
    return () => { alive = false; };
  }, [src]);

  // The outer size, so the scrollbars a zoom brings never change the fit. It
  // matters only once the picture has a size of its own.
  const loaded = natural.w > 0;
  useEffect(() => {
    const el = boxRef.current;
    if (!el || !loaded) return;
    const measure = () => setBox({ w: el.offsetWidth, h: el.offsetHeight });
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [loaded]);

  // A trackpad pinch arrives as a wheel event with ctrlKey in Chrome and
  // Firefox, and as gesture events in Safari. Both must be stopped here, or
  // the page zooms. On a touch screen Safari sends gesture events beside the
  // pointer events, so they count only while no finger is down.
  useEffect(() => {
    const el = boxRef.current;
    if (!el || !loaded) return;
    let gestureStart = 1;
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey) return;
      e.preventDefault();
      anchorAt(e.clientX, e.clientY);
      onZoom((z) => clampZoom(z * Math.exp(-e.deltaY / 100)));
    };
    type GestureEvent = UIEvent & { scale: number; clientX: number; clientY: number };
    const onGestureStart = (e: Event) => {
      e.preventDefault();
      gestureStart = zoomNow.current;
    };
    const onGestureChange = (e: Event) => {
      e.preventDefault();
      const g = e as GestureEvent;
      if (fingers.current.size > 0) return;
      anchorAt(g.clientX, g.clientY);
      onZoom(clampZoom(gestureStart * g.scale));
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    el.addEventListener('gesturestart', onGestureStart);
    el.addEventListener('gesturechange', onGestureChange);
    return () => {
      el.removeEventListener('wheel', onWheel);
      el.removeEventListener('gesturestart', onGestureStart);
      el.removeEventListener('gesturechange', onGestureChange);
    };
  }, [loaded, onZoom]); // eslint-disable-line react-hooks/exhaustive-deps

  const fit = Math.min(1, box.w / natural.w, box.h / natural.h);
  const size = zoom > 1 && loaded
    ? { width: Math.floor(natural.w * fit * zoom), height: Math.floor(natural.h * fit * zoom) }
    : null;

  useLayoutEffect(() => {
    const el = boxRef.current;
    const img = imgRef.current;
    if (!el || !img) return;
    const a = anchor.current;
    el.scrollLeft = img.offsetLeft + a.fx * img.offsetWidth - a.px;
    el.scrollTop = img.offsetTop + a.fy * img.offsetHeight - a.py;
    // A clamped position fires no scroll event, so the anchor is read back here.
    anchorCenter();
  }, [size?.width]); // eslint-disable-line react-hooks/exhaustive-deps

  // Two fingers on the picture are a pinch: they never swipe, and the zoom
  // follows the distance between them from where it stood when they landed.
  // One finger on a zoomed picture pans it. The browser pan is not used: once
  // it starts, a second finger never reaches the pinch.
  const spread = () => {
    const [a, b] = [...fingers.current.values()];
    return { dist: Math.hypot(a!.x - b!.x, a!.y - b!.y), x: (a!.x + b!.x) / 2, y: (a!.y + b!.y) / 2 };
  };
  const startFling = () => {
    let { x: vx, y: vy } = velocity.current;
    let last = performance.now();
    const step = (now: number) => {
      const el = boxRef.current;
      if (!el) return;
      const dt = now - last;
      last = now;
      el.scrollLeft -= vx * dt;
      el.scrollTop -= vy * dt;
      const decay = FLING_DECAY ** (dt / 16);
      vx *= decay;
      vy *= decay;
      if (Math.hypot(vx, vy) > 0.02) fling.current = requestAnimationFrame(step);
    };
    fling.current = requestAnimationFrame(step);
  };
  const onFingerDown = (e: React.PointerEvent) => {
    cancelAnimationFrame(fling.current);
    if (e.pointerType === 'mouse') return onPointerDown(e);
    fingers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    velocity.current = { x: 0, y: 0, t: e.timeStamp };
    if (fingers.current.size !== 2) return onPointerDown(e);
    onPointerCancel();
    const { dist, x, y } = spread();
    anchorAt(x, y);
    pinch.current = { dist, zoom, fx: anchor.current.fx, fy: anchor.current.fy };
  };
  const onFingerMove = (e: React.PointerEvent) => {
    const last = fingers.current.get(e.pointerId);
    if (!last) return;
    fingers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (fingers.current.size === 1 && size) {
      const dx = e.clientX - last.x;
      const dy = e.clientY - last.y;
      boxRef.current!.scrollLeft -= dx;
      boxRef.current!.scrollTop -= dy;
      const v = velocity.current;
      const dt = e.timeStamp - v.t;
      if (dt > 0) {
        // Smoothed, so one uneven sample does not set the speed.
        velocity.current = { x: 0.6 * dx / dt + 0.4 * v.x, y: 0.6 * dy / dt + 0.4 * v.y, t: e.timeStamp };
      }
      return;
    }
    const start = pinch.current;
    if (!start || fingers.current.size !== 2) return;
    const { dist, x, y } = spread();
    const rect = boxRef.current!.getBoundingClientRect();
    anchor.current = { fx: start.fx, fy: start.fy, px: x - rect.left, py: y - rect.top };
    onZoom(clampZoom(start.zoom * dist / start.dist));
  };
  const onFingerUp = (e: React.PointerEvent, cancelled: boolean) => {
    fingers.current.delete(e.pointerId);
    if (pinch.current) {
      if (fingers.current.size < 2) pinch.current = null;
      return;
    }
    // A finger that stopped before it lifted leaves the picture where it is.
    if (!cancelled && size && fingers.current.size === 0 && e.timeStamp - velocity.current.t < 50) startFling();
    if (cancelled) onPointerCancel();
    else onPointerUp(e);
  };

  return (
    <div
      ref={boxRef}
      data-backdrop=""
      onPointerDown={onFingerDown}
      onPointerMove={onFingerMove}
      onPointerUp={(e) => onFingerUp(e, false)}
      onPointerCancel={(e) => onFingerUp(e, true)}
      onScroll={anchorCenter}
      // touch-none hands every finger movement here, for the swipe, the pinch
      // and the pan. A zoomed picture centers by m-auto, which still lets
      // every edge of a larger picture scroll into view.
      className={`relative h-full flex select-none touch-none ${size ? 'overflow-auto' : 'items-center justify-center'}`}
    >
      {url ? (
        <img
          ref={imgRef}
          src={url}
          alt={alt}
          onLoad={(e) => {
            setNatural({ w: e.currentTarget.naturalWidth, h: e.currentTarget.naturalHeight });
            anchorCenter();
          }}
          style={size ?? undefined}
          className={`block m-auto ${size ? 'max-w-none shrink-0' : 'max-w-full max-h-full'}`}
          draggable={false}
        />
      ) : (
        <Notice text={failed ? t('image.notFound') : t('image.loading')} />
      )}
    </div>
  );
}
