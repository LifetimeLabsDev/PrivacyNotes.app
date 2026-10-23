/**
 * The shared viewer: one picture, PDF or saved email at a time, from the list that opened
 * it, on a stage that fills the window.
 *
 * Nothing on the stage takes its size from the item except the item itself.
 * The bar is pinned to the top of the window and the arrows to its sides, so
 * they hold still under the pointer while each picture or PDF takes the room
 * it needs. A picture opens at its fitted size and is scaled up only by the
 * zoom buttons, and no control sits on it: the arrows have gutters of their
 * own, and on a phone they move into the bar.
 *
 * Spec: ops/docs/archive/ui-patterns.md (section 98, the picture viewer)
 */
import { Suspense, useCallback, useEffect, useLayoutEffect, useRef, useState } from 'react';
import { lazyPart } from './chunkLoad';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import { CaretLeft, CaretRight, Download, MagnifyingGlassMinus, MagnifyingGlassPlus, X } from './icons';
import { useEscapeToClose } from './useEscapeToClose';
import { HoverLabel, type positionClasses } from './HoverLabel';
import { loadAttachmentData } from './EncryptedAttachment';
import { canSaveMedia, loadPictureUrl, saveMedia } from './mediaUrls';
import { FILE_REF_PREFIX, isDocumentRef, isMailRef, isPdfRef, type MediaRef } from './mediaRefs';
import { clampPan, fittedBase, toTransform, zoomAround, type Size, type ZoomView } from './viewerZoom';

const PdfPages = lazyPart(() => import('./PdfPages').then((m) => m.PdfPages));
const MailView = lazyPart(() => import('./MailView').then((m) => m.MailView));

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
  const mail = isMailRef(item);
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
      if (near && !isDocumentRef(near)) void loadPictureUrl(near.src);
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
          {/* A mail is text that scrolls; zoom is for pictures and pages. */}
          <div className={`shrink-0 flex items-center${mail ? ' invisible' : ''}`}>
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
          {mail ? (
            <Suspense fallback={<Notice text={t('mail.loading')} />}>
              <MailView key={item.src} uuid={item.src.slice(FILE_REF_PREFIX.length)} />
            </Suspense>
          ) : pdf ? (
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
 * The picture, shrunk to fit the stage and never scaled up on its own. It is
 * laid out once at its largest zoom and shown through one transform, so a
 * pinch, a pan or a flick only moves that transform: no React render, no
 * layout, no scroll. The zoom and the position live in a ref while a finger
 * is down, and the zoom reaches the parent (the buttons, the swipe gate) when
 * the gesture ends. The area around the picture is backdrop, so a tap beside
 * a small picture closes the viewer the way a tap on the stage does.
 * Spec: ops/docs/archive/viewer-pinch-zoom.md
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
  const [box, setBox] = useState<Size>({ w: 0, h: 0 });
  const [natural, setNatural] = useState<Size>({ w: 0, h: 0 });
  const loaded = natural.w > 0;
  const measured = loaded && box.w > 0;
  const base = measured ? fittedBase(natural, box, MAX_ZOOM) : null;
  const view = useRef<ZoomView>({ zoom: 1, tx: 0, ty: 0 });
  const fingers = useRef(new Map<number, { x: number; y: number }>());
  const pinch = useRef<{ dist: number; x: number; y: number } | null>(null);
  // The finger's speed in CSS pixels per millisecond, carried on after it
  // lifts so a flicked picture slides to a stop the way a scroll does.
  const velocity = useRef({ x: 0, y: 0, t: 0 });
  const fling = useRef(0);
  useEffect(() => () => cancelAnimationFrame(fling.current), []);

  /** Clamps the view to the stage and shows it. `animate` eases a button step. */
  const paint = (animate = false) => {
    const img = imgRef.current;
    if (!img || !base) return;
    view.current = clampPan(view.current, box, base, MAX_ZOOM);
    img.style.transition = animate ? 'transform 150ms ease-out' : '';
    img.style.transform = toTransform(view.current, MAX_ZOOM);
  };
  /** Hands a zoom a gesture settled on to the parent. */
  const commit = () => onZoom(view.current.zoom);
  /** A stage pixel from a client pixel. */
  const local = (clientX: number, clientY: number) => {
    const rect = boxRef.current!.getBoundingClientRect();
    return { x: clientX - rect.left, y: clientY - rect.top };
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

  useEffect(() => {
    const el = boxRef.current;
    if (!el || !loaded) return;
    const measure = () => setBox({ w: el.clientWidth, h: el.clientHeight });
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, [loaded]);

  // A new layout size (the first measure, a resize, a rotation) keeps the
  // point at the middle of the view where it was.
  const lastBase = useRef<Size | null>(null);
  useLayoutEffect(() => {
    if (!base) return;
    const prev = lastBase.current;
    if (prev) {
      const v = view.current;
      const k = base.w / prev.w;
      const cx = box.w / 2;
      const cy = box.h / 2;
      view.current = { zoom: v.zoom, tx: cx - (cx - v.tx) * k, ty: cy - (cy - v.ty) * k };
    }
    lastBase.current = base;
    paint();
  }, [base?.w, base?.h, box.w, box.h]); // eslint-disable-line react-hooks/exhaustive-deps

  // The zoom buttons, and the reset when the list moves on, change the zoom
  // from outside; a zoom this component committed itself is already shown.
  useLayoutEffect(() => {
    if (!base || Math.abs(zoom - view.current.zoom) < 0.001) return;
    view.current = zoomAround(view.current, box.w / 2, box.h / 2, zoom);
    paint(true);
  }, [zoom]); // eslint-disable-line react-hooks/exhaustive-deps

  // A trackpad pinch arrives as a wheel event with ctrlKey in Chrome and
  // Firefox, and as gesture events in Safari. Both must be stopped here, or
  // the page zooms. On a touch screen Safari sends gesture events beside the
  // pointer events, so they count only while no finger is down.
  useEffect(() => {
    const el = boxRef.current;
    if (!el || !measured) return;
    let gestureStart = 1;
    const onWheel = (e: WheelEvent) => {
      if (!e.ctrlKey) return;
      e.preventDefault();
      const p = local(e.clientX, e.clientY);
      view.current = zoomAround(view.current, p.x, p.y, clampZoom(view.current.zoom * Math.exp(-e.deltaY / 100)));
      paint();
      commit();
    };
    type GestureEvent = UIEvent & { scale: number; clientX: number; clientY: number };
    const onGestureStart = (e: Event) => {
      e.preventDefault();
      gestureStart = view.current.zoom;
    };
    const onGestureChange = (e: Event) => {
      e.preventDefault();
      const g = e as GestureEvent;
      if (fingers.current.size > 0) return;
      const p = local(g.clientX, g.clientY);
      view.current = zoomAround(view.current, p.x, p.y, clampZoom(gestureStart * g.scale));
      paint();
      commit();
    };
    el.addEventListener('wheel', onWheel, { passive: false });
    el.addEventListener('gesturestart', onGestureStart);
    el.addEventListener('gesturechange', onGestureChange);
    return () => {
      el.removeEventListener('wheel', onWheel);
      el.removeEventListener('gesturestart', onGestureStart);
      el.removeEventListener('gesturechange', onGestureChange);
    };
  }, [measured, box.w, box.h, base?.w]); // eslint-disable-line react-hooks/exhaustive-deps

  // Two fingers on the picture are a pinch: they never swipe, the zoom
  // follows the distance between them, and the picture follows the point
  // between them. One finger on a zoomed picture pans it.
  const spread = () => {
    const [a, b] = [...fingers.current.values()];
    return { dist: Math.hypot(a!.x - b!.x, a!.y - b!.y), x: (a!.x + b!.x) / 2, y: (a!.y + b!.y) / 2 };
  };
  const startFling = () => {
    let { x: vx, y: vy } = velocity.current;
    let last = performance.now();
    const step = (now: number) => {
      const dt = now - last;
      last = now;
      view.current = { ...view.current, tx: view.current.tx + vx * dt, ty: view.current.ty + vy * dt };
      paint();
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
    const p = local(x, y);
    pinch.current = { dist, x: p.x, y: p.y };
  };
  const onFingerMove = (e: React.PointerEvent) => {
    const last = fingers.current.get(e.pointerId);
    if (!last) return;
    fingers.current.set(e.pointerId, { x: e.clientX, y: e.clientY });
    if (fingers.current.size === 1 && view.current.zoom > 1) {
      const dx = e.clientX - last.x;
      const dy = e.clientY - last.y;
      view.current = { ...view.current, tx: view.current.tx + dx, ty: view.current.ty + dy };
      paint();
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
    const p = local(x, y);
    const moved = { ...view.current, tx: view.current.tx + p.x - start.x, ty: view.current.ty + p.y - start.y };
    view.current = zoomAround(moved, p.x, p.y, clampZoom(view.current.zoom * dist / start.dist));
    pinch.current = { dist, x: p.x, y: p.y };
    paint();
  };
  const onFingerUp = (e: React.PointerEvent, cancelled: boolean) => {
    fingers.current.delete(e.pointerId);
    if (pinch.current) {
      if (fingers.current.size < 2) {
        pinch.current = null;
        commit();
      }
      return;
    }
    // A finger that stopped before it lifted leaves the picture where it is.
    if (!cancelled && view.current.zoom > 1 && fingers.current.size === 0 && e.timeStamp - velocity.current.t < 50) startFling();
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
      // touch-none hands every finger movement here, for the swipe, the pinch
      // and the pan.
      className="relative h-full overflow-hidden select-none touch-none"
    >
      {url ? (
        <img
          ref={imgRef}
          src={url}
          alt={alt}
          onLoad={(e) => setNatural({ w: e.currentTarget.naturalWidth, h: e.currentTarget.naturalHeight })}
          // Physical left and top on purpose: the transform is in physical
          // pixels, like the pointer coordinates it follows.
          style={{
            position: 'absolute',
            left: 0,
            top: 0,
            width: base?.w,
            height: base?.h,
            maxWidth: 'none',
            transformOrigin: '0 0',
            visibility: base ? 'visible' : 'hidden',
          }}
          draggable={false}
        />
      ) : (
        <Notice text={failed ? t('image.notFound') : t('image.loading')} />
      )}
    </div>
  );
}
