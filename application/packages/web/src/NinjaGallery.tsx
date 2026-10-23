// The Ninja tile's screenshots button (LandingPage.tsx), beside the demo
// button. It is a plain link to the first picture, so without JS a click
// opens it. With JS it opens the viewer /changelog and /themes use, on the
// first shot, stepping through every shot in NINJA_SHOTS: the first click
// loads /static-pages.js and the viewer's CSS, both on demand, so neither is
// on the boot path. A shot's caption is its catalog line, at the headline
// size of /themes.
// Spec: ops/design/patterns/145-150.md section 145
import { useTranslation } from 'react-i18next';
import { Image as ImageIcon } from './icons';
import { NINJA_SHOTS } from './ninjaShots';

type Shot = { src: string; dark: null; alt: string; big: true };
type Open = (shots: Shot[], i: number, back: Element | null) => void;

declare global {
  interface Window {
    /** Set by /static-pages.js: the shared lightbox, built on first use. */
    pnLightbox?: () => Open;
  }
}

const SCRIPT = '/static-pages.js';

let loading: Promise<Open> | null = null;
/** The viewer, after its script and CSS are on the page; loaded once. */
function viewer(): Promise<Open> {
  if (window.pnLightbox) return Promise.resolve(window.pnLightbox());
  loading ??= Promise.all([
    import('./lightboxCss').then(({ LIGHTBOX_CSS }) => {
      const style = document.createElement('style');
      style.textContent = LIGHTBOX_CSS;
      document.head.appendChild(style);
    }),
    new Promise<void>((resolve, reject) => {
      const s = document.createElement('script');
      s.src = SCRIPT;
      s.onload = () => resolve();
      s.onerror = () => reject(new Error(`${SCRIPT} did not load`));
      document.head.appendChild(s);
    }),
  ]).then(() => {
    const lb = window.pnLightbox;
    if (!lb) throw new Error(`${SCRIPT} set no viewer`);
    return lb();
  });
  return loading;
}

export function NinjaShotsButton() {
  const { t } = useTranslation('landing');
  const first = NINJA_SHOTS[0];
  if (!first) return null;
  const shots: Shot[] = NINJA_SHOTS.map((s) => ({ src: s.src, dark: null, alt: t(`ninja.shots.${s.key}`), big: true }));
  return (
    <a
      href={first.src}
      onClick={(e) => {
        e.preventDefault();
        const back = e.currentTarget;
        viewer().then((open) => open(shots, 0, back), () => window.open(first.src, '_blank', 'noopener'));
      }}
      className="inline-flex items-center gap-2 rounded-full border-2 border-[var(--wl-ink)] bg-[var(--wl-card)] px-4 py-2 text-sm font-bold text-[var(--wl-ink)] transition-colors hover:bg-[var(--wl-bg)] cursor-zoom-in"
    >
      <ImageIcon size={15} weight="bold" aria-hidden="true" />
      {t('ninja.seeShots')}
      <span className="rounded-full bg-[var(--wl-tint-blue)] px-1.5 text-[11px] font-semibold tabular-nums text-accent dark:text-blue-300">{NINJA_SHOTS.length}</span>
    </a>
  );
}
