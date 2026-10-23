import { useEffect, useLayoutEffect, useRef, useState } from 'react';
import type { ReactNode, RefObject } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowUpRight, CaretDown, CaretUp, Compass, List, SignIn } from './icons';
import { DEMO_HREF, NAV_SECTIONS, type FooterIcon } from './footerData';
import { FooterGlyph } from './SiteFooter';
import { LanguageMenu } from './LanguageMenu';
import { helpPath } from './localeRoutes';
import { activeLocale } from './languages';

// The homepage header rail: the same structure, sections, labels and glyphs
// as the static-page rail (siteNav() in ../static-page-chrome.ts), drawn in
// the washi palette. Sections come from NAV_SECTIONS in footerData.ts; only
// Downloads is the homepage's own. Spec: ops/docs/archive/ui-patterns.md
// section 49.

/**
 * Widest first. The header measures every mode in a hidden copy and shows
 * the first that fits, so no locale or window width can overflow: all
 * sections, then the Explore fold (Help stays in the row, then Help folds
 * too, which keeps the long locales off the hamburger at 1024px), then the
 * hamburger with fewer controls:
 * the demo goes, then the theme toggle, then the App glyph, then the
 * flag's caret and some padding. The language flag never goes.
 */
export type NavMode = 'full' | 'fold' | 'foldAll' | 'compact' | 'bare' | 'min' | 'tiny' | 'micro';
const MODES: NavMode[] = ['full', 'fold', 'foldAll', 'compact', 'bare', 'min', 'tiny', 'micro'];
export const hasMenu = (m: NavMode) => m !== 'full' && m !== 'fold' && m !== 'foldAll';

export type NavItem = {
  key: FooterIcon;
  href: string;
  label: string;
  /** One line under the label in the Explore panel. */
  line?: string;
  /** Folds into Explore in `fold`; everything but Downloads folds in `foldAll`. */
  fold: boolean;
  /** An on-page anchor: the overlay scrolls to it after closing. */
  section?: string;
};

export function useNavItems(): NavItem[] {
  const { t } = useTranslation('landing');
  const text = (icon: FooterIcon, short: string): { label: string; line?: string } => {
    switch (icon) {
      case 'faq': return { label: t('header.help'), line: t('header.helpLine') };
      case 'changelog': return { label: t('header.changelog'), line: t('header.changelogLine') };
      case 'themes': return { label: t('header.themes'), line: t('header.themesLine') };
      case 'roadmap': return { label: t('header.roadmap'), line: t('header.roadmapLine') };
      default: return { label: short };
    }
  };
  return [
    { key: 'download', href: '#downloads', label: t('header.downloads'), fold: false, section: 'downloads' },
    ...NAV_SECTIONS.map((l) => ({
      key: l.icon,
      href: l.icon === 'faq' ? helpPath(activeLocale()) : l.href,
      ...text(l.icon, l.short ?? l.label),
      // Help stays in the row: it is the one section every visitor may need.
      fold: l.icon !== 'faq',
    })),
  ];
}

const GHOST = 'group inline-flex items-center gap-1.5 rounded-lg px-[11px] py-[7px] transition hover:text-accent';
// Accent glyphs, like the overlay rows and the Explore panel.
const GLYPH = 'text-accent';
const ICON_BTN = 'inline-flex h-[29px] cursor-pointer items-center justify-center rounded-lg transition hover:text-accent';

function Explore({ items, measure }: { items: NavItem[]; measure?: boolean }) {
  const { t } = useTranslation('landing');
  const [open, setOpen] = useState(false);
  const wrap = useRef<HTMLDivElement>(null);
  const button = useRef<HTMLButtonElement>(null);
  useEffect(() => {
    if (!open) return;
    const down = (e: PointerEvent) => {
      if (!wrap.current?.contains(e.target as Node)) setOpen(false);
    };
    const key = (e: KeyboardEvent) => {
      if (e.key !== 'Escape') return;
      setOpen(false);
      button.current?.focus();
    };
    document.addEventListener('pointerdown', down);
    document.addEventListener('keydown', key);
    return () => {
      document.removeEventListener('pointerdown', down);
      document.removeEventListener('keydown', key);
    };
  }, [open]);
  return (
    <div ref={wrap} className="relative">
      <button
        ref={button}
        type="button"
        onClick={() => setOpen((o) => !o)}
        aria-expanded={open}
        aria-controls={measure ? undefined : 'pn-explore'}
        className={`${GHOST} cursor-pointer ${open ? 'bg-[var(--wl-card)] text-accent' : ''}`}
      >
        <Compass size={15} className={GLYPH} aria-hidden="true" />
        {t('header.explore')}
        {open ? <CaretUp size={11} aria-hidden="true" /> : <CaretDown size={11} aria-hidden="true" />}
      </button>
      {open && (
        <div
          id="pn-explore"
          className="absolute end-0 top-full z-50 mt-2 w-64 whitespace-normal rounded-xl border border-[var(--wl-line)] bg-[var(--wl-card)] p-1.5 text-start shadow-lg"
        >
          {items.map((l) => (
            <a key={l.key} href={l.href} onClick={() => setOpen(false)} className="group flex items-start gap-2.5 rounded-lg p-2 transition hover:bg-[var(--wl-tint)]">
              <span className="mt-px text-accent"><FooterGlyph icon={l.key} size={16} /></span>
              <span>
                <span className="block text-[13px] font-semibold leading-tight text-[var(--wl-ink)]">{l.label}</span>
                {l.line && <span className="mt-0.5 block text-xs leading-snug text-[var(--wl-sub)]">{l.line}</span>}
              </span>
            </a>
          ))}
        </div>
      )}
    </div>
  );
}

/**
 * One rail: sections, a divider, then the controls. The language flag is
 * part of it at every width and in every mode, in both bars.
 */
export function HeaderRail({ mode, items, measure, themeToggle, onApp, onMenu, menuOpen }: {
  mode: NavMode;
  items: NavItem[];
  measure?: boolean;
  themeToggle: ReactNode;
  onApp: () => void;
  onMenu: () => void;
  menuOpen: boolean;
}) {
  const { t } = useTranslation('landing');
  const shown = mode === 'full' ? items : mode === 'fold' ? items.filter((l) => !l.fold) : mode === 'foldAll' ? items.filter((l) => l.section) : [];
  const folded = mode === 'fold' ? items.filter((l) => l.fold) : mode === 'foldAll' ? items.filter((l) => !l.section) : [];
  const tight = mode === 'micro';
  return (
    <div data-nav={measure ? undefined : mode} className={`flex items-center gap-0.5 whitespace-nowrap rounded-[11px] bg-[var(--wl-tint)] ${tight ? 'px-0.5 py-1' : 'p-1'} text-[13px] leading-none text-[var(--wl-ink)]`}>
      {shown.length > 0 && (
        <>
          <nav aria-label={measure ? undefined : t('header.sections')} className="flex items-center gap-0.5">
            {shown.map((l) => (
              <a key={l.key} href={l.href} className={GHOST}>
                <span className={GLYPH}><FooterGlyph icon={l.key} size={15} /></span>
                {l.label}
              </a>
            ))}
            {folded.length > 0 && <Explore items={folded} measure={measure} />}
          </nav>
          <span className="mx-[5px] h-5 w-px bg-[var(--wl-line)]" aria-hidden="true" />
        </>
      )}
      <LanguageMenu navigate rail={tight ? 'tight' : true} />
      {mode !== 'min' && mode !== 'tiny' && mode !== 'micro' && themeToggle}
      {mode !== 'bare' && mode !== 'min' && mode !== 'tiny' && mode !== 'micro' && (
        <a
          href={DEMO_HREF}
          className="ms-0.5 inline-flex items-center gap-1.5 rounded-lg border border-[var(--wl-amber-border)] bg-[var(--wl-tint-amber)] px-[11px] py-[6px] font-semibold text-[var(--wl-amber-text)] transition hover:brightness-95"
        >
          {t('hero.tryDemo')}
          <ArrowUpRight size={13} aria-hidden="true" />
        </a>
      )}
      {/* "App" is a deliberate literal, not a locale key: see the comment
          in LandingPage.tsx at the sticky bar. */}
      <button
        type="button"
        onClick={onApp}
        className={`pn-fx-conic-btn inline-flex cursor-pointer items-center gap-1.5 rounded-lg ${tight ? 'px-[9px]' : 'ms-0.5 px-[12px]'} py-[5px] font-semibold text-[var(--wl-bg)]`}
      >
        App
        {mode !== 'tiny' && mode !== 'micro' && <SignIn size={15} aria-hidden="true" />}
      </button>
      {hasMenu(mode) && (
        <button type="button" onClick={onMenu} aria-label={t('header.menuLabel')} aria-expanded={menuOpen} className={`${ICON_BTN} ${tight ? 'w-[26px]' : 'w-[30px]'}`}>
          <List size={18} />
        </button>
      )}
    </div>
  );
}

/**
 * Picks the widest mode whose rail fits beside the brand at its full width.
 * `row` is the header row, `brand` its brand block (logo + truncating h1),
 * `measurer` holds one hidden rail per mode under [data-mode].
 */
export function useNavMode(row: RefObject<HTMLElement | null>, brand: RefObject<HTMLElement | null>, measurer: RefObject<HTMLElement | null>): NavMode {
  const [mode, setMode] = useState<NavMode>('compact');
  useLayoutEffect(() => {
    const r = row.current, b = brand.current, m = measurer.current;
    if (!r || !b || !m) return;
    const fit = () => {
      const h1 = b.querySelector('h1');
      const brandWidth = b.getBoundingClientRect().width + (h1 ? h1.scrollWidth - h1.clientWidth : 0);
      const gap = parseFloat(getComputedStyle(r).columnGap) || 0;
      const room = r.clientWidth - brandWidth - gap;
      const next = MODES.find((x) => {
        const el = m.querySelector<HTMLElement>(`[data-mode="${x}"]`);
        return el != null && el.getBoundingClientRect().width <= room + 0.5;
      }) ?? 'micro';
      setMode(next);
    };
    fit();
    const ro = new ResizeObserver(fit);
    ro.observe(r);
    for (const el of m.querySelectorAll('[data-mode]')) ro.observe(el);
    void document.fonts?.ready.then(fit);
    return () => ro.disconnect();
  }, [row, brand, measurer]);
  return mode;
}

/** The hidden copies useNavMode measures: one rail per mode, out of flow. */
export function NavMeasurer({ measurerRef, ...rail }: { measurerRef: RefObject<HTMLDivElement | null> } & Omit<Parameters<typeof HeaderRail>[0], 'mode' | 'measure'>) {
  return (
    <div ref={measurerRef} aria-hidden="true" inert className="pointer-events-none invisible absolute start-0 top-0 h-0 overflow-hidden">
      {MODES.map((m) => (
        <div key={m} data-mode={m} className="w-max">
          <HeaderRail {...rail} mode={m} measure />
        </div>
      ))}
    </div>
  );
}

/** The overlay rows: every item, flat, with the rail's glyphs. */
export function OverlayRows({ items, onSection }: { items: NavItem[]; onSection: (id: string) => void }) {
  return (
    <>
      {items.map((l, i) => {
        const cls = `flex items-center gap-4 ${i < items.length - 1 ? 'border-b border-[var(--wl-line)] ' : ''}py-4`;
        const glyph = <span className="text-accent"><FooterGlyph icon={l.key} size={26} /></span>;
        const section = l.section;
        return section ? (
          <button key={l.key} type="button" onClick={() => onSection(section)} className={`cursor-pointer ${cls} text-start`}>
            {glyph}
            {l.label}
          </button>
        ) : (
          <a key={l.key} href={l.href} className={cls}>
            {glyph}
            {l.label}
          </a>
        );
      })}
    </>
  );
}
