import { Fragment, useEffect, useRef, type ReactNode } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import i18n, { activeLocale } from '../i18n';
import { isNativeStoreBuild } from '../devices';
import { ArrowSquareOut } from '../icons';
import { helpPath } from '../localeRoutes';
import { SETTINGS_EYEBROW } from '../settingsUI';
import { siteHref } from '../siteLinks';
import { isTouchOnly } from '../touchOnly';
import { SECTION_LABEL, TAB_LABEL, type SectionId, type SettingEntry } from './registry';
import { searchSettings, type SettingHit } from './searchSettings';

export type { SettingHit } from './searchSettings';

/** The catalogs i18next holds, read with no fallback. */
function fromCatalog(lng: string, key: string): string | undefined {
  const at = key.indexOf(':');
  const value = i18n.getResource(lng, key.slice(0, at), key.slice(at + 1)) as unknown;
  return typeof value === 'string' ? value : undefined;
}

/** A row some devices never draw is left out where its pane leaves it out. */
function isShown(entry: SettingEntry): boolean {
  if (entry.shownOn === 'storeBuild') return isNativeStoreBuild();
  if (entry.shownOn === 'keyboard') return !isTouchOnly();
  return true;
}

/**
 * The settings that match `query` in the language on screen. `railLabels`
 * are the section names as the rail draws them: a few stay English on
 * purpose in some languages (i18nExempt.ts), and the search matches the
 * word the reader sees.
 */
export function runSettingsSearch(query: string, railLabels: ReadonlyMap<string, string>): SettingHit[] {
  const lng = activeLocale();
  const sectionOf = new Map(Object.entries(SECTION_LABEL).map(([section, key]) => [key, section]));
  const resolve = (at: string, key: string) => {
    const section = at === lng ? sectionOf.get(key) : undefined;
    return (section && railLabels.get(section)) || fromCatalog(at, key);
  };
  return searchSettings(query, lng, resolve, isShown);
}

/** The id the results list gives each option, for `aria-activedescendant`. */
export function resultOptionId(index: number): string {
  return `settings-search-result-${index}`;
}

/** The inner tab a row lives on, when the row is not that tab itself. */
function tabOf(hit: SettingHit): string | null {
  const key = hit.entry.tab ? TAB_LABEL[`${hit.entry.section}/${hit.entry.tab}`] : undefined;
  if (!key || key === hit.entry.label) return null;
  return i18n.t(key);
}

function Highlighted({ text, mark }: { text: string; mark: SettingHit['mark'] }) {
  if (!mark) return <>{text}</>;
  return (
    <>
      {text.slice(0, mark.start)}
      <mark className="rounded-sm bg-accent/20 text-inherit">{text.slice(mark.start, mark.end)}</mark>
      {text.slice(mark.end)}
    </>
  );
}

/**
 * The results pane: grouped by section, the group header carrying the
 * section's rail icon. The active result is the one the arrows point at;
 * the field keeps the focus, so the list is a listbox driven from there.
 * Spec: ops/docs/ui-patterns.md (section 114, settings search)
 */
export function SettingsSearchResults({
  query,
  hits,
  activeIndex,
  onPick,
  onHover,
  onClear,
  sectionLabel,
  sectionIcon,
}: {
  query: string;
  hits: SettingHit[];
  activeIndex: number;
  onPick: (hit: SettingHit) => void;
  onHover: (index: number) => void;
  onClear: () => void;
  sectionLabel: (id: SectionId) => string;
  sectionIcon: (id: SectionId) => ReactNode;
}) {
  const { t } = useTranslation('settingsSearch');
  const listRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    listRef.current?.querySelector(`#${resultOptionId(activeIndex)}`)?.scrollIntoView({ block: 'nearest' });
  }, [activeIndex]);

  if (hits.length === 0) {
    return (
      <div className="flex-1 min-h-0 overflow-y-auto px-6 py-10 text-center text-pn-soft">
        <p role="status" className="sr-only">{t('resultCount', { count: 0 })}</p>
        <p className="mt-2 text-sm text-pn">
          {t('common:state.noResults')}: <bdi>“{query}”</bdi>
        </p>
        <a
          href={siteHref(`${helpPath(activeLocale())}?q=${encodeURIComponent(query)}`)}
          target="_blank"
          rel="noopener noreferrer"
          className="mt-3 inline-flex items-center gap-1.5 text-sm text-accent hover:underline"
        >
          <span>
            <Trans t={t} i18nKey="searchHelp" values={{ query }} components={{ q: <bdi /> }} />
          </span>
          <ArrowSquareOut size={13} className="shrink-0" aria-hidden="true" />
        </a>
        <div className="mt-4">
          <button
            type="button"
            onClick={onClear}
            className="rounded-full border border-divider px-3 py-1 text-xs text-pn-soft hover:text-pn hover:bg-surface-1 transition"
          >
            {t('common:actions.clearSearch')}
          </button>
        </div>
      </div>
    );
  }

  let index = -1;
  return (
    <div className="flex-1 min-h-0 overflow-y-auto px-4 pt-2 pb-4">
      <p role="status" className="sr-only">{t('resultCount', { count: hits.length })}</p>
      <div ref={listRef} role="listbox" id="settings-search-results" aria-label={t('common:actions.search')}>
        {hits.map((hit, i) => {
          const newGroup = hit.entry.section !== hits[i - 1]?.entry.section;
          index += 1;
          const at = index;
          const crumb = tabOf(hit);
          return (
            <Fragment key={hit.entry.id}>
              {newGroup && (
                <div className={`flex items-center gap-1.5 px-2 pt-3 pb-1 first:pt-1 ${SETTINGS_EYEBROW}`}>
                  <span className="shrink-0 [&>svg]:w-3.5 [&>svg]:h-3.5">{sectionIcon(hit.entry.section)}</span>
                  {sectionLabel(hit.entry.section)}
                </div>
              )}
              <div
                id={resultOptionId(at)}
                role="option"
                aria-selected={at === activeIndex}
                onClick={() => onPick(hit)}
                onMouseMove={() => { if (at !== activeIndex) onHover(at); }}
                className={`cursor-pointer rounded-md px-2 py-1.5 text-start ${at === activeIndex ? 'bg-surface-1' : ''}`}
              >
                <div className="text-sm text-pn">
                  <Highlighted text={hit.label} mark={hit.english ? null : hit.mark} />
                  {crumb && <span className="text-xs text-pn-soft"> · {crumb}</span>}
                  {hit.entry.section === 'help' && (
                    <ArrowSquareOut size={12} className="inline ms-1.5 text-accent" aria-hidden="true" />
                  )}
                </div>
                {hit.why && (
                  <div className="text-xs text-pn-muted">
                    {hit.english ? t('matchedInEnglish') : t('matched')} <bdi>{hit.why}</bdi>
                  </div>
                )}
              </div>
            </Fragment>
          );
        })}
      </div>
    </div>
  );
}

function accentShadow(alpha: number): string {
  const rgb = getComputedStyle(document.documentElement).getPropertyValue('--pn-accent').trim() || '30 64 175';
  return `rgb(${rgb} / ${alpha})`;
}

/**
 * Scroll the row marked `data-setting="<id>"` inside `root` into view and
 * flash it. A pane paints from a cache and then updates (ui-patterns section
 * 84), so the row is looked up every frame and re-centered until its place
 * holds for five frames or the time runs out, the rule the find bar uses. A
 * row this device does not draw is never found: the pane stays at its top
 * and nothing flashes. Returns a function that stops the walk.
 */
export function jumpToSetting(root: HTMLElement, id: string): () => void {
  const start = performance.now();
  let foundAt = 0;
  let lastTop = Number.NaN;
  let stableFrames = 0;
  let frame = 0;
  let stopped = false;
  const flash = (el: HTMLElement) => {
    const reduced = window.matchMedia('(prefers-reduced-motion: reduce)').matches;
    const on = { boxShadow: `0 0 0 2px ${accentShadow(0.55)}`, backgroundColor: accentShadow(0.12) };
    const off = { boxShadow: `0 0 0 2px ${accentShadow(0)}`, backgroundColor: accentShadow(0) };
    el.animate(reduced ? [on, on] : [on, on, off], { duration: reduced ? 1200 : 2000, easing: 'ease-out' });
  };
  const step = () => {
    if (stopped) return;
    const now = performance.now();
    const el = root.querySelector<HTMLElement>(`[data-setting="${CSS.escape(id)}"]`);
    if (!el) {
      if (now - start < 1500) frame = requestAnimationFrame(step);
      return;
    }
    if (!foundAt) foundAt = now;
    const top = el.getBoundingClientRect().top;
    stableFrames = Math.abs(top - lastTop) < 1 ? stableFrames + 1 : 0;
    lastTop = top;
    el.scrollIntoView({ block: 'center', inline: 'nearest' });
    if (stableFrames >= 5 || now - foundAt > 1200) {
      flash(el);
      return;
    }
    frame = requestAnimationFrame(step);
  };
  frame = requestAnimationFrame(step);
  return () => {
    stopped = true;
    cancelAnimationFrame(frame);
  };
}
