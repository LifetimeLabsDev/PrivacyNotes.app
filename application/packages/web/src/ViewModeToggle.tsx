import { useTranslation } from 'react-i18next';
import { HoverLabel } from './HoverLabel';
import { exemptOpts } from './i18nExempt';
import { List, Sparkle, SquaresFour } from './icons';
import { SIDEBAR_ACTIVE } from './sidebarUI';
import type { ViewMode } from './viewMode';

/**
 * The layout switch: an Auto icon button beside a List / Grid segmented pair.
 * Drawn in the list preferences menu of every pane; the choice is this
 * device's own (viewMode.ts).
 */
export function ViewModeToggle({ mode, onChange }: { mode: ViewMode; onChange: (next: ViewMode) => void }) {
  const { t } = useTranslation('shell');
  const autoLabel = t('tagsRail.viewAuto', exemptOpts('shell:tagsRail.viewAuto'));
  return (
    <div className="flex items-stretch gap-1.5">
      <HoverLabel label={autoLabel} position="end">
        <button
          type="button"
          onClick={() => onChange('auto')}
          aria-pressed={mode === 'auto'}
          aria-label={autoLabel}
          className={`h-full px-2 rounded-md border inline-flex items-center justify-center transition ${
            mode === 'auto'
              ? `${SIDEBAR_ACTIVE} border-accent`
              : 'border-divider text-neutral-500 hover:text-accent hover:border-accent/50 dark:text-neutral-400 dark:hover:text-accent'
          }`}
        >
          <Sparkle size={15} />
        </button>
      </HoverLabel>
      <div className="flex-1 min-w-0 flex rounded-md border border-divider overflow-hidden">
        {(['list', 'grid'] as const).map((m) => (
          <button
            key={m}
            type="button"
            onClick={() => onChange(m)}
            aria-pressed={mode === m}
            className={`flex-auto min-w-0 inline-flex items-center justify-center gap-1 px-1.5 py-1 text-[12px] font-medium transition ${
              mode === m
                ? SIDEBAR_ACTIVE
                : 'text-neutral-500 hover:text-accent dark:text-neutral-400 dark:hover:text-accent'
            }`}
          >
            {m === 'list' ? <List size={13} className="shrink-0" /> : <SquaresFour size={13} className="shrink-0" />}
            <span className="truncate">{m === 'list' ? t('tagsRail.viewList') : t('tagsRail.viewGrid')}</span>
          </button>
        ))}
      </div>
    </div>
  );
}
