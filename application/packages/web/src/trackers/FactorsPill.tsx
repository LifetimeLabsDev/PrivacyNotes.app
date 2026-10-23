import { useTranslation } from 'react-i18next';
import { activeFactors, type FactorDef } from '../trackerTypes';
import { foldForMatch } from '../textMatch';
import { Gear } from '../icons';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';
import { PanelQuestion, chipClass } from './panelUI';

/** The starter names the tracker setup offers on an empty list, named from
 *  the catalog. A tap there makes one an ordinary factor. */
// Only what happens to a day and no other tracker asks: sport is Activity,
// friends is Social, bad sleep is Sleep, stress is an emotion, and what the
// person does (outside, alcohol) is a Habits question.
const STARTER_FACTORS = ['work', 'family', 'travel', 'holiday', 'deadline', 'celebration', 'badWeather', 'sick', 'hangover', 'period', 'jetLag', 'allergies'] as const;

/**
 * The parts of a day, from the person's own list: "family", "work",
 * "travel". A chip is on or off. The list itself is kept in one place, the
 * Factors tab of the tracker setup: the gear link opens it, as the Habits
 * pill's link opens its questions, so the panel stays a row of chips.
 * Spec: ops/issues/0439.md (Spec), ops/docs/plans/mood-tracking-landscape.md (proposal 4)
 */
export function FactorsPill({
  value,
  factors,
  expanded,
  onToggle,
  onChange,
  onEditFactors,
  readOnly,
}: {
  value?: string[];
  factors: FactorDef[];
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: string[]) => void;
  /** Opens the tracker setup on its Factors list. */
  onEditFactors?: () => void;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  const live = activeFactors(factors);
  const byId = new Map(factors.map((f) => [f.id, f]));
  const chosen = (value ?? []).filter((id) => byId.has(id));
  const count = chosen.length;
  const filledLabel = count === 1 ? byId.get(chosen[0]!)!.name : t('factors.count', { count });

  const toggleFactor = (id: string) => {
    const current = value ?? [];
    onChange(current.includes(id) ? current.filter((k) => k !== id) : [...current, id]);
  };

  return (
    <PillShell
      label={t('labels.factors')}
      filled={count > 0}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledLabel}
      icon={TRACKER_ICONS.factors}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-2">
        <PanelQuestion>{t('factors.prompt')}</PanelQuestion>
        {onEditFactors && (
          <button
            type="button"
            onClick={onEditFactors}
            className="-mt-3 self-start inline-flex items-center gap-1.5 text-[12px] font-medium text-accent hover:underline"
          >
            <Gear size={14} aria-hidden="true" />
            {t('factors.editList')}
          </button>
        )}
        {live.length > 0 && (
          <div className="flex flex-wrap gap-1.5">
            {live.map((f) => {
              const on = chosen.includes(f.id);
              return (
                <button
                  key={f.id}
                  type="button"
                  aria-pressed={on}
                  onClick={() => toggleFactor(f.id)}
                  className={chipClass(on)}
                >
                  {f.name}
                </button>
              );
            })}
          </div>
        )}
        {live.length === 0 && (
          <span className="text-[11px] text-pn-muted">{t('factors.pillEmpty')}</span>
        )}
      </div>
    </PillShell>
  );
}

/** The starter names the list does not hold yet, by folded name, in the person's language. */
export function starterSuggestions(live: FactorDef[], t: (key: string) => string): string[] {
  const held = new Set(live.map((f) => foldForMatch(f.name)));
  return STARTER_FACTORS.map((k) => t(`factors.starter.${k}`)).filter((name) => !held.has(foldForMatch(name)));
}
