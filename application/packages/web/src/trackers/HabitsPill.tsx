import { useTranslation } from 'react-i18next';
import type { HabitAnswers } from '../trackerTypes';
import { askedHabits, useCustomHabits } from '../habitList';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';
import { PanelQuestion, Segmented } from './panelUI';
import { Gear } from '../icons';

/**
 * The free Habits tracker: one yes or no row per question the person turned
 * on in the tracker setup ("Did you meditate?"), built-in or their own. A tap on the answer a row
 * already carries clears it, so a mis-tap is one tap back. The panel stays
 * open while the rows are answered; the pass moves on with Next, as it does
 * for medications. The ids are fixed and the names come from the catalog,
 * so the statistics read each question as its own yes or no tracker.
 * Spec: ops/docs/plans/mood-tracking-landscape.md (proposal 1)
 */
export function HabitsPill({
  value,
  questions,
  expanded,
  onToggle,
  onChange,
  onChangeQuestions,
  includeCustom,
  readOnly,
}: {
  value?: HabitAnswers;
  /** The questions that are on, from `trackerSettings.habits`. */
  questions: readonly string[];
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: HabitAnswers | undefined) => void;
  /** Whether the person's own habits are asked: they are Pro. */
  includeCustom: boolean;
  /** Opens the tracker setup on its Questions list. */
  onChangeQuestions?: () => void;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  // The built-in questions and the person's own, in the setup's order.
  const custom = useCustomHabits();
  const asked = askedHabits(questions, includeCustom ? custom : []);
  const answers = value ?? {};
  const answered = asked.filter((q) => typeof answers[q.id] === 'boolean');
  const yes = asked.filter((q) => answers[q.id] === true).length;

  const setAnswer = (id: string, next: boolean) => {
    const out: HabitAnswers = { ...answers };
    if (out[id] === next) delete out[id];
    else out[id] = next;
    // An empty record is no value: the key leaves the entry with the last answer.
    onChange(Object.keys(out).length > 0 ? out : undefined);
  };

  const options = [
    { key: 'yes', label: t('habits.yes') },
    { key: 'no', label: t('habits.no') },
  ] as const;

  return (
    <PillShell
      label={t('labels.habits')}
      filled={answered.length > 0}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={t('habits.count', { yes, total: asked.length })}
      icon={TRACKER_ICONS.habits}
      readOnly={readOnly}
    >
      <div className="flex flex-col max-w-[420px]">
        <PanelQuestion>{t('habits.prompt')}</PanelQuestion>
        {onChangeQuestions && (
          <button
            type="button"
            onClick={onChangeQuestions}
            className="-mt-1 mb-1 self-start inline-flex items-center gap-1.5 text-[12px] font-medium text-accent hover:underline"
          >
            <Gear size={14} aria-hidden="true" />
            {t('habits.changeQuestions')}
          </button>
        )}
        {asked.length === 0 && (
          <p className="text-[11px] text-pn-muted">{t('habits.empty')}</p>
        )}
        {asked.map((q) => {
          const a = answers[q.id];
          return (
            <div key={q.id} className="flex items-center justify-between gap-3 py-2 border-b border-divider last:border-b-0">
              <span className="min-w-0 flex-1 break-words text-[13px] text-pn">{q.question}</span>
              <Segmented
                ariaLabel={q.question}
                options={options}
                value={a === true ? 'yes' : a === false ? 'no' : null}
                onPick={(k) => setAnswer(q.id, k === 'yes')}
              />
            </div>
          );
        })}
      </div>
    </PillShell>
  );
}
