/**
 * TrackerPills - modular mood & wellness tracker UI for journal entries.
 *
 * Renders a row of pill buttons above the editor. Each pill has three states:
 *   1. Empty (not filled) - muted outline, shows "+" icon
 *   2. Active (expanded)  - user is filling in data, shows inline picker
 *   3. Filled (collapsed) - shows the logged value as a compact chip
 *
 * On a TOUCH device, pills render as a single horizontal-scrolling row (no
 * wrapping) whose scrollbar is hidden - a finger swipes it. When `collapsed`
 * is true (editor focused / keyboard open), only filled pills are shown with
 * shortened labels but icons preserved.
 *
 * Wherever there is a pointer, pills wrap (flex-wrap). The choice is a device
 * test, NOT a width test: a mouse cannot reach a hidden sideways scroller, so
 * a desktop window narrowed below ~600px used to clip its pills with no way
 * to get at them. Spec: ops/docs/ui-patterns.md section 85.
 */

import { useCallback, type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Plus } from './icons';
import { TrackerConfig } from './TrackerConfig';
import {
  BUILTIN_TRACKER_COLORS,
  EMOTION_TAGS,
  MOOD_ANCHORS,
  type ActivityLevel,
  type JournalTrackerData,
  type MedicationTemplate,
  type SleepQuality,
  type TrackerSettings,
  activeCustomTrackers,
} from './trackerTypes';
import { TRACKER_ICONS } from './trackers/icons';
import { ActivityPill } from './trackers/ActivityPill';
import { CustomPill } from './trackers/CustomPill';
import { EmotionsPill } from './trackers/EmotionsPill';
import { MedicationPill } from './trackers/MedicationPill';
import { MoodPill } from './trackers/MoodPill';
import { ScalePill } from './trackers/ScalePill';
import { SleepPill } from './trackers/SleepPill';
import { SleepScorePill } from './trackers/SleepScorePill';
import { HeartRatePill } from './trackers/HeartRatePill';
import { NumberInputPill } from './trackers/NumberInputPill';
import { PillExpandContext } from './trackers/PillShell';
import { proUnlocked } from './demo';
import { useIsTouchDevice } from './useIsMobile';

export interface TrackerPillsProps {
  data: JournalTrackerData;
  onChange: (next: JournalTrackerData) => void;
  trackerSettings: TrackerSettings;
  onSettingsChange: (next: TrackerSettings) => void;
  medications: MedicationTemplate[];
  onMedicationsChange: (meds: MedicationTemplate[]) => void;
  readOnly?: boolean;
  isPro: boolean;
  onOpenUpgrade?: () => void;
  /** When true, render compact strip (editor focused on mobile). */
  collapsed?: boolean;
}

/** Compact pill - icon + short value. */
function MiniPill({ color, icon, label, onClick }: { color: string; icon: ReactNode; label: string; onClick: () => void }) {
  return (
    <button
      type="button"
      onPointerDown={(e) => {
        e.preventDefault();
        e.stopPropagation();
        onClick();
      }}
      className="inline-flex items-center gap-1 rounded-full px-2 py-0.5 text-[11px] font-medium whitespace-nowrap shrink-0 transition-colors"
      style={{ background: `${color}30`, color }}
    >
      {icon}
      {label}
    </button>
  );
}

/**
 * The one place the row decides between a swipeable strip and a wrapping row.
 * `touch` hides the scrollbar because a finger needs no bar; `pointer` wraps
 * because a hidden bar is unreachable with a mouse.
 * Spec: ops/docs/ui-patterns.md section 85 (hidden sideways scroll).
 */
const SCROLL_OR_WRAP = {
  touch: 'overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden',
  pointer: 'flex-wrap',
} as const;

function moodShort(v: number, t: (key: string) => string): string {
  return MOOD_ANCHORS[v] != null ? `${v} ${t(`mood.anchor.${v}`)}` : `${v}`;
}

export function TrackerPills({
  data,
  onChange,
  trackerSettings,
  onSettingsChange,
  medications,
  onMedicationsChange,
  readOnly,
  isPro,
  onOpenUpgrade,
  collapsed,
}: TrackerPillsProps) {
  const { t } = useTranslation('trackers');
  const [expanded, setExpanded] = useState<string | null>(null);
  const isTouch = useIsTouchDevice();
  // Custom trackers are Pro, and purely local - the demo unlocks them so
  // visitors can build one. The PRO badge on "Custom" keys off isPro.
  const customUnlocked = proUnlocked(isPro);
  const [expandEl, setExpandEl] = useState<HTMLDivElement | null>(null);

  const toggle = useCallback(
    (id: string) => {
      if (readOnly) return;
      setExpanded((prev) => (prev === id ? null : id));
    },
    [readOnly]
  );

  const update = useCallback(
    (patch: Partial<JournalTrackerData>) => {
      onChange({ ...data, ...patch });
    },
    [data, onChange]
  );

  const { activeBuiltins, customTrackers } = trackerSettings;
  const activeCustom = activeCustomTrackers(customTrackers).filter((t) => !t.stoppedAt);

  // --- Collapsed mode: compact single-row strip with only filled pills ---
  if (collapsed) {
    const pills: { key: string; color: string; icon: ReactNode; label: string; toggle: string }[] = [];

    if (activeBuiltins.includes('mood') && data.mood != null) {
      pills.push({ key: 'mood', color: BUILTIN_TRACKER_COLORS.mood, icon: TRACKER_ICONS.mood, label: moodShort(data.mood, t), toggle: 'mood' });
    }
    if (activeBuiltins.includes('emotions') && data.emotions?.length) {
      const eLabel = data.emotions.length === 1
        ? (EMOTION_TAGS.some((tag) => tag.key === data.emotions![0]) ? t(`emotions.tags.${data.emotions[0]}`) : '1')
        : `${data.emotions.length}`;
      pills.push({ key: 'emotions', color: BUILTIN_TRACKER_COLORS.emotions, icon: TRACKER_ICONS.emotions, label: eLabel, toggle: 'emotions' });
    }
    if (activeBuiltins.includes('sleep') && data.sleep) {
      const sq = t(`sleep.quality.${data.sleep.quality as SleepQuality}`);
      const sh = `${data.sleep.hours ?? 7.5}${t('units.hoursSuffix')}`;
      pills.push({ key: 'sleep', color: BUILTIN_TRACKER_COLORS.sleep, icon: TRACKER_ICONS.sleep, label: `${sq} (${sh})`, toggle: 'sleep' });
    }
    if (activeBuiltins.includes('sleepScore') && data.sleepScore != null) {
      pills.push({ key: 'sleepScore', color: BUILTIN_TRACKER_COLORS.sleepScore, icon: TRACKER_ICONS.sleepScore, label: `${data.sleepScore}`, toggle: 'sleepScore' });
    }
    if (activeBuiltins.includes('heartRate') && data.heartRate != null) {
      pills.push({ key: 'heartRate', color: BUILTIN_TRACKER_COLORS.heartRate, icon: TRACKER_ICONS.heartRate, label: `${data.heartRate}${t('units.bpm')}`, toggle: 'heartRate' });
    }
    if (activeBuiltins.includes('activity') && data.activity) {
      pills.push({ key: 'activity', color: BUILTIN_TRACKER_COLORS.activity, icon: TRACKER_ICONS.activity, label: t(`activity.level.${data.activity as ActivityLevel}`), toggle: 'activity' });
    }
    if (activeBuiltins.includes('energy') && data.energy != null) {
      pills.push({ key: 'energy', color: BUILTIN_TRACKER_COLORS.energy, icon: TRACKER_ICONS.energy, label: `${data.energy}/10`, toggle: 'energy' });
    }
    if (activeBuiltins.includes('focus') && data.focus != null) {
      pills.push({ key: 'focus', color: BUILTIN_TRACKER_COLORS.focus, icon: TRACKER_ICONS.focus, label: `${data.focus}/10`, toggle: 'focus' });
    }
    if (activeBuiltins.includes('medication') && data.medications?.length) {
      pills.push({ key: 'meds', color: BUILTIN_TRACKER_COLORS.medication, icon: TRACKER_ICONS.medication, label: `${data.medications.length}`, toggle: 'medication' });
    }
    if (activeBuiltins.includes('weight') && data.weight != null) {
      pills.push({ key: 'weight', color: BUILTIN_TRACKER_COLORS.weight, icon: TRACKER_ICONS.weight, label: `${data.weight}${t('units.kg')}`, toggle: 'weight' });
    }
    if (activeBuiltins.includes('steps') && data.steps != null) {
      pills.push({ key: 'steps', color: BUILTIN_TRACKER_COLORS.steps, icon: TRACKER_ICONS.steps, label: `${data.steps}`, toggle: 'steps' });
    }
    if (activeBuiltins.includes('water') && data.water != null) {
      pills.push({ key: 'water', color: BUILTIN_TRACKER_COLORS.water, icon: TRACKER_ICONS.water, label: `${data.water}/10`, toggle: 'water' });
    }
    if (activeBuiltins.includes('screenTime') && data.screenTime != null) {
      pills.push({ key: 'screenTime', color: BUILTIN_TRACKER_COLORS.screenTime, icon: TRACKER_ICONS.screenTime, label: `${data.screenTime}${t('units.hoursSuffix')}`, toggle: 'screenTime' });
    }
    if (activeBuiltins.includes('caffeine') && data.caffeine != null) {
      pills.push({ key: 'caffeine', color: BUILTIN_TRACKER_COLORS.caffeine, icon: TRACKER_ICONS.caffeine, label: `${data.caffeine}/5`, toggle: 'caffeine' });
    }
    if (activeBuiltins.includes('pain') && data.pain != null) {
      pills.push({ key: 'pain', color: BUILTIN_TRACKER_COLORS.pain, icon: TRACKER_ICONS.pain, label: `${data.pain}/10`, toggle: 'pain' });
    }
    if (activeBuiltins.includes('social') && data.social != null) {
      pills.push({ key: 'social', color: BUILTIN_TRACKER_COLORS.social, icon: TRACKER_ICONS.social, label: `${data.social}/5`, toggle: 'social' });
    }
    if (customUnlocked) {
      for (const t of activeCustom) {
        const entry = data.customTrackers?.find((e) => e.trackerId === t.id);
        if (entry?.value != null) {
          pills.push({ key: `c-${t.id}`, color: t.color ?? '#888', icon: null, label: `${entry.value}`, toggle: `custom-${t.id}` });
        }
      }
    }

    if (pills.length === 0) return null;

    return (
      <div className={`flex gap-1.5 px-4 sm:px-6 pt-2 pb-1 ${SCROLL_OR_WRAP[isTouch ? 'touch' : 'pointer']}`}>
        {pills.map((p) => (
          <MiniPill key={p.key} color={p.color} icon={p.icon} label={p.label} onClick={() => toggle(p.toggle)} />
        ))}
      </div>
    );
  }

  // --- Normal mode ---
  const containerClass = `flex gap-1.5 px-4 sm:px-6 pt-3 pb-2 ${SCROLL_OR_WRAP[isTouch ? 'touch' : 'pointer']}`;

  return (
    <PillExpandContext.Provider value={expandEl}>
    <div className={containerClass}>
      {!readOnly && (
        <TrackerConfig
          settings={trackerSettings}
          onChange={onSettingsChange}
          isPro={isPro}
          onOpenUpgrade={onOpenUpgrade}
          forceOpen={expanded === '__config__'}
          onClose={() => setExpanded(null)}
        />
      )}
      {activeBuiltins.includes('mood') && (
        <MoodPill
          value={data.mood}
          expanded={expanded === 'mood'}
          onToggle={() => toggle('mood')}
          onChange={(mood) => update({ mood })}
          readOnly={readOnly}
        />
      )}
      {activeBuiltins.includes('emotions') && (
        <EmotionsPill
          value={data.emotions}
          expanded={expanded === 'emotions'}
          onToggle={() => toggle('emotions')}
          onChange={(emotions) => update({ emotions })}
          readOnly={readOnly}
        />
      )}
      {activeBuiltins.includes('sleep') && (
        <SleepPill
          value={data.sleep}
          expanded={expanded === 'sleep'}
          onToggle={() => toggle('sleep')}
          onChange={(sleep) => update({ sleep })}
          readOnly={readOnly}
        />
      )}
      {activeBuiltins.includes('sleepScore') && (
        <SleepScorePill
          value={data.sleepScore}
          expanded={expanded === 'sleepScore'}
          onToggle={() => toggle('sleepScore')}
          onChange={(sleepScore) => update({ sleepScore })}
          readOnly={readOnly}
        />
      )}
      {activeBuiltins.includes('heartRate') && (
        <HeartRatePill
          value={data.heartRate}
          expanded={expanded === 'heartRate'}
          onToggle={() => toggle('heartRate')}
          onChange={(heartRate) => update({ heartRate })}
          readOnly={readOnly}
        />
      )}
      {activeBuiltins.includes('activity') && (
        <ActivityPill
          value={data.activity}
          expanded={expanded === 'activity'}
          onToggle={() => toggle('activity')}
          onChange={(activity) => update({ activity })}
          readOnly={readOnly}
        />
      )}
      {activeBuiltins.includes('energy') && (
        <ScalePill
          id="energy"
          label={t('labels.energy')}
          color={BUILTIN_TRACKER_COLORS.energy}
          value={data.energy}
          expanded={expanded === 'energy'}
          onToggle={() => toggle('energy')}
          onChange={(energy) => update({ energy })}
          readOnly={readOnly}
        />
      )}
      {activeBuiltins.includes('focus') && (
        <ScalePill
          id="focus"
          label={t('labels.focus')}
          color={BUILTIN_TRACKER_COLORS.focus}
          value={data.focus}
          expanded={expanded === 'focus'}
          onToggle={() => toggle('focus')}
          onChange={(focus) => update({ focus })}
          readOnly={readOnly}
        />
      )}
      {activeBuiltins.includes('medication') && (
        <MedicationPill
          value={data.medications}
          expanded={expanded === 'medication'}
          onToggle={() => toggle('medication')}
          onChange={(medications) => update({ medications })}
          templates={medications}
          onTemplatesChange={onMedicationsChange}
          readOnly={readOnly}
        />
      )}
      {activeBuiltins.includes('weight') && (
        <NumberInputPill
          id="weight"
          label={t('labels.weight')}
          color={BUILTIN_TRACKER_COLORS.weight}
          value={data.weight}
          expanded={expanded === 'weight'}
          onToggle={() => toggle('weight')}
          onChange={(weight) => update({ weight })}
          readOnly={readOnly}
          unit={t('units.kg')}
          placeholder="70"
          min={20}
          max={300}
          step={0.1}
        />
      )}
      {activeBuiltins.includes('steps') && (
        <NumberInputPill
          id="steps"
          label={t('labels.steps')}
          color={BUILTIN_TRACKER_COLORS.steps}
          value={data.steps}
          expanded={expanded === 'steps'}
          onToggle={() => toggle('steps')}
          onChange={(steps) => update({ steps })}
          readOnly={readOnly}
          unit={t('units.steps', { count: data.steps ?? 0 })}
          placeholder="8000"
          min={0}
          max={100000}
          step={1}
        />
      )}
      {activeBuiltins.includes('water') && (
        <ScalePill
          id="water"
          label={t('labels.water')}
          color={BUILTIN_TRACKER_COLORS.water}
          value={data.water}
          expanded={expanded === 'water'}
          onToggle={() => toggle('water')}
          onChange={(water) => update({ water })}
          readOnly={readOnly}
          suffix={t('units.glasses', { count: data.water ?? 0 })}
          lowLabel={t('scaleEnds.none')}
          highLabel={t('scaleEnds.waterHigh')}
        />
      )}
      {activeBuiltins.includes('screenTime') && (
        <NumberInputPill
          id="screenTime"
          label={t('labels.screenTime')}
          color={BUILTIN_TRACKER_COLORS.screenTime}
          value={data.screenTime}
          expanded={expanded === 'screenTime'}
          onToggle={() => toggle('screenTime')}
          onChange={(screenTime) => update({ screenTime })}
          readOnly={readOnly}
          unit={t('units.hrs')}
          placeholder="4"
          min={0}
          max={24}
          step={0.5}
        />
      )}
      {activeBuiltins.includes('caffeine') && (
        <ScalePill
          id="caffeine"
          label={t('labels.caffeine')}
          color={BUILTIN_TRACKER_COLORS.caffeine}
          value={data.caffeine}
          expanded={expanded === 'caffeine'}
          onToggle={() => toggle('caffeine')}
          onChange={(caffeine) => update({ caffeine })}
          readOnly={readOnly}
          max={5}
          suffix={t('units.cups', { count: data.caffeine ?? 0 })}
          lowLabel={t('scaleEnds.none')}
          highLabel={t('scaleEnds.caffeineHigh')}
        />
      )}
      {activeBuiltins.includes('pain') && (
        <ScalePill
          id="pain"
          label={t('labels.pain')}
          color={BUILTIN_TRACKER_COLORS.pain}
          value={data.pain}
          expanded={expanded === 'pain'}
          onToggle={() => toggle('pain')}
          onChange={(pain) => update({ pain })}
          readOnly={readOnly}
          lowLabel={t('scaleEnds.none')}
          highLabel={t('scaleEnds.painHigh')}
        />
      )}
      {activeBuiltins.includes('social') && (
        <ScalePill
          id="social"
          label={t('labels.social')}
          color={BUILTIN_TRACKER_COLORS.social}
          value={data.social}
          expanded={expanded === 'social'}
          onToggle={() => toggle('social')}
          onChange={(social) => update({ social })}
          readOnly={readOnly}
          max={5}
          lowLabel={t('scaleEnds.socialLow')}
          highLabel={t('scaleEnds.socialHigh')}
        />
      )}
      {customUnlocked && activeCustom.map((t) => (
        <CustomPill
          key={t.id}
          template={t}
          value={data.customTrackers?.find((e) => e.trackerId === t.id)?.value}
          expanded={expanded === `custom-${t.id}`}
          onToggle={() => toggle(`custom-${t.id}`)}
          onChange={(value) => {
            const existing = data.customTrackers ?? [];
            const idx = existing.findIndex((e) => e.trackerId === t.id);
            const next = [...existing];
            if (idx >= 0) {
              next[idx] = { trackerId: t.id, value };
            } else {
              next.push({ trackerId: t.id, value });
            }
            update({ customTrackers: next });
          }}
          readOnly={readOnly}
        />
      ))}
      {!readOnly && (
        <button
          type="button"
          onClick={() => customUnlocked ? toggle('__config__') : onOpenUpgrade?.()}
          className="inline-flex items-center gap-1 rounded-full px-2.5 py-1 text-xs font-medium border border-dashed border-neutral-300 dark:border-neutral-600 text-neutral-400 dark:text-neutral-500 hover:border-neutral-400 dark:hover:border-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition-colors shrink-0"
        >
          <Plus size={10} />
          {t('labels.custom')}
          {!isPro && (
            <span className="inline-flex items-center px-1 py-0 rounded text-[8px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300 ms-0.5">
              PRO
            </span>
          )}
        </button>
      )}
    </div>
    <div ref={setExpandEl} />
    </PillExpandContext.Provider>
  );
}
