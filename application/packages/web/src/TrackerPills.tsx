/**
 * TrackerPills - modular mood & wellness tracker UI for journal entries.
 *
 * Renders a row of pill buttons above the editor. Each pill has three states:
 *   1. Empty (not filled) - muted outline, shows "+" icon
 *   2. Active (expanded)  - user is filling in data, shows inline picker
 *   3. Filled (collapsed) - shows the logged value as a compact chip
 *
 * The row wraps and shows every tracker of the setup; it never scrolls
 * sideways, so no pill is out of reach on any width. When `collapsed` is true
 * (editor focused / keyboard open), only filled pills are shown as a short
 * swipeable strip with shortened labels but icons preserved.
 *
 * The guided pass is the row's own: in the check-in card it starts at once
 * (`flow`), in the entry it starts when a picker commits. A picker that
 * commits and closes opens the next tracker without a value, and a bar over
 * the panel names the step and offers Next (Finish on the last) and, in the
 * entry, Done. Spec: ops/docs/archive/ui-patterns.md section 141
 */

import { answeredHabitIds, customHabitsNow } from './habitList';
import { useCallback, useEffect, useRef, type ReactNode, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Gear, Plus } from './icons';
import type { TrackerSetupTab } from './TrackerConfig';
import { HoverLabel } from './HoverLabel';
import {
  BUILTIN_TRACKER_COLORS,
  EMOTION_TAGS,
  MOOD_ANCHORS,
  type ActivityLevel,
  type FactorDef,
  type JournalTrackerData,
  type MedicationTemplate,
  type SleepQuality,
  type TrackerSettings,
  type CaffeineUnit,
  type WaterUnit,
  type WeightUnit,
  CAFFEINE_UNITS,
  caffeineInput,
  caffeineToCanonical,
  caffeineToDisplay,
  WATER_UNITS,
  WEIGHT_UNITS,
  waterInput,
  waterToCanonical,
  waterToDisplay,
  activeCustomTrackers,
  customTrackerColor,
  weightRange,
  weightToCanonical,
  weightToDisplay,
} from './trackerTypes';
import { caffeineText, waterText } from './trackerExport';
import { TRACKER_ICONS } from './trackers/icons';
import { ActivityPill } from './trackers/ActivityPill';
import { CustomPill } from './trackers/CustomPill';
import { EmotionsPill } from './trackers/EmotionsPill';
import { FactorsPill } from './trackers/FactorsPill';
import { HabitsPill } from './trackers/HabitsPill';
import { MedicationPill } from './trackers/MedicationPill';
import { MoodPill } from './trackers/MoodPill';
import { ScalePill } from './trackers/ScalePill';
import { SleepPill } from './trackers/SleepPill';
import { SleepScorePill } from './trackers/SleepScorePill';
import { HeartRatePill } from './trackers/HeartRatePill';
import { NumberInputPill } from './trackers/NumberInputPill';
import { PillCloseOutsideContext, PillExpandContext } from './trackers/PillShell';
import { proUnlocked } from './demo';
import { useLastLogged } from './trackerLastLogged';
import { CustomTrackerGlyph } from './trackers/CustomTrackerGlyph';
import { useIsTouchDevice } from './useIsMobile';
import { Button } from './ui';

export interface TrackerPillsProps {
  data: JournalTrackerData;
  onChange: (next: JournalTrackerData) => void;
  trackerSettings: TrackerSettings;
  onSettingsChange: (next: TrackerSettings) => void;
  medications: MedicationTemplate[];
  readOnly?: boolean;
  isPro: boolean;
  onOpenUpgrade?: () => void;
  /** When true, render compact strip (editor focused on mobile). */
  collapsed?: boolean;
  /** The person's own factor list; the tracker setup edits it. */
  factors: FactorDef[];
  /** `card`: the check-in card's row, with no setup button and no Custom
   *  button; the card's gear holds the setup. */
  variant?: 'entry' | 'card';
  /** Pills the host draws itself (the card draws the mood as faces). */
  exclude?: readonly string[];
  className?: string;
  /** The check-in card's pass: the first empty tracker opens at once, and
   *  `onFinish` runs when the pass ends. `extra` sits under the open panel.
   *  Without it the row runs the entry's pass, which starts on the first commit.
   *  `done`, once the pass has ended, takes the place of the step bar and the
   *  panel while the pills stay: the card's success state. */
  flow?: { onFinish: () => void; extra?: ReactNode; done?: ReactNode };
  /** The card only: the pills on the start, the step bar and the open panel
   *  in a column of the panel's width on the end, for a card far wider than
   *  the panel. */
  split?: boolean;
  /** Opens Settings > Trackers, the one tracker setup, on a tab or a part
   *  of one. Without it the row offers no setup button. */
  onOpenSetup?: (tab: TrackerSetupTab) => void;
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
      className="inline-flex items-center gap-1 rounded-md px-2 py-0.5 text-[11px] font-medium whitespace-nowrap shrink-0 transition-colors"
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
 * Spec: ops/docs/archive/ui-patterns.md section 85 (hidden sideways scroll).
 */
const SCROLL_OR_WRAP = {
  touch: 'overflow-x-auto [scrollbar-width:none] [&::-webkit-scrollbar]:hidden',
  pointer: 'flex-wrap',
} as const;

function extraSlot(node: ReactNode): ReactNode {
  return node ?? null;
}

/** The quick picks of the number trackers, fixed per tracker. */
const QUICK_STEPS = [5000, 8000, 10000, 12000] as const;
const QUICK_SCREEN_HOURS = [1, 2, 4, 6] as const;

function moodShort(v: number, t: (key: string) => string): string {
  return MOOD_ANCHORS[v] != null ? `${v} ${t(`mood.anchor.${v}`)}` : `${v}`;
}

export function TrackerPills({
  data,
  onChange,
  trackerSettings,
  onSettingsChange,
  medications,
  readOnly,
  isPro,
  onOpenUpgrade,
  collapsed,
  factors,
  variant = 'entry',
  exclude,
  className = '',
  flow,
  onOpenSetup,
  split = false,
}: TrackerPillsProps) {
  const { t } = useTranslation('trackers');
  const [expanded, setExpanded] = useState<string | null>(null);
  // The entry's pass: on while a panel is open, and from the first commit
  // until Done or the last step, so Next is there for a number too.
  const [entryPass, setEntryPass] = useState(false);
  const passOn = !!flow || entryPass || expanded !== null;
  // The pass's place in the row, kept apart from `expanded`: an outside tap
  // closes the panel, and the bar still knows which tracker comes next.
  const [cursor, setCursor] = useState<string | null>(null);
  const flowStarted = useRef(false);
  // When the last value was written, to tell a picker that closes because it
  // committed from one closed by a tap elsewhere.
  const lastChange = useRef(0);
  const orderRef = useRef<string[]>([]);
  const filledRef = useRef<Set<string>>(new Set());
  const openNext = useCallback((from: string | null) => {
    const order = orderRef.current;
    const at = from ? order.indexOf(from) : -1;
    const next = order[at + 1];
    if (next) {
      setExpanded(next);
      setCursor(next);
    } else {
      setExpanded(null);
      setCursor(null);
      setEntryPass(false);
      flow?.onFinish();
    }
  }, [flow]);
  const isTouch = useIsTouchDevice();
  // Custom trackers are Pro, and purely local - the demo unlocks them so
  // visitors can build one. The PRO badge on "Custom" keys off isPro.
  const customUnlocked = proUnlocked(isPro);
  const [expandEl, setExpandEl] = useState<HTMLDivElement | null>(null);

  const toggle = useCallback(
    (id: string) => {
      if (readOnly) return;
      // A picker that closes right after it wrote a value hands over to the
      // next tracker: that is the pass, and in the entry it is what starts it.
      if (expanded === id && Date.now() - lastChange.current < 120) {
        if (!flow) setEntryPass(true);
        openNext(id);
        return;
      }
      setCursor(id);
      setExpanded((prev) => (prev === id ? null : id));
    },
    [readOnly, flow, expanded, openNext]
  );

  const update = useCallback(
    (patch: Partial<JournalTrackerData>) => {
      lastChange.current = Date.now();
      onChange({ ...data, ...patch });
    },
    [data, onChange]
  );

  const { activeBuiltins, customTrackers, weightUnit } = trackerSettings;
  const caffeineUnit = trackerSettings.caffeineUnit ?? 'cups';
  const caffeineIn = caffeineInput(caffeineUnit);
  const caffeineShown = data.caffeine != null ? caffeineToDisplay(data.caffeine, caffeineUnit) : undefined;
  const caffeineLabel = data.caffeine != null ? caffeineText(data.caffeine, caffeineUnit) : '';
  const caffeineUnitOptions = CAFFEINE_UNITS.map((u) => ({ key: u, label: t(`units.caffeine.${u}`) }));
  const waterUnit = trackerSettings.waterUnit ?? 'glasses';
  const waterIn = waterInput(waterUnit);
  // An empty number panel starts from the last value logged, in the unit shown.
  const waterLast = useLastLogged((d) => (d.water == null ? undefined : waterToDisplay(d.water, waterUnit)));
  const caffeineLast = useLastLogged((d) => (d.caffeine == null ? undefined : caffeineToDisplay(d.caffeine, caffeineUnit)));
  const stepsLast = useLastLogged((d) => d.steps);
  const screenLast = useLastLogged((d) => d.screenTime);
  const weightLast = useLastLogged((d) => (d.weight == null ? undefined : weightToDisplay(d.weight, weightUnit)));
  const waterUnitOptions = WATER_UNITS.map((u) => ({ key: u, label: t(`units.water.${u}`) }));
  const waterShown = data.water != null ? waterToDisplay(data.water, waterUnit) : undefined;
  const waterLabel = data.water != null ? waterText(data.water, waterUnit) : '';
  const weightBounds = weightRange(weightUnit);
  const weightUnitOptions = WEIGHT_UNITS.map((u) => ({ key: u, label: t(`units.${u}`) }));
  const activeCustom = activeCustomTrackers(customTrackers).filter((t) => !t.stoppedAt);

  // The flow opens on the first tracker with no value yet, once. Declared
  // before the collapsed branch returns, so the hook count never changes
  // between a collapsed and an open render.
  useEffect(() => {
    if (!flow || flowStarted.current) return;
    flowStarted.current = true;
    const first = orderRef.current.find((key) => !filledRef.current.has(key)) ?? null;
    if (first) {
      setExpanded(first);
      setCursor(first);
    }
    // eslint-disable-next-line react-hooks/exhaustive-deps -- once, on the first render of a flow
  }, []);

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
    if (activeBuiltins.includes('factors') && data.factors?.length) {
      pills.push({ key: 'factors', color: BUILTIN_TRACKER_COLORS.factors, icon: TRACKER_ICONS.factors, label: `${data.factors.length}`, toggle: 'factors' });
    }
    if (activeBuiltins.includes('habits') && answeredHabitIds(data.habits, customHabitsNow()).length > 0) {
      const yes = answeredHabitIds(data.habits, customHabitsNow()).filter((id) => data.habits?.[id] === true).length;
      pills.push({ key: 'habits', color: BUILTIN_TRACKER_COLORS.habits, icon: TRACKER_ICONS.habits, label: `${yes}/${trackerSettings.habits.length}`, toggle: 'habits' });
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
      pills.push({ key: 'weight', color: BUILTIN_TRACKER_COLORS.weight, icon: TRACKER_ICONS.weight, label: `${weightToDisplay(data.weight, weightUnit)}${t(`units.${weightUnit}`)}`, toggle: 'weight' });
    }
    if (activeBuiltins.includes('steps') && data.steps != null) {
      pills.push({ key: 'steps', color: BUILTIN_TRACKER_COLORS.steps, icon: TRACKER_ICONS.steps, label: `${data.steps}`, toggle: 'steps' });
    }
    if (activeBuiltins.includes('water') && data.water != null) {
      pills.push({ key: 'water', color: BUILTIN_TRACKER_COLORS.water, icon: TRACKER_ICONS.water, label: waterLabel, toggle: 'water' });
    }
    if (activeBuiltins.includes('screenTime') && data.screenTime != null) {
      pills.push({ key: 'screenTime', color: BUILTIN_TRACKER_COLORS.screenTime, icon: TRACKER_ICONS.screenTime, label: `${data.screenTime}${t('units.hoursSuffix')}`, toggle: 'screenTime' });
    }
    if (activeBuiltins.includes('caffeine') && data.caffeine != null) {
      pills.push({ key: 'caffeine', color: BUILTIN_TRACKER_COLORS.caffeine, icon: TRACKER_ICONS.caffeine, label: caffeineLabel, toggle: 'caffeine' });
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
          pills.push({ key: `c-${t.id}`, color: customTrackerColor(t) ?? '#888', icon: <CustomTrackerGlyph icon={t.icon} />, label: `${entry.value}`, toggle: `custom-${t.id}` });
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
  // Each pill is listed with whether it holds a value, so the check-in card
  // can show a short row: the filled pills, then the first empty ones up to
  // its limit, then "+ N more".
  const items: { key: string; filled: boolean; node: ReactNode; label: string }[] = [];
  const add = (key: string, filled: boolean, node: ReactNode, label?: string) => {
    if (exclude?.includes(key)) return;
    items.push({ key, filled, node, label: label ?? t(`labels.${key === 'medication' ? 'medication' : key}`) });
  };
  if (activeBuiltins.includes('mood')) add('mood', data.mood != null, (
    <MoodPill
      key="mood"
      value={data.mood}
      expanded={expanded === 'mood'}
      onToggle={() => toggle('mood')}
      onChange={(mood) => update({ mood })}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('emotions')) add('emotions', !!data.emotions?.length, (
    <EmotionsPill
      key="emotions"
      value={data.emotions}
      expanded={expanded === 'emotions'}
      onToggle={() => toggle('emotions')}
      onChange={(emotions) => update({ emotions })}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('factors')) add('factors', !!data.factors?.length, (
    <FactorsPill
      key="factors"
      value={data.factors}
      factors={factors}
      expanded={expanded === 'factors'}
      onToggle={() => toggle('factors')}
      onChange={(next) => update({ factors: next })}
      onEditFactors={onOpenSetup ? () => onOpenSetup('factors') : undefined}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('habits')) add('habits', answeredHabitIds(data.habits, customHabitsNow()).length > 0, (
    <HabitsPill
      key="habits"
      value={data.habits}
      questions={trackerSettings.habits}
      expanded={expanded === 'habits'}
      onToggle={() => toggle('habits')}
      onChange={(habits) => update({ habits })}
      onChangeQuestions={onOpenSetup ? () => onOpenSetup('questions') : undefined}
      includeCustom={customUnlocked}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('sleep')) add('sleep', !!data.sleep, (
    <SleepPill
      key="sleep"
      value={data.sleep}
      expanded={expanded === 'sleep'}
      onToggle={() => toggle('sleep')}
      onChange={(sleep) => update({ sleep })}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('sleepScore')) add('sleepScore', data.sleepScore != null, (
    <SleepScorePill
      key="sleepScore"
      value={data.sleepScore}
      expanded={expanded === 'sleepScore'}
      onToggle={() => toggle('sleepScore')}
      onChange={(sleepScore) => update({ sleepScore })}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('heartRate')) add('heartRate', data.heartRate != null, (
    <HeartRatePill
      key="heartRate"
      value={data.heartRate}
      expanded={expanded === 'heartRate'}
      onToggle={() => toggle('heartRate')}
      onChange={(heartRate) => update({ heartRate })}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('activity')) add('activity', !!data.activity, (
    <ActivityPill
      key="activity"
      value={data.activity}
      expanded={expanded === 'activity'}
      onToggle={() => toggle('activity')}
      onChange={(activity) => update({ activity })}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('energy')) add('energy', data.energy != null, (
    <ScalePill
      key="energy"
      id="energy"
      label={t('labels.energy')}
      value={data.energy}
      expanded={expanded === 'energy'}
      onToggle={() => toggle('energy')}
      onChange={(energy) => update({ energy })}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('focus')) add('focus', data.focus != null, (
    <ScalePill
      key="focus"
      id="focus"
      label={t('labels.focus')}
      value={data.focus}
      expanded={expanded === 'focus'}
      onToggle={() => toggle('focus')}
      onChange={(focus) => update({ focus })}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('medication')) add('medication', !!data.medications?.length, (
    <MedicationPill
      key="medication"
      value={data.medications}
      day={typeof data.journalDate === 'string' ? data.journalDate : undefined}
      expanded={expanded === 'medication'}
      onToggle={() => toggle('medication')}
      onChange={(medications) => update({ medications })}
      templates={medications}
      onEditMedications={onOpenSetup ? () => onOpenSetup('medications') : undefined}
      supplyUnlocked={proUnlocked(isPro)}
      readOnly={readOnly}
    />
  ));
  if (activeBuiltins.includes('weight')) add('weight', data.weight != null, (
    <NumberInputPill
      key="weight"
      id="weight"
      label={t('labels.weight')}
      value={data.weight != null ? weightToDisplay(data.weight, weightUnit) : undefined}
      expanded={expanded === 'weight'}
      onToggle={() => toggle('weight')}
      onChange={(v) => update({ weight: weightToCanonical(v, weightUnit) })}
      readOnly={readOnly}
      unit={t(`units.${weightUnit}`)}
      unitOptions={weightUnitOptions}
      activeUnit={weightUnit}
      onUnitChange={(u) =>
        onSettingsChange({ ...trackerSettings, weightUnit: u as WeightUnit })
      }
      placeholder={weightUnit === 'kg' ? '70' : '155'}
      min={weightBounds.min}
      max={weightBounds.max}
      step={0.1}
      start={weightLast}
    />
  ));
  if (activeBuiltins.includes('steps')) add('steps', data.steps != null, (
    <NumberInputPill
      key="steps"
      id="steps"
      label={t('labels.steps')}
      value={data.steps}
      expanded={expanded === 'steps'}
      onToggle={() => toggle('steps')}
      onChange={(steps) => update({ steps })}
      readOnly={readOnly}
      unit={t('units.steps', { count: data.steps ?? 0 })}
      placeholder="8000"
      min={0}
      max={100000}
      step={500}
      quick={QUICK_STEPS}
      start={stepsLast}
    />
  ));
  if (activeBuiltins.includes('water')) add('water', data.water != null, (
    <NumberInputPill
      key="water"
      id="water"
      label={t('labels.water')}
      prompt={t('water.prompt')}
      value={waterShown}
      filledText={waterLabel}
      expanded={expanded === 'water'}
      onToggle={() => toggle('water')}
      onChange={(v) => update({ water: waterToCanonical(v, waterUnit) })}
      readOnly={readOnly}
      unit={t(`units.water.${waterUnit}`)}
      unitOptions={waterUnitOptions}
      activeUnit={waterUnit}
      onUnitChange={(u) => onSettingsChange({ ...trackerSettings, waterUnit: u as WaterUnit })}
      placeholder="0"
      min={0}
      max={waterIn.max}
      step={waterIn.step}
      quick={waterIn.quick}
      start={waterLast}
    />
  ));
  if (activeBuiltins.includes('screenTime')) add('screenTime', data.screenTime != null, (
    <NumberInputPill
      key="screenTime"
      id="screenTime"
      label={t('labels.screenTime')}
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
      quick={QUICK_SCREEN_HOURS}
      start={screenLast}
    />
  ));
  if (activeBuiltins.includes('caffeine')) add('caffeine', data.caffeine != null, (
    <NumberInputPill
      key="caffeine"
      id="caffeine"
      label={t('labels.caffeine')}
      prompt={t('caffeine.prompt')}
      value={caffeineShown}
      filledText={caffeineLabel}
      expanded={expanded === 'caffeine'}
      onToggle={() => toggle('caffeine')}
      onChange={(v) => update({ caffeine: caffeineToCanonical(v, caffeineUnit) })}
      readOnly={readOnly}
      unit={t(`units.caffeine.${caffeineUnit}`)}
      unitOptions={caffeineUnitOptions}
      activeUnit={caffeineUnit}
      onUnitChange={(u) => onSettingsChange({ ...trackerSettings, caffeineUnit: u as CaffeineUnit })}
      placeholder="0"
      min={0}
      max={caffeineIn.max}
      step={caffeineIn.step}
      quick={caffeineIn.quick}
      start={caffeineLast}
    />
  ));
  if (activeBuiltins.includes('pain')) add('pain', data.pain != null, (
    <ScalePill
      key="pain"
      id="pain"
      label={t('labels.pain')}
      value={data.pain}
      expanded={expanded === 'pain'}
      onToggle={() => toggle('pain')}
      onChange={(pain) => update({ pain })}
      readOnly={readOnly}
      lowLabel={t('scaleEnds.none')}
      highLabel={t('scaleEnds.painHigh')}
    />
  ));
  if (activeBuiltins.includes('social')) add('social', data.social != null, (
    <ScalePill
      key="social"
      id="social"
      label={t('labels.social')}
      value={data.social}
      expanded={expanded === 'social'}
      onToggle={() => toggle('social')}
      onChange={(social) => update({ social })}
      readOnly={readOnly}
      max={5}
      lowLabel={t('scaleEnds.socialLow')}
      highLabel={t('scaleEnds.socialHigh')}
    />
  ));
  if (customUnlocked) {
    for (const ct of activeCustom) {
      const entry = data.customTrackers?.find((e) => e.trackerId === ct.id);
      add(`custom-${ct.id}`, entry?.value != null, (
        <CustomPill
          key={ct.id}
          template={ct}
          value={entry?.value}
          expanded={expanded === `custom-${ct.id}`}
          onToggle={() => toggle(`custom-${ct.id}`)}
          onChange={(value) => {
            const existing = data.customTrackers ?? [];
            const idx = existing.findIndex((e) => e.trackerId === ct.id);
            const next = [...existing];
            if (idx >= 0) {
              next[idx] = { trackerId: ct.id, value };
            } else {
              next.push({ trackerId: ct.id, value });
            }
            update({ customTrackers: next });
          }}
          readOnly={readOnly}
        />
      ), ct.name);
    }
  }

  orderRef.current = items.map((it) => it.key);
  filledRef.current = new Set(items.filter((it) => it.filled).map((it) => it.key));

  const card = variant === 'card';
  // The way to Settings > Trackers, the one setup. In the card it ends the
  // row near the card's edge, so its tip opens above instead of beside it.
  const setupGear = onOpenSetup && (
    <HoverLabel label={t('config.configureTrackers')} position={card ? 'above' : 'end'}>
      <button
        type="button"
        onClick={() => onOpenSetup('trackers')}
        className="inline-flex items-center justify-center w-7 h-7 shrink-0 self-center rounded-full text-pn-muted hover:text-pn-soft hover:bg-pn/5 transition-colors"
        aria-label={t('config.configureTrackers')}
      >
        <Gear />
      </button>
    </HoverLabel>
  );
  const containerClass = card
    ? `flex flex-wrap gap-1.5 ${split ? 'min-w-0 flex-1 content-start' : ''} ${className}`
    : 'flex flex-wrap gap-1.5 px-4 sm:px-6 pt-3 pb-2';

  const pillRow = (
    <div className={containerClass}>
      {!readOnly && !card && setupGear}
      {items.map((it) => it.node)}
      {/* In the card the setup gear ends the row: at its start it sat beside
          the card's own gear. */}
      {!readOnly && card && setupGear}
      {!readOnly && !card && onOpenSetup && (
        <button
          type="button"
          onClick={() => customUnlocked ? onOpenSetup('custom') : onOpenUpgrade?.()}
          className="inline-flex items-center gap-1 rounded-md border border-dashed border-pn-muted/50 px-2 h-7 [@media(hover:none)]:h-8 text-[12px] font-medium text-pn-muted hover:border-pn-muted hover:text-pn-soft transition-colors shrink-0"
        >
          <Plus size={11} />
          {t('labels.custom')}
          {!isPro && (
            <span className="inline-flex items-center px-1 py-0 rounded text-[8px] font-bold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300 ms-0.5">
              PRO
            </span>
          )}
        </button>
      )}
    </div>
  );

  const pass = flow?.done ? <>{flow.done}</> : (
    <>
    {passOn && !readOnly && (() => {
      const order = orderRef.current;
      const at = cursor ? order.indexOf(cursor) : -1;
      const current = at >= 0 ? items[at] : undefined;
      const hasNext = at + 1 < order.length;
      const finish = () => {
        setExpanded(null);
        setCursor(null);
        setEntryPass(false);
        flow?.onFinish();
      };
      return (
        // Above the panel, so a panel that closes under a tap cannot move it.
        // The pointerdown stops here: `PillShell` closes the open panel on any
        // pointerdown outside it, and a bar that unmounts under the finger
        // would swallow the Next tap. In the card it takes the panel's width,
        // so Next ends where the panel and its top line end, and it keeps the
        // entry's 16 px from the pills, whose row in the card has no padding.
        <div className={`flex flex-wrap items-center gap-2 pb-3 ${split ? '' : card ? 'pt-4' : 'pt-2'} ${card ? 'max-w-[560px]' : 'px-4 sm:px-6'}`} onPointerDown={(e) => e.stopPropagation()}>
          {current && (
            <span className="min-w-[7rem] flex-1 leading-tight">
              <span className="block truncate text-[13px] font-semibold text-pn">{current.label}</span>
              <span className="block whitespace-nowrap text-[11px] text-pn-muted">{t('flow.step', { n: at + 1, total: order.length })}</span>
            </span>
          )}
          {!current && <span className="flex-1" />}
          {/* The card's Done sits here too, beside Next, so the card's own
              line keeps only its gear. On the last step Finish does its job. */}
          {/* The buttons wrap under the step name at the end when the card is narrow. */}
          <div className="ms-auto flex shrink-0 gap-2">
            {(!flow || (card && hasNext)) && (
              <Button action="done" variant="secondary" onClick={finish}>
                {t('flow.done')}
              </Button>
            )}
            {hasNext ? (
              <Button action="next" onClick={() => openNext(cursor)}>
                {t('flow.next')}
              </Button>
            ) : (
              <Button action="finish" onClick={finish}>
                {t('flow.finish')}
              </Button>
            )}
          </div>
        </div>
      );
    })()}
    <div ref={setExpandEl} className={card ? '[&>div]:px-0 [&>div]:mt-2 [&>div]:max-w-[560px]' : ''} />
    {/* Under the panel, so the step bar keeps its room for the step count. */}
    {flow?.extra && <div className="pt-2">{extraSlot(flow.extra)}</div>}
    </>
  );

  return (
    <PillExpandContext.Provider value={expandEl}>
    <PillCloseOutsideContext.Provider value={!card}>
    {/* The card keeps one tree at every width, so a resize across the split
        never remounts the open panel. A column of the panel's width keeps
        Next at the panel's edge, under the card's Done. */}
    {card ? (
      <div className={split ? 'flex items-start gap-6' : ''}>
        {pillRow}
        <div className={split ? 'w-[560px] shrink-0' : ''}>{pass}</div>
      </div>
    ) : (
      <>
        {pillRow}
        {pass}
      </>
    )}
    </PillCloseOutsideContext.Provider>
    </PillExpandContext.Provider>
  );
}
