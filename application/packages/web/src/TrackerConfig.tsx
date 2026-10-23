/**
 * Settings > Trackers: the one place the trackers are set up. Four tabs:
 * the trackers and the Habits questions with the custom trackers, the
 * person's factor list, the medication list, and the check-in card with its
 * reminder. Every door to the setup opens this pane (the gear of a journal
 * entry's pill row, its "+ Custom" button, the check-in card's gear, the
 * Habits panel's "Change these questions"); there is no second dialog.
 * Changes apply as they are made, like every other settings pane.
 * Spec: ops/docs/archive/ui-patterns.md section 141
 */

import { lazy, Suspense, useLayoutEffect, useMemo, useRef, useState, type KeyboardEvent, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { BellSimple, Check, Coffee, TextT, Eye, Heartbeat, ListChecks, Palette, Pause, Play, Shapes, Smiley, type Icon, Clock, ClockCounterClockwise, Gauge, Hash, Percent, Star, ToggleLeft, PencilSimple, Pill, Plus, PuzzlePiece, SlidersHorizontal } from './icons';
import { CustomTrackerInput } from './trackers/CustomPill';
import { TEXT_COLORS } from './editorColors';
import { starterSuggestions } from './trackers/FactorsPill';
import { CustomTrackerGlyph, MarkTile } from './trackers/CustomTrackerGlyph';
import { ColorSwatch } from './ColorSwatch';
import { setItemLook } from './itemStyles';
import { loadLocalSettings } from './userSettings';
import { proUnlocked } from './demo';
import { IconUpgrade } from './UpgradeModal';
import { HoverLabel } from './HoverLabel';
import { isImeComposing } from './imeComposing';
import { toLocalIso } from './notesViewUtils';
import { formatDay } from './intlFormat';
import { Switch } from './Switch';
import { EYEBROW_ICON_ROW, EyebrowGlyph, ROW_TITLE, RowTitle, SETTINGS_BTN, SETTINGS_BTN_PRIMARY, SETTINGS_EYEBROW, SETTINGS_HELP, SETTINGS_ROW, SETTINGS_SELECT, SectionEyebrow, SettingsSegmented, SettingsTabStrip, settingsTabClass, settingsChipClass, ResetDefaultsButton } from './settingsUI';
import { Badge, Button, DeleteButton, EditRow, GlyphTile, IconButton, ItemSwitcher, SubViewHeader, TextField, type SwitcherItem } from './ui';
import { TimeInput } from './CalendarSettings';
import { setCheckInCardShown } from './checkInCardSwitch';
import { DEFAULT_CHECK_IN_TIME, setCheckInReminder, useCheckInReminder } from './checkIn';
import { REMINDER_PLATFORM, askForRemindersOnce } from './notesView/useReminders';
import { adoptFactor, adoptFactors, removeFactor, renameFactor } from './factorList';
import { CUSTOM_HABITS_MAX, CUSTOM_HABIT_NAME_MAX, CUSTOM_HABIT_SHORT_MAX, activeCustomHabits, addCustomHabit, allHabitQuestions, askedHabits, cleanHabitName, removeCustomHabit, renameCustomHabit, type CustomHabitDef, type HabitKind } from './habitList';
import { addMedication, removeMedication, saveMedication } from './medicationTemplates';
import { MedicationEditor, MedicationGlyph, describeMedication, type MedicationEdit } from './trackers/MedicationEditor';
import { setMedicationReminder, useMedicationReminders } from './medicationReminders';
import { runsOutOn, supplyLeft } from './medicationDoses';
import { useTrackerHistory } from './trackerLastLogged';
import {
  type BuiltinTrackerId,
  type FactorDef,
  type MedicationTemplate,
  type TrackerSettings,
  type CustomTrackerTemplate,
  type CustomTrackerType,
  type TrackerColor,
  BUILTIN_TRACKER_COLORS,
  CUSTOM_TRACKER_TYPE_LABELS,
  FACTOR_NAME_MAX,
  HABIT_IDS,
  WATCH_HABITS,
  TRACKER_COLORS,
  activeCustomTrackers,
  activeFactors,
  activeMedications,
  customTrackerColor,
  defaultTrackerSettings,
} from './trackerTypes';
import { usePaneTab } from './settingsPaneTab';

/** The pane's tabs, and the two doors that land on a part of the first one. */
export type TrackerSetupTab = 'trackers' | 'questions' | 'custom' | 'factors' | 'medications' | 'checkIn';
type Tab = 'general' | 'factors' | 'medications' | 'custom';

/** The most custom trackers one account can have. They cost nothing to
 *  keep; the cap keeps the check-in pass, the pill row and the statistics
 *  page a usable size. Spec: ops/docs/mood-wellness-tracker.md section 16.4 */
const CUSTOM_MAX = 20;

/** The glyph of each custom tracker type in the setup's type chips: a gauge
 *  and stars for the two scales, a percent for the score, a hash for the
 *  number, a switch for yes or no. */
const TYPE_GLYPHS: Record<CustomTrackerType, Icon> = {
  scale10: Gauge,
  scale5: Star,
  slider100: Percent,
  number: Hash,
  yesno: ToggleLeft,
};

// The icon picker is a chunk of its own, as in the sidebar: it loads on the first open.
const LookPicker = lazy(() => import('./looks/LookPicker').then((m) => ({ default: m.LookPicker })));

interface TrackerMeta { id: BuiltinTrackerId }

const CATEGORIES: { titleKey: string; icon: Icon; trackers: TrackerMeta[] }[] = [
  {
    titleKey: 'config.categoryMoodMind',
    icon: Smiley,
    trackers: [{ id: 'mood' }, { id: 'emotions' }, { id: 'factors' }, { id: 'focus' }, { id: 'pain' }, { id: 'social' }],
  },
  {
    titleKey: 'config.categoryBodyHealth',
    icon: Heartbeat,
    trackers: [{ id: 'sleep' }, { id: 'sleepScore' }, { id: 'heartRate' }, { id: 'activity' }, { id: 'medication' }, { id: 'weight' }],
  },
  {
    titleKey: 'config.categoryLifestyle',
    icon: Coffee,
    trackers: [{ id: 'habits' }, { id: 'energy' }, { id: 'steps' }, { id: 'water' }, { id: 'caffeine' }, { id: 'screenTime' }],
  },
];

/** Grid placement in the own-habits list: the question takes a line of its
 *  own in a narrow pane, the buttons the end of the row. The breakpoint is the
 *  pane's width (a container query), not the window's: Settings can be narrow
 *  on a wide screen. */
const HABIT_QUESTION_FIELD = 'w-full col-span-full @2xl:col-span-1';
const HABIT_ACTIONS = 'col-span-full justify-self-end @2xl:col-span-1';
const QUIET_BTN = 'inline-flex items-center justify-center w-7 h-7 rounded-md text-pn-muted hover:bg-pn/5 hover:text-pn transition';

export interface TrackerSettingsPaneProps {
  settings: TrackerSettings;
  onChange: (next: TrackerSettings) => void;
  factors: FactorDef[];
  onFactorsChange: (next: FactorDef[]) => void;
  /** The person's own habit questions. */
  customHabits: CustomHabitDef[];
  onCustomHabitsChange: (next: CustomHabitDef[]) => void;
  medications: MedicationTemplate[];
  onMedicationsChange: (next: MedicationTemplate[]) => void;
  isPro: boolean;
  onOpenUpgrade: () => void;
  initialTab?: string;
}

export function TrackerSettingsPane(p: TrackerSettingsPaneProps) {
  const { t } = useTranslation('trackers');
  const door = p.initialTab as TrackerSetupTab | undefined;
  const [tab, setTab] = usePaneTab<Tab>('trackers', door === 'custom' || door === 'factors' || door === 'medications' ? door : 'general');
  const tabs: { id: Tab; label: string; icon: ReactNode; pro?: boolean }[] = [
    { id: 'general', label: t('config.tabGeneral'), icon: <SlidersHorizontal aria-hidden="true" /> },
    { id: 'factors', label: t('labels.factors'), icon: <PuzzlePiece aria-hidden="true" /> },
    { id: 'medications', label: t('labels.medication'), icon: <Pill aria-hidden="true" /> },
    { id: 'custom', label: t('config.tabCustom'), icon: <Plus aria-hidden="true" />, pro: true },
  ];
  return (
    <div className="flex-1 min-h-0 flex flex-col">
      <SettingsTabStrip role="tablist" aria-label={t('config.title')} className="shrink-0 px-4 sm:px-6">
        {tabs.map((tb) => (
          <button key={tb.id} type="button" data-setting={`trackers.tab.${tb.id}`} role="tab" aria-selected={tab === tb.id}
            onClick={() => setTab(tb.id)} className={settingsTabClass(tab === tb.id)}>
            {tb.icon}
            {/* Custom trackers are Pro: the rocket says so on the tab, as on every
                Pro row. It shares the label's line: the tab stacks its children,
                and a rocket of its own would take a third line on a phone. */}
            <span className="inline-flex items-center gap-1">
              {tb.label}
              {tb.pro && !p.isPro && <IconUpgrade size={12} />}
            </span>
          </button>
        ))}
      </SettingsTabStrip>
      <div className="flex-1 min-h-0 overflow-y-auto text-pn px-6 pb-6">
        {tab === 'general' && (
          <>
            <CheckInSection />
            <TrackersSection settings={p.settings} onChange={p.onChange} door={door} customHabits={p.customHabits} onCustomHabitsChange={p.onCustomHabitsChange} isPro={p.isPro} onOpenUpgrade={p.onOpenUpgrade} />
            {/* Which trackers and habit questions are on, and the card. Custom
                trackers, factors, medications and units are the person's own
                lists and stay as they are. */}
            <ResetDefaultsButton
              onReset={() => {
                const d = defaultTrackerSettings();
                p.onChange({ ...p.settings, activeBuiltins: d.activeBuiltins, habits: d.habits });
                // The card's switch is this device's (checkInCardSwitch.ts).
                setCheckInCardShown(true);
              }}
            />
          </>
        )}
        {tab === 'factors' && <FactorsTab factors={p.factors} onChange={p.onFactorsChange} />}
        {tab === 'medications' && <MedicationsTab medications={p.medications} onChange={p.onMedicationsChange} isPro={p.isPro} onOpenUpgrade={p.onOpenUpgrade} />}
        {tab === 'custom' && <CustomTab {...p} />}
      </div>
    </div>
  );
}


/** Room for several comma-separated names; each is cut to its own limit. */
const FACTOR_INPUT_MAX = 200;
// ------------------------------------------------------------------
// General: the built-ins and the Habits questions
// ------------------------------------------------------------------

function TrackersSection({ settings, onChange, door, customHabits, onCustomHabitsChange, isPro, onOpenUpgrade }: {
  settings: TrackerSettings;
  onChange: (next: TrackerSettings) => void;
  door?: TrackerSetupTab;
  customHabits: CustomHabitDef[];
  onCustomHabitsChange: (next: CustomHabitDef[]) => void;
  isPro: boolean;
  onOpenUpgrade: () => void;
}) {
  const { t } = useTranslation('trackers');
  const toggleBuiltin = (id: BuiltinTrackerId) => onChange({
    ...settings,
    activeBuiltins: settings.activeBuiltins.includes(id) ? settings.activeBuiltins.filter((x) => x !== id) : [...settings.activeBuiltins, id],
  });
  // A person's own habits are Pro, unlocked in the public demo; without it
  // they are neither listed nor asked, and the add form opens the upgrade.
  const unlocked = proUnlocked(isPro);
  const questions = allHabitQuestions(unlocked ? customHabits : []);
  const onCount = askedHabits(settings.habits, unlocked ? customHabits : []).length;
  // Kept in the asked order, whichever order the taps came in; an id this
  // build does not list (a newer app's habit) stays where it was.
  const habitsWith = (id: string, on: boolean) => {
    const known = new Set(questions.map((q) => q.id));
    const next = questions.map((q) => q.id).filter((h) => (h === id ? on : settings.habits.includes(h)));
    return [...next, ...settings.habits.filter((h) => !known.has(h))];
  };
  const toggleHabit = (id: string) => onChange({ ...settings, habits: habitsWith(id, !settings.habits.includes(id)) });

  return (
    <div className="flex flex-col gap-6 pt-6">
      <div data-setting="trackers.setup" className="flex flex-col gap-4">
        {CATEGORIES.map((cat) => (
          <div key={cat.titleKey}>
            <SectionEyebrow icon={cat.icon} className="mb-2">{t(cat.titleKey)}</SectionEyebrow>
            <div className="flex flex-wrap gap-1.5">
              {cat.trackers.map((meta) => (
                <ToggleChip
                  key={meta.id}
                  on={settings.activeBuiltins.includes(meta.id)}
                  color={BUILTIN_TRACKER_COLORS[meta.id]}
                  label={t(`labels.${meta.id}`)}
                  onToggle={() => toggleBuiltin(meta.id)}
                />
              ))}
            </div>
          </div>
        ))}
      </div>

      {/* The Habits questions, open while Habits is on: the habits to build,
          then the habits to watch. The panel's "Change these questions" link
          lands here. */}
      {settings.activeBuiltins.includes('habits') && (
        <div
          data-setting="trackers.habitQuestions"
          ref={(el) => { if (el && door === 'questions') el.scrollIntoView({ block: 'nearest' }); }}
        >
          <div className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW}`}>
            <EyebrowGlyph icon={ListChecks} />
            {t('config.habitQuestions')}
            {/* A count is metadata: muted, not the accent of the heading. */}
            <span className="ms-auto normal-case tracking-normal font-normal tabular-nums text-pn-muted">{t('config.questionsOn', { on: onCount, total: questions.length })}</span>
          </div>
          {([['habitsBuild', false], ['habitsWatch', true]] as const).map(([key, watch]) => (
            <div key={key} className="mt-3">
              <p className={`${SETTINGS_HELP} mb-1.5`}>{t(`config.${key}`)}</p>
              <div className="flex flex-wrap gap-1.5">
                {questions.filter((q) => q.watch === watch).map((q) => (
                  <ToggleChip key={q.id} on={settings.habits.includes(q.id)} label={q.label} onToggle={() => toggleHabit(q.id)} />
                ))}
              </div>
            </div>
          ))}
          <OwnHabits
            list={unlocked ? customHabits : []}
            locked={!unlocked}
            showPro={!isPro}
            onOpenUpgrade={onOpenUpgrade}
            onChange={onCustomHabitsChange}
            // The new id is not in this render's question list yet; it goes on
            // the end, and every reader sorts by the setup's order.
            onAdded={(id) => onChange({ ...settings, habits: [...settings.habits, id] })}
          />
        </div>
      )}
    </div>
  );
}

/**
 * The person's own habit questions, below the built-in chips: one row each
 * with rename and remove, the Factors tab's rows, and a form that adds one
 * as a habit to build or to watch, switched on at once.
 * Spec: ops/issues/0439.md (Spec)
 */
function OwnHabits({ list, locked, showPro, onOpenUpgrade, onChange, onAdded }: {
  list: CustomHabitDef[];
  /** Free and outside the demo: Add opens the upgrade, name or not. */
  locked: boolean;
  /** The rocket on Add, for every account that is not Pro. */
  showPro: boolean;
  onOpenUpgrade: () => void;
  onChange: (next: CustomHabitDef[]) => void;
  onAdded: (id: string) => void;
}) {
  const { t } = useTranslation('trackers');
  const live = activeCustomHabits(list);
  const [draft, setDraft] = useState('');
  const [draftShort, setDraftShort] = useState('');
  const [kind, setKind] = useState<HabitKind>('build');
  const [editing, setEditing] = useState<{ id: string; name: string; short: string; kind: HabitKind } | null>(null);
  const saveEdit = () => {
    if (editing) onChange(renameCustomHabit(list, editing.id, editing.name, editing.short, editing.kind));
    setEditing(null);
  };
  const editKeys = (e: KeyboardEvent) => { if (!isImeComposing(e) && e.key === 'Enter') saveEdit(); };
  const add = () => {
    if (locked) { onOpenUpgrade(); return; }
    const r = addCustomHabit(list, draft, kind, draftShort);
    if (!r) return;
    onChange(r.list);
    onAdded(r.id);
    setDraft('');
    setDraftShort('');
  };
  const kinds = [{ value: 'build' as const, label: t('config.kindBuild') }, { value: 'watch' as const, label: t('config.kindWatch') }];
  return (
    // One grid for every row: the add form, then a row per habit, editing or
    // not, put their question, short name, kind and buttons in the same
    // columns. On a phone the question takes a line of its own.
    <div data-setting="trackers.ownHabits" className="@container mt-5">
    <div className="grid grid-cols-[minmax(0,1fr)_auto] @2xl:grid-cols-[minmax(0,1fr)_8rem_auto_auto] items-center gap-x-1.5 gap-y-2">
      <p className={`${SETTINGS_HELP} col-span-full`}>{t('config.ownHabits')}</p>
      {live.length < CUSTOM_HABITS_MAX ? (
        <form className="contents" onSubmit={(e) => { e.preventDefault(); add(); }}>
          <TextField
            size="sm"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && isImeComposing(e)) e.preventDefault(); }}
            maxLength={CUSTOM_HABIT_NAME_MAX}
            placeholder={t('config.ownHabitPlaceholder')}
            aria-label={t('config.addHabit')}
            className={HABIT_QUESTION_FIELD}
          />
          <TextField
            size="sm"
            value={draftShort}
            onChange={(e) => setDraftShort(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && isImeComposing(e)) e.preventDefault(); }}
            maxLength={CUSTOM_HABIT_SHORT_MAX}
            placeholder={t('config.shortName')}
            aria-label={t('config.shortNameLabel')}
            className="w-full"
          />
          <SettingsSegmented label={t('config.habitKind')} value={kind} onChange={setKind} options={kinds} className="flex-nowrap whitespace-nowrap" />
          <Button
            type="submit"
            disabled={!cleanHabitName(draft) && !locked}
            icon={<Plus size={15} aria-hidden="true" />}
            pro={showPro}
            className={HABIT_ACTIONS}
          >
            {t('config.addHabit')}
          </Button>
        </form>
      ) : (
        <p className={`${SETTINGS_HELP} col-span-full`}>{t('config.ownHabitsFull', { max: CUSTOM_HABITS_MAX })}</p>
      )}
      {live.map((h) => {
        if (editing?.id === h.id) {
          return (
            <div key={h.id} className="contents">
              <TextField
                size="sm"
                value={editing.name}
                onChange={(e) => setEditing({ ...editing, name: e.target.value })}
                onKeyDown={editKeys}
                maxLength={CUSTOM_HABIT_NAME_MAX}
                aria-label={t('config.editHabit', { name: h.name })}
                autoFocus
                className={HABIT_QUESTION_FIELD}
              />
              <TextField
                size="sm"
                value={editing.short}
                onChange={(e) => setEditing({ ...editing, short: e.target.value })}
                onKeyDown={editKeys}
                maxLength={CUSTOM_HABIT_SHORT_MAX}
                placeholder={t('config.shortName')}
                aria-label={t('config.shortNameLabel')}
                className="w-full"
              />
              <SettingsSegmented label={t('config.habitKind')} value={editing.kind} onChange={(k) => setEditing({ ...editing, kind: k })} options={kinds} className="flex-nowrap whitespace-nowrap" />
              <EditRow className="col-span-full" onSave={saveEdit} onCancel={() => setEditing(null)} canSave={!!cleanHabitName(editing.name)} />
            </div>
          );
        }
        return (
          <div key={h.id} className="col-span-full flex min-h-9 items-center gap-2 @2xl:contents">
            <span className="min-w-0 flex-1 truncate text-sm text-pn @2xl:ps-2.5">{h.name}</span>
            <span className="min-w-0 truncate text-xs text-pn-muted @2xl:ps-2.5">{h.short}</span>
            <span className="shrink-0 text-xs text-pn-muted @2xl:ps-2.5">{t(h.kind === 'watch' ? 'config.kindWatch' : 'config.kindBuild')}</span>
            <div className={`${HABIT_ACTIONS} flex justify-end gap-1`}>
              <IconButton label={t('config.editHabit', { name: h.name })} onClick={() => setEditing({ id: h.id, name: h.name, short: h.short ?? '', kind: h.kind })}>
                <PencilSimple size={14} aria-hidden="true" />
              </IconButton>
              <DeleteButton kind="remove" label={t('config.removeHabit', { name: h.name })} onConfirm={() => onChange(removeCustomHabit(list, h.id))} />
            </div>
          </div>
        );
      })}
    </div>
    </div>
  );
}

// ------------------------------------------------------------------
// Custom: the person's own trackers (Pro)
// ------------------------------------------------------------------

function CustomTab({ settings, onChange, isPro, onOpenUpgrade }: TrackerSettingsPaneProps) {
  const { t } = useTranslation('trackers');
  const unlocked = proUnlocked(isPro);
  // A new key after each Create clears the form for the next tracker.
  const [formKey, setFormKey] = useState(0);
  const [editingId, setEditingId] = useState<string | null>(null);
  const visibleCustom = activeCustomTrackers(settings.customTrackers);
  const canAddMore = visibleCustom.length < CUSTOM_MAX;
  const now = () => new Date().toISOString();
  const patchCustom = (id: string, patch: Partial<CustomTrackerTemplate>) => onChange({
    ...settings,
    customTrackers: settings.customTrackers.map((c) => (c.id === id ? { ...c, ...patch, updatedAt: now() } : c)),
  });
  const editing = visibleCustom.find((ct) => ct.id === editingId);

  return (
    <TrackerListTab
      setting="trackers.custom"
      newTitle={t('config.newCustomTracker')}
      newHelp={t('config.customHelp', { max: CUSTOM_MAX })}
      form={canAddMore ? (
        <AddCustomView
          key={formKey}
          // Pro, unlocked in the public demo: without it, Create opens the upgrade.
          onAdd={unlocked
            ? (tpl) => {
              onChange({ ...settings, customTrackers: [...settings.customTrackers, { ...tpl, updatedAt: now() }] });
              setFormKey((k) => k + 1);
            }
            : () => onOpenUpgrade()}
          usedColors={visibleCustom.map(customTrackerColor)}
          showPro={!isPro}
          locked={!unlocked}
        />
      ) : (
        <p className="text-[12px] text-pn-muted">{t('config.maxReached', { max: CUSTOM_MAX })}</p>
      )}
      listIcon={SlidersHorizontal}
      listTitle={t('config.yourCustomTrackers')}
      switchItems={visibleCustom.map((ct) => ({
        id: ct.id,
        name: ct.name,
        tile: (size: number) => (
          <GlyphTile color={customTrackerColor(ct)} size={size}>
            <CustomTrackerGlyph icon={ct.icon} size={Math.round(size * 0.6)} className="shrink-0" />
          </GlyphTile>
        ),
        detail: t(`custom.typeLabels.${ct.type}`),
      }))}
      onEdit={setEditingId}
      edit={editing && {
        id: editing.id,
        form: (
          <AddCustomView
            key={editing.id}
            initial={editing}
            onAdd={(tpl) => { patchCustom(editing.id, tpl); setEditingId(null); }}
            onCancel={() => setEditingId(null)}
            usedColors={[]}
            showPro={false}
            locked={false}
          />
        ),
      }}
      rows={visibleCustom.map((ct) => (
        <ListRow
          key={ct.id}
          mark={<TrackerMark icon={ct.icon} color={customTrackerColor(ct)} size={18} tile />}
          title={ct.name}
          // Muted and labeled, never struck through: a paused tracker is not gone.
          muted={!!ct.stoppedAt}
          meta={`${ct.stoppedAt ? `${t('config.paused')} · ` : ''}${t(`custom.typeLabels.${ct.type}`)}`}
          actions={(
            <>
              {ct.stoppedAt ? (
                <IconButton position="start" label={t('config.resume')} onClick={() => patchCustom(ct.id, { stoppedAt: undefined })}>
                  <Play size={14} aria-hidden="true" />
                </IconButton>
              ) : (
                <IconButton position="start" label={t('config.pause')} onClick={() => patchCustom(ct.id, { stoppedAt: now() })}>
                  <Pause size={14} aria-hidden="true" />
                </IconButton>
              )}
              {/* Editing is for a Pro account (the demo unlocks it), as creating is. */}
              <IconButton position="start" label={t('common:actions.edit')} onClick={() => (unlocked ? setEditingId(ct.id) : onOpenUpgrade())}>
                <PencilSimple size={14} aria-hidden="true" />
              </IconButton>
              {/* Tombstone, never splice: the merge would bring the row back,
                  and the journal values that name this id would lose their name. */}
              <DeleteButton position="start" label={t('common:actions.delete')} onConfirm={() => patchCustom(ct.id, { deletedAt: now() })} />
            </>
          )}
        />
      ))}
    />
  );
}

// ------------------------------------------------------------------
// Factors: the person's own list
// ------------------------------------------------------------------

function FactorsTab({ factors, onChange }: { factors: FactorDef[]; onChange: (next: FactorDef[]) => void }) {
  const { t } = useTranslation('trackers');
  const live = activeFactors(factors);
  const suggestions = starterSuggestions(live, t);
  // A factor chip carries its own rename and remove; a suggestion chip adds
  // itself, as an off chip of General does.
  const [draft, setDraft] = useState('');
  const [editing, setEditing] = useState<{ id: string; name: string } | null>(null);
  const adopt = (raw: string) => {
    const r = adoptFactor(factors, raw);
    if (r && r.list.length !== factors.length) onChange(r.list);
  };
  const saveEdit = () => {
    if (editing) onChange(renameFactor(factors, editing.id, editing.name));
    setEditing(null);
  };
  const addDraft = () => {
    const r = adoptFactors(factors, draft);
    if (r.list.length !== factors.length) onChange(r.list);
    setDraft('');
  };
  return (
    <div data-setting="trackers.factors" className="flex flex-col gap-3 pt-4">
      <div className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW}`}>
        <EyebrowGlyph icon={PuzzlePiece} />
        {t('labels.factors')}
      </div>
      <p className={SETTINGS_HELP}>{t('config.factorsHelp')}</p>
      <div className="flex flex-wrap items-center gap-1.5">
        {live.map((f) => {
          if (editing?.id === f.id) {
            return (
              <TextField
                key={f.id}
                size="sm"
                value={editing.name}
                onChange={(e) => setEditing({ id: f.id, name: e.target.value })}
                onBlur={saveEdit}
                onKeyDown={(e) => { if (isImeComposing(e)) return; if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') { e.stopPropagation(); setEditing(null); } }}
                maxLength={FACTOR_NAME_MAX}
                aria-label={t('config.renameFactor', { name: f.name })}
                autoFocus
                className="w-40"
              />
            );
          }
          return (
            <span key={f.id} className="inline-flex items-center h-8 ps-2.5 rounded-md border border-accent/30 bg-accent/10 text-xs font-medium text-accent-strong">
              <Check size={12} aria-hidden="true" className="me-1.5 shrink-0" />
              <span className="me-1">{f.name}</span>
              {/* The tools sit behind a hairline, quiet until a pointer reaches the chip. */}
              <span className="inline-flex items-center border-s border-accent/20 [@media(hover:hover)]:opacity-50 hover:opacity-100 focus-within:opacity-100 transition-opacity">
                <IconButton label={t('config.renameFactor', { name: f.name })} onClick={() => setEditing({ id: f.id, name: f.name })}>
                  <PencilSimple size={12} aria-hidden="true" />
                </IconButton>
                <DeleteButton kind="remove" label={t('factors.remove', { name: f.name })} onConfirm={() => onChange(removeFactor(factors, f.id))} />
              </span>
            </span>
          );
        })}
        {suggestions.map((name) => (
          <button key={name} type="button" aria-pressed={false} onClick={() => adopt(name)} className={`${settingsChipClass(false)} gap-1.5`}>
            <Plus size={12} aria-hidden="true" />
            {name}
          </button>
        ))}
      </div>
      {live.length === 0 && <p className={SETTINGS_HELP}>{t('factors.empty')}</p>}
      {/* The field is always open: a button that only opened it was easy to miss. */}
      <form className="flex items-start gap-2 max-w-md" onSubmit={(e) => { e.preventDefault(); if (draft.trim()) addDraft(); }}>
        <div className="min-w-0 flex-1">
          <TextField
            size="sm"
            value={draft}
            onChange={(e) => setDraft(e.target.value)}
            onKeyDown={(e) => { if (e.key === 'Enter' && isImeComposing(e)) e.preventDefault(); }}
            maxLength={FACTOR_INPUT_MAX}
            placeholder={t('factors.placeholder')}
            aria-label={t('config.addFactor')}
            hint={t('factors.commaHint')}
          />
        </div>
        <Button type="submit" action="add" disabled={!draft.trim()} />
      </form>
    </div>
  );
}

// ------------------------------------------------------------------
// Medications: the list the Meds pill asks about
// ------------------------------------------------------------------

function MedicationsTab({ medications, onChange, isPro, onOpenUpgrade }: { medications: MedicationTemplate[]; onChange: (next: MedicationTemplate[]) => void; isPro: boolean; onOpenUpgrade: () => void }) {
  const { t } = useTranslation('trackers');
  // Reminders and the supply are Pro; the demo unlocks them and still shows the rocket.
  const unlocked = proUnlocked(isPro);
  const pro = { unlocked, showPro: !isPro, onUpgrade: onOpenUpgrade };
  const live = activeMedications(medications);
  // Spec: ops/docs/mood-wellness-tracker.md section 6.7
  const [formKey, setFormKey] = useState(0);
  const [editingId, setEditingId] = useState<string | null>(null);
  const ringing = useMedicationReminders();
  const history = useTrackerHistory();
  const days = history.map((d) => ({ date: typeof d.journalDate === 'string' ? d.journalDate : '', logs: d.medications }));
  const today = toLocalIso(new Date());
  const draft: MedicationTemplate = { id: '', name: '', dosage: '', timing: 'morning', startedAt: today, dosageHistory: [] };
  const add = (edit: MedicationEdit) => {
    if (!edit.name.trim()) return;
    const created = addMedication(medications, edit.name, edit.dosage);
    const id = created[created.length - 1]!.id;
    onChange(saveMedication(created, id, edit.name, edit.dosage, edit.plan, edit.refill, true));
    setMedicationReminder(id, edit.remind && !edit.plan.asNeeded);
    setFormKey((k) => k + 1);
  };
  const save = (id: string, edit: MedicationEdit) => {
    onChange(saveMedication(medications, id, edit.name, edit.dosage, edit.plan, edit.refill));
    setMedicationReminder(id, edit.remind && !edit.plan.asNeeded);
    setEditingId(null);
  };
  const editing = live.find((m) => m.id === editingId);

  return (
    <TrackerListTab
      setting="trackers.medications"
      newTitle={t('config.newMedication')}
      newHelp={live.length > 0 ? t('config.newMedicationHelp') : t('config.medicationsHelp')}
      form={<MedicationEditor key={formKey} initial={draft} remind={false} supply={null} {...pro} onSave={add} />}
      listIcon={Pill}
      listTitle={t('config.medicationsTitle')}
      listHelp={t('config.medicationsHelp')}
      switchItems={live.map((m) => ({
        id: m.id,
        name: m.name,
        tile: (size: number) => (
          <GlyphTile color={m.color} size={size}>
            <MedicationGlyph form={m.form} size={Math.round(size * 0.6)} className="shrink-0" />
          </GlyphTile>
        ),
        detail: m.dosage,
      }))}
      onEdit={setEditingId}
      edit={editing && {
        id: editing.id,
        form: (
          <MedicationEditor
            key={editing.id}
            initial={editing}
            remind={ringing.includes(editing.id)}
            supply={supplyLeft(editing, days)}
            runsOut={runsOutOn(editing, supplyLeft(editing, days), today)}
            {...pro}
            onSave={(e) => save(editing.id, e)}
            onCancel={() => setEditingId(null)}
          />
        ),
      }}
      rows={live.map((m) => {
        const left = supplyLeft(m, days);
        const ended = !!m.endsOn && m.endsOn < today;
        const meta = describeMedication(m, t);
        // Not yet started, or already ended: said first, the row muted.
        const state = ended ? t('medication.ended') : m.startedAt > today ? t('medication.starts', { date: formatDay(m.startedAt, 'date') }) : '';
        return (
          <ListRow
            key={m.id}
            // The form's glyph in the medication's color, where a tracker has its icon.
            mark={(
              <MarkTile color={m.color}>
                <MedicationGlyph form={m.form} size={18} style={m.color ? { color: m.color } : undefined} className={m.color ? 'shrink-0' : 'shrink-0 text-pn-muted'} />
              </MarkTile>
            )}
            title={m.name}
            aside={m.dosage}
            muted={!!state}
            meta={(
              <>
                {unlocked && ringing.includes(m.id) && !m.asNeeded && <BellSimple size={11} className="shrink-0" aria-label={t('medication.remind')} />}
                <span className="truncate">{state ? `${state} · ${meta}` : meta}</span>
              </>
            )}
            actions={(
              <>
                {unlocked && left !== null && <Badge>{t('medication.leftShort', { count: left })}</Badge>}
                <IconButton position="start" label={t('medication.editMedication')} onClick={() => setEditingId(m.id)}>
                  <PencilSimple size={14} aria-hidden="true" />
                </IconButton>
                <DeleteButton position="start" kind="remove" label={t('medication.removeMedication')} onConfirm={() => { onChange(removeMedication(medications, m.id)); setMedicationReminder(m.id, false); }} />
              </>
            )}
          />
        );
      })}
    />
  );
}

// ------------------------------------------------------------------
// The shared shape of Custom and Medication: the new item's form, always
// open, then the list. A row's pencil swaps the whole tab for that item's
// edit page, headed as a tracker's statistics are: the back caret and the
// item switcher. Back, Cancel and Save all return to the list.
// ------------------------------------------------------------------

function TrackerListTab({ setting, newTitle, newHelp, form, listIcon, listTitle, listHelp, rows, switchItems, onEdit, edit }: {
  setting: string;
  newTitle: string;
  newHelp: string;
  form: ReactNode;
  listIcon: Icon;
  listTitle: string;
  listHelp?: string;
  rows: ReactNode[];
  /** The siblings an edit page switches between. */
  switchItems: SwitcherItem[];
  onEdit: (id: string | null) => void;
  edit?: { id: string; form: ReactNode } | false;
}) {
  // The scroll of the statistics' views: an edit page opens at its top, and
  // Back lands where the list was left.
  const top = useRef<HTMLDivElement>(null);
  const opened = useRef(false);
  const listScroll = useRef<number | null>(null);
  const scroller = () => top.current?.closest('.overflow-y-auto') ?? null;
  const viewKey = edit ? `edit:${edit.id}` : 'list';
  useLayoutEffect(() => {
    // Not on the first open: the settings search scrolls to its own marker then.
    if (opened.current) {
      const box = scroller();
      if (!edit && listScroll.current !== null && box) box.scrollTop = listScroll.current;
      else top.current?.scrollIntoView({ block: 'start' });
    }
    opened.current = true;
    // eslint-disable-next-line react-hooks/exhaustive-deps -- the view key names every view
  }, [viewKey]);

  if (edit) {
    return (
      <div data-setting={setting} className="flex flex-col gap-6 pt-4">
        <SubViewHeader backLabel={listTitle} onBack={() => onEdit(null)} anchorRef={top}>
          <ItemSwitcher items={switchItems} currentId={edit.id} label={listTitle} onPick={onEdit} />
        </SubViewHeader>
        <div className="flex flex-col">{edit.form}</div>
      </div>
    );
  }
  return (
    <div ref={top} data-setting={setting} className="flex flex-col pt-4">
      {/* The form leads, so it is in view without a scroll past the list. */}
      <SectionEyebrow icon={Plus} className="mb-1">{newTitle}</SectionEyebrow>
      <p className={`${SETTINGS_HELP} mb-4`}>{newHelp}</p>
      <div className={`flex flex-col ${rows.length > 0 ? 'mb-8' : ''}`}>{form}</div>
      {rows.length > 0 && (
        <>
          <SectionEyebrow icon={listIcon} className="mb-1">{listTitle}</SectionEyebrow>
          {listHelp && <p className={`${SETTINGS_HELP} mb-3`}>{listHelp}</p>}
          {/* Any tap in the list keeps its scroll, so the pencil's Back finds it. */}
          <div className="flex flex-col gap-1.5" onClickCapture={() => { listScroll.current = scroller()?.scrollTop ?? null; }}>{rows}</div>
        </>
      )}
    </div>
  );
}

function ListRow({ mark, title, aside, meta, muted, actions }: {
  mark: ReactNode;
  title: string;
  /** Beside the name, quieter: a medication's strength. */
  aside?: string;
  meta: ReactNode;
  /** Paused, not yet started, or ended: still listed, never struck through. */
  muted: boolean;
  actions: ReactNode;
}) {
  return (
    <div className="flex items-center gap-2 rounded-md border border-divider bg-surface-2 ps-3 pe-1.5 py-1.5">
      {mark}
      <div className={`min-w-0 flex-1 ${muted ? 'opacity-60' : ''}`}>
        <span className="flex items-center gap-1.5 min-w-0">
          <span className="truncate text-sm font-medium text-pn">{title}</span>
          {aside && <span className="shrink-0 text-[11px] text-pn-muted">{aside}</span>}
        </span>
        <span className="flex items-center gap-1.5 min-w-0 text-[11px] text-pn-muted">{meta}</span>
      </div>
      {actions}
    </div>
  );
}

// ------------------------------------------------------------------
// General, first: the check-in card in Journals and All, and its reminder
// ------------------------------------------------------------------

function CheckInSection() {
  const { t } = useTranslation('settings');
  const reminder = useCheckInReminder();
  return (
    <>
    <div className="divide-y divide-divider pt-1">
      {/* The daily reminder: this device only, one time per day, off by
          default, free. A phone asks its permission from the switch, the
          moment the reason is plain. Spec: ops/issues/0439.md (Reminder plan) */}
      {/* One item of the divided list: the switch and, while it is on, its
          time, so no hairline cuts the reminder from its own time. */}
      <div>
        <Switch
          setting="calendar.checkInReminder"
          icon={<BellSimple size={14} className="text-accent" />}
          labelClassName={ROW_TITLE}
          label={t('calendar.checkInReminder')}
          description={t('calendar.checkInReminderHelp')}
          checked={reminder !== null}
          onChange={(on) => {
            setCheckInReminder(on ? DEFAULT_CHECK_IN_TIME : null);
            if (on) askForRemindersOnce();
          }}
          className="py-3"
        />
        {reminder !== null && (
          <div className={`${SETTINGS_ROW} pt-0`}>
            <div className="min-w-0">
              <RowTitle icon={Clock}>{t('calendar.checkInReminderAt')}</RowTitle>
              {/* Where it rings: a browser only while the app is open. */}
              <p className={`${SETTINGS_HELP} mt-0.5`}>{t(`calendar.reminderHint.${REMINDER_PLATFORM}`)}</p>
            </div>
            <TimeInput value={reminder} label={t('calendar.checkInReminderAt')} onCommit={setCheckInReminder} />
          </div>
        )}
      </div>
    </div>
    </>
  );
}

/**
 * One switch of the pane, a toggle chip in the look of the emotion and factor
 * chips: a check and a soft tint when on, one text weight either way, and
 * chips wrap without orphan rows. A tracker's chip carries a dot in its chart
 * color, so the pane doubles as the legend of the charts.
 */
function ToggleChip({ on, label, color, onToggle }: { on: boolean; label: string; color?: string; onToggle: () => void }) {
  return (
    <button type="button" aria-pressed={on} onClick={onToggle} className={`${settingsChipClass(on)} gap-1.5`}>
      {on && <Check size={12} aria-hidden="true" />}
      {color && <span aria-hidden="true" className="w-2 h-2 shrink-0 rounded-full" style={{ backgroundColor: color }} />}
      {label}
    </button>
  );
}

// ------------------------------------------------------------------
// The new custom tracker form, in place of the Trackers tab's list
// ------------------------------------------------------------------

/** A custom tracker's mark in its own color: its icon, or the Trackers
 *  heartbeat while it has none. `tile` sets it in the tinted square of the
 *  icon picker's header, for the setup rows. */
function TrackerMark({ icon, color, size = 12, tile = false }: { icon?: string; color?: string; size?: number; tile?: boolean }) {
  const glyph = <CustomTrackerGlyph icon={icon} size={size} className="shrink-0" style={{ color }} />;
  if (!tile) return glyph;
  return <MarkTile color={color}>{glyph}</MarkTile>;
}


/** The note menu's icon picker on a tracker that is being made or edited.
 *  A pick lives in the form until Create or Save; Cancel puts back the icon
 *  the picker found. The recent row reads the person's other looks. */
function TrackerIconPicker({ name, icon, onPick, onClose }: { name: string; icon?: string; onPick: (icon: string | undefined) => void; onClose: () => void }) {
  const [before] = useState(icon);
  const lookKey = 'tracker:draft';
  const styles = useMemo(() => setItemLook(loadLocalSettings().itemStyles, lookKey, { icon: icon ?? null }), [icon]);
  return (
    <LookPicker
      target={{ kind: 'tracker', lookKey, name }}
      styles={styles}
      noteColors="off"
      onNoteColors={() => {}}
      onPick={(patch) => onPick(patch.icon ?? undefined)}
      onCancel={() => onPick(before)}
      onClose={onClose}
    />
  );
}

/** The preview's input, holding its own value so a try never saves. */
function PreviewInput({ name, type }: { name: string; type: CustomTrackerType }) {
  const [value, setValue] = useState<number | boolean | undefined>(undefined);
  return <CustomTrackerInput name={name} type={type} value={value} onChange={setValue} expanded />;
}

function AddCustomView({
  initial,
  onAdd,
  onCancel,
  usedColors,
  showPro,
  locked,
}: {
  /** The tracker to edit. Its type stays: the days already hold values of it. */
  initial?: CustomTrackerTemplate;
  onAdd: (t: CustomTrackerTemplate) => void;
  /** Closes the edit form. */
  onCancel?: () => void;
  usedColors: TrackerColor[];
  showPro: boolean;
  /** Free and outside the demo: Create opens the upgrade, name or not. */
  locked: boolean;
}) {
  const { t } = useTranslation('trackers');
  const [name, setName] = useState(initial?.name ?? '');
  const [type, setType] = useState<CustomTrackerType>(initial?.type ?? 'scale10');
  const [startFromLast, setStartFromLast] = useState(initial?.startFromLast !== false);
  const [icon, setIcon] = useState<string | undefined>(initial?.icon);
  // The note menu's icon picker, open over the form while choosing.
  const [picking, setPicking] = useState(false);
  // Only the two steppers have a starting number; tiles and yes or no do not.
  const hasStart = type === 'number' || type === 'slider100';
  // The first palette color no live tracker has, past gray, so a new
  // tracker stands apart on the charts.
  const [color, setColor] = useState<TrackerColor>(
    () => initial?.color ?? TRACKER_COLORS.slice(1).find((c) => !usedColors.includes(c)) ?? TRACKER_COLORS[1]!
  );

  const handleSubmit = () => {
    // A free person's tap goes to the upgrade, with or without a name.
    if (!name.trim() && !locked) return;
    if (initial) {
      // Every field the form owns is set, undefined included: the row merges
      // this into the stored tracker, so a cleared icon or a switch turned
      // back on must overwrite the old value, not leave it.
      onAdd({ ...initial, name: name.trim(), color, icon, startFromLast: hasStart && !startFromLast ? false : undefined });
      return;
    }
    onAdd({
      id: crypto.randomUUID(),
      name: name.trim(),
      type,
      color,
      createdAt: toLocalIso(new Date()),
      ...(icon ? { icon } : {}),
      ...(hasStart && !startFromLast ? { startFromLast: false } : {}),
    });
  };

  return (
    <>
      {/* Four pixels of room on every side, cancelled by the negative margin:
          a scroll area clips at its edge, and the selected swatch draws its
          ring that far outside itself. */}
      <div className="flex-1 min-h-0 overflow-y-auto flex flex-col gap-4 -mx-1 px-1 pb-1">
        {/* The count sits inside the field, at its end, so it reads as part of it. */}
        <div className="flex flex-col gap-1.5">
        <RowTitle icon={TextT}>{t('config.nameLabel')}</RowTitle>
        <div className="relative">
          <input
            type="text"
            placeholder={t('config.trackerNamePlaceholder')}
            aria-label={t('config.trackerNamePlaceholder')}
            value={name}
            onChange={(e) => setName(e.target.value)}
            className="w-full h-9 ps-3 pe-14 rounded-md text-[13px] border border-divider bg-surface-0 text-pn outline-none focus:border-accent"
            maxLength={24}
            onKeyDown={(e) => { if (e.key === 'Enter' && !isImeComposing(e)) handleSubmit(); }}
          />
          <span className={`pointer-events-none absolute inset-y-0 end-3 flex items-center text-[11px] tabular-nums ${name.length >= 24 ? 'text-danger' : 'text-pn-muted'}`}>
            {t('config.nameCount', { count: name.length, max: 24 })}
          </span>
        </div>
        </div>

        {/* The panel the new tracker opens, live: the type's real input under
            the typed name, with the color as a dot. Changing the type starts
            the preview over. */}
        <div className="flex flex-col gap-1.5">
          <RowTitle icon={Eye}>{t('config.preview')}</RowTitle>
          <div className="rounded-md border border-divider bg-surface-0/60 p-3">
            <p className="flex items-center gap-2 text-[13px] font-semibold text-pn mb-2 min-w-0">
              <TrackerMark icon={icon} color={color} />
              <span className={`truncate ${name.trim() ? '' : 'text-pn-muted font-normal'}`}>{name.trim() || t('config.trackerNamePlaceholder')}</span>
            </p>
            <PreviewInput key={type} name={name.trim() || t('config.trackerNamePlaceholder')} type={type} />
          </div>
        </div>

        {/* Icon and type share a row, each a labeled control of one line; a
            type picked from a list of five is a select, as the UI rules ask
            for a list too long for a segmented control. Editing keeps the
            type, so the row then holds the icon alone. */}
        <div className="flex flex-wrap items-end gap-x-4 gap-y-4">
          <div className="flex flex-col gap-1.5">
            <RowTitle icon={Shapes}>{t('config.iconLabel')}</RowTitle>
            <Button icon={<TrackerMark icon={icon} color={color} size={15} />} onClick={() => setPicking(true)}>
              {t('config.chooseIcon')}
            </Button>
            {picking && (
              <Suspense fallback={null}>
                <TrackerIconPicker name={name.trim() || t('config.trackerNamePlaceholder')} icon={icon} onPick={setIcon} onClose={() => setPicking(false)} />
              </Suspense>
            )}
          </div>
          {!initial && (
            <div className="flex min-w-[16rem] flex-1 flex-col gap-1.5">
              <RowTitle icon={SlidersHorizontal}>{t('config.typeLabel')}</RowTitle>
              {/* The chips of the Factors and Habits lists, one per type, each
                  with a glyph of its input; they wrap where the row is short. */}
              <div role="group" aria-label={t('config.typeLabel')} className="flex flex-wrap gap-1.5">
                {(Object.keys(CUSTOM_TRACKER_TYPE_LABELS) as CustomTrackerType[]).map((k) => {
                  const Glyph = TYPE_GLYPHS[k];
                  return (
                    <button key={k} type="button" aria-pressed={type === k} onClick={() => setType(k)} className={`${settingsChipClass(type === k)} gap-1.5 whitespace-nowrap`}>
                      <Glyph size={12} aria-hidden="true" className="shrink-0" />
                      {t(`custom.typeLabels.${k}`)}
                    </button>
                  );
                })}
              </div>
            </div>
          )}
        </div>

        {hasStart && (
          <Switch
            icon={<ClockCounterClockwise size={14} className="text-accent" />}
            labelClassName={ROW_TITLE}
            label={t('config.startFromLast')}
            description={t('config.startFromLastHelp')}
            checked={startFromLast}
            onChange={setStartFromLast}
          />
        )}

        <div className="flex flex-wrap items-end gap-x-4 gap-y-4">
          <div className="flex flex-col gap-1.5">
            <RowTitle icon={Palette}>{t('config.colorLabel')}</RowTitle>
            {/* The round swatch of the note menu's color row, with its tooltip. */}
            <div className="flex flex-wrap items-center gap-1.5 min-h-9">
              {TEXT_COLORS.map(({ name: colorName, value: c }, i) => (
                <ColorSwatch
                  key={c}
                  label={t(`editor:color.names.${colorName.toLowerCase()}`)}
                  background={c}
                  selected={color === c}
                  labelPosition={i === 0 ? 'above-start' : 'above'}
                  onClick={() => setColor(c)}
                />
              ))}
            </div>
          </div>
          {!initial && (
            <button
              type="button"
              onClick={handleSubmit}
              disabled={!name.trim() && !locked}
              className={`${SETTINGS_BTN_PRIMARY} ms-auto`}
            >
              {t('common:actions.create')}
              {showPro && <IconUpgrade size={14} />}
            </button>
          )}
        </div>
        {initial && onCancel && <EditRow onSave={handleSubmit} onCancel={onCancel} canSave={!!name.trim()} />}

      </div>

    </>
  );
}

