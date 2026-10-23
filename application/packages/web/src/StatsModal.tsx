import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { Heartbeat, PencilSimple, SquaresFour } from './icons';
import type { LocalNote } from './db';
import { computeStats } from './stats';
import { NO_FACTORS, type FactorDef, type MedicationTemplate, type TrackerSettings } from './trackerTypes';
import { StatsPage, type StatsView } from './stats/StatsPage';
import { OverviewTab } from './stats/OverviewTab';
import { WritingTab } from './stats/WritingTab';
import { SettingsTabStrip, settingsTabClass } from './settingsUI';
import { Modal } from './ui';
import { usePaneTab } from './settingsPaneTab';

type Props = {
  notes: LocalNote[];
  /** The view's lock predicate: the wellness readers leave out a journal
   *  whose gate is closed, and count it again once the gate opens. */
  isNoteLocked: (n: LocalNote) => boolean;
  medications: MedicationTemplate[];
  isPro: boolean;
  onOpenUpgrade?: () => void;
  onClose: () => void;
  /** Current week's reflection text (from Monday journal entry). */
  weekReflection?: string;
  /** Save reflection to the Monday journal entry. */
  onWeekReflectionChange?: (text: string) => void;
  /** Render inline as a settings pane (no overlay, no own header/footer/escape). */
  embedded?: boolean;
  /** Which page to open on. Defaults to the one page. */
  initialTab?: Tab;
  trackerSettings: TrackerSettings;
  /** The person's own factor names, for the Factors charts and the export. */
  factors?: FactorDef[];
  /** Opens the journal entry of a day picked on a chart; absent in the modal path. */
  onOpenDay?: (date: string) => void;
  /** Opens Settings > Import & Export on its Wellness tab. */
  onOpenWellnessExport?: () => void;
  /** Items created in the app, the honest count behind the notes milestones. */
  notesCreated: number;
  /** When the account was first seen; null on an account older than the stamp. */
  firstSeenAt: string | null;
};

/** Where Statistics opens: the one page, or one of the pages a row opens. */
/** Where Statistics opens: a tab, or a page of the Trackers tab. */
export type Tab = 'overview' | 'wellness' | 'writing' | 'medication' | 'mood';

/**
 * The Statistics pane: one page of days logged, what stands out, every
 * tracker and the writing numbers; a row opens its own page.
 * Spec: ops/docs/archive/wellness-statistics.md (section 22)
 */
export function StatsModal({ notes, isNoteLocked, onClose, medications, isPro, onOpenUpgrade, weekReflection, onWeekReflectionChange, embedded = false, initialTab = 'overview', notesCreated, firstSeenAt, trackerSettings, factors = NO_FACTORS, onOpenDay, onOpenWellnessExport }: Props) {
  const { t } = useTranslation('stats');
  const stats = useMemo(() => computeStats(notes), [notes]);

  const [tab, setTab] = usePaneTab<'overview' | 'wellness' | 'writing'>(
    'stats',
    initialTab === 'writing' ? 'writing' : initialTab === 'wellness' || initialTab === 'medication' || initialTab === 'mood' ? 'wellness' : 'overview',
  );
  const initialView: StatsView = initialTab === 'medication' ? { kind: 'medication' }
    : initialTab === 'mood' ? { kind: 'tracker', id: 'mood' }
    : { kind: 'home' };
  // Literal markers: the settings search test reads them from the source.
  const tabs = [
    { id: 'overview', icon: SquaresFour, label: t('tabs.overview'), setting: undefined },
    { id: 'wellness', icon: Heartbeat, label: t('tabs.wellness'), setting: undefined },
    { id: 'writing', icon: PencilSimple, label: t('tabs.writing'), setting: 'stats.writing' },
  ] as const;

  return (
    <Modal
      embedded={embedded}
      embeddedClassName="flex-1 min-h-0 overflow-hidden flex flex-col text-pn"
      onClose={onClose}
      title={t('title')}
      header="bar"
      className="max-w-2xl max-h-[90vh] overflow-hidden flex flex-col"
    >
      <SettingsTabStrip className="shrink-0 px-4 sm:px-6 pt-2">
        {tabs.map(({ id, icon: Icon, label, setting }) => (
          <button key={id} type="button" data-setting={setting} aria-pressed={tab === id} className={settingsTabClass(tab === id)} onClick={() => setTab(id)}>
            <Icon aria-hidden="true" />
            <span>{label}</span>
          </button>
        ))}
      </SettingsTabStrip>
      {/* Keyed on the tab, so a tab opens at its top. */}
      <div key={tab} className="flex-1 overflow-y-auto p-4 sm:p-6 space-y-6 [scrollbar-width:none] [&::-webkit-scrollbar]:hidden">
        {tab === 'overview' && (
          <OverviewTab
            notes={notes}
            stats={stats}
            isNoteLocked={isNoteLocked}
            trackerSettings={trackerSettings}
            factors={factors}
            medications={medications}
            notesCreated={notesCreated}
            firstSeenAt={firstSeenAt}
            onOpenTrackers={() => setTab('wellness')}
          />
        )}
        {tab === 'wellness' && (
          <StatsPage
            notes={notes}
            isNoteLocked={isNoteLocked}
            trackerSettings={trackerSettings}
            factors={factors}
            medications={medications}
            isPro={isPro}
            onOpenUpgrade={onOpenUpgrade}
            weekReflection={weekReflection}
            onWeekReflectionChange={onWeekReflectionChange}
            onOpenDay={onOpenDay}
            onOpenExport={onOpenWellnessExport}
            initialView={initialView}
          />
        )}
        {tab === 'writing' && <WritingTab notes={notes} stats={stats} isNoteLocked={isNoteLocked} notesCreated={notesCreated} firstSeenAt={firstSeenAt} />}
      </div>
    </Modal>
  );
}
