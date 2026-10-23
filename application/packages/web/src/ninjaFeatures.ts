import type { SettingEntry } from './settingsSearch/registry';
import type { TrackerSetupTab } from './TrackerConfig';
import { ArrowsClockwise, ChartBar, GridFour, Heartbeat, LockSimple, Megaphone, PaintBrush, Palette, Password, Pill, Plus, Question, Repeat, Trash, Globe, type Icon } from './icons';

/**
 * Ninja's doors to the features that sit deep in Settings or in a dialog:
 * the Features group of ">" (each row with a line that says what it does),
 * the commands with no key, and two Create rows of "+". One list of data;
 * NotesView gives each action its run and says when it is offered.
 *
 * A door into Settings names a settings search entry, never a section and a
 * tab of its own: the entry holds both, and `tests/settingsSearch.test.ts`
 * proves each entry has its row in a pane. `tests/ninjaFeatures.test.ts`
 * proves each entry named here exists, so a moved setting fails a test, not
 * Ninja.
 *
 * Spec: ops/docs/plans/ninja-features.md
 */

export type NinjaAction = 'passwordGenerator' | 'lock' | 'syncNow' | 'syncPause' | 'emptyTrash';
type NinjaPage = '/' | '/changelog' | '/help' | '/themes';

export type NinjaDoor = {
  /** Stable: the recent list keeps it. */
  id: string;
  group: 'features' | 'commands' | 'new';
  /** Catalog keys, with their namespace. */
  label: string;
  detail?: string;
  icon: Icon;
  pro?: true;
  /** Also a Create row of "+". */
  inCreate?: true;
  to:
    | { kind: 'settings'; entry: SettingEntry['id'] }
    // Settings > Trackers at a tab, in the full window (`openTrackerSettings`).
    | { kind: 'tracker'; tab: TrackerSetupTab; entry: SettingEntry['id'] }
    | { kind: 'page'; path: NinjaPage }
    | { kind: 'action'; id: NinjaAction };
};

export const NINJA_DOORS: readonly NinjaDoor[] = [
  { id: 'feature:stats', group: 'features', label: 'common:ninja.features.stats.label', detail: 'common:ninja.features.stats.detail', icon: ChartBar, to: { kind: 'settings', entry: 'section.stats' } },
  { id: 'feature:trackers', group: 'features', label: 'common:ninja.features.trackers.label', detail: 'common:ninja.features.trackers.detail', icon: Heartbeat, to: { kind: 'tracker', tab: 'trackers', entry: 'trackers.setup' } },
  { id: 'feature:medication', group: 'features', label: 'common:ninja.features.medication.label', detail: 'common:ninja.features.medication.detail', icon: Pill, to: { kind: 'tracker', tab: 'medications', entry: 'trackers.medications' } },
  { id: 'feature:yearInPixels', group: 'features', label: 'common:ninja.features.yearInPixels.label', detail: 'common:ninja.features.yearInPixels.detail', icon: GridFour, to: { kind: 'settings', entry: 'stats.yearInPixels' } },
  { id: 'feature:importExport', group: 'features', label: 'common:ninja.features.importExport.label', detail: 'common:ninja.features.importExport.detail', icon: Repeat, to: { kind: 'settings', entry: 'section.import' } },
  { id: 'feature:generator', group: 'features', label: 'common:ninja.features.generator.label', detail: 'common:ninja.features.generator.detail', icon: Password, to: { kind: 'action', id: 'passwordGenerator' } },
  { id: 'feature:themes', group: 'features', label: 'common:ninja.features.themes.label', detail: 'common:ninja.features.themes.detail', icon: Palette, to: { kind: 'settings', entry: 'appearance.theme' } },

  { id: 'new:medication', group: 'new', label: 'common:ninja.new.medication', icon: Pill, inCreate: true, to: { kind: 'tracker', tab: 'medications', entry: 'trackers.medications' } },
  { id: 'new:customTracker', group: 'new', label: 'common:ninja.new.customTracker', icon: Plus, pro: true, inCreate: true, to: { kind: 'tracker', tab: 'custom', entry: 'trackers.custom' } },

  { id: 'cmd:lock', group: 'commands', label: 'notes:footer.lockApp', icon: LockSimple, to: { kind: 'action', id: 'lock' } },
  { id: 'cmd:syncNow', group: 'commands', label: 'settings:syncPanel.syncNow', icon: ArrowsClockwise, to: { kind: 'action', id: 'syncNow' } },
  // Its label and icon follow the switch: Pause sync or Resume sync.
  { id: 'cmd:syncPause', group: 'commands', label: 'settings:syncPanel.pauseSync', icon: ArrowsClockwise, to: { kind: 'action', id: 'syncPause' } },
  { id: 'cmd:emptyTrash', group: 'commands', label: 'common:emptyTrash.title', icon: Trash, to: { kind: 'action', id: 'emptyTrash' } },
  { id: 'page:changelog', group: 'commands', label: 'common:ninja.commands.changelog', icon: Megaphone, to: { kind: 'page', path: '/changelog' } },
  { id: 'page:help', group: 'commands', label: 'common:ninja.commands.help', icon: Question, to: { kind: 'page', path: '/help' } },
  { id: 'page:themes', group: 'commands', label: 'common:ninja.commands.themesPage', icon: PaintBrush, to: { kind: 'page', path: '/themes' } },
  { id: 'page:home', group: 'commands', label: 'common:ninja.commands.website', icon: Globe, to: { kind: 'page', path: '/' } },
];

/** The settings sections a Features row already opens: ">" lists them once. */
export const SECTIONS_IN_FEATURES: ReadonlySet<string> = new Set(
  NINJA_DOORS.flatMap((d) => (d.group === 'features' && d.to.kind === 'settings' && d.to.entry.startsWith('section.') ? [d.to.entry] : [])),
);

const RECENT_KEY = 'privacynotes.ninja.recentCommands';
/** How many commands ">" keeps as recent. */
const RECENT_COMMANDS_MAX = 5;

/** The ids of the commands run last in ">", newest first; empty when storage is closed. */
export function readRecentCommands(): string[] {
  try {
    const raw: unknown = JSON.parse(localStorage.getItem(RECENT_KEY) ?? '[]');
    return Array.isArray(raw) ? raw.filter((x): x is string => typeof x === 'string').slice(0, RECENT_COMMANDS_MAX) : [];
  } catch {
    return [];
  }
}

/** Put a command first in the recent list. */
export function noteRecentCommand(id: string): void {
  try {
    const next = [id, ...readRecentCommands().filter((x) => x !== id)].slice(0, RECENT_COMMANDS_MAX);
    localStorage.setItem(RECENT_KEY, JSON.stringify(next));
  } catch {
    // A private window or blocked storage: the list stays as it was.
  }
}
