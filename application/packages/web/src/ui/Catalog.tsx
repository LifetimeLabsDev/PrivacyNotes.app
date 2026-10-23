import { UploadProgressModal, type FileUploadEntry } from '../UploadProgressModal';
import { ExportProgressModal } from '../ExportProgressModal';
import { createContext, useContext, useEffect, useRef, useState, type ReactNode } from 'react';
import { textMatcher } from '../textMatch';
import { TrackerPills } from '../TrackerPills';
import { TimeInput } from '../TimeInput';
import { defaultTrackerSettings, type JournalTrackerData, type FactorDef, type MedicationTemplate } from '../trackerTypes';
import { MonthGrid } from '../MonthGrid';
import catalogIndex from './catalogIndex.json';
import { AppWindow, ArrowSquareOut, Article, Bell, BookmarkSimple, ChatText, CheckCircle, Clock, Copy, Folder, Gear, Globe, HardDrives, Info, Moon, PencilSimple, Plus, PushPin, Scissors, SlidersHorizontal, Sparkle, Stethoscope, Sun, Trash, User, Warning } from '../icons';
import {
  Button,
  FeedbackButton,
  VaultFormActions,
  VaultFieldAction,
  CHIP_ADD,
  ChoiceGrid,
  DeleteButton,
  EYEBROW_ICON_ROW,
  EyebrowGlyph,
  HoverLabel,
  IconUpgrade,
  Modal,
  ModalFooter,
  Badge,
  Banner,
  Callout,
  Checkbox,
  TaskCheckbox,
  CopyButton,
  Divider,
  EmptyState,
  IconTile,
  Kbd,
  Popover,
  ProgressBar,
  Snackbar,
  Spinner,
  StatusLine,
  BackRow,
  ColorSwatch,
  ContextMenu,
  DETAIL_COLUMN,
  DetailAction,
  DetailCopyAction,
  DetailGroup,
  DetailHero,
  DetailLink,
  DetailNotes,
  DetailRow,
  DetailTile,
  InlineRenameField,
  ListSearchInput,
  StorageBar,
  UpdateToast,
  useContextMenu,
  FieldLabel,
  GroupHeading,
  FIELD_CLASS,
  FIELD_BUTTON,
  NumberStepper,
  PanelQuestion,
  PanelSegmented,
  ROW_TITLE,
  SETTINGS_BTN,
  SETTINGS_BTN_DANGER,
  SETTINGS_BTN_PRIMARY,
  SETTINGS_BTN_UPGRADE,
  SETTINGS_EYEBROW,
  SETTINGS_SELECT,
  ScaleTiles,
  chipClass,
  EditRow,
  HelpChip,
  IconButton,
  MoodScale,
  ProMark,
  ResetDefaultsButton,
  RowTitle,
  SETTINGS_HELP,
  SETTINGS_ROW,
  SETTINGS_TRACK,
  SectionEyebrow,
  Select,
  SettingsCallout,
  SettingsSegmented,
  SettingsTabStrip,
  StatTile,
  Switch,
  TextField,
  settingsSegClass,
  settingsTabClass,
  useProGate,
} from './index';

const patternGroups = {
  'Actions': ['Button', 'IconButton', 'DeleteButton', 'EditRow', 'Vault form actions', 'Vault field actions', 'Generation actions', 'Bookmark actions', 'useProGate', 'Class strings'],
  'Fields and settings': ['TextField and Select', 'FieldLabel, GroupHeading, FIELD_CLASS', 'Segmented', 'Setting row, Switch, heading', 'Tabs', 'ListSearchInput, InlineRenameField', 'ColorSwatch', 'Checkbox', 'TaskCheckbox', 'SettingsCallout, ResetDefaultsButton, HelpChip'],
  'Content and trackers': ['StatTile', 'MoodScale', 'ScaleTiles', 'Tracker panel parts', 'MonthGrid, StorageBar', 'Detail pane kit', 'Badge, IconTile, Kbd'],
  'Product flows': ['Guided tracker flow', 'Time input', 'Import workflow', 'Export progress', 'Upload progress', 'Flow reference map'],
  'Window contract': ['Window anatomy and behavior', 'Window sizing lab'],
  'App map': ['Replay recipes', 'Settings paths', 'Window implementation inventory'],
  'Public site': ['Marketing and documentation map'],
  'Feedback and overlays': ['Modal, ModalFooter', 'ContextMenu', 'UpdateToast', 'Callout, Banner', 'Spinner, ProgressBar, StatusLine', 'EmptyState', 'Popover, Divider, CopyButton, Snackbar'],
};
const CatalogFilter = createContext({ search: '', group: 'All patterns' });

/**
 * Reference examples of shared UI parts in the app's own CSS.
 * Opened at `?demo=1#ui-catalog` (demo and dev builds only, see main.tsx).
 * The layout harness and a reviewing session look at the same page.
 * Spec: ops/docs/archive/design-system.md
 */
export default function Catalog() {
  const [trackerData, setTrackerData] = useState<JournalTrackerData>({});
  const [trackerConfig, setTrackerConfig] = useState(defaultTrackerSettings);
  const [fixtureFactors] = useState<FactorDef[]>([]);
  const fixtureMeds: MedicationTemplate[] = [];
  const [trackerDone, setTrackerDone] = useState(false);
  const [trackerMode, setTrackerMode] = useState<'entry' | 'card'>('card');
  const [trackerReadOnly, setTrackerReadOnly] = useState(false);
  const [trackerReset, setTrackerReset] = useState(0);
  const [fixtureTime, setFixtureTime] = useState<string | undefined>('15:00');
  const [patternSearch, setPatternSearch] = useState('');
  const [patternGroup, setPatternGroup] = useState('All patterns');
  const [dark, setDark] = useState(() => document.documentElement.classList.contains('dark'));
  const [seg, setSeg] = useState<'a' | 'b' | 'c'>('a');
  const [row, setRow] = useState('a');
  const [on, setOn] = useState(true);
  const [fieldExample, setFieldExample] = useState('');
  const [tab, setTab] = useState(0);
  const [scale, setScale] = useState<number | null>(6);
  const [choice, setChoice] = useState<'poor' | 'ok' | 'good' | null>('ok');
  const [taken, setTaken] = useState<'taken' | 'skipped' | null>('taken');
  const [water, setWater] = useState<number | null>(6);
  const [chips, setChips] = useState<string[]>(['Work']);
  const menu = useContextMenu();
  const popAnchor = useRef<HTMLSpanElement | null>(null);
  const [pop, setPop] = useState(false);
  const [snack, setSnack] = useState(false);
  const [ticked, setTicked] = useState(true);
  const [query, setQuery] = useState('');
  const [swatch, setSwatch] = useState<string | null>('blue');
  const [renaming, setRenaming] = useState(false);
  const [fileName, setFileName] = useState('Quarterly report.pdf');
  const [day, setDay] = useState<string | undefined>(undefined);
  const [toast, setToast] = useState(false);
  const [copied, setCopied] = useState<string | null>(null);
  const [windowOpen, setWindowOpen] = useState<'inline' | 'bar' | null>(null);
  const [mood, setMood] = useState<number | null>(7);
  const [editing, setEditing] = useState(true);
  const [log, setLog] = useState('');
  const [free, setFree] = useState(true);
  const guard = useProGate(!free, () => setLog('The upgrade window opens.'));

  const toggleDark = () => {
    document.documentElement.classList.toggle('dark', !dark);
    setDark(!dark);
  };

  return (
    <CatalogFilter.Provider value={{ search: patternSearch, group: patternGroup }}>
    <div className="min-h-dvh bg-surface-1 text-pn">
      <div className="mx-auto max-w-3xl px-6 py-8 space-y-8">
        <header className="flex flex-wrap items-center gap-3">
          <h1 className="text-base font-semibold">UI catalog</h1>
          <p className={`${SETTINGS_HELP} flex-1`}>Find an existing pattern before building another.</p>
          <IconButton label={dark ? 'Light' : 'Dark'} onClick={toggleDark}>
            {dark ? <Sun size={18} aria-hidden="true" /> : <Moon size={18} aria-hidden="true" />}
          </IconButton>
        </header>

        <div className="space-y-3">
          <p className={SETTINGS_HELP}>{Object.values(patternGroups).flat().length} example groups · shared components and class tokens · local fixture state</p>
          <TextField label="Find a pattern" value={patternSearch} onChange={(e) => setPatternSearch(e.target.value)}
            placeholder="Try disabled, snackbar, TextField or CalendarSettings" />
          <Select aria-label="Pattern category" value={patternGroup} onChange={(e) => setPatternGroup(e.target.value)}>
            <option>All patterns</option>
            {Object.keys(patternGroups).map((group) => <option key={group}>{group}</option>)}
          </Select>
          {(patternSearch || patternGroup !== 'All patterns') && <Button action="back" onClick={() => { setPatternSearch(''); setPatternGroup('All patterns'); }}>Show all patterns</Button>}
          <p className={SETTINGS_HELP}>Search matches names, guidance and recorded source locations. Clear the filters if nothing matches.</p>
        </div>

        <details className="rounded-lg border border-divider bg-surface-2 p-4">
          <summary className="cursor-pointer text-sm font-semibold">How to use this catalog and what remains unverified</summary>
          <div className="mt-3 space-y-3">
            <p className={SETTINGS_HELP}>Import shared parts from packages/web/src/ui. Check the real usage before choosing a pattern: identical appearance does not prove shared implementation, and a shared component can have intentional variants.</p>
            <p className={SETTINGS_HELP}>Examples use local fixture state. Some buttons demonstrate appearance only. A rendered example does not verify the product trigger, persistence, permissions or recovery behavior.</p>
            <p className={SETTINGS_HELP}>The browser, demo, macOS and Android inventory is recorded in ops/audits/2026-10-20-ui-foundation/. coverage.json lists per-setting observations and open gaps; findings.md separates implementation candidates from visual differences; ui-check-audit.md records check limitations.</p>
            <p className={SETTINGS_HELP}>Coverage is partial. Android notification denial, retry and permission granted were observed; delivery remains separate. Untested combinations, persistence, destructive actions, billing and failure recovery stay in the coverage register.</p>
          </div>
        </details>

        <Part name="Marketing and documentation map" note="Find public-page patterns, real routes and the code that owns them."
          searchText={catalogIndex.sites.map((r) => `${r.name} ${r.path} ${r.source} ${r.status}`).join(' ')}
          source="ui/catalogIndex.json; ../static-page-chrome.ts; LandingPage.tsx"
          gap="Public pages are now in scope. Static HTML/CSS and React app patterns have different owners. Each row states what was observed and what remains.">
          <p className={SETTINGS_HELP}>The homepage uses React and Tailwind. Help, Brand, Changelog, Themes and Roadmap use static page generators and static-pages.js. Shared footer data does not mean their renderers are interchangeable. Source paths below are relative to packages/web.</p>
          <CatalogIndex kind="sites" />
        </Part>

        <Part name="Replay recipes" note="Reach the real product UI, including its dependent controls and alternate entry points."
          searchText={catalogIndex.flows.map((r) => `${r.name} ${r.path} ${r.source}`).join(' ')}
          source="ui/catalogIndex.json" gap="Read each recipe's evidence scope. Browser observations do not establish native parity; source-derived branches remain explicit.">
          <CatalogIndex kind="flows" />
        </Part>
        <Part name="Settings paths" note="Find the actual setting, its menu path, platform gate and implementation anchor."
          searchText={catalogIndex.settings.map((r) => `${r.name} ${r.path} ${r.source.join(' ')}`).join(' ')}
          source="settingsSearch/registry.ts; ui/catalogIndex.json"
          gap="Generated registry routes. An observed anchor does not prove every option, dependency or persistence outcome. Native AX evidence is recorded separately.">
          <CatalogIndex kind="settings" />
        </Part>
        <Part name="Window implementation inventory" note="Find shared modal calls and custom window shells before creating another."
          searchText={catalogIndex.windows.map((r) => `${r.file} ${r.path}`).join(' ')}
          source="ui/catalogIndex.json; ops/audits/2026-10-20-ui-foundation/scan-windows.mjs"
          gap="Source candidates, not unique windows or confirmed defects. Backdrop and dialog rows may describe the same window. Source-derived paths still need runtime verification where evidence is absent.">
          <CatalogIndex kind="windows" />
        </Part>

        <Part name="Window anatomy and behavior" note="Choose a window by its job, then verify its exits, scrolling and keyboard behavior."
          source="ui/Modal.tsx; ui/Button.tsx; useEscapeToClose.ts; SettingsWindow.tsx; androidBack.ts"
          usage="ConfirmModal.tsx; ClipPageModal.tsx; NoteHistoryModal.tsx"
          gap="The shared shell currently lacks initial-focus, focus-containment and focus-return guarantees. The catalog exposes this gap; it does not repair it.">
          <div className="grid gap-3 sm:grid-cols-2">
            <div className="space-y-2"><h3 className="text-sm font-semibold">Required anatomy</h3><p className={SETTINGS_HELP}>One title, one CloseButton at the top end, a named dialog, a body and optional ModalFooter. Forms end with Cancel and the primary action. Information windows have no redundant Close footer.</p></div>
            <div className="space-y-2"><h3 className="text-sm font-semibold">Exit behavior</h3><p className={SETTINGS_HELP}>Escape closes the top layer. Android Back uses the same overlay stack. Outside clicks close ordinary windows. Settings clears search first and goes back before closing on phones. Busy and required-answer windows need explicit exceptions.</p></div>
            <div className="space-y-2"><h3 className="text-sm font-semibold">Size by content</h3><p className={SETTINGS_HELP}>max-w-sm for confirms, max-w-md for short forms, max-w-lg for ordinary long content. Settings, comparison and media have documented wider layouts. Bound long bodies and keep the header and actions reachable.</p></div>
            <div className="space-y-2"><h3 className="text-sm font-semibold">Review before reuse</h3><p className={SETTINGS_HELP}>Test short height, phone keyboard, long labels, RTL, nested pickers, Tab boundaries and focus after closing. A dialog role alone does not make the background inert or trap focus.</p></div>
          </div>
          <details className="rounded-md border border-divider p-3">
            <summary className="cursor-pointer text-sm font-semibold">Drafts, validation and submission</summary>
            <div className="mt-3 space-y-2">
              <p className={SETTINGS_HELP}>Specify whether X, Escape, backdrop and Cancel discard, retain or save edits. A Cancel label does not prove rollback. Folder/tag appearance saves immediately: Cancel restores the opening values; X and Done keep changes. Its first Escape clears a nonempty search. Child pickers must preserve the parent draft and scroll position.</p>
              <p className={SETTINGS_HELP}>Invalid input stays in the window with an associated field error and a recovery path. Submission prevents duplicate requests. Failure retains useful input; success defines where focus returns.</p>
              <p className={SETTINGS_HELP}>Enter follows the form’s submission policy. Multiline editors, input-method composition and child pickers must keep their own key behavior. Dangerous actions must not become a generic default Enter action.</p>
              <p className={SETTINGS_HELP}>Native macOS About is a separate fixed 280 × 485 window. Its native close, Escape and settled Cmd+W were verified. It has no duplicate in-content X. Recurring-event confirmations use occurrence-scope choices instead of a normal Save footer.</p>
            </div>
          </details>
          <details className="rounded-md border border-divider p-3">
            <summary className="cursor-pointer text-sm font-semibold">Completion checklist for each window</summary>
            <ol className="mt-3 list-decimal ps-5 space-y-2 text-sm">
              <li>Record its owner, real trigger path, prerequisites and verified platforms.</li>
              <li>Record width, height, scroll owner, header, footer and each dismissal route.</li>
              <li>Exercise clean, dirty, invalid, busy, failure and success states where applicable.</li>
              <li>Check focus boundaries, nested layers, phone keyboard, short height and long labels.</li>
              <li>Attach evidence and unresolved gaps. Source inventory and fixture coverage do not establish runtime completion.</li>
            </ol>
          </details>
          <p className={SETTINGS_HELP}>Full contract and offender evidence: ops/audits/2026-10-20-ui-foundation/window-contract.md and window-inventory.json. Proposed focus and scroll requirements await the attended cleanup.</p>
        </Part>

        <Part name="Window sizing lab" note="Real Modal and ModalFooter, with long content, nested windows and a reversible busy state."
          source="ui/Modal.tsx" gap="This local fixture demonstrates the current API. Width choices are examples, not permission to change existing product windows.">
          <WindowLab />
        </Part>

        <Part name="Import workflow" note="One importer, two shells: Sidebar > Import opens a window; Settings > Import & Export embeds the content."
          source="import/ImportModal.tsx; import/registry.ts; notesView/useFilesUpload.ts"
          usage="Sidebar Import; Settings > Import & Export; Files > Upload > Import as notes"
          gap="Demo Markdown success, warning previews and blocking parse errors observed. Import actions use Button; parse errors, warning lists and the oversize split option use Callout. Native file pickers, large-file progress, quota limits, restore and every format's parsing outcomes remain separate scenarios. This map is not an importer simulator.">
          <ol className="list-decimal space-y-2 ps-5 text-sm text-pn-soft">
            <li>Pick: source-tag switch, format cards and guide links, plus Webcal address validation. No footer. Import, Export, Restore and Passwords tabs; Trackers depends on caller data.</li>
            <li>Preview: source and item counts, warnings, sample titles and Add to destination. Folder trees reveal folder tags; Firefox tags/keywords reveal Keep tags from your browser; embedded contact photos reveal Import photos; notes over 1 MB reveal the split option. Back returns to format selection; Import names the item count.</li>
            <li>Working: parsing or writing status. The standalone shell has a bar header, Close and a scrolling body capped at 85vh. Busy dismissal and long-running recovery still need runtime checks.</li>
            <li>Failure: blocking parse errors show Back and Cancel. A malformed Keep JSON instead produces a warning preview with zero items. Do not collapse these into one generic error state.</li>
            <li>Success: the tested single-note import closes the window and adds the note. Files upload has a separate Import or store? choice and Upload complete surface.</li>
          </ol>
          <p className={SETTINGS_HELP}>Android uses an unrestricted native file filter because its MIME mapping can hide supported extensions. Its embedded import pane was measured at 411px without horizontal overflow. iOS picker behavior remains unverified. Observed review gaps: malformed ZIP exposes raw library error text; Escape leaves BODY focused. Replay evidence and synthetic inputs: ops/audits/2026-10-20-ui-foundation/import-runtime.json and fixtures/.</p>
        </Part>

        <Part name="Guided tracker flow" note="Real TrackerPills: empty, filled, expanded, guided completion and read-only. Changes stay in this fixture."
          source="TrackerPills.tsx; trackers/PillShell.tsx; trackers/panelUI.tsx"
          usage="CheckInCard.tsx; journal editor"
          gap="This is the shared tracker composition, not the full check-in card. Card timing, streaks, skip/undo and persistence require the live app.">
          <SettingsSegmented label="Tracker host" value={trackerMode} onChange={(value) => { setTrackerMode(value); setTrackerDone(false); setTrackerReset((v) => v + 1); }} options={[{ value: 'card', label: 'Guided card' }, { value: 'entry', label: 'Journal entry' }]} />
          <Switch label="Read-only tracker fixture" checked={trackerReadOnly} onChange={setTrackerReadOnly} />
          <Button action="restore" onClick={() => { setTrackerData({}); setTrackerDone(false); setTrackerReset((v) => v + 1); }}>Restart empty flow</Button>
          <TrackerPills key={trackerReset} data={trackerData} onChange={setTrackerData}
            trackerSettings={trackerConfig} onSettingsChange={setTrackerConfig}
            factors={fixtureFactors}
            medications={fixtureMeds}
            isPro readOnly={trackerReadOnly} variant={trackerMode}
            flow={trackerMode === 'card' && !trackerReadOnly ? { onFinish: () => setTrackerDone(true), done: trackerDone ? <StatusLine tone="success">Fixture complete</StatusLine> : undefined } : undefined} />
        </Part>

        <Part name="Time input" note="One stored HH:MM value, with separate desktop, Android and iOS input experiences."
          source="TimeInput.tsx; touchOnly.ts" usage="ScheduleView.tsx; CalendarSettings.tsx"
          gap="Desktop parsing and the Pixel native picker were observed. iOS picker appearance, wheel commits and Reset remain source-derived until tested on an iPhone or iPad.">
          <dl className="space-y-3">
            <div><dt className="text-sm font-semibold">Desktop / fine pointer</dt><dd className={SETTINGS_HELP}>Text entry accepts 3pm or 15:30. Enter or blur commits. Invalid text keeps the previous committed value; clearing removes an optional time. Verified in the browser.</dd></div>
            <div><dt className="text-sm font-semibold">Android</dt><dd className={SETTINGS_HELP}>Native time input. The tested Pixel opens a clock picker with a text-entry mode and Set, Cancel and Clear controls. Cancel returns to Schedule. This is the observed Pixel UI, not a promise that every Android version looks identical.</dd></div>
            <div><dt className="text-sm font-semibold">iOS / iPadOS</dt><dd className={SETTINGS_HELP}>Native time input with the platform’s own presentation. The source handles wheel updates separately from committed change events and supports Safari Reset for optional times. Runtime verification is still open; Android evidence does not cover iOS.</dd></div>
          </dl>
          <p className={SETTINGS_HELP}>This live example uses this device’s actual input mode. The component chooses native input when touch is available and the pointer is not fine; resizing a desktop browser does not simulate a phone picker.</p>
          <TimeInput label="Fixture time" value={fixtureTime} onCommit={(value) => setFixtureTime(value ?? undefined)} className={FIELD_CLASS} clearable />
          <p className={SETTINGS_HELP}>Committed value: {fixtureTime ?? 'No time'}. With text entry, try 3pm, 15:30, invalid text, then clear. On a touch device, inspect its native picker and cancellation.</p>
        </Part>

        <Part name="Flow reference map" note="Start with the real composition when building a related feature. These are navigation recipes, not verified coverage claims."
          source="CheckInCard.tsx; QuickSwitcher.tsx; ScheduleView.tsx; NoteOptionsMenu.tsx; EventCard.tsx"
          gap="Browser state evidence is in flow-observations.json. Native equivalents, full error recovery and untouched branches remain separate checks.">
          <details><summary className="cursor-pointer text-sm">Daily check-in: list and grid</summary><p className={SETTINGS_HELP}>Enable Settings → Trackers → Daily check-in card. In All, Journals must also be included in All. Choose mood, follow trackers, finish, reopen the summary. Check the options menu, another day, skip/undo, protected entry and empty tracker setup. Grid uses a full-width tile; list uses a band.</p></details>
          <details><summary className="cursor-pointer text-sm">Quick switcher and quick add</summary><p className={SETTINGS_HELP}>Cmd+K opens search; &gt; changes to commands. Q opens creation mode. Type a synthetic title with a date and time, inspect parsed chips, choose an item type, then verify the created item. Item search, settings results, empty results and command results are different states.</p></details>
          <details><summary className="cursor-pointer text-sm">Journal, event and alert submenus</summary><p className={SETTINGS_HELP}>Create a journal or event, open its date, then Alert. Inspect presets, custom amount and units, duplicate prevention, multiple selections and None. Also inspect all-day versus timed, end date, repeats and occurrence scope. ScheduleView shares menu parts with NoteOptionsMenu; visual similarity does not mean every row is a ui/ component.</p></details>
          <details><summary className="cursor-pointer text-sm">Event date tile and date preferences</summary><p className={SETTINGS_HELP}>Settings → Date &amp; Time → Format → Date format. Try Automatic, Day first, Month first and Year first (ISO), then open Yoga in the demo. The desktop tile always has localized month / day / weekday, such as OCT / 21 / Wed. Date order applies to complete dates, never to these standalone labels. Check a narrow pane too: the phone layout uses a full date line. Source: EventCard.tsx and intlFormat.ts. ISO regression reproduced and fixed in Chromium on 2026-10-21; this is not a Firefox or native runtime verification.</p></details>
        </Part>

        <Part name="Button" note="action brings the one icon, label and look of each action; one size for every button; pro; disabled">
          <div className="flex flex-wrap gap-2">
            {(['save', 'add', 'create', 'done', 'confirm', 'next', 'delete', 'remove', 'cancel', 'back', 'edit', 'rename', 'copy', 'search'] as const).map((a) => (
              <Button key={a} action={a} />
            ))}
            <Button action="restore">Restore</Button>
            <Button action="apply">Apply</Button>
            <Button action="open">Open</Button>
          </div>
          <div className="flex flex-wrap items-center gap-2">
            <Button action="add">Add medication</Button>
            <Button variant="upgrade" icon={<IconUpgrade size={15} onFill />}>Upgrade to Pro</Button>
            <Button pro icon={<Stethoscope size={15} aria-hidden="true" />} onClick={guard(() => setLog('Ran the Pro action.'))}>Doctor report</Button>
            <Button action="save" disabled />
          </div>
        </Part>

        <Part name="IconButton" note="row tools only; the label is required">
          <div className="flex gap-1">
            <IconButton label="Edit"><PencilSimple size={16} aria-hidden="true" /></IconButton>
            <IconButton label="Remove" tone="danger"><Trash size={16} aria-hidden="true" /></IconButton>
            <IconButton label="Settings"><Gear size={16} aria-hidden="true" /></IconButton>
          </div>
        </Part>

        <Part name="TextField and Select" note="size md in a window or form, sm in a settings row; label with an accent icon, hint, error"
          source="ui/fields.tsx; formFields.tsx; settingsUI.tsx"
          usage="ClipPageModal.tsx (TextField); CalendarSettings.tsx (SETTINGS_SELECT on native selects)"
          gap="Fixture validation below only checks length. Actual forms own their validation and recovery.">
          <div className="grid gap-3 sm:grid-cols-2">
            <TextField label="Web address" icon={<Globe size={13} />} placeholder="https://" hint="A page or an article." />
            <TextField label="Short name" icon={<User size={13} />} defaultValue="A name that is far too long" error="Too long." />
            <Select aria-label="Range" defaultValue="30">
              <option value="7">7 days</option>
              <option value="30">30 days</option>
            </Select>
            <TextField size="sm" aria-label="A settings row field" placeholder="size sm, a settings row" />
            <TextField label="Disabled field" value="Unavailable" disabled />
            <TextField label="Read-only field" value="Selectable, not editable" readOnly />
            <TextField label="Validation example" value={fieldExample} onChange={(e) => setFieldExample(e.target.value)}
              hint="Type more than 12 characters to show an error; shorten it to recover."
              error={fieldExample.length > 12 ? 'Use 12 characters or fewer.' : undefined} />
            <Select aria-label="Disabled select" disabled defaultValue="30">
              <option value="30">30 days</option>
            </Select>
          </div>
        </Part>

        <Part name="FieldLabel, GroupHeading, FIELD_CLASS" note="the item-form kit, for a field laid out by hand">
          <GroupHeading>Login</GroupHeading>
          <FieldLabel icon={<User size={13} />}>Username</FieldLabel>
          <div className="flex gap-1.5">
            <input className={FIELD_CLASS} defaultValue="user@example.com" aria-label="Username" />
            <button type="button" className={FIELD_BUTTON} aria-label="Copy"><Copy size={16} aria-hidden="true" /></button>
          </div>
        </Part>

        <Part name="Segmented" note="SettingsSegmented in a header; SETTINGS_TRACK in a row">
          <div className="space-y-3">
            <SettingsSegmented label="Layer" value={seg} onChange={setSeg} options={[{ value: 'a', label: 'Both' }, { value: 'b', label: 'Writing' }, { value: 'c', label: 'Mood' }]} />
            <div className={SETTINGS_TRACK}>
              {['a', 'b', 'c'].map((v) => (
                <button key={v} type="button" aria-pressed={row === v} onClick={() => setRow(v)} className={settingsSegClass(row === v)}>{v === 'a' ? 'Automatic' : v === 'b' ? '24-hour' : '12-hour'}</button>
              ))}
            </div>
          </div>
        </Part>

        <Part name="Setting row, Switch, heading" note="RowTitle with a glyph, helper, control"
          source="Switch.tsx; settingsUI.tsx"
          usage="ImagesSheet.tsx; CalendarSettings.tsx; security/BiometricTab.tsx"
          gap="The switch changes only this example. Synced settings, permission gates and dependent controls need their own scenarios.">
          <SectionEyebrow icon={Sparkle}>Section heading <ProMark /></SectionEyebrow>
          <div className="divide-y divide-divider">
            <div className={SETTINGS_ROW}>
              <div className="min-w-0">
                <RowTitle icon={Gear}>A setting row</RowTitle>
                <p className={SETTINGS_HELP}>The helper line says what the setting does.</p>
              </div>
              <div className={SETTINGS_TRACK}>
                <button type="button" aria-pressed className={settingsSegClass(true)}>On</button>
                <button type="button" aria-pressed={false} className={settingsSegClass(false)}>Off</button>
              </div>
            </div>
            <Switch label="A boolean setting" icon={<Gear size={14} className="text-accent" />} labelClassName={ROW_TITLE} description="A switch row: the whole row is the label." checked={on} onChange={setOn} className="py-3" />
            <Switch label="Disabled, off" checked={false} onChange={() => {}} disabled className="py-3" />
            <Switch label="Disabled, on" checked onChange={() => {}} disabled className="py-3" />
          </div>
        </Part>

        <Part name="Tabs" note="directly under the pane title, outside the scroll area">
          <SettingsTabStrip>
            {['General', 'Lists', 'Custom'].map((label, i) => (
              <button key={label} type="button" aria-pressed={tab === i} onClick={() => setTab(i)} className={settingsTabClass(tab === i)}>
                <Gear aria-hidden="true" />
                <span>{label}</span>
              </button>
            ))}
          </SettingsTabStrip>
        </Part>

        <Part name="StatTile" note="label above, value below">
          <div className="grid grid-cols-2 gap-2 sm:grid-cols-4">
            <StatTile label="Writing streak" value="4 days" sub="Today is in." />
            <StatTile label="Words" value="2,515" />
            <StatTile label="Mood" value="7.4" />
            <StatTile label="Days logged" value="5 of 7" />
          </div>
        </Part>

        <Part name="DeleteButton" note="Inline confirmation: trash → Delete? → click to confirm. Remove uses the same interaction."
          source="ui/DeleteButton.tsx"
          usage="EncryptedAttachment.tsx: editor attachment controls; TrackerConfig.tsx: habit, factor and medication rows"
          gap="This fixture reports confirmation without deleting data. Editor caret preservation and each caller's deletion, persistence and failure handling need separate checks. The shared component has no busy or disabled prop.">
          <p className={SETTINGS_HELP}>The first click only arms the button. Confirm within three seconds; Escape or timeout returns to the trash icon. Keyboard activation focuses the confirmation so Enter can confirm. Outside click and blur are not explicit cancellation handlers.</p>
          <div className="flex max-w-md items-center gap-2 rounded-md border border-divider bg-surface-2 py-1.5 pe-1.5 ps-3">
            <span className="min-w-0 flex-1 truncate text-sm font-medium">Multivitamin</span>
            <IconButton label="Edit"><PencilSimple size={14} aria-hidden="true" /></IconButton>
            <DeleteButton kind="remove" label="Remove Multivitamin" onConfirm={() => setLog('Removed')} />
          </div>
          <div className="flex max-w-md items-center gap-2 rounded-xl border border-divider bg-surface-2 py-2 pe-3 ps-3">
            <span className="min-w-0 flex-1 truncate text-sm">qa-repeat.jpg</span>
            <DeleteButton label="Delete qa-repeat.jpg" onConfirm={() => setLog('Deleted')} />
          </div>
          <p className={SETTINGS_HELP} role="status">{log || 'No confirmation yet. These are local examples.'}</p>
        </Part>

        <Part name="Vault form actions" note="Shared Save/Cancel for login, card and SSH forms. Action icons come from the Phosphor action map."
          source="ui/VaultFormActions.tsx; ui/actions.ts" usage="LoginForm.tsx; CardForm.tsx; SshKeyForm.tsx"
          gap="Scoped vault composition, not a replacement for ModalFooter or EditRow. Keeps existing dimensions and callbacks; Cancel gains its mapped icon. No new Escape behavior or busy state.">
          <VaultActionsLab />
        </Part>
        <Part name="Bookmark actions" note="Copy keeps its label and width after success; Open uses the soft accent variant."
          source="BookmarkItem.tsx; ui/Button.tsx; ui/actions.ts"
          gap="Static states below. Product: Bookmarks > row Edit. Clipboard ownership, saved URL validation and external navigation remain in BookmarkItem; the narrow row uses its existing container query.">
          <div className="flex flex-wrap gap-2">
            <Button action="copy" onClick={() => setLog('Copy fixture selected.')}>Copy</Button>
            <Button action="done" variant="secondary" className="[&_svg]:text-success" onClick={() => setLog('Copied-state fixture selected.')}>Copy</Button>
            <Button action="open" variant="accent" onClick={() => setLog('Open fixture selected.')}>Open</Button>
          </div>
          <p className={SETTINGS_HELP}>Idle Copy, successful Copy, Open. These fixtures do not write to the clipboard or open a site.</p>
        </Part>

        <Part name="Upload progress" note="The actual upload window with mixed results, storage failures and running files."
          source="UploadProgressModal.tsx" usage="Files > Upload; editor attachments"
          gap="Local fixtures only. No uploads, purchases or file deletion. Running finishes after three seconds. Storage messages use the real structured error codes; account-tier purchase doors need separate account verification.">
          <UploadProgressLab />
        </Part>
        <Part name="Export progress" note="The actual export window in running, complete, incomplete and failed states."
          source="ExportProgressModal.tsx; notesView/useExports.ts"
          gap="Local fixture only: no files exported. Running automatically finishes after three seconds so the non-cancellable window cannot trap the catalog. Product path: Settings > Import & Export > Export. Real disk/network failures require separate checks.">
          <ExportProgressLab />
        </Part>

        <Part name="Generation actions" note="Generate opens a tool or creates a key; Regenerate replaces the preview; Apply accepts it."
          source="ui/actions.ts; LoginForm.tsx; SshKeyForm.tsx; PasswordGenerator.tsx"
          gap="Presentation fixtures only. Real generator: Vault > GitHub > Edit > Generate password. Password and Passphrase modes share these actions; generation and clipboard logic stay in the product.">
          <div className="flex flex-wrap gap-2">
            <Button action="generate" onClick={() => setLog('Generation fixture selected.')}>Generate password</Button>
            <Button action="generate" disabled>Generating...</Button>
            <Button action="regenerate" onClick={() => setLog('Regeneration fixture selected.')}>Regenerate</Button>
            <Button action="apply" onClick={() => setLog('Apply fixture selected.')}>Use password</Button>
          </div>
        </Part>

        <Part name="Vault field actions" note="Copy, reveal and download share field spacing and canonical action icons."
          source="ui/VaultFieldAction.tsx; ui/actions.ts; clipboard.ts"
          usage="LoginForm.tsx; CardForm.tsx; SshKeyForm.tsx"
          gap="These are local presentation fixtures. Real clipboard success, failure and timing stay in useCopyToClipboard; native file downloads require platform checks.">
          <div className="flex flex-wrap items-center gap-4">
            <div><p className={SETTINGS_HELP}>Copy</p><VaultFieldAction kind="copy" title="Copy fixture" onClick={() => setLog('Copy callback requested.')} /></div>
            <div><p className={SETTINGS_HELP}>Copied</p><VaultFieldAction kind="copy" active title="Copied fixture" onClick={() => setLog('Copy callback requested.')} /></div>
            <div><p className={SETTINGS_HELP}>Hidden</p><VaultFieldAction kind="reveal" title="Show fixture" onClick={() => setLog('Reveal callback requested.')} /></div>
            <div><p className={SETTINGS_HELP}>Revealed</p><VaultFieldAction kind="reveal" active title="Hide fixture" onClick={() => setLog('Hide callback requested.')} /></div>
            <div><p className={SETTINGS_HELP}>Download</p><VaultFieldAction kind="download" title="Download fixture" onClick={() => setLog('Download callback requested. No file written.')} /></div>
          </div>
        </Part>
        <Part name="EditRow" note="the footer of every inline edit; Escape cancels">
          {editing ? (
            <div className="space-y-2 rounded-md border border-divider p-3">
              <div className="grid gap-2 sm:grid-cols-2">
                <TextField aria-label="Question" defaultValue="Did you test the code?" />
                <TextField aria-label="Short name" defaultValue="Code" />
              </div>
              <EditRow onCancel={() => setEditing(false)} onSave={() => setEditing(false)} />
            </div>
          ) : <Button action="edit" onClick={() => setEditing(true)} />}
        </Part>

        <Part name="useProGate" note="Pro actions stay enabled; a free account gets the upgrade window">
          <div className="flex flex-wrap items-center gap-3">
            <Switch label="Free account" checked={free} onChange={setFree} />
            <Button pro={free} icon={<Sparkle size={15} aria-hidden="true" />} onClick={guard(() => setLog('Ran the Pro action.'))}>Show and copy AI prompt</Button>
            <span className={SETTINGS_HELP}>{log}</span>
          </div>
        </Part>

        <Part name="MoodScale" note="the mood scale; ScaleTiles below is the same row for every other scale">
          <MoodScale value={mood} onPick={setMood} label="How are you today?" />
        </Part>

        <Part name="Class strings" note="SETTINGS_BTN* and SETTINGS_SELECT on a link or a label; ROW_TITLE and SETTINGS_EYEBROW without the component">
          <div className="flex flex-wrap items-center gap-2">
            <a href="#ui-catalog" className={SETTINGS_BTN}>Secondary link</a>
            <a href="#ui-catalog" className={SETTINGS_BTN_PRIMARY}>Primary link</a>
            <a href="#ui-catalog" className={SETTINGS_BTN_DANGER}>Danger link</a>
            <a href="#ui-catalog" className={SETTINGS_BTN_UPGRADE}><IconUpgrade size={12} onFill /> Upgrade link</a>
            <span className={SETTINGS_SELECT}>A value styled as a field</span>
          </div>
          <p className={ROW_TITLE}>ROW_TITLE on a plain element</p>
          <p className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW}`}><EyebrowGlyph icon={Sparkle} />SETTINGS_EYEBROW with EyebrowGlyph</p>
          <HoverLabel label="HoverLabel with a shortcut" keys="Mod+K">
            <span className={SETTINGS_BTN}>Hover me</span>
          </HoverLabel>
        </Part>

        <Part name="ScaleTiles" note="every other 0 to 10 scale: energy, focus, pain">
          <ScaleTiles min={0} max={10} value={scale} onPick={setScale} label="Energy" ends={['Low', 'High']} />
        </Part>

        <Part name="Tracker panel parts" note="inside a tracker panel only: question, choice tiles, joined pair, stepper, chips">
          <div className="max-w-sm space-y-4 rounded-lg bg-surface-1 p-3">
            <div>
              <PanelQuestion>How did you sleep?</PanelQuestion>
              <ChoiceGrid options={[{ key: 'poor', label: 'Poor' }, { key: 'ok', label: 'Okay' }, { key: 'good', label: 'Good' }]} value={choice} onPick={setChoice} />
            </div>
            <div>
              <PanelQuestion>Medication</PanelQuestion>
              <PanelSegmented options={[{ key: 'taken', label: 'Taken' }, { key: 'skipped', label: 'Skipped' }]} value={taken} onPick={setTaken} tone="status" className="w-full" />
            </div>
            <div>
              <PanelQuestion>Water</PanelQuestion>
              <NumberStepper value={water} onChange={setWater} min={0} step={1} unit="glasses" quick={[4, 6, 8]} expanded />
            </div>
            <div className="flex flex-wrap gap-1.5">
              {['Work', 'Family', 'Exercise'].map((c) => (
                <button key={c} type="button" aria-pressed={chips.includes(c)} onClick={() => setChips((x) => (x.includes(c) ? x.filter((y) => y !== c) : [...x, c]))} className={chipClass(chips.includes(c))}>{c}</button>
              ))}
              <button type="button" className={CHIP_ADD}><Plus size={12} aria-hidden="true" />Add</button>
            </div>
          </div>
        </Part>

        <Part name="Modal, ModalFooter" note="title with an icon and the close X; inline header for a short window, bar header over a scrolling body; footer with icon buttons">
          <div className="flex flex-wrap gap-2">
            <Button icon={<AppWindow size={15} aria-hidden="true" />} onClick={() => setWindowOpen('inline')}>Short window</Button>
            <Button icon={<AppWindow size={15} aria-hidden="true" />} onClick={() => setWindowOpen('bar')}>Window with a title bar</Button>
          </div>
          {windowOpen === 'inline' && (
            <Modal onClose={() => setWindowOpen(null)} title="Clip page" icon={<Scissors size={16} />} className="max-w-md p-6 space-y-4">
              <TextField label="Web address" icon={<Globe size={13} />} dir="ltr" placeholder="https://" />
              <div className={SETTINGS_TRACK}>
                <button type="button" aria-pressed={false} className={settingsSegClass(false)}>Bookmark</button>
                <button type="button" aria-pressed className={settingsSegClass(true)}>Main text</button>
              </div>
              <p className={SETTINGS_HELP}>Downloading pictures, 1 of 2</p>
              <ModalFooter>
                <Button action="cancel" onClick={() => setWindowOpen(null)} />
                <Button action="save" onClick={() => setWindowOpen(null)} />
              </ModalFooter>
            </Modal>
          )}
          {windowOpen === 'bar' && (
            <Modal onClose={() => setWindowOpen(null)} title="Note history" icon={<Clock size={16} />} subtitle="Local example versions." header="bar" className="max-w-lg max-h-[80vh] flex flex-col">
              <div className="flex-1 min-h-0 overflow-y-auto px-6 py-4 space-y-2">
                {['Today, 14:02', 'Yesterday, 09:40', 'Oct 12, 18:15'].map((v) => (
                  <p key={v} className="flex items-center gap-2 text-sm"><Article size={14} className="text-accent" aria-hidden="true" />{v}</p>
                ))}
              </div>
              <ModalFooter bar>
                <Button action="cancel" onClick={() => setWindowOpen(null)} />
                <Button action="restore" onClick={() => setWindowOpen(null)}>Restore</Button>
              </ModalFooter>
            </Modal>
          )}
        </Part>

        <Part name="ContextMenu" note="rows with an accent icon, a shortcut, a toggle check, a Pro mark, a destructive row, separators, a header">
          <Button
            action="open"
            onClick={(e) => {
              const r = e.currentTarget.getBoundingClientRect();
              menu.open({ clientX: r.left, clientY: r.bottom + 4, preventDefault: () => {}, stopPropagation: () => {} }, [
                { type: 'header', label: 'Note' },
                { label: 'Rename', icon: <PencilSimple />, onSelect: () => setLog('Rename'), shortcut: 'F2' },
                { label: 'Pinned', icon: <PushPin />, onSelect: () => setLog('Pin'), checked: true },
                { label: 'Move to folder', icon: <Folder />, onSelect: () => setLog('Move'), pro: true },
                { type: 'separator' },
                { label: 'Move to trash', icon: <Trash />, onSelect: () => setLog('Trash'), destructive: true },
              ]);
            }}
          >Open a menu</Button>
          {menu.state && <ContextMenu state={menu.state} onClose={menu.close} />}
          <BackRow title="Schedule" onBack={() => setLog('Back')} />
        </Part>

        <Part name="ListSearchInput, InlineRenameField" note="the search over a list; renaming in place">
          <div className="max-w-xs"><ListSearchInput value={query} onChange={setQuery} placeholder="Search notes..." /></div>
          {renaming
            ? <InlineRenameField value={fileName} onValueChange={setFileName} onCommit={() => setRenaming(false)} onCancel={() => setRenaming(false)} aria-label="File name" />
            : <Button action="rename" onClick={() => setRenaming(true)}>{fileName}</Button>}
        </Part>

        <Part name="ColorSwatch" note="one color choice, the no-color swatch, the selected ring">
          <div className="flex flex-wrap gap-2">
            <ColorSwatch label="No color" none selected={swatch === null} onClick={() => setSwatch(null)} />
            {([['blue', '#2563eb'], ['green', '#16a34a'], ['amber', '#d97706'], ['red', '#dc2626'], ['purple', '#9333ea']] as const).map(([k, c]) => (
              <ColorSwatch key={k} label={k} background={c} selected={swatch === k} onClick={() => setSwatch(k)} />
            ))}
          </div>
        </Part>

        <Part name="MonthGrid, StorageBar" note="every date choice; storage used against the limit">
          <div className="grid gap-4 sm:grid-cols-2">
            <MonthGrid marked={{ has: (d) => d.endsWith('-05') || d.endsWith('-12') }} selected={day} onPick={setDay} />
            <StorageBar label="Files" usedBytes={312_000_000} maxBytes={1_000_000_000} onRefresh={async () => setLog('Refreshed')} />
          </div>
        </Part>

        <Part name="UpdateToast" note="a toast at the bottom end: icon tile, title, meta, one action">
          <Button icon={<Bell size={15} aria-hidden="true" />} onClick={() => setToast(true)}>Show a toast</Button>
          {toast && <UpdateToast version="0.700.0" actionLabel="Restart" onAction={() => setToast(false)} onDismiss={() => setToast(false)} />}
        </Part>

        <Part name="Detail pane kit" note="hero with tile and Edit, a group, rows with an accent label, one action group with copy, a link, notes">
          <div className={DETAIL_COLUMN}>
            <DetailHero tile={<DetailTile><Globe size={22} /></DetailTile>} title="Google" subtitle="accounts.google.com" onEdit={() => setLog('Edit')} editLabel="Edit" />
            <DetailGroup heading="Login">
              <DetailRow icon={<User size={13} />} label="Username" actions={<DetailCopyAction value="user@example.com" id="u" copied={copied} onCopy={(_, id) => setCopied(id)} label="Copy" />}>user@example.com</DetailRow>
              <DetailRow icon={<Globe size={13} />} label="Website" actions={<DetailAction label="Open" href="https://accounts.google.com"><ArrowSquareOut size={15} /></DetailAction>}><DetailLink href="https://accounts.google.com">accounts.google.com</DetailLink></DetailRow>
            </DetailGroup>
            <DetailNotes heading="Notes">Example login. Edit or delete anytime.</DetailNotes>
          </div>
        </Part>

        <Part name="Callout, Banner" note="four tones: info, warning, danger, success; title and shared FeedbackButton action optional"
          source="ui/feedback.tsx"
          usage="VaultFormActions: empty-field and save failures in Login, Card and SSH key forms; ContactForm: empty-contact validation; import/ImportModal: parse failure, warning preview and oversize split; ExportProgressModal: failed export"
          gap="QuotaExceededBanner and SyncErrorBanner currently have separate implementations. These examples do not establish that their behavior or styling matches Banner.">
          <div className="space-y-2">
            <Callout>Files up to 5 MB on the free plan.</Callout>
            <Callout tone="warning" title="Notifications are blocked">Allow them in the settings of this browser.</Callout>
            <Callout tone="danger">Fill in at least one field before saving.</Callout>
            <Callout tone="danger" action={<FeedbackButton action="retry" onClick={() => setLog('Example retry requested.')}>Retry</FeedbackButton>}>The page could not be downloaded.</Callout>
            <Callout tone="success">Your recovery phrase is saved.</Callout>
          </div>
          <div className="overflow-hidden rounded-md border border-divider">
            <Banner action={<FeedbackButton icon={<HardDrives size={15} aria-hidden="true" />}>Manage storage</FeedbackButton>} onDismiss={() => setLog('Dismissed')} dismissLabel="Later">Storage is full. New files are not uploaded.</Banner>
            <Banner tone="info">A newer version is ready.</Banner>
            <Banner tone="warning">Example: permission is needed before continuing.</Banner>
            <Banner tone="danger">Example: the operation failed. Your draft is still available.</Banner>
            <Banner tone="success">Example: the operation completed.</Banner>
          </div>
        </Part>

        <Part name="Badge, IconTile, Kbd" note="a short status beside a name; the tinted tile; a key in text">
          <div className="flex flex-wrap items-center gap-2">
            <Badge>Default</Badge><Badge tone="success">Stronger</Badge><Badge tone="warning">Not backed up</Badge><Badge tone="danger">Expired</Badge><Badge tone="info">3</Badge>
          </div>
          <div className="flex flex-wrap items-center gap-3">
            <IconTile tone="danger"><Trash /></IconTile><IconTile tone="warning"><Warning /></IconTile><IconTile><Info /></IconTile><IconTile tone="success"><CheckCircle /></IconTile>
            <span className="text-sm text-pn-muted">Press <Kbd>Esc</Kbd> to close, <Kbd>⌘</Kbd><Kbd>K</Kbd> to jump.</span>
          </div>
        </Part>

        <Part name="TaskCheckbox" note="shared drawn tick for Tasks, notes and Kanban; 750 ms">
          <TaskCheckbox aria-label="Complete example task" defaultChecked={false} />
          <TaskCheckbox aria-label="Completed example task" defaultChecked />
          <TaskCheckbox aria-label="Disabled example task" disabled />
          <TaskCheckbox aria-label="Disabled completed task" defaultChecked disabled />
        </Part>
        <Part name="Checkbox" note="a yes or no inside a form or a confirm; card for its own box">
          <Checkbox label="Also delete its subfolders" checked={ticked} onChange={(e) => setTicked(e.target.checked)} />
          <Checkbox label="I wrote my recovery phrase down" description="Nobody can recover a lost phrase." card />
          <Checkbox label="Require PIN to view" disabled />
        </Part>

        <Part name="Spinner, ProgressBar, StatusLine" note="unknown length; a known job; one line about a running step">
          <div className="flex items-center gap-3"><Spinner /><Spinner size={24} label="Loading" /></div>
          <ProgressBar value={0.42} label="Exporting" />
          <ProgressBar label="Preparing" />
          <ProgressBar value={0} label="Waiting" />
          <ProgressBar value={1} tone="success" label="Complete" />
          <ProgressBar value={1} tone="warning" label="Incomplete" />
          <ProgressBar value={1} tone="danger" label="Failed" />
          <StatusLine busy>Downloading pictures, 1 of 2</StatusLine>
          <StatusLine tone="danger">The page could not be downloaded.</StatusLine>
        </Part>

        <Part name="EmptyState" note="a list with nothing in it; compact for a short list">
          <EmptyState icon={<BookmarkSimple weight="duotone" />} title="No bookmarks yet" actions={<><Button action="add">Add bookmark</Button><Button action="import">Import</Button></>}>Save a link to read later.</EmptyState>
          <EmptyState compact>No versions yet.</EmptyState>
        </Part>

        <Part name="Popover, Divider, CopyButton, Snackbar" note="a panel at its control; a rule between groups; copy with a check; a message after an action">
          <div className="flex flex-wrap items-center gap-2">
            <span ref={popAnchor} className="inline-flex"><Button icon={<SlidersHorizontal size={15} aria-hidden="true" />} onClick={() => setPop((v) => !v)}>View options</Button></span>
            <CopyButton value="otpauth://example" label="Copy code" />
            <Button icon={<ChatText size={15} aria-hidden="true" />} onClick={() => setSnack((v) => !v)}>Show a snackbar</Button>
          </div>
          <Popover open={pop} anchorRef={popAnchor} onClose={() => setPop(false)} title="View options">
            <Checkbox label="Show previews" defaultChecked />
            <Divider />
            <Checkbox label="Compact rows" />
          </Popover>
          {snack && <Snackbar actionLabel="Undo" onAction={() => setSnack(false)}>Moved to Work</Snackbar>}
        </Part>

        <Part name="SettingsCallout, ResetDefaultsButton, HelpChip" note="must-read lines; the foot of a pane">
          <SettingsCallout>Notifications are blocked for PrivacyNotes. Allow them in the settings of this browser.</SettingsCallout>
          <ResetDefaultsButton onReset={() => setLog('Reset.')} />
          <HelpChip surface="images" className="mt-3" />
        </Part>
      </div>
    </div>
    </CatalogFilter.Provider>
  );
}

function WindowLab() {
  const [size, setSize] = useState('max-w-md');
  const [long, setLong] = useState(false);
  const [info, setInfo] = useState(false);
  const [open, setOpen] = useState(false);
  const [child, setChild] = useState(false);
  const [busy, setBusy] = useState(false);
  const [invalid, setInvalid] = useState(false);
  const [result, setResult] = useState('No window opened yet.');
  const close = (reason: string) => { setOpen(false); setChild(false); setBusy(false); setResult(reason); };
  return (
    <div className="space-y-3">
      <Select aria-label="Window width" value={size} onChange={(e) => setSize(e.target.value)}>
        <option value="max-w-sm">Confirm · max-w-sm</option>
        <option value="max-w-md">Form · max-w-md</option>
        <option value="max-w-lg">Content · max-w-lg</option>
        <option value="max-w-3xl">Workspace · max-w-3xl</option>
      </Select>
      <Switch label="Long window content" checked={long} onChange={setLong} />
      <Switch label="Information window without footer" checked={info} onChange={setInfo} />
      <Switch label="Show field error" checked={invalid} onChange={setInvalid} />
      <Button action="open" onClick={() => setOpen(true)}>Open window lab</Button>
      <p className={SETTINGS_HELP} role="status">{result}</p>
      {open && <Modal title="Window lab" header="bar" onClose={() => close('Dismissed through X, Escape or outside click.')}
        escape={!busy} closeOnBackdrop={!busy} className={`${size} max-h-[calc(100dvh-3rem)] flex flex-col`}>
        <div className="min-h-0 flex-1 overflow-y-auto p-6 space-y-4">
          <TextField label="Example name" placeholder="A local draft" error={invalid ? 'Example validation error. Correct the value before saving.' : undefined} />
          <p className={SETTINGS_HELP}>Tab from the final action to inspect the current focus gap. Escape should close only the child when a child is open.</p>
          <div className="flex flex-wrap gap-2">
            <Button action="open" disabled={busy} onClick={() => setChild(true)}>Open child window</Button>
            <Button action={busy ? 'done' : 'next'} onClick={() => setBusy((v) => !v)}>{busy ? 'End simulated busy state' : 'Simulate busy state'}</Button>
          </div>
          {busy && <StatusLine busy>Local busy simulation. End it with the button above; X, Escape and outside click are disabled.</StatusLine>}
          {long && Array.from({ length: 16 }, (_, i) => <p key={i} className="text-sm">Example paragraph {i + 1}. Long content belongs in the scrolling body while the title and actions remain reachable.</p>)}
        </div>
        {!info && <ModalFooter bar><Button action="cancel" disabled={busy} onClick={() => close('Cancelled the local draft.')} /><Button action="save" disabled={busy || invalid} onClick={() => close('Saved the local fixture only.')} /></ModalFooter>}
        {child && <Modal title="Child window" layer="z-[60]" onClose={() => setChild(false)} className="max-w-sm p-6 space-y-4">
          <p className="text-sm">Close this layer first. The parent window should remain open.</p>
          <ModalFooter><Button action="cancel" onClick={() => setChild(false)} /><Button action="done" onClick={() => setChild(false)} /></ModalFooter>
        </Modal>}
      </Modal>}
    </div>
  );
}

function CatalogIndex({ kind }: { kind: 'settings' | 'windows' | 'flows' | 'sites' }) {
  const [query, setQuery] = useState('');
  const match = textMatcher(query);
  const rows = kind === 'sites'
    ? catalogIndex.sites.map((r) => ({ id: r.id, title: r.name, path: r.path, source: r.source, detail: r.status, extra: `Remaining: ${r.gap}` }))
    : kind === 'flows'
    ? catalogIndex.flows.map((r) => ({ id: r.id, title: r.name, path: r.path, source: r.source, detail: r.scope, extra: 'Replay on the target platform before changing its implementation.' }))
    : kind === 'settings'
    ? catalogIndex.settings.map((r) => ({ id: r.id, title: r.name, path: r.path, source: r.source.join('; ') || 'settingsSearch/registry.ts', detail: `${r.gate}. ${r.status}`, extra: r.observed.length ? `Pane/anchor observed: ${r.observed.join(', ')}` : 'No DOM anchor observation recorded.' }))
    : catalogIndex.windows.map((r) => ({ id: `${r.file}:${r.line}`, title: `${r.file}:${r.line}`, path: r.path, source: `${r.file}:${r.line}`, detail: `${r.kind}. ${r.note}`, extra: [
      `Title expression: ${r.title ?? 'Inspect owner or named element'}`,
      `Panel classes: ${r.size ?? 'Inherited from owner'}`,
      `Close handler: ${r.close ?? 'Not explicit at this call site'}`,
      `Escape: ${r.escape ?? 'Inherited; inspect owner'}`,
      `Backdrop: ${r.backdrop ?? 'Inherited; inspect owner'}`,
      `Embedded: ${r.embedded ?? 'Not explicit'}`,
      `Layer: ${r.layer ?? 'Inherited; inspect owner'}`,
      'Runtime exit, draft, focus and keyboard matrix: not established by this source row.',
    ].join('\n') }));
  const found = rows.filter((r) => !query.trim() || match(`${r.title} ${r.path} ${r.source} ${r.detail} ${r.extra}`) !== null);
  return <div className="space-y-3">
    <TextField label={kind === 'sites' ? 'Search public site map' : kind === 'flows' ? 'Search replay recipes' : kind === 'settings' ? 'Search settings map' : 'Search window inventory'} value={query} onChange={(e) => setQuery(e.target.value)} placeholder="Search a label, menu path or source file" />
    <p className={SETTINGS_HELP}>{found.length} of {rows.length} entries · {catalogIndex.scope}</p>
    <div className="max-h-[32rem] overflow-y-auto space-y-2">
      {found.map((r) => <details key={r.id} className="rounded-md border border-divider p-3">
        <summary className="cursor-pointer text-sm font-semibold break-words">{r.title}</summary>
        <div className="mt-2 space-y-2">
          {kind === 'sites' ? <a href={r.path} target="_blank" rel="noopener noreferrer" className="block text-sm text-accent underline break-words">{r.path}</a> : <p className="text-sm break-words">{r.path}</p>}
          <p className={`${SETTINGS_HELP} break-words`}>Source: {r.source}</p>
          <p className={SETTINGS_HELP}>{r.detail}</p>
          <p className={`${SETTINGS_HELP} whitespace-pre-line break-words`}>{r.extra}</p>
        </div>
      </details>)}
      {!found.length && <EmptyState compact>No matching entries. Clear the search or try the source filename.</EmptyState>}
    </div>
  </div>;
}

function Part({ name, note, source, usage, gap, searchText = '', children }: { name: string; note: string; source?: string; usage?: string; gap?: string; searchText?: string; children: ReactNode }) {
  const filter = useContext(CatalogFilter);
  const group = Object.entries(patternGroups).find(([, names]) => names.includes(name))?.[0];
  const matches = (filter.group === 'All patterns' || group === filter.group)
    && (!filter.search.trim() || textMatcher(filter.search)(`${name} ${note} ${source ?? ''} ${usage ?? ''} ${gap ?? ''} ${searchText}`) !== null);
  return (
    <section hidden={!matches} className="space-y-3 rounded-lg border border-divider bg-surface-2 p-4" data-catalog={name}>
      <div>
        <p className={SETTINGS_HELP}>{group}</p>
        <h2 className="text-sm font-semibold">{name}</h2>
        <p className={SETTINGS_HELP}>{note}</p>
        {source && <p className={SETTINGS_HELP}>Source, relative to packages/web/src: {source}</p>}
        {usage && <p className={SETTINGS_HELP}>Real usages: {usage}</p>}
        {gap && <p className={SETTINGS_HELP}>Verification scope: {gap}</p>}
      </div>
      {children}
    </section>
  );
}

function VaultActionsLab() {
  const [isNew, setIsNew] = useState(false);
  const [locked, setLocked] = useState(false);
  const [error, setError] = useState(false);
  const [result, setResult] = useState('No action yet.');
  return <div className="space-y-4">
    <Switch label="New vault item" checked={isNew} onChange={setIsNew} />
    <Switch label="Read-only vault item" checked={locked} onChange={setLocked} />
    <Switch label="Show vault save error" checked={error} onChange={setError} />
    <div className="space-y-4 pt-2">
      <VaultFormActions isNew={isNew} locked={locked} saveError={error ? 'Example save error. Your draft stays here.' : undefined}
        onSave={() => setResult('Save callback called.')} onCancel={() => setResult('Cancel callback called.')} />
    </div>
    <p className={SETTINGS_HELP} role="status">{result}</p>
  </div>;
}

function ExportProgressLab() {
  const [phase, setPhase] = useState('failed');
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open || phase !== 'running') return;
    const timer = window.setTimeout(() => setPhase('complete'), 3000);
    return () => window.clearTimeout(timer);
  }, [open, phase]);
  return <>
    <select aria-label="Export fixture state" className={SETTINGS_SELECT} value={phase} onChange={e => setPhase(e.target.value)}>
      <option value="failed">Failed</option><option value="incomplete">Incomplete</option><option value="complete">Complete</option><option value="running">Running, then completes</option>
    </select>
    <Button action="export" onClick={() => setOpen(true)}>Open export fixture</Button>
    {open && <ExportProgressModal done={phase !== 'running'} status={phase === 'incomplete' ? 'Some files could not be included. Keep your original data.' : phase === 'running' ? 'Preparing the example backup...' : ''} error={phase === 'failed' ? 'The backup could not be created. Try exporting again.' : undefined} onClose={() => setOpen(false)} />}
  </>;
}

function UploadProgressLab() {
  const [phase, setPhase] = useState('mixed');
  const [open, setOpen] = useState(false);
  useEffect(() => {
    if (!open || phase !== 'running') return;
    const timer = window.setTimeout(() => setPhase('complete'), 3000);
    return () => window.clearTimeout(timer);
  }, [open, phase]);
  const entries: FileUploadEntry[] = phase === 'running'
    ? [{ name: 'Example.pdf', size: 1024, status: 'uploading' }, { name: 'Waiting.txt', size: 128, status: 'pending' }]
    : phase === 'complete' ? [{ name: 'Example.pdf', size: 1024, status: 'done' }]
    : phase === 'storage' ? [{ name: 'Example.pdf', size: 1024, status: 'failed', errorCode: 'storage-full' }, { name: 'Kept-on-device.txt', size: 128, status: 'failed', errorCode: 'storage-full-kept' }]
    : [{ name: 'Example.pdf', size: 1024, status: 'done' }, { name: 'A long example filename that must stay within the upload window.txt', size: 128, status: 'failed', error: 'The file could not be uploaded. Try again.' }];
  return <>
    <select aria-label="Upload fixture state" className={SETTINGS_SELECT} value={phase} onChange={e => setPhase(e.target.value)}>
      <option value="mixed">Mixed results</option><option value="storage">Storage failures</option><option value="complete">Complete</option><option value="running">Running, then completes</option>
    </select>
    <Button action="open" onClick={() => setOpen(true)}>Open upload fixture</Button>
    {open && <UploadProgressModal entries={entries} isPro hasStorageSub onOpenUpgrade={() => {}} onManageStorage={() => {}} onClose={() => setOpen(false)} />}
  </>;
}
