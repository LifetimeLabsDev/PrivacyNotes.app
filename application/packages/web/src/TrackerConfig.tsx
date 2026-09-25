/**
 * TrackerConfig - centered modal for configuring tracker pills.
 *
 * Save-on-commit: all edits (builtin toggles, custom tracker changes)
 * stay in local draft state until the user hits Save. This avoids
 * expensive parent re-renders on every checkbox click.
 *
 * Layout: built-in trackers grouped into 3 categories (Mood & mind,
 * Body & health, Lifestyle) in a 2-column checkbox grid. Custom tracker
 * creation is a second view inside the same modal (no stacked modals).
 * Cancel/Save buttons at the bottom.
 */

import { useState, useCallback, useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { createPortal } from 'react-dom';
import { CaretLeft, Check, Gear, Plus, X } from './icons';
import { useEscapeToClose } from './useEscapeToClose';
import { proUnlocked } from './demo';
import { HoverLabel } from './HoverLabel';
import { isImeComposing } from './imeComposing';
import {
  type BuiltinTrackerId,
  type TrackerSettings,
  type CustomTrackerTemplate,
  type CustomTrackerType,
  type TrackerColor,
  BUILTIN_TRACKER_COLORS,
  CUSTOM_TRACKER_TYPE_LABELS,
  TRACKER_COLORS,
  activeCustomTrackers,
} from './trackerTypes';

// ------------------------------------------------------------------
// Props
// ------------------------------------------------------------------

export interface TrackerConfigProps {
  settings: TrackerSettings;
  onChange: (next: TrackerSettings) => void;
  isPro: boolean;
  onOpenUpgrade?: () => void;
  /** When true, the modal opens (controlled by parent). */
  forceOpen?: boolean;
  /** Called when the modal closes (so parent can clear forceOpen). */
  onClose?: () => void;
}

// ------------------------------------------------------------------
// Built-in tracker categories
// ------------------------------------------------------------------

interface TrackerMeta { id: BuiltinTrackerId }

const CATEGORIES: { titleKey: string; trackers: TrackerMeta[] }[] = [
  {
    titleKey: 'config.categoryMoodMind',
    trackers: [
      { id: 'mood' },
      { id: 'emotions' },
      { id: 'focus' },
      { id: 'pain' },
      { id: 'social' },
    ],
  },
  {
    titleKey: 'config.categoryBodyHealth',
    trackers: [
      { id: 'sleep' },
      { id: 'sleepScore' },
      { id: 'heartRate' },
      { id: 'activity' },
      { id: 'medication' },
      { id: 'weight' },
    ],
  },
  {
    titleKey: 'config.categoryLifestyle',
    trackers: [
      { id: 'energy' },
      { id: 'steps' },
      { id: 'water' },
      { id: 'caffeine' },
      { id: 'screenTime' },
    ],
  },
];

// ------------------------------------------------------------------
// Main component
// ------------------------------------------------------------------

export function TrackerConfig({ settings, onChange, isPro, onOpenUpgrade, forceOpen, onClose }: TrackerConfigProps) {
  const { t } = useTranslation('trackers');
  const [ownOpen, setOwnOpen] = useState(false);
  // 'config' = main view, 'add' = custom tracker creation form
  const [view, setView] = useState<'config' | 'add'>('config');

  // Local draft - all edits stay here until Save is clicked.
  // No parent re-renders until commit.
  const [draft, setDraft] = useState(settings);

  const open = ownOpen || !!forceOpen;

  // Snapshot settings into draft when the modal opens; reset view to config.
  // eslint-disable-next-line react-hooks/exhaustive-deps -- only on open transition
  useEffect(() => { if (open) { setDraft(settings); setView('config'); } }, [open]);

  const cancel = useCallback(() => {
    setOwnOpen(false);
    onClose?.();
  }, [onClose]);

  const save = useCallback(() => {
    onChange(draft);
    setOwnOpen(false);
    onClose?.();
  }, [draft, onChange, onClose]);

  const handleEscape = useCallback(() => {
    if (view === 'add') { setView('config'); } else { cancel(); }
  }, [view, cancel]);
  useEscapeToClose(handleEscape, open);

  const toggleBuiltin = useCallback(
    (id: BuiltinTrackerId) => {
      setDraft((prev) => ({
        ...prev,
        activeBuiltins: prev.activeBuiltins.includes(id)
          ? prev.activeBuiltins.filter((x) => x !== id)
          : [...prev.activeBuiltins, id],
      }));
    },
    []
  );

  const addCustom = useCallback(
    (template: CustomTrackerTemplate) => {
      const next = {
        ...draft,
        customTrackers: [
          ...draft.customTrackers,
          { ...template, updatedAt: new Date().toISOString() },
        ],
      };
      setDraft(next);
      onChange(next);
      setView('config');
    },
    [draft, onChange]
  );

  const stopCustom = useCallback(
    (id: string) => {
      setDraft((prev) => ({
        ...prev,
        customTrackers: prev.customTrackers.map((t) =>
          t.id === id
            ? { ...t, stoppedAt: new Date().toISOString(), updatedAt: new Date().toISOString() }
            : t
        ),
      }));
    },
    []
  );

  const resumeCustom = useCallback(
    (id: string) => {
      setDraft((prev) => ({
        ...prev,
        customTrackers: prev.customTrackers.map((t) =>
          t.id === id ? { ...t, stoppedAt: undefined, updatedAt: new Date().toISOString() } : t
        ),
      }));
    },
    []
  );

  const deleteCustom = useCallback(
    (id: string) => {
      // Tombstone, never splice. Dropping the row lets the settings
      // union-merge resurrect it from any device that still has it, and
      // it orphans every journal value logged against this id - nothing
      // else can turn that id back into a name.
      setDraft((prev) => ({
        ...prev,
        customTrackers: prev.customTrackers.map((t) =>
          t.id === id
            ? { ...t, deletedAt: new Date().toISOString(), updatedAt: new Date().toISOString() }
            : t
        ),
      }));
    },
    []
  );

  const visibleCustom = activeCustomTrackers(draft.customTrackers);
  const canAddMore = visibleCustom.length < 10;

  return (
    <>
      <HoverLabel label={t('config.configureTrackers')} position="end">
      <button
        type="button"
        onClick={() => setOwnOpen(true)}
        className="inline-flex items-center justify-center w-7 h-7 shrink-0 self-center rounded-full text-neutral-400 dark:text-neutral-500 hover:text-neutral-600 dark:hover:text-neutral-300 hover:bg-neutral-100 dark:hover:bg-surface-0 transition-colors"
        aria-label={t('config.configureTrackers')}
      >
        <Gear />
      </button>
      </HoverLabel>

      {open && createPortal(
        <div
          className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 z-50"
          onClick={cancel}
        >
          <div
            className="bg-surface-1 border border-divider rounded-lg shadow-lg p-4 w-full max-w-xs max-h-[85dvh] flex flex-col"
            onClick={(e) => e.stopPropagation()}
          >
            {view === 'config' ? (
              <ConfigView
                draft={draft}
                isPro={isPro}
                canAddMore={canAddMore}
                onToggleBuiltin={toggleBuiltin}
                onStopCustom={stopCustom}
                onResumeCustom={resumeCustom}
                onDeleteCustom={deleteCustom}
                onAddCustom={() => { onChange(draft); setView('add'); }}
                onCancel={cancel}
                onSave={save}
                onOpenUpgrade={() => { cancel(); onOpenUpgrade?.(); }}
              />
            ) : (
              <AddCustomView
                onAdd={addCustom}
                onBack={() => setView('config')}
                usedColors={visibleCustom.map((t) => t.color)}
              />
            )}
          </div>
        </div>,
        document.body
      )}
    </>
  );
}

// ------------------------------------------------------------------
// Config view (main tracker list)
// ------------------------------------------------------------------

function ConfigView({
  draft,
  isPro,
  canAddMore,
  onToggleBuiltin,
  onStopCustom,
  onResumeCustom,
  onDeleteCustom,
  onAddCustom,
  onCancel,
  onSave,
  onOpenUpgrade,
}: {
  draft: TrackerSettings;
  isPro: boolean;
  canAddMore: boolean;
  onToggleBuiltin: (id: BuiltinTrackerId) => void;
  onStopCustom: (id: string) => void;
  onResumeCustom: (id: string) => void;
  onDeleteCustom: (id: string) => void;
  onAddCustom: () => void;
  onCancel: () => void;
  onSave: () => void;
  onOpenUpgrade: () => void;
}) {
  const { t } = useTranslation('trackers');
  // Tombstoned trackers stay in the array for the settings union merge,
  // but they are gone as far as the user is concerned.
  const visibleCustom = activeCustomTrackers(draft.customTrackers);
  return (
    <>
      {/* Header - pinned */}
      <div className="flex items-center justify-between mb-3 shrink-0">
        <h3 className="text-sm font-semibold text-neutral-700 dark:text-neutral-200">
          {t('config.title')}
        </h3>
        <button
          type="button"
          onClick={onCancel}
          className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
          aria-label={t('common:actions.close')}
        >
          <X size={18} />
        </button>
      </div>

      {/* Scrollable content - pe-2 keeps the scrollbar off the action text */}
      <div className="flex-1 overflow-y-auto min-h-0 pe-2">
      {/* Categorized built-in toggles */}
      <div className="flex flex-col gap-3">
        {CATEGORIES.map((cat) => (
          <div key={cat.titleKey}>
            <h4 className="text-[10px] uppercase tracking-wide font-semibold text-neutral-400 dark:text-neutral-500 mb-1.5">
              {t(cat.titleKey)}
            </h4>
            <div className="grid grid-cols-2 gap-x-3 gap-y-0.5">
              {cat.trackers.map((meta) => {
                const active = draft.activeBuiltins.includes(meta.id);
                return (
                  <label
                    key={meta.id}
                    className="flex items-center gap-2 cursor-pointer py-1"
                  >
                    <input
                      type="checkbox"
                      checked={active}
                      onChange={() => onToggleBuiltin(meta.id)}
                      className="sr-only peer"
                    />
                    <span
                      className="w-[15px] h-[15px] rounded-[3px] border-[1.5px] flex items-center justify-center transition-colors shrink-0 peer-checked:border-transparent peer-checked:bg-current"
                      style={{
                        borderColor: active ? undefined : '#9CA3AF',
                        color: BUILTIN_TRACKER_COLORS[meta.id],
                      }}
                    >
                      {active && (
                        <Check size={10} className="text-white" />
                      )}
                    </span>
                    <span className={`text-[12px] ${active ? 'font-medium text-neutral-700 dark:text-neutral-200' : 'text-neutral-500 dark:text-neutral-400'}`}>
                      {t(`labels.${meta.id}`)}
                    </span>
                  </label>
                );
              })}
            </div>
          </div>
        ))}
      </div>

      {/* Custom trackers section - Pro, unlocked in the public demo. */}
      <hr className="my-3 border-divider" />
      {proUnlocked(isPro) ? (
        <>
          {visibleCustom.length > 0 && (
            <>
              <h4 className="text-[10px] uppercase tracking-wide font-semibold text-neutral-400 dark:text-neutral-500 mb-1.5">
                {t('config.customHeading')}
              </h4>
              <div className="flex flex-col gap-1 mb-2">
                {visibleCustom.map((ct) => (
                  <div key={ct.id} className="flex items-center gap-2">
                    <span
                      className="w-2.5 h-2.5 rounded-full shrink-0"
                      style={{ backgroundColor: ct.color }}
                    />
                    <span className={`flex-1 min-w-0 text-[12px] truncate ${ct.stoppedAt ? 'text-neutral-400 line-through' : 'text-neutral-700 dark:text-neutral-200'}`}>
                      {ct.name}
                    </span>
                    {ct.stoppedAt ? (
                      <div className="flex gap-2 shrink-0">
                        <button
                          type="button"
                          onClick={() => onResumeCustom(ct.id)}
                          className="text-[11px] text-accent hover:underline py-0.5"
                        >
                          {t('config.resume')}
                        </button>
                        <button
                          type="button"
                          onClick={() => onDeleteCustom(ct.id)}
                          className="text-[11px] text-red-500 hover:underline py-0.5"
                        >
                          {t('common:actions.delete')}
                        </button>
                      </div>
                    ) : (
                      <button
                        type="button"
                        onClick={() => onStopCustom(ct.id)}
                        className="text-[11px] text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 py-0.5 shrink-0"
                      >
                        {t('config.stop')}
                      </button>
                    )}
                  </div>
                ))}
              </div>
            </>
          )}
          {canAddMore ? (
            <button
              type="button"
              onClick={onAddCustom}
              className="w-full flex items-center gap-2.5 p-2.5 rounded-lg bg-surface-0 border border-divider hover:bg-neutral-100 dark:hover:bg-neutral-800 transition-colors text-start"
            >
              <span className="w-7 h-7 rounded-md bg-accent/10 flex items-center justify-center shrink-0">
                <Plus size={15} className="text-accent" />
              </span>
              <span className="flex flex-col">
                <span className="text-[12px] font-medium text-neutral-700 dark:text-neutral-200">
                  {visibleCustom.length > 0
                    ? t('config.addCustomTrackerCount', { count: visibleCustom.length, max: 10 })
                    : t('config.addCustomTracker')}
                </span>
                <span className="text-[10px] text-neutral-400 dark:text-neutral-500">
                  {t('config.addCustomTrackerHint')}
                </span>
              </span>
            </button>
          ) : (
            <p className="text-[11px] text-neutral-400">
              {t('config.maxReached', { max: 10 })}
            </p>
          )}
        </>
      ) : (
        <button
          type="button"
          onClick={onOpenUpgrade}
          className="flex items-center gap-2 py-1.5 w-full text-start group"
        >
          <span className="text-[12px] text-neutral-500 dark:text-neutral-400 group-hover:text-neutral-700 dark:group-hover:text-neutral-200 transition-colors">
            {t('config.customTrackers')}
          </span>
          <span className="inline-flex items-center px-1.5 py-0.5 rounded text-[9px] font-semibold bg-amber-100 dark:bg-amber-900/40 text-amber-700 dark:text-amber-300">
            PRO
          </span>
        </button>
      )}
      </div>

      {/* Cancel / Save - pinned */}
      <div className="flex gap-2 mt-3 shrink-0">
        <button
          type="button"
          onClick={onCancel}
          className="flex-1 rounded-md border border-neutral-300 dark:border-neutral-800 hover:bg-surface-1 px-4 py-2 text-sm transition"
        >
          {t('common:actions.cancel')}
        </button>
        <button
          type="button"
          onClick={onSave}
          className="flex-1 rounded-md bg-accent text-white hover:bg-accent-hover px-4 py-2 text-sm font-medium transition"
        >
          {t('common:actions.save')}
        </button>
      </div>
    </>
  );
}

// ------------------------------------------------------------------
// Add custom tracker view (renders inside the same modal)
// ------------------------------------------------------------------

function AddCustomView({
  onAdd,
  onBack,
  usedColors,
}: {
  onAdd: (t: CustomTrackerTemplate) => void;
  onBack: () => void;
  usedColors: TrackerColor[];
}) {
  const { t } = useTranslation('trackers');
  const [name, setName] = useState('');
  const [type, setType] = useState<CustomTrackerType>('scale10');
  const [color, setColor] = useState<TrackerColor>(
    () => TRACKER_COLORS.find((c) => !usedColors.includes(c)) ?? TRACKER_COLORS[0]
  );

  const handleSubmit = () => {
    if (!name.trim()) return;
    onAdd({
      id: crypto.randomUUID(),
      name: name.trim(),
      type,
      color,
      createdAt: new Date().toISOString().slice(0, 10),
    });
  };

  return (
    <>
      <div className="flex items-center gap-2 mb-3">
        <button
          type="button"
          onClick={onBack}
          className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1"
          aria-label={t('common:actions.back')}
        >
          <CaretLeft size={18} />
        </button>
        <h3 className="text-sm font-semibold text-neutral-700 dark:text-neutral-200">
          {t('config.newCustomTracker')}
        </h3>
      </div>

      <div className="flex flex-col gap-3">
        <input
          type="text"
          placeholder={t('config.trackerNamePlaceholder')}
          value={name}
          onChange={(e) => setName(e.target.value)}
          className="w-full px-3 py-2 rounded-md text-[13px] border border-neutral-300 dark:border-neutral-600 bg-surface-0 text-neutral-800 dark:text-neutral-200"
          autoFocus
          maxLength={24}
          onKeyDown={(e) => { if (e.key === 'Enter' && !isImeComposing(e)) handleSubmit(); }}
        />
        <div className={`text-[11px] text-end -mt-1 ${name.length >= 24 ? 'text-red-500 dark:text-red-400' : 'text-neutral-400 dark:text-neutral-500'}`}>
          {t('config.nameCount', { count: name.length, max: 24 })}
        </div>

        <div className="flex flex-col gap-1.5">
          <span className="text-[11px] text-neutral-500 dark:text-neutral-400">{t('config.typeLabel')}</span>
          <div className="grid grid-cols-2 gap-1.5">
            {(Object.keys(CUSTOM_TRACKER_TYPE_LABELS) as CustomTrackerType[]).map(
              (k) => (
                <button
                  key={k}
                  type="button"
                  onClick={() => setType(k)}
                  className={`px-2 py-2 rounded-md text-[12px] font-medium text-center transition-colors ${
                    type === k
                      ? 'bg-accent text-white'
                      : 'bg-surface-0 text-neutral-600 dark:text-neutral-300 hover:bg-accent/20'
                  }`}
                >
                  {t(`custom.typeLabels.${k}`)}
                </button>
              )
            )}
          </div>
        </div>

        <div className="flex gap-2 items-center">
          <span className="text-[11px] text-neutral-500 dark:text-neutral-400">{t('config.colorLabel')}</span>
          {TRACKER_COLORS.map((c) => (
            <button
              key={c}
              type="button"
              onClick={() => setColor(c)}
              className={`w-6 h-6 rounded-full transition-transform ${color === c ? 'ring-2 ring-offset-1 ring-neutral-400 dark:ring-neutral-500 scale-110' : 'hover:scale-110'}`}
              style={{ backgroundColor: c }}
            />
          ))}
        </div>

        <div className="flex gap-2 pt-1">
          <button
            type="button"
            onClick={handleSubmit}
            disabled={!name.trim()}
            className="flex-1 px-3 py-2 rounded-md text-[12px] font-medium bg-accent text-white hover:bg-accent-hover disabled:opacity-40"
          >
            {t('common:actions.create')}
          </button>
          <button
            type="button"
            onClick={onBack}
            className="px-3 py-2 rounded-md text-[12px] font-medium text-neutral-500 hover:bg-neutral-100 dark:hover:bg-neutral-700"
          >
            {t('common:actions.cancel')}
          </button>
        </div>
      </div>
    </>
  );
}
