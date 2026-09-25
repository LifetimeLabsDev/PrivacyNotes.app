import { useState } from 'react';
import { Trans, useTranslation } from 'react-i18next';
import {
  BUILTIN_TRACKER_COLORS,
  activeMedications,
  type MedicationLogEntry,
  type MedicationStatus,
  type MedicationTemplate,
} from '../trackerTypes';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';
import { X } from '../icons';
import { HoverLabel } from '../HoverLabel';
import { toLocalIso } from '../notesViewUtils';
import { isImeComposing } from '../imeComposing';

// Caps on medication template fields. Long unbroken names/dosages overflow
// the pill row layout (truncation only hides display overflow, not input).
const MED_NAME_MAX = 50;
const MED_DOSAGE_MAX = 30;

/** Today as a LOCAL ISO date, matching how journal entries are filed.
 *  `new Date().toISOString().slice(0, 10)` is the UTC day, which is
 *  tomorrow for anyone east of Greenwich late in the evening - so a
 *  medication could be recorded as starting on a day not yet lived. */
function todayLocalIso(): string {
  return toLocalIso(new Date());
}

/**
 * Medication pill - log per-medication status (taken/skipped), add new
 * templates inline, edit name/dosage, and delete. Templates are persisted
 * at the user-settings level so the same list is available across entries.
 */
export function MedicationPill({
  value,
  expanded,
  onToggle,
  onChange,
  templates,
  onTemplatesChange,
  readOnly,
}: {
  value?: MedicationLogEntry[];
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: MedicationLogEntry[]) => void;
  templates: MedicationTemplate[];
  onTemplatesChange: (meds: MedicationTemplate[]) => void;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  const [addingNew, setAddingNew] = useState(false);
  const [newName, setNewName] = useState('');
  const [newDosage, setNewDosage] = useState('');
  const [confirmDeleteId, setConfirmDeleteId] = useState<string | null>(null);
  const [editingId, setEditingId] = useState<string | null>(null);
  const [editName, setEditName] = useState('');
  const [editDosage, setEditDosage] = useState('');

  const handleDelete = (medId: string) => {
    // Tombstone instead of removing - sync union-merge needs the entry
    // to stay so deletion propagates across devices.
    const now = new Date().toISOString();
    onTemplatesChange(
      templates.map((m) =>
        m.id === medId ? { ...m, deletedAt: now, updatedAt: now } : m
      )
    );
    // The LOG entries stay. This deletes a medication from the list going
    // forward; it is not a claim that the user never took it. Stripping
    // the entry from `value` erased the record for whichever day happened
    // to be open - and on a backfilled entry that is a past day the user
    // was not even looking at. The tombstone already hides the row.
    setConfirmDeleteId(null);
  };

  const startEdit = (med: MedicationTemplate) => {
    setEditingId(med.id);
    setEditName(med.name);
    setEditDosage(med.dosage);
    setConfirmDeleteId(null);
  };

  const saveEdit = () => {
    if (!editingId || !editName.trim()) return;
    const nextDosage = editDosage.trim();
    onTemplatesChange(
      templates.map((m) => {
        if (m.id !== editingId) return m;
        // A dosage change is a medical fact with a date, and the doctor
        // report renders it as a timeline. Overwriting the field in place
        // destroyed every earlier dose - the timeline was permanently
        // empty because nothing ever appended here.
        const changed = nextDosage !== m.dosage;
        return {
          ...m,
          name: editName.trim(),
          dosage: nextDosage,
          // Stamped so the settings merge can tell this edit from the copy
          // another device still holds. Without it the merge fell back to
          // "local wins" and this correction never left the device.
          updatedAt: new Date().toISOString(),
          dosageHistory: changed
            ? [...m.dosageHistory, { dosage: nextDosage, changedAt: todayLocalIso() }]
            : m.dosageHistory,
        };
      })
    );
    setEditingId(null);
  };

  // Only show active (non-tombstoned) meds in the UI.
  const visibleTemplates = activeMedications(templates);

  // Count only entries whose medication is still on the list. A deleted
  // medication keeps its log entries (they are history), so counting them
  // against the visible template count produced labels like "2/1".
  const visibleIds = new Set(visibleTemplates.map((m) => m.id));
  const loggedCount =
    value?.filter((e) => e.status === 'taken' && visibleIds.has(e.medicationId)).length ?? 0;
  const totalCount = visibleTemplates.length;
  const filledLabel =
    totalCount === 0
      ? undefined
      : loggedCount === totalCount
        ? t('medication.takenCount', { count: loggedCount })
        : `${loggedCount}/${totalCount}`;

  const setStatus = (medId: string, status: MedicationStatus) => {
    const current = value ?? [];
    const idx = current.findIndex((e) => e.medicationId === medId);
    if (idx < 0) {
      onChange([...current, { medicationId: medId, status }]);
      return;
    }
    // Tapping the status a medication already carries clears it. There was
    // no way back from a mis-tap: once "taken" was recorded, the day said
    // taken forever, and on a medication log that is the wrong default.
    const next = [...current];
    if (current[idx]!.status === status) {
      next.splice(idx, 1);
    } else {
      next[idx] = { medicationId: medId, status };
    }
    onChange(next);
  };

  const handleAddMed = () => {
    if (!newName.trim()) return;
    const startedAt = todayLocalIso();
    const dosage = newDosage.trim();
    const med: MedicationTemplate = {
      id: crypto.randomUUID(),
      name: newName.trim(),
      dosage,
      timing: 'morning',
      startedAt,
      updatedAt: new Date().toISOString(),
      // The first entry IS the starting dose. Without it the timeline had
      // to print the CURRENT dosage next to the start date, so a med that
      // began at 10mg and moved to 20mg read "Started 20mg" - a wrong
      // fact on a page written for a clinician.
      dosageHistory: dosage ? [{ dosage, changedAt: startedAt }] : [],
    };
    onTemplatesChange([...templates, med]);
    setNewName('');
    setNewDosage('');
    setAddingNew(false);
  };

  return (
    <PillShell
      label={t('labels.meds')}
      color={BUILTIN_TRACKER_COLORS.medication}
      filled={totalCount > 0 && (value?.length ?? 0) > 0}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledLabel}
      icon={TRACKER_ICONS.medication}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-2 min-w-[220px] max-w-[280px] overflow-hidden">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {t('medication.heading')}
        </span>
        {visibleTemplates.length === 0 && !addingNew && (
          <p className="text-[11px] text-neutral-400 dark:text-neutral-500">
            {t('medication.empty')}
          </p>
        )}
        {visibleTemplates.map((med) => {
          const entry = value?.find((e) => e.medicationId === med.id);
          const status = entry?.status;

          // Inline edit mode
          if (editingId === med.id) {
            return (
              <div key={med.id} className="flex flex-col gap-1.5 py-1 border-t border-b border-divider">
                <input
                  type="text"
                  value={editName}
                  maxLength={MED_NAME_MAX}
                  onChange={(e) => setEditName(e.target.value)}
                  className="w-full px-2 py-1 rounded-md text-xs border border-neutral-300 dark:border-neutral-600 bg-surface-0 text-neutral-800 dark:text-neutral-200"
                  autoFocus
                  placeholder={t('medication.namePlaceholder')}
                  onKeyDown={(e) => { if (isImeComposing(e)) return; if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') setEditingId(null); }}
                />
                <input
                  type="text"
                  value={editDosage}
                  maxLength={MED_DOSAGE_MAX}
                  onChange={(e) => setEditDosage(e.target.value)}
                  className="w-full px-2 py-1 rounded-md text-xs border border-neutral-300 dark:border-neutral-600 bg-surface-0 text-neutral-800 dark:text-neutral-200"
                  placeholder={t('medication.dosagePlaceholder')}
                  onKeyDown={(e) => { if (isImeComposing(e)) return; if (e.key === 'Enter') saveEdit(); if (e.key === 'Escape') setEditingId(null); }}
                />
                <div className="flex gap-1">
                  <button
                    type="button"
                    onClick={saveEdit}
                    className="flex-1 px-2 py-1 rounded-md text-[11px] font-medium bg-accent text-white hover:bg-accent-hover"
                  >
                    {t('common:actions.save')}
                  </button>
                  <button
                    type="button"
                    onClick={() => setEditingId(null)}
                    className="px-2 py-1 rounded-md text-[11px] font-medium text-neutral-500 hover:bg-neutral-100 dark:hover:bg-neutral-700"
                  >
                    {t('common:actions.cancel')}
                  </button>
                </div>
              </div>
            );
          }

          // Confirm delete mode
          if (confirmDeleteId === med.id) {
            return (
              <div key={med.id} className="flex items-center justify-between gap-2 py-0.5">
                <span className="text-[11px] text-neutral-600 dark:text-neutral-300">
                  <Trans
                    i18nKey="trackers:medication.confirmRemove"
                    values={{ name: med.name }}
                    components={{ highlight: <span className="font-medium" /> }}
                  />
                </span>
                <div className="flex gap-1">
                  <button
                    type="button"
                    onClick={() => handleDelete(med.id)}
                    className="px-2 py-0.5 rounded text-[10px] font-medium bg-red-500 text-white hover:bg-red-600"
                  >
                    {t('medication.yes')}
                  </button>
                  <button
                    type="button"
                    onClick={() => setConfirmDeleteId(null)}
                    className="px-2 py-0.5 rounded text-[10px] font-medium text-neutral-500 hover:bg-neutral-100 dark:hover:bg-neutral-700"
                  >
                    {t('medication.no')}
                  </button>
                </div>
              </div>
            );
          }

          // Normal row
          return (
            <div key={med.id} className="flex items-center justify-between gap-2">
              <div className="flex-1 min-w-0">
                <div className="flex items-center gap-1 min-w-0">
                  {readOnly ? (
                    <span className="text-xs font-medium text-neutral-700 dark:text-neutral-200 truncate min-w-0">
                      {med.name}
                    </span>
                  ) : (
                    <HoverLabel label={t('medication.editMedication')} position="above">
                    <button
                      type="button"
                      onClick={() => startEdit(med)}
                      className="text-xs font-medium text-neutral-700 dark:text-neutral-200 truncate min-w-0 hover:text-accent dark:hover:text-accent transition-colors text-start"
                      aria-label={t('medication.editMedication')}
                    >
                      {med.name}
                    </button>
                    </HoverLabel>
                  )}
                  {!readOnly && (
                    <HoverLabel label={t('medication.removeMedication')} position="above">
                    <button
                      type="button"
                      onClick={() => setConfirmDeleteId(med.id)}
                      className="shrink-0 p-0.5 text-neutral-300 hover:text-red-400 dark:text-neutral-600 dark:hover:text-red-400 transition-colors"
                      aria-label={t('medication.removeMedication')}
                    >
                      <X size={10} />
                    </button>
                    </HoverLabel>
                  )}
                </div>
                {med.dosage && (
                  <span className="text-[10px] text-neutral-400 dark:text-neutral-500">
                    {med.dosage}
                  </span>
                )}
              </div>
              <div className="flex gap-0.5 shrink-0">
                <MedButton
                  active={status === 'taken'}
                  onClick={() => setStatus(med.id, 'taken')}
                  color="emerald"
                  label={t('medication.taken')}
                />
                <MedButton
                  active={status === 'skipped'}
                  onClick={() => setStatus(med.id, 'skipped')}
                  color="amber"
                  label={t('medication.skip')}
                />
              </div>
            </div>
          );
        })}
        {addingNew ? (
          <div className="flex flex-col gap-1.5 pt-1 border-t border-divider">
            <input
              type="text"
              placeholder={t('medication.namePlaceholder')}
              value={newName}
              maxLength={MED_NAME_MAX}
              onChange={(e) => setNewName(e.target.value)}
              className="w-full px-2 py-1 rounded-md text-xs border border-neutral-300 dark:border-neutral-600 bg-surface-0 text-neutral-800 dark:text-neutral-200"
              autoFocus
              onKeyDown={(e) => { if (e.key === 'Enter' && !isImeComposing(e)) handleAddMed(); }}
            />
            <input
              type="text"
              placeholder={t('medication.dosagePlaceholder')}
              value={newDosage}
              maxLength={MED_DOSAGE_MAX}
              onChange={(e) => setNewDosage(e.target.value)}
              className="w-full px-2 py-1 rounded-md text-xs border border-neutral-300 dark:border-neutral-600 bg-surface-0 text-neutral-800 dark:text-neutral-200"
              onKeyDown={(e) => { if (e.key === 'Enter' && !isImeComposing(e)) handleAddMed(); }}
            />
            <div className="flex gap-1">
              <button
                type="button"
                onClick={handleAddMed}
                className="flex-1 px-2 py-1 rounded-md text-[11px] font-medium bg-accent text-white hover:bg-accent-hover"
              >
                {t('common:actions.add')}
              </button>
              <button
                type="button"
                onClick={() => { setAddingNew(false); setNewName(''); setNewDosage(''); }}
                className="px-2 py-1 rounded-md text-[11px] font-medium text-neutral-500 hover:bg-neutral-100 dark:hover:bg-neutral-700"
              >
                {t('common:actions.cancel')}
              </button>
            </div>
          </div>
        ) : (
          <button
            type="button"
            onClick={() => setAddingNew(true)}
            className="text-[11px] text-accent hover:underline self-start"
          >
            {t('medication.addMedication')}
          </button>
        )}
      </div>
    </PillShell>
  );
}

function MedButton({
  active,
  onClick,
  color,
  label,
}: {
  active: boolean;
  onClick: () => void;
  color: 'emerald' | 'amber';
  label: string;
}) {
  const bg = active
    ? color === 'emerald'
      ? 'bg-emerald-500 text-white'
      : 'bg-amber-500 text-white'
    : 'bg-surface-0 text-neutral-500 dark:text-neutral-400 hover:bg-neutral-200 dark:hover:bg-neutral-700';
  return (
    <button
      type="button"
      onClick={onClick}
      className={`px-2 py-0.5 rounded text-[10px] font-medium transition-colors ${bg}`}
    >
      {label}
    </button>
  );
}
