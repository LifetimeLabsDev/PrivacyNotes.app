import { useTranslation } from 'react-i18next';
import {
  SKIP_REASONS,
  activeMedications,
  type MedicationDose,
  type MedicationLogEntry,
  type MedicationStatus,
  type MedicationTemplate,
  type SkipReason,
} from '../trackerTypes';
import { PillShell } from './PillShell';
import { TRACKER_ICONS } from './icons';
import { CHIP_ADD, PanelQuestion, Segmented, chipClass } from './panelUI';
import { Gear, Plus, Warning, X } from '../icons';
import { formatDay, toLocalIso } from '../intlFormat';
import { timeLabel } from '../JournalCalendar';
import { useTrackerHistory } from '../trackerLastLogged';
import {
  LOW_SUPPLY_DAYS,
  asNeededOn,
  daysLeft,
  doseLogId,
  dosesOf,
  dosesOn,
  isLiveOn,
  logDoseId,
  logsOf,
  newDoseId,
  runsOutOn,
  sortDoses,
  supplyLeft,
} from '../medicationDoses';

/**
 * Medication pill - one row per dose the entry's day asks about (Taken or
 * Skip, a reason under a skip), the as-needed doses of the day with "Log a
 * dose", and the low-supply line. It only logs: medications are added,
 * edited and removed in Settings > Trackers > Medication, which "Change
 * these medications" opens. Spec: ops/docs/mood-wellness-tracker.md section 6.7
 */
export function MedicationPill({
  value,
  day,
  expanded,
  onToggle,
  onChange,
  templates,
  onEditMedications,
  supplyUnlocked = false,
  readOnly,
}: {
  value?: MedicationLogEntry[];
  /** The entry's day; today when the entry carries none. */
  day?: string;
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: MedicationLogEntry[]) => void;
  templates: MedicationTemplate[];
  /** Opens Settings > Trackers > Medication: the one place medications are
   *  added, edited and removed. */
  onEditMedications?: () => void;
  /** Pro or the demo: the low-supply line shows (section 6.7). */
  supplyUnlocked?: boolean;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  const history = useTrackerHistory();

  const today = toLocalIso(new Date());
  const entryDay = day ?? today;
  const isToday = entryDay === today;

  // The medications of this day: a live one the day asks about, an as-needed
  // one, and any one the day already holds a log for, so a log never hides.
  const rows = activeMedications(templates).flatMap((med) => {
    const logs = logsOf(value, med.id);
    if (isLiveOn(med, entryDay) && asNeededOn(med, entryDay)) return [{ med, doses: [] as MedicationDose[], asNeeded: true }];
    const doses = dosesOn(med, entryDay);
    if (doses.length > 0) return [{ med, doses, asNeeded: false }];
    if (logs.length === 0) return [];
    // A day the schedule does not ask about, with logs: scheduled doses show
    // as their rows; doses the schedule never had are as-needed ones.
    const byId = new Map(dosesOf(med).map((d) => [d.id, d]));
    const known = logs.map((l) => byId.get(logDoseId(l.medicationId)));
    if (known.every(Boolean)) return [{ med, doses: sortDoses(known as MedicationDose[]), asNeeded: false }];
    return [{ med, doses: [] as MedicationDose[], asNeeded: true }];
  });

  const hasAny = activeMedications(templates).length > 0;

  // The count on the pill: taken doses out of the scheduled ones. As-needed
  // doses are not owed, so they do not count.
  let expected = 0;
  let taken = 0;
  for (const r of rows) {
    if (r.asNeeded) continue;
    const done = new Set(logsOf(value, r.med.id).filter((l) => l.status === 'taken').map((l) => logDoseId(l.medicationId)));
    expected += r.doses.length;
    taken += r.doses.filter((d) => done.has(d.id)).length;
  }
  const filledLabel =
    expected === 0
      ? undefined
      : taken === expected
        ? t('medication.takenCount', { count: taken })
        : `${taken}/${expected}`;

  const setStatus = (logId: string, status: MedicationStatus) => {
    const current = value ?? [];
    const idx = current.findIndex((e) => e.medicationId === logId);
    // A Taken tap on today's entry records when; a tap on another day does
    // not, because the time it happened is unknown.
    // `ts` lets the merge keep the newer of two taps on one dose.
    const entry: MedicationLogEntry = { medicationId: logId, status, ...(status === 'taken' && isToday ? { at: nowTime() } : {}), ts: new Date().toISOString() };
    if (idx < 0) {
      onChange([...current, entry]);
      return;
    }
    // Tapping the status a medication already carries clears it. There was
    // no way back from a mis-tap: once "taken" was recorded, the day said
    // taken forever, and on a medication log that is the wrong default.
    const next = [...current];
    if (current[idx]!.status === status) {
      next.splice(idx, 1);
    } else {
      next[idx] = entry;
    }
    onChange(next);
  };

  const setReason = (logId: string, reason: SkipReason) => {
    const current = value ?? [];
    onChange(current.map((e) => {
      if (e.medicationId !== logId) return e;
      const ts = new Date().toISOString();
      if (e.reason === reason) { const { reason: _, ...rest } = e; return { ...rest, ts }; }
      return { ...e, reason, ts };
    }));
  };

  // An as-needed dose is a fact of its own, with its own id, so two devices
  // that each log one keep both.
  const logDose = (medId: string) => {
    onChange([...(value ?? []), { medicationId: doseLogId(medId, newDoseId()), status: 'taken', ...(isToday ? { at: nowTime() } : {}), ts: new Date().toISOString() }]);
  };
  const removeDose = (logId: string) => onChange((value ?? []).filter((e) => e.medicationId !== logId));

  // The supply line: a scheduled medication with a week of use or less left.
  const supplyDays = history.map((d) => ({ date: typeof d.journalDate === 'string' ? d.journalDate : '', logs: d.medications }));
  const low = !supplyUnlocked ? [] : rows.flatMap(({ med }) => {
    const count = supplyLeft(med, supplyDays);
    const left = daysLeft(med, count);
    return left !== null && left < LOW_SUPPLY_DAYS ? [{ med, left, date: runsOutOn(med, count, today) }] : [];
  });

  const nameOf = (med: MedicationTemplate) => (
    <span className="flex items-center gap-1.5 min-w-0">
      {med.color && <span aria-hidden="true" className="w-2 h-2 shrink-0 rounded-full" style={{ backgroundColor: med.color }} />}
      <span className="truncate text-[13px] font-medium text-pn">{med.name}</span>
    </span>
  );

  return (
    <PillShell
      label={t('labels.meds')}
      filled={rows.length > 0 && (value?.length ?? 0) > 0}
      expanded={expanded}
      onToggle={onToggle}
      filledLabel={filledLabel}
      icon={TRACKER_ICONS.medication}
      readOnly={readOnly}
    >
      <div className="@container flex flex-col gap-1.5 max-w-[460px]">
        <PanelQuestion>{t('medication.prompt')}</PanelQuestion>
        {onEditMedications && !readOnly && (
          <button
            type="button"
            onClick={onEditMedications}
            className="-mt-3 mb-1 self-start inline-flex items-center gap-1.5 text-xs font-medium text-accent hover:underline"
          >
            <Gear size={14} aria-hidden="true" />
            {t(hasAny ? 'medication.editList' : 'medication.add')}
          </button>
        )}
        {/* No row: either no medication at all, or none is due on this day
            (before its start, after its end, a day its repeat skips). */}
        {rows.length === 0 && (
          <p className="text-xs text-pn-muted">{t(hasAny ? 'medication.noneThisDay' : onEditMedications ? 'medication.emptyAdd' : 'medication.empty')}</p>
        )}
        {rows.map(({ med, doses, asNeeded }) => {
          if (asNeeded) {
            // As needed: today's doses as chips with a remove button, and
            // "Log a dose". The limit is a note, never a lock.
            const logged = logsOf(value, med.id).filter((l) => l.status === 'taken');
            const max = med.maxPerDay;
            const sub = [strengthOn(med, entryDay), max ? t('medication.todayCount', { count: logged.length, max }) : t('medication.asNeeded')].filter(Boolean).join(' · ');
            return (
              <div key={med.id} className="rounded-md border border-divider bg-surface-2 ps-3 pe-1.5 py-1.5">
                {/* The same grid as a dose row: on a narrow panel the button
                    takes a line of its own, so the count is never cut. */}
                <div className="grid grid-cols-[minmax(0,1fr)_auto] @sm:grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-x-2 gap-y-1.5">
                  <div className="min-w-0">
                    {nameOf(med)}
                    <span className="block truncate text-[11px] text-pn-muted">{sub}</span>
                  </div>
                  {!readOnly && (
                    <button type="button" onClick={() => logDose(med.id)} className={`${CHIP_ADD} justify-center order-last col-span-2 @sm:order-none @sm:col-span-1`}>
                      <Plus size={11} aria-hidden="true" />
                      {t('medication.logDose')}
                    </button>
                  )}
                </div>
                {logged.length > 0 && (
                  <div className="flex flex-wrap gap-1.5 mt-1.5">
                    {logged.map((l) => {
                      const label = l.at ? timeLabel(entryDay, l.at) : t('medication.dose');
                      return (
                        <span key={l.medicationId} className={chipClass(true)}>
                          {label}
                          {!readOnly && (
                            <button type="button" onClick={() => removeDose(l.medicationId)} aria-label={t('medication.removeDose', { time: label })} className="ms-1 -me-1 inline-flex items-center justify-center w-4 h-4 rounded hover:bg-pn/10">
                              <X size={10} aria-hidden="true" />
                            </button>
                          )}
                        </span>
                      );
                    })}
                  </div>
                )}
                {max !== undefined && logged.length >= max && (
                  <p className="mt-1.5 text-[11px] text-warning">{t('medication.limitReached')}</p>
                )}
              </div>
            );
          }

          // One card per dose: the name and dose, the answer for the day, and
          // the quiet edit and remove buttons on the first dose. On a narrow
          // panel the answer takes a second line of its own, full width, so
          // the name is never cut to a few letters.
          return doses.map((dose, i) => {
            const logId = doseLogId(med.id, dose.id);
            const log = value?.find((e) => e.medicationId === logId);
            const when = dose.time ? timeLabel(entryDay, dose.time) : doses.length > 1 ? t('medication.doseN', { n: i + 1 }) : '';
            const sub = [
              i === 0 || doses.length === 1 ? strengthOn(med, entryDay) : '',
              when,
              log?.status === 'taken' && log.at ? t('medication.takenAt', { time: timeLabel(entryDay, log.at) }) : '',
            ].filter(Boolean).join(' · ');
            return (
              <div key={logId} className="rounded-md border border-divider bg-surface-2 ps-3 pe-1.5 py-1.5">
                <div className="grid grid-cols-[minmax(0,1fr)_auto] @sm:grid-cols-[minmax(0,1fr)_auto_auto] items-center gap-x-2 gap-y-1.5">
                  <div className="min-w-0">
                    {nameOf(med)}
                    {sub && <span className="block truncate text-[11px] text-pn-muted">{sub}</span>}
                  </div>
                  <Segmented
                    tone="status"
                    ariaLabel={when ? `${med.name}, ${when}` : med.name}
                    options={[{ key: 'taken', label: t('medication.taken') }, { key: 'skipped', label: t('medication.skip') }]}
                    value={log?.status === 'missed' ? null : (log?.status ?? null)}
                    onPick={(st) => setStatus(logId, st)}
                    className={`order-last col-span-2 @sm:order-none @sm:col-span-1 ${i === 0 ? '' : '@sm:col-span-2'}`}
                  />
                </div>
                {log?.status === 'skipped' && !readOnly && (
                  <div role="group" aria-label={t('medication.skipWhy')} className="flex flex-wrap items-center gap-1.5 mt-1.5">
                    <span className="text-[11px] text-pn-muted me-0.5">{t('medication.skipWhy')}</span>
                    {SKIP_REASONS.map((r) => (
                      <button key={r} type="button" aria-pressed={log.reason === r} onClick={() => setReason(logId, r)} className={chipClass(log.reason === r)}>
                        {t(`medication.reasons.${r}`)}
                      </button>
                    ))}
                  </div>
                )}
              </div>
            );
          });
        })}
        {low.map(({ med, left, date }) => (
          <p key={med.id} className="flex items-center gap-1.5 text-[11px] text-warning">
            <Warning size={12} aria-hidden="true" />
            {date ? t('medication.lowSupplyOn', { name: med.name, count: left, date: formatDay(date, 'date') }) : t('medication.lowSupply', { name: med.name, count: left })}
          </p>
        ))}
      </div>
    </PillShell>
  );
}

/** The strength a day was taken at: the last dose change on or before it,
 *  so a past entry keeps the dose of its day after a change. */
function strengthOn(med: MedicationTemplate, day: string): string {
  let at = '';
  for (const h of med.dosageHistory) if (h.changedAt <= day) at = h.dosage;
  return at || med.dosage;
}

/** The local time now, `HH:MM`. */
function nowTime(): string {
  const d = new Date();
  return `${String(d.getHours()).padStart(2, '0')}:${String(d.getMinutes()).padStart(2, '0')}`;
}
