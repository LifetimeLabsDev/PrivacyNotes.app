import { toLocalIso } from './notesViewUtils';
import type { MedicationTemplate } from './trackerTypes';
import { currentSchedule, latestRevision, withRevision } from './medicationDoses';

/**
 * The edits of the medication list, shared by the Meds pill and the
 * Medications tab of Settings > Trackers so both write the same rows.
 * Spec: ops/docs/mood-wellness-tracker.md
 */

// Caps on medication template fields. Long unbroken names/dosages overflow
// the pill row layout (truncation only hides display overflow, not input).
export const MED_NAME_MAX = 50;
export const MED_DOSAGE_MAX = 30;

/** Today as a LOCAL ISO date, matching how journal entries are filed: the
 *  date part of `toISOString()` is the UTC day, which is tomorrow for anyone
 *  east of Greenwich late in the evening. */
function todayLocalIso(): string {
  return toLocalIso(new Date());
}

/** The list with a new medication; unchanged when the name is empty. */
export function addMedication(list: readonly MedicationTemplate[], rawName: string, rawDosage: string): MedicationTemplate[] {
  const name = rawName.trim().slice(0, MED_NAME_MAX);
  if (!name) return [...list];
  const startedAt = todayLocalIso();
  const dosage = rawDosage.trim().slice(0, MED_DOSAGE_MAX);
  return [...list, {
    id: crypto.randomUUID(),
    name,
    dosage,
    timing: 'morning',
    startedAt,
    updatedAt: new Date().toISOString(),
    // The first entry IS the starting dose, so the doctor report's timeline
    // never prints today's dose beside the start date.
    dosageHistory: dosage ? [{ dosage, changedAt: startedAt }] : [],
    // The first schedule revision: a template with none was last written by
    // a client that predates schedules, which the settings merge relies on.
    scheduleHistory: [{ id: crypto.randomUUID(), changedAt: startedAt, editedAt: new Date().toISOString(), doses: [{ id: 'main', amount: 1 }] }],
  }];
}

/** The list with one medication tombstoned. The row stays so the union merge
 *  never brings it back, and the log entries stay: removing a medication from
 *  the list is not a claim that it was never taken. */
export function removeMedication(list: readonly MedicationTemplate[], id: string): MedicationTemplate[] {
  const now = new Date().toISOString();
  return list.map((m) => (m.id === id ? { ...m, deletedAt: now, updatedAt: now } : m));
}

/** What the Settings form edits beyond the name and the strength. */
export type MedicationPlan = Pick<MedicationTemplate, 'form' | 'color' | 'asNeeded' | 'maxPerDay' | 'repeat' | 'doses' | 'endsOn' | 'startedAt'>;

/** The schedule of a template, compared to tell a schedule change. */
function scheduleKey(m: MedicationTemplate): string {
  const { doses, asNeeded, maxPerDay, repeat, endsOn } = currentSchedule(m);
  return JSON.stringify([doses, !!asNeeded, maxPerDay ?? null, repeat ?? null, endsOn ?? null]);
}

/**
 * The list with one medication's name, strength and plan set, and a refill
 * when `refill` is a count. A dose change appends to `dosageHistory`. A
 * schedule change appends a whole revision to `scheduleHistory`, effective
 * today (a second change on one day replaces this device's revision of that
 * day), so the days before keep the doses, times and amounts that held on
 * them; the first change of a template from before schedules also records
 * the schedule it had as a baseline at its start. Only a change of a plain field (name, strength, form,
 * color, start) stamps `updatedAt`: the schedule resolves by its revisions
 * and the refills by their ids, so neither must make a stale copy of the
 * other fields win on another device.
 * Spec: ops/docs/mood-wellness-tracker.md section 6.7
 */
export function saveMedication(
  list: readonly MedicationTemplate[],
  id: string,
  rawName: string,
  rawDosage: string,
  plan: MedicationPlan,
  refill?: number | null,
  /** A medication made a moment ago from the form: its history is one
   *  revision, effective on its start day, whatever day that is. */
  fresh = false,
): MedicationTemplate[] {
  const name = rawName.trim().slice(0, MED_NAME_MAX);
  if (!name) return [...list];
  const dosage = rawDosage.trim().slice(0, MED_DOSAGE_MAX);
  const today = todayLocalIso();
  const now = new Date().toISOString();
  return list.map((m) => {
    if (m.id !== id) return m;
    let next: MedicationTemplate = { ...m, name, dosage };
    for (const [k, v] of Object.entries(plan) as [keyof MedicationPlan, unknown][]) {
      if (v === undefined) delete (next as Partial<MedicationTemplate>)[k];
      else (next as unknown as Record<string, unknown>)[k] = v;
    }
    if (!next.startedAt) next.startedAt = m.startedAt;
    const plainChanged = name !== m.name || dosage !== m.dosage || next.form !== m.form || next.color !== m.color || next.startedAt !== m.startedAt;
    if (plainChanged) next.updatedAt = now;
    if (!fresh && dosage !== m.dosage) next.dosageHistory = [...m.dosageHistory, { dosage, changedAt: today }];
    // A start moved earlier or later carries the starting dose with it.
    if (!fresh && next.startedAt !== m.startedAt && next.dosageHistory[0]?.changedAt === m.startedAt) {
      next.dosageHistory = [{ ...next.dosageHistory[0]!, changedAt: next.startedAt }, ...next.dosageHistory.slice(1)];
    }
    if (fresh) {
      // Its starting dose is the dose of its start day, whatever day that is.
      next.dosageHistory = dosage ? [{ dosage, changedAt: next.startedAt }] : [];
      next.scheduleHistory = [currentSchedule(next, crypto.randomUUID(), now)];
      next = withRevision(next, next.scheduleHistory[0]!);
    } else if (scheduleKey(next) !== scheduleKey(m)) {
      const own = (m.scheduleHistory ?? []).filter((h) => h && typeof h.id === 'string');
      const past = own.length ? own : [currentSchedule(m, crypto.randomUUID(), m.updatedAt ?? '')];
      const rev = { ...currentSchedule(next, crypto.randomUUID(), now), changedAt: today < next.startedAt ? next.startedAt : today };
      next.scheduleHistory = [...past.filter((h) => h.changedAt !== rev.changedAt), rev];
      next = withRevision(next, latestRevision(next.scheduleHistory) ?? rev);
    }
    if (typeof refill === 'number' && Number.isFinite(refill) && refill >= 0) {
      next.refills = [...(m.refills ?? []), { id: crypto.randomUUID(), at: now, count: refill }];
    }
    return next;
  });
}
