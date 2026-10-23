import { useSyncExternalStore } from 'react';
import { isDemoMode } from './demo';
import { activeMedications, type MedicationLogEntry, type MedicationTemplate } from './trackerTypes';
import type { ReminderItem } from './reminders';
import type { Repeat } from './schedule';
import { asNeededOn, doseLogId, dosesOf, firstRepeatDay, isLiveOn } from './medicationDoses';

/**
 * Medication reminders. The switch is THIS device's, like the check-in
 * reminder: a list of template ids in local storage, never synced, so a phone
 * and a desktop ring only where the person switched it on. Each dose with a
 * time becomes one item of the reminder plan in useReminders. The text never
 * names the medication.
 * Spec: ops/docs/mood-wellness-tracker.md section 6.7
 */

/** The prefix of a medication reminder's item id: `medication:<templateId>:<doseId>`. */
export const MEDICATION_REMINDER_PREFIX = 'medication:';

const storeKey = () => (isDemoMode() ? 'privacynotes.demo.medicationReminders' : 'privacynotes.medicationReminders');
const listeners = new Set<() => void>();
/** The list when storage refuses it (a private window): this page only. */
let pageList: string[] | null = null;
let cached: { raw: string | null; ids: readonly string[] } = { raw: null, ids: [] };

function read(): readonly string[] {
  let raw: string | null = null;
  try {
    raw = localStorage.getItem(storeKey());
  } catch {
    return pageList ?? [];
  }
  if (raw === null && pageList) return pageList;
  if (raw === cached.raw) return cached.ids;
  let ids: string[] = [];
  try {
    const parsed: unknown = raw ? JSON.parse(raw) : [];
    if (Array.isArray(parsed)) ids = parsed.filter((x): x is string => typeof x === 'string');
  } catch {
    // A damaged value reads as no reminders.
  }
  cached = { raw, ids };
  return ids;
}

/** The template ids that ring on this device. */
export function useMedicationReminders(): readonly string[] {
  return useSyncExternalStore((l) => { listeners.add(l); return () => { listeners.delete(l); }; }, read);
}

/** Switch one medication's reminder on or off on this device. */
export function setMedicationReminder(id: string, on: boolean): void {
  const now = read();
  const next = on ? (now.includes(id) ? [...now] : [...now, id]) : now.filter((x) => x !== id);
  pageList = next;
  try {
    localStorage.setItem(storeKey(), JSON.stringify(next));
  } catch {
    // Storage refused: `pageList` holds it for this page.
  }
  listeners.forEach((l) => l());
}

/**
 * The plan items of the medications that ring here: one per dose with a
 * time, on the medication's own repeat counted from its start, until its end
 * day. A dose already logged takes its day out (today, and yesterday for a
 * snooze past midnight), so a reminder never asks about a dose that is done. As needed and ended medications ring never.
 */
export function medicationReminderItems(
  medications: readonly MedicationTemplate[],
  ringing: readonly string[],
  today: string,
  /** The logs of today and of yesterday, by day: a snooze set late in the
   *  evening reaches past midnight, so a dose logged yesterday must keep
   *  yesterday out too. */
  logsByDay: Readonly<Record<string, readonly MedicationLogEntry[] | undefined>>,
): ReminderItem[] {
  if (ringing.length === 0) return [];
  const days = Object.keys(logsByDay).sort();
  const out: ReminderItem[] = [];
  for (const med of activeMedications([...medications])) {
    if (!ringing.includes(med.id) || med.asNeeded) continue;
    if (med.endsOn && med.endsOn < today) continue;
    for (const dose of dosesOf(med)) {
      if (!dose.time) continue;
      const base: Repeat = med.repeat ?? { every: 'day', interval: 1 };
      const logId = doseLogId(med.id, dose.id);
      const skip = days.filter((day) => isLiveOn(med, day) && !asNeededOn(med, day) && (logsByDay[day] ?? []).some((l) => l.medicationId === logId));
      const repeat: Repeat = {
        ...base,
        ...(med.endsOn ? { until: med.endsOn } : {}),
        ...(skip.length ? { skip } : {}),
      };
      out.push({
        id: `${MEDICATION_REMINDER_PREFIX}${med.id}:${dose.id}`,
        // The anchor is the first day the repeat falls on: the calendar's
        // repeat always holds its start day, which a weekday schedule may not.
        schedule: { day: firstRepeatDay(med.startedAt, base), time: dose.time, repeat, alerts: [{ before: 0 }] },
        title: '',
        gated: true,
      });
    }
  }
  return out;
}
