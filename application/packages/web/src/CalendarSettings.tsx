import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowLineDown, BellRinging, BellSimple, CalendarDots, Cake, Check, Clock, Devices, Hash, Eye, Sun } from './icons';
import { ROW_TITLE, RowTitle, SectionEyebrow, SETTINGS_HELP, SETTINGS_ROW } from './settingsUI';
import { Switch } from './Switch';
import { IconUpgrade } from './UpgradeModal';
import { formatDay, toLocalIso } from './intlFormat';
import { isTime, parseTimeText } from './schedule';
import { alertLabel, ALL_DAY_ALERTS, TIMED_ALERTS } from './scheduleText';
import { timeLabel } from './JournalCalendar';
import type { CalendarSettings as Settings } from './userSettings';
import { askReminderPermission, openReminderSettings, useReminderPermission, useRemindersThrough, REMINDER_PLATFORM } from './notesView/useReminders';

/**
 * Settings › Date & Time › Calendar: the default alerts (Pro), whether a reminder shows the
 * title, where reminders ring on this device, the week numbers and the hours
 * the hour grid opens on. Every value syncs; where a reminder rings is this
 * device's own answer.
 * Spec: ops/docs/plans/calendar-pillar-spec.md (decisions 11, 12, 15; step 7)
 */

const SELECT = 'rounded-md bg-track border border-divider px-2.5 py-1.5 text-sm text-pn focus:border-accent focus:outline-none';
const FIELD = 'w-24 rounded-md bg-track border border-divider px-2.5 py-1.5 text-sm text-pn text-center tabular-nums focus:border-accent focus:outline-none';
const NONE = 'none';

/** A time typed into a field, committed on blur or Enter. */
function TimeInput({ value, onCommit, label }: { value: string; onCommit: (t: string) => void; label: string }) {
  const today = toLocalIso(new Date());
  const [draft, setDraft] = useState<string | null>(null);
  const commit = () => {
    if (draft === null) return;
    const parsed = parseTimeText(draft);
    setDraft(null);
    if (parsed) onCommit(parsed);
  };
  return (
    <input
      type="text"
      aria-label={label}
      value={draft ?? timeLabel(today, value)}
      onChange={(e) => setDraft(e.target.value)}
      onFocus={(e) => e.currentTarget.select()}
      onBlur={commit}
      onKeyDown={(e) => { if (e.key === 'Enter') { e.preventDefault(); commit(); } }}
      className={FIELD}
    />
  );
}

export function CalendarSettings({ value, onChange, alertsUnlocked, showPro, onUpgrade }: {
  value: Settings;
  onChange: (next: Settings) => void;
  alertsUnlocked: boolean;
  showPro: boolean;
  onUpgrade: () => void;
}) {
  const { t } = useTranslation('settings');
  const { t: ts } = useTranslation('shell');
  const today = toLocalIso(new Date());
  const through = useRemindersThrough();
  const permission = useReminderPermission();
  const set = (patch: Partial<Settings>) => onChange({ ...value, ...patch });
  const pro = showPro ? <IconUpgrade size={12} /> : null;
  const guard = (fn: () => void) => () => (alertsUnlocked ? fn() : onUpgrade());

  const dayAlertRow = (icon: typeof Sun, title: string, current: { days: number; at: string } | null, write: (v: { days: number; at: string } | null) => void) => (
    <div className={SETTINGS_ROW}>
      <RowTitle icon={icon}>{title}</RowTitle>
      <div className="flex items-center gap-2 text-sm">
        <select
          value={current === null ? NONE : String(current.days)}
          onChange={(e) => guard(() => write(e.target.value === NONE ? null : { days: Number(e.target.value), at: current?.at ?? '09:00' }))()}
          aria-label={title}
          className={SELECT}
        >
          <option value={NONE}>{ts('alerts.none')}</option>
          {ALL_DAY_ALERTS.map((days) => (
            <option key={days} value={days}>{days === 0 ? ts('alerts.onDay') : ts('alerts.daysBefore', { count: days })}</option>
          ))}
        </select>
        {current && <>
          <span className="text-pn-muted">{ts('alerts.at')}</span>
          <TimeInput value={current.at} label={title} onCommit={(at) => guard(() => write({ ...current, at }))()} />
        </>}
      </div>
    </div>
  );

  return (
    <div className="flex-1 min-h-0 overflow-y-auto text-pn">
      <SectionEyebrow icon={CalendarDots} className="px-6 pt-4">{t('calendar.groupView')}</SectionEyebrow>
      <div className="px-6 divide-y divide-divider">
        <Switch
          setting="calendar.weekNumbers"
          label={t('calendar.weekNumbers')}
          icon={<Hash size={14} className="text-accent" />}
          labelClassName={ROW_TITLE}
          description={t('calendar.weekNumbersHelp')}
          checked={value.weekNumbers}
          onChange={(on) => set({ weekNumbers: on })}
          className="py-3"
        />
        <div data-setting="calendar.hours" className={SETTINGS_ROW}>
          <div className="min-w-0">
            <RowTitle icon={ArrowLineDown}>{t('calendar.hours')}</RowTitle>
            <p className={`${SETTINGS_HELP} mt-0.5`}>{t('calendar.hoursHelp')}</p>
          </div>
          <TimeInput value={value.hourStart} label={t('calendar.hours')} onCommit={(v) => isTime(v) && set({ hourStart: v })} />
        </div>
      </div>
      <SectionEyebrow icon={BellRinging} className="px-6 pt-6">{t('calendar.groupReminders')}</SectionEyebrow>
      <div className="px-6 divide-y divide-divider">
        <div data-setting="calendar.where" className={`${SETTINGS_ROW}`}>
          <div className="min-w-0">
            <RowTitle icon={Devices}>{t('calendar.whereTitle')}</RowTitle>
            <p className={`${SETTINGS_HELP} mt-0.5`}>{t(`calendar.reminderHint.${REMINDER_PLATFORM}`)}</p>
            {through && <p className={`${SETTINGS_HELP} mt-0.5`}>{t('calendar.scheduledThrough', { date: formatDay(through, 'date') })}</p>}
            {permission === 'denied' && <p className={`${SETTINGS_HELP} mt-0.5`}>{t('calendar.permissionDenied')}</p>}
          </div>
          {permission === 'prompt' && (
            <button
              type="button"
              onClick={() => void askReminderPermission().catch(() => {})}
              className="rounded-md bg-accent-fill text-white px-3 py-1.5 text-sm font-medium hover:bg-accent-fill-hover transition"
            >
              {t('calendar.permissionAsk')}
            </button>
          )}
          {permission === 'granted' && (
            <span role="status" className="shrink-0 inline-flex items-center gap-1.5 rounded-md bg-track px-3 py-1.5 text-sm text-pn-muted">
              <Check size={14} aria-hidden="true" />
              {t('calendar.permissionGranted')}
            </span>
          )}
          {permission === 'denied' && REMINDER_PLATFORM === 'mobile' && (
            <button
              type="button"
              onClick={() => void openReminderSettings().catch(() => {})}
              className="shrink-0 rounded-md border border-divider px-3 py-1.5 text-sm font-medium text-pn hover:bg-track transition"
            >
              {t('calendar.permissionOpenSettings')}
            </button>
          )}
        </div>
        <Switch
          setting="calendar.reminderTitles"
          label={t('calendar.reminderTitles')}
          icon={<Eye size={14} className="text-accent" />}
          labelClassName={ROW_TITLE}
          description={t('calendar.reminderTitlesHelp')}
          checked={value.reminderTitles}
          onChange={(on) => set({ reminderTitles: on })}
          className="py-3"
        />
      </div>
      <SectionEyebrow icon={BellSimple} className="px-6 pt-6">{t('calendar.groupDefaults')} {pro}</SectionEyebrow>
      <p className={`${SETTINGS_HELP} px-6 mt-1`}>{t('calendar.alertsHelp')}</p>
      <div className="px-6 pb-4 divide-y divide-divider">
        <div data-setting="calendar.alertTimed" className={SETTINGS_ROW}>
          <RowTitle icon={Clock}>{t('calendar.alertTimed')}</RowTitle>
          <select
            value={value.alertTimed === null ? NONE : String(value.alertTimed)}
            onChange={(e) => guard(() => set({ alertTimed: e.target.value === NONE ? null : Number(e.target.value) }))()}
            aria-label={t('calendar.alertTimed')}
            className={SELECT}
          >
            <option value={NONE}>{ts('alerts.none')}</option>
            {TIMED_ALERTS.map((before) => (
              <option key={before} value={before}>{alertLabel({ before }, today, ts)}</option>
            ))}
          </select>
        </div>
        <div data-setting="calendar.alertAllDay">{dayAlertRow(Sun, t('calendar.alertAllDay'), value.alertAllDay, (v) => set({ alertAllDay: v }))}</div>
        <div data-setting="calendar.alertBirthday">{dayAlertRow(Cake, t('calendar.alertBirthday'), value.alertBirthday, (v) => set({ alertBirthday: v }))}</div>
      </div>
    </div>
  );
}

