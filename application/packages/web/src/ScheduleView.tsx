import { useEffect, useState, type ComponentType, type ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { BellSimple, CalendarX, CalendarDots, Check, Clock, Repeat as RepeatGlyph, Sun, X, ArrowRight } from './icons';
import type { LocalNote } from './db';
import { MonthGrid, firstWeekday } from './MonthGrid';
import { formatDay, weekdayDate, weekdayLabel } from './intlFormat';
import { entryDayOf, journalDateOf, type JournalDays } from './notesViewUtils';
import { pushEscapeHandler } from './useEscapeToClose';
import { timeLabel } from './JournalCalendar';
import {
  MAX_ALERTS,
  dayNumber,
  isTime,
  nthOf,
  parseTimeText,
  scheduleOf,
  shiftDay,
  weekdayOf,
  type Alert,
  type Repeat,
  type RepeatUnit,
  type ScheduleEdit,
} from './schedule';
import {
  ALL_DAY_ALERTS,
  TIMED_ALERTS,
  alertLabel,
  alertOrder,
  alertsSummary,
  describeRepeat,
  presetEdit,
  repeatPresets,
  sameRule,
} from './scheduleText';
import { intlLocale } from './languages';
import { askForRemindersOnce } from './notesView/useReminders';

/**
 * The Schedule view of the "..." menu: the day on the grid, then the rows a
 * type gets. An event: Ends, All day, Starts and Ends at, Repeat, Alert. A
 * note or a task list: the same, with "Make this an event to repeat it" in
 * place of Repeat, and Remove from calendar. A journal entry: Entry date, All
 * day, the times and Alert. Repeat, Ends and Alert open their own views
 * inside the same menu, as Color does. Every change goes through `onEdit`,
 * which asks "Change this item?" on a repeating event.
 * Spec: ops/docs/plans/calendar-pillar-spec.md (steps 4, 6 and 7, section 4.4)
 */

/** The menu's own row parts, handed in so the view draws exactly like the menu. */
export type MenuUi = {
  BackRow: ComponentType<{ title: string; onBack: () => void }>;
  Group: ComponentType<{ children: ReactNode }>;
  ActionItem: ComponentType<{ label: ReactNode; icon: ReactNode; onClick: () => void; pro?: boolean; disabled?: boolean; value?: ReactNode; chevron?: boolean; tone?: 'accent' | 'muted' | 'danger' }>;
  ToggleItem: ComponentType<{ label: string; icon: ReactNode; checked: boolean; pro?: boolean; onClick: () => void }>;
};

type Props = {
  ui: MenuUi;
  note: LocalNote;
  /** The occurrence a repeating event was opened on. */
  occurrence: string | null;
  journalDays?: JournalDays;
  onSetJournalDate?: (day: string) => void;
  onSetNoteDate?: (day: string | null) => void;
  onEdit: (edit: ScheduleEdit) => void;
  /** Opens Convert to, where a note becomes an event. */
  onMakeEvent: () => void;
  /** Alerts open (Pro, or the demo). */
  alertsUnlocked: boolean;
  /** Draw the Pro mark (not Pro, the demo included). */
  showPro: boolean;
  onUpgrade: () => void;
  onBack: () => void;
};

type Sub = 'main' | 'ends' | 'repeat' | 'repeatCustom' | 'alerts';

const NO_DAYS: ReadonlySet<string> = new Set();
const FIELD = 'w-[5.5rem] h-8 rounded-md border border-divider bg-surface-1 px-2 text-[13px] text-pn tabular-nums text-center focus:border-accent outline-none';
const SELECT = 'h-8 rounded-md border border-divider bg-surface-1 px-1.5 text-[13px] text-pn focus:border-accent outline-none';

/** A time field: shows the time as the clock setting writes it, takes it as
 *  typed ("15:00", "3pm"), and commits on Enter or when it loses focus. */
function TimeField({ day, value, onCommit, label }: { day: string; value: string | undefined; onCommit: (time: string | null) => void; label: string }) {
  const shown = value ? timeLabel(day, value) : '';
  const [draft, setDraft] = useState<string | null>(null);
  const commit = () => {
    if (draft === null) return;
    const parsed = draft.trim() === '' ? null : parseTimeText(draft);
    setDraft(null);
    if (parsed !== null || draft.trim() === '') onCommit(parsed);
  };
  return (
    <input
      type="text"
      inputMode="text"
      aria-label={label}
      value={draft ?? shown}
      placeholder="--:--"
      onChange={(e) => setDraft(e.target.value)}
      onFocus={(e) => e.currentTarget.select()}
      onBlur={commit}
      onKeyDown={(e) => {
        if (e.key === 'Enter') { e.preventDefault(); commit(); }
        e.stopPropagation();
      }}
      className={FIELD}
    />
  );
}

export default function ScheduleView({
  ui, note, occurrence, journalDays, onSetJournalDate, onSetNoteDate, onEdit, onMakeEvent,
  alertsUnlocked, showPro, onUpgrade, onBack,
}: Props) {
  const { t } = useTranslation('shell');
  const { BackRow, Group, ActionItem, ToggleItem } = ui;
  const [sub, setSub] = useState<Sub>('main');
  useEffect(() => (sub === 'main' ? undefined : pushEscapeHandler(() => setSub(sub === 'repeatCustom' ? 'repeat' : 'main'))), [sub]);

  const journal = note.type === 'journal';
  const event = note.type === 'event';
  const s = scheduleOf(note.trackers as Record<string, unknown> | undefined, note.type, journal ? entryDayOf(note) : journalDateOf(note));
  // The day the view shows: the occurrence a series was opened on.
  const shownDay = s ? (occurrence && s.repeat ? occurrence : s.day) : null;
  const len = s?.end ? dayNumber(s.end) - dayNumber(s.day) : 0;
  const shownEnd = shownDay && len > 0 ? shiftDay(shownDay, len) : null;

  function pickDay(day: string) {
    if (journal) {
      if (day !== entryDayOf(note)) onSetJournalDate?.(day);
      return;
    }
    if (!shownDay) {
      onSetNoteDate?.(day);
      return;
    }
    if (day !== shownDay) onEdit({ shiftDays: dayNumber(day) - dayNumber(shownDay) });
  }

  if (sub === 'ends' && shownDay) {
    return (
      <>
        <BackRow title={t('noteOptionsMenu.ends')} onBack={() => setSub('main')} />
        <div className="flex justify-center px-2 pt-3 pb-2">
          <MonthGrid
            marked={NO_DAYS}
            selected={shownEnd ?? shownDay}
            initialMonth={shownEnd ?? shownDay}
            onPick={(day) => {
              onEdit({ end: day > shownDay ? day : null });
              setSub('main');
            }}
          />
        </div>
        <Group>
          <ActionItem
            label={t('noteOptionsMenu.sameDay')}
            icon={<CalendarDots size={16} aria-hidden="true" />}
            value={!shownEnd ? <Check size={14} aria-hidden="true" /> : undefined}
            onClick={() => { onEdit({ end: null }); setSub('main'); }}
          />
        </Group>
      </>
    );
  }

  if (sub === 'repeat' && shownDay) {
    const current = s?.repeat ?? null;
    return (
      <>
        <BackRow title={t('repeat.label')} onBack={() => setSub('main')} />
        <Group>
          {repeatPresets(s!.day).map(({ key, repeat }) => {
            const on = sameRule(current, repeat);
            return (
              <ActionItem
                key={key}
                label={repeat ? describeRepeat(repeat, s!.day, t) : t('repeat.never')}
                icon={on ? <Check size={16} aria-hidden="true" /> : <span className="inline-block w-4" />}
                onClick={() => {
                  const change = presetEdit(repeat, current);
                  if (change) onEdit(change);
                  setSub('main');
                }}
              />
            );
          })}
          <ActionItem
            label={t('repeat.custom')}
            icon={<span className="inline-block w-4" />}
            chevron
            onClick={() => setSub('repeatCustom')}
          />
        </Group>
      </>
    );
  }

  if (sub === 'repeatCustom' && s) {
    return <CustomRepeat ui={ui} day={s.day} current={s.repeat ?? null} onBack={() => setSub('repeat')} onApply={(r) => { onEdit({ repeat: r }); setSub('main'); }} />;
  }

  if (sub === 'alerts' && s && shownDay) {
    return <AlertsView ui={ui} day={shownDay} timed={!!s.time} alerts={s.alerts ?? []} onBack={() => setSub('main')} onChange={(alerts) => onEdit({ alerts })} />;
  }

  const title = journal ? t('noteOptionsMenu.entryDate') : t('noteOptionsMenu.schedule');
  return (
    <>
      <BackRow title={title} onBack={onBack} />
      <div className="flex justify-center px-2 pt-3 pb-2">
        <MonthGrid
          key={note.id}
          marked={journal ? (journalDays ?? NO_DAYS) : NO_DAYS}
          selected={shownDay ?? undefined}
          initialMonth={shownDay ?? undefined}
          onPick={pickDay}
        />
      </div>
      {s && shownDay && (
        <Group>
          {!journal && (
            <ActionItem
              label={t('noteOptionsMenu.ends')}
              icon={<ArrowRight size={16} aria-hidden="true" />}
              value={shownEnd ? formatDay(shownEnd, 'weekdayDate') : t('noteOptionsMenu.sameDay')}
              chevron
              onClick={() => setSub('ends')}
            />
          )}
          <ToggleItem
            label={t('noteOptionsMenu.allDay')}
            icon={<Sun size={16} aria-hidden="true" />}
            checked={!s.time}
            onClick={() => onEdit(s.time ? { time: null } : { time: '09:00', timeEnd: '10:00' })}
          />
          {s.time && (
            <div className="px-4 py-1.5 flex items-center gap-3 text-[14px] text-pn">
              <Clock size={16} aria-hidden="true" className="shrink-0 text-accent" />
              <span className="flex-1 min-w-0 truncate">{t('noteOptionsMenu.starts')}</span>
              <TimeField day={shownDay} value={s.time} label={t('noteOptionsMenu.starts')} onCommit={(time) => onEdit({ time })} />
            </div>
          )}
          {s.time && (
            <div className="px-4 py-1.5 flex items-center gap-3 text-[14px] text-pn">
              <span className="shrink-0 w-4" />
              <span className="flex-1 min-w-0 truncate">{t('noteOptionsMenu.endsAt')}</span>
              <TimeField day={shownDay} value={s.timeEnd} label={t('noteOptionsMenu.endsAt')} onCommit={(timeEnd) => onEdit({ timeEnd })} />
            </div>
          )}
          {event && (
            <ActionItem
              label={t('repeat.label')}
              icon={<RepeatGlyph size={16} aria-hidden="true" />}
              value={s.repeat ? describeRepeat(s.repeat, s.day, t) : t('repeat.never')}
              chevron
              onClick={() => setSub('repeat')}
            />
          )}
          {(note.type === 'note' || note.type === 'task') && (
            <ActionItem
              label={t('noteOptionsMenu.makeEvent')}
              icon={<RepeatGlyph size={16} aria-hidden="true" />}
              chevron
              onClick={onMakeEvent}
            />
          )}
          <ActionItem
            label={t('alerts.label')}
            icon={<BellSimple size={16} aria-hidden="true" />}
            pro={showPro}
            value={alertsUnlocked ? alertsSummary(s.alerts, shownDay, t) : undefined}
            chevron={alertsUnlocked}
            onClick={() => {
              if (!alertsUnlocked) { onUpgrade(); return; }
              setSub('alerts');
            }}
          />
        </Group>
      )}
      {(note.type === 'note' || note.type === 'task') && s && (
        <Group>
          <ActionItem
            label={t('noteOptionsMenu.removeFromCalendar')}
            icon={<CalendarX size={16} aria-hidden="true" />}
            onClick={() => { onSetNoteDate?.(null); onBack(); }}
          />
        </Group>
      )}
    </>
  );
}

/** The alerts of an item: the presets as switches (five at most), then a
 *  custom row. A timed item counts in minutes before; an all-day item in
 *  days before, at a time. */
function AlertsView({ ui, day, timed, alerts, onBack, onChange }: { ui: MenuUi; day: string; timed: boolean; alerts: Alert[]; onBack: () => void; onChange: (alerts: Alert[]) => void }) {
  const { t } = useTranslation('shell');
  const { BackRow, Group, ActionItem } = ui;
  const allDayAt = alerts.find((a): a is { days: number; at: string } => 'days' in a)?.at ?? '09:00';
  const presets: Alert[] = timed ? TIMED_ALERTS.map((before) => ({ before })) : ALL_DAY_ALERTS.map((days) => ({ days, at: allDayAt }));
  const key = (a: Alert) => ('before' in a ? `b${a.before}` : `d${a.days}@${a.at}`);
  const held = new Set(alerts.map(key));
  const custom = alerts.filter((a) => !presets.some((p) => key(p) === key(a)));
  const full = alerts.length >= MAX_ALERTS;
  const [amount, setAmount] = useState('1');
  const [unit, setUnit] = useState<'minutes' | 'hours' | 'days' | 'weeks'>(timed ? 'hours' : 'days');
  const [at, setAt] = useState(allDayAt);
  const set = (next: Alert[]) => {
    if (next.length > alerts.length) askForRemindersOnce();
    onChange([...next].sort((a, b) => alertOrder(a) - alertOrder(b)));
  };
  function addCustom() {
    const n = Math.max(0, Math.min(999, Number(amount) || 0));
    const a: Alert = timed
      ? { before: n * { minutes: 1, hours: 60, days: 1440, weeks: 10080 }[unit] }
      : { days: Math.min(28, n * (unit === 'weeks' ? 7 : 1)), at: isTime(at) ? at : '09:00' };
    if (!held.has(key(a)) && !full) set([...alerts, a]);
  }
  return (
    <>
      <BackRow title={t('alerts.label')} onBack={onBack} />
      <Group>
        <ActionItem
          label={t('alerts.none')}
          icon={alerts.length === 0 ? <Check size={16} aria-hidden="true" /> : <span className="inline-block w-4" />}
          onClick={() => set([])}
        />
        {presets.map((p) => {
          const on = held.has(key(p));
          return (
            <ActionItem
              key={key(p)}
              label={alertLabel(p, day, t)}
              icon={on ? <Check size={16} aria-hidden="true" /> : <span className="inline-block w-4" />}
              disabled={!on && full}
              onClick={() => set(on ? alerts.filter((a) => key(a) !== key(p)) : [...alerts, p])}
            />
          );
        })}
        {custom.map((a) => (
          <ActionItem
            key={key(a)}
            label={alertLabel(a, day, t)}
            icon={<Check size={16} aria-hidden="true" />}
            value={<X size={13} aria-label={t('alerts.remove', { alert: alertLabel(a, day, t) })} />}
            onClick={() => set(alerts.filter((x) => key(x) !== key(a)))}
          />
        ))}
      </Group>
      <div className="px-4 py-2.5 flex flex-wrap items-center gap-2 text-[13px] text-pn">
        <span className="text-pn-muted">{t('alerts.custom')}</span>
        <input type="number" min={0} max={999} value={amount} onChange={(e) => setAmount(e.target.value)} onKeyDown={(e) => e.stopPropagation()} aria-label={t('alerts.custom')} className={`${FIELD} w-14`} />
        <select value={unit} onChange={(e) => setUnit(e.target.value as typeof unit)} className={SELECT}>
          {(timed ? (['minutes', 'hours', 'days', 'weeks'] as const) : (['days', 'weeks'] as const)).map((u) => (
            <option key={u} value={u}>{t(`alerts.units.${u}`)}</option>
          ))}
        </select>
        {!timed && (
          <>
            <span className="text-pn-muted">{t('alerts.at')}</span>
            <TimeField day={day} value={at} label={t('alerts.at')} onCommit={(v) => v && setAt(v)} />
          </>
        )}
        <button type="button" disabled={full} onClick={addCustom} className="h-8 px-3 rounded-md bg-accent-fill text-white text-[13px] font-medium disabled:opacity-50">
          {t('alerts.add')}
        </button>
        {full && <span className="w-full text-[12px] text-pn-muted">{t('alerts.max')}</span>}
      </div>
    </>
  );
}

/** Custom repeat: every N units, the weekdays of a weekly repeat, the day or
 *  the Nth weekday of a monthly one, and how it ends. */
function CustomRepeat({ ui, day, current, onBack, onApply }: { ui: MenuUi; day: string; current: Repeat | null; onBack: () => void; onApply: (r: Repeat) => void }) {
  const { t } = useTranslation('shell');
  const { BackRow } = ui;
  const [every, setEvery] = useState<RepeatUnit>(current?.every ?? 'week');
  const [interval, setInterval] = useState(String(current?.interval ?? 1));
  const [weekdays, setWeekdays] = useState<number[]>(current?.weekdays ?? [weekdayOf(day)]);
  const [monthly, setMonthly] = useState<'day' | 'weekday'>(current?.monthly ?? 'day');
  const [ends, setEnds] = useState<'never' | 'on' | 'after'>(current?.until ? 'on' : current?.count ? 'after' : 'never');
  const [until, setUntil] = useState(current?.until ?? shiftDay(day, 30));
  const [count, setCount] = useState(String(current?.count ?? 10));
  const n = Math.max(1, Math.min(999, Number(interval) || 1));
  const weekStart = firstWeekday(intlLocale());
  const nth = nthOf(day) > 4 ? -1 : (nthOf(day) as 1 | 2 | 3 | 4);
  const draft: Repeat = {
    every,
    interval: n,
    ...(every === 'week' && weekdays.length ? { weekdays: [...weekdays].sort((a, b) => a - b) } : {}),
    ...(every === 'month' ? { monthly, ...(monthly === 'weekday' ? { nth } : {}) } : {}),
    ...(ends === 'on' ? { until } : {}),
    ...(ends === 'after' ? { count: Math.max(1, Math.min(999, Number(count) || 1)) } : {}),
    ...(current?.skip?.length ? { skip: current.skip } : {}),
  };
  const radio = (on: boolean) => `w-4 h-4 rounded-full border-2 ${on ? 'border-accent bg-accent' : 'border-divider'}`;
  return (
    <>
      <BackRow title={t('repeat.custom')} onBack={onBack} />
      <div className="px-4 py-3 space-y-3 text-[13px] text-pn">
        <div className="flex items-center gap-2">
          <span>{t('repeat.every')}</span>
          <input type="number" min={1} max={999} value={interval} onChange={(e) => setInterval(e.target.value)} onKeyDown={(e) => e.stopPropagation()} aria-label={t('repeat.every')} className={`${FIELD} w-14`} />
          <select value={every} onChange={(e) => setEvery(e.target.value as RepeatUnit)} className={SELECT}>
            {(['day', 'week', 'month', 'year'] as const).map((u) => <option key={u} value={u}>{t(`repeat.units.${u}`, { count: n })}</option>)}
          </select>
        </div>
        {every === 'week' && (
          <div role="group" aria-label={t('repeat.onDays')} className="flex gap-1">
            {Array.from({ length: 7 }, (_, i) => (weekStart + i) % 7).map((w) => {
              const on = weekdays.includes(w);
              return (
                <button
                  key={w}
                  type="button"
                  aria-pressed={on}
                  aria-label={weekdayLabel(weekdayDate(w), 'long')}
                  onClick={() => setWeekdays((cur) => (on ? (cur.length > 1 ? cur.filter((x) => x !== w) : cur) : [...cur, w]))}
                  className={`w-8 h-8 rounded-full text-[12px] font-semibold transition ${on ? 'bg-accent-fill text-white' : 'bg-surface-1 text-pn-muted hover:text-pn'}`}
                >
                  {weekdayLabel(weekdayDate(w), 'narrow')}
                </button>
              );
            })}
          </div>
        )}
        {every === 'month' && (
          <div className="flex flex-col gap-1.5">
            {(['day', 'weekday'] as const).map((m) => (
              <label key={m} className="flex items-center gap-2 cursor-pointer">
                <input type="radio" className="sr-only" checked={monthly === m} onChange={() => setMonthly(m)} />
                <span aria-hidden="true" className={radio(monthly === m)} />
                {m === 'day'
                  ? t('repeat.onDay', { day: Number(day.slice(8, 10)) })
                  : t('repeat.onNth', { nth: t(nth === -1 ? 'repeat.nth.last' : `repeat.nth.${nth}`), weekday: weekdayLabel(weekdayDate(weekdayOf(day)), 'long') })}
              </label>
            ))}
          </div>
        )}
        <div className="flex flex-col gap-1.5">
          <span className="text-pn-muted">{t('repeat.ends')}</span>
          {(['never', 'on', 'after'] as const).map((e) => (
            <label key={e} className="flex items-center gap-2 cursor-pointer min-h-8">
              <input type="radio" className="sr-only" checked={ends === e} onChange={() => setEnds(e)} />
              <span aria-hidden="true" className={radio(ends === e)} />
              <span className="flex-1">{t(e === 'never' ? 'repeat.endsNever' : e === 'on' ? 'repeat.endsOn' : 'repeat.endsAfter')}</span>
              {e === 'on' && ends === 'on' && <span className="tabular-nums text-pn-muted">{formatDay(until, 'date')}</span>}
              {e === 'after' && ends === 'after' && (
                <input type="number" min={1} max={999} value={count} onChange={(ev) => setCount(ev.target.value)} onKeyDown={(ev) => ev.stopPropagation()} aria-label={t('repeat.endsAfter')} className={`${FIELD} w-16`} />
              )}
            </label>
          ))}
          {ends === 'on' && (
            <div className="flex justify-center pt-1">
              <MonthGrid marked={NO_DAYS} selected={until} initialMonth={until} onPick={(d) => setUntil(d < day ? day : d)} />
            </div>
          )}
        </div>
        <p className="text-[12px] text-pn-muted">{describeRepeat(draft, day, t)}</p>
        <button type="button" onClick={() => onApply(draft)} className="w-full h-9 rounded-md bg-accent-fill text-white text-[13px] font-medium">
          {t('repeat.apply')}
        </button>
      </div>
    </>
  );
}

