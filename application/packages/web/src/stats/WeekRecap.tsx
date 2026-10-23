import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import { CaretLeft, CaretRight } from '../icons';
import { MoodMark } from '../moodMark';
import { formatDay, weekdayLabel } from '../intlFormat';
import { toLocalIso } from '../notesViewUtils';
import { FIELD_CLASS, IconButton } from '../ui';
import { visibleInUi } from '../trackerRegistry';
import type { TrackerDescriptor } from '../wellnessTypes';
import { trackerName, type WellnessModel } from './wellnessModel';
import { StatPill, changeTone, signedValue, spreadOf } from './statsParts';

/** The changes the recap names, biggest first, and the days each week needs for a change to count. */
const CHANGES_MAX = 3;
const CHANGE_MIN_DAYS = 3;
/** A change smaller than this share of the tracker's spread is not named. */
const CHANGE_MIN_SHARE = 0.05;

function shift(day: string, n: number): string {
  const d = new Date(`${day}T12:00:00`);
  d.setDate(d.getDate() + n);
  return toLocalIso(d);
}

/** A sentence that opens with a weekday name, which many languages write in lowercase, still opens with a capital. */
function upperFirst(text: string): string {
  return text.charAt(0).toLocaleUpperCase() + text.slice(1);
}

/** The Monday of the week `day` falls in. */
function mondayOf(day: string): string {
  const wd = (new Date(`${day}T12:00:00`).getDay() + 6) % 7;
  return shift(day, -wd);
}

/**
 * The weekly recap: one calendar week, Monday to Sunday, with the earlier
 * weeks a step away. The mood of each day on its square, the best and the
 * hardest day in one sentence, the biggest changes against the week before
 * as pills, the week's other numbers, and the reflection: editable for this
 * week, read back for an earlier one.
 * Spec: ops/docs/archive/wellness-statistics.md (section 22)
 */
export function WeekRecap({ model, notes, reflection, onReflectionChange }: {
  model: WellnessModel;
  notes: LocalNote[];
  reflection?: string;
  onReflectionChange?: (text: string) => void;
}) {
  const { t } = useTranslation('stats');
  const today = toLocalIso(new Date());
  const [back, setBack] = useState(0);
  const first = model.firstDay;
  const monday = shift(mondayOf(today), -7 * back);
  const days = Array.from({ length: 7 }, (_, i) => shift(monday, i));
  const prevMonday = shift(monday, -7);
  const canGoBack = first !== null && prevMonday >= mondayOf(first);

  const byDate = useMemo(() => new Map(model.entries.map((e) => [e.date, e.data])), [model.entries]);
  const mood = model.byId('mood');
  const moodOf = (day: string) => {
    const data = byDate.get(day);
    const v = data && mood ? mood.read(data) : undefined;
    return typeof v === 'number' ? v : null;
  };
  const moods = days.map((d) => ({ day: d, v: d > today ? null : moodOf(d) }));
  const logged = moods.filter((m) => m.v !== null);
  const best = logged.length >= 2 ? logged.reduce((a, b) => (b.v! > a.v! ? b : a)) : null;
  const worst = logged.length >= 2 ? logged.reduce((a, b) => (b.v! < a.v! ? b : a)) : null;
  const dayName = (day: string) => weekdayLabel(new Date(`${day}T12:00:00`), 'long');

  // The numeric trackers whose weekly average moved most against the week before, as a share of each one's spread.
  const changes = useMemo(() => {
    const avgOver = (d: TrackerDescriptor, from: string) => {
      const vals: number[] = [];
      for (let i = 0; i < 7; i++) {
        const data = byDate.get(shift(from, i));
        const v = data ? d.read(data) : undefined;
        if (typeof v === 'number') vals.push(v);
      }
      return vals.length >= CHANGE_MIN_DAYS ? vals.reduce((a, b) => a + b, 0) / vals.length : null;
    };
    return model.registry
      .filter((d) => (d.kind === 'scale' || d.kind === 'measure') && d.id !== 'mood' && visibleInUi(d))
      .map((d) => {
        const now = avgOver(d, monday);
        const before = avgOver(d, prevMonday);
        if (now === null || before === null) return null;
        const delta = now - before;
        return { d, delta, share: Math.abs(delta) / spreadOf(d, model.seriesOf(d)) };
      })
      .filter((x): x is { d: TrackerDescriptor; delta: number; share: number } => x !== null && x.share >= CHANGE_MIN_SHARE)
      .sort((a, b) => b.share - a.share)
      .slice(0, CHANGES_MAX);
  }, [model, byDate, monday, prevMonday]);

  const created = notes.filter((n) => n.deleted === 0 && n.trashed === 0 && n.type !== 'journal' && days.includes(toLocalIso(new Date(n.createdAt)))).length;
  const pastReflection = back > 0 ? (byDate.get(monday) as { weekReflection?: unknown } | undefined)?.weekReflection : undefined;

  return (
    <div className="rounded-lg border border-divider bg-surface-2 p-3 space-y-3">
      <div className="flex items-center justify-between gap-2">
        <IconButton label={t('recap.previous')} onClick={() => setBack((b) => b + 1)} disabled={!canGoBack}>
          <CaretLeft size={14} aria-hidden="true" />
        </IconButton>
        <span className="text-sm font-semibold text-pn">
          {back === 0 ? t('recap.thisWeek') : t('wellness.week.range', { start: formatDay(days[0]!, 'dayMonth'), end: formatDay(days[6]!, 'dayMonth') })}
        </span>
        <IconButton label={t('recap.next')} onClick={() => setBack((b) => Math.max(0, b - 1))} disabled={back === 0}>
          <CaretRight size={14} aria-hidden="true" />
        </IconButton>
      </div>

      <div className="grid grid-cols-7 gap-1.5 text-center">
        {moods.map(({ day, v }) => (
          <div key={day} className="flex flex-col items-center gap-1">
            {v !== null ? <MoodMark mood={v} size={30} /> : <span className={`w-[30px] h-[30px] rounded-md ${day > today ? '' : 'border border-dashed border-divider'}`} />}
            <span className="text-[11px] text-pn-muted">{weekdayLabel(new Date(`${day}T12:00:00`), 'narrow')}</span>
          </div>
        ))}
      </div>

      {best && worst && best.day !== worst.day ? (
        <p className="text-sm text-pn">{upperFirst(t('recap.bestWorst', { best: dayName(best.day), bestMood: best.v, worst: dayName(worst.day), worstMood: worst.v }))}</p>
      ) : logged.length === 0 ? (
        <p className="text-xs text-pn-muted">{t('recap.noMood')}</p>
      ) : null}

      {changes.length > 0 && (
        <div className="flex flex-wrap gap-1.5">
          {changes.map(({ d, delta }) => {
            const tone = changeTone(d, delta);
            return (
              <StatPill key={d.id} tone={tone === 'neutral' ? 'neutral' : tone}>
                {trackerName(d, t)} {signedValue(d, delta, t)}
              </StatPill>
            );
          })}
        </div>
      )}

      <p className="text-[11px] text-pn-muted">
        {t('recap.also', { logged: logged.length, created })}
        {changes.length > 0 && ` ${t('recap.againstWeekBefore')}`}
      </p>

      {back === 0 && onReflectionChange ? (
        <textarea
          aria-label={t('wellness.week.reflection')}
          placeholder={best ? t('recap.prompt', { day: dayName(best.day) }) : t('wellness.week.reflectionPlaceholder')}
          className={`${FIELD_CLASS} resize-none h-16`}
          value={reflection ?? ''}
          onChange={(e) => onReflectionChange(e.target.value)}
        />
      ) : typeof pastReflection === 'string' && pastReflection.trim() ? (
        <p className="rounded-md bg-surface-0 p-2 text-xs text-pn-soft whitespace-pre-wrap">{pastReflection}</p>
      ) : null}
    </div>
  );
}

