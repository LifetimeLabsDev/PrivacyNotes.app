import { useMemo } from 'react';
import { PALETTE } from '../editorColors';
import { useTranslation } from 'react-i18next';
import type { TFunction } from 'i18next';
import type { MedicationTemplate } from '../trackerTypes';
import type { TrackerStats } from '../trackerStats';
import { SectionEyebrow } from '../settingsUI';
import { ProMark } from '../UpgradeModal';
import { ArrowsLeftRight, CalendarBlank, ClockCounterClockwise, Pill } from '../icons';
import { formatDay } from '../intlFormat';
import { TrackerChart } from '../TrackerChart';
import { MIN_PER_SIDE } from '../trackerCompare';
import { daysBetween, doseLenses, formatNumber, hasData, type WellnessModel } from './wellnessModel';

/** Up to a month the days fit one strip per medication on the shared axis; a longer range
 *  reads as a week-column calendar, one per medication, like the writing heatmap. */
const STRIP_MAX_DAYS = 31;
const STRIP_HEIGHT = 18;
/** Seven rows of calendar cells at most 14 px each; a long range gets narrower cells. */
const CALENDAR_HEIGHT = 7 * 14 + 6 * 2;

function Legend({ t, dose, round }: { t: TFunction; dose?: boolean; round?: boolean }) {
  const shape = round ? 'rounded-full' : 'rounded-[2px]';
  return (
    <div className="flex flex-wrap gap-3 mt-1 text-[10px] text-pn-muted">
      <span className="inline-flex items-center gap-1"><span className={`w-2.5 h-2.5 ${shape} bg-pn-soft`} />{t('wellness.medCalendar.taken')}</span>
      <span className="inline-flex items-center gap-1"><span className={`w-2.5 h-2.5 ${shape} ${round ? 'border-2 border-pn-soft' : 'bg-pn-soft opacity-30'}`} />{t('wellness.medCalendar.skipped')}, {t('wellness.medCalendar.missed')}</span>
      <span className="inline-flex items-center gap-1"><span className={`w-2.5 h-2.5 ${shape} border border-divider`} />{t('wellness.medCalendar.noEntry')}</span>
      {dose && <span className="inline-flex items-center gap-1"><span style={{ color: PALETTE.orange }}>&#9650;</span>{t('wellness.medCalendar.doseChange')}</span>}
    </div>
  );
}

function MedTimeline({ medications }: { medications: MedicationTemplate[] }) {
  const { t } = useTranslation('stats');
  const meds = medications.filter((m) => m.dosageHistory.length > 0 || m.startedAt);
  if (meds.length === 0) return null;
  return (
    <div className="mt-3 space-y-3">
      <SectionEyebrow icon={ClockCounterClockwise}>{t('wellness.medication.dosageTimeline')}</SectionEyebrow>
      {meds.map((med) => {
        // dosageHistory[0] is the dose the medication STARTED on; `dosage` is the current one.
        const events: { date: string; label: string }[] = [
          // Without a strength the line says only that it started.
          { date: med.startedAt, label: (med.dosageHistory[0]?.dosage || med.dosage) ? t('wellness.medication.started', { dosage: med.dosageHistory[0]?.dosage || med.dosage }) : t('wellness.medication.startedPlain') },
          ...med.dosageHistory.slice(1).map((h) => ({ date: h.changedAt, label: t('wellness.medication.changedTo', { dosage: h.dosage }) })),
        ];
        events.sort((a, b) => a.date.localeCompare(b.date));
        return (
          <div key={med.id} className="ps-2 border-s-2 border-divider space-y-1.5">
            <span className="text-xs font-medium text-pn-soft">{med.name}</span>
            {events.map((ev, i) => (
              <div key={i} className="flex items-center gap-2 ms-2">
                <div className="w-2 h-2 rounded-full bg-accent-fill -ms-[13px]" />
                <span className="text-[10px] text-pn-muted tabular-nums w-20">{formatDay(ev.date, 'date')}</span>
                <span className="text-[11px] text-pn-muted">{ev.label}</span>
              </div>
            ))}
          </div>
        );
      })}
    </div>
  );
}

/** Spec: ops/docs/archive/wellness-statistics.md (section 10) */
export function MedicationSubTab({ model, stats, medications, unlocked, isPro, onOpenDay }: {
  model: WellnessModel;
  stats: TrackerStats;
  medications: MedicationTemplate[];
  unlocked: boolean;
  isPro: boolean;
  onOpenDay?: (date: string) => void;
}) {
  const { t } = useTranslation('stats');
  const { t: tt } = useTranslation('trackers');
  const meds = useMemo(
    () => model.registry.filter((d) => d.kind === 'medication').map((d) => ({ d, series: model.seriesOf(d) })).filter(({ series }) => hasData(series)),
    [model],
  );
  const lenses = useMemo(() => doseLenses(model.entries, medications, model.range), [model, medications]);
  // Dose events inside the range, as marks under the strips, on the same axis.
  const doseMarks = useMemo(() => {
    const out: { date: string; label: string }[] = [];
    for (const m of medications) {
      for (const h of m.dosageHistory) {
        if (h.changedAt >= model.range.from && h.changedAt <= model.range.to) out.push({ date: h.changedAt, label: t('wellness.mood.dose', { name: m.name, dosage: h.dosage }) });
      }
    }
    return out;
  }, [medications, model.range, t]);
  const statusLabel = (v: unknown) =>
    v === 'taken' ? tt('medication.taken') : v === 'skipped' ? tt('medication.skip') : v === 'missed' ? t('wellness.medCalendar.missed') : t('wellness.medCalendar.unmarked');

  if (stats.medBreakdown.length === 0 && meds.length === 0) {
    return (
      <div className="text-center py-8 text-pn-muted">
        <p className="text-sm">{t('wellness.medication.empty.title')}</p>
        <p className="text-xs mt-1">{t('wellness.medication.empty.hint')}</p>
      </div>
    );
  }
  return (
    <>
      {/* No heading over an empty list: the breakdown is empty until a dose is logged. */}
      {stats.medBreakdown.length > 0 && (
      <div>
        <SectionEyebrow className="mb-2" icon={Pill}>{t('wellness.medication.adherence')}</SectionEyebrow>
        <div className="space-y-1.5">
          {stats.medBreakdown.map((m) => (
            <div key={m.id} className="flex items-center gap-2">
              <span className="text-xs text-pn-soft flex-1 truncate">{m.name}</span>
              <div className="w-24 h-3 bg-surface-0 rounded overflow-hidden">
                <div className="h-full rounded" style={{ width: `${m.pct}%`, backgroundColor: m.pct >= 80 ? PALETTE.green : m.pct >= 50 ? PALETTE.yellow : PALETTE.red }} />
              </div>
              <span className="text-[11px] text-pn-muted w-12 text-end">{m.pct}%</span>
            </div>
          ))}
        </div>
      </div>
      )}

      {meds.length > 0 && model.rangeDays <= STRIP_MAX_DAYS && (
        <div>
          <SectionEyebrow className="mb-2" icon={CalendarBlank}>{t('wellness.medCalendar.heading')}</SectionEyebrow>
          <div className="space-y-1.5">
            {meds.map(({ d, series }) => (
              <div key={d.id} className="flex items-center gap-3">
                <span className="text-xs text-pn-soft w-24 flex-none truncate">{d.name}</span>
                <div className="flex-1 min-w-0">
                  <TrackerChart
                    spec={{ form: 'strip', series, color: d.color }}
                    height={STRIP_HEIGHT}
                    ariaLabel={`${d.name}: ${t('wellness.medCalendar.heading')}`}
                    formatValue={statusLabel}
                    onPickDay={onOpenDay}
                  />
                </div>
              </div>
            ))}
          </div>
          <div className="ms-24 ps-3">
            <div className="relative h-4">
              {doseMarks.map((m) => (
                <span
                  key={m.date + m.label}
                  title={`${formatDay(m.date, 'date')}: ${m.label}`}
                  className="absolute -translate-x-1/2 text-[10px] leading-none"
                  style={{ left: `${((daysBetween(model.range.from, m.date) + 0.5) / model.rangeDays) * 100}%`, color: PALETTE.orange }}
                >
                  &#9650;
                </span>
              ))}
            </div>
            <div className="flex justify-between text-[11px] text-pn-muted">
              <span>{formatDay(model.range.from, 'dayMonth')}</span>
              <span>{formatDay(model.range.to, 'dayMonth')}</span>
            </div>
          </div>
          <Legend t={t} dose={doseMarks.length > 0} round />
        </div>
      )}

      {model.rangeDays > STRIP_MAX_DAYS && meds.map(({ d, series }) => (
        <div key={d.id}>
          <SectionEyebrow className="mb-2" icon={CalendarBlank}>{d.name}: {t('wellness.medCalendar.heading')}</SectionEyebrow>
          <TrackerChart
            spec={{ form: 'calendar', series, color: d.color }}
            height={CALENDAR_HEIGHT}
            ariaLabel={`${d.name}: ${t('wellness.medCalendar.heading')}`}
            formatValue={statusLabel}
            onPickDay={onOpenDay}
          />
          <Legend t={t} />
        </div>
      ))}

      {lenses.length > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <SectionEyebrow icon={ArrowsLeftRight}>{t('wellness.medCalendar.doseLensHeading')}</SectionEyebrow>
            {!isPro && <ProMark />}
          </div>
          {unlocked && (
            <div className="space-y-1.5">
              {lenses.map((l) => (
                <div key={l.medicationId + l.date} className="rounded-md bg-track border border-divider px-3 py-2 text-xs text-pn-soft">
                  <span className="text-pn-muted">{formatDay(l.date, 'date')}, {[l.name, l.dosage].filter(Boolean).join(' ')}: </span>
                  {l.before.n >= MIN_PER_SIDE && l.after.n >= MIN_PER_SIDE && l.before.mean !== null && l.after.mean !== null
                    ? t('wellness.medCalendar.doseLens', { before: formatNumber(l.before.mean), nBefore: l.before.n, after: formatNumber(l.after.mean), nAfter: l.after.n })
                    : t('wellness.medCalendar.doseLensShort', { count: MIN_PER_SIDE - Math.min(l.before.n, l.after.n) })}
                </div>
              ))}
            </div>
          )}
        </div>
      )}

      {unlocked && <MedTimeline medications={medications} />}
    </>
  );
}
