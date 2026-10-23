import type { TFunction } from 'i18next';
import { PALETTE } from '../editorColors';
import type { MedicationTemplate } from '../trackerTypes';
import type { TrackerStats } from '../trackerStats';
import { insightText } from '../trackerStats';
import { activeLocale } from '../languages';
import { formatDay, formatInstant } from '../intlFormat';
import { RTL_LOCALES } from '../localeRoutes';
import { aggregate, rollingAverage } from '../trackerSeries';
import { compareAll, qualifiesForInsight } from '../trackerCompare';
import { toSvgString } from '../trackerChartGeometry';
import { chartSpecFor } from './TrackerCard';
import {
  compareSentence,
  daysBetween,
  doseLenses,
  formatNumber,
  formatValue,
  hasData,
  levelLabel,
  rowName,
  ruleLabel,
  trackerName,
  type WellnessModel,
} from './wellnessModel';
import { MIN_PER_SIDE } from '../trackerCompare';

/**
 * The doctor report and the AI prompt, both built from the same model the
 * pane shows, over the same range. The report is HTML written into a
 * same-origin window, so every user-authored string goes through `esc`.
 * Spec: ops/docs/archive/wellness-statistics.md (section 12)
 */

/** The dose a medication STARTED on; `dosage` is the current one. Templates
 *  created before the history was written fall back to it. */
function startingDosage(m: MedicationTemplate, t: TFunction): string {
  return m.dosageHistory[0]?.dosage || m.dosage || (t('wellness.report.unknownDose') as string);
}

function startedLine(m: MedicationTemplate, t: TFunction): string {
  return t('wellness.report.started', { dosage: startingDosage(m, t), date: formatDay(m.startedAt, 'date') }) as string;
}

function changedLine(dosage: string, date: string, t: TFunction): string {
  return t('wellness.report.changedTo', { dosage, date: formatDay(date, 'date') }) as string;
}

/** Medication names, dosages and custom tracker names are user-authored,
 *  and the report is written into a window that inherits the app's origin. */
function esc(value: string): string {
  return value
    .replace(/&/g, '&amp;')
    .replace(/</g, '&lt;')
    .replace(/>/g, '&gt;')
    .replace(/"/g, '&quot;')
    .replace(/'/g, '&#39;');
}

type TrackerLine = { name: string; days: number; average: string; lowHigh: string; svg: string; yes?: number };

/** One line per tracker with data in the range, custom included, for the table and the prompt. */
function trackerLines(model: WellnessModel, t: TFunction, withSvg: boolean): TrackerLine[] {
  const out: TrackerLine[] = [];
  const weekly = model.rangeDays > 182;
  for (const d of model.registry) {
    if (d.id === 'mood' || d.kind === 'medication' || d.kind === 'set') continue;
    const series = model.seriesOf(d);
    if (!hasData(series)) continue;
    const a = aggregate(series, d);
    const name = trackerName(d, t);
    const svg = withSvg ? toSvgString(chartSpecFor(d, series, weekly), 110, 18) : '';
    if (a.kind === 'numeric') {
      out.push({
        name,
        days: a.n,
        average: d.aggregate === 'sum' ? t('wellness.report.total', { value: formatNumber(a.sum) }) : formatValue(d, a.avg ?? 0, t),
        lowHigh: `${formatNumber(a.low ?? 0)} / ${formatNumber(a.high ?? 0)}`,
        svg,
      });
    } else if (a.kind === 'yesno') {
      out.push({ name, days: a.yes + a.no, average: t('wellness.report.yesOn', { count: a.yes }), lowHigh: '-', svg, yes: a.yes });
    } else if (a.kind === 'ordinal') {
      const top = Object.entries(a.counts).sort((x, y) => y[1] - x[1])[0];
      // No number to average: the low and the high are the lowest and the
      // highest level logged, in the order the tracker defines.
      const logged = (d.levels ?? []).filter((l) => (a.counts[l] ?? 0) > 0);
      const lowHigh = logged.length > 0 ? `${levelLabel(d, logged[0]!, t)} / ${levelLabel(d, logged[logged.length - 1]!, t)}` : '-';
      out.push({ name, days: a.n, average: top ? levelLabel(d, top[0], t) : '-', lowHigh, svg });
    }
  }
  return out;
}

export function generateDoctorReport(stats: TrackerStats, medications: MedicationTemplate[], t: TFunction, model: WellnessModel): string {
  const r = (key: string, vars: Record<string, unknown> = {}) => t(`wellness.report.${key}`, vars) as string;
  const locale = activeLocale();
  const dir = (RTL_LOCALES as readonly string[]).includes(locale) ? 'rtl' : 'ltr';
  const mood = model.byId('mood');
  const moodSeries = mood ? model.seriesOf(mood) : null;
  const moodAgg = mood && moodSeries ? aggregate(moodSeries, mood) : null;
  const moodAvg = moodAgg?.kind === 'numeric' && moodAgg.avg !== null ? formatNumber(moodAgg.avg) : '-';
  const sleep = model.byId('sleepHours');
  const sleepAgg = sleep ? aggregate(model.seriesOf(sleep), sleep) : null;
  const sleepAvg = sleepAgg?.kind === 'numeric' && sleepAgg.avg !== null ? formatValue(sleep!, sleepAgg.avg, t) : '-';

  const moodSvg = mood && moodSeries && hasData(moodSeries)
    ? toSvgString(chartSpecFor(mood, moodSeries, model.rangeDays > 182), 640, 110, { average: true })
    : '';
  const marks = medications
    .flatMap((m) => m.dosageHistory.filter((h) => h.changedAt >= model.range.from && h.changedAt <= model.range.to).map((h) => ({ m, h })))
    .map(({ m, h }) => `<span style="position:absolute;left:${(((daysBetween(model.range.from, h.changedAt) + 0.5) / model.rangeDays) * 100).toFixed(2)}%;color:${PALETTE.orange}">&#9650;</span>`)
    .join('');

  const lines = trackerLines(model, t, true);
  const trackerRows = lines
    .map((l) => `<tr><td>${esc(l.name)}</td><td>${l.days}</td><td>${esc(l.average)}</td><td>${esc(l.lowHigh)}</td><td>${l.svg}</td></tr>`)
    .join('');

  const effectRows: string[] = [];
  if (mood) {
    for (const lag of [0, 1] as const) {
      for (const c of compareAll(model.entries, model.registry, mood, model.range, lag)) {
        if (!qualifiesForInsight(c)) continue;
        const d = model.byId(c.trackerId)!;
        const name = lag === 1 ? r('nextDaySuffix', { name: rowName(c, d, t) }) : rowName(c, d, t);
        effectRows.push(
          `<tr><td>${esc(name)}</td><td>${esc(ruleLabel(c, d, t))}</td><td>${formatNumber(c.a.mean ?? 0)}</td><td>${formatNumber(c.b.mean ?? 0)}</td><td>${(c.delta ?? 0) >= 0 ? '+' : '-'}${formatNumber(Math.abs(c.delta ?? 0))}</td><td>${c.a.n} / ${c.b.n}</td></tr>`,
        );
      }
    }
  }

  const medRows = stats.medBreakdown
    .map((m) => {
      const tpl = medications.find((x) => x.id === m.id);
      const changes = tpl ? [startedLine(tpl, t), ...tpl.dosageHistory.slice(1).map((h) => changedLine(h.dosage, h.changedAt, t))].map(esc).join('<br>') : '';
      return `<tr><td>${esc(m.name)}</td><td>${m.taken}/${m.total}</td><td>${m.pct}%</td><td>${changes}</td></tr>`;
    })
    .join('');
  const medCalendars = model.registry
    .filter((d) => d.kind === 'medication' && hasData(model.seriesOf(d)))
    .map((d) => {
      const series = model.seriesOf(d);
      return `<h4>${esc(trackerName(d, t))}</h4>${toSvgString(model.rangeDays <= 31 ? { form: 'strip', series, color: d.color } : { form: 'calendar', series, color: d.color }, 640, model.rangeDays <= 31 ? 14 : 110)}`;
    })
    .join('');
  const lensLines = doseLenses(model.entries, medications, model.range)
    .filter((l) => l.before.n >= MIN_PER_SIDE && l.after.n >= MIN_PER_SIDE && l.before.mean !== null && l.after.mean !== null)
    .map((l) => `<li>${esc(`${formatDay(l.date, 'date')}, ${[l.name, l.dosage].filter(Boolean).join(' ')}: ${t('wellness.medCalendar.doseLens', { before: formatNumber(l.before.mean!), nBefore: l.before.n, after: formatNumber(l.after.mean!), nAfter: l.after.n })}`)}</li>`)
    .join('');

  const patternItems = stats.patterns.map((p) => `<li>${esc(insightText(p, t))}</li>`).join('');
  const today = formatInstant(new Date(), 'date');

  return `<!DOCTYPE html>
<html lang="${locale}" dir="${dir}"><head><meta charset="utf-8"><title>${esc(r('documentTitle'))}</title>
<style>
body{font-family:-apple-system,sans-serif;max-width:700px;margin:40px auto;padding:0 20px;font-size:13px;color:#222}
h1{font-size:20px;margin-bottom:4px}h2{font-size:15px;margin-top:24px;border-bottom:1px solid #ddd;padding-bottom:4px}
h3{font-size:13px;margin-top:16px}h4{font-size:12px;margin:8px 0 4px}
table{border-collapse:collapse;width:100%;margin:8px 0}td,th{border:1px solid #ddd;padding:4px 8px;text-align:start;font-size:12px;vertical-align:middle}
.meta{color:#666;font-size:11px}svg{display:block}.marks{position:relative;height:14px}
ul{margin:4px 0;padding-inline-start:20px}li{font-size:12px;margin:2px 0}
.footer{margin-top:32px;border-top:1px solid #ddd;padding-top:8px;font-size:10px;color:#999}
@media print{body{margin:0;padding:20px}}
</style></head><body>
<h1>${esc(r('heading'))}</h1>
<p class="meta">${esc(r('meta', { date: today, from: formatDay(model.range.from, 'date'), to: formatDay(model.range.to, 'date'), days: model.inRange.length }))}<br>${esc(r('daysLogged', { logged: model.inRange.length, days: model.rangeDays }))}</p>

<h2>${esc(r('overview'))}</h2>
<table><tr><th>${esc(r('columnMetric'))}</th><th>${esc(r('columnValue'))}</th></tr>
<tr><td>${esc(r('avgMood'))}</td><td>${esc(moodAvg)}/10</td></tr>
<tr><td>${esc(r('avgSleep'))}</td><td>${esc(sleepAvg)}</td></tr>
<tr><td>${esc(r('adherence'))}</td><td>${stats.medAdherence ?? '-'}%</td></tr>
<tr><td>${esc(r('daysTracked'))}</td><td>${model.inRange.length}</td></tr>
</table>

${moodSvg ? `<h2>${esc(r('moodHeading'))}</h2>${moodSvg}<div class="marks">${marks}</div><p class="meta">${esc(r('moodLegend'))}</p>` : ''}

${trackerRows ? `<h2>${esc(r('trackers'))}</h2><table><tr><th>${esc(r('columnTracker'))}</th><th>${esc(r('columnDays'))}</th><th>${esc(r('columnAverage'))}</th><th>${esc(r('columnLowHigh'))}</th><th>${esc(r('columnHistory'))}</th></tr>${trackerRows}</table>` : ''}

${effectRows.length ? `<h2>${esc(r('effects'))}</h2><table><tr><th>${esc(r('columnFactor'))}</th><th>${esc(r('columnRule'))}</th><th>${esc(r('columnWith'))}</th><th>${esc(r('columnWithout'))}</th><th>${esc(r('columnDifference'))}</th><th>${esc(r('columnDays'))}</th></tr>${effectRows.join('')}</table><p class="meta">${esc(r('effectsNote'))}</p>` : ''}

${medRows ? `<h2>${esc(r('adherenceHeading'))}</h2><p class="meta">${esc(r('adherenceNote'))}</p><table><tr><th>${esc(r('columnMedication'))}</th><th>${esc(r('columnTaken'))}</th><th>${esc(r('columnRate'))}</th><th>${esc(r('columnDoseChanges'))}</th></tr>${medRows}</table>${medCalendars}${lensLines ? `<ul>${lensLines}</ul>` : ''}` : ''}

${patternItems ? `<h2>${esc(r('patterns'))}</h2><ul>${patternItems}</ul>` : ''}

<p class="footer">${esc(r('footer'))}</p>
<script>window.print();</script>
</body></html>`;
}

export function generateAIPrompt(stats: TrackerStats, medications: MedicationTemplate[], t: TFunction, model: WellnessModel): string {
  const p = (key: string, vars: Record<string, unknown> = {}) => t(`wellness.aiPrompt.${key}`, vars) as string;
  const days = (count: number) => t('wellness.units.days', { count }) as string;
  const mood = model.byId('mood');
  const moodSeries = mood ? model.seriesOf(mood) : null;
  const moodAgg = mood && moodSeries ? aggregate(moodSeries, mood) : null;

  const lines: string[] = [
    p('intro'),
    '',
    `## ${p('overview')}`,
    `- ${p('period', { from: model.range.from, to: model.range.to })}`,
    `- ${p('daysLogged', { logged: model.inRange.length, days: model.rangeDays })}`,
  ];
  if (moodAgg?.kind === 'numeric' && moodAgg.avg !== null) lines.push(`- ${p('avgMood', { mood: formatNumber(moodAgg.avg) })}`);
  if (stats.avgSleepHours != null) lines.push(`- ${p('avgSleep', { hours: stats.avgSleepHours })}`);
  if (stats.medAdherence != null) lines.push(`- ${p('adherence', { pct: stats.medAdherence })}`);
  if (stats.emotionFrequency.length > 0) {
    const list = stats.emotionFrequency.slice(0, 8).map((e) => `${t(`trackers:emotions.tags.${e.key}`, { defaultValue: e.key })} (${e.count}x)`).join(', ');
    lines.push(`- ${p('topEmotions', { list })}`);
  }

  if (moodSeries && hasData(moodSeries)) {
    lines.push('', `## ${p('moodTrend')}`, `| ${p('columnDate')} | ${p('columnMood')} | ${p('columnAverage')} |`, '|------|------|------|');
    const avg = rollingAverage(moodSeries);
    for (const [i, pt] of moodSeries.points.entries()) {
      if (typeof pt.value !== 'number') continue;
      const a = avg.points[i]?.value;
      lines.push(`| ${pt.date} | ${pt.value}/10 | ${typeof a === 'number' ? formatNumber(a) : ''} |`);
    }
  }

  const tl = trackerLines(model, t, false);
  if (tl.length) {
    lines.push('', `## ${p('trackers')}`);
    for (const l of tl) {
      lines.push(l.yes !== undefined ? `- ${p('trackerYesLine', { name: l.name, yes: l.yes, count: l.days })}` : `- ${p('trackerLine', { name: l.name, avg: l.average, low: l.lowHigh.split(' / ')[0], high: l.lowHigh.split(' / ')[1], count: l.days })}`);
    }
  }

  if (stats.medBreakdown.length > 0) {
    lines.push('', `## ${p('adherenceHeading')}`);
    for (const m of stats.medBreakdown) lines.push(`- ${p('adherenceLine', { name: m.name, taken: m.taken, total: m.total, pct: m.pct })}`);
    const withHistory = medications.filter((m) => m.dosageHistory.length > 0 || m.startedAt);
    if (withHistory.length > 0) {
      lines.push('', `### ${p('dosageTimeline')}`);
      for (const m of withHistory) {
        lines.push(`- ${m.name}: ${startedLine(m, t)}`);
        for (const h of m.dosageHistory.slice(1)) lines.push(`  - ${changedLine(h.dosage, h.changedAt, t)}`);
      }
    }
  }

  const effects: string[] = [];
  const customNames: string[] = [];
  if (mood) {
    for (const lag of [0, 1] as const) {
      for (const c of compareAll(model.entries, model.registry, mood, model.range, lag)) {
        if (!qualifiesForInsight(c)) continue;
        const d = model.byId(c.trackerId)!;
        effects.push(`- ${compareSentence(c, d, mood, t)}`);
        if (d.source === 'custom' && !customNames.includes(trackerName(d, t))) customNames.push(trackerName(d, t));
      }
    }
  }
  if (effects.length || stats.patterns.length) {
    lines.push('', `## ${p('patterns')}`, ...effects, ...stats.patterns.map((pt) => `- ${insightText(pt, t)}`));
  }

  lines.push('', `## ${p('questions')}`);
  const asks = ['question1', 'question2', 'question3', 'question4', 'question5', 'question6'].map((k) => p(k));
  for (const name of customNames) asks.push(p('customQuestion', { name }));
  asks.forEach((a, i) => lines.push(`${i + 1}. ${a}`));
  lines.push('', '---', p('footer'));
  return lines.join('\n');
}
