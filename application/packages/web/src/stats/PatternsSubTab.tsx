import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { PatternInsight, TrackerStats } from '../trackerStats';
import { insightText } from '../trackerStats';
import { EYEBROW_ICON_ROW, EyebrowGlyph, SectionEyebrow, SETTINGS_EYEBROW, SettingsSegmented } from '../settingsUI';
import { ProMark } from '../UpgradeModal';
import { CalendarBlank, ChartLineUp, Fire, Sparkle, TrendUp, type Icon } from '../icons';
import { compareAll } from '../trackerCompare';
import { EffectBarRow, SureDots } from './statsParts';
import { standoutLabel, type WellnessModel } from './wellnessModel';

/** The glyph of each kind of finding beside the comparisons. */
const PATTERN_ICONS: Record<PatternInsight['type'], Icon> = { day_of_week: CalendarBlank, streak: Fire, trend: TrendUp };

/** One finding that is not a comparison: its glyph on an accent tile, then the sentence. */
function PatternCard({ text, icon: Glyph }: { text: string; icon: Icon }) {
  return (
    <div className="flex items-center gap-3 py-2.5">
      <span aria-hidden="true" className="inline-flex w-[26px] h-[26px] shrink-0 items-center justify-center rounded-md bg-accent/10 text-accent">
        <Glyph size={14} />
      </span>
      <span className="text-sm text-pn">{text}</span>
    </div>
  );
}

/** Spec: ops/docs/archive/wellness-statistics.md (section 11) */
export function PatternsSubTab({ model, stats, unlocked, isPro, onOpenUpgrade }: {
  model: WellnessModel;
  stats: TrackerStats;
  unlocked: boolean;
  isPro: boolean;
  onOpenUpgrade?: () => void;
}) {
  const { t } = useTranslation('stats');
  const [lag, setLag] = useState<0 | 1>(0);
  const mood = model.byId('mood');
  const rows = useMemo(() => (mood ? compareAll(model.entries, model.registry, mood, model.range, lag) : []), [model, mood, lag]);
  // Every comparison with a difference, biggest first; the ones still short of days are counted, not listed.
  const shown = useMemo(() => rows.filter((r) => r.delta !== null).sort((a, b) => Math.abs(b.delta ?? 0) - Math.abs(a.delta ?? 0)), [rows]);
  const waiting = rows.length - shown.length;
  const scale = Math.max(1, ...shown.map((r) => Math.abs(r.delta ?? 0)));
  const others: PatternInsight[] = stats.patterns;
  const insightCount = others.length;

  return (
    <>
      {mood && shown.length > 0 && (
        <div>
          <div className="flex items-center justify-between mb-1 gap-2">
            <div className="flex items-center gap-2">
              <span className={`${SETTINGS_EYEBROW} ${EYEBROW_ICON_ROW}`}><EyebrowGlyph icon={ChartLineUp} />{t('wellness.effects.heading')}</span>
              {!isPro && <ProMark />}
            </div>
            <SettingsSegmented
              label={`${t('wellness.effects.sameDay')} / ${t('wellness.effects.nextDay')}`}
              value={lag === 0 ? 'same' : 'next'}
              onChange={(v) => setLag(v === 'same' ? 0 : 1)}
              options={[
                { value: 'same', label: t('wellness.effects.sameDay') },
                { value: 'next', label: t('wellness.effects.nextDay') },
              ]}
            />
          </div>
          {unlocked ? (
            <>
              <div className="@container rounded-lg border border-divider bg-surface-2 px-3 divide-y divide-divider mt-2">
                {shown.map((r) => {
                  const d = model.byId(r.trackerId);
                  return d ? (
                    <EffectBarRow
                      key={r.trackerId + (r.tag ?? '')}
                      d={d}
                      label={standoutLabel(r, d, t)}
                      sub={t('home.daysSplit', { a: r.a.n, b: r.b.n })}
                      delta={r.delta ?? 0}
                      sure={<SureDots r={r} />}
                      share={Math.abs(r.delta ?? 0) / scale}
                    />
                  ) : null;
                })}
              </div>
              {waiting > 0 && <p className="text-[11px] text-pn-muted mt-2">{t('wellness.patterns.waiting', { count: waiting })}</p>}
              <p className="text-[11px] text-pn-muted mt-1">{t('home.footnoteShort')}</p>
            </>
          ) : (
            <button type="button" onClick={onOpenUpgrade} className="w-full rounded-lg border border-dashed border-divider p-3 text-xs text-pn-muted hover:text-pn hover:border-pn-muted transition-colors text-center">
              {t('wellness.patterns.tableLocked')}
            </button>
          )}
        </div>
      )}

      {insightCount > 0 && (
        <div>
          <div className="flex items-center gap-2 mb-2">
            <SectionEyebrow icon={Sparkle}>{t('wellness.patterns.insights')}</SectionEyebrow>
            {!isPro && <ProMark />}
          </div>
          {unlocked ? (
            <div className="rounded-lg border border-divider bg-surface-2 px-3 divide-y divide-divider">
              {others.map((p, i) => <PatternCard key={`p${i}`} text={insightText(p, t)} icon={PATTERN_ICONS[p.type] ?? Sparkle} />)}
            </div>
          ) : (
            <button type="button" onClick={onOpenUpgrade} className="w-full rounded-lg border border-dashed border-divider p-3 text-xs text-pn-muted hover:text-pn hover:border-pn-muted transition-colors text-center">
              {t('wellness.patterns.insightsLocked', { count: insightCount })}
            </button>
          )}
        </div>
      )}
    </>
  );
}
