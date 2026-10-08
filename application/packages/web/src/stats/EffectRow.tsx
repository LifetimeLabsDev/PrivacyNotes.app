import { useTranslation } from 'react-i18next';
import type { CompareResult, TrackerDescriptor } from '../wellnessTypes';
import { formatDelta, rowName, ruleLabel } from './wellnessModel';

/** The width a difference of 2.5 points fills on one side of the bar. */
const FULL_DELTA = 2.5;

/**
 * One tracker against the outcome: the name, the rule with the two counts,
 * a diverging bar and the signed difference, or the days still missing.
 */
export function EffectRow({ r, tracker, outcome, compact = false }: {
  r: CompareResult;
  tracker: TrackerDescriptor;
  outcome?: TrackerDescriptor;
  compact?: boolean;
}) {
  const { t } = useTranslation('stats');
  const width = r.delta === null ? 0 : Math.min(50, (Math.abs(r.delta) / FULL_DELTA) * 50);
  const positive = (r.delta ?? 0) >= 0;
  return (
    <div className={`grid items-center gap-3 py-1.5 border-b border-divider last:border-b-0 ${compact ? 'grid-cols-[110px_1fr_40px]' : 'grid-cols-[minmax(0,1.2fr)_minmax(0,1fr)_44px]'}`}>
      <div className="min-w-0">
        <div className="text-xs text-pn-soft truncate">{rowName(r, tracker, t)}</div>
        <div className="text-[10px] text-pn-muted truncate">
          {ruleLabel(r, tracker, t)}{', '}{t('wellness.effects.days', { a: r.a.n, b: r.b.n })}
        </div>
      </div>
      {r.delta === null ? (
        <div className="text-[10px] text-pn-muted">
          {r.shortfall
            ? t('wellness.effects.shortfall', { count: r.shortfall.days, side: t(r.shortfall.side === 'a' ? 'wellness.effects.sideWith' : 'wellness.effects.sideWithout') })
            : ''}
        </div>
      ) : (
        <div className="relative h-2 rounded bg-surface-0" dir="ltr">
          {/* rtl-ok: a diverging bar is a chart and reads left to right in every script */}
          <span className="absolute left-1/2 -top-0.5 w-px h-3 bg-pn-muted/60" /> {/* rtl-ok: inside the LTR island */}
          <span
            className="absolute top-0 h-2 rounded"
            style={{
              [positive ? 'left' : 'right']: '50%',
              width: `${width}%`,
              backgroundColor: positive ? '#2F77BE' : '#C2512B',
            }}
          />
        </div>
      )}
      <div className="text-xs tabular-nums text-end">
        {r.delta === null ? '-' : formatDelta(r.delta)}
      </div>
      {outcome && null}
    </div>
  );
}
