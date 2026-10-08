import { useEffect, useMemo, useRef, useState, type KeyboardEvent, type MouseEvent } from 'react';
import { barPath, chartGeometry, rollingLine } from './trackerChartGeometry';
import { formatDay } from './intlFormat';
import type { ChartSpec, TrackerValue } from './wellnessTypes';

/**
 * One chart for every tracker: bars, a line, dots or a calendar, all drawn
 * from `chartGeometry`. A time axis runs left to right in every locale, so
 * the container is a forced-LTR island.
 * Spec: ops/docs/plans/wellness-statistics.md (section 6)
 */

const defaultFormat = (v: TrackerValue | number | undefined): string =>
  typeof v === 'number' ? new Intl.NumberFormat(undefined, { maximumFractionDigits: 2 }).format(v)
    : Array.isArray(v) ? v.join(', ')
    : v === undefined ? '-' : String(v);

export function TrackerChart({ spec, height, ariaLabel, onPickDay, average, formatValue = defaultFormat }: {
  spec: ChartSpec;
  height: number;
  ariaLabel: string;
  onPickDay?: (date: string) => void;
  average?: boolean;
  formatValue?: (value: TrackerValue | number | undefined, date: string) => string;
}) {
  const boxRef = useRef<HTMLDivElement>(null);
  const [width, setWidth] = useState(600);
  const [cursor, setCursor] = useState<number | null>(null);

  useEffect(() => {
    const el = boxRef.current;
    if (!el || typeof ResizeObserver === 'undefined') return;
    const measure = () => { if (el.clientWidth > 0) setWidth(el.clientWidth); };
    measure();
    const ro = new ResizeObserver(measure);
    ro.observe(el);
    return () => ro.disconnect();
  }, []);

  const geo = useMemo(() => chartGeometry(spec, width, height), [spec, width, height]);
  const avg = useMemo(
    () => (average && spec.form !== 'calendar' ? rollingLine(spec.series, width, height, geo.lo, geo.hi) : ''),
    [average, spec, width, height, geo.lo, geo.hi],
  );
  const calendar = spec.form === 'calendar';
  const cellForm = calendar || spec.form === 'strip';
  const hit = cursor !== null ? geo.hits[cursor] : undefined;
  const cell = hit && cellForm ? geo.cells.find((c) => c.date === hit.date) : undefined;

  const indexAt = (e: MouseEvent<SVGSVGElement>): number | null => {
    const rect = e.currentTarget.getBoundingClientRect();
    const x = e.clientX - rect.left;
    const y = e.clientY - rect.top;
    if (calendar) {
      const i = geo.hits.findIndex((h) => {
        const c = geo.cells.find((k) => k.date === h.date);
        return !!c && x >= c.x && x < c.x + c.size && y >= c.y && y < c.y + c.size;
      });
      return i >= 0 ? i : null;
    }
    let best: number | null = null;
    let dist = Infinity;
    geo.hits.forEach((h, i) => {
      const d = Math.abs(h.x + h.w / 2 - x);
      if (d < dist) { dist = d; best = i; }
    });
    return best;
  };

  const onKeyDown = (e: KeyboardEvent<SVGSVGElement>) => {
    const n = geo.hits.length;
    if (!n) return;
    const step: Record<string, number> = calendar
      ? { ArrowLeft: -7, ArrowRight: 7, ArrowUp: -1, ArrowDown: 1 }
      : { ArrowLeft: -1, ArrowRight: 1 };
    const delta = step[e.key];
    if (delta !== undefined) {
      e.preventDefault();
      setCursor((c) => Math.min(n - 1, Math.max(0, (c ?? (delta > 0 ? -1 : n)) + delta)));
    } else if (e.key === 'Home' || e.key === 'End') {
      e.preventDefault();
      setCursor(e.key === 'Home' ? 0 : n - 1);
    } else if (e.key === 'Enter' && hit && onPickDay) {
      e.preventDefault();
      onPickDay(hit.date);
    }
  };

  const tipX = hit ? (cell ? cell.x + cell.size / 2 : hit.x + hit.w / 2) : 0;

  return (
    <div ref={boxRef} dir="ltr" className="relative w-full" /* rtl-ok: a time axis runs left to right in every locale */>
      <svg
        role="img"
        aria-label={ariaLabel}
        tabIndex={0}
        width={width}
        height={height}
        viewBox={`0 0 ${width} ${height}`}
        className={`block text-pn-muted outline-none focus-visible:ring-2 focus-visible:ring-blue-500/50 rounded-sm ${onPickDay ? 'cursor-pointer' : ''}`}
        onMouseMove={(e) => setCursor(indexAt(e))}
        onMouseLeave={() => setCursor(null)}
        onBlur={() => setCursor(null)}
        onClick={(e) => {
          const i = indexAt(e);
          const h = i !== null ? geo.hits[i] : undefined;
          if (h && onPickDay) onPickDay(h.date);
        }}
        onKeyDown={onKeyDown}
      >
        {!cellForm && <line x1={0} x2={width} y1={height - 0.5} y2={height - 0.5} stroke="currentColor" strokeOpacity={0.3} />}
        {geo.bars.map((b) => <path key={b.date} d={barPath(b)} fill={b.fill} />)}
        {geo.path && <path d={geo.path} fill="none" stroke={spec.color} strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />}
        {geo.dots.map((d) => d.filled
          ? <circle key={d.date} cx={d.cx} cy={d.cy} r={d.r} fill={spec.color} />
          : <circle key={d.date} cx={d.cx} cy={d.cy} r={d.r - 0.75} fill="none" stroke={spec.color} strokeWidth={1.5} />)}
        {geo.cells.map((c) => {
          if (c.state === 'outside') return null;
          if (c.round) {
            const r = c.size / 2;
            return c.state === 'no'
              ? <circle key={c.date} cx={c.x + r} cy={c.y + r} r={Math.max(1, r - 1)} fill="none" stroke={spec.color} strokeWidth={Math.min(2, r)} />
              : <circle key={c.date} cx={c.x + r} cy={c.y + r} r={r} fill={c.state === 'missing' ? 'currentColor' : spec.color} fillOpacity={c.state === 'missing' ? 0.12 : 1} />;
          }
          return (
            <rect
              key={c.date} x={c.x} y={c.y} width={c.size} height={c.size} rx={2}
              fill={c.state === 'missing' ? 'currentColor' : spec.color}
              fillOpacity={c.state === 'value' ? 1 : c.state === 'no' ? 0.3 : 0.12}
            />
          );
        })}
        {avg && <path d={avg} fill="none" stroke="currentColor" strokeWidth={2} strokeLinejoin="round" strokeLinecap="round" />}
        {hit && (cell
          ? <rect x={cell.x - 1} y={cell.y - 1} width={cell.size + 2} height={cell.size + 2} rx={cell.round ? cell.size / 2 + 1 : 3} fill="none" stroke="currentColor" strokeWidth={1.5} />
          : <line x1={tipX} x2={tipX} y1={0} y2={height} stroke="currentColor" strokeOpacity={0.5} strokeDasharray="2 2" />)}
      </svg>
      {hit && (
        <div
          className="pointer-events-none absolute top-0 z-10 -translate-x-1/2 -translate-y-full whitespace-nowrap bg-surface-2 border border-divider text-xs text-pn rounded px-2 py-1"
          style={{ left: Math.min(Math.max(tipX, 48), Math.max(48, width - 48)) }}
        >
          <span className="text-pn-muted">{formatDay(hit.date, 'date')}</span>{' '}
          <span className="tabular-nums">{formatValue(hit.value, hit.date)}</span>
        </div>
      )}
    </div>
  );
}
