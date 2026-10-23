import { useMemo, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { CaretLeft, CaretRight, GridFour } from '../icons';
import { SectionEyebrow } from '../settingsUI';
import { saveBlob } from '../saveFile';
import { formatDay, monthInitial } from '../intlFormat';
import { toLocalIso } from '../notesViewUtils';
import { buildSeries } from '../trackerSeries';
import { moodColor } from '../moodColors';
import { PIXEL_ROWS, pixelYears, yearPixelGrid, yearRange } from '../yearPixels';
import type { WellnessModel } from './wellnessModel';

// The saved picture: squares and gaps in device pixels, no text on it.
const PNG_CELL = 20;
const PNG_GAP = 4;
const PNG_PAD = 16;

function paintedColor(el: Element | null, fallback: string): string {
  const color = el ? getComputedStyle(el).backgroundColor : '';
  return color && color !== 'rgba(0, 0, 0, 0)' && color !== 'transparent' ? color : fallback;
}

/**
 * One square per day of a year in the mood colors, free. The grid reads the
 * mood series of the chosen year, never the entries; a tap opens the day. The
 * picture it saves carries no title and no name, so it can be shared as it
 * is: a reader sees colors and nothing else.
 * Spec: ops/docs/archive/wellness-statistics.md (section 8)
 */
export function YearInPixels({ model, onOpenDay }: { model: WellnessModel; onOpenDay?: (date: string) => void }) {
  const { t } = useTranslation('stats');
  const today = toLocalIso(new Date());
  const years = useMemo(() => pixelYears(model.firstDay, today), [model.firstDay, today]);
  const [picked, setPicked] = useState<number | null>(null);
  const year = picked !== null && years.includes(picked) ? picked : years[years.length - 1]!;
  const mood = model.byId('mood');
  const grid = useMemo(
    () => (mood ? yearPixelGrid(buildSeries(model.entries, mood, yearRange(year)), year) : null),
    [model.entries, mood, year],
  );
  const months = useMemo(() => Array.from({ length: 12 }, (_, i) => monthInitial(i)), []);
  const [saveFailed, setSaveFailed] = useState(false);
  // The picture takes the colors the pane paints, so it matches the theme on screen.
  const surfaceProbe = useRef<HTMLSpanElement>(null);
  const emptyProbe = useRef<HTMLSpanElement>(null);

  if (!grid) return null;
  const index = years.indexOf(year);

  const cellTitle = (date: string, value: number | undefined) =>
    value === undefined
      ? t('writing.tooltipNoMood', { date: formatDay(date, 'date') })
      : t('writing.tooltipMood', { date: formatDay(date, 'date'), mood: value });

  const saveImage = async () => {
    const canvas = document.createElement('canvas');
    canvas.width = PNG_PAD * 2 + 12 * PNG_CELL + 11 * PNG_GAP;
    canvas.height = PNG_PAD * 2 + PIXEL_ROWS * PNG_CELL + (PIXEL_ROWS - 1) * PNG_GAP;
    const ctx = canvas.getContext('2d');
    if (!ctx) return;
    ctx.fillStyle = paintedColor(surfaceProbe.current, '#FFFFFF');
    ctx.fillRect(0, 0, canvas.width, canvas.height);
    const empty = paintedColor(emptyProbe.current, '#E5E7EB');
    grid.forEach((column, m) => {
      column.forEach((cell, d) => {
        if (!cell) return;
        ctx.fillStyle = cell.mood === undefined ? empty : moodColor(cell.mood);
        ctx.fillRect(PNG_PAD + m * (PNG_CELL + PNG_GAP), PNG_PAD + d * (PNG_CELL + PNG_GAP), PNG_CELL, PNG_CELL);
      });
    });
    const blob = await new Promise<Blob | null>((resolve) => {
      try {
        canvas.toBlob((b) => resolve(b), 'image/png');
      } catch {
        resolve(null);
      }
    });
    if (!blob) {
      setSaveFailed(true);
      return;
    }
    const saved = await saveBlob(blob, `privacy-notes-year-in-pixels-${year}.png`);
    if (saved.ok) setSaveFailed(false);
    else if (saved.reason === 'failed') setSaveFailed(true);
  };

  const cellOf = (cell: NonNullable<(typeof grid)[number][number]>) => {
    const color = cell.mood === undefined ? undefined : moodColor(cell.mood);
    const className = `aspect-square rounded-[2px] ${color ? '' : 'bg-track'}`;
    const style = color ? { backgroundColor: color } : undefined;
    const title = cellTitle(cell.date, cell.mood);
    return onOpenDay ? (
      <button key={cell.date} type="button" title={title} aria-label={title} className={`${className} hover:ring-1 hover:ring-pn-muted`} style={style} onClick={() => onOpenDay(cell.date)} />
    ) : (
      <div key={cell.date} title={title} className={className} style={style} />
    );
  };

  return (
    <div data-setting="stats.yearInPixels" className="@container">
      <div className="flex items-center justify-between mb-2 gap-2">
        <SectionEyebrow icon={GridFour}>{t('wellness.pixels.heading')}</SectionEyebrow>
        <div className="flex items-center gap-1 text-xs">
          <button
            type="button"
            aria-label={t('wellness.pixels.prevYear')}
            disabled={index <= 0}
            onClick={() => setPicked(years[index - 1]!)}
            className="p-1 rounded text-pn-muted hover:text-pn disabled:opacity-30 disabled:hover:text-pn-muted"
          >
            <CaretLeft size={14} />
          </button>
          <span className="tabular-nums font-medium min-w-[3ch] text-center">{year}</span>
          <button
            type="button"
            aria-label={t('wellness.pixels.nextYear')}
            disabled={index >= years.length - 1}
            onClick={() => setPicked(years[index + 1]!)}
            className="p-1 rounded text-pn-muted hover:text-pn disabled:opacity-30 disabled:hover:text-pn-muted"
          >
            <CaretRight size={14} />
          </button>
        </div>
      </div>
      {/* Wide: one row per month, the days across, so the year fills the pane. */}
      <div
        className="hidden @xl:grid gap-[3px] items-center"
        style={{ gridTemplateColumns: `1.25rem repeat(${PIXEL_ROWS}, minmax(0, 1fr))` }}
        role="img"
        aria-label={t('wellness.pixels.aria', { year })}
      >
        {grid.flatMap((column, m) => [
          <span key={`l${m}`} className="text-[11px] text-pn-muted leading-none">{months[m]}</span>,
          ...column.map((cell, d) => (cell ? cellOf(cell) : <div key={`${m}-${d}`} aria-hidden="true" />)),
        ])}
      </div>
      {/* Narrow: one column per month, the days down. */}
      <div className="@xl:hidden mx-auto w-full max-w-[220px]">
        <div className="grid grid-cols-12 gap-[3px] mb-1">
          {months.map((m, i) => (
            <span key={i} className="text-center text-[9px] text-pn-muted leading-none">{m}</span>
          ))}
        </div>
        <div
          className="grid grid-cols-12 grid-flow-col gap-[3px]"
          style={{ gridTemplateRows: `repeat(${PIXEL_ROWS}, minmax(0, 1fr))` }}
          role="img"
          aria-label={t('wellness.pixels.aria', { year })}
        >
          {grid.flatMap((column, m) => column.map((cell, d) => (cell ? cellOf(cell) : <div key={`${m}-${d}`} aria-hidden="true" />)))}
        </div>
      </div>
      <div className="flex flex-wrap items-center justify-between gap-2 mt-2">
        <span className="text-[11px] text-pn-muted">{onOpenDay ? t('wellness.pixels.hintTap') : t('wellness.pixels.hint')}</span>
        <button type="button" onClick={saveImage} className="px-3 py-1.5 rounded-md text-xs font-medium border border-divider hover:bg-surface-1 transition-colors">
          {t('wellness.pixels.saveImage')}
        </button>
      </div>
      {saveFailed && <p className="mt-2 text-xs text-danger">{t('wellness.export.saveFailed')}</p>}
      <span ref={surfaceProbe} className="hidden bg-surface-2" aria-hidden="true" />
      <span ref={emptyProbe} className="hidden bg-track" aria-hidden="true" />
    </div>
  );
}
