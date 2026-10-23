import { useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowRight, BellSimple, CaretDown, CaretUp, Repeat as RepeatGlyph, Sun } from './icons';
import { ProMark } from './ui';
import { formatDay } from './intlFormat';
import { intlLocale } from './languages';
import { timeLabel } from './JournalCalendar';
import { dayNumber, minutesOf, shiftDay, type Schedule } from './schedule';
import { alertsSummary, describeRepeat } from './scheduleText';
import { typeGlyph } from './NoteRow';

/**
 * The schedule of an event, drawn above its body: a date tile, the time
 * range and its length, and a chip for each schedule row, so the date, the
 * repeat and the alerts are on screen without a menu. Every part opens the
 * Schedule view of the "..." menu, the one place a schedule is edited, on the
 * row it names.
 *
 * On a phone the card folds to one line once the event has text, or while the
 * keyboard is up, so the body keeps the screen; the line opens it again. A
 * wider pane always shows the whole card.
 */

export type ScheduleRow = 'main' | 'ends' | 'repeat' | 'alerts';

type Props = {
  schedule: Schedule;
  /** The day shown: the occurrence a repeating event was opened on. */
  day: string;
  /** The event has text, or the phone keyboard is up. */
  fold: boolean;
  alertsUnlocked: boolean;
  showPro: boolean;
  onOpen: (row: ScheduleRow) => void;
  onUpgrade: () => void;
};

const CHIP = 'inline-flex items-center gap-1.5 h-7 max-w-full px-2.5 rounded-md border text-xs font-medium transition-colors';
const CHIP_SET = `${CHIP} border-divider text-pn-soft hover:border-accent/50 hover:text-pn`;
const CHIP_OFF = `${CHIP} border-dashed border-pn-muted/50 text-pn-muted hover:border-pn-muted hover:text-pn-soft`;

/** "1 h 30 min" in the app language, or nothing for an untimed or zero span. */
function lengthLabel(s: Schedule): string {
  if (!s.time || !s.timeEnd) return '';
  const total = (minutesOf(s.timeEnd) - minutesOf(s.time) + 1440) % 1440;
  if (!total) return '';
  const unit = (unit: 'hour' | 'minute', n: number) =>
    new Intl.NumberFormat(intlLocale(), { style: 'unit', unit, unitDisplay: 'short' }).format(n);
  const h = Math.floor(total / 60);
  const m = total % 60;
  return [h ? unit('hour', h) : '', m ? unit('minute', m) : ''].filter(Boolean).join(' ');
}

export function EventCard({ schedule: s, day, fold, alertsUnlocked, showPro, onOpen, onUpgrade }: Props) {
  const { t } = useTranslation('shell');
  // null follows `fold`; a tap on the line or the caret takes over for this note.
  const [open, setOpen] = useState<boolean | null>(null);
  const folded = open === null ? fold : !open;
  const tone = typeGlyph('event').color;
  const len = s.end ? dayNumber(s.end) - dayNumber(s.day) : 0;
  const endDay = len > 0 ? shiftDay(day, len) : null;
  const times = s.time
    ? (s.timeEnd ? `${timeLabel(day, s.time)} - ${timeLabel(day, s.timeEnd)}` : timeLabel(day, s.time))
    : t('calendar.allDay');
  const length = lengthLabel(s);
  const month = formatDay(day, 'monthShort');
  const weekday = formatDay(day, 'weekdayShort');
  const when = `${formatDay(day, 'weekdayDate')}${endDay ? ` - ${formatDay(endDay, 'weekdayDate')}` : ''}`;
  const openAlerts = () => (alertsUnlocked ? onOpen('alerts') : onUpgrade());

  return (
    <div className="mx-4 sm:mx-6 mt-1 mb-3">
      {/* The folded line: phones only. */}
      <button
        type="button"
        onClick={() => setOpen(true)}
        aria-expanded={false}
        aria-label={t('eventCard.show', { when: `${when}, ${times}` })}
        className={`${folded ? 'flex' : 'hidden'} sm:hidden w-full min-w-0 items-center gap-2 border-s-[3px] border-current ps-2.5 py-1 text-[13px] text-start ${tone}`}
      >
        <span className="shrink-0">{formatDay(day, 'weekdayDate')}</span>
        <span className="min-w-0 truncate text-pn tabular-nums">{times}</span>
        <CaretDown size={14} aria-hidden="true" className="ms-auto shrink-0 text-pn-muted" />
      </button>

      <div className={`${folded ? 'hidden sm:flex' : 'flex'} items-start gap-3 sm:gap-4 rounded-e-md border border-s-[3px] border-divider bg-surface-2/60 p-3 ${tone} [border-inline-start-color:currentColor]`}>
        <button
          type="button"
          onClick={() => onOpen('main')}
          aria-label={`${t('noteOptionsMenu.schedule')}: ${when}, ${times}`}
          className="hidden sm:flex shrink-0 w-14 flex-col items-center rounded-md border border-divider py-1 leading-tight hover:border-accent/50 transition-colors"
        >
          <span className="text-[11px] font-medium uppercase">{month}</span>
          <span className="text-xl font-semibold text-pn tabular-nums">{Number(day.slice(8, 10))}</span>
          <span className="text-[11px] text-pn-muted">{weekday}</span>
        </button>
        <div className="min-w-0 flex-1">
          <div className="flex items-start gap-2">
            <button
              type="button"
              onClick={() => onOpen('main')}
              className="min-w-0 flex-1 text-start rounded-sm hover:opacity-80"
            >
              <span className="block text-[13px] sm:hidden">{when}</span>
              <span className="block text-base font-semibold text-pn tabular-nums">
                {times}
                {length && <span className="ms-2 text-sm font-normal text-pn-muted">{length}</span>}
              </span>
              {endDay && (
                <span className="hidden sm:block text-[13px] text-pn-soft">{t('eventCard.until', { day: formatDay(endDay, 'weekdayDate') })}</span>
              )}
            </button>
            {fold && (
              <button
                type="button"
                onClick={() => setOpen(false)}
                aria-expanded={true}
                aria-label={t('eventCard.hide')}
                className="sm:hidden shrink-0 -m-1 p-1 text-pn-muted hover:text-pn"
              >
                <CaretUp size={14} aria-hidden="true" />
              </button>
            )}
          </div>
          <div className="mt-2 flex flex-wrap gap-1.5">
            <button type="button" onClick={() => onOpen('repeat')} className={s.repeat ? CHIP_SET : CHIP_OFF}>
              <RepeatGlyph size={14} aria-hidden="true" className="shrink-0" />
              <span className="truncate">{s.repeat ? describeRepeat(s.repeat, s.day, t) : t('repeat.never')}</span>
            </button>
            <button type="button" onClick={openAlerts} className={alertsUnlocked && s.alerts?.length ? CHIP_SET : CHIP_OFF}>
              <BellSimple size={14} aria-hidden="true" className="shrink-0" />
              <span className="truncate">{alertsUnlocked && s.alerts?.length ? alertsSummary(s.alerts, day, t) : t('eventCard.noAlert')}</span>
              {showPro && <ProMark />}
            </button>
            {s.time && (
              <button type="button" onClick={() => onOpen('main')} className={CHIP_OFF}>
                <Sun size={14} aria-hidden="true" className="shrink-0" />
                <span className="truncate">{t('calendar.allDay')}</span>
              </button>
            )}
            {!endDay && (
              <button type="button" onClick={() => onOpen('ends')} className={CHIP_OFF}>
                <ArrowRight size={14} aria-hidden="true" className="shrink-0" />
                <span className="truncate">{t('eventCard.endsLater')}</span>
              </button>
            )}
          </div>
        </div>
      </div>
    </div>
  );
}
