import { useEffect, useRef } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { intlLocale } from './languages';

/**
 * Date picker for creating journal entries on recent days.
 *
 * Lists today + the last 6 days. Always creates a new journal -
 * no dedup, no detection of existing entries (there's no reliable
 * way to map a journal to a calendar date once the title is renamed
 * or the entry is backfilled from a different day).
 *
 * Today has its own callback because it is not a backfill: the ordinary
 * new-entry path inherits the open folder, the active tag and the pinned
 * state of the list the user is standing in, and a dated row deliberately
 * inherits none of that. The two rows sit in one menu; the actions stay apart.
 *
 * `onPick` receives the picked date as an ISO yyyy-mm-dd string.
 */
type Props = {
  /** Called with the picked ISO date (yyyy-mm-dd). Never today's date. */
  onPick: (isoDate: string) => void;
  /** Called for the today row, which creates an ordinary new entry. */
  onToday: () => void;
  /** Called when the user clicks outside or presses Escape. */
  onClose: () => void;
  /** The trigger button - excluded from outside-click detection. */
  anchorRef?: React.RefObject<HTMLElement | null>;
};

function pad(n: number) { return n < 10 ? `0${n}` : String(n); }

function toIso(d: Date) {
  return `${d.getFullYear()}-${pad(d.getMonth() + 1)}-${pad(d.getDate())}`;
}

function labelFor(d: Date, today: Date): { kind: 'today' | 'yesterday' | 'weekday'; weekday: string; secondary: string } {
  const isToday = toIso(d) === toIso(today);
  const yesterday = new Date(today);
  yesterday.setDate(today.getDate() - 1);
  const isYesterday = toIso(d) === toIso(yesterday);
  const weekday = d.toLocaleDateString(intlLocale(), { weekday: 'long' });
  const date = d.toLocaleDateString(intlLocale(), { month: 'short', day: 'numeric' });
  if (isToday) return { kind: 'today', weekday, secondary: date };
  if (isYesterday) return { kind: 'yesterday', weekday, secondary: date };
  return { kind: 'weekday', weekday, secondary: date };
}

export function BackfillPopover({ onPick, onToday, onClose, anchorRef }: Props) {
  const { t } = useTranslation('shell');
  const popoverRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (popoverRef.current && popoverRef.current.contains(target)) return;
      if (anchorRef?.current && anchorRef.current.contains(target)) return;
      onClose();
    }
    window.addEventListener('pointerdown', handler, true);
    return () => window.removeEventListener('pointerdown', handler, true);
  }, [onClose, anchorRef]);

  useEscapeToClose(onClose);

  const today = new Date();
  today.setHours(12, 0, 0, 0);
  const days: Date[] = [];
  for (let i = 0; i < 7; i++) {
    const d = new Date(today);
    d.setDate(today.getDate() - i);
    days.push(d);
  }

  return (
    <div
      ref={popoverRef}
      role="menu"
      aria-label={t('backfillPopover.ariaLabel')}
      className="absolute end-0 top-full mt-1 z-50 min-w-[180px] rounded-md border border-divider bg-surface-2 shadow-lg py-1"
    >
      <div className="px-3 pt-1.5 pb-1 text-[11px] tracking-wide text-pn-muted select-none">{t('backfillPopover.heading')}</div>
      {days.map((d) => {
        const iso = toIso(d);
        const { kind, weekday, secondary } = labelFor(d, today);
        const isToday = kind === 'today';
        const primary =
          kind === 'today'
            ? t('backfillPopover.today')
            : kind === 'yesterday'
              ? t('backfillPopover.yesterday')
              : weekday;
        return (
          <button
            key={iso}
            type="button"
            role="menuitem"
            onClick={() => { if (isToday) onToday(); else onPick(iso); onClose(); }}
            className={`w-full flex items-baseline justify-between gap-3 px-3 py-2 text-start transition ${
              isToday
                ? 'bg-accent/10 border-s-[3px] border-accent hover:bg-accent/15'
                : 'hover:bg-neutral-100 dark:hover:bg-neutral-800'
            }`}
          >
            <span className={`text-[14px] ${isToday ? 'font-medium text-pn' : 'text-pn'}`}>{primary}</span>
            <span className={`text-[12px] tabular-nums ${isToday ? 'font-medium text-accent' : 'text-pn-muted'}`}>{secondary}</span>
          </button>
        );
      })}
    </div>
  );
}
