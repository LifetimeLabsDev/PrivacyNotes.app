import { useTranslation } from 'react-i18next';
import { CaretUp, CaretDown } from './icons';
import { HoverLabel } from './HoverLabel';

/**
 * Button style shared by every icon control in the find and replace bars.
 * One string, so the two bars cannot drift apart by a shade.
 */
export const BAR_BTN =
  'flex items-center justify-center w-7 h-7 rounded text-neutral-600 dark:text-neutral-300 ' +
  '[@media(hover:hover)]:hover:bg-neutral-200 [@media(hover:hover)]:dark:hover:bg-neutral-800 ' +
  'disabled:opacity-40 disabled:cursor-not-allowed active:scale-95 transition shrink-0 outline-none';

type Props = {
  /** Text in the count slot: "2/7", "0/0", a status line, or nothing. */
  count: string;
  /** Paint the count red: a query with nothing found. */
  noHits: boolean;
  canStep: boolean;
  onStep: (dir: 1 | -1) => void;
};

/**
 * The match count and the previous/next arrows, as both bars render them.
 * The buttons swallow mousedown so a click never takes focus away from the
 * input the reader is typing in.
 */
export function MatchNav({ count, noHits, canStep, onStep }: Props) {
  const { t } = useTranslation('editor');
  return (
    <>
      <span
        className={`min-w-[3.5ch] text-center text-xs tabular-nums shrink-0 ${
          noHits ? 'text-red-500' : 'text-neutral-400 dark:text-neutral-500'
        }`}
      >
        {count}
      </span>
      <HoverLabel label={t('find.previousTitle')} position="below">
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => onStep(-1)}
          disabled={!canStep}
          aria-label={t('find.previous')}
          className={BAR_BTN}
        >
          <CaretUp size={15} />
        </button>
      </HoverLabel>
      <HoverLabel label={t('find.nextTitle')} position="below">
        <button
          type="button"
          onMouseDown={(e) => e.preventDefault()}
          onClick={() => onStep(1)}
          disabled={!canStep}
          aria-label={t('find.next')}
          className={BAR_BTN}
        >
          <CaretDown size={15} />
        </button>
      </HoverLabel>
    </>
  );
}
