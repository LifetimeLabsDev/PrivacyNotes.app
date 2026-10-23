import type { ReactNode } from 'react';
import { NotePencil } from '../icons';
import type { LookColor, NoteColorChoice } from '../itemStyles';

/**
 * One note row as a folder or tag color shows on it under each "Folder and
 * tag colors" choice: the whole row tinted, only its icon, or neither. The
 * Design pane draws it under the control, and the look picker draws it with
 * the color being picked, so the effect shows before the picker closes.
 */
export function NoteColorExample({
  choice,
  color,
  title,
  source,
}: {
  choice: NoteColorChoice;
  color: LookColor;
  title: string;
  /** The line under the title: the folder or tag the color comes from. */
  source: ReactNode;
}) {
  const tint = `var(--pn-label-${color}-tint)`;
  return (
    <div
      className="flex items-center gap-3 rounded-md bg-surface-1 px-2.5 py-2"
      style={choice === 'background' ? { backgroundImage: `linear-gradient(${tint}, ${tint})` } : undefined}
    >
      <span
        className={`flex h-7 w-7 shrink-0 items-center justify-center rounded-md ${choice === 'off' ? 'bg-pn/5 text-accent' : ''}`}
        style={choice === 'off' ? undefined : { background: tint, color: `var(--pn-label-${color}-ink)` }}
        aria-hidden="true"
      >
        <NotePencil size={15} />
      </span>
      <div className="min-w-0">
        <p className="truncate text-[13px] font-semibold text-pn">{title}</p>
        <p className="flex items-center gap-1 text-[11px] text-pn-muted truncate" dir="auto">{source}</p>
      </div>
    </div>
  );
}
