import { Trans } from 'react-i18next';
import { PencilSimpleSlash } from './icons';

/**
 * Says how many of the items a confirm modal asks about are read-only and
 * will therefore stay where they are. Renders nothing when none of them
 * are, so a caller can hand it a raw count without a guard of its own.
 */
export function ReadOnlySkipNotice({ count }: { count: number }) {
  if (count === 0) return null;
  return (
    <div className="mt-3 flex items-start gap-2 rounded-md border border-divider bg-surface-1 text-[13px] leading-snug p-3">
      <PencilSimpleSlash size={16} className="shrink-0 mt-0.5" />
      <span>
        <Trans
          i18nKey="notes:bulkTrash.readOnlySkipped"
          count={count}
          values={{ count }}
          components={{ highlight: <span className="font-medium text-pn" /> }}
        />
      </span>
    </div>
  );
}
