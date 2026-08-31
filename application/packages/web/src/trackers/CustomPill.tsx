import { useMemo, useState } from 'react';
import { useTranslation } from 'react-i18next';
import type { CustomTrackerTemplate } from '../trackerTypes';
import { PillShell, useCommitOnCollapse } from './PillShell';

// Spec: ops/docs/design-decisions.md (number tracker bounds - prevents scientific-notation display)
const MAX_NUMBER = 1e12;

/** Clamp to a sane magnitude and round to 4 decimals so the value never stringifies to exponential form. Returns null for non-numeric input. */
function sanitizeNumber(raw: string): number | null {
  const n = parseFloat(raw);
  if (isNaN(n)) return null;
  const clamped = Math.max(-MAX_NUMBER, Math.min(MAX_NUMBER, n));
  return Math.round(clamped * 10000) / 10000;
}

/**
 * Custom (Pro) tracker pill. Picker shape by template type:
 * scale10 (0-10), scale5 (0-5), slider100 (0-100), number (+unit), yesno.
 */
export function CustomPill({
  template,
  value,
  expanded,
  onToggle,
  onChange,
  readOnly,
}: {
  template: CustomTrackerTemplate;
  value?: number | boolean | string;
  expanded: boolean;
  onToggle: () => void;
  onChange: (v: number | boolean | string) => void;
  readOnly?: boolean;
}) {
  const { t } = useTranslation('trackers');
  const [draft, setDraft] = useState('');

  // Closing the picker saves the typed number - see the hook. Only the
  // 'number' shape has a free-text field; the scales and yes/no commit
  // on the tap itself.
  useCommitOnCollapse(expanded, () => {
    if (template.type !== 'number') return;
    const n = sanitizeNumber(draft);
    if (n != null) onChange(n);
  });

  const filledLabel = useMemo(() => {
    if (value == null) return undefined;
    if (template.type === 'yesno') return value ? t('custom.yes') : t('custom.no');
    if (template.type === 'slider100') return `${value}`;
    if (template.type === 'number') return `${value}`;
    return `${value}/${template.type === 'scale5' ? 5 : 10}`;
  }, [value, template.type, t]);

  return (
    <PillShell
      label={template.name}
      color={template.color}
      filled={value != null}
      expanded={expanded}
      onToggle={() => {
        if (!expanded) setDraft(value != null ? String(value) : '');
        onToggle();
      }}
      filledLabel={filledLabel}
      readOnly={readOnly}
    >
      <div className="flex flex-col gap-2">
        <span className="text-xs font-medium text-neutral-600 dark:text-neutral-300">
          {template.name}
        </span>
        {template.type === 'scale10' && (
          <div className="flex gap-1">
            {Array.from({ length: 11 }, (_, i) => i).map((n) => (
              <button
                key={n}
                type="button"
                onClick={() => { onChange(n); onToggle(); }}
                className={`w-6 h-6 rounded text-[10px] font-semibold transition-colors ${
                  value === n
                    ? 'text-white'
                    : 'bg-surface-0 text-neutral-600 dark:text-neutral-300 hover:opacity-80'
                }`}
                style={value === n ? { backgroundColor: template.color } : undefined}
              >
                {n}
              </button>
            ))}
          </div>
        )}
        {template.type === 'scale5' && (
          <div className="flex gap-1">
            {Array.from({ length: 6 }, (_, i) => i).map((n) => (
              <button
                key={n}
                type="button"
                onClick={() => { onChange(n); onToggle(); }}
                className={`w-8 h-8 rounded-md text-xs font-semibold transition-colors ${
                  value === n
                    ? 'text-white'
                    : 'bg-surface-0 text-neutral-600 dark:text-neutral-300 hover:opacity-80'
                }`}
                style={value === n ? { backgroundColor: template.color } : undefined}
              >
                {n}
              </button>
            ))}
          </div>
        )}
        {template.type === 'slider100' && (
          <div className="flex items-center gap-3">
            <input
              type="range"
              min={0}
              max={100}
              step={1}
              value={typeof value === 'number' ? value : 50}
              onChange={(e) => onChange(parseInt(e.target.value, 10))}
              className="flex-1 h-1.5 cursor-pointer"
              style={{ accentColor: template.color }}
            />
            <span className="text-sm font-medium text-neutral-700 dark:text-neutral-200 w-8 text-end tabular-nums">
              {typeof value === 'number' ? value : 50}
            </span>
          </div>
        )}
        {template.type === 'number' && (
          <div className="flex items-center gap-2">
            <input
              type="number"
              inputMode="decimal"
              step="any"
              placeholder="0"
              value={draft}
              onChange={(e) => setDraft(e.target.value.slice(0, 16))}
              onKeyDown={(e) => {
                if (e.key === 'Enter') {
                  const n = sanitizeNumber(draft);
                  if (n != null) { onChange(n); onToggle(); }
                }
              }}
              className="w-24 px-2.5 py-1.5 rounded-md text-sm border border-neutral-300 dark:border-neutral-600 bg-surface-0 text-neutral-800 dark:text-neutral-200 tabular-nums"
              autoFocus
            />
            <button
              type="button"
              onClick={() => {
                const n = sanitizeNumber(draft);
                if (n != null) { onChange(n); onToggle(); }
              }}
              className="px-3 py-1.5 rounded-md text-xs font-medium text-white transition-colors"
              style={{ backgroundColor: template.color }}
            >
              {t('common:actions.save')}
            </button>
          </div>
        )}
        {template.type === 'yesno' && (
          <div className="flex gap-2">
            {[true, false].map((v) => (
              <button
                key={String(v)}
                type="button"
                onClick={() => { onChange(v); onToggle(); }}
                className={`flex-1 px-3 py-1.5 rounded-md text-xs font-medium transition-colors ${
                  value === v
                    ? 'text-white'
                    : 'bg-surface-0 text-neutral-600 dark:text-neutral-300 hover:opacity-80'
                }`}
                style={value === v ? { backgroundColor: template.color } : undefined}
              >
                {v ? t('custom.yes') : t('custom.no')}
              </button>
            ))}
          </div>
        )}
      </div>
    </PillShell>
  );
}
