import type { CSSProperties, ReactNode } from 'react';
import { Heartbeat } from '../icons';
import { PathGlyph } from '../looks/LookGlyph';
import { useLookIcons } from '../looks/lookIconsLoader';

/**
 * A custom tracker's own icon, from the look icon catalog that notes, folders
 * and tags pick from. Without one, and while the catalog loads, it draws the
 * Trackers heartbeat, the glyph of Settings > Trackers.
 * Spec: ops/docs/mood-wellness-tracker.md (section 16.3)
 */
export function CustomTrackerGlyph({ icon, size = 12, className, style }: {
  icon?: string;
  size?: number;
  className?: string;
  style?: CSSProperties;
}) {
  const catalog = useLookIcons(!!icon);
  const paths = icon ? catalog?.LOOK_ICONS[icon] : undefined;
  if (!paths) return <Heartbeat size={size} className={className} style={style} aria-hidden="true" />;
  return <PathGlyph paths={paths} size={size} className={className} style={style} />;
}

/** The tinted square of a setup row in Settings > Trackers: a custom
 *  tracker's icon, or a medication's form glyph, in its own color. */
export function MarkTile({ color, children }: { color?: string; children: ReactNode }) {
  return (
    <span
      className="w-9 h-9 rounded-lg flex items-center justify-center shrink-0 border border-divider bg-surface-2"
      style={color ? { background: `color-mix(in srgb, ${color} 14%, var(--color-surface-2))` } : undefined}
    >
      {children}
    </span>
  );
}
