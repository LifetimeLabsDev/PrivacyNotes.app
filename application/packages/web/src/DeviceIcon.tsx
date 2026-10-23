import type { ComponentType } from 'react';
import {
  AndroidLogo,
  AppleLogo,
  Browser,
  DeviceMobile,
  DeviceTablet,
  Devices,
  GoogleChromeLogo,
  Laptop,
  LinuxLogo,
  WindowsLogo,
  type IconProps,
} from './icons';
import type { DeviceRow } from './devices';
import { deviceLook, type DeviceKind, type DeviceOs } from './deviceLook';

/**
 * The OS logo in its brand color, with a badge for the kind of device. The
 * brand greens and yellows are darker on a light theme, where the official
 * marks fall under 3:1 against a light surface.
 * Spec: ops/docs/archive/ui-patterns.md (section 142, Registered devices row)
 */
const OS_LOGO: Record<DeviceOs, { Icon: ComponentType<IconProps>; color: string }> = {
  apple: { Icon: AppleLogo, color: 'text-pn' },
  windows: { Icon: WindowsLogo, color: 'text-[#0078D4] dark:text-[#4CC2FF]' /* theme-ok: Windows brand mark */ },
  android: { Icon: AndroidLogo, color: 'text-[#1E8E4E] dark:text-[#3DDC84]' /* theme-ok: Android brand mark */ },
  linux: { Icon: LinuxLogo, color: 'text-[#B7791F] dark:text-[#F5C211]' /* theme-ok: Linux brand mark */ },
  chromeos: { Icon: GoogleChromeLogo, color: 'text-pn' },
  other: { Icon: Devices, color: 'text-pn-muted' },
};

const KIND_BADGE: Record<DeviceKind, ComponentType<IconProps>> = {
  computer: Laptop,
  browser: Browser,
  phone: DeviceMobile,
  tablet: DeviceTablet,
};

export function DeviceIcon({ row }: { row: Pick<DeviceRow, 'platform' | 'device_name'> }) {
  const { os, kind } = deviceLook(row);
  const { Icon, color } = OS_LOGO[os];
  const Badge = KIND_BADGE[kind];
  return (
    <span aria-hidden="true" className="relative shrink-0 flex items-center justify-center w-8 h-8 rounded-lg bg-surface-2 border border-divider">
      <Icon size={18} weight={os === 'other' ? 'bold' : 'fill'} className={color} />
      <span className="absolute -bottom-1 -end-1 flex items-center justify-center w-4 h-4 rounded-full bg-surface-1 border border-divider text-pn-muted">
        <Badge size={9} weight="fill" />
      </span>
    </span>
  );
}
