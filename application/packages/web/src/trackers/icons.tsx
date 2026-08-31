import type { ReactNode } from 'react';
import {
  Barbell,
  Coffee,
  Drop,
  Footprints,
  Heart,
  Heartbeat,
  Lightning,
  Monitor,
  Moon,
  MoonStars,
  PersonSimpleRun,
  Pill,
  Smiley,
  SmileySad,
  Target,
  Users,
} from '../icons';

/**
 * Compact glyphs shown on filled tracker pills. Keys match the built-in
 * tracker IDs used in `trackerSettings.activeBuiltins`. Weight comes from
 * the sitewide IconDefaults provider.
 */
export const TRACKER_ICONS: Record<string, ReactNode> = {
  mood: <Smiley size={12} />,
  emotions: <Heart size={12} />,
  sleep: <Moon size={12} />,
  activity: <PersonSimpleRun size={12} />,
  energy: <Lightning size={12} />,
  focus: <Target size={12} />,
  sleepScore: <MoonStars size={12} />,
  heartRate: <Heartbeat size={12} />,
  medication: <Pill size={12} />,
  weight: <Barbell size={12} />,
  steps: <Footprints size={12} />,
  water: <Drop size={12} />,
  screenTime: <Monitor size={12} />,
  caffeine: <Coffee size={12} />,
  pain: <SmileySad size={12} />,
  social: <Users size={12} />,
};
