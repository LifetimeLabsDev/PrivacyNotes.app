import {
  ArrowClockwise,
  ArrowCounterClockwise,
  BoxArrowDown,
  BoxArrowUp,
  DownloadSimple,
  Eye,
  EyeSlash,
  ArrowLeft,
  ArrowRight,
  ArrowSquareOut,
  Check,
  Checks,
  Copy,
  FloppyDisk,
  MagnifyingGlass,
  PencilSimple,
  Password,
  ArrowsClockwise,
  Plus,
  Trash,
  XSquare,
} from '../icons';
import type { ComponentType } from 'react';
import type { IconProps } from '@phosphor-icons/react';

type Variant = 'secondary' | 'accent' | 'primary' | 'danger' | 'upgrade';

/**
 * One icon, one label and one look per action, so every Save in the app shows
 * the same glyph and word. `label` is a key in `common:actions`, or null when
 * the caller words it (Restore, Apply, Open take the object's own word).
 * Spec: ops/docs/archive/design-system.md
 */
export const ACTIONS = {
  save: { icon: FloppyDisk, label: 'save', variant: 'primary' },
  add: { icon: Plus, label: 'add', variant: 'primary' },
  create: { icon: Plus, label: 'create', variant: 'primary' },
  done: { icon: Check, label: 'done', variant: 'primary' },
  finish: { icon: Checks, label: null, variant: 'primary' },
  confirm: { icon: Check, label: 'confirm', variant: 'primary' },
  apply: { icon: Check, label: null, variant: 'primary' },
  next: { icon: ArrowRight, label: 'next', variant: 'primary' },
  restore: { icon: ArrowCounterClockwise, label: null, variant: 'primary' },
  delete: { icon: Trash, label: 'delete', variant: 'danger' },
  remove: { icon: Trash, label: 'remove', variant: 'danger' },
  cancel: { icon: XSquare, label: 'cancel', variant: 'secondary' },
  back: { icon: ArrowLeft, label: 'back', variant: 'secondary' },
  edit: { icon: PencilSimple, label: 'edit', variant: 'secondary' },
  rename: { icon: PencilSimple, label: 'rename', variant: 'secondary' },
  copy: { icon: Copy, label: 'copy', variant: 'secondary' },
  search: { icon: MagnifyingGlass, label: 'search', variant: 'secondary' },
  open: { icon: ArrowSquareOut, label: null, variant: 'secondary' },
  view: { icon: Eye, label: null, variant: 'secondary' },
  hide: { icon: EyeSlash, label: null, variant: 'secondary' },
  download: { icon: DownloadSimple, label: null, variant: 'secondary' },
  import: { icon: BoxArrowDown, label: null, variant: 'secondary' },
  export: { icon: BoxArrowUp, label: null, variant: 'secondary' },
  generate: { icon: Password, label: null, variant: 'accent' },
  regenerate: { icon: ArrowsClockwise, label: null, variant: 'secondary' },
  retry: { icon: ArrowClockwise, label: null, variant: 'secondary' },
} as const satisfies Record<string, { icon: ComponentType<IconProps>; label: string | null; variant: Variant }>;

export type ActionName = keyof typeof ACTIONS;
