import { HoverLabel } from '../HoverLabel';
import { FIELD_BUTTON } from '../formFields';
import { ACTIONS } from './actions';

/**
 * @catalog VaultFieldAction
 * use: copy, reveal and download beside Login, Card and SSH fields. Preserves FIELD_BUTTON spacing and tooltip placement. Copy feedback uses the success token; the owning form supplies the successful-copy state and existing clipboard callback. Reveal exposes its pressed state. Icons come from ACTIONS.
 * never: replacing generic CopyButton (which owns clipboard state), changing a form's shared copy timer, or moving secret values into this presentation component. Pass labels and callbacks, never the secret itself.
 */
export function VaultFieldAction({ kind, active = false, title, onClick }: {
  kind: 'copy' | 'reveal' | 'download';
  active?: boolean;
  title: string;
  onClick: () => void;
}) {
  const Glyph = kind === 'copy'
    ? (active ? ACTIONS.done.icon : ACTIONS.copy.icon)
    : kind === 'reveal'
      ? (active ? ACTIONS.hide.icon : ACTIONS.view.icon)
      : ACTIONS.download.icon;
  return <HoverLabel label={title} position={kind === 'reveal' ? 'above' : 'start'}>
    <button type="button" onClick={onClick} aria-label={title}
      aria-pressed={kind === 'reveal' ? active : undefined} className={FIELD_BUTTON}>
      <Glyph size={16} aria-hidden="true" className={kind === 'copy' && active ? 'text-success' : undefined} />
    </button>
  </HoverLabel>;
}
