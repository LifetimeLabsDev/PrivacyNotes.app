import type { ReactNode } from 'react';
import { LinksList, type ModalLink } from './LinksList';
import { Modal } from './ui';

export type { ModalLink };

type Props = {
  title: string;
  /** Optional mark before the title, for a surface with its own identity. */
  titleIcon?: ReactNode;
  intro: string;
  links: readonly ModalLink[];
  /** Optional extra block between the links and the closing line. */
  children?: ReactNode;
  /** Optional closing line under the links. */
  outro?: ReactNode;
  /** Forwarded to LinksList - see there. */
  onLinkClick?: () => void;
  /** Forwarded to LinksList, and widens the modal so two columns fit. */
  grid?: boolean;
  onClose: () => void;
};

// Shared shell for the small external-links modals (Feedback, Rate): header
// with title + close, an intro line, then one row per link with icon, label,
// description and an external-arrow affordance. Extracted from FeedbackModal
// when the Rate modal reused the same layout.
export function LinksModal({ title, titleIcon, intro, links, children, outro, onLinkClick, onClose, grid = false }: Props) {

  return (
    <Modal onClose={onClose} title={title} icon={titleIcon} header="bar" className={`${grid ? 'max-w-2xl' : 'max-w-sm'} max-h-full overflow-y-auto`}>

        {/* Body */}
        <div className="px-5 py-4">
          <p className="text-sm text-pn-muted mb-3">{intro}</p>
          <LinksList links={links} onLinkClick={onLinkClick} grid={grid} />
          {children}
          {outro && (
            <p className="mt-3 pt-3 border-t border-divider text-xs leading-relaxed text-pn-muted">
              {outro}
            </p>
          )}
        </div>
    </Modal>
  );
}
