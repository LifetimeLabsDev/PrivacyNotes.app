import type { ReactNode } from 'react';
import { useTranslation } from 'react-i18next';
import { useEscapeToClose } from './useEscapeToClose';
import { LinksList, type ModalLink } from './LinksList';
import { X } from './icons';

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
  const { t } = useTranslation('common');
  useEscapeToClose(onClose);

  return (
    <div
      className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 sm:p-6 z-50"
      onClick={onClose}
    >
      <div
        className={`bg-surface-2 border border-divider text-pn rounded-lg ${grid ? 'max-w-2xl' : 'max-w-sm'} w-full max-h-full overflow-y-auto`}
        onClick={(e) => e.stopPropagation()}
      >
        {/* Header */}
        <div className="flex items-center justify-between px-5 py-4 border-b border-divider">
          <h2 className="text-base font-semibold inline-flex items-center gap-2">
            {titleIcon}
            {title}
          </h2>
          <button
            onClick={onClose}
            className="text-pn-muted hover:text-pn-soft transition p-1 -m-1"
            aria-label={t('actions.close')}
          >
            <X size={18} />
          </button>
        </div>

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
      </div>
    </div>
  );
}
