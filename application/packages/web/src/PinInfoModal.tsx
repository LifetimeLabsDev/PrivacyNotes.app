import { createPortal } from 'react-dom';
import { useEscapeToClose } from './useEscapeToClose';
import { X } from './icons';

type Props = { onClose: () => void };

export function PinInfoModal({ onClose }: Props) {
  useEscapeToClose(onClose);
  return createPortal(
    <div className="fixed inset-0 bg-black/50 dark:bg-black/70 flex items-center justify-center p-4 z-50" onClick={onClose}>
      <div className="bg-surface-2 border border-divider text-pn rounded-lg max-w-sm w-full p-5 space-y-3" onClick={(e) => e.stopPropagation()}>
        <div className="flex items-start justify-between">
          <h2 className="text-base font-semibold">Require PIN to view</h2>
          <button onClick={onClose} className="text-neutral-400 hover:text-neutral-600 dark:hover:text-neutral-300 transition p-1 -m-1" aria-label="Close">
            <X size={18} />
          </button>
        </div>
        <p className="text-sm text-neutral-600 dark:text-neutral-400 leading-relaxed">
          When enabled, your PIN is required every time you open this item, even if the app is already unlocked. Use it for sensitive items that should stay protected when you step away.
        </p>
        <button onClick={onClose} className="w-full rounded-md bg-accent text-white hover:bg-accent-hover px-4 py-2 text-sm font-medium transition">Got it</button>
      </div>
    </div>,
    document.body,
  );
}
