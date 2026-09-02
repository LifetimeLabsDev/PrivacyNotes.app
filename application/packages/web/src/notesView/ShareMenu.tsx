import { useEffect, useRef } from 'react';
import { createPortal } from 'react-dom';
import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import { Export, Fire, FileMd, FileHtml, Printer } from '../icons';
import { HoverLabel } from '../HoverLabel';
import { usePopoverPosition } from '../usePopoverPosition';

export function ShareMenu({
  open,
  onClose,
  onToggle,
  zenMode,
  selected,
  exportSingleMarkdown,
  exportSingleHtml,
  printNote,
  handleBurnShare,
}: {
  open: boolean;
  onClose: () => void;
  onToggle: () => void;
  zenMode: boolean;
  selected: LocalNote;
  exportSingleMarkdown: (n: LocalNote) => Promise<void> | void;
  exportSingleHtml: (n: LocalNote) => Promise<void> | void;
  printNote: (n: LocalNote) => Promise<void> | void;
  handleBurnShare: (n: LocalNote) => Promise<void> | void;
}) {
  const { t } = useTranslation('notes');
  const anchorRef = useRef<HTMLDivElement | null>(null);
  const panelRef = useRef<HTMLDivElement | null>(null);
  // Positioned by the same hook and the same alignment as the "..." menu one
  // button along, and for the same reason it was needed there: the panel used
  // to be pinned to the viewport at a fixed 3.5rem, which assumes the header
  // starts at the top of the window. It does not whenever a banner sits above
  // the shell - the demo bar, or an announcement - and the panel then opened
  // ON TOP of the button that had just been pressed. The hook measures the
  // trigger, opens below it, and flips above when there is no room.
  // Spec: ops/docs/ui-patterns.md (section 15)
  const pos = usePopoverPosition(open, anchorRef, panelRef, { align: 'end' });

  // Close on an outside pointerdown, ignoring the trigger so it can toggle
  // without a re-open flicker. Same handler shape as NoteOptionsMenu.
  useEffect(() => {
    if (!open) return;
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (panelRef.current && panelRef.current.contains(target)) return;
      if (anchorRef.current && anchorRef.current.contains(target)) return;
      onClose();
    }
    window.addEventListener('pointerdown', handler, true);
    return () => window.removeEventListener('pointerdown', handler, true);
  }, [open, onClose]);

  return (
    <>
      {/* Share / Export button. It holds its place at every width, because
          it is the action people reach for and the header no longer carries
          burn, pin or trash to crowd it. Zen is the one place it stands
          down, and the "..." menu grows a Share cell there instead. The
          dropdown owns both per-note exports and whole-vault backups. */}
      <div ref={anchorRef} className={`shrink-0 ${zenMode ? 'hidden' : 'block'}`}>
        {/* Same tip placement as the "..." button beside it: both sit at
            the end of the row, and a centred tip on the last control is cut
            by the window edge. */}
        <HoverLabel label={t('share.hover')} position="below-end">
          <button
            onClick={onToggle}
            aria-label={t('share.ariaLabel')}
            aria-expanded={open}
            className={`shrink-0 flex items-center justify-center w-8 h-8 rounded-md transition ${
              open
                ? 'text-accent bg-accent/15'
                : 'text-neutral-600 dark:text-neutral-300 active:scale-95 [@media(hover:hover)]:hover:text-accent [@media(hover:hover)]:hover:bg-neutral-200 [@media(hover:hover)]:dark:hover:bg-neutral-800'
            }`}
          >
          {/* 18px in a 32px box, the size every button in the editor header
              wears. Spec: ops/docs/ui-patterns.md (section 80) */}
          <Export size={18} />
          </button>
        </HoverLabel>
      </div>
      {open && createPortal(
        (
          <div
            ref={panelRef}
            role="dialog"
            aria-label={t('share.ariaLabel')}
            className="fixed z-50 w-72 max-h-[calc(100vh-16px)] overflow-y-auto rounded-lg border border-divider bg-surface-2 shadow-lg text-sm py-1"
            style={{
              top: pos?.top ?? 0,
              left: pos?.left ?? 0,
              visibility: pos ? 'visible' : 'hidden',
            }}
          >
              {/* Icon column in accent, the grammar the "..." menu next door
                  already uses, and the same marks the Export tab of Settings
                  > Import & Export wears for these file types. Burn keeps its
                  orange, because colour in this header means burn or
                  destructive and never decoration. */}
              <button
                onClick={() => {
                  onClose();
                  void exportSingleMarkdown(selected);
                }}
                className="w-full text-start px-3 py-2.5 flex items-start gap-2.5 hover:bg-surface-1 transition"
              >
                <span className="shrink-0 mt-0.5 text-accent"><FileMd size={18} aria-hidden="true" /></span>
                <span className="min-w-0">
                  <span className="block font-medium text-pn">
                    {t('share.currentMdTitle')}
                  </span>
                  <span className="block text-[12px] text-neutral-500">
                    {t('share.currentMdDesc')}
                  </span>
                </span>
              </button>
              <button
                onClick={() => {
                  onClose();
                  void exportSingleHtml(selected);
                }}
                className="w-full text-start px-3 py-2.5 flex items-start gap-2.5 hover:bg-surface-1 transition"
              >
                <span className="shrink-0 mt-0.5 text-accent"><FileHtml size={18} aria-hidden="true" /></span>
                <span className="min-w-0">
                  <span className="block font-medium text-pn">
                    {t('share.currentHtmlTitle')}
                  </span>
                  <span className="block text-[12px] text-neutral-500">
                    {t('share.currentHtmlDesc')}
                  </span>
                </span>
              </button>
              <button
                onClick={() => {
                  onClose();
                  void printNote(selected);
                }}
                className="w-full text-start px-3 py-2.5 flex items-start gap-2.5 hover:bg-surface-1 transition"
              >
                <span className="shrink-0 mt-0.5 text-accent"><Printer size={18} aria-hidden="true" /></span>
                <span className="min-w-0">
                  <span className="block font-medium text-pn">
                    {t('share.printTitle')}
                  </span>
                  <span className="block text-[12px] text-neutral-500">
                    {t('share.printDesc')}
                  </span>
                </span>
              </button>
              <button
                onClick={() => {
                  onClose();
                  void handleBurnShare(selected);
                }}
                className="w-full text-start px-3 py-2.5 flex items-start gap-2.5 hover:bg-surface-1 transition"
              >
                <span className="shrink-0 mt-0.5 text-orange-600 dark:text-orange-400"><Fire size={18} aria-hidden="true" /></span>
                <span className="min-w-0">
                  <span className="block font-medium text-orange-600 dark:text-orange-400">
                    {t('share.burnTitle')}
                  </span>
                  <span className="block text-[12px] text-neutral-500">
                    {t('share.burnDesc')}
                  </span>
                </span>
              </button>
          </div>
        ),
        document.body,
      )}
    </>
  );
}
