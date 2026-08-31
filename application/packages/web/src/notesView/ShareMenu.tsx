import { useTranslation } from 'react-i18next';
import type { LocalNote } from '../db';
import { Export, Fire } from '../icons';
import { HoverLabel } from '../HoverLabel';

export function ShareMenu({
  open,
  onClose,
  onToggle,
  compactHeaderActions,
  zenMode,
  selected,
  notes,
  exportSingleMarkdown,
  exportSingleHtml,
  exportAllMarkdownZip,
  exportAllHtmlZip,
  exportAllJson,
  printNote,
  handleBurnShare,
}: {
  open: boolean;
  onClose: () => void;
  onToggle: () => void;
  compactHeaderActions: boolean;
  zenMode: boolean;
  selected: LocalNote;
  notes: LocalNote[];
  exportSingleMarkdown: (n: LocalNote) => Promise<void> | void;
  exportSingleHtml: (n: LocalNote) => Promise<void> | void;
  exportAllMarkdownZip: (ns: LocalNote[]) => Promise<void> | void;
  exportAllHtmlZip: (ns: LocalNote[]) => Promise<void> | void;
  exportAllJson: (ns: LocalNote[]) => Promise<void> | void;
  printNote: (n: LocalNote) => Promise<void> | void;
  handleBurnShare: (n: LocalNote) => Promise<void> | void;
}) {
  const { t } = useTranslation('notes');
  return (
    <>
      {/* Share / Export button - collapses into the "..." menu when
          the header is narrow. Desktop dropdown owns both per-note
          exports and whole-vault backups. */}
      <div className={`relative shrink-0 ${compactHeaderActions || zenMode ? 'hidden' : 'block'}`}>
        <HoverLabel label={t('share.hover')} position="below">
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
      {open && (
        <>
          {/* invisible backdrop to catch outside clicks */}
          <div
            className="fixed inset-0 z-40"
            onClick={onClose}
          />
          <div className="fixed end-2 z-50 w-72 rounded-lg border border-divider bg-surface-2 shadow-xl overflow-y-auto text-sm" style={{ top: '3.5rem', maxHeight: 'calc(100vh - 4.5rem)' }}>
              <div className="px-3 pt-3 pb-1 text-[11px] uppercase tracking-wide text-neutral-500 dark:text-neutral-600">
                {t('share.thisNote')}
              </div>
              <button
                onClick={() => {
                  onClose();
                  void exportSingleMarkdown(selected);
                }}
                className="w-full text-start px-3 py-2 hover:bg-surface-1 transition"
              >
                <div className="font-medium text-pn">
                  {t('share.currentMdTitle')}
                </div>
                <div className="text-[12px] text-neutral-500">
                  {t('share.currentMdDesc')}
                </div>
              </button>
              <button
                onClick={() => {
                  onClose();
                  void exportSingleHtml(selected);
                }}
                className="w-full text-start px-3 py-2 hover:bg-surface-1 transition"
              >
                <div className="font-medium text-pn">
                  {t('share.currentHtmlTitle')}
                </div>
                <div className="text-[12px] text-neutral-500">
                  {t('share.currentHtmlDesc')}
                </div>
              </button>
              <button
                onClick={() => {
                  onClose();
                  void printNote(selected);
                }}
                className="w-full text-start px-3 py-2 hover:bg-surface-1 transition"
              >
                <div className="font-medium text-pn">
                  {t('share.printTitle')}
                </div>
                <div className="text-[12px] text-neutral-500">
                  {t('share.printDesc')}
                </div>
              </button>
              <button
                onClick={() => {
                  onClose();
                  void handleBurnShare(selected);
                }}
                className="w-full text-start px-3 py-2 hover:bg-surface-1 transition"
              >
                <div className="font-medium text-orange-600 dark:text-orange-400 flex items-center gap-1.5">
                  <Fire />
                  {t('share.burnTitle')}
                </div>
                <div className="text-[12px] text-neutral-500">
                  {t('share.burnDesc')}
                </div>
              </button>
              <div className="border-t border-divider" />
              <div className="px-3 pt-3 pb-1 text-[11px] uppercase tracking-wide text-neutral-500 dark:text-neutral-600">
                {t('share.backup')}
              </div>
              <button
                onClick={() => {
                  onClose();
                  void exportAllMarkdownZip(notes);
                }}
                className="w-full text-start px-3 py-2 hover:bg-surface-1 transition"
              >
                <div className="font-medium text-pn">
                  {t('share.fullBackupTitle')}
                </div>
                <div className="text-[12px] text-neutral-500">
                  {t('share.fullBackupDesc')}
                </div>
              </button>
              <button
                onClick={() => {
                  onClose();
                  void exportAllHtmlZip(notes);
                }}
                className="w-full text-start px-3 py-2 hover:bg-surface-1 transition"
              >
                <div className="font-medium text-pn">
                  {t('share.allHtmlTitle')}
                </div>
                <div className="text-[12px] text-neutral-500">
                  {t('share.allHtmlDesc')}
                </div>
              </button>
              <button
                onClick={() => {
                  onClose();
                  void exportAllJson(notes);
                }}
                className="w-full text-start px-3 py-2 hover:bg-surface-1 transition"
              >
                <div className="font-medium text-pn">
                  {t('share.jsonTitle')}
                </div>
                <div className="text-[12px] text-neutral-500">
                  {t('share.jsonDesc')}
                </div>
              </button>
            </div>
          </>
        )}
    </>
  );
}
