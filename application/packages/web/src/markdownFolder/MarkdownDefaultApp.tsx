/**
 * The "open .md files with PrivacyNotes" control, in its three homes.
 *
 * One body, three frames, because the same handful of facts has to fit three
 * very different amounts of room:
 *
 *   - `MarkdownDefaultAppPopover` - behind the folder toolbar's Markdown button.
 *     The only home that exists in grid mode, where the file pane is hidden
 *     outright and the resting card below never renders.
 *   - `MarkdownDefaultAppCard` - the resting file pane, under "Open a Markdown
 *     file to read it here". Replaced the pitch that used to sit there: a reader
 *     with a folder already open has read the pitch, and this is the one thing
 *     left to tell them.
 *   - `MarkdownDefaultAppRow` - the last row of `MarkdownPitch`, so the explainer
 *     modal and the no-folder empty state both carry it for free.
 *
 * Every frame renders NOTHING off the desktop app, and nothing until the first
 * status has come back - a control that flickers from "make this the default" to
 * "already the default" on mount is worse than one that appears a beat late.
 *
 * It is a button, not a toggle, and `defaultApp.ts` explains why: no
 * platform has an API to stop being the default handler.
 *
 * Spec: ops/docs/plans/markdown-folder.md (section 11)
 */
import { useEffect, useRef, useState } from 'react';
import { useTranslation } from 'react-i18next';
import { ArrowSquareOut, CheckCircle, FileMd } from '../icons';
import { useEscapeToClose } from '../useEscapeToClose';
import {
  claimMarkdownDefaultApp,
  markMarkdownDefaultAppOurs,
  openOsDefaultAppSettings,
  useMarkdownDefaultApp,
  type MarkdownAssoc,
} from './defaultApp';

/** Which file manager the hint names. Driven by the platform the Rust side
 *  reports, never by the user agent. Linux has no one file manager to name, so
 *  it gets the generic phrase - which is also why these are three strings
 *  rather than one with a `{{app}}`: "Finder" must not be translated and "your
 *  file manager" must be. */
const HINT_KEY: Record<MarkdownAssoc['platform'], string> = {
  macos: 'markdown.assocHintFinder',
  windows: 'markdown.assocHintExplorer',
  linux: 'markdown.assocHintFileManager',
};

/**
 * The shared behaviour: current status, the one action, and whether it failed.
 *
 * The action is "claim" on macOS and Linux and "open Settings" on Windows,
 * decided by `settable` rather than by the platform string, so the day a
 * platform changes its mind only the native side moves.
 */
function useDefaultAppAction() {
  const assoc = useMarkdownDefaultApp();
  const [busy, setBusy] = useState(false);
  const [failed, setFailed] = useState(false);

  // A failure describes one attempt against one OS state, so it has to expire
  // when that state changes. Without this, a user whose claim failed and who then
  // set the default in System Settings comes back to the green success statement
  // with the red "Could not change the default app" still sitting under it -
  // nothing else ever clears the flag except another click on the same button,
  // and in the success state there is no button left to click.
  useEffect(() => { setFailed(false); }, [assoc?.owner]);

  async function run() {
    if (!assoc || busy) return;
    setBusy(true);
    setFailed(false);
    try {
      if (assoc.settable) {
        await claimMarkdownDefaultApp();
        // Publish the outcome locally instead of reading the OS back. The
        // read-back used to be here and was wrong twice over: LaunchServices
        // answers an in-process read from a cache that has not caught up with the
        // write, so it could report the handler we just replaced, and resolving a
        // bundle id can take tens of seconds on a machine carrying a lot of stale
        // registrations - the disabled button and the unchanged status came from
        // exactly that pair. The OS already said the write succeeded; the next
        // window focus reconciles against reality.
        markMarkdownDefaultAppOurs();
      } else {
        // Windows. Nothing to re-read yet - the user has not chosen anything
        // yet, and the window's own focus listener picks up whatever they do.
        await openOsDefaultAppSettings();
      }
    } catch {
      setFailed(true);
    } finally {
      setBusy(false);
    }
  }

  return { assoc, busy, failed, run };
}

/** The sentence naming who owns Markdown now, or null when there is nothing
 *  honest to say. Windows adds why we cannot change it ourselves. */
function useOwnerLine(assoc: MarkdownAssoc): string | null {
  const { t } = useTranslation('shell');
  const parts: string[] = [];
  if (assoc.owner === 'other') {
    parts.push(
      assoc.otherName
        ? t('markdown.assocOwnerOther', { app: assoc.otherName })
        : t('markdown.assocOwnerOtherUnnamed'),
    );
  } else if (assoc.owner === 'none') {
    parts.push(t('markdown.assocOwnerNone'));
  }
  // 'unknown' says nothing: the OS would not answer, so asserting anything about
  // the current handler would be invention.
  if (!assoc.settable) parts.push(t('markdown.assocWindowsManual'));
  return parts.length ? parts.join(' ') : null;
}

/**
 * The action button. Two labels for two verbs - one changes the default, the
 * other opens a settings page - and the arrow marks the second as leaving the
 * app, which is the whole difference the user needs to see before clicking.
 */
function ActionButton({
  assoc,
  busy,
  onClick,
  emphasis,
}: {
  assoc: MarkdownAssoc;
  busy: boolean;
  onClick: () => void;
  /** `solid` for the resting card, where this is the only action on a wide
   *  empty pane; `quiet` inside the popover and the pitch, where an accent fill
   *  would outrank the surrounding content. */
  emphasis: 'solid' | 'quiet';
}) {
  const { t } = useTranslation('shell');
  return (
    <button
      type="button"
      onClick={onClick}
      disabled={busy}
      className={`inline-flex items-center gap-1.5 text-[13px] font-medium px-3 py-1.5 rounded-md transition disabled:opacity-50 cursor-pointer ${
        emphasis === 'solid'
          ? 'bg-accent text-white hover:bg-accent-hover'
          : 'border border-divider bg-surface-2 text-pn hover:border-accent'
      }`}
    >
      {/* A distinct label while the OS is working, not just a disabled button.
          Setting the handler is a synchronous LaunchServices call that is
          normally instant but can run into tens of seconds where the system
          carries a lot of stale registrations of the same bundle id, and an
          unexplained dead button for that long reads as a broken feature. */}
      {busy ? (
        t('markdown.assocWorking')
      ) : assoc.settable ? (
        t('markdown.assocMakeDefault')
      ) : (
        <>
          {t('markdown.assocWindowsOpen')}
          <ArrowSquareOut size={14} className="shrink-0" />
        </>
      )}
    </button>
  );
}

/**
 * Hint, status, action - the content every frame shares.
 *
 * When we already own the association this inverts: the fact leads and the hint
 * becomes its explanation, so the finished state reads as a statement rather
 * than as an offer with the offer removed.
 */
function DefaultAppBody({
  assoc,
  busy,
  failed,
  onAction,
  emphasis,
}: {
  assoc: MarkdownAssoc;
  busy: boolean;
  failed: boolean;
  onAction: () => void;
  emphasis: 'solid' | 'quiet';
}) {
  const { t } = useTranslation('shell');
  const hint = t(HINT_KEY[assoc.platform]);
  const ownerLine = useOwnerLine(assoc);
  const isOurs = assoc.owner === 'ours';

  return (
    <>
      <p className="text-[13px] font-medium text-pn leading-snug">
        {isOurs ? t('markdown.assocOwnerOurs') : hint}
      </p>
      <p className="mt-0.5 text-[12px] text-pn-muted leading-snug">
        {isOurs ? hint : ownerLine}
      </p>
      {isOurs ? (
        <p className="mt-2 text-[11.5px] text-pn-muted leading-snug">
          {t('markdown.assocChangeHint')}
        </p>
      ) : (
        <div className="mt-2.5">
          <ActionButton assoc={assoc} busy={busy} onClick={onAction} emphasis={emphasis} />
        </div>
      )}
      {failed && (
        <p className="mt-1.5 text-[12px] text-red-600 dark:text-red-400 leading-snug">
          {t('markdown.assocFailed')}
        </p>
      )}
    </>
  );
}

/**
 * The resting file pane's card, under the "pick a file" prompt.
 *
 * Deliberately the loudest of the three frames: it has a pane to itself, it is
 * what a reader sees for as long as no file is selected, and it is the only
 * surface that tells someone double-click works without their having gone
 * looking. `null` off the desktop app, where the caller falls back to the pitch.
 */
export function MarkdownDefaultAppCard() {
  const { assoc, busy, failed, run } = useDefaultAppAction();
  if (!assoc) return null;
  const isOurs = assoc.owner === 'ours';

  return (
    // Centred as a column, icon above the text, rather than the icon-beside-text
    // row this started as. It sits alone in the middle of the widest pane in the
    // app, where everything around it - the "Open a Markdown file" prompt above,
    // and the pitch this replaced - is centred too, and a left-aligned block was
    // the only thing in that pane with an edge to align to.
    // `text-center` also carries the button: it is `inline-flex`, so text
    // alignment centres it and no flex wrapper is needed. The other two frames
    // stay start-aligned, which is why this lives here and not in the body.
    <div
      className={`rounded-lg border p-4 text-center ${
        isOurs
          ? 'border-divider bg-surface-1'
          : 'border-accent/40 bg-accent/[0.04] dark:bg-accent/[0.07]'
      }`}
    >
      <span className="flex justify-center mb-2">
        {isOurs ? (
          <CheckCircle size={22} weight="fill" className="text-green-600 dark:text-green-500" />
        ) : (
          <FileMd size={22} className="text-accent" />
        )}
      </span>
      <DefaultAppBody
        assoc={assoc}
        busy={busy}
        failed={failed}
        onAction={() => void run()}
        emphasis="solid"
      />
    </div>
  );
}

/**
 * The last row of `MarkdownPitch`, so the explainer modal and the no-folder
 * empty state carry this without either knowing it exists.
 *
 * Quietest of the three: the pitch above it is already six stacked blocks, so
 * this is a hairline and two lines rather than a card inside a card.
 */
export function MarkdownDefaultAppRow() {
  const { assoc, busy, failed, run } = useDefaultAppAction();
  if (!assoc) return null;

  return (
    <div className="mt-3 pt-3 border-t border-divider text-start">
      <DefaultAppBody
        assoc={assoc}
        busy={busy}
        failed={failed}
        onAction={() => void run()}
        emphasis="quiet"
      />
    </div>
  );
}

/**
 * Behind the folder toolbar's Markdown button.
 *
 * The toolbar is the only place this control exists in grid mode, and the row is
 * too tight for a sentence - hence a button that opens this rather than any
 * amount of inline text. Same dismissal contract as `ListPrefsPopover`:
 * pointerdown outside or Escape, with the anchor excluded so clicking the
 * trigger closes rather than flickers.
 */
export function MarkdownDefaultAppPopover({
  onClose,
  anchorRef,
  className = '',
}: {
  onClose: () => void;
  /** The trigger. Clicks inside it are the trigger's own toggle, not "outside". */
  anchorRef?: React.RefObject<HTMLElement | null>;
  /** Positioning only. */
  className?: string;
}) {
  const { t } = useTranslation('shell');
  const { assoc, busy, failed, run } = useDefaultAppAction();
  const popoverRef = useRef<HTMLDivElement | null>(null);

  useEffect(() => {
    function handler(e: PointerEvent) {
      const target = e.target as Node | null;
      if (!target) return;
      if (popoverRef.current?.contains(target)) return;
      if (anchorRef?.current?.contains(target)) return;
      onClose();
    }
    window.addEventListener('pointerdown', handler, true);
    return () => window.removeEventListener('pointerdown', handler, true);
  }, [onClose, anchorRef]);

  useEscapeToClose(onClose);

  return (
    <div
      ref={popoverRef}
      role="dialog"
      aria-label={t('markdown.assocTitle')}
      // `max-w-full` is load-bearing, not belt-and-braces: this list column is
      // resizable down to a rail, and 19rem overflows its end edge from about
      // 300px down. Absolute positioning resolves the cap against the row that
      // carries `relative`, so the popover ends up exactly as wide as the column
      // when the column is the smaller of the two.
      className={`z-50 w-[19rem] max-w-full rounded-lg border border-divider bg-surface-2 shadow-lg p-3.5 text-start ${className}`}
    >
      <div className="flex items-center gap-2 mb-2.5">
        <FileMd size={16} className="shrink-0 text-pn-muted" />
        <p className="text-[11px] font-semibold uppercase tracking-wide text-pn-muted">
          {t('markdown.assocTitle')}
        </p>
      </div>
      {assoc ? (
        <DefaultAppBody
          assoc={assoc}
          busy={busy}
          failed={failed}
          onAction={() => void run()}
          emphasis="quiet"
        />
      ) : (
        // Only reachable for the beat before the first status returns: the
        // trigger is desktop-only, so `null` here means "not read yet" rather
        // than "not supported".
        <p className="text-[12px] text-pn-muted">{t('markdown.assocReading')}</p>
      )}
    </div>
  );
}
