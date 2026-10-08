import { useEffect } from 'react';
import { useTranslation } from 'react-i18next';
import { VERSION } from './version';
import { LogoIcon } from './LogoIcon';
import { Brand } from './Brand';
import { useEscapeToClose } from './useEscapeToClose';
import { marketingHomeHref, siteHref } from './siteLinks';
import { activeLocale } from './languages';
import { helpPath } from './localeRoutes';
import { matchesKey } from './shortcutMatch';

/**
 * Custom About window content (desktop only). The macOS "About PrivacyNotes"
 * menu item opens a small fixed-size window whose URL carries ?about-window=1;
 * main.tsx routes here instead of mounting the app. Replaces the unstylable
 * system About panel. See desktop/src-tauri/src/lib.rs (open_about_window).
 *
 * Links must call the opener plugin directly: this window renders outside
 * App.tsx, so its target="_blank" interceptor is not active here.
 */

async function closeWindow() {
  const { getCurrentWindow } = await import('@tauri-apps/api/window');
  await getCurrentWindow().close();
}

async function openExternal(url: string) {
  const { openUrl } = await import('@tauri-apps/plugin-opener');
  await openUrl(url);
}

const buttonClass =
  'w-full rounded-lg border border-divider py-1.5 text-[13px] text-pn-soft transition hover:bg-pn/10';

export default function AboutWindow() {
  const { t } = useTranslation('landing');
  useEscapeToClose(() => void closeWindow());
  // Cmd+W closes this window. The menu's Close Window is Shift+Cmd+W in this
  // app, because Cmd+W in the main window closes a tab.
  useEffect(() => {
    function onKey(e: KeyboardEvent) {
      if (!matchesKey(e, [{ mod: true, key: 'w' }])) return;
      e.preventDefault();
      void closeWindow();
    }
    window.addEventListener('keydown', onKey);
    return () => window.removeEventListener('keydown', onKey);
  }, []);

  return (
    <div className="flex h-dvh select-none flex-col items-center justify-center gap-1 bg-surface-1 px-6 text-center">
      <div className="mb-2 flex h-[72px] w-[72px] items-center justify-center rounded-[18px] border border-pn/10 bg-surface-2 shadow-sm">
        <LogoIcon size={44} />
      </div>
      <h1 className="text-lg text-pn">
        <Brand />
      </h1>
      <p className="select-text text-xs text-pn-muted">
        {t('about.windowVersion', { version: VERSION })}
      </p>
      <p className="text-xs text-pn-muted">© 2026 Lifetime Labs LLC</p>
      {/* Roadmap reuses the tab-strip label rather than carrying a second key
          for the same word; /changelog and /roadmap are English-only pages, so
          only the help hub takes a locale slug. */}
      <div className="mt-4 flex w-full max-w-[210px] flex-col gap-2">
        <button onClick={() => void openExternal(marketingHomeHref())} className={buttonClass}>
          PrivacyNotes.app
        </button>
        <button onClick={() => void openExternal(siteHref(helpPath(activeLocale())))} className={buttonClass}>
          {t('about.windowHelp')}
        </button>
        <button onClick={() => void openExternal(siteHref('/changelog'))} className={buttonClass}>
          {t('about.windowWhatsNew')}
        </button>
        <button onClick={() => void openExternal(siteHref('/roadmap'))} className={buttonClass}>
          {t('about.tabs.roadmap')}
        </button>
      </div>
    </div>
  );
}
