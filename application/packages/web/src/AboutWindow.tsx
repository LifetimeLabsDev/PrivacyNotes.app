import { useTranslation } from 'react-i18next';
import { VERSION } from './version';
import { LogoIcon } from './LogoIcon';
import { Brand } from './Brand';
import { useEscapeToClose } from './useEscapeToClose';
import { marketingHomeHref, siteHref } from './siteLinks';
import { activeLocale } from './languages';
import { helpPath } from './localeRoutes';

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
  'w-full rounded-lg border border-neutral-300 py-1.5 text-[13px] text-neutral-700 transition hover:bg-neutral-200 dark:border-neutral-700 dark:text-neutral-200 dark:hover:bg-neutral-800';

export default function AboutWindow() {
  const { t } = useTranslation('landing');
  useEscapeToClose(() => void closeWindow());

  return (
    <div className="flex h-dvh select-none flex-col items-center justify-center gap-1 bg-neutral-50 px-6 text-center dark:bg-neutral-900">
      <div className="mb-2 flex h-[72px] w-[72px] items-center justify-center rounded-[18px] border border-black/10 bg-white shadow-sm dark:border-white/10 dark:bg-neutral-800">
        <LogoIcon size={44} />
      </div>
      <h1 className="text-lg text-neutral-900 dark:text-neutral-100">
        <Brand />
      </h1>
      <p className="select-text text-xs text-neutral-500 dark:text-neutral-400">
        {t('about.windowVersion', { version: VERSION })}
      </p>
      <p className="text-xs text-neutral-400 dark:text-neutral-500">© 2026 Lifetime Labs LLC</p>
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
