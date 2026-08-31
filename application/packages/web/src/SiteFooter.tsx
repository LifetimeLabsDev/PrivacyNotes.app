import { ArrowCounterClockwise, DownloadSimple, FileText, GithubLogo, ListBullets, Lock, MastodonLogo, Palette, Printer, Question, RedditLogo, Scales, ShieldCheck, XLogo } from './icons';
import { LogoIcon } from './LogoIcon';
import { Brand } from './Brand';
import { LanguageMenu } from './LanguageMenu';
import { VERSION } from './version';
import { FOOTER_COLUMNS, type FooterIcon } from './footerData';
import { activeLocale } from './languages';
import { helpPath } from './localeRoutes';
import { marketingHomeHref } from './siteLinks';

const KICKER = 'font-mono text-[10px] font-semibold uppercase tracking-[0.18em] text-[#8F8776]';

// Homepage footer. Link columns come from the shared ./footerData module,
// the single source also used by the static /faq + /changelog pages
// (../static-page-chrome.ts). Styling stays Tailwind here because the
// static pages can't load it (see footerData.ts header).
// The slab is dark ink in BOTH themes (like the static pages' footer).
// Only its background rides a variable (--wl-footer): in dark mode the
// slab lifts slightly above the page so the footer has a visible start;
// the text colors stay warm literals because the ground is always dark.

function iconFor(icon: FooterIcon) {
  switch (icon) {
    case 'github':
      return <GithubLogo size={18} weight="fill" className="shrink-0" />;
    case 'shield':
      return <ShieldCheck size={18} className="shrink-0" />;
    case 'download':
      return <DownloadSimple size={18} className="shrink-0" />;
    case 'x':
      return <XLogo size={18} weight="fill" className="shrink-0" />;
    case 'reddit':
      return <RedditLogo size={18} weight="fill" className="shrink-0" />;
    case 'mastodon':
      return <MastodonLogo size={18} weight="fill" className="shrink-0" />;
    case 'faq':
      return <Question size={18} className="shrink-0" />;
    case 'changelog':
      return <ListBullets size={18} className="shrink-0" />;
    case 'roadmap':
      return (
        <svg width={18} height={18} viewBox="0 0 256 256" className="shrink-0" aria-hidden="true">
          <path d="M72 102V132Q72 172 112 172H162" fill="none" stroke="currentColor" strokeWidth={18} strokeLinecap="round" strokeLinejoin="round" />
          <circle cx={72} cy={76} r={26} fill="currentColor" />
          <circle cx={188} cy={172} r={26} fill="currentColor" />
        </svg>
      );
    case 'lock':
      return <Lock size={18} className="shrink-0" />;
    case 'file':
      return <FileText size={18} className="shrink-0" />;
    case 'refund':
      return <ArrowCounterClockwise size={18} className="shrink-0" />;
    case 'scales':
      return <Scales size={18} className="shrink-0" />;
    case 'brand':
      return <Palette size={18} className="shrink-0" />;
    case 'print':
      return <Printer size={18} className="shrink-0" />;
  }
}

export function SiteFooter() {
  return (
    <footer className="bg-[var(--wl-footer)] border-t border-[var(--wl-line)] mt-16">
      <div className="mx-auto max-w-5xl px-5 sm:px-8 py-10 sm:py-14">
        <div className="grid grid-cols-2 lg:grid-cols-4 gap-x-8 gap-y-10 text-sm">
          {FOOTER_COLUMNS.map((col, i) => (
            <div key={col.heading}>
              {i === 0 && (
                <>
                  <div className="flex items-center gap-2.5">
                    <LogoIcon size={26} className="text-blue-400" />
                    <Brand tone="dark" />
                  </div>
                  {/* The site is built from this version, so the number rendered
                      here is always the current release - the dot is a static
                      fact, not an update check. */}
                  <a
                    href="/changelog"
                    className="mt-3 inline-flex items-center gap-2 rounded-full border border-[#2E2820] px-2.5 py-1 font-mono text-[11px] text-[#A69E8F] hover:text-white hover:border-[#3D362A] transition"
                  >
                    <span className="w-1.5 h-1.5 rounded-full bg-green-400 shadow-[0_0_0_3px_rgba(74,222,128,0.15)]" />
                    v{VERSION}
                    <span className="text-[#8F8776]">latest</span>
                  </a>
                </>
              )}
              <div className={`${KICKER} ${i === 0 ? 'mt-6' : ''} mb-3`}>
                {'// '}
                {col.heading}
              </div>
              <div className="flex flex-col gap-2 items-start">
                {col.links.map((link) => (
                  <a
                    key={link.label + link.href}
                    // The FAQ and Download links follow the page's active
                    // locale so a visitor on /de lands on the German hub and
                    // the German homepage's download section. Other links
                    // stay as-is (changelog/roadmap/cheat-sheet are
                    // English-only).
                    href={
                      link.icon === 'faq'
                        ? helpPath(activeLocale())
                        : link.icon === 'download'
                          ? `${marketingHomeHref()}#downloads`
                          : link.href
                    }
                    {...(link.external ? { target: '_blank', rel: `noopener noreferrer${link.relMe ? ' me' : ''}` } : {})}
                    className="text-[#A69E8F] hover:text-white transition inline-flex items-center gap-2"
                  >
                    {iconFor(link.icon)}
                    {link.label}
                  </a>
                ))}
              </div>
            </div>
          ))}
        </div>
        <div className="mt-10 pt-6 border-t border-[#2E2820]">
          <div className="flex flex-col gap-4 sm:flex-row sm:items-center sm:justify-between">
          <div className="text-sm text-[#A69E8F] space-y-1">
            <p>
              Data Stored in{' '}
              <svg width="13" height="13" viewBox="0 0 32 32" aria-hidden="true" className="inline-block align-[-1.5px] rounded-[2px]">
                <rect width="32" height="32" fill="#da291c" />
                <rect x="13" y="6" width="6" height="20" fill="#fff" />
                <rect x="6" y="13" width="20" height="6" fill="#fff" />
              </svg>
              {' '}Switzerland.
              Encrypted on your device.
            </p>
            <p>
              No subscriptions. Just Software. Not a service.
              {' '}&copy; {new Date().getFullYear()} <a href="https://lifetimelabs.dev" target="_blank" rel="noopener noreferrer" className="hover:text-white transition">Lifetime Labs LLC</a>. All rights reserved.
              {' '}<a href="https://lifetimelabs.dev/contact/" target="_blank" rel="noopener noreferrer" className="hover:text-white transition">Contact</a>
            </p>
          </div>
          <div className="flex justify-end">
            <LanguageMenu dropUp dark navigate />
          </div>
          </div>
        </div>
      </div>
    </footer>
  );
}
